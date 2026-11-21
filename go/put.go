package main

// put — the voice-typing app for macOS (subnsub-tools/subnsub-put) — reaching
// put on the owner's other Macs through this helper and theirs.
//
// WHO IS A PEER: only the Macs the owner's Monitor page names, in signed
// commands over the tunnel (put-key, put-peer and put-peers below, refused on
// the relay road): each one's agent id, name, tunnel address and the tailcat
// key it dials this Mac from. The list is a file, put-peers (0600), like
// allowed-clients, and nothing else adds to it. So "which Macs are mine" is
// decided where every other grant here is decided: by a key this machine has
// pinned. A page learns a Mac's keys from put-key, which carries no secret and
// is answered only under a signature this Mac verifies, and it hands out
// addresses only among the Macs that answered. put-key also says whether put
// is on this Mac (putPresence): a Mac without it is named to no other, and is
// taken off the lists that hold it. put itself pairs nothing, scans nothing
// and needs no Tailscale.
//
// ONE KEY PER DESTINATION: this Mac dials each peer from a key of its own,
// derived from a seed (put-seed, 0600) and the peer's agent id. One key in two
// clients would push each other off the DERP relay, and so would the
// tunnel's own key.
//
// WHAT A PEER GETS: one door, /v1/put/stream, which hands the connection to
// put on this Mac (putServe), and nothing else this helper serves: no
// readings, no commands, no files, no terminal. The bytes on it are put's own
// protocol, which put encrypts end to end between the two apps, inside the
// tunnel's WireGuard; this helper never reads them.
//
// HOW PUT REACHES THIS HELPER: a unix socket, put.sock in the config
// directory (0600 in a 0700 directory), like metrics.sock. One JSON line asks
// and one JSON line answers; for open and accept the socket then IS the
// stream:
//
//	{"op":"peers"}             → {"self":{…},"peers":[{"agent","name"}],"tunnel":bool,"version":…}
//	{"op":"open","agent":"…"}  → {"ok":true,"route":"direct|derp|"} then put's bytes,
//	                             or {"ok":false,"error":"<code>"}
//	{"op":"accept"}            → waits; {"from":"…","name":"…"} then put's bytes
//	{"op":"screen"}            → waits; {"from":"page"} then a screen session's
//	                             two streams, the page's own (screen.go)
//
// put keeps a few accepts waiting, so a stream from another Mac is handed to
// one at once; with none waiting (put is not running) the other side is told
// put-not-running.
//
// NOT A RELAY: a stream goes from put on one of the owner's Macs to put on
// another, and nowhere else — no other port, no other process, no other
// machine. Where no direct path forms, the encrypted bytes cross a public
// DERP relay like every tunnel's; put keeps large Shelf contents to direct
// paths.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"github.com/tailscale/tailcat"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	putPeersFile  = "put-peers"
	putSeedFile   = "put-seed"
	putSockName   = "put.sock"
	putStreamPath = "/v1/put/stream"
	// The owner's Macs; a page asking for more than this is not describing a desk.
	putMaxPeers = 32
	// Waiting accepts kept per Mac, and streams carried at once.
	putMaxAccepts = 8
	putMaxStreams = 32
	putLineMax    = 4 << 10
	putAskWait    = 10 * time.Second
	putDialWait   = 20 * time.Second
	putClientIdle = 10 * time.Minute
	putNameMax    = 64
	putAddrMax    = 1024
	// An answer's head on the way out, before the stream starts.
	putHeadMax = 8 << 10
)

var putAgentRE = regexp.MustCompile(`^[A-Za-z0-9_-]{4,40}$`)

// Where put runs at all: a Mac. A test turns it on elsewhere, in process or,
// for a test that runs the helper itself against a stand-in for the app
// (cmd/outmock), with MON_OUT_TEST=1.
var putSupported = runtime.GOOS == "darwin" || os.Getenv("MON_OUT_TEST") == "1"

// Where put is installed: its install line and its updater keep it in
// Applications. A test points it elsewhere.
var putAppPaths = func() []string {
	// The app is out; it was put until its 0.1.49, and a copy from before
	// moves itself to the new name when it next starts.
	paths := []string{"/Applications/out.app", "/Applications/put.app"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, "Applications", "out.app"), filepath.Join(home, "Applications", "put.app"))
	}
	return paths
}

// putSeen: put on this Mac has asked this helper something since it started.
var putSeen atomic.Bool

// putPresence says whether put is on this Mac: its app is in Applications,
// or it has asked this helper something since it started. Every helper on a
// Mac can carry put (the put cap in hello); put-key also says whether put is
// there, so a page or a primary names to the owner's other Macs only the
// Macs that have it, and takes a Mac off their lists once its helper says
// it has not. A helper is asked at every sweep, so this is always current,
// where a hello is read once per connection. An error when it cannot be told
// (a lookup failed other than by the app not being there): "not here" then
// would take this Mac off every list.
func putPresence() (bool, error) {
	if !putSupported {
		return false, nil
	}
	if putSeen.Load() {
		return true, nil
	}
	var failed error
	for _, p := range putAppPaths() {
		fi, err := os.Stat(p)
		switch {
		case err == nil && fi.IsDir():
			return true, nil
		case err == nil, os.IsNotExist(err), errors.Is(err, syscall.ENOTDIR):
		default:
			failed = err
		}
	}
	return false, failed
}

// putHere says whether put is on this Mac now: its app is in Applications,
// or it holds a connection at put.sock this moment. Unlike putPresence it
// remembers nothing: a Mac whose put was removed stops showing its screen
// (screen.go) without the helper being started again.
func putHere() bool {
	if !putSupported {
		return false
	}
	for _, p := range putAppPaths() {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return true
		}
	}
	putLocal.Lock()
	defer putLocal.Unlock()
	return len(putLocal.accepts)+len(putLocal.screens) > 0
}

// putPeer is one of the owner's other Macs as the page described it.
type putPeer struct {
	Agent string `json:"agent"`
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	Key   string `json:"key"`

	node key.NodePublic
}

var putState struct {
	sync.Mutex
	loaded bool
	peers  []putPeer
}

func putPeersPath() string {
	conf := configDir()
	if conf == "" {
		return ""
	}
	return filepath.Join(conf, putPeersFile)
}

// putLoadLocked reads the file once; afterwards the list in memory is the one
// this process wrote, and the gate asks it on every request.
func putLoadLocked() {
	if putState.loaded {
		return
	}
	putState.loaded = true
	path := putPeersPath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var list []putPeer
	if json.Unmarshal(b, &list) != nil {
		warnf("put: %s is unreadable; no Mac is a peer until the Monitor page sends the list again", path)
		return
	}
	for _, p := range list {
		if k, ok := transport.ParseNodeKey(p.Key); ok && putAgentRE.MatchString(p.Agent) {
			p.node = k
			putState.peers = append(putState.peers, p)
		}
	}
}

func putSaveLocked() error {
	path := putPeersPath()
	if path == "" {
		return errors.New("no config directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(putState.peers)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func putPeers() []putPeer {
	putState.Lock()
	defer putState.Unlock()
	putLoadLocked()
	return append([]putPeer(nil), putState.peers...)
}

// activePutNodes are the keys the tunnel admits for put (direct.go Allowed).
func activePutNodes() []key.NodePublic {
	var out []key.NodePublic
	for _, p := range putPeers() {
		out = append(out, p.node)
	}
	return out
}

func putPeerForNode(k key.NodePublic) (putPeer, bool) {
	for _, p := range putPeers() {
		if p.node == k {
			return p, true
		}
	}
	return putPeer{}, false
}

func putPeerByAgent(agent string) (putPeer, bool) {
	for _, p := range putPeers() {
		if p.Agent == agent {
			return p, true
		}
	}
	return putPeer{}, false
}

// putEntryDigest names one peer as held, so a page can tell whether this Mac
// already holds the entry it would send. The page computes it the same way
// (monitor.js putEntryDigest; the vector both pin is in put_test.go and
// infra/put-digest-unit.mjs): SHA-256 over agent, key, address and name joined
// by tabs and ended by a newline, and the first 16 hex digits of it.
func putEntryDigest(p putPeer) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\t%s\t%s\t%s\n", p.Agent, p.Key, p.Addr, p.Name)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ── the keys this Mac dials its peers from ──────────────────────────────

var putSeedState struct {
	sync.Mutex
	seed []byte
}

func putSeed() ([]byte, error) {
	putSeedState.Lock()
	defer putSeedState.Unlock()
	if putSeedState.seed != nil {
		return putSeedState.seed, nil
	}
	conf := configDir()
	if conf == "" {
		return nil, errors.New("no config directory")
	}
	path := filepath.Join(conf, putSeedFile)
	if b, err := os.ReadFile(path); err == nil {
		if seed, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(seed) == 32 {
			putSeedState.seed = seed
			return seed, nil
		}
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(conf, 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	putSeedState.seed = seed
	return seed, nil
}

// putKeyFor is the key this Mac dials the peer with this agent id from.
func putKeyFor(agent string) (key.NodePrivate, error) {
	seed, err := putSeed()
	if err != nil {
		return key.NodePrivate{}, err
	}
	mac := hmac.New(sha256.New, seed)
	io.WriteString(mac, "put client key\x00"+agent)
	raw := mac.Sum(nil)
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte("privkey:" + hex.EncodeToString(raw))); err != nil {
		return key.NodePrivate{}, err
	}
	return priv, nil
}

// putNameOK: a name is stored as the page sent it, so that both sides hash the
// same bytes; the page makes it one trimmed line.
func putNameOK(name string) bool {
	if len(name) > putNameMax || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ── the page's three commands ────────────────────────────────────────────

// runPutKey tells a page that this Mac takes its signature — only a command
// verified under a pinned key gets here — and gives it, for each agent id in
// Cmd (a JSON array), the key this Mac dials that Mac from, and for each peer
// held the digest of its entry. No address leaves this Mac this way.
func runPutKey(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Code: -1}
	if !putSupported {
		res.Error = "unsupported"
		return res
	}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	var dests []string
	if json.Unmarshal([]byte(c.Cmd), &dests) != nil || len(dests) > 4*putMaxPeers {
		res.Error = "bad-args"
		return res
	}
	present, err := putPresence()
	if err != nil {
		res.Error = "unavailable"
		return res
	}
	keys := map[string]string{}
	self := agentID()
	for _, d := range dests {
		// Without put this Mac dials no one, so it gives no key: a page or a
		// primary too old to read "present" cannot name it to the others.
		if !present || !putAgentRE.MatchString(d) || d == self {
			continue
		}
		priv, err := putKeyFor(d)
		if err != nil {
			res.Error = "unavailable"
			return res
		}
		text, _ := priv.Public().MarshalText()
		keys[d] = string(text)
	}
	held := map[string]string{}
	for _, p := range putPeers() {
		held[p.Agent] = putEntryDigest(p)
	}
	b, _ := json.Marshal(map[string]any{"keys": keys, "held": held, "present": present})
	res.Code, res.Out = 0, string(b)
	return res
}

type putPeerArgs struct {
	Name string `json:"n"`
	Addr string `json:"a"`
	Key  string `json:"k"`
}

// runPutPeer adds, changes or (with an empty Cmd) removes one peer: Target is
// its agent id, Cmd {"n": name, "a": tunnel address, "k": the key it dials
// this Mac from}. Answered with the digest of the entry now held ("" when
// removed). A removed or changed peer's streams end at once.
func runPutPeer(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Target: c.Target, Code: -1}
	if !putSupported {
		res.Error = "unsupported"
		return res
	}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	agent := strings.TrimSpace(c.Target)
	if !putAgentRE.MatchString(agent) || agent == agentID() {
		res.Error = "bad-target"
		return res
	}
	var next *putPeer
	if strings.TrimSpace(c.Cmd) != "" {
		var a putPeerArgs
		if json.Unmarshal([]byte(c.Cmd), &a) != nil {
			res.Error = "bad-args"
			return res
		}
		k, ok := transport.ParseNodeKey(a.Key)
		name := a.Name
		if !ok || len(a.Addr) == 0 || len(a.Addr) > putAddrMax || !putNameOK(name) {
			res.Error = "bad-args"
			return res
		}
		if _, err := tailcat.ParseAddr(tailcat.Addr(a.Addr)); err != nil {
			res.Error = "bad-args"
			return res
		}
		text, _ := k.MarshalText()
		next = &putPeer{Agent: agent, Name: name, Addr: a.Addr, Key: string(text), node: k}
	}
	putState.Lock()
	putLoadLocked()
	list := make([]putPeer, 0, len(putState.peers)+1)
	var was *putPeer
	for i, p := range putState.peers {
		if p.Agent == agent {
			was = &putState.peers[i]
			continue
		}
		list = append(list, p)
	}
	if next != nil {
		if len(list) >= putMaxPeers {
			putState.Unlock()
			res.Error = "too-many"
			return res
		}
		list = append(list, *next)
	}
	old := putState.peers
	putState.peers = list
	if err := putSaveLocked(); err != nil {
		putState.peers = old
		putState.Unlock()
		res.Error = "save-failed"
		return res
	}
	digest := ""
	if next != nil {
		digest = putEntryDigest(*next)
	}
	putState.Unlock()
	if was != nil && (next == nil || was.Addr != next.Addr || was.Key != next.Key) {
		putCut(agent)
	}
	if next != nil {
		admitNow(next.node)
	}
	res.Code, res.Out = 0, digest
	return res
}

// runPutPeers keeps the peers whose agent ids Cmd lists (a JSON array) and
// drops the rest: the page's way of saying a Mac is no longer the owner's.
func runPutPeers(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Code: -1}
	if !putSupported {
		res.Error = "unsupported"
		return res
	}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	var keep []string
	if json.Unmarshal([]byte(c.Cmd), &keep) != nil || len(keep) > 4*putMaxPeers {
		res.Error = "bad-args"
		return res
	}
	want := map[string]bool{}
	for _, a := range keep {
		want[a] = true
	}
	putState.Lock()
	putLoadLocked()
	var list, gone []putPeer
	for _, p := range putState.peers {
		if want[p.Agent] {
			list = append(list, p)
		} else {
			gone = append(gone, p)
		}
	}
	if len(gone) > 0 {
		old := putState.peers
		putState.peers = list
		if err := putSaveLocked(); err != nil {
			putState.peers = old
			putState.Unlock()
			res.Error = "save-failed"
			return res
		}
	}
	n := len(putState.peers)
	putState.Unlock()
	for _, p := range gone {
		putCut(p.Agent)
	}
	res.Code, res.Out = 0, fmt.Sprint(n)
	return res
}

// ── the door a peer comes in by ──────────────────────────────────────────

var putStreams struct {
	sync.Mutex
	n int
	// The connections of the streams open now, by the peer they are with, so
	// that a peer removed or changed is cut off at once.
	by map[string]map[*putTracked]struct{}
}

type putTracked struct{ conns []net.Conn }

// putTrack notes a stream with a peer; the func it returns forgets it.
func putTrack(agent string, conns ...net.Conn) func() {
	t := &putTracked{conns: conns}
	putStreams.Lock()
	if putStreams.by == nil {
		putStreams.by = map[string]map[*putTracked]struct{}{}
	}
	if putStreams.by[agent] == nil {
		putStreams.by[agent] = map[*putTracked]struct{}{}
	}
	putStreams.by[agent][t] = struct{}{}
	putStreams.Unlock()
	return func() {
		putStreams.Lock()
		delete(putStreams.by[agent], t)
		if len(putStreams.by[agent]) == 0 {
			delete(putStreams.by, agent)
		}
		putStreams.Unlock()
	}
}

// putCut ends every stream with a peer and drops its client.
func putCut(agent string) {
	putStreams.Lock()
	var cut []*putTracked
	for t := range putStreams.by[agent] {
		cut = append(cut, t)
	}
	putStreams.Unlock()
	for _, t := range cut {
		for _, c := range t.conns {
			c.Close()
		}
	}
	putDropClient(agent)
}

func putStreamStart() bool {
	putStreams.Lock()
	defer putStreams.Unlock()
	if putStreams.n >= putMaxStreams {
		return false
	}
	putStreams.n++
	return true
}

func putStreamEnd() {
	putStreams.Lock()
	putStreams.n--
	putStreams.Unlock()
}

// putServe is all a peer's key may ask for: the stream to put here.
func (h *directHandler) putServe(w http.ResponseWriter, r *http.Request, p putPeer) {
	if r.URL.Path != putStreamPath || r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "put") {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	if !putStreamStart() {
		h.refuse(w, http.StatusServiceUnavailable, "busy")
		return
	}
	header, _ := json.Marshal(map[string]string{"from": p.Agent, "name": p.Name})
	local := putTakeAccept(append(header, '\n'))
	if local == nil {
		putStreamEnd()
		h.refuse(w, http.StatusServiceUnavailable, "put-not-running")
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		putStreamEnd()
		local.Close()
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: put\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		putStreamEnd()
		conn.Close()
		local.Close()
		return
	}
	// What the peer sent after its request, read with it, goes first.
	var early []byte
	if n := brw.Reader.Buffered(); n > 0 {
		b, _ := brw.Reader.Peek(n)
		early = append([]byte(nil), b...)
	}
	untrack := putTrack(p.Agent, local, conn)
	go func() {
		defer putStreamEnd()
		defer untrack()
		putPipe(local, local, conn, io.MultiReader(bytes.NewReader(early), conn))
	}()
}

// putPipe carries bytes both ways until either side ends, then closes both:
// put never half-closes a stream. ar and br are where each side's bytes are
// read from: the connection, or a reader holding what was read past the
// handshake before it.
func putPipe(a net.Conn, ar io.Reader, b net.Conn, br io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, ar); done <- struct{}{} }()
	go func() { io.Copy(a, br); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

// ── put on this Mac: the local socket ────────────────────────────────────

var putLocal struct {
	sync.Mutex
	on      bool
	accepts []net.Conn
	// Connections put keeps waiting for a screen session from the Monitor
	// page (screen.go): the app shows this Mac's screen on it.
	screens []net.Conn
}

// A screen is one page's at a time; put keeps a spare waiting.
const putMaxScreens = 4

// putParkScreen keeps a connection of put's waiting for a screen session.
func putParkScreen(c net.Conn) {
	putLocal.Lock()
	defer putLocal.Unlock()
	if len(putLocal.screens) >= putMaxScreens {
		putLocal.screens[0].Close()
		putLocal.screens = putLocal.screens[1:]
	}
	putLocal.screens = append(putLocal.screens, c)
}

// putTakeScreen hands a waiting connection the word that a page's screen
// session is its own from here on, and takes it out of the pool: nil where
// put keeps none waiting (it is not running, or its switch for the screen is
// off). One whose put has gone away fails the write and the next is tried.
func putTakeScreen() net.Conn {
	for {
		putLocal.Lock()
		if len(putLocal.screens) == 0 {
			putLocal.Unlock()
			return nil
		}
		c := putLocal.screens[0]
		putLocal.screens = putLocal.screens[1:]
		putLocal.Unlock()
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("{\"from\":\"page\"}\n")); err != nil {
			c.Close()
			continue
		}
		c.SetWriteDeadline(time.Time{})
		return c
	}
}

func putSockPath() string {
	conf := configDir()
	if conf == "" {
		return ""
	}
	return filepath.Join(conf, putSockName)
}

// putTakeAccept hands a waiting accept its header and takes it out of the
// pool, the oldest first; one whose put has gone away fails the write and the
// next is tried.
func putTakeAccept(header []byte) net.Conn {
	for {
		putLocal.Lock()
		if len(putLocal.accepts) == 0 {
			putLocal.Unlock()
			return nil
		}
		c := putLocal.accepts[0]
		putLocal.accepts = putLocal.accepts[1:]
		putLocal.Unlock()
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(header); err != nil {
			c.Close()
			continue
		}
		c.SetWriteDeadline(time.Time{})
		return c
	}
}

func putPark(c net.Conn) {
	putLocal.Lock()
	defer putLocal.Unlock()
	if len(putLocal.accepts) >= putMaxAccepts {
		// put came back after a restart: the oldest are from before it.
		putLocal.accepts[0].Close()
		putLocal.accepts = putLocal.accepts[1:]
	}
	putLocal.accepts = append(putLocal.accepts, c)
}

// startPutSocket opens put.sock where put runs; started with the daemon and
// with the tunnel, and once.
func startPutSocket() {
	if !putSupported {
		return
	}
	putLocal.Lock()
	if putLocal.on {
		putLocal.Unlock()
		return
	}
	putLocal.on = true
	putLocal.Unlock()
	path := putSockPath()
	if path == "" {
		return
	}
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		// Another helper process answers there already.
		c.Close()
		return
	}
	// The directory is the socket's gate: owner only, whatever an older
	// install left it at, or no socket.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			warnf("put: %s is open to other users and could not be closed: %v; no socket for put", dir, err)
			return
		}
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		warnf("put: no socket at %s: %v", path, err)
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		os.Remove(path)
		warnf("put: could not make %s owner-only: %v; no socket for put", path, err)
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(time.Second)
				continue
			}
			go servePutLocal(c)
		}
	}()
}

type putAsk struct {
	Op    string `json:"op"`
	Agent string `json:"agent,omitempty"`
}

func putAnswer(c net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write(append(b, '\n'))
	c.SetWriteDeadline(time.Time{})
	return err
}

// putReadLine reads one line of at most putLineMax bytes, nothing past it.
func putReadLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			return line, nil
		}
		if len(line) >= putLineMax {
			return nil, errors.New("line too long")
		}
		line = append(line, b)
	}
}

func servePutLocal(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(putAskWait))
	r := bufio.NewReaderSize(c, 256)
	line, err := putReadLine(r)
	if err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	var ask putAsk
	if json.Unmarshal(line, &ask) != nil {
		putAnswer(c, map[string]any{"ok": false, "error": "bad-frame"})
		c.Close()
		return
	}
	// Only the user's own programs reach this socket, and put asks these: it
	// is on this Mac. A hint rather than proof of the app, as the socket is.
	switch ask.Op {
	case "peers", "open", "accept", "screen":
		putSeen.Store(true)
	}
	switch ask.Op {
	case "peers":
		type who struct {
			Agent string `json:"agent"`
			Name  string `json:"name"`
		}
		peers := []who{}
		for _, p := range putPeers() {
			peers = append(peers, who{p.Agent, p.Name})
		}
		putAnswer(c, map[string]any{
			"ok": true, "self": who{agentID(), agentLabel()}, "peers": peers,
			"tunnel": directAddress() != "", "version": helperVersion,
		})
		c.Close()
	case "accept":
		if r.Buffered() > 0 {
			// Nothing may follow an accept until its header has come.
			c.Close()
			return
		}
		putPark(c)
	case "screen":
		if r.Buffered() > 0 {
			// Nothing may follow until the session has come.
			c.Close()
			return
		}
		putParkScreen(c)
	case "open":
		putOpen(c, r, ask.Agent)
	default:
		putAnswer(c, map[string]any{"ok": false, "error": "unknown-op"})
		c.Close()
	}
}

// putOpen dials a peer's helper for put on this Mac and, once the other side
// has taken it, carries the stream.
func putOpen(c net.Conn, r *bufio.Reader, agent string) {
	fail := func(code string) {
		putAnswer(c, map[string]any{"ok": false, "error": code})
		c.Close()
	}
	p, ok := putPeerByAgent(agent)
	if !ok {
		fail("unknown-peer")
		return
	}
	if !putStreamStart() {
		fail("busy")
		return
	}
	defer putStreamEnd()
	// One deadline for the whole open, retry included.
	deadline := time.Now().Add(putDialWait)
	pc, reused, err := putClientFor(p)
	if err != nil {
		fail("unavailable")
		return
	}
	first := deadline
	if reused {
		if d := time.Now().Add(putReusedWait); d.Before(first) {
			first = d
		}
	}
	nc, nr, code, err := putConnect(pc, first)
	if errors.Is(err, errPutSilent) && reused {
		// A client kept from an earlier stream can have lost its tunnel
		// without knowing it — its relay session gone while this Mac slept —
		// and, kept busy, it is never idle long enough to be reaped: every
		// stream then waited out putDialWait and failed (user 2026-11-20, mbp
		// to m2). It is closed, and a fresh one is tried once, in the time
		// left, for the peer as its entry is now (it may have changed or gone
		// meanwhile).
		putDiscardClient(pc)
		pc.release()
		now, ok := putPeerByAgent(agent)
		if !ok {
			fail("unknown-peer")
			return
		}
		p = now
		if pc, _, err = putClientFor(p); err != nil {
			fail("unavailable")
			return
		}
		nc, nr, code, err = putConnect(pc, deadline)
	}
	defer pc.release()
	if err != nil {
		// A client that got no answer at all is not kept for the next stream:
		// that one starts afresh. One that was answered has a tunnel that works.
		if errors.Is(err, errPutSilent) {
			putDiscardClient(pc)
		}
		fail("unreachable")
		return
	}
	if code != "" {
		fail(code)
		return
	}
	nc.SetDeadline(time.Time{})
	untrack := putTrack(p.Agent, c, nc)
	defer untrack()
	if putAnswer(c, map[string]any{"ok": true, "route": pc.route()}) != nil {
		nc.Close()
		c.Close()
		return
	}
	putPipe(c, r, nc, nr)
}

// errPutSilent: the peer's helper did not answer at all — no connection, or no
// byte of an answer — which is what a client whose tunnel is gone sees.
var errPutSilent = errors.New("no answer")

// putConnect opens the stream to the peer's helper through the client, by
// deadline: the connection and its reader once the other side has taken it; a
// refusal's code (the connection closed) when it answered with no; an error
// when it did not, wrapping errPutSilent while no byte of an answer came.
func putConnect(pc *putClient, deadline time.Time) (net.Conn, *bufio.Reader, string, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	nc, err := pc.cl.DialTCPPort(ctx, directPort)
	cancel()
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", errPutSilent, err)
	}
	nc.SetDeadline(deadline)
	if _, err := io.WriteString(nc, "GET "+putStreamPath+" HTTP/1.1\r\nHost: tailcat\r\nUpgrade: put\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		nc.Close()
		return nil, nil, "", fmt.Errorf("%w: %v", errPutSilent, err)
	}
	nr := bufio.NewReader(nc)
	if _, err := nr.Peek(1); err != nil {
		nc.Close()
		return nil, nil, "", fmt.Errorf("%w: %v", errPutSilent, err)
	}
	// An answer has begun: whatever happens now, the tunnel works, and the
	// other side may have handed the stream on already, so it is not retried.
	status, upgraded, code, err := putReadHead(nr)
	if err != nil {
		nc.Close()
		return nil, nil, "", err
	}
	if status != http.StatusSwitchingProtocols || !upgraded {
		nc.Close()
		if code == "" {
			code = "refused"
		}
		return nil, nil, code, nil
	}
	return nc, nr, "", nil
}

// putReadHead reads the other helper's answer to the upgrade — at most
// putHeadMax bytes of it, and nothing past it — for the status, whether it
// upgraded to put, and for a refusal its error frame's code.
func putReadHead(r *bufio.Reader) (status int, upgraded bool, code string, err error) {
	total := 0
	line := func() (string, error) {
		var b []byte
		for {
			c, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			total++
			if total > putHeadMax {
				return "", errors.New("answer head too long")
			}
			if c == '\n' {
				return strings.TrimRight(string(b), "\r"), nil
			}
			b = append(b, c)
		}
	}
	first, err := line()
	if err != nil {
		return 0, false, "", err
	}
	parts := strings.SplitN(first, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return 0, false, "", errors.New("not an HTTP answer")
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &status); err != nil {
		return 0, false, "", err
	}
	header := http.Header{}
	for {
		l, err := line()
		if err != nil {
			return 0, false, "", err
		}
		if l == "" {
			break
		}
		if i := strings.IndexByte(l, ':'); i > 0 {
			header.Add(strings.TrimSpace(l[:i]), strings.TrimSpace(l[i+1:]))
		}
	}
	if status == http.StatusSwitchingProtocols {
		conn := strings.ToLower(header.Get("Connection"))
		return status, strings.EqualFold(header.Get("Upgrade"), "put") && strings.Contains(conn, "upgrade"), "", nil
	}
	var n int
	if _, err := fmt.Sscanf(header.Get("Content-Length"), "%d", &n); err == nil && n > 0 && n <= 4<<10 {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err == nil {
			if f, err := transport.Decode(b); err == nil && f.Type == transport.TypeError {
				var e transport.Error
				if json.Unmarshal(f.Body, &e) == nil {
					code = e.Code
				}
			}
		}
	}
	return status, false, code, nil
}

// ── the clients this Mac dials its peers with ────────────────────────────

// How long a client kept from an earlier stream gets before it is given up for
// a fresh one (putOpen): a healthy one answers well inside it. A test shortens it.
var putReusedWait = 5 * time.Second

// putTunnel is what a put client needs of its tailcat client; a test puts its
// own in its place.
type putTunnel interface {
	DialTCPPort(ctx context.Context, port uint16) (net.Conn, error)
	DiscoPing(ctx context.Context) (*ipnstate.PingResult, error)
	Close() error
}

type putClient struct {
	agent  string
	addr   string
	cl     putTunnel
	users  int
	last   time.Time
	closed bool
	// "direct", "derp", or "" until a ping has said.
	via string
}

var putClients struct {
	sync.Mutex
	m       map[string]*putClient
	reaping bool
}

// putDial makes a client; a test puts its own in its place.
var putDial = func(addr string, priv key.NodePrivate) putTunnel {
	return &tailcat.Client{Server: tailcat.ConnBlob(addr), Key: priv, Logf: logger.Discard, DERPMapURL: derpMapURL()}
}

// putClientFor is the peer's client, under the key for that peer, kept
// between streams so that the next one finds the tunnel up; reused says it
// was kept from earlier rather than made now.
func putClientFor(p putPeer) (pc *putClient, reused bool, err error) {
	priv, err := putKeyFor(p.Agent)
	if err != nil {
		return nil, false, err
	}
	putClients.Lock()
	defer putClients.Unlock()
	if putClients.m == nil {
		putClients.m = map[string]*putClient{}
	}
	pc = putClients.m[p.Agent]
	if pc != nil && pc.addr != p.Addr {
		if pc.users == 0 {
			putCloseLocked(pc)
		}
		pc = nil
	}
	reused = pc != nil
	if pc == nil {
		pc = &putClient{agent: p.Agent, addr: p.Addr, cl: putDial(p.Addr, priv)}
		putClients.m[p.Agent] = pc
		go pc.learnRoute()
	}
	pc.users++
	pc.last = time.Now()
	if !putClients.reaping {
		putClients.reaping = true
		go putReap()
	}
	return pc, reused, nil
}

func (pc *putClient) release() {
	putClients.Lock()
	defer putClients.Unlock()
	pc.users--
	pc.last = time.Now()
	// Dropped or replaced while in use: closed now that nobody is.
	if pc.users == 0 && putClients.m[pc.agent] != pc {
		putCloseLocked(pc)
	}
}

func (pc *putClient) route() string {
	putClients.Lock()
	defer putClients.Unlock()
	return pc.via
}

// learnRoute asks magicsock how a ping came back, as a Files fetch does
// (filesfetch.go Route), and asks again while the client lives: a path that
// starts on DERP often goes direct a few seconds later.
func (pc *putClient) learnRoute() {
	for i := 0; i < 6; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r, err := pc.cl.DiscoPing(ctx)
		cancel()
		via := ""
		if err == nil && r != nil {
			via = "derp"
			if r.Endpoint != "" {
				via = "direct"
			}
		}
		putClients.Lock()
		alive := putClients.m[pc.agent] == pc
		if via != "" {
			pc.via = via
		}
		putClients.Unlock()
		if !alive || via == "direct" {
			return
		}
		time.Sleep(10 * time.Second)
	}
}

func putDropClient(agent string) {
	putClients.Lock()
	defer putClients.Unlock()
	if pc := putClients.m[agent]; pc != nil {
		delete(putClients.m, agent)
		if pc.users == 0 {
			putCloseLocked(pc)
		}
	}
}

// putCloseLocked closes a client once. Caller holds putClients.
func putCloseLocked(pc *putClient) {
	if !pc.closed {
		pc.closed = true
		pc.cl.Close()
	}
}

// putDiscardClient gives a client up: out of use, so the next stream makes a
// fresh one, and closed at once, streams on it included (they were not getting
// through either), so that its successor never shares the relay with it under
// the same key — two clients with one key push each other off.
func putDiscardClient(pc *putClient) {
	putClients.Lock()
	defer putClients.Unlock()
	if putClients.m[pc.agent] == pc {
		delete(putClients.m, pc.agent)
	}
	putCloseLocked(pc)
}

// putForgetClients gives every client up, as putDiscardClient does: called
// when this Mac wakes (outageTick), since a relay session does not outlive a
// sleep and a client may not notice.
func putForgetClients() {
	putClients.Lock()
	defer putClients.Unlock()
	for agent, pc := range putClients.m {
		delete(putClients.m, agent)
		putCloseLocked(pc)
	}
}

// putReap closes the clients nobody has used for a while.
func putReap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		putClients.Lock()
		for agent, pc := range putClients.m {
			if pc.users == 0 && time.Since(pc.last) > putClientIdle {
				delete(putClients.m, agent)
				putCloseLocked(pc)
			}
		}
		putClients.Unlock()
	}
}
