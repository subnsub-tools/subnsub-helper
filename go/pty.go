package main

// Terminal — a real one, carried by the direct tunnel.
//
// WHAT IT IS. The console (console.go) runs one `sh -c` per line: no
// terminal, no input, thirty seconds, sixteen kilobytes. Nothing interactive
// survives that — not `cd`, not an editor, not an agent's own interface. This
// is the other thing: one login shell on a pseudo-terminal, its bytes
// streamed both ways.
//
// HOW LONG IT LIVES (user 2026-11-07: every window kept, whenever it is
// opened or dropped, still running). A session is not the page's: closing
// the browser, a tunnel that drops, this helper restarting or updating leave
// it running. Its shell is held by a process of its own (ptyhold_unix.go), and
// it ends when somebody ends it (a page closing its tab), when the shell
// exits, or when nobody has shown a sign of life on it for its KEEP: the
// account's allowance, which the relay says on every push (pty_keep, from
// an hour to a week), never longer than the ceiling the
// browser signed into the opening command, and never longer than ptyKeepMax.
// Until the relay has said, a session keeps ptyQuietMax, as every session
// did before this build.
//
// WHO MAY OPEN ONE. Exactly who may run a console line through the tunnel,
// and by the same three gates: the peer's key is on the allowlist (the
// tunnel's own gate), the console switch is on at the machine, and the
// opening is a `pty` command SIGNED by a dashboard key this machine has
// pinned (verifyCommand, in direct.go's command) — an unpinned machine has no
// terminal, as it has no tunnel console. The relay's mailbox never carries
// this kind: runCommand does not know it, so it is refused there as any
// unknown kind is.
//
// WHO MAY COME BACK TO ONE. A session has an id, which the machine lists in
// its push (the relay keeps the list for the account's pages), and a
// `pty-attach` command naming it — signed like the opening, by any key this
// machine has pinned — hands the browser that sent it a token of its own.
// The id is not a capability: only the signed command turns it into a token.
// A portable copy may come back only to the sessions it opened itself.
//
// WHAT THE SIGNATURE BUYS. The signed command answers with a session token:
// 128 random bits, good only on the tunnel of the peer that got it. The
// streams that follow (out, in, resize, close) carry the token and are not
// signed one by one — a keystroke is not a command — so the token is the
// capability and the tunnel is its channel: WireGuard between this machine
// and one allowlisted key.
//
// ONE KEYBOARD. Every token may watch. The keys are the token's that came
// last — an attach takes them from whoever had them (a watching attach only
// where nobody holds them), and that page is told (`taken`, 423) when it
// next types, so it can take them back the same way.
//
// BOUNDS. ptyMaxSessions sessions at once. Every session ends the moment the
// console is switched off; a session ends when the key that opened it is
// unpinned; a token goes when its peer leaves the allowlist (sweep).

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	// Several per machine, as an editor keeps several tabs (user 2026-10-06),
	// and more of them now that they outlive the page.
	ptyMaxSessions = 16
	// Output kept for a page that attaches again.
	ptyRing = 256 << 10
	// How long a session outlives its last sign of life until the relay has
	// said otherwise: what every session kept before sessions outlived their
	// page.
	ptyQuietMax = 3 * time.Minute
	// The most anybody can make it: a week, and a little for the clocks.
	ptyKeepMax = 7*24*time.Hour + 10*time.Minute
	// One write to the browser; a reader this slow is gone.
	ptyWriteWait = 30 * time.Second
	// How often the rules above are re-read while a session exists: the
	// longest a shell outlives `console off`.
	ptySweepEvery = 5 * time.Second
	ptyChunk      = 32 << 10
	// The window a shell may be given. Bounded so a number from the wire is
	// never an allocation in somebody's curses library.
	ptyMaxCols = 500
	ptyMaxRows = 200
	// A sign of life is passed to the holder at most this often.
	ptyBeatEvery = 20 * time.Second
	// A request to a holder.
	ptyHoldWait = 3 * time.Second
	// Where the relay's last word on the keep is kept, in the config
	// directory, so a restart before the next push does not shorten it.
	ptyKeepFile = "pty-keep"
)

// The socket's name in the holders' directory: the session's id, then this.
// Short, since a Unix socket's path is bounded (104 bytes on macOS).
const ptyHoldExt = ".s"

func ptyHoldSock(dir, id string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, id+ptyHoldExt)
}

// ptyHoldInfo is what a holder says about its session.
type ptyHoldInfo struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	At     int64  `json:"at"`
	Seen   int64  `json:"seen"`
	Until  int64  `json:"until"`
	Keep   int64  `json:"keep"`
	Ceil   int64  `json:"ceil"`
	Signer string `json:"signer,omitempty"`
	Prog   string `json:"prog,omitempty"`
	Cols   int    `json:"cols"`
	Rows   int    `json:"rows"`
	Total  int64  `json:"total"`
	Ended  bool   `json:"ended,omitempty"`
}

type ptyHoldReq struct {
	Op   string `json:"op"`
	Cols int    `json:"c,omitempty"`
	Rows int    `json:"r,omitempty"`
	Keep int64  `json:"keep,omitempty"`
}

// clampKeep bounds a keep to what any session may have.
func clampKeep(d time.Duration) time.Duration {
	if d < ptyQuietMax {
		return ptyQuietMax
	}
	if d > ptyKeepMax {
		return ptyKeepMax
	}
	return d
}

var ptyTokenRe = regexp.MustCompile(`^[a-f0-9]{32}$`)
var ptyIDRe = regexp.MustCompile(`^[a-f0-9]{16}$`)

// The opening command's target: the size, and the ceiling in seconds the
// browser signed (absent from a page or a command line that predates it).
var ptyTargetRe = regexp.MustCompile(`^([0-9]{1,3})x([0-9]{1,3})(?:/([0-9]{1,7}))?$`)

// ptySess is one session as this process knows it: its holder's socket, who
// opened it, and the tokens that reach it.
type ptySess struct {
	id     string
	sock   string
	signer ed25519.PublicKey
	at     time.Time

	mu    sync.Mutex
	ended bool
	done  chan struct{}
	// The token with the keyboard, and the tokens with an input stream
	// open (one each).
	owner  string
	inToks map[string]bool
	beatAt time.Time
}

// A token: the session it reaches, the tunnel peer it is good for, the key
// that signed the command it came from, and a channel closed when it is let
// go — which ends every stream opened with it (review: a peer dropped from
// the allowlist, or a signer unpinned, must not keep typing on a stream it
// opened before).
type ptyTok struct {
	s      *ptySess
	peer   key.NodePublic
	signer ed25519.PublicKey
	gone   chan struct{}
}

// revokeLocked lets a token go. Holds hub.mu.
func (hub *ptyHub) revokeLocked(tok string) {
	if k := hub.toks[tok]; k != nil {
		delete(hub.toks, tok)
		close(k.gone)
	}
}

type ptyHub struct {
	mu   sync.Mutex
	sess map[string]*ptySess
	toks map[string]*ptyTok
	// Openings under way, counted against the ceiling.
	pending int
	// Whether a tunnel key is still on the allowlist, and whether a signing
	// key is still pinned; nil admits (a test).
	allowed func(key.NodePublic) bool
	trusted func(ed25519.PublicKey) bool
	// The sweeper runs only while there is a session to sweep.
	sweeping bool
	// The keep the relay said last, and whether it has said one.
	keep     time.Duration
	keepSaid bool
	// Where the holders' sockets are, and how one is started; the tests
	// give their own.
	dir     string
	spawn   func(dir, id string, cols, rows int, keep, ceil time.Duration, signer ed25519.PublicKey) error
	adopted bool
	// Whether the keep is written down (only the process's own hub does).
	persist bool
}

func newPtyHub() *ptyHub {
	return &ptyHub{sess: map[string]*ptySess{}, toks: map[string]*ptyTok{}, keep: ptyQuietMax, spawn: ptyHoldSpawn}
}

// The process's sessions. One table whatever becomes of the tunnel's carrier
// (direct.go makes a handler per carrier), so the ceiling counts every shell
// there is and a token still names its session after a rebuild.
var ptySessions = func() *ptyHub {
	hub := newPtyHub()
	hub.persist = true
	hub.allowed = func(k key.NodePublic) bool {
		for _, a := range loadAllowedClients() {
			if a == k {
				return true
			}
		}
		// A portable copy's session lasts while the copy does (clone.go).
		_, ok := cloneForNode(k, agentID(), time.Now())
		return ok
	}
	hub.trusted = func(k ed25519.PublicKey) bool { return trustsKey(k) || cloneSignerActive(k) }
	return hub
}()

// ptyTarget reads an opening's target: "COLSxROWS", and the signed ceiling
// after a slash.
func ptyTarget(target string) (cols, rows int, ceil time.Duration, ok bool) {
	m := ptyTargetRe.FindStringSubmatch(target)
	if m == nil {
		return 0, 0, 0, false
	}
	cols, _ = strconv.Atoi(m[1])
	rows, _ = strconv.Atoi(m[2])
	if cols < 2 || rows < 2 || cols > ptyMaxCols || rows > ptyMaxRows {
		return 0, 0, 0, false
	}
	ceil = ptyKeepMax
	if m[3] != "" {
		n, _ := strconv.Atoi(m[3])
		ceil = time.Duration(n) * time.Second
	}
	return cols, rows, ceil, true
}

func ptySize(target string) (cols, rows int, ok bool) {
	cols, rows, _, ok = ptyTarget(target)
	return
}

func (hub *ptyHub) holdDir() string {
	if hub.dir != "" {
		return hub.dir
	}
	return ptyHoldDir()
}

/* ── talking to a holder ─────────────────────────────────────────────── */

func ptyDial(sock string) (net.Conn, error) {
	if sock == "" {
		return nil, errors.New("no holder")
	}
	return net.DialTimeout("unix", sock, ptyHoldWait)
}

// ptyAsk sends one request and reads its one-line answer into out (nil:
// read and drop it).
func ptyAsk(sock string, q ptyHoldReq, out any) error {
	c, err := ptyDial(sock)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(ptyHoldWait))
	b, _ := json.Marshal(q)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReaderSize(c, 4096).ReadSlice('\n')
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(line, out)
}

// ptyStream opens a streaming request (out, in, wait): the connection after
// the request's line.
func ptyStream(sock, op string) (net.Conn, error) {
	c, err := ptyDial(sock)
	if err != nil {
		return nil, err
	}
	c.SetWriteDeadline(time.Now().Add(ptyHoldWait))
	if _, err := c.Write([]byte(`{"op":"` + op + `"}` + "\n")); err != nil {
		c.Close()
		return nil, err
	}
	c.SetWriteDeadline(time.Time{})
	return c, nil
}

/* ── the table ───────────────────────────────────────────────────────── */

func ptyRandHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// adopt takes in the sessions whose holders outlived the process before
// this one, once. A socket nobody answers on is a holder that is gone.
func (hub *ptyHub) adopt() {
	hub.mu.Lock()
	if hub.adopted {
		hub.mu.Unlock()
		return
	}
	hub.adopted = true
	if hub.persist {
		if b, err := os.ReadFile(filepath.Join(configDir(), ptyKeepFile)); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
				hub.keep = clampKeep(time.Duration(n) * time.Second)
			}
		}
	}
	hub.mu.Unlock()
	if !ptySupported {
		return
	}
	dir := hub.holdDir()
	if dir == "" {
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		id := strings.TrimSuffix(name, ptyHoldExt)
		if id == name || !ptyIDRe.MatchString(id) {
			continue
		}
		sock := filepath.Join(dir, name)
		var in ptyHoldInfo
		if err := ptyAsk(sock, ptyHoldReq{Op: "info"}, &in); err != nil {
			if c, derr := ptyDial(sock); derr != nil {
				os.Remove(sock)
			} else {
				c.Close()
			}
			continue
		}
		if in.ID != id || in.Ended {
			continue
		}
		var signer ed25519.PublicKey
		if b, err := base64.StdEncoding.DecodeString(in.Signer); err == nil && len(b) == ed25519.PublicKeySize {
			signer = b
		}
		s := &ptySess{id: id, sock: sock, signer: signer, at: time.Unix(in.At, 0), done: make(chan struct{})}
		hub.mu.Lock()
		if _, had := hub.sess[id]; !had && len(hub.sess) < ptyMaxSessions {
			hub.sess[id] = s
			go hub.follow(s)
		}
		hub.mu.Unlock()
		warnf("terminal: a session kept from before is back")
	}
	hub.startSweep()
}

// follow notices a session's end at its holder — the shell exited, its
// clock ran out — and takes it off the table.
func (hub *ptyHub) follow(s *ptySess) {
	for {
		c, err := ptyStream(s.sock, "wait")
		if err == nil {
			go func() {
				<-s.done
				c.Close()
			}()
			io.Copy(io.Discard, c)
			c.Close()
		}
		select {
		case <-s.done:
			return
		default:
		}
		// The holder answered and then went, or never answered: one more
		// look, and gone if nobody is there.
		if c, err := ptyDial(s.sock); err != nil {
			hub.drop(s)
			return
		} else {
			c.Close()
		}
		time.Sleep(time.Second)
	}
}

func (hub *ptyHub) startSweep() {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if !hub.sweeping && len(hub.sess) > 0 {
		hub.sweeping = true
		go hub.watch()
	}
}

// mint gives peer a token for s, with the keyboard. Holds hub.mu.
func (hub *ptyHub) mintLocked(s *ptySess, peer key.NodePublic, signer ed25519.PublicKey) (string, error) {
	tok, err := ptyRandHex(16)
	if err != nil {
		return "", err
	}
	hub.toks[tok] = &ptyTok{s: s, peer: peer, signer: signer, gone: make(chan struct{})}
	s.mu.Lock()
	s.owner = tok
	s.mu.Unlock()
	return tok, nil
}

// open starts a shell for peer, sized by the command's target. The caller
// has verified the command's signature and that a key is pinned. Answers the
// token and the session's id, or a refusal code.
func (hub *ptyHub) open(peer key.NodePublic, signer ed25519.PublicKey, target string) (string, string, string) {
	if !consoleEnabled() {
		return "", "", "console-off"
	}
	if !ptySupported {
		return "", "", "pty-unsupported"
	}
	cols, rows, ceil, ok := ptyTarget(target)
	if !ok {
		return "", "", "bad-target"
	}
	hub.adopt()
	dir := hub.holdDir()
	if dir == "" {
		return "", "", "unavailable"
	}
	hub.mu.Lock()
	if len(hub.sess)+hub.pending >= ptyMaxSessions {
		hub.mu.Unlock()
		return "", "", "busy"
	}
	hub.pending++
	keep := hub.keep
	hub.mu.Unlock()
	defer func() {
		hub.mu.Lock()
		hub.pending--
		hub.mu.Unlock()
	}()
	id, err := ptyRandHex(8)
	if err != nil {
		return "", "", "unavailable"
	}
	if err := hub.spawn(dir, id, cols, rows, keep, ceil, signer); err != nil {
		warnf("terminal: could not start a shell: %v", err)
		return "", "", "pty-failed"
	}
	s := &ptySess{id: id, sock: ptyHoldSock(dir, id), signer: signer, at: time.Now(), done: make(chan struct{})}
	hub.mu.Lock()
	hub.sess[id] = s
	tok, err := hub.mintLocked(s, peer, signer)
	n := len(hub.sess)
	hub.mu.Unlock()
	if err != nil {
		hub.end(s)
		return "", "", "unavailable"
	}
	go hub.follow(s)
	warnf("terminal: session opened (%d of %d)", n, ptyMaxSessions)
	hub.startSweep()
	return tok, id, ""
}

// attach hands peer a token for a session that is running: the target is
// the session's id, with the keyboard; or the id and "/w", to watch — the
// keyboard only where nobody else holds it (a page that follows a session
// opened somewhere else must not take the keys from where they are in use).
// `own`, when set, is the only signer whose sessions it may have (a
// portable copy's); `signer` signed the command, and the token lasts while
// that key is trusted. Answers the token and whether the keyboard came with
// it.
func (hub *ptyHub) attach(peer key.NodePublic, target string, own, signer ed25519.PublicKey) (string, bool, string) {
	if !consoleEnabled() {
		return "", false, "console-off"
	}
	sid, watch := strings.CutSuffix(target, "/w")
	if !ptyIDRe.MatchString(sid) {
		return "", false, "bad-target"
	}
	hub.adopt()
	hub.mu.Lock()
	s := hub.sess[sid]
	if s == nil {
		hub.mu.Unlock()
		return "", false, "no-session"
	}
	if own != nil && !own.Equal(s.signer) {
		hub.mu.Unlock()
		return "", false, "not-allowed"
	}
	if watch {
		s.mu.Lock()
		_, held := hub.toks[s.owner]
		s.mu.Unlock()
		if held {
			tok, err := ptyRandHex(16)
			if err == nil {
				hub.toks[tok] = &ptyTok{s: s, peer: peer, signer: signer, gone: make(chan struct{})}
			}
			hub.mu.Unlock()
			if err != nil {
				return "", false, "unavailable"
			}
			return tok, false, ""
		}
	}
	tok, err := hub.mintLocked(s, peer, signer)
	hub.mu.Unlock()
	if err != nil {
		return "", false, "unavailable"
	}
	// A full-screen program draws itself again for the page that just came
	// back: a moment from now, once its stream is likely open.
	go func() {
		time.Sleep(400 * time.Millisecond)
		ptyAsk(s.sock, ptyHoldReq{Op: "nudge"}, nil)
	}()
	return tok, true, ""
}

// watch sweeps every ptySweepEvery until no session is left.
func (hub *ptyHub) watch() {
	t := time.NewTicker(ptySweepEvery)
	defer t.Stop()
	for range t.C {
		hub.sweep(time.Now())
		hub.mu.Lock()
		if len(hub.sess) == 0 {
			hub.sweeping = false
			hub.mu.Unlock()
			return
		}
		hub.mu.Unlock()
	}
}

// drop takes a session off the table without asking its holder (which has
// ended, or is gone). Safe to call twice.
func (hub *ptyHub) drop(s *ptySess) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	close(s.done)
	s.mu.Unlock()
	hub.mu.Lock()
	if hub.sess[s.id] == s {
		delete(hub.sess, s.id)
	}
	for t, k := range hub.toks {
		if k.s == s {
			hub.revokeLocked(t)
		}
	}
	n := len(hub.sess)
	hub.mu.Unlock()
	warnf("terminal: session ended (%d left)", n)
}

// end closes a session: its holder hangs up on the shell and everything it
// started, and every reader here is woken to find it over.
func (hub *ptyHub) end(s *ptySess) {
	hub.drop(s)
	ptyAsk(s.sock, ptyHoldReq{Op: "end"}, nil)
}

func (hub *ptyHub) endAll() {
	hub.mu.Lock()
	all := make([]*ptySess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	hub.mu.Unlock()
	for _, s := range all {
		hub.end(s)
	}
}

// sweep ends what may no longer run: every session once the console is off,
// one whose signing key was unpinned; and lets go of every token whose
// tunnel key left the allowlist or whose command's signing key was
// unpinned, with the streams opened by it. The keep is the holders' own
// clock.
func (hub *ptyHub) sweep(t time.Time) {
	hub.mu.Lock()
	allowed, trusted := hub.allowed, hub.trusted
	all := make([]*ptySess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	for tok, k := range hub.toks {
		if (allowed != nil && !allowed(k.peer)) || (trusted != nil && k.signer != nil && !trusted(k.signer)) {
			hub.revokeLocked(tok)
		}
	}
	hub.mu.Unlock()
	if len(all) == 0 {
		return
	}
	open := consoleEnabled()
	for _, s := range all {
		if !open || (trusted != nil && !trusted(s.signer)) {
			hub.end(s)
		}
	}
}

// setKeep files the relay's word on the keep and passes it to every holder.
func (hub *ptyHub) setKeep(d time.Duration) {
	d = clampKeep(d)
	hub.mu.Lock()
	same := hub.keepSaid && hub.keep == d
	hub.keep, hub.keepSaid = d, true
	all := make([]*ptySess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	persist := hub.persist
	hub.mu.Unlock()
	if same {
		return
	}
	if persist {
		if dir := configDir(); dir != "" {
			writeFileAtomic(filepath.Join(dir, ptyKeepFile), []byte(strconv.FormatInt(int64(d/time.Second), 10)+"\n"))
		}
	}
	for _, s := range all {
		ptyAsk(s.sock, ptyHoldReq{Op: "keep", Keep: int64(d / time.Second)}, nil)
	}
}

// ptyListed is one session as the push lists it: its id (not a token — a
// token is a capability, an id is not), when it opened, until when it lasts
// with nobody watching, and what runs in its foreground.
type ptyListed struct {
	ID    string `json:"id"`
	At    int64  `json:"at"`
	Until int64  `json:"until"`
	Prog  string `json:"prog,omitempty"`
}

// list is the push's view of the table, oldest first.
func (hub *ptyHub) list() []ptyListed {
	hub.adopt()
	hub.mu.Lock()
	all := make([]*ptySess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	hub.mu.Unlock()
	out := make([]ptyListed, 0, len(all))
	for _, s := range all {
		var in ptyHoldInfo
		if err := ptyAsk(s.sock, ptyHoldReq{Op: "info"}, &in); err != nil || in.Ended {
			continue
		}
		out = append(out, ptyListed{ID: s.id, At: in.At, Until: in.Until, Prog: ptyProgClean(in.Prog)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ptyProgClean keeps a program's name to what a card can show: letters,
// digits and . _ + -, at most 32 of them.
func ptyProgClean(s string) string {
	s = strings.TrimPrefix(strings.TrimSpace(s), "-")
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < 32; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '+' || c == '-' {
			b = append(b, c)
		}
	}
	return string(b)
}

// ptyPushList is what a push carries of the terminal: nil (no key) where the
// machine offers no terminal, the list — empty or not — where it does, so a
// page can tell a machine that keeps its sessions from one too old to.
func ptyPushList() *[]ptyListed {
	if !ptySupported || !consoleEnabled() || !loadTrust().sealed {
		return nil
	}
	l := ptySessions.list()
	return &l
}

// find is the token a request names, for the peer that got it and no
// other; a sign of life either way.
func (hub *ptyHub) find(r *http.Request) (string, *ptySess) {
	tok, k := hub.findTok(r)
	if k == nil {
		return "", nil
	}
	return tok, k.s
}

// findTok is find with the token's record, whose `gone` ends a stream.
func (hub *ptyHub) findTok(r *http.Request) (string, *ptyTok) {
	peer, ok := transport.PeerFromContext(r.Context())
	if !ok {
		return "", nil
	}
	tok := r.URL.Query().Get("s")
	if !ptyTokenRe.MatchString(tok) {
		return "", nil
	}
	hub.mu.Lock()
	k := hub.toks[tok]
	hub.mu.Unlock()
	if k == nil || k.peer != peer {
		return "", nil
	}
	s := k.s
	s.mu.Lock()
	ended := s.ended
	beat := !ended && time.Since(s.beatAt) >= ptyBeatEvery
	if beat {
		s.beatAt = time.Now()
	}
	s.mu.Unlock()
	if ended {
		return "", nil
	}
	if beat {
		go ptyAsk(s.sock, ptyHoldReq{Op: "beat"}, nil)
	}
	return tok, k
}

// ptyOut is GET /v1/pty/out?s=…: the shell's output, from the oldest byte
// still held, then as it comes, until the session ends (a clean EOF).
func (h *directHandler) ptyOut(w http.ResponseWriter, r *http.Request) {
	_, k := h.ptys.findTok(r)
	if k == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	s := k.s
	c, err := ptyStream(s.sock, "out")
	if err != nil {
		h.ptys.drop(s)
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	defer c.Close()
	go func() {
		select {
		case <-r.Context().Done():
		case <-s.done:
		case <-k.gone:
		}
		c.Close()
	}()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()
	buf := make([]byte, ptyChunk)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			rc.SetWriteDeadline(time.Now().Add(ptyWriteWait))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if ferr := rc.Flush(); ferr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ptyIn is POST /v1/pty/in?s=…: what is typed, for as long as the body stays
// open. Ends with the body, or with the session; and with "taken" (423) at
// the first bytes typed through a token that no longer has the keyboard —
// never before: on the tunnel's carrier the input stream is one with the
// output, and cutting it would cut the watching too.
func (h *directHandler) ptyIn(w http.ResponseWriter, r *http.Request) {
	tok, k := h.ptys.findTok(r)
	if k == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	s := k.s
	s.mu.Lock()
	if s.inToks[tok] {
		s.mu.Unlock()
		h.refuse(w, http.StatusConflict, "busy")
		return
	}
	if s.inToks == nil {
		s.inToks = map[string]bool{}
	}
	s.inToks[tok] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inToks, tok)
		s.mu.Unlock()
	}()
	c, err := ptyStream(s.sock, "in")
	if err != nil {
		h.ptys.drop(s)
		h.refuse(w, http.StatusGone, "no-session")
		return
	}
	defer c.Close()
	rc := http.NewResponseController(w)
	// Full duplex, and no keep-alive: the answer must be able to go out
	// under a body the browser has not ended, where the server would first
	// try to read the rest of that body and hold the answer until then.
	rc.EnableFullDuplex()
	w.Header().Set("Connection", "close")
	// The tunnel's server gives a request ten seconds to be read; a keyboard
	// is silent for longer than that. No deadline here: what ends a stream
	// nobody is behind is the session's end, which wakes the read below.
	rc.SetReadDeadline(time.Time{})
	errTaken := errors.New("taken")
	errGone := errors.New("gone")
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 8<<10)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				select {
				case <-k.gone:
					result <- errGone
					return
				default:
				}
				s.mu.Lock()
				mine := s.owner == tok
				s.mu.Unlock()
				if !mine {
					result <- errTaken
					return
				}
				c.SetWriteDeadline(time.Now().Add(ptyWriteWait))
				if _, werr := c.Write(buf[:n]); werr != nil {
					result <- werr
					return
				}
			}
			if rerr != nil {
				if rerr == io.EOF {
					rerr = nil
				}
				result <- rerr
				return
			}
		}
	}()
	select {
	case err := <-result:
		// A body that ended is the page letting go; one that broke is
		// not the shell ending, and must not read as that — the page
		// attaches again on anything but "no session".
		select {
		case <-s.done:
			h.refuse(w, http.StatusGone, "no-session")
			return
		default:
		}
		if err == errTaken {
			h.refuse(w, http.StatusLocked, "taken")
			return
		}
		if err == errGone {
			h.refuse(w, http.StatusNotFound, "no-session")
			return
		}
		if err != nil {
			h.refuse(w, http.StatusBadRequest, "stream-broken")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	case <-s.done:
		// The reader is parked in a body read; make it return.
		rc.SetReadDeadline(time.Now())
		h.refuse(w, http.StatusGone, "no-session")
	case <-k.gone:
		// The token was let go (its peer or its signer is no longer
		// trusted): the stream ends with it.
		rc.SetReadDeadline(time.Now())
		h.refuse(w, http.StatusNotFound, "no-session")
	}
}

// ptyResize is POST /v1/pty/resize?s=…&c=…&r=…: the window's new size — and,
// sent with the size it already has, the page's heartbeat. Only the page
// with the keys sets the size; anybody's is a sign of life.
func (h *directHandler) ptyResize(w http.ResponseWriter, r *http.Request) {
	tok, s := h.ptys.find(r)
	if s == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	q := r.URL.Query()
	cols, rows, ok := ptySize(q.Get("c") + "x" + q.Get("r"))
	if !ok {
		h.refuse(w, http.StatusBadRequest, "bad-frame")
		return
	}
	s.mu.Lock()
	mine := s.owner == tok
	s.mu.Unlock()
	req := ptyHoldReq{Op: "beat"}
	if mine {
		req = ptyHoldReq{Op: "resize", Cols: cols, Rows: rows}
	}
	if err := ptyAsk(s.sock, req, nil); err != nil {
		if c, derr := ptyDial(s.sock); derr != nil {
			h.ptys.drop(s)
			h.refuse(w, http.StatusNotFound, "no-session")
			return
		} else {
			c.Close()
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if !mine {
		// Said, so the page knows it watches; the size stays the other's.
		w.Header().Set("X-Pty-Keys", "taken")
	}
	w.WriteHeader(http.StatusNoContent)
}

// ptyClose is POST /v1/pty/close?s=…: the page ending its session.
func (h *directHandler) ptyClose(w http.ResponseWriter, r *http.Request) {
	if _, s := h.ptys.find(r); s != nil {
		h.ptys.end(s)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
