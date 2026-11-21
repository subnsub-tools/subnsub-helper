package main

// host.go — files kept on the primary helper, each with a link that opens
// on the owner's tailnet and nowhere else.
//
// out, the Mac app, keeps a Shelf of files, images and text (put.go carries
// its connections between the owner's Macs). A click there asks this helper,
// on put.sock, to host one item: its bytes go to the primary helper — the
// machine that stays on whether or not this Mac does — which keeps them and
// answers the address they open at:
//
//	http://<the primary's tailnet name or address>:<port>/s/<token>/<name>
//
// served by the listener the tailnet road already has (tailnet.go), which is
// bound to the machine's tailnet address alone. The token is 128 random
// bits and is the whole permission: whoever is on the tailnet and holds the
// link reads the file, as the person who copied the link meant. Nothing else
// on that port answers without a key.
//
// How a Mac reaches the primary. A member never dialed its primary before
// (the primary dials the members, primary.go), so each coordinator round
// asks every member whose hello says "host" for the key it will dial from
// (host-key, one of the delegated kinds) and tells it the primary's tunnel
// address in the same command. The member keeps the address (host-at); the
// primary keeps the key beside the member's roster identity (primary-hosts)
// and admits it to three paths on the tunnel and nothing else:
//
//	GET  /v1/host/have?id=            the link of an item already here
//	POST /v1/host/put?id=&name=&size= its bytes, exactly size of them
//	POST /v1/host/drop?id=            taken down
//
// Any of the owner's Macs may ask for, put or take down any item: an item on
// the Shelf is the same item on all of them.
//
// Files (in the 0700 config dir):
//
//	hosted/index.json  on the primary: [{"id","token","name","size","at","from"}]
//	hosted/<token>     on the primary: one item's bytes, 0600
//	primary-hosts      on the primary: [{"agent","addr","kid","key"}]
//	host-at            on a member: the primary's tunnel address
//
// The primary role ending (primary-off) removes what was hosted with it.
// Off with MON_HOST=off; MON_HOST_MAX_GB is the most the primary keeps (10).

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	hostDirName   = "hosted"
	hostIndexName = "index.json"
	hostAtFile    = "host-at"
	hostKeysFile  = "primary-hosts"
	hostMaxItems  = 400
	hostNameMax   = 200
	// A transfer that has moved nothing for this long is over.
	hostIdle     = time.Minute
	hostDialWait = 25 * time.Second
	hostHavePath = "/v1/host/have"
	hostPutPath  = "/v1/host/put"
	hostDropPath = "/v1/host/drop"
)

var (
	// The most the primary keeps, all items together, unless MON_HOST_MAX_GB
	// says otherwise. A put past it is refused: nothing already linked is
	// let go to make room.
	hostMaxDefault int64 = 10 << 30
	hostIDRE             = regexp.MustCompile(`^[a-z0-9-]{8,64}$`)
	hostTokenRE          = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func hostOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MON_HOST"))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

func hostMaxBytes() int64 {
	if v := strings.TrimSpace(os.Getenv("MON_HOST_MAX_GB")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n <= 4096 {
			return n << 30
		}
	}
	return hostMaxDefault
}

// ── what the primary keeps ───────────────────────────────────────────────

type hostItem struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	At    int64  `json:"at"`
	From  string `json:"from"`
}

// hostState guards the index and counts what is still arriving, so two puts
// at once cannot both be let in under the same room.
var hostState struct {
	sync.Mutex
	pending  int64
	pendingN int
	swept    bool
	// The puts still arriving, by item: a drop marks them, so that bytes
	// which land after it are not kept.
	arriving map[string][]*hostPut
}

type hostPut struct{ dropped bool }

func hostDir() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, hostDirName)
}

func hostLoadLocked() []hostItem {
	dir := hostDir()
	if dir == "" {
		return nil
	}
	var list []hostItem
	if err := readJSONFile(filepath.Join(dir, hostIndexName), &list); err != nil {
		if !os.IsNotExist(err) {
			warnf("host: %s is unreadable; nothing reads as hosted", filepath.Join(dir, hostIndexName))
		}
		return nil
	}
	kept := list[:0]
	for _, it := range list {
		if hostIDRE.MatchString(it.ID) && hostTokenRE.MatchString(it.Token) && it.Size > 0 {
			kept = append(kept, it)
		}
	}
	return kept
}

func hostSaveLocked(list []hostItem) error {
	dir := hostDir()
	if dir == "" {
		return errors.New("no config directory")
	}
	if list == nil {
		list = []hostItem{}
	}
	return writeJSONFile(filepath.Join(dir, hostIndexName), list)
}

// hostName makes what a Mac called a file one path component of at most
// hostNameMax bytes, with nothing a terminal or a header would act on.
func hostName(name string) string {
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > hostNameMax {
			break
		}
		b.WriteRune(r)
	}
	name = strings.TrimSpace(b.String())
	if name == "" || strings.HasPrefix(name, ".") {
		return "file"
	}
	return name
}

// hostEscape percent-encodes all but letters, digits and "-._~": the same
// bytes are right in a link's path and in a header's filename*, and a link
// pasted into a chat does not end early at a bracket or a quote.
func hostEscape(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		}
	}
	return b.String()
}

// hostBase is where links start: the tailnet road's listener, by the
// machine's tailnet name where it has one. No road, no links.
func hostBase() (string, bool) {
	road := tailnetRoadNow()
	// The sealed road answers on any address that looks like a tailnet's,
	// since nothing there rests on the network. A link does: it is given,
	// and answered, only where the address is known to be Tailscale's.
	if road == nil || road.Port <= 0 || !tailnetSure.Load() {
		return "", false
	}
	h := road.Host
	if h == "" {
		h = road.IP
	}
	if h == "" {
		return "", false
	}
	return "http://" + net.JoinHostPort(h, strconv.Itoa(road.Port)), true
}

func hostURL(it hostItem) (string, bool) {
	base, ok := hostBase()
	if !ok {
		return "", false
	}
	return base + "/s/" + it.Token + "/" + hostEscape(it.Name), true
}

// hostFind is the item with this id, while its bytes are still here.
func hostFind(id string) (hostItem, bool) {
	if hostOff() || !primaryIsPrimary() {
		return hostItem{}, false
	}
	hostState.Lock()
	defer hostState.Unlock()
	for _, it := range hostLoadLocked() {
		if it.ID == id {
			if fi, err := os.Stat(filepath.Join(hostDir(), it.Token)); err == nil && fi.Size() == it.Size {
				return it, true
			}
			return hostItem{}, false
		}
	}
	return hostItem{}, false
}

func hostByToken(token string) (hostItem, bool) {
	if !hostTokenRE.MatchString(token) || hostOff() || !primaryIsPrimary() {
		return hostItem{}, false
	}
	hostState.Lock()
	defer hostState.Unlock()
	for _, it := range hostLoadLocked() {
		if hmac.Equal([]byte(it.Token), []byte(token)) {
			return it, true
		}
	}
	return hostItem{}, false
}

// hostSweepLocked removes what an upload cut off by a restart left behind.
func hostSweepLocked() {
	if hostState.swept {
		return
	}
	hostState.swept = true
	dir := hostDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".part-") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// hostAccept keeps size bytes of body as the item id. An item already here
// is answered as it is and body is not read. tick is called as bytes
// arrive, for whoever holds a deadline over the read. The code is "" or why
// not: off, not-primary, bad-args, full, bad-size, dropped, failed.
func hostAccept(id, name string, size int64, from string, body io.Reader, tick func()) (hostItem, string) {
	if hostOff() {
		return hostItem{}, "off"
	}
	if !primaryIsPrimary() {
		return hostItem{}, "not-primary"
	}
	dir := hostDir()
	if dir == "" || !hostIDRE.MatchString(id) || size <= 0 {
		return hostItem{}, "bad-args"
	}
	if it, ok := hostFind(id); ok {
		return it, ""
	}
	most := hostMaxBytes()
	if size > most {
		return hostItem{}, "full"
	}
	hostState.Lock()
	hostSweepLocked()
	list := hostLoadLocked()
	var used int64
	for _, it := range list {
		used += it.Size
	}
	// What is left is worked out first and the size compared with it: a
	// size somebody announced is never added to anything before it is known
	// to fit.
	if len(list)+hostState.pendingN >= hostMaxItems || size > most-used-hostState.pending {
		hostState.Unlock()
		return hostItem{}, "full"
	}
	hostState.pending += size
	hostState.pendingN++
	mine := &hostPut{}
	if hostState.arriving == nil {
		hostState.arriving = map[string][]*hostPut{}
	}
	hostState.arriving[id] = append(hostState.arriving[id], mine)
	hostState.Unlock()
	defer func() {
		hostState.Lock()
		hostState.pending -= size
		hostState.pendingN--
		left := hostState.arriving[id][:0]
		for _, p := range hostState.arriving[id] {
			if p != mine {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			delete(hostState.arriving, id)
		} else {
			hostState.arriving[id] = left
		}
		hostState.Unlock()
	}()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return hostItem{}, "failed"
	}
	var tb [16]byte
	if _, err := rand.Read(tb[:]); err != nil {
		return hostItem{}, "failed"
	}
	token := hex.EncodeToString(tb[:])
	part := filepath.Join(dir, ".part-"+token)
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return hostItem{}, "failed"
	}
	got, code := hostCopy(f, body, size, tick)
	if cerr := f.Close(); cerr != nil && code == "" {
		code = "failed"
	}
	if code == "" && got != size {
		code = "bad-size"
	}
	if code != "" {
		os.Remove(part)
		return hostItem{}, code
	}
	it := hostItem{ID: id, Token: token, Name: hostName(name), Size: size, At: time.Now().Unix(), From: from}
	hostState.Lock()
	defer hostState.Unlock()
	// The role may have ended, or the same item landed from another Mac,
	// while these bytes were arriving.
	if !primaryIsPrimary() {
		os.Remove(part)
		return hostItem{}, "not-primary"
	}
	// Taken down while it was arriving: whoever dropped it was told it is
	// gone, so it does not appear after that.
	if mine.dropped {
		os.Remove(part)
		return hostItem{}, "dropped"
	}
	list = hostLoadLocked()
	kept := list[:0]
	for _, have := range list {
		if have.ID != id {
			kept = append(kept, have)
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, have.Token)); err == nil && fi.Size() == have.Size {
			os.Remove(part)
			return have, ""
		}
		os.Remove(filepath.Join(dir, have.Token))
	}
	if err := os.Rename(part, filepath.Join(dir, token)); err != nil {
		os.Remove(part)
		return hostItem{}, "failed"
	}
	if err := hostSaveLocked(append(kept, it)); err != nil {
		os.Remove(filepath.Join(dir, token))
		return hostItem{}, "failed"
	}
	return it, ""
}

// hostCopy writes what body gives, and at most one byte past size, so more
// than was announced is seen as more rather than read to its end.
func hostCopy(w io.Writer, body io.Reader, size int64, tick func()) (int64, string) {
	buf := make([]byte, 256<<10)
	var got int64
	for {
		if tick != nil {
			tick()
		}
		n, err := body.Read(buf)
		if n > 0 {
			got += int64(n)
			if got > size {
				return got, "bad-size"
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return got, "failed"
			}
		}
		if err == io.EOF {
			return got, ""
		}
		if err != nil {
			return got, "bad-size"
		}
	}
}

// hostDrop takes an item down, and says whether it is: one that is not here
// is down already, and one that could not be taken off the index still
// opens, which whoever asked has to hear.
func hostDrop(id string) bool {
	dir := hostDir()
	if dir == "" {
		return true
	}
	hostState.Lock()
	defer hostState.Unlock()
	for _, p := range hostState.arriving[id] {
		p.dropped = true
	}
	list := hostLoadLocked()
	kept := list[:0]
	var gone []string
	for _, it := range list {
		if it.ID == id {
			gone = append(gone, it.Token)
			continue
		}
		kept = append(kept, it)
	}
	if len(gone) == 0 {
		return true
	}
	if err := hostSaveLocked(kept); err != nil {
		warnf("host: could not take %s down: %v", id, err)
		return false
	}
	for _, token := range gone {
		os.Remove(filepath.Join(dir, token))
	}
	return true
}

// hostClear removes everything hosted and the members' keys: the role ended.
func hostClear() {
	hostState.Lock()
	for _, puts := range hostState.arriving {
		for _, p := range puts {
			p.dropped = true
		}
	}
	if dir := hostDir(); dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			warnf("host: could not remove %s: %v", dir, err)
		}
	}
	hostState.Unlock()
	hostKeysMu.Lock()
	if path := primaryPath(hostKeysFile); path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			warnf("host: could not remove %s: %v", path, err)
		}
	}
	hostKeysMu.Unlock()
}

// ── the link itself, on the tailnet listener ─────────────────────────────

// What a browser may show in place: pictures, sound, video, PDF and plain
// text. Anything else — a page, a script, an archive — is handed over as a
// download, so nothing hosted ever runs under this address.
var hostTypes = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
	".webp": "image/webp", ".avif": "image/avif", ".heic": "image/heic", ".bmp": "image/bmp",
	".tif": "image/tiff", ".tiff": "image/tiff", ".svg": "image/svg+xml",
	".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm",
	".mkv": "video/x-matroska",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".wav": "audio/wav",
	".flac": "audio/flac", ".ogg": "audio/ogg", ".opus": "audio/ogg",
	".pdf": "application/pdf",
	".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
	".log": "text/plain; charset=utf-8", ".csv": "text/plain; charset=utf-8",
	".json": "text/plain; charset=utf-8", ".yaml": "text/plain; charset=utf-8",
	".yml": "text/plain; charset=utf-8",
}

// hostReaders bounds the links being read at once, each of which holds a
// file open; hostWriter gives every piece of an answer hostIdle to leave, so
// a reader that stopped reading does not hold one for ever while a large
// file on a slow road still arrives whole.
var hostReaders = make(chan struct{}, 32)

type hostWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (w *hostWriter) Write(p []byte) (int, error) {
	w.rc.SetWriteDeadline(time.Now().Add(hostIdle))
	return w.ResponseWriter.Write(p)
}

// hostedServe answers GET /s/<token>/<name> on the tailnet listener. The
// token finds the file; the name in the link is for the reader.
func hostedServe(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Only on an address known to be Tailscale's (hostBase): the listener
	// may stand on another network that merely looks like one.
	if !tailnetSure.Load() {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	token, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/s/"), "/")
	it, ok := hostByToken(token)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	select {
	case hostReaders <- struct{}{}:
		defer func() { <-hostReaders }()
	default:
		h.Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	f, err := os.Open(filepath.Join(hostDir(), it.Token))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ext := strings.ToLower(filepath.Ext(it.Name))
	ctype, shown := hostTypes[ext]
	disp := "inline"
	if !shown {
		ctype, disp = "application/octet-stream", "attachment"
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Disposition", disp+"; filename*=UTF-8''"+hostEscape(it.Name))
	if ext == ".svg" {
		// A picture, never a document: no script in it runs.
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'")
	}
	http.ServeContent(&hostWriter{ResponseWriter: w, rc: http.NewResponseController(w)}, r, "", fi.ModTime(), f)
}

// ── the members' keys, on the primary ────────────────────────────────────

type hostMember struct {
	Agent string `json:"agent"`
	Addr  string `json:"addr"`
	Kid   string `json:"kid"`
	Key   string `json:"key"`
}

var hostKeysMu sync.Mutex

func hostMembersLoad() []hostMember {
	path := primaryPath(hostKeysFile)
	if path == "" {
		return nil
	}
	var list []hostMember
	if err := readJSONFile(path, &list); err != nil {
		return nil
	}
	return list
}

// hostMembersLive are the keys that count now: this machine is the primary,
// and the member is on the roster as it was when it gave the key.
func hostMembersLive() []hostMember {
	if hostOff() || !primaryIsPrimary() {
		return nil
	}
	hostKeysMu.Lock()
	list := hostMembersLoad()
	hostKeysMu.Unlock()
	if len(list) == 0 {
		return nil
	}
	roster := map[string]primaryMember{}
	for _, m := range readPrimaryRoster() {
		roster[m.Agent] = m
	}
	var out []hostMember
	for _, e := range list {
		if m, ok := roster[e.Agent]; ok && m.Addr == e.Addr && m.Kid == e.Kid {
			out = append(out, e)
		}
	}
	return out
}

// activeHostNodes are the members' keys the tunnel admits, for the host
// door alone (direct.go Allowed).
func activeHostNodes() []key.NodePublic {
	var out []key.NodePublic
	for _, e := range hostMembersLive() {
		if k, ok := transport.ParseNodeKey(e.Key); ok {
			out = append(out, k)
		}
	}
	return out
}

// hostMemberForNode finds the roster member this peer is, asked per
// request: a member taken off the roster is refused at its next one.
func hostMemberForNode(k key.NodePublic) (string, bool) {
	for _, e := range hostMembersLive() {
		if have, ok := transport.ParseNodeKey(e.Key); ok && have == k {
			return e.Agent, true
		}
	}
	return "", false
}

// primaryHostRound is the round's part in this: every member whose hello
// says host is told where the primary is and asked for the key it will dial
// from. A member that did not answer keeps the key it gave before, for as
// long as its roster identity is the same.
func primaryHostRound(ctx context.Context, sign ed25519.PrivateKey, roster []primaryMember, links []*sweepLink) {
	if hostOff() {
		return
	}
	addr := directAddress()
	if addr == "" {
		return
	}
	cmd, _ := json.Marshal(map[string]string{"a": addr})
	got := map[string]string{}
	for _, l := range links {
		if l.self || l.conn == nil || !l.host {
			continue
		}
		r, err := l.conn.command(ctx, "host-key", "", string(cmd))
		if err != nil || r.Code != 0 {
			continue
		}
		var out struct {
			Key string `json:"key"`
		}
		if json.Unmarshal([]byte(r.Out), &out) != nil {
			continue
		}
		if _, ok := transport.ParseNodeKey(out.Key); !ok {
			continue
		}
		got[l.agent] = out.Key
	}
	hostKeysMu.Lock()
	defer hostKeysMu.Unlock()
	// The role this round began under may have ended meanwhile, or ended
	// and begun again: what it learned is then nobody's. primary-off removes
	// the signing key before it comes for this lock, so a round that still
	// sees its own key here writes before the clearing, never after it.
	if now, err := primarySignKey(); err != nil || now == nil || !now.Equal(sign) {
		return
	}
	old := hostMembersLoad()
	had := map[string]hostMember{}
	for _, e := range old {
		had[e.Agent] = e
	}
	next := []hostMember{}
	self := agentID()
	for _, m := range roster {
		if m.Agent == self {
			continue
		}
		if k, ok := got[m.Agent]; ok {
			next = append(next, hostMember{Agent: m.Agent, Addr: m.Addr, Kid: m.Kid, Key: k})
		} else if e, ok := had[m.Agent]; ok && e.Addr == m.Addr && e.Kid == m.Kid {
			next = append(next, e)
		}
	}
	same := len(old) == len(next)
	for i := 0; same && i < len(next); i++ {
		same = old[i] == next[i]
	}
	if same {
		return
	}
	if err := writeJSONFile(primaryPath(hostKeysFile), next); err != nil {
		warnf("host: could not keep the members' keys: %v", err)
		return
	}
	for _, e := range next {
		if k, ok := transport.ParseNodeKey(e.Key); ok {
			admitNow(k)
		}
	}
}

// hostServe is the only door a member's host key reaches on the primary.
func (h *directHandler) hostServe(w http.ResponseWriter, r *http.Request, agent string) {
	q := r.URL.Query()
	id := strings.ToLower(q.Get("id"))
	if !hostIDRE.MatchString(id) {
		h.refuse(w, http.StatusBadRequest, "bad-args")
		return
	}
	answer := func(v any) {
		b, _ := json.Marshal(v)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == hostHavePath:
		it, ok := hostFind(id)
		if !ok {
			h.refuse(w, http.StatusNotFound, "not-hosted")
			return
		}
		link, ok := hostURL(it)
		if !ok {
			h.refuse(w, http.StatusConflict, "no-tailnet")
			return
		}
		answer(map[string]string{"url": link})
	case r.Method == http.MethodPost && r.URL.Path == hostDropPath:
		if !hostDrop(id) {
			h.refuse(w, http.StatusInternalServerError, "failed")
			return
		}
		answer(map[string]bool{"ok": true})
	case r.Method == http.MethodPost && r.URL.Path == hostPutPath:
		size, err := strconv.ParseInt(q.Get("size"), 10, 64)
		if err != nil || size <= 0 || r.ContentLength != size {
			h.refuse(w, http.StatusBadRequest, "bad-args")
			return
		}
		// Before a byte is taken: a file nobody could be given a link to
		// is not worth carrying here.
		if _, ok := hostBase(); !ok {
			h.refuse(w, http.StatusConflict, "no-tailnet")
			return
		}
		rc := http.NewResponseController(w)
		it, code := hostAccept(id, q.Get("name"), size, agent, r.Body, func() {
			rc.SetReadDeadline(time.Now().Add(hostIdle))
		})
		if code != "" {
			status := http.StatusInternalServerError
			switch code {
			case "full":
				status = http.StatusInsufficientStorage
			case "bad-args", "bad-size":
				status = http.StatusBadRequest
			case "dropped":
				status = http.StatusConflict
			case "off", "not-primary":
				status = http.StatusForbidden
			}
			h.refuse(w, status, code)
			return
		}
		link, ok := hostURL(it)
		if !ok {
			h.refuse(w, http.StatusConflict, "no-tailnet")
			return
		}
		answer(map[string]string{"url": link})
	default:
		h.refuse(w, http.StatusForbidden, "not-allowed")
	}
}

// ── a member's side ──────────────────────────────────────────────────────

// hostClientKey is the key this Mac dials its primary from, out of the seed
// its keys for the other Macs come from (put.go).
func hostClientKey() (key.NodePrivate, error) {
	seed, err := putSeed()
	if err != nil {
		return key.NodePrivate{}, err
	}
	mac := hmac.New(sha256.New, seed)
	io.WriteString(mac, "host client key")
	raw := mac.Sum(nil)
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte("privkey:" + hex.EncodeToString(raw))); err != nil {
		return key.NodePrivate{}, err
	}
	return priv, nil
}

// hostAtRead is the primary's tunnel address as the last host-key gave it,
// or "".
func hostAtRead() string {
	path := primaryPath(hostAtFile)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	addr := strings.TrimSpace(string(b))
	if _, err := tailcat.ParseAddr(tailcat.Addr(addr)); err != nil {
		return ""
	}
	return addr
}

func hostAtClear() {
	if path := primaryPath(hostAtFile); path != "" {
		os.Remove(path)
	}
}

// runHostKey answers a primary's host-key: Cmd {"a": the primary's tunnel
// address}. The address is kept and the key this Mac will dial it from is
// given. Only a verified command gets here, under a pinned key or the
// delegated one.
func runHostKey(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Code: -1}
	if !putSupported {
		res.Error = "unsupported"
		return res
	}
	if hostOff() {
		res.Error = "off"
		return res
	}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	var a struct {
		Addr string `json:"a"`
	}
	if json.Unmarshal([]byte(c.Cmd), &a) != nil {
		res.Error = "bad-args"
		return res
	}
	addr := strings.TrimSpace(a.Addr)
	if _, err := tailcat.ParseAddr(tailcat.Addr(addr)); err != nil || len(addr) > 4<<10 {
		res.Error = "bad-args"
		return res
	}
	priv, err := hostClientKey()
	if err != nil {
		res.Error = "unavailable"
		return res
	}
	path := primaryPath(hostAtFile)
	if path == "" {
		res.Error = "unavailable"
		return res
	}
	if hostAtRead() != addr {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			res.Error = "save-failed"
			return res
		}
		tmp := path + ".new"
		if err := os.WriteFile(tmp, []byte(addr+"\n"), 0o600); err != nil {
			res.Error = "save-failed"
			return res
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			res.Error = "save-failed"
			return res
		}
	}
	text, _ := priv.Public().MarshalText()
	b, _ := json.Marshal(map[string]string{"key": string(text)})
	res.Code, res.Out = 0, string(b)
	return res
}

// hostAvailable: out on this Mac can be given links — this machine is the
// primary, or knows where its primary is.
func hostAvailable() bool {
	return !hostOff() && (primaryIsPrimary() || hostAtRead() != "")
}

// hostRoad is this Mac's way to its primary's host door — the seam the
// socket's side is tested through. Each answers a link or a refusal's code;
// an error means the primary did not answer.
type hostRoad interface {
	have(ctx context.Context, id string) (link, code string, err error)
	put(ctx context.Context, id, name string, size int64, body io.Reader) (link, code string, err error)
	drop(ctx context.Context, id string) (code string, err error)
	Close()
}

// One tunnel to the primary for everything out asks at once: two clients
// under the same key would take each other's place at the relay (put.go
// keeps one per peer for the same reason). It is kept a little while after
// its last use, and not at all once a request on it got no answer — a
// tunnel lost while the Mac slept does not know it is gone.
const hostKeep = 2 * time.Minute

var hostShared struct {
	sync.Mutex
	cur *hostTunnel
}

var hostRoadFor = func(addr string) (hostRoad, error) {
	hostShared.Lock()
	defer hostShared.Unlock()
	if t := hostShared.cur; t != nil && t.addr == addr && !t.stale {
		t.refs++
		if t.idle != nil {
			t.idle.Stop()
			t.idle = nil
		}
		return t, nil
	}
	priv, err := hostClientKey()
	if err != nil {
		return nil, err
	}
	cl := &tailcat.Client{Server: tailcat.ConnBlob(addr), Key: priv, Logf: logger.Discard, DERPMapURL: derpMapURL()}
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return cl.DialTCPPort(ctx, directPort)
		},
		MaxIdleConnsPerHost: 2,
	}}
	if old := hostShared.cur; old != nil {
		old.retireLocked()
	}
	t := &hostTunnel{addr: addr, cl: cl, hc: hc, refs: 1}
	hostShared.cur = t
	return t, nil
}

type hostTunnel struct {
	addr string
	cl   *tailcat.Client
	hc   *http.Client
	// Under hostShared's lock.
	refs  int
	stale bool
	shut  bool
	idle  *time.Timer
}

// retireLocked: no new use; closed once the uses it has are over.
func (t *hostTunnel) retireLocked() {
	t.stale = true
	if t.idle != nil {
		t.idle.Stop()
		t.idle = nil
	}
	if hostShared.cur == t {
		hostShared.cur = nil
	}
	if t.refs <= 0 && !t.shut {
		t.shut = true
		t.hc.CloseIdleConnections()
		t.cl.Close()
	}
}

func (t *hostTunnel) Close() {
	hostShared.Lock()
	defer hostShared.Unlock()
	t.refs--
	if t.refs > 0 {
		return
	}
	if t.stale {
		t.retireLocked()
		return
	}
	t.idle = time.AfterFunc(hostKeep, func() {
		hostShared.Lock()
		defer hostShared.Unlock()
		if t.refs <= 0 {
			t.retireLocked()
		}
	})
}

// silent: a request got no answer at all, so the next one starts afresh.
func (t *hostTunnel) silent() {
	hostShared.Lock()
	t.stale = true
	if hostShared.cur == t {
		hostShared.cur = nil
	}
	hostShared.Unlock()
}

func (t *hostTunnel) do(ctx context.Context, method, path string, q url.Values, body io.Reader, size int64) (link, code string, err error) {
	var rd io.Reader
	if body != nil {
		rd = io.NopCloser(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://tailcat"+path+"?"+q.Encode(), rd)
	if err != nil {
		return "", "", err
	}
	if body != nil {
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := t.hc.Do(req)
	if err != nil {
		t.silent()
		return "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode == http.StatusOK {
		var out struct {
			URL string `json:"url"`
		}
		json.Unmarshal(b, &out)
		return out.URL, "", nil
	}
	if f, derr := transport.Decode(b); derr == nil && f.Type == transport.TypeError {
		var e transport.Error
		if json.Unmarshal(f.Body, &e) == nil && e.Code != "" {
			return "", e.Code, nil
		}
	}
	return "", "refused", nil
}

func (t *hostTunnel) have(ctx context.Context, id string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, hostDialWait)
	defer cancel()
	return t.do(ctx, http.MethodGet, hostHavePath, url.Values{"id": {id}}, nil, 0)
}

func (t *hostTunnel) put(ctx context.Context, id, name string, size int64, body io.Reader) (string, string, error) {
	q := url.Values{"id": {id}, "name": {name}, "size": {strconv.FormatInt(size, 10)}}
	return t.do(ctx, http.MethodPost, hostPutPath, q, body, size)
}

func (t *hostTunnel) drop(ctx context.Context, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, hostDialWait)
	defer cancel()
	_, code, err := t.do(ctx, http.MethodPost, hostDropPath, url.Values{"id": {id}}, nil, 0)
	return code, err
}

// hostFeed is out's bytes on their way through: each read pushes the
// socket's deadline on and says that the transfer still moves.
type hostFeed struct {
	r    io.Reader
	c    net.Conn
	last *atomic.Int64
}

func (f *hostFeed) Read(p []byte) (int, error) {
	f.c.SetReadDeadline(time.Now().Add(hostIdle))
	n, err := f.r.Read(p)
	if f.last != nil {
		f.last.Store(time.Now().UnixNano())
	}
	return n, err
}

// hostLocal answers out on put.sock:
//
//	{"op":"host","id","name","size","have"}  → {"ok":true,"url"} when the
//	    item is hosted already; else, where out has its bytes ("have"),
//	    {"ok":true,"send":true}, then exactly size bytes from out, then
//	    {"ok":true,"url"}. Without the bytes: {"ok":false,"error":"not-hosted"}.
//	{"op":"unhost","id"}                     → {"ok":true}
//
// Refusals: no-primary (this Mac knows of none), unreachable, no-tailnet (the
// primary is on no tailnet, so there is no address to give), full, off,
// bad-args, dropped (taken down while it was arriving), failed.
func hostLocal(c net.Conn, r *bufio.Reader, ask putAsk) {
	defer c.Close()
	fail := func(code string) { putAnswer(c, map[string]any{"ok": false, "error": code}) }
	linked := func(link string) { putAnswer(c, map[string]any{"ok": true, "url": link}) }
	if hostOff() {
		fail("off")
		return
	}
	id := strings.ToLower(ask.ID)
	if !hostIDRE.MatchString(id) || (ask.Op == "host" && ask.Have && ask.Size <= 0) {
		fail("bad-args")
		return
	}
	name := hostName(ask.Name)
	if primaryIsPrimary() {
		// This Mac is the primary: nothing to dial.
		if ask.Op == "unhost" {
			if !hostDrop(id) {
				fail("failed")
				return
			}
			putAnswer(c, map[string]any{"ok": true})
			return
		}
		if _, ok := hostBase(); !ok {
			fail("no-tailnet")
			return
		}
		it, ok := hostFind(id)
		if !ok {
			if !ask.Have {
				fail("not-hosted")
				return
			}
			if putAnswer(c, map[string]any{"ok": true, "send": true}) != nil {
				return
			}
			var code string
			it, code = hostAccept(id, name, ask.Size, agentID(), &hostFeed{r: io.LimitReader(r, ask.Size), c: c}, nil)
			c.SetReadDeadline(time.Time{})
			if code != "" {
				fail(code)
				return
			}
		}
		link, ok := hostURL(it)
		if !ok {
			fail("no-tailnet")
			return
		}
		linked(link)
		return
	}
	addr := hostAtRead()
	if addr == "" {
		fail("no-primary")
		return
	}
	road, err := hostRoadFor(addr)
	if err != nil {
		fail("unavailable")
		return
	}
	defer road.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if ask.Op == "unhost" {
		code, err := road.drop(ctx, id)
		switch {
		case err != nil:
			fail("unreachable")
		case code != "":
			fail(code)
		default:
			putAnswer(c, map[string]any{"ok": true})
		}
		return
	}
	link, code, err := road.have(ctx, id)
	if err != nil {
		fail("unreachable")
		return
	}
	if code == "" && link != "" {
		linked(link)
		return
	}
	if code != "not-hosted" {
		if code == "" {
			code = "failed"
		}
		fail(code)
		return
	}
	if !ask.Have {
		fail("not-hosted")
		return
	}
	if putAnswer(c, map[string]any{"ok": true, "send": true}) != nil {
		return
	}
	// No deadline over the whole transfer, which may be long; one over its
	// silences. The last move is out's last byte, then the primary's answer.
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > 2*hostIdle {
					cancel()
					return
				}
			}
		}
	}()
	link, code, err = road.put(ctx, id, name, ask.Size, &hostFeed{r: io.LimitReader(r, ask.Size), c: c, last: &last})
	close(done)
	c.SetReadDeadline(time.Time{})
	switch {
	case err != nil:
		fail("unreachable")
	case code != "":
		fail(code)
	case link == "":
		fail("failed")
	default:
		linked(link)
	}
}
