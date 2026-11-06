package main

/* ── read-only grants: another computer reading files here ──

   A copy from this machine to another one of the person's computers can go
   from helper to helper over tailcat, straight from here to there, instead of
   out to DERP, through the page and back (PLAN-files-tailcat-direct.md). The
   computer the files go to (B) pulls them; this one (A) only lets it read.

   What lets it read is a GRANT, in the portable copy's shape (clone.go): the
   page has B make a tailcat node key for the job, signs with its own pinned
   key a grant saying "this node key may read these paths here until then",
   and sends it here as a signed files command. From then until it expires,
   is revoked or the key that signed it is unpinned, that node key passes the
   tunnel's gate, and the tailnet port's where this machine has one (B goes
   there first: tailnet.go), and may do exactly this, and nothing else:

     GET  /v1/hello              who this is (B checks it dialled the right machine)
     POST /v1/files/grant/open   a file under the grant's roots, opened for reading
     POST /v1/files/grant/walk   a folder under them, walked (the tree, for a copy)
     GET  /v1/files/file         a piece of a file it opened
     GET  /v1/files/search       a page of a walk it started
     POST /v1/files/grant/done   the grant ended by the one holding it

   A grant with caps "speed" names no path and reaches none of the files
   above: only the hello, the Speed tab's three paths (speed.go) and its own
   end, for another computer measuring the road to here (speedpeer.go).

   Never /v1/command, never a terminal, never /v1/files/put, never anything a
   watcher reads (the snapshot, the stream, the history, the music): the door
   turns a grant's key away from every other path before any handler sees it
   (directHandler.ServeHTTP).

   The root does not move. trusted-keys, granted at the keyboard, decides who
   may command this machine; a grant counts only while the key that signed it
   is pinned here, and it can only be enrolled by a command that same key
   signed, where the console is on. The console already gives that key a
   shell as this user, so reading a file here is no new power for it; what is
   new is who holds the reading, and that is one node key, for one job, read
   only, inside the roots, for a day at most.

   A path is inside the roots when, links followed, it is one of them or
   below one of them, compared byte for byte (no case folding: on a disk that
   tells case apart that would reach a different folder). The file opened is
   the one the links lead to, so nothing a link swapped in later is read
   through the token.

   Expiry is this machine's to enforce, against its own clock, on every
   request. An expired or revoked key can still finish a WireGuard handshake
   (upstream cannot forget a peer short of a rebuild) and gets nothing past
   the door. */

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	grantSigVersion = "mon-grant-v1"
	grantsFile      = "grants"
	// Ids revoked here, "<id> <unix until>" a line, only ever appended to,
	// for the reason clonesRevokedFile gives.
	grantsRevokedFile = "grants.revoked"
	grantsRevokedMax  = 64 << 10
	// The longest a grant lives, from its signing (operator ruling
	// 2026-11-05: a day at most), and the slack for a page's clock a little
	// ahead.
	grantMaxLife = 24*time.Hour + 10*time.Minute
	// Grants kept at once: a page has two copies running at a time.
	grantsMax = 32
	// Paths one grant may name.
	grantRootsMax = 64
	// A grant rides in a files command's arguments, which the tunnel bounds
	// with the rest of the command at 2000 bytes.
	grantCertMax = 1800
	// What a grant's own requests may carry.
	grantBodyMax = 8 << 10
)

// files-read: the roots, for a copy. speed: no path at all, only the
// Speed tab's three (speed.go), for one computer measuring the road to this
// one (speedpeer.go).
var grantCapsOK = map[string]bool{"files-read": true, "speed": true}

// grantCert is a grant as it travels and as it is kept. Every field but Sig
// is signed (grantSigningInput).
type grantCert struct {
	V     int      `json:"v"`
	ID    string   `json:"id"`
	Agent string   `json:"agent"` // the machine it is for: this one
	NK    string   `json:"nk"`    // the node key it lets in, nodekey:<hex>
	Caps  string   `json:"caps"`  // files-read
	Roots []string `json:"roots"`
	IAT   int64    `json:"iat"`
	EXP   int64    `json:"exp"`
	By    string   `json:"by"` // the pinned key that signed it, base64
	Sig   string   `json:"sig"`
}

func grantSigningInput(c grantCert) []byte {
	var b strings.Builder
	b.WriteString(grantSigVersion)
	b.WriteByte('\n')
	field := func(f string) {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
		b.WriteByte('\n')
	}
	field(c.ID)
	field(c.Agent)
	field(c.NK)
	field(c.Caps)
	// The count first, so a root can never be read as the field after it.
	field(strconv.Itoa(len(c.Roots)))
	for _, r := range c.Roots {
		field(r)
	}
	field(strconv.FormatInt(c.IAT, 10))
	field(strconv.FormatInt(c.EXP, 10))
	field(c.By)
	return []byte(b.String())
}

// grantRootOK: an absolute path written as it cleans to, nothing that could
// be read as two lines or as a different path.
func grantRootOK(r string) bool {
	p, code := musicPathArg(r)
	return code == "" && p == r
}

// parseGrantCert reads one grant and checks its SHAPE only.
func parseGrantCert(text string) (grantCert, bool) {
	var c grantCert
	if text == "" || len(text) > grantCertMax {
		return c, false
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return c, false
	}
	if c.V != 1 || !cloneIDRe.MatchString(c.ID) || !cloneAgentRe.MatchString(c.Agent) || exactKey(c.By) == nil {
		return c, false
	}
	if _, ok := exactNodeKey(c.NK); !ok {
		return c, false
	}
	if !grantCapsOK[c.Caps] || len(c.Roots) > grantRootsMax {
		return c, false
	}
	// A copy reads somewhere; a measurement reads nowhere.
	if (c.Caps == "speed") != (len(c.Roots) == 0) {
		return c, false
	}
	for _, r := range c.Roots {
		if !grantRootOK(r) {
			return c, false
		}
	}
	if c.IAT <= 0 || c.EXP <= c.IAT {
		return c, false
	}
	if sig, err := base64.StdEncoding.DecodeString(c.Sig); err != nil || len(sig) != ed25519.SignatureSize {
		return c, false
	}
	return c, true
}

// activeGrant is a grant that counts here, right now.
type activeGrant struct {
	cert grantCert
	by   ed25519.PublicKey
	node key.NodePublic
}

// checkGrant is the whole verdict on one well-formed grant for this agent at
// this moment; "" means it counts.
func checkGrant(c grantCert, agent string, t trust, now time.Time) (activeGrant, string) {
	var a activeGrant
	if !t.sealed || len(t.keys) == 0 {
		return a, "unpinned"
	}
	by := exactKey(c.By)
	pinned := false
	for _, k := range t.keys {
		if k.Equal(by) {
			pinned = true
			break
		}
	}
	if !pinned {
		return a, "grant-untrusted"
	}
	sig, _ := base64.StdEncoding.DecodeString(c.Sig)
	if !ed25519.Verify(by, grantSigningInput(c), sig) {
		return a, "bad-grant"
	}
	iat, exp := time.Unix(c.IAT, 0), time.Unix(c.EXP, 0)
	if iat.After(now.Add(commandSkew)) {
		return a, "bad-grant"
	}
	if exp.Sub(iat) > grantMaxLife {
		return a, "grant-too-long"
	}
	if !now.Before(exp) {
		return a, "grant-expired"
	}
	if c.Agent != agent {
		return a, "grant-not-here"
	}
	node, _ := exactNodeKey(c.NK)
	return activeGrant{cert: c, by: by, node: node}, ""
}

func grantsPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, grantsFile)
}

func grantsRevokedPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, grantsRevokedFile)
}

func revokedGrants(now time.Time) map[string]bool {
	out := map[string]bool{}
	path := grantsRevokedPath()
	if path == "" {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	body, _ := io.ReadAll(io.LimitReader(f, grantsRevokedMax))
	for _, line := range strings.Split(string(body), "\n") {
		id, until, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !cloneIDRe.MatchString(id) {
			continue
		}
		if n, err := strconv.ParseInt(until, 10, 64); err == nil && now.Unix() < n {
			out[id] = true
		}
	}
	return out
}

// tombstoneGrant: under grantsMu.
func tombstoneGrant(id string, now time.Time) error {
	path := grantsRevokedPath()
	if path == "" {
		return errString("no config directory to write to")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > grantsRevokedMax/2 {
		var b strings.Builder
		for old := range revokedGrants(now) {
			b.WriteString(old + " " + strconv.FormatInt(now.Add(grantMaxLife).Unix(), 10) + "\n")
		}
		if err := writeFileAtomic(path, []byte(b.String())); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(id + " " + strconv.FormatInt(now.Add(grantMaxLife+commandSkew).Unix(), 10) + "\n")
	return err
}

func readGrantCerts() []grantCert {
	path := grantsPath()
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, int64(grantsMax+1)*(grantCertMax+1)))
	if err != nil {
		return nil
	}
	var out []grantCert
	for _, line := range bytes.Split(body, []byte("\n")) {
		if c, ok := parseGrantCert(string(bytes.TrimSpace(line))); ok {
			out = append(out, c)
		}
	}
	return out
}

func writeGrants(certs []grantCert) error {
	path := grantsPath()
	if path == "" {
		return errString("no config directory to write to")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b bytes.Buffer
	for _, c := range certs {
		line, err := json.Marshal(c)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return writeFileAtomic(path, b.Bytes())
}

// activeGrants is what counts here now, read on every call: revoking has to
// be the fast direction.
func activeGrants(agent string, now time.Time) []activeGrant {
	t := loadTrust()
	if !t.sealed {
		return nil
	}
	revoked := revokedGrants(now)
	var out []activeGrant
	for _, c := range readGrantCerts() {
		if revoked[c.ID] {
			continue
		}
		if a, why := checkGrant(c, agent, t, now); why == "" {
			out = append(out, a)
		}
	}
	return out
}

func activeGrantNodes() []key.NodePublic {
	var out []key.NodePublic
	for _, a := range activeGrants(agentID(), time.Now()) {
		out = append(out, a.node)
	}
	return out
}

// grantsForNode is every grant that lets k in now.
func grantsForNode(k key.NodePublic, now time.Time) []activeGrant {
	var out []activeGrant
	for _, a := range activeGrants(agentID(), now) {
		if a.node == k {
			out = append(out, a)
		}
	}
	return out
}

// grantHeld says whether k holds a grant here now. A key no kept grant names
// costs a read of the file and no signature (the tailnet port asks it of every
// key that opens a session there).
func grantHeld(k key.NodePublic) bool {
	named := false
	for _, c := range readGrantCerts() {
		var n key.NodePublic
		if n.UnmarshalText([]byte(c.NK)) == nil && n == k {
			named = true
			break
		}
	}
	return named && len(grantsForNode(k, time.Now())) > 0
}

// grantFor is the grant id, if it lets k in now.
func grantFor(id string, k key.NodePublic, now time.Time) (activeGrant, bool) {
	for _, a := range grantsForNode(k, now) {
		if a.cert.ID == id {
			return a, true
		}
	}
	return activeGrant{}, false
}

// grantLive: what a token opened under a grant is still good for.
func grantLive(id string, k key.NodePublic) bool {
	_, ok := grantFor(id, k, time.Now())
	return ok
}

// enrollGrant keeps a grant that counts here, signed by the key that signed
// the command bringing it, dropping on the way every kept one that no longer
// counts. The same id again replaces it.
// grantsMu orders every change to the grants and their tombstones: each is a
// read, then a rewrite, and two at once would put back what the other took
// out, or drop what it added.
var grantsMu sync.Mutex

func enrollGrant(text, agent string, signer ed25519.PublicKey, now time.Time) (grantCert, string) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	c, ok := parseGrantCert(text)
	if !ok {
		return c, "bad-grant"
	}
	if len(signer) == 0 || !exactKey(c.By).Equal(signer) {
		return c, "grant-untrusted"
	}
	t := loadTrust()
	if _, why := checkGrant(c, agent, t, now); why != "" {
		return c, why
	}
	revoked := revokedGrants(now)
	if revoked[c.ID] {
		return c, "grant-revoked"
	}
	var keep []grantCert
	for _, have := range readGrantCerts() {
		if have.ID == c.ID || revoked[have.ID] {
			continue
		}
		if _, why := checkGrant(have, agent, t, now); why != "" {
			continue
		}
		keep = append(keep, have)
	}
	if len(keep) >= grantsMax {
		return c, "too-many-grants"
	}
	if err := writeGrants(append(keep, c)); err != nil {
		warnf("files: could not keep a grant: %v", err)
		return c, "grant-failed"
	}
	return c, ""
}

// revokeGrant forgets one grant (and every one that no longer counts). The
// tombstone goes first, so the revocation holds whatever else rewrites the
// file at the same moment.
func revokeGrant(id, agent string, now time.Time) error {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	if err := tombstoneGrant(id, now); err != nil {
		return err
	}
	t := loadTrust()
	var keep []grantCert
	found := false
	for _, have := range readGrantCerts() {
		if have.ID == id {
			found = true
			continue
		}
		if _, why := checkGrant(have, agent, t, now); why != "" {
			found = true
			continue
		}
		keep = append(keep, have)
	}
	if !found {
		return nil
	}
	return writeGrants(keep)
}

// grantInside is p with its links followed, when that lies in one of the
// grant's roots (theirs followed too); "" and why when it does not.
func grantInside(roots []string, p string) (string, string) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", "missing"
		case errors.Is(err, fs.ErrPermission):
			return "", "no-access"
		}
		return "", "unavailable"
	}
	for _, r := range roots {
		rr, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if real == rr {
			return real, ""
		}
		rel, err := filepath.Rel(rr, real)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			continue
		}
		return real, ""
	}
	return "", "not-allowed"
}

// runGrantCommand is the A side's two commands: `grant` keeps one, and
// `grant-revoke` ends one. The caller (runFilesCommand) has checked the pin,
// the console and the tunnel.
func runGrantCommand(op string, signer ed25519.PublicKey, a filesArgs) (any, string) {
	now := time.Now()
	switch op {
	case "grant":
		// Nothing can dial a grant's key in here without the tunnel.
		if transportMode() == "relay" || !directEnabled() || directAddress() == "" {
			return nil, "direct-off"
		}
		c, why := enrollGrant(a.Cert, agentID(), signer, now)
		if why != "" {
			return nil, why
		}
		if node, ok := exactNodeKey(c.NK); ok {
			admitNow(node)
		}
		return map[string]any{"id": c.ID, "exp": c.EXP}, ""
	case "grant-revoke":
		if !cloneIDRe.MatchString(a.ID) {
			return nil, "bad-args"
		}
		if err := revokeGrant(a.ID, agentID(), now); err != nil {
			warnf("files: could not revoke a grant: %v", err)
			return nil, "grant-failed"
		}
		return map[string]any{}, ""
	}
	return nil, "unknown-op"
}

// ── the door a grant's key comes through ───────────────────────────────

// grantServe answers a peer the door let in by a grant alone. Every path not
// named here is refused, whatever the mux would have done with it.
func (h *directHandler) grantServe(w http.ResponseWriter, r *http.Request, k key.NodePublic) {
	switch r.URL.Path {
	case "/v1/hello":
		if r.Method != http.MethodGet {
			h.refuse(w, http.StatusMethodNotAllowed, "unknown-frame")
			return
		}
		h.grantHello(w, r)
		return
	case "/v1/files/file", "/v1/files/search":
		if r.Method != http.MethodGet {
			h.refuse(w, http.StatusMethodNotAllowed, "unknown-frame")
			return
		}
		if !filesOn() {
			h.refuse(w, http.StatusNotFound, "console-off")
			return
		}
		if r.URL.Path == "/v1/files/file" {
			h.filesFileFor(w, r, k)
		} else {
			h.filesSearchFor(w, r, k)
		}
		return
	case "/v1/files/grant/open", "/v1/files/grant/walk", "/v1/files/grant/done":
		if r.Method != http.MethodPost {
			h.refuse(w, http.StatusMethodNotAllowed, "unknown-frame")
			return
		}
		h.grantDoor(w, r, k)
		return
	case "/v1/speed/ping", "/v1/speed/down", "/v1/speed/up":
		// Another computer measuring the road to here (speedpeer.go): only
		// under a grant made for that.
		if !grantHasCap(k, "speed") {
			h.refuse(w, http.StatusForbidden, "not-allowed")
			return
		}
		// The console's switch, as for a copy's reads: off, and a grant
		// already given moves nothing more.
		if !filesOn() {
			h.refuse(w, http.StatusNotFound, "console-off")
			return
		}
		h.speedServe(w, r)
		return
	}
	h.refuse(w, http.StatusForbidden, "not-allowed")
}

// grantHasCap says whether one of the grants letting k in now is for caps.
func grantHasCap(k key.NodePublic, caps string) bool {
	for _, a := range grantsForNode(k, time.Now()) {
		if a.cert.Caps == caps {
			return true
		}
	}
	return false
}

// grantHello is the hello a grant's key gets: who this machine is, and no
// capability, since it holds none beyond its grant.
func (h *directHandler) grantHello(w http.ResponseWriter, r *http.Request) {
	f, err := transport.New(transport.TypeHello, agentID(), r.Header.Get("X-Request-Id"), transport.Hello{
		HelperVersion: helperVersion,
		Caps:          []string{},
		Carrier:       grantCarrier(r),
	})
	var b []byte
	if err == nil {
		b, err = transport.Encode(f)
	}
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func grantCarrier(r *http.Request) string {
	if tailnetRequest(r) {
		return "tailnet"
	}
	return "tailcat"
}

type grantReq struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	In   string `json:"in"`
}

func (h *directHandler) grantDoor(w http.ResponseWriter, r *http.Request, k key.NodePublic) {
	body, err := io.ReadAll(io.LimitReader(r.Body, grantBodyMax+1))
	if err != nil || len(body) > grantBodyMax {
		h.refuse(w, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	var q grantReq
	if json.Unmarshal(body, &q) != nil || !cloneIDRe.MatchString(q.ID) {
		h.refuse(w, http.StatusBadRequest, "bad-args")
		return
	}
	g, ok := grantFor(q.ID, k, time.Now())
	// A grant to measure the road opens and walks nothing; it may only end.
	if !ok || (g.cert.Caps != "files-read" && r.URL.Path != "/v1/files/grant/done") {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	var out any
	code := ""
	switch r.URL.Path {
	case "/v1/files/grant/done":
		if err := revokeGrant(g.cert.ID, agentID(), time.Now()); err != nil {
			code = "grant-failed"
		}
		out = map[string]any{}
	case "/v1/files/grant/open":
		if !filesOn() {
			code = "console-off"
			break
		}
		out, code = grantOpen(k, g, q.Path)
	case "/v1/files/grant/walk":
		if !filesOn() {
			code = "console-off"
			break
		}
		out, code = grantWalk(k, g, q.In)
	}
	if code != "" {
		status := http.StatusConflict
		switch code {
		case "not-allowed":
			status = http.StatusForbidden
		case "console-off", "missing":
			status = http.StatusNotFound
		case "busy", "unavailable", "timeout":
			status = http.StatusServiceUnavailable
		}
		h.refuse(w, status, code)
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// grantOpen is a file under the grant's roots, opened for reading by its key
// alone, as filesOpenFile opens one for a browser.
func grantOpen(k key.NodePublic, g activeGrant, raw string) (filesOpenBody, string) {
	p, code := musicPathArg(raw)
	if code != "" {
		return filesOpenBody{}, code
	}
	// Keyed by the grant as well as the path: the look is judged by this
	// grant's roots, and its answer is no other grant's.
	got, code := musicWithin(filesListWait, "grant-open\n"+g.cert.ID+"\n"+p, nil, func() (filesLooked, string) {
		real, code := grantInside(g.cert.Roots, p)
		if code != "" {
			return filesLooked{}, code
		}
		got, code := filesLookAt(real)
		if code != "" {
			return got, code
		}
		// Looked at again once it is open: the file opened must be the one
		// the path inside the roots leads to now, or a link swapped in
		// between the two looks could have led the open elsewhere.
		again, code := grantInside(g.cert.Roots, p)
		if code != "" {
			return filesLooked{}, code
		}
		if fi, err := os.Stat(again); err != nil || !os.SameFile(fi, got.id) {
			return filesLooked{}, "changed"
		}
		return got, ""
	})
	if code != "" {
		return filesOpenBody{}, code
	}
	body, code := filesOpenToken(k, g.by, g.cert.ID, got)
	if code == "" {
		// The name as it was asked for, not where its links lead.
		body.N, body.Path = filepath.Base(p), p
	}
	return body, code
}

// grantWalk is the tree under a folder inside the grant's roots, for a copy
// of a folder, by the same token and pages as a browser's walk.
func grantWalk(k key.NodePublic, g activeGrant, raw string) (map[string]any, string) {
	p, code := musicPathArg(raw)
	if code != "" {
		return nil, code
	}
	real, code := musicWithin(filesListWait, "grant-walk\n"+g.cert.ID+"\n"+p, nil, func() (string, string) { return grantInside(g.cert.Roots, p) })
	if code != "" {
		return nil, code
	}
	tok, code := filesStartWalk(k, g.by, g.cert.ID, real)
	if code != "" {
		return nil, code
	}
	return map[string]any{"t": tok, "page": filesWalkPage, "hits": filesWalkLimit, "secs": int(filesWalkTime / time.Second), "in": real}, ""
}

// grantPost is B's side of a grant's door: one POST, its answer decoded, or
// the machine's error code.
func grantPost(ctx context.Context, hc *http.Client, path string, q grantReq, out any) string {
	b, _ := json.Marshal(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://tailcat"+path, bytes.NewReader(b))
	if err != nil {
		return "unavailable"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "unreachable"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "unreachable"
	}
	if resp.StatusCode != http.StatusOK {
		return frameCode(body, resp.StatusCode)
	}
	if out != nil && json.Unmarshal(body, out) != nil {
		return "bad-frame"
	}
	return ""
}

// frameCode is the code an error frame names, or one made of the status.
func frameCode(body []byte, status int) string {
	if f, err := transport.Decode(body); err == nil && f.Type == transport.TypeError {
		var e transport.Error
		if json.Unmarshal(f.Body, &e) == nil && e.Code != "" {
			return e.Code
		}
	}
	return "status-" + strconv.Itoa(status)
}
