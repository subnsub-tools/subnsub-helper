package main

/* ── portable copies of a dashboard ──

   A dashboard can lend its access to a command line for a while. It makes a
   fresh pair of keys — a tailcat node key for the tunnel and an Ed25519 key
   for signing — and signs a CERTIFICATE with its own pinned key saying what
   that pair may do on which machines, and until when. The certificate reaches
   each machine over the tunnel as a `clone` command, signed like any other,
   and from then until it expires the pair is let in: its node key passes the
   tunnel's gate, and the shell lines and terminals it signs run. Nothing else
   — a copy cannot rename, update, enroll, allow or trust anything, and it
   cannot make another copy.

   The root does not move. trusted-keys, granted at the keyboard, still decides
   who may command this machine: a certificate counts only while the key that
   signed it is pinned here, so `untrust` ends every copy that key made. A copy
   holds none of the dashboard's own keys, so losing one loses only itself, and
   only until its expiry.

   Expiry is this machine's to enforce, against its own clock, on every request
   (the gate, the command door, the terminal sweep). An expired copy can still
   complete a WireGuard handshake — upstream cannot forget a peer short of a
   rebuild — and gets nothing past the gate. However long a certificate claims,
   no copy lives longer than cloneMaxLife from the moment it was signed.

   The certificate is signed over length-prefixed fields exactly as a command
   is (signing.go says why the prefixes matter); monitor.js builds the same
   bytes. Its JSON form is what travels and what is kept, one per line, in
   the clones file. */

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	cloneSigVersion = "mon-clone-v1"
	clonesFile      = "clones"
	// Ids revoked here, one "<id> <unix until>" per line, appended and never
	// rewritten by a reader: what makes a revocation stick when a revoke at
	// the keyboard and an enrolment over the tunnel rewrite the clones file at
	// the same moment (the enrolment could write back the
	// copy the revoke had just removed). A revoked id never counts again,
	// whatever the clones file says.
	clonesRevokedFile = "clones.revoked"
	clonesRevokedMax  = 64 << 10
	// The longest any copy lives, measured from its signing: the dashboard
	// offers an hour, a day or a week, and the slack is for a clock that is a
	// little ahead of this machine's.
	cloneMaxLife = 7*24*time.Hour + 10*time.Minute
	// Copies kept at once. A dashboard issues a handful; more than this is
	// something other than a person pressing a button.
	clonesMax = 32
	// A certificate rides in a command's Cmd field, which the tunnel bounds.
	cloneCertMax  = 2000
	cloneLabelMax = 60
	// Agents one certificate may name; "*" names them all.
	cloneScopeMax = 64
)

var (
	cloneIDRe    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	cloneAgentRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	cloneCapsOK  = map[string]bool{"sh": true, "pty": true}
)

// cloneCert is a certificate as it travels and as it is kept. Every field but
// Sig is signed (cloneSigningInput); By names the pinned key that signed it,
// and is believed only if it is pinned here.
type cloneCert struct {
	V     int    `json:"v"`
	ID    string `json:"id"`
	SK    string `json:"sk"`  // the copy's Ed25519 public key, base64
	NK    string `json:"nk"`  // the copy's tailcat node key, nodekey:<hex>
	IAT   int64  `json:"iat"` // signed at, unix seconds
	EXP   int64  `json:"exp"` // good until, unix seconds
	Scope string `json:"scope"`
	Caps  string `json:"caps"`
	Label string `json:"label,omitempty"`
	By    string `json:"by"`
	Sig   string `json:"sig"`
}

func cloneSigningInput(c cloneCert) []byte {
	var b strings.Builder
	b.WriteString(cloneSigVersion)
	b.WriteByte('\n')
	for _, f := range []string{c.ID, c.SK, c.NK, strconv.FormatInt(c.IAT, 10), strconv.FormatInt(c.EXP, 10), c.Scope, c.Caps, c.Label, c.By} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// exactKey is a base64 Ed25519 public key with nothing around it — stricter
// than parsePublicKey, which allows the trusted-keys file's trailing labels.
func exactKey(s string) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != s {
		return nil
	}
	return ed25519.PublicKey(raw)
}

func exactNodeKey(s string) (key.NodePublic, bool) {
	if strings.ContainsAny(s, " \t#") {
		return key.NodePublic{}, false
	}
	return transport.ParseNodeKey(s)
}

func cloneCapsOf(s string) []string {
	if s == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range strings.Split(s, ",") {
		if !cloneCapsOK[c] || seen[c] {
			return nil
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

func cloneScopeOK(s string) bool {
	if s == "*" {
		return true
	}
	parts := strings.Split(s, ",")
	if len(parts) == 0 || len(parts) > cloneScopeMax {
		return false
	}
	for _, p := range parts {
		if !cloneAgentRe.MatchString(p) {
			return false
		}
	}
	return true
}

func cloneInScope(scope, agent string) bool {
	if scope == "*" {
		return true
	}
	for _, p := range strings.Split(scope, ",") {
		if p == agent {
			return true
		}
	}
	return false
}

func cloneLabelOK(s string) bool {
	if len(s) > cloneLabelMax || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// parseCloneCert reads one certificate and checks its SHAPE: nothing here
// says whether it is trusted, current or meant for this machine.
func parseCloneCert(text string) (cloneCert, bool) {
	var c cloneCert
	if text == "" || len(text) > cloneCertMax {
		return c, false
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return c, false
	}
	if c.V != 1 || !cloneIDRe.MatchString(c.ID) || exactKey(c.SK) == nil || exactKey(c.By) == nil {
		return c, false
	}
	if _, ok := exactNodeKey(c.NK); !ok {
		return c, false
	}
	if c.IAT <= 0 || c.EXP <= c.IAT || !cloneScopeOK(c.Scope) || cloneCapsOf(c.Caps) == nil || !cloneLabelOK(c.Label) {
		return c, false
	}
	if sig, err := base64.StdEncoding.DecodeString(c.Sig); err != nil || len(sig) != ed25519.SignatureSize {
		return c, false
	}
	return c, true
}

// activeClone is a certificate that counts here, right now.
type activeClone struct {
	cert cloneCert
	sign ed25519.PublicKey
	node key.NodePublic
	caps []string
}

func (a activeClone) can(cap string) bool {
	for _, c := range a.caps {
		if c == cap {
			return true
		}
	}
	return false
}

// checkClone is the whole verdict on one well-formed certificate for this
// agent at this moment; "" means it counts. The codes are the dashboard's.
func checkClone(c cloneCert, agent string, t trust, now time.Time) (activeClone, string) {
	var a activeClone
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
		return a, "clone-untrusted"
	}
	sig, _ := base64.StdEncoding.DecodeString(c.Sig)
	if !ed25519.Verify(by, cloneSigningInput(c), sig) {
		return a, "bad-clone"
	}
	iat, exp := time.Unix(c.IAT, 0), time.Unix(c.EXP, 0)
	if iat.After(now.Add(commandSkew)) {
		return a, "bad-clone"
	}
	if exp.Sub(iat) > cloneMaxLife {
		return a, "clone-too-long"
	}
	if !now.Before(exp) {
		return a, "clone-expired"
	}
	if !cloneInScope(c.Scope, agent) {
		return a, "clone-not-here"
	}
	node, _ := exactNodeKey(c.NK)
	return activeClone{cert: c, sign: exactKey(c.SK), node: node, caps: cloneCapsOf(c.Caps)}, ""
}

func clonesPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, clonesFile)
}

func clonesRevokedPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, clonesRevokedFile)
}

// revokedClones is every id revoked here whose tombstone still stands.
func revokedClones(now time.Time) map[string]bool {
	out := map[string]bool{}
	path := clonesRevokedPath()
	if path == "" {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	body, _ := io.ReadAll(io.LimitReader(f, clonesRevokedMax))
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

// tombstoneClone records a revocation, for as long as any certificate with
// that id could still count. One append, which a concurrent writer cannot
// undo.
func tombstoneClone(id string, now time.Time) error {
	path := clonesRevokedPath()
	if path == "" {
		return errString("no config directory to write to")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > clonesRevokedMax/2 {
		// Grown past any real use: start again from the stones still standing.
		var b strings.Builder
		for old := range revokedClones(now) {
			b.WriteString(old + " " + strconv.FormatInt(now.Add(cloneMaxLife).Unix(), 10) + "\n")
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
	_, err = f.WriteString(id + " " + strconv.FormatInt(now.Add(cloneMaxLife+commandSkew).Unix(), 10) + "\n")
	return err
}

// writeFileAtomic writes beside path under a name of its own and renames it
// over: two writers never share a half-written temporary file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// readCloneCerts is every well-formed certificate on file, judged by nothing.
func readCloneCerts() []cloneCert {
	path := clonesPath()
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, int64(clonesMax+1)*(cloneCertMax+1)))
	if err != nil {
		return nil
	}
	var out []cloneCert
	for _, line := range bytes.Split(body, []byte("\n")) {
		if c, ok := parseCloneCert(string(bytes.TrimSpace(line))); ok {
			out = append(out, c)
		}
	}
	return out
}

// activeClones is what counts here now. Read on every call, like the
// allowlist and trusted-keys: revoking has to be the fast direction.
func activeClones(agent string, now time.Time) []activeClone {
	t := loadTrust()
	if !t.sealed {
		return nil
	}
	revoked := revokedClones(now)
	var out []activeClone
	for _, c := range readCloneCerts() {
		if revoked[c.ID] {
			continue
		}
		if a, why := checkClone(c, agent, t, now); why == "" {
			out = append(out, a)
		}
	}
	return out
}

func cloneForNode(k key.NodePublic, agent string, now time.Time) (activeClone, bool) {
	for _, a := range activeClones(agent, now) {
		if a.node == k {
			return a, true
		}
	}
	return activeClone{}, false
}

func activeCloneNodes() []key.NodePublic {
	var out []key.NodePublic
	for _, a := range activeClones(agentID(), time.Now()) {
		out = append(out, a.node)
	}
	return out
}

func cloneSignerActive(pub ed25519.PublicKey) bool {
	if len(pub) == 0 {
		return false
	}
	for _, a := range activeClones(agentID(), time.Now()) {
		if a.sign.Equal(pub) {
			return true
		}
	}
	return false
}

// writeClones replaces the file. Beside it and renamed over it, 0600, for
// the reasons untrustKey gives.
func writeClones(certs []cloneCert) error {
	path := clonesPath()
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

// enrollClone keeps a certificate that counts here, dropping on the way every
// kept one that no longer does. Enrolling the same id again replaces it.
func enrollClone(text, agent string, now time.Time) (cloneCert, string) {
	c, ok := parseCloneCert(text)
	if !ok {
		return c, "bad-clone"
	}
	t := loadTrust()
	if _, why := checkClone(c, agent, t, now); why != "" {
		return c, why
	}
	revoked := revokedClones(now)
	if revoked[c.ID] {
		return c, "clone-revoked"
	}
	var keep []cloneCert
	for _, have := range readCloneCerts() {
		if have.ID == c.ID || revoked[have.ID] {
			continue
		}
		if _, why := checkClone(have, agent, t, now); why != "" {
			continue
		}
		keep = append(keep, have)
	}
	if len(keep) >= clonesMax {
		return c, "too-many-clones"
	}
	if err := writeClones(append(keep, c)); err != nil {
		warnf("clone: could not keep a copy: %v", err)
		return c, "clone-failed"
	}
	return c, ""
}

// revokeClone forgets one certificate, and every expired or untrusted one
// with it. Reports whether the id was there. The tombstone goes first, so the
// revocation holds even if a concurrent enrolment writes the old list back.
func revokeClone(id, agent string, now time.Time) (bool, error) {
	if err := tombstoneClone(id, now); err != nil {
		return false, err
	}
	t := loadTrust()
	found := false
	var keep []cloneCert
	for _, have := range readCloneCerts() {
		if have.ID == id {
			found = true
			continue
		}
		if _, why := checkClone(have, agent, t, now); why != "" {
			continue
		}
		keep = append(keep, have)
	}
	if !found {
		return false, nil
	}
	return true, writeClones(keep)
}

func cloneName(c cloneCert) string {
	if c.Label != "" {
		return strconv.Quote(c.Label) + " (" + c.ID + ")"
	}
	return c.ID
}

// runClone answers the `clone` kind: a dashboard enrolling a copy it signed.
// The caller has verified the command under a PINNED key — a copy's own
// signature is never taken for this kind (verifyCloneCommand) — and this kind
// rides the tunnel only (mailboxRefusal). A copy reaches the machine through
// the tunnel and does nothing but console work, so the tunnel and the
// console are both required; neither is switched on from here.
func runClone(c consoleCmd) consoleResult {
	r := consoleResult{ID: c.ID, Kind: "clone", Code: -1}
	switch {
	case !loadTrust().sealed:
		r.Error = "unpinned"
	case !consoleEnabled():
		r.Error = "console-off"
	case transportMode() == "relay" || !directEnabled():
		r.Error = "direct-off"
	}
	if r.Error != "" {
		return r
	}
	cert, why := enrollClone(c.Cmd, agentID(), time.Now())
	if why != "" {
		r.Error = why
		return r
	}
	if node, ok := exactNodeKey(cert.NK); ok {
		admitNow(node)
	}
	warnf("clone: a dashboard admitted the portable copy %s until %s", cloneName(cert), time.Unix(cert.EXP, 0).Format(time.RFC3339))
	r.Code = 0
	r.Out = cert.ID
	return r
}

// runUnclone answers `unclone`: the dashboard revoking a copy before its
// expiry. Its terminals end at the next sweep (pty.go).
func runUnclone(c consoleCmd) consoleResult {
	r := consoleResult{ID: c.ID, Kind: "unclone", Code: -1}
	if !loadTrust().sealed {
		r.Error = "unpinned"
		return r
	}
	if !cloneIDRe.MatchString(c.Cmd) {
		r.Error = "bad-clone"
		return r
	}
	found, err := revokeClone(c.Cmd, agentID(), time.Now())
	if err != nil {
		warnf("clone: could not revoke a copy: %v", err)
		r.Error = "clone-failed"
		return r
	}
	if found {
		warnf("clone: a dashboard revoked the portable copy %s", c.Cmd)
	}
	// Answered 0 whether or not the copy was here: revoking is idempotent,
	// and a dashboard that never heard the enrolment's answer revokes
	// everywhere the copy might have gone.
	r.Code = 0
	r.Out = c.Cmd
	return r
}

// verifyCloneCommand judges a command that came from a copy's own tunnel
// peer: one of the kinds the certificate grants, signed by the copy's key,
// fresh and unused — the same checks verifyCommand makes for a pinned key,
// against the one key this copy holds.
func verifyCloneCommand(c consoleCmd, agent string, a activeClone, now time.Time) string {
	want := ""
	switch c.Kind {
	case "", "sh":
		want = "sh"
	case "pty":
		want = "pty"
	}
	if want == "" || !a.can(want) {
		return "clone-not-allowed"
	}
	return verifyCommand(c, agent, trust{keys: []ed25519.PublicKey{a.sign}, sealed: true}, now)
}

/* ── at the machine's keyboard ───────────────────────────────────────── */

func runClonesCLI(args []string) int {
	now := time.Now()
	if len(args) >= 1 && (args[0] == "revoke" || args[0] == "remove") {
		if len(args) < 2 || !cloneIDRe.MatchString(args[1]) {
			warnf("say 'clones revoke <id>' — 'clones' lists them")
			return 2
		}
		found, err := revokeClone(args[1], agentID(), now)
		if err != nil {
			warnf("could not revoke that copy: %v", err)
			return 1
		}
		if !found {
			warnf("no copy %s here", args[1])
			return 1
		}
		os.Stdout.WriteString("revoked " + args[1] + "\n")
		return 0
	}
	if len(args) > 0 {
		warnf("usage: subnsub-helper clones [revoke <id>]")
		return 2
	}
	t := loadTrust()
	certs := readCloneCerts()
	if len(certs) == 0 {
		os.Stdout.WriteString("no portable copies admitted here\n")
		return 0
	}
	revoked := revokedClones(now)
	for _, c := range certs {
		state := "active"
		if revoked[c.ID] {
			state = "revoked"
		} else if _, why := checkClone(c, agentID(), t, now); why != "" {
			state = why
		}
		os.Stdout.WriteString(c.ID + "  " + state + "  until " + time.Unix(c.EXP, 0).Format("2006-01-02 15:04") +
			"  " + c.Caps + "  " + strconv.Quote(c.Label) + "\n")
	}
	return 0
}
