package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// A dashboard key, pinned, and a copy it signs.
type cloneFixture struct {
	dashPub  ed25519.PublicKey
	dashPriv ed25519.PrivateKey
	copyPub  ed25519.PublicKey
	copyPriv ed25519.PrivateKey
	node     key.NodePrivate
}

func newCloneFixture(t *testing.T, pin bool) cloneFixture {
	t.Helper()
	var f cloneFixture
	f.dashPub, f.dashPriv, _ = ed25519.GenerateKey(nil)
	f.copyPub, f.copyPriv, _ = ed25519.GenerateKey(nil)
	f.node = key.NewNode()
	if pin {
		if err := trustKey(base64.StdEncoding.EncodeToString(f.dashPub)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f cloneFixture) cert(id string, iat, exp time.Time, scope, caps string, signer ed25519.PrivateKey) cloneCert {
	nk, _ := f.node.Public().MarshalText()
	c := cloneCert{
		V: 1, ID: id,
		SK:  base64.StdEncoding.EncodeToString(f.copyPub),
		NK:  string(nk),
		IAT: iat.Unix(), EXP: exp.Unix(),
		Scope: scope, Caps: caps, Label: "laptop \u00b7 \u7b14\u8bb0\u672c",
		By: base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)),
	}
	c.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, cloneSigningInput(c)))
	return c
}

func certText(c cloneCert) string {
	b, _ := json.Marshal(c)
	return string(b)
}

// The bytes monitor.js signs. Pinned so a change on either side fails here
// before it fails in somebody's browser.
func TestCloneSigningInputIsPinned(t *testing.T) {
	c := cloneCert{ID: "0123456789abcdef", SK: "SK", NK: "nodekey:00", IAT: 1, EXP: 2, Scope: "*", Caps: "pty,sh", Label: "\u7b14", By: "BY"}
	want := "mon-clone-v1\n16:0123456789abcdef\n2:SK\n10:nodekey:00\n1:1\n1:2\n1:*\n6:pty,sh\n3:\u7b14\n2:BY\n"
	if got := string(cloneSigningInput(c)); got != want {
		t.Fatalf("signing input\n got %q\nwant %q", got, want)
	}
}

func TestCloneVerdicts(t *testing.T) {
	scratchHome(t)
	f := newCloneFixture(t, true)
	now := time.Now()
	agent := agentID()
	tr := loadTrust()
	_, stranger, _ := ed25519.GenerateKey(nil)
	cases := []struct {
		name string
		c    cloneCert
		want string
	}{
		{"current", f.cert("0123456789abcdef", now, now.Add(time.Hour), "*", "sh,pty", f.dashPriv), ""},
		{"named here", f.cert("0123456789abcdef", now, now.Add(time.Hour), "other,"+agent, "sh", f.dashPriv), ""},
		{"not here", f.cert("0123456789abcdef", now, now.Add(time.Hour), "other", "sh", f.dashPriv), "clone-not-here"},
		{"expired", f.cert("0123456789abcdef", now.Add(-2*time.Hour), now.Add(-time.Hour), "*", "sh", f.dashPriv), "clone-expired"},
		{"too long", f.cert("0123456789abcdef", now, now.Add(8*24*time.Hour), "*", "sh", f.dashPriv), "clone-too-long"},
		{"from the future", f.cert("0123456789abcdef", now.Add(time.Hour), now.Add(2*time.Hour), "*", "sh", f.dashPriv), "bad-clone"},
		{"signed by a stranger", f.cert("0123456789abcdef", now, now.Add(time.Hour), "*", "sh", stranger), "clone-untrusted"},
	}
	for _, tc := range cases {
		c, ok := parseCloneCert(certText(tc.c))
		if !ok {
			t.Fatalf("%s: did not parse", tc.name)
		}
		if _, why := checkClone(c, agent, tr, now); why != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, why, tc.want)
		}
	}
	// Any field moved after signing breaks the signature.
	c := f.cert("0123456789abcdef", now, now.Add(time.Hour), "*", "sh", f.dashPriv)
	c.Caps = "sh,pty"
	if _, why := checkClone(c, agent, tr, now); why != "bad-clone" {
		t.Errorf("widened caps: %q, want bad-clone", why)
	}
	// Shapes that never parse.
	for name, mut := range map[string]func(*cloneCert){
		"unknown cap":  func(c *cloneCert) { c.Caps = "sh,update" },
		"repeated cap": func(c *cloneCert) { c.Caps = "sh,sh" },
		"bad id":       func(c *cloneCert) { c.ID = "XYZ" },
		"bad scope":    func(c *cloneCert) { c.Scope = "a b" },
		"padded key":   func(c *cloneCert) { c.SK = " " + c.SK },
		"control":      func(c *cloneCert) { c.Label = "a\nb" },
		"version":      func(c *cloneCert) { c.V = 2 },
	} {
		c := f.cert("0123456789abcdef", now, now.Add(time.Hour), "*", "sh", f.dashPriv)
		mut(&c)
		if _, ok := parseCloneCert(certText(c)); ok {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, ok := parseCloneCert(certText(c) + "{}"); ok {
		t.Error("trailing data parsed")
	}
	// Unpinning the dashboard's key ends its copies.
	if err := untrustKey(base64.StdEncoding.EncodeToString(f.dashPub)); err != nil {
		t.Fatal(err)
	}
	ok := f.cert("0123456789abcdef", now, now.Add(time.Hour), "*", "sh", f.dashPriv)
	if _, why := checkClone(ok, agent, loadTrust(), now); why != "unpinned" {
		t.Errorf("after untrust: %q, want unpinned", why)
	}
}

func TestCloneEnrollRevokePrune(t *testing.T) {
	scratchHome(t)
	f := newCloneFixture(t, true)
	now := time.Now()
	agent := agentID()
	a := f.cert("aaaaaaaaaaaaaaaa", now, now.Add(time.Hour), "*", "sh,pty", f.dashPriv)
	if _, why := enrollClone(certText(a), agent, now); why != "" {
		t.Fatalf("enroll: %s", why)
	}
	if fi, err := os.Stat(clonesPath()); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("clones file: %v %v", err, fi)
	}
	got, ok := cloneForNode(f.node.Public(), agent, now)
	if !ok || !got.can("pty") || got.can("update") {
		t.Fatalf("active copy: %+v %v", got, ok)
	}
	if !cloneSignerActive(f.copyPub) {
		t.Error("signer not active")
	}
	// A second copy; the first expires and is dropped on the next write.
	g := newCloneFixture(t, false)
	g.dashPub, g.dashPriv = f.dashPub, f.dashPriv
	b := g.cert("bbbbbbbbbbbbbbbb", now, now.Add(3*time.Hour), "*", "sh", f.dashPriv)
	later := now.Add(2 * time.Hour)
	if _, why := enrollClone(certText(b), agent, later); why != "" {
		t.Fatalf("enroll b: %s", why)
	}
	if n := len(readCloneCerts()); n != 1 {
		t.Errorf("after the first expired: %d kept, want 1", n)
	}
	// Refused enrolments leave the file alone.
	if _, why := enrollClone(certText(f.cert("cccccccccccccccc", now, now.Add(time.Hour), "nobody", "sh", f.dashPriv)), agent, now); why != "clone-not-here" {
		t.Errorf("out of scope: %q", why)
	}
	if found, err := revokeClone("bbbbbbbbbbbbbbbb", agent, later); err != nil || !found {
		t.Fatalf("revoke: %v %v", found, err)
	}
	if _, ok := cloneForNode(g.node.Public(), agent, later); ok {
		t.Error("revoked copy still active")
	}
	if found, _ := revokeClone("bbbbbbbbbbbbbbbb", agent, later); found {
		t.Error("revoked twice")
	}
}

// The tunnel's command door, from a copy's own peer.
func TestCloneCommandsOverTheTunnel(t *testing.T) {
	scratchHome(t)
	t.Setenv("MON_CONSOLE", "1")
	f := newCloneFixture(t, true)
	if err := setDirect(true); err != nil {
		t.Fatal(err)
	}
	agent := agentID()
	now := time.Now()
	h := newDirectHandler()
	// Ids unique to this run: the replay guard is process-wide, and -count
	// would otherwise meet the previous run's ids.
	tag := "-" + strconv.FormatInt(time.Now().UnixNano()%1e12, 36)
	send := func(peer key.NodePublic, id string, cmd transport.Command) *httptest.ResponseRecorder {
		fr, _ := transport.New(transport.TypeCommand, "", id+tag, cmd)
		b, _ := transport.Encode(fr)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/command", strings.NewReader(string(b)))
		h.ServeHTTP(rec, req.WithContext(transport.WithPeer(req.Context(), peer)))
		return rec
	}
	post := func(peer key.NodePublic, id string, cmd transport.Command) consoleResult {
		t.Helper()
		rec := send(peer, id, cmd)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", id, rec.Code, rec.Body.String())
		}
		out, _ := transport.Decode(rec.Body.Bytes())
		var res consoleResult
		json.Unmarshal(out.Body, &res)
		return res
	}
	sign := func(priv ed25519.PrivateKey, id, kind, target, cmd string) transport.Command {
		at := time.Now().Unix()
		sig := ed25519.Sign(priv, commandSigningInput(agent, id+tag, kind, target, at, cmd))
		return transport.Command{Kind: kind, Cmd: cmd, Target: target, Sig: base64.StdEncoding.EncodeToString(sig), At: at}
	}
	dashNode := key.NewNode().Public()
	if err := allowClient(mustText(dashNode)); err != nil {
		t.Fatal(err)
	}
	copyNode := f.node.Public()
	cert := certText(f.cert("dddddddddddddddd", now, now.Add(time.Hour), "*", "sh", f.dashPriv))

	// Not enrolled, the copy's peer is a stranger: the door turns it away
	// before any signature is looked at — even its own certificate.
	if rec := send(copyNode, "c1", sign(f.copyPriv, "c1", "clone", "", cert)); rec.Code != http.StatusForbidden {
		t.Fatalf("unenrolled copy: %d %s", rec.Code, rec.Body.String())
	}
	// The dashboard enrolls it.
	if res := post(dashNode, "c2", sign(f.dashPriv, "c2", "clone", "", cert)); res.Code != 0 || res.Out != "dddddddddddddddd" {
		t.Fatalf("enroll: %+v", res)
	}
	// Now the copy runs a console line, signed with its own key.
	if res := post(copyNode, "c3", sign(f.copyPriv, "c3", "sh", "", "echo copy")); res.Code != 0 || strings.TrimSpace(res.Out) != "copy" {
		t.Fatalf("copy's sh: %+v", res)
	}
	// Its key is not the dashboard's: a dashboard-signed line from the copy's
	// peer, or the copy's signature from another peer, is refused.
	if res := post(copyNode, "c4", sign(f.dashPriv, "c4", "sh", "", "echo x")); res.Error != "bad-signature" {
		t.Errorf("dashboard signature from the copy's peer: %+v", res)
	}
	if res := post(dashNode, "c5", sign(f.copyPriv, "c5", "sh", "", "echo x")); res.Error != "bad-signature" {
		t.Errorf("copy's signature from the dashboard's peer: %+v", res)
	}
	// Kinds the certificate does not grant.
	for i, kind := range []string{"pty", "rename", "allow", "update", "unclone"} {
		id := "k" + string(rune('0'+i))
		if res := post(copyNode, id, sign(f.copyPriv, id, kind, "80x24", "x")); res.Error != "clone-not-allowed" {
			t.Errorf("copy's %s: %+v", kind, res)
		}
	}
	// The copy may read the hello.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
	h.ServeHTTP(rec, req.WithContext(transport.WithPeer(req.Context(), copyNode)))
	if rec.Code != http.StatusOK {
		t.Errorf("copy's hello: %d", rec.Code)
	}
	// The copy cannot enroll another copy, or itself again.
	if res := post(copyNode, "c8", sign(f.copyPriv, "c8", "clone", "", cert)); res.Error != "clone-not-allowed" {
		t.Errorf("copy enrolling: %+v", res)
	}
	// Revoked: back to a stranger at the door.
	if res := post(dashNode, "c6", sign(f.dashPriv, "c6", "unclone", "", "dddddddddddddddd")); res.Code != 0 {
		t.Fatalf("revoke: %+v", res)
	}
	if rec := send(copyNode, "c7", sign(f.copyPriv, "c7", "sh", "", "echo x")); rec.Code != http.StatusForbidden {
		t.Errorf("revoked copy: %d %s", rec.Code, rec.Body.String())
	}
	// The hello names the capability wherever a key is pinned — with the
	// console off too, so a copy can still be revoked — and an enrolment is
	// refused there.
	if !hasCap(h, transport.CapClone) {
		t.Error("hello does not name clone")
	}
	t.Setenv("MON_CONSOLE", "0")
	if !hasCap(h, transport.CapClone) {
		t.Error("hello drops clone with the console off")
	}
	cert2 := certText(f.cert("ffffffffffffffff", now, now.Add(time.Hour), "*", "sh", f.dashPriv))
	if res := post(dashNode, "c9", sign(f.dashPriv, "c9", "clone", "", cert2)); res.Error != "console-off" {
		t.Errorf("enrolment with the console off: %+v", res)
	}
	if res := post(dashNode, "c10", sign(f.dashPriv, "c10", "unclone", "", "ffffffffffffffff")); res.Code != 0 {
		t.Errorf("revoking a copy that never arrived: %+v", res)
	}
}

// A revocation holds even when an enrolment that read the list before it
// writes the old list back afterwards.
func TestCloneRevocationSticks(t *testing.T) {
	scratchHome(t)
	f := newCloneFixture(t, true)
	now := time.Now()
	agent := agentID()
	a := f.cert("1111111111111111", now, now.Add(time.Hour), "*", "sh", f.dashPriv)
	if _, why := enrollClone(certText(a), agent, now); why != "" {
		t.Fatal(why)
	}
	before := readCloneCerts()
	if found, err := revokeClone(a.ID, agent, now); err != nil || !found {
		t.Fatalf("revoke: %v %v", found, err)
	}
	// The racing writer puts the old list back.
	if err := writeClones(before); err != nil {
		t.Fatal(err)
	}
	if _, ok := cloneForNode(f.node.Public(), agent, now); ok {
		t.Fatal("a revoked copy came back")
	}
	if _, why := enrollClone(certText(a), agent, now); why != "clone-revoked" {
		t.Errorf("re-enrolling a revoked id: %q", why)
	}
}

func TestCloneMachineNamesAreNeverGuessed(t *testing.T) {
	a := cloneAccess{blob: cloneBlob{Machines: []cloneMachine{
		{ID: "aaa111", Name: "web"}, {ID: "bbb222", Name: "WEB"}, {ID: "web", Name: "other"},
	}}}
	if m, err := a.machine("web"); err != nil || m.ID != "web" {
		t.Errorf("an exact id wins over names: %v %v", m, err)
	}
	if _, err := a.machine("Web"); err == nil {
		t.Error("two machines named web: one was chosen")
	}
	if m, err := a.machine("bbb"); err != nil || m.ID != "bbb222" {
		t.Errorf("unique id prefix: %v %v", m, err)
	}
}

func hasCap(h *directHandler, want string) bool {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/hello", nil))
	f, _ := transport.Decode(rec.Body.Bytes())
	var hello transport.Hello
	json.Unmarshal(f.Body, &hello)
	for _, c := range hello.Caps {
		if c == want {
			return true
		}
	}
	return false
}

func mustText(k key.NodePublic) string {
	b, _ := k.MarshalText()
	return string(b)
}

// The command line's side: a copy whose keys do not match its certificate
// is refused before anything is dialled.
func TestCloneBlobParse(t *testing.T) {
	scratchHome(t)
	f := newCloneFixture(t, false)
	now := time.Now()
	cert := certText(f.cert("eeeeeeeeeeeeeeee", now, now.Add(time.Hour), "*", "sh,pty", f.dashPriv))
	nk, _ := f.node.MarshalText()
	mk := func(seed []byte, nk string) string {
		b, _ := json.Marshal(cloneBlob{V: 1, Cert: cert, SK: base64.StdEncoding.EncodeToString(seed), NK: nk,
			Machines: []cloneMachine{{ID: "abc123", Name: "mars", Addr: "tcXYZ"}, {ID: "def456", Name: "mini", Addr: "tcABC"}}})
		return cloneBlobPrefix + base64.RawURLEncoding.EncodeToString(b)
	}
	a, err := parseCloneBlob(mk(f.copyPriv.Seed(), string(nk)))
	if err != nil {
		t.Fatalf("good copy: %v", err)
	}
	if m, err := a.machine("MARS"); err != nil || m.ID != "abc123" {
		t.Errorf("by name: %v %v", m, err)
	}
	if m, err := a.machine("def"); err != nil || m.Name != "mini" {
		t.Errorf("by id prefix: %v %v", m, err)
	}
	if _, err := a.machine("m"); err == nil {
		t.Error("ambiguous prefix accepted")
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := parseCloneBlob(mk(other.Seed(), string(nk))); err == nil {
		t.Error("mismatched signing key accepted")
	}
	onk, _ := key.NewNode().MarshalText()
	if _, err := parseCloneBlob(mk(f.copyPriv.Seed(), string(onk))); err == nil {
		t.Error("mismatched tunnel key accepted")
	}
	if _, err := parseCloneBlob("smc1.!!!"); err == nil {
		t.Error("garbage accepted")
	}
}
