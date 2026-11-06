package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// The bytes monitor.js signs (filesGrantInput). Pinned so a change on either
// side fails here before it fails in somebody's browser; infra/
// files-grant-sig-unit.mjs pins the same string for the page.
func TestGrantSigningInputIsPinned(t *testing.T) {
	c := grantCert{ID: "0123456789abcdef", Agent: "ag", NK: "nodekey:00", Caps: "files-read",
		Roots: []string{"/a b", "/\u7b14"}, IAT: 1, EXP: 2, By: "BY"}
	want := "mon-grant-v1\n16:0123456789abcdef\n2:ag\n10:nodekey:00\n10:files-read\n1:2\n4:/a b\n4:/\u7b14\n1:1\n1:2\n2:BY\n"
	if got := string(grantSigningInput(c)); got != want {
		t.Fatalf("signing input\n got %q\nwant %q", got, want)
	}
}

// A machine whose tunnel is up, with the files fixture's pinned key and
// allowlisted browser.
func newGrantFixture(t *testing.T) *filesFixture {
	t.Helper()
	f := newWriteFixture(t)
	if err := setDirect(true); err != nil {
		t.Fatal(err)
	}
	setDirectAddress("tcTESTADDRESSFORAGRANT00")
	t.Cleanup(func() { setDirectAddress("") })
	return f
}

var grantSeq int

func newGrantID() string {
	grantSeq++
	return fmt.Sprintf("%016x", time.Now().UnixNano()+int64(grantSeq))
}

func signGrant(c grantCert, signer ed25519.PrivateKey) grantCert {
	c.V = 1
	c.Caps = "files-read"
	c.By = base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey))
	c.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, grantSigningInput(c)))
	return c
}

func (f *filesFixture) grantFor(node key.NodePublic, roots ...string) grantCert {
	now := time.Now()
	return signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: roots,
		IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, f.priv)
}

func grantText(c grantCert) string {
	b, _ := json.Marshal(c)
	return string(b)
}

func (f *filesFixture) enrol(t *testing.T, c grantCert) consoleResult {
	t.Helper()
	return f.command(t, f.peer, "grant", map[string]string{"cert": grantText(c)})
}

func TestGrantVerdicts(t *testing.T) {
	f := newGrantFixture(t)
	node := key.NewNode().Public()
	docs := filepath.Join(f.home, "Documents")
	now := time.Now()

	g := f.grantFor(node, docs)
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatalf("a good grant: %+v", r)
	}
	if !containsKey(activeGrantNodes(), node) {
		t.Fatal("an enrolled grant does not let its key in")
	}
	if fi, err := os.Stat(grantsPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("grants file: %v %v", err, fi)
	}

	_, stranger, _ := ed25519.GenerateKey(nil)
	bad := []struct {
		name string
		c    grantCert
		want string
	}{
		{"signed by a key not pinned here", signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: []string{docs}, IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, stranger), "grant-untrusted"},
		{"for another machine", signGrant(grantCert{ID: newGrantID(), Agent: "elsewhere", NK: node.String(), Roots: []string{docs}, IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, f.priv), "grant-not-here"},
		{"longer than a day", signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: []string{docs}, IAT: now.Unix(), EXP: now.Add(25 * time.Hour).Unix()}, f.priv), "grant-too-long"},
		{"run out", signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: []string{docs}, IAT: now.Add(-2 * time.Hour).Unix(), EXP: now.Add(-time.Hour).Unix()}, f.priv), "grant-expired"},
		{"a root not written as it cleans", signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: []string{docs + "/../Work"}, IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, f.priv), "bad-grant"},
		{"a relative root", signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: []string{"Documents"}, IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, f.priv), "bad-grant"},
		{"no root", signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, f.priv), "bad-grant"},
	}
	for _, b := range bad {
		if r := f.enrol(t, b.c); r.Error != b.want {
			t.Errorf("%s: %+v, want %s", b.name, r, b.want)
		}
	}
	tampered := f.grantFor(node, docs)
	tampered.Roots = []string{f.home}
	if r := f.enrol(t, tampered); r.Error != "bad-grant" {
		t.Errorf("a grant whose roots were widened after signing: %+v", r)
	}

	// Signed by one pinned key, brought by a command another signed.
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub2)); err != nil {
		t.Fatal(err)
	}
	other := signGrant(grantCert{ID: newGrantID(), Agent: agentID(), NK: node.String(), Roots: []string{docs}, IAT: now.Unix(), EXP: now.Add(time.Hour).Unix()}, priv2)
	if r := f.enrol(t, other); r.Error != "grant-untrusted" {
		t.Errorf("a grant brought by a command another key signed: %+v", r)
	}

	// Revoked: gone, and never again under that id.
	if r := f.command(t, f.peer, "grant-revoke", map[string]string{"id": g.ID}); r.Code != 0 {
		t.Fatalf("revoke: %+v", r)
	}
	if containsKey(activeGrantNodes(), node) {
		t.Fatal("a revoked grant still lets its key in")
	}
	if r := f.enrol(t, g); r.Error != "grant-revoked" {
		t.Fatalf("a revoked grant enrolled again: %+v", r)
	}

	// Its signing key unpinned: every grant it signed is over.
	g2 := f.grantFor(node, docs)
	if r := f.enrol(t, g2); r.Code != 0 {
		t.Fatal(r)
	}
	if err := untrustKey(base64.StdEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	if containsKey(activeGrantNodes(), node) {
		t.Fatal("a grant outlived the key that signed it")
	}
}

func TestGrantNeedsTheTunnel(t *testing.T) {
	f := newGrantFixture(t)
	setDirectAddress("")
	if r := f.enrol(t, f.grantFor(key.NewNode().Public(), f.home)); r.Error != "direct-off" {
		t.Fatalf("a grant with no tunnel to dial: %+v", r)
	}
}

func containsKey(ks []key.NodePublic, k key.NodePublic) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

// grantCall is one request as a grant's key.
func (f *filesFixture) grantCall(t *testing.T, node key.NodePublic, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rd)
	req = req.WithContext(transport.WithPeer(req.Context(), node))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func errCodeOf(rec *httptest.ResponseRecorder) string {
	fr, err := transport.Decode(rec.Body.Bytes())
	if err != nil || fr.Type != transport.TypeError {
		return ""
	}
	var e transport.Error
	json.Unmarshal(fr.Body, &e)
	return e.Code
}

func TestGrantDoorIsNarrow(t *testing.T) {
	f := newGrantFixture(t)
	node := key.NewNode().Public()
	docs := filepath.Join(f.home, "Documents")
	g := f.grantFor(node, docs)
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatal(r)
	}

	// Everything a watcher or a console reads or does: refused before any
	// handler, whatever the body says.
	cmdBody := func() []byte {
		c := signedCmd(t, f.priv, agentID(), consoleCmd{ID: "g-sh-1", Kind: "sh", Cmd: "id"})
		fr, _ := transport.New(transport.TypeCommand, "", c.ID, transport.Command{Kind: c.Kind, Cmd: c.Cmd, Sig: c.Sig, At: c.IssuedAt})
		b, _ := transport.Encode(fr)
		return b
	}()
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/snapshot"}, {"GET", "/v1/events"}, {"GET", "/v1/history"},
		{"GET", "/v1/music"}, {"GET", "/v1/music/index"}, {"GET", "/v1/pty/out?t=x"},
		{"POST", "/v1/pty/in?t=x"}, {"POST", "/v1/files/put?s=x&o=0"},
	} {
		rec := f.grantCall(t, node, c.method, c.path, nil)
		if rec.Code != http.StatusForbidden || errCodeOf(rec) != "not-allowed" {
			t.Errorf("%s %s as a grant's key: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/command", bytes.NewReader(cmdBody))
	req = req.WithContext(transport.WithPeer(req.Context(), node))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a signed shell line through a grant's key: %d %s", rec.Code, rec.Body.String())
	}

	// Its hello says who this is, and names nothing it may do.
	rec = f.grantCall(t, node, "GET", "/v1/hello", nil)
	fr, err := transport.Decode(rec.Body.Bytes())
	if rec.Code != 200 || err != nil || fr.AgentID != agentID() {
		t.Fatalf("hello: %d %s", rec.Code, rec.Body.String())
	}
	var hello transport.Hello
	json.Unmarshal(fr.Body, &hello)
	if len(hello.Caps) != 0 {
		t.Fatalf("a grant's hello names caps: %v", hello.Caps)
	}

	open := func(id, p string) (filesOpenBody, *httptest.ResponseRecorder) {
		rec := f.grantCall(t, node, "POST", "/v1/files/grant/open", map[string]string{"id": id, "path": p})
		var b filesOpenBody
		json.Unmarshal(rec.Body.Bytes(), &b)
		return b, rec
	}
	ob, rec := open(g.ID, filepath.Join(docs, "notes.txt"))
	if rec.Code != 200 || ob.T == "" || ob.Path != filepath.Join(docs, "notes.txt") {
		t.Fatalf("open inside the root: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.grantCall(t, node, "GET", "/v1/files/file?s="+ob.T+"&o=0&n=100", nil)
	if rec.Code != 200 || rec.Body.String() != "content of Documents/notes.txt" {
		t.Fatalf("a piece: %d %q", rec.Code, rec.Body.String())
	}
	// The token is this key's alone: the browser cannot read with it.
	if rec := f.get(t, "/v1/files/file?s="+ob.T+"&o=0&n=100", &f.peer); rec.Code == 200 {
		t.Fatal("a grant's token read by another peer")
	}
	// …and the browser does not reach the grant's door.
	if rec := f.get(t, "/v1/files/grant/open", &f.peer); rec.Code == 200 {
		t.Fatal("a browser reached the grant door")
	}

	// Outside the root, by name, by .. or by a link: refused.
	if err := os.Symlink(filepath.Join(f.home, "Work", "b", "c", "other.txt"), filepath.Join(docs, "away")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("notes.txt", filepath.Join(docs, "near")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(f.home, "Work", "b", "c", "other.txt"),
		docs + "/../Work/b/c/other.txt",
		filepath.Join(docs, "away"),
		f.home + "/Documents-other",
		"Documents/notes.txt",
	} {
		if _, rec := open(g.ID, p); rec.Code == 200 {
			t.Errorf("open %q outside the root: %s", p, rec.Body.String())
		}
	}
	if ob, rec := open(g.ID, filepath.Join(docs, "near")); rec.Code != 200 || ob.S != int64(len("content of Documents/notes.txt")) {
		t.Fatalf("a link that stays inside: %d %s", rec.Code, rec.Body.String())
	}
	// A grant id that is not this key's.
	other := f.grantFor(key.NewNode().Public(), docs)
	if r := f.enrol(t, other); r.Code != 0 {
		t.Fatal(r)
	}
	if _, rec := open(other.ID, filepath.Join(docs, "notes.txt")); rec.Code != http.StatusForbidden {
		t.Fatalf("another key's grant: %d %s", rec.Code, rec.Body.String())
	}

	// The console off: nothing is read.
	t.Setenv("MON_CONSOLE", "0")
	if _, rec := open(g.ID, filepath.Join(docs, "notes.txt")); errCodeOf(rec) != "console-off" {
		t.Fatalf("open with the console off: %d %s", rec.Code, rec.Body.String())
	}
	t.Setenv("MON_CONSOLE", "1")

	// Revoked: the token it holds reads nothing more, and the door is shut.
	if r := f.command(t, f.peer, "grant-revoke", map[string]string{"id": g.ID}); r.Code != 0 {
		t.Fatal(r)
	}
	if rec := f.grantCall(t, node, "GET", "/v1/files/file?s="+ob.T+"&o=0&n=100", nil); rec.Code == 200 {
		t.Fatal("a revoked grant's token still reads")
	}
	if rec := f.grantCall(t, node, "GET", "/v1/hello", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a revoked grant's key at the door: %d", rec.Code)
	}
}

// A token reads the file it opened, never another put where its name was:
// a file swapped in under the same size and time (or a link swapped into
// its path, leading outside the roots) is refused as changed.
func TestGrantReadsTheFileItOpened(t *testing.T) {
	f := newGrantFixture(t)
	node := key.NewNode().Public()
	docs := filepath.Join(f.home, "Documents")
	g := f.grantFor(node, docs)
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatal(r)
	}
	p := filepath.Join(docs, "same.txt")
	writeFile(t, p, []byte("inside the roots"))
	mod := time.Unix(1700000000, 0)
	os.Chtimes(p, mod, mod)
	rec := f.grantCall(t, node, "POST", "/v1/files/grant/open", map[string]string{"id": g.ID, "path": p})
	var ob filesOpenBody
	if json.Unmarshal(rec.Body.Bytes(), &ob); rec.Code != 200 || ob.T == "" {
		t.Fatalf("open: %d %s", rec.Code, rec.Body.String())
	}
	outside := filepath.Join(f.home, "Work", "secret.txt")
	writeFile(t, outside, []byte("outside same len"))
	os.Chtimes(outside, mod, mod)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
	rec = f.grantCall(t, node, "GET", "/v1/files/file?s="+ob.T+"&o=0&n=100", nil)
	if rec.Code == 200 || errCodeOf(rec) != "changed" {
		t.Fatalf("a link swapped in after the open: %d %q", rec.Code, rec.Body.String())
	}
}

func TestGrantDoneEndsItsOwnGrantOnly(t *testing.T) {
	f := newGrantFixture(t)
	a, b := key.NewNode().Public(), key.NewNode().Public()
	ga, gb := f.grantFor(a, f.home), f.grantFor(b, f.home)
	f.enrol(t, ga)
	f.enrol(t, gb)
	if rec := f.grantCall(t, a, "POST", "/v1/files/grant/done", map[string]string{"id": gb.ID}); rec.Code == 200 {
		t.Fatal("one key ended another's grant")
	}
	if !containsKey(activeGrantNodes(), b) {
		t.Fatal("b's grant is gone")
	}
	if rec := f.grantCall(t, a, "POST", "/v1/files/grant/done", map[string]string{"id": ga.ID}); rec.Code != 200 {
		t.Fatalf("done: %d %s", rec.Code, rec.Body.String())
	}
	if containsKey(activeGrantNodes(), a) {
		t.Fatal("a grant its holder ended still counts")
	}
}

func TestGrantWalkStaysInside(t *testing.T) {
	f := newGrantFixture(t)
	node := key.NewNode().Public()
	g := f.grantFor(node, filepath.Join(f.home, "Work"))
	f.enrol(t, g)
	rec := f.grantCall(t, node, "POST", "/v1/files/grant/walk", map[string]string{"id": g.ID, "in": filepath.Join(f.home, "Work")})
	var started struct {
		T string `json:"t"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &started) != nil || started.T == "" {
		t.Fatalf("walk: %d %s", rec.Code, rec.Body.String())
	}
	var got []string
	from := 0
	deadline := time.Now().Add(10 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("the walk never finished")
		}
		rec := f.grantCall(t, node, "GET", fmt.Sprintf("/v1/files/search?s=%s&from=%d", started.T, from), nil)
		var p filesPage
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatalf("page: %d %s", rec.Code, rec.Body.String())
		}
		for _, h := range p.Hits {
			got = append(got, h.P)
		}
		from = p.Next
		if p.Done {
			break
		}
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "other.txt") || strings.Contains(joined, "Documents") {
		t.Fatalf("walk found %v", got)
	}
	if rec := f.grantCall(t, node, "POST", "/v1/files/grant/walk", map[string]string{"id": g.ID, "in": f.home}); rec.Code == 200 {
		t.Fatal("a walk above the root")
	}
}

func TestGrantCapsInTheHello(t *testing.T) {
	f := newGrantFixture(t)
	rec := f.get(t, "/v1/hello", &f.peer)
	fr, _ := transport.Decode(rec.Body.Bytes())
	var hello transport.Hello
	json.Unmarshal(fr.Body, &hello)
	if !containsStr(hello.Caps, transport.CapFilesGrant) || !containsStr(hello.Caps, transport.CapFilesFetch) {
		t.Fatalf("caps %v", hello.Caps)
	}
	setDirectAddress("")
	rec = f.get(t, "/v1/hello", &f.peer)
	fr, _ = transport.Decode(rec.Body.Bytes())
	hello = transport.Hello{}
	json.Unmarshal(fr.Body, &hello)
	if containsStr(hello.Caps, transport.CapFilesGrant) {
		t.Fatal("files-grant named with no tunnel to be dialled")
	}
}
