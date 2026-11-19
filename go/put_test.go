package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// putFixture is a Mac with put, a pinned key and one allowlisted browser.
type putFixture struct {
	home    string
	h       *directHandler
	browser key.NodePublic
	priv    ed25519.PrivateKey
	n       int
}

func newPutFixture(t *testing.T) *putFixture {
	t.Helper()
	home := scratchHome(t)
	was := putSupported
	putSupported = true
	putReset()
	t.Cleanup(func() { putSupported = was; putReset() })
	f := &putFixture{home: home, h: newDirectHandler(), browser: key.NewNode().Public()}
	if err := allowClient(f.browser.String()); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.priv = priv
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	return f
}

// putReset forgets what an earlier test left in the process.
func putReset() {
	putState.Lock()
	putState.loaded, putState.peers = false, nil
	putState.Unlock()
	putSeedState.Lock()
	putSeedState.seed = nil
	putSeedState.Unlock()
	putLocal.Lock()
	for _, c := range putLocal.accepts {
		c.Close()
	}
	putLocal.accepts = nil
	putLocal.Unlock()
}

func testPutAddr(t *testing.T) string {
	t.Helper()
	ci := &tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: key.NewNode().Public()},
		ServerDiscoPublic: tailcat.DiscoPublic{DiscoPublic: key.NewDisco().Public()},
		RegionID:          tailcfg.DERPRegionID(1),
	}
	return string(ci.Addr())
}

func nodeText(k key.NodePublic) string {
	b, _ := k.MarshalText()
	return string(b)
}

// command sends a signed command through the tunnel's command door, as the
// allowlisted browser.
func (f *putFixture) command(t *testing.T, kind, target, cmd string) consoleResult {
	t.Helper()
	f.n++
	c := signedCmd(t, f.priv, agentID(), consoleCmd{ID: fmt.Sprintf("p%x-%d", time.Now().UnixNano(), f.n), Kind: kind, Target: target, Cmd: cmd})
	fr, _ := transport.New(transport.TypeCommand, "", c.ID, transport.Command{Kind: c.Kind, Cmd: c.Cmd, Target: c.Target, Sig: c.Sig, At: c.IssuedAt})
	body, _ := transport.Encode(fr)
	req := httptest.NewRequest(http.MethodPost, "/v1/command", strings.NewReader(string(body)))
	req = req.WithContext(transport.WithPeer(req.Context(), f.browser))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", kind, rec.Code, rec.Body.String())
	}
	out, err := transport.Decode(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var res consoleResult
	if err := json.Unmarshal(out.Body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func (f *putFixture) addPeer(t *testing.T, agent, name, addr string, node key.NodePublic) consoleResult {
	t.Helper()
	b, _ := json.Marshal(putPeerArgs{Name: name, Addr: addr, Key: nodeText(node)})
	return f.command(t, "put-peer", agent, string(b))
}

// The page computes the same digest (monitor.js putEntryDigest;
// infra/put-digest-unit.mjs holds this vector too).
func TestPutEntryDigestVector(t *testing.T) {
	p := putPeer{Agent: "aaAlpha", Key: "nodekey:1111111111111111111111111111111111111111111111111111111111111111", Addr: "tcA", Name: "Study \u4e66\u623f"}
	if got, want := putEntryDigest(p), "fc307a9e8d898917"; got != want {
		t.Fatalf("digest %s, want %s (agent, key, address and name joined by tabs, a newline at the end)", got, want)
	}
}

func TestPutPeerCommands(t *testing.T) {
	f := newPutFixture(t)
	a, b := key.NewNode().Public(), key.NewNode().Public()
	addrA, addrB := testPutAddr(t), testPutAddr(t)

	r := f.addPeer(t, "macStudy01", "Study", addrA, a)
	if r.Code != 0 || len(r.Out) != 16 {
		t.Fatalf("add: %+v", r)
	}
	if r := f.addPeer(t, "macOffice1", "Office", addrB, b); r.Code != 0 {
		t.Fatalf("add a second: %+v", r)
	}
	if p, ok := putPeerForNode(a); !ok || p.Agent != "macStudy01" || p.Name != "Study" || p.Addr != addrA {
		t.Fatalf("the tunnel does not know the first: %+v %v", p, ok)
	}
	if ks := activePutNodes(); len(ks) != 2 {
		t.Fatalf("admitted keys: %v", ks)
	}
	fi, err := os.Stat(filepath.Join(configDir(), putPeersFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the list is kept 0600: %v %v", fi, err)
	}
	// Read back from the file by a fresh process.
	putState.Lock()
	putState.loaded, putState.peers = false, nil
	putState.Unlock()
	if len(putPeers()) != 2 {
		t.Fatal("the list did not survive a restart")
	}

	// What the page cannot make this machine hold.
	for _, c := range []struct{ what, agent, cmd string }{
		{"itself", agentID(), `{"n":"x","a":"` + addrA + `","k":"` + nodeText(a) + `"}`},
		{"a bad agent id", "no spaces", `{"n":"x","a":"` + addrA + `","k":"` + nodeText(a) + `"}`},
		{"a bad key", "macOther01", `{"n":"x","a":"` + addrA + `","k":"nodekey:zz"}`},
		{"a bad address", "macOther01", `{"n":"x","a":"tc-not-an-address","k":"` + nodeText(a) + `"}`},
		{"a name with a line break", "macOther01", `{"n":"x\ny","a":"` + addrA + `","k":"` + nodeText(a) + `"}`},
		{"a name with a C1 control", "macOther01", `{"n":"x\u0085","a":"` + addrA + `","k":"` + nodeText(a) + `"}`},
		{"a name too long", "macOther01", `{"n":"` + strings.Repeat("x", 65) + `","a":"` + addrA + `","k":"` + nodeText(a) + `"}`},
		{"no JSON", "macOther01", `{`},
	} {
		if r := f.command(t, "put-peer", c.agent, c.cmd); r.Code == 0 {
			t.Errorf("%s was taken: %+v", c.what, r)
		}
	}

	// A changed address replaces the entry; an empty one removes it.
	addrA2 := testPutAddr(t)
	if r := f.addPeer(t, "macStudy01", "Study", addrA2, a); r.Code != 0 {
		t.Fatal(r)
	}
	if p, _ := putPeerByAgent("macStudy01"); p.Addr != addrA2 || len(putPeers()) != 2 {
		t.Fatalf("change: %+v %d", p, len(putPeers()))
	}
	if r := f.command(t, "put-peer", "macStudy01", ""); r.Code != 0 || len(putPeers()) != 1 {
		t.Fatalf("remove: %+v %d", r, len(putPeers()))
	}
	if _, ok := putPeerForNode(a); ok {
		t.Fatal("a removed Mac's key is still admitted")
	}

	// put-peers keeps the listed ones only.
	f.addPeer(t, "macStudy01", "Study", addrA, a)
	r = f.command(t, "put-peers", "", `["macStudy01"]`)
	if r.Code != 0 || len(putPeers()) != 1 || putPeers()[0].Agent != "macStudy01" || r.Out != "1" {
		t.Fatalf("prune: %+v %+v", r, putPeers())
	}

	// put-key: the key this Mac dials each named Mac from, one of its own for
	// each, and the digest of each entry held; never an address.
	r = f.command(t, "put-key", "", `["macStudy01","macOffice1","`+agentID()+`","bad id"]`)
	var got struct {
		Keys map[string]string `json:"keys"`
		Held map[string]string `json:"held"`
	}
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &got) != nil {
		t.Fatalf("put-key: %+v", r)
	}
	k1, _ := putKeyFor("macStudy01")
	k2, _ := putKeyFor("macOffice1")
	if len(got.Keys) != 2 || got.Keys["macStudy01"] != nodeText(k1.Public()) || got.Keys["macOffice1"] != nodeText(k2.Public()) || k1.Public() == k2.Public() {
		t.Fatalf("keys: %v", got.Keys)
	}
	if p, _ := putPeerByAgent("macStudy01"); len(got.Held) != 1 || got.Held["macStudy01"] != putEntryDigest(p) {
		t.Fatalf("held: %v", got.Held)
	}
	if strings.Contains(r.Out, "tc") && strings.Contains(r.Out, addrA[:12]) {
		t.Fatal("an address left by put-key")
	}
	// The keys stay the same across a restart: they come from the seed.
	putSeedState.Lock()
	putSeedState.seed = nil
	putSeedState.Unlock()
	if again, _ := putKeyFor("macStudy01"); again.Public() != k1.Public() {
		t.Fatal("the key changed after a restart")
	}
	// A browser on the list is told the Mac runs put.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
	f.h.ServeHTTP(rec, req.WithContext(transport.WithPeer(req.Context(), f.browser)))
	fr, _ := transport.Decode(rec.Body.Bytes())
	var hello transport.Hello
	json.Unmarshal(fr.Body, &hello)
	has := false
	for _, c := range hello.Caps {
		has = has || c == transport.CapPut
	}
	if !has {
		t.Fatalf("caps: %v", hello.Caps)
	}
}

func TestPutCommandsAreTheTunnelsAlone(t *testing.T) {
	for _, k := range []string{"put-key", "put-peer", "put-peers"} {
		if why := mailboxRefusal(consoleCmd{Kind: k}); why != "tunnel-only" {
			t.Errorf("%s over the relay: %q", k, why)
		}
	}
	// Where put does not run there is nothing to hold.
	f := newPutFixture(t)
	putSupported = false
	if r := f.addPeer(t, "macStudy01", "Study", testPutAddr(t), key.NewNode().Public()); r.Error != "unsupported" {
		t.Fatalf("%+v", r)
	}
}

// A peer's key reaches the stream to put and nothing else.
func TestPutPeerDoor(t *testing.T) {
	f := newPutFixture(t)
	peer := key.NewNode().Public()
	f.addPeer(t, "macStudy01", "Study", testPutAddr(t), peer)
	call := func(method, path string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req.WithContext(transport.WithPeer(req.Context(), peer)))
		return rec
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/hello"}, {"GET", "/v1/snapshot"}, {"GET", "/v1/events"}, {"POST", "/v1/command"},
		{"GET", "/v1/files/file"}, {"GET", "/v1/pty/out?t=x"}, {"GET", putStreamPath},
	} {
		if rec := call(c.method, c.path, nil); rec.Code != http.StatusForbidden || errCodeOf(rec) != "not-allowed" {
			t.Errorf("%s %s as a peer: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if rec := call("GET", putStreamPath, map[string]string{"Upgrade": "put"}); rec.Code != http.StatusServiceUnavailable || errCodeOf(rec) != "put-not-running" {
		t.Fatalf("with put not running: %d %s", rec.Code, rec.Body.String())
	}
	// And the browser on the list does not get a stream either.
	req := httptest.NewRequest("GET", putStreamPath, nil)
	req.Header.Set("Upgrade", "put")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req.WithContext(transport.WithPeer(req.Context(), f.browser)))
	if rec.Code == http.StatusSwitchingProtocols || rec.Code == http.StatusOK {
		t.Fatalf("a browser opened a stream: %d", rec.Code)
	}
}

// The stream is handed to a waiting accept with who it is from, and carries
// bytes both ways.
func TestPutStreamCarriesBytes(t *testing.T) {
	f := newPutFixture(t)
	peer := key.NewNode().Public()
	f.addPeer(t, "macStudy01", "Study", testPutAddr(t), peer)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.h.ServeHTTP(w, r.WithContext(transport.WithPeer(r.Context(), peer)))
	}))
	defer srv.Close()
	local, app := net.Pipe()
	putPark(local)
	defer app.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The request and the first bytes of put's own in one write.
	io.WriteString(c, "GET "+putStreamPath+" HTTP/1.1\r\nHost: tailcat\r\nUpgrade: put\r\nConnection: Upgrade\r\n\r\nhello")
	app.SetDeadline(time.Now().Add(5 * time.Second))
	ar := bufio.NewReader(app)
	line, err := ar.ReadString('\n')
	if err != nil || !strings.Contains(line, `"from":"macStudy01"`) || !strings.Contains(line, `"name":"Study"`) {
		t.Fatalf("header %q %v", line, err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(ar, got); err != nil || string(got) != "hello" {
		t.Fatalf("to put: %q %v", got, err)
	}
	cr := bufio.NewReader(c)
	resp, err := http.ReadResponse(cr, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("answer %v %v", resp, err)
	}
	app.Write([]byte("back"))
	c.SetDeadline(time.Now().Add(5 * time.Second))
	got = make([]byte, 4)
	if _, err := io.ReadFull(cr, got); err != nil || string(got) != "back" {
		t.Fatalf("from put: %q %v", got, err)
	}
	// The peer taken off the list: its stream ends at once.
	if r := f.command(t, "put-peer", "macStudy01", ""); r.Code != 0 {
		t.Fatal(r)
	}
	if _, err := cr.ReadByte(); err == nil {
		t.Fatal("the stream outlived its peer's removal")
	}
	app.Close()
}

func TestPutReadHead(t *testing.T) {
	read := func(s string) (int, bool, string, error) { return putReadHead(bufio.NewReader(strings.NewReader(s))) }
	if st, up, _, err := read("HTTP/1.1 101 Switching Protocols\r\nUpgrade: put\r\nConnection: Upgrade\r\n\r\nbytes"); err != nil || st != 101 || !up {
		t.Fatalf("an upgrade: %d %v %v", st, up, err)
	}
	if _, up, _, _ := read("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); up {
		t.Fatal("an upgrade to something else is not put")
	}
	fr, _ := transport.New(transport.TypeError, "", "", transport.Error{Code: "put-not-running"})
	b, _ := transport.Encode(fr)
	if st, up, code, err := read(fmt.Sprintf("HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\n\r\n%s", len(b), b)); err != nil || st != 503 || up || code != "put-not-running" {
		t.Fatalf("a refusal: %d %v %q %v", st, up, code, err)
	}
	if _, _, _, err := read("HTTP/1.1 101 OK\r\nX: " + strings.Repeat("a", putHeadMax) + "\r\n\r\n"); err == nil {
		t.Fatal("a head without end was read")
	}
	// What follows the head stays for the stream.
	r := bufio.NewReader(strings.NewReader("HTTP/1.1 101 Switching Protocols\r\nUpgrade: put\r\nConnection: upgrade\r\n\r\nrest"))
	putReadHead(r)
	if rest, _ := io.ReadAll(r); string(rest) != "rest" {
		t.Fatalf("after the head: %q", rest)
	}
}

func dialPut(t *testing.T, ask string) (net.Conn, *bufio.Reader, map[string]any) {
	t.Helper()
	c, err := net.Dial("unix", putSockPath())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	io.WriteString(c, ask+"\n")
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("%s: %v", ask, err)
	}
	var out map[string]any
	json.Unmarshal([]byte(line), &out)
	return c, r, out
}

func TestPutLocalSocket(t *testing.T) {
	f := newPutFixture(t)
	f.addPeer(t, "macStudy01", "Study", testPutAddr(t), key.NewNode().Public())
	putLocal.Lock()
	putLocal.on = false
	putLocal.Unlock()
	// An older install's directory, open to others, is closed first.
	os.Chmod(filepath.Dir(putSockPath()), 0o755)
	startPutSocket()
	fi, err := os.Stat(putSockPath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(putSockPath())); di.Mode().Perm() != 0o700 {
		t.Fatalf("directory %v", di.Mode())
	}
	c, _, out := dialPut(t, `{"op":"peers"}`)
	c.Close()
	peers, _ := out["peers"].([]any)
	if out["ok"] != true || len(peers) != 1 || !strings.Contains(fmt.Sprint(peers[0]), "macStudy01") {
		t.Fatalf("peers: %v", out)
	}
	if strings.Contains(fmt.Sprint(out), "tc") && strings.Contains(fmt.Sprint(out), "addr") {
		t.Fatalf("an address reached put: %v", out)
	}
	c, _, out = dialPut(t, `{"op":"open","agent":"nobody00"}`)
	c.Close()
	if out["ok"] != false || out["error"] != "unknown-peer" {
		t.Fatalf("open an unknown Mac: %v", out)
	}
	c, _, out = dialPut(t, `{"op":"fly"}`)
	c.Close()
	if out["error"] != "unknown-op" {
		t.Fatalf("unknown op: %v", out)
	}
}

// Two carriers over a real DERP: put on one Mac opens a stream to put on the
// other through both helpers (here one process plays both).
func TestE2EPutOverTailcat(t *testing.T) {
	if os.Getenv("MON_E2E") == "" {
		t.Skip("set MON_E2E=1 to run against a real DERP")
	}
	f := newPutFixture(t)
	state := filepath.Join(t.TempDir(), "state")
	page := key.NewNode().Public()
	tc, err := transport.StartTailcat(transport.TailcatConfig{
		StateDir: state,
		Port:     directPort,
		Allowed:  func() []key.NodePublic { return append([]key.NodePublic{page}, activePutNodes()...) },
		Handler:  f.h,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	setDirectAdmit(func(k key.NodePublic) {
		if !tc.Known(k) {
			tc.AddAllowed(k)
		}
	})
	t.Cleanup(func() { setDirectAdmit(nil) })
	// The key this process dials "the other Mac" from, as its peer there.
	priv, err := putKeyFor("macOther01")
	if err != nil {
		t.Fatal(err)
	}
	if r := f.addPeer(t, "macOther01", "Other", tc.ConnBlob(), priv.Public()); r.Code != 0 {
		t.Fatal(r)
	}
	putLocal.Lock()
	putLocal.on = false
	putLocal.Unlock()
	startPutSocket()
	// put on "the other Mac" waits for a stream.
	a, _, _ := func() (net.Conn, *bufio.Reader, map[string]any) {
		c, err := net.Dial("unix", putSockPath())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, `{"op":"accept"}`+"\n")
		return c, nil, nil
	}()
	defer a.Close()
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	c, r, out := dialPut(t, `{"op":"open","agent":"macOther01"}`)
	defer c.Close()
	if out["ok"] != true {
		t.Fatalf("open: %v", out)
	}
	t.Logf("open took %s, route %v", time.Since(t0), out["route"])
	io.WriteString(c, "ping")
	a.SetDeadline(time.Now().Add(20 * time.Second))
	ar := bufio.NewReader(a)
	line, err := ar.ReadString('\n')
	if err != nil || !strings.Contains(line, "macOther01") {
		t.Fatalf("header %q %v", line, err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(ar, got); err != nil || string(got) != "ping" {
		t.Fatalf("to the other put: %q %v", got, err)
	}
	a.Write([]byte("pong"))
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "pong" {
		t.Fatalf("back: %q %v", got, err)
	}
}
