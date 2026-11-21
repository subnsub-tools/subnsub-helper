package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveFake is tailscaled's LocalAPI for the serve config: the status, the
// config as stored, its ETag, and the answers a write can be refused with.
type serveFake struct {
	mu       sync.Mutex
	state    string
	statusNo int
	conf     []byte
	etag     int
	getCode  int
	postCode int
	// bump: someone else writes once, just before this helper's first write.
	bump    bool
	posts   int
	ifMatch []string
}

func (f *serveFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/localapi/v0/status":
		if f.statusNo != 0 {
			w.WriteHeader(f.statusNo)
			return
		}
		json.NewEncoder(w).Encode(tsStatusDoc(f.state))
	case "/localapi/v0/serve-config":
		switch r.Method {
		case http.MethodGet:
			if f.getCode != 0 {
				w.WriteHeader(f.getCode)
				return
			}
			w.Header().Set("Etag", strconv.Quote(strconv.Itoa(f.etag)))
			if len(f.conf) == 0 {
				io.WriteString(w, "null")
				return
			}
			w.Write(f.conf)
		case http.MethodPost:
			f.posts++
			f.ifMatch = append(f.ifMatch, r.Header.Get("If-Match"))
			if f.postCode != 0 {
				w.WriteHeader(f.postCode)
				io.WriteString(w, "must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket\n")
				return
			}
			if f.bump {
				f.bump = false
				f.etag++
			}
			if r.Header.Get("If-Match") != strconv.Quote(strconv.Itoa(f.etag)) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			b, _ := io.ReadAll(r.Body)
			f.conf = b
			f.etag++
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *serveFake) doc(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	m := map[string]any{}
	if len(f.conf) > 0 {
		if err := json.Unmarshal(f.conf, &m); err != nil {
			t.Fatalf("stored config: %v", err)
		}
	}
	return m
}

// serveUse points the LocalAPI at f, with a scratch home and no folders
// served, and stops what the test served.
func serveUse(t *testing.T, f *serveFake) string {
	t.Helper()
	home := scratchHome(t)
	dial := tsLocalDial
	tok := tsLocalToken
	serveReset()
	t.Cleanup(func() {
		tsLocalDial, tsLocalToken = dial, tok
		serveReset()
	})
	tsLocalToken = func() string { return "" }
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	tsLocalDial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return home
}

func serveReset() {
	serveOwn.Lock()
	for p, r := range serveOwn.run {
		r.stop()
		delete(serveOwn.run, p)
	}
	serveOwn.items = map[int]serveOwnItem{}
	serveOwn.Unlock()
	serveStats.Lock()
	serveStats.m = nil
	serveStats.Unlock()
}

func serveMkdir(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func serveGet(t *testing.T, url string, method string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// Every handler of a serve config, by port: a folder, a proxy, a text, a TCP
// forward, a funnel, a foreground session's; a service is not a port.
func TestServeItemsOf(t *testing.T) {
	raw := []byte(`{
		"TCP": {"443": {"HTTPS": true}, "8800": {"HTTP": true}, "2222": {"TCPForward": "127.0.0.1:22"}},
		"Web": {
			"web-1.tail1234.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}, "/docs": {"Path": "/srv/docs/"}}},
			"web-1.tail1234.ts.net:8800": {"Handlers": {"/": {"Text": "hello"}}},
			"svc:web": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9"}}}
		},
		"AllowFunnel": {"web-1.tail1234.ts.net:443": true},
		"Foreground": {"abc": {"TCP": {"8810": {"HTTP": true}}, "Web": {"web-1.tail1234.ts.net:8810": {"Handlers": {"/": {"Path": "/tmp/x"}}}}}}
	}`)
	items, ok := serveItemsOf(raw, false)
	if !ok {
		t.Fatal("not read")
	}
	got := map[string]serveItem{}
	for _, it := range items {
		got[strconv.Itoa(it.Port)+it.Route] = it
	}
	if len(items) != 5 {
		t.Fatalf("items: %+v", items)
	}
	if it := got["443/"]; it.Kind != "proxy" || it.Target != "http://127.0.0.1:3000" || !it.HTTPS || !it.Funnel {
		t.Errorf("443/: %+v", it)
	}
	if it := got["443/docs"]; it.Kind != "path" || it.Dir != "/srv/docs" {
		t.Errorf("443/docs: %+v", it)
	}
	if it := got["8800/"]; it.Kind != "text" || it.HTTPS {
		t.Errorf("8800/: %+v", it)
	}
	if it := got["2222"]; it.Kind != "tcp" || it.Target != "127.0.0.1:22" {
		t.Errorf("2222: %+v", it)
	}
	if it := got["8810/"]; it.Kind != "path" || !it.Fg {
		t.Errorf("8810/: %+v", it)
	}
	if items, ok := serveItemsOf([]byte("null"), false); !ok || len(items) != 0 {
		t.Errorf("null: %v %+v", ok, items)
	}
	if _, ok := serveItemsOf([]byte("{"), false); ok {
		t.Error("a broken config read as one")
	}
}

const chartPage = `<html><head><title>  Chart &amp; table
 demo </title><meta property="og:image" content="./shots/a.png?v=2"></head></html>`

// A folder Tailscale serves is listed with what it holds: its page's title,
// its picture, its files; one that is gone says so.
func TestServeListLooksInFolders(t *testing.T) {
	f := &serveFake{state: "Running"}
	home := serveUse(t, f)
	site := filepath.Join(home, "demos", "chart")
	serveMkdir(t, site, map[string]string{
		"index.html":     chartPage,
		"shots/a.png":    "png",
		"app.js":         "1",
		".git/HEAD":      "ref",
		"node_modules/x": "y",
	})
	plain := filepath.Join(home, "demos", "plain")
	serveMkdir(t, plain, map[string]string{"preview.webp": "w", "a.txt": "abc"})
	f.conf = []byte(fmt.Sprintf(`{"TCP":{"8800":{"HTTP":true},"8801":{"HTTP":true},"8802":{"HTTP":true}},"Web":{
		"web-1.tail1234.ts.net:8800":{"Handlers":{"/":{"Path":%q}}},
		"web-1.tail1234.ts.net:8801":{"Handlers":{"/":{"Path":%q}}},
		"web-1.tail1234.ts.net:8802":{"Handlers":{"/":{"Path":%q}}}}}`, site, plain, filepath.Join(home, "gone")))
	out := serveList(context.Background())
	if out.State != "ok" || out.Host != "web-1.tail1234.ts.net" || out.Name != "web-1" || out.IP != "100.91.179.57" {
		t.Fatalf("list: %+v", out)
	}
	if out.Root != filepath.Join(home, "demos") {
		t.Errorf("root %q", out.Root)
	}
	if len(out.Items) != 3 {
		t.Fatalf("items: %+v", out.Items)
	}
	a, b, c := out.Items[0], out.Items[1], out.Items[2]
	if a.Port != 8800 || a.Title != "Chart & table demo" || !a.Index || a.Thumb != filepath.Join(site, "shots", "a.png") || a.Files != 3 || a.Bytes != int64(len("png")+1)+int64(len(chartPage)) {
		t.Errorf("chart: %+v", a)
	}
	if b.Title != "" || b.Index || b.Thumb != filepath.Join(plain, "preview.webp") || b.Files != 2 {
		t.Errorf("plain: %+v", b)
	}
	if !c.Missing {
		t.Errorf("gone: %+v", c)
	}
}

// What a list says when Tailscale is not there to ask, not up, or will not
// show its serve config.
func TestServeListStates(t *testing.T) {
	f := &serveFake{state: "Stopped"}
	serveUse(t, f)
	if s := serveList(context.Background()).State; s != "stopped" {
		t.Errorf("stopped: %q", s)
	}
	f.state = "Running"
	f.getCode = http.StatusForbidden
	if s := serveList(context.Background()).State; s != "denied" {
		t.Errorf("denied: %q", s)
	}
	f.statusNo = http.StatusForbidden
	if s := serveList(context.Background()).State; s != "denied" {
		t.Errorf("status denied: %q", s)
	}
}

// A picture a page names is one inside its folder.
func TestServeInside(t *testing.T) {
	dir := t.TempDir()
	serveMkdir(t, dir, map[string]string{"a.png": "x", "b.txt": "y", "sub/c.jpg": "z"})
	for ref, want := range map[string]string{
		"a.png": filepath.Join(dir, "a.png"), "/sub/c.jpg": filepath.Join(dir, "sub", "c.jpg"), "./a.png#x": filepath.Join(dir, "a.png"),
		"../a.png": "", "b.txt": "", "https://example.com/a.png": "", "//cdn/a.png": "", "data:image/png;base64,AA": "", "missing.png": "",
	} {
		if got := serveInside(dir, ref); got != want {
			t.Errorf("%q: %q, want %q", ref, got, want)
		}
	}
}

// A folder added is served here and proxied there, written under the ETag
// it was read with (read again when someone wrote meanwhile); a port in use
// is refused; it is kept, and served again on a restart.
func TestServeAddStopAndRestart(t *testing.T) {
	f := &serveFake{state: "Running", conf: []byte(`{"TCP":{"443":{"HTTPS":true}},"Web":{"web-1.tail1234.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}},"Services":{"svc:x":{"TCP":{}}},"Future":1}`), bump: true}
	home := serveUse(t, f)
	dir := filepath.Join(home, "demos", "site")
	serveMkdir(t, dir, map[string]string{"index.html": "<title>Site</title>hello", ".env": "SECRET=1", "a/b.txt": "b", "a/.hidden": "h"})
	if err := os.Symlink("../.env", filepath.Join(dir, "a", "link")); err != nil {
		t.Skip("no symlinks here:", err)
	}
	if err := os.Symlink("..", filepath.Join(dir, "a", "dirlink")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	dir, _ = filepath.EvalSymlinks(dir)
	it, code := serveAdd(ctx, dir, 8850)
	if code != "" {
		t.Fatalf("add: %s", code)
	}
	if it.Kind != "folder" || it.Port != 8850 || it.Dir != dir || it.Title != "Site" {
		t.Errorf("added: %+v", it)
	}
	if f.posts != 2 || f.ifMatch[0] != `"0"` || f.ifMatch[1] != `"1"` {
		t.Errorf("writes: %d %v", f.posts, f.ifMatch)
	}
	doc := f.doc(t)
	if doc["Future"] != 1.0 || doc["Services"] == nil {
		t.Errorf("what this helper does not know of was not kept: %v", doc)
	}
	web := doc["Web"].(map[string]any)
	h := web["web-1.tail1234.ts.net:8850"].(map[string]any)["Handlers"].(map[string]any)["/"].(map[string]any)
	proxy, _ := h["Proxy"].(string)
	if !strings.HasPrefix(proxy, "http://127.0.0.1:") || web["web-1.tail1234.ts.net:443"] == nil {
		t.Fatalf("web: %v", web)
	}
	if lp, _ := strconv.Atoi(strings.TrimPrefix(proxy, "http://127.0.0.1:")); lp < serveLocalMin || lp >= serveLocalMin+serveLocalSpan {
		t.Errorf("local port %d is in the range systems hand out", lp)
	}
	if tcp := doc["TCP"].(map[string]any)["8850"].(map[string]any); tcp["HTTP"] != true {
		t.Errorf("tcp: %v", tcp)
	}
	if c, b := serveGet(t, proxy+"/", "GET"); c != 200 || !strings.Contains(b, "hello") {
		t.Errorf("index: %d %q", c, b)
	}
	if c, b := serveGet(t, proxy+"/a/b.txt", "GET"); c != 200 || b != "b" {
		t.Errorf("file: %d %q", c, b)
	}
	for _, p := range []string{"/.env", "/a/../.env", "/%2eenv"} {
		if c, b := serveGet(t, proxy+p, "GET"); c == 200 || strings.Contains(b, "SECRET") {
			t.Errorf("%s: %d %q", p, c, b)
		}
	}
	if c, _ := serveGet(t, proxy+"/", "POST"); c != http.StatusMethodNotAllowed {
		t.Errorf("post: %d", c)
	}
	// A folder's list shows neither what starts with a dot nor a link, and
	// no link is followed, even to a file inside.
	if c, b := serveGet(t, proxy+"/a/", "GET"); c != 200 || !strings.Contains(b, "b.txt") || strings.Contains(b, ".hidden") || strings.Contains(b, "link") {
		t.Errorf("list: %d %q", c, b)
	}
	if c, b := serveGet(t, proxy+"/a/link", "GET"); c == 200 || strings.Contains(b, "SECRET") {
		t.Errorf("link: %d %q", c, b)
	}
	if c, b := serveGet(t, proxy+"/a/dirlink/", "GET"); c == 200 || strings.Contains(b, "b.txt") {
		t.Errorf("folder link: %d %q", c, b)
	}

	// Listed as this helper's folder.
	out := serveList(ctx)
	var mine serveItem
	for _, x := range out.Items {
		if x.Port == 8850 {
			mine = x
		}
	}
	if mine.Kind != "folder" || mine.Dir != dir || mine.Target != "" || mine.Down {
		t.Errorf("listed: %+v", mine)
	}

	// A port in use, a port not offered, a folder too broad (a link to one
	// too).
	homeLink := filepath.Join(home, "demos", "home-link")
	if err := os.Symlink(home, homeLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dir  string
		port int
		want string
	}{
		{dir, 8850, "port-taken"}, {dir, 443, "bad-port"}, {dir, tailnetPort, "bad-port"}, {dir, 70000, "bad-port"},
		{home, 8851, "too-broad"}, {homeLink, 8851, "too-broad"}, {"relative", 8851, "bad-path"}, {filepath.Join(dir, "index.html"), 8851, "not-a-folder"},
		{filepath.Join(home, "nope"), 8851, "missing"},
	} {
		if _, code := serveAdd(ctx, tc.dir, tc.port); code != tc.want {
			t.Errorf("add %s %d: %q, want %q", tc.dir, tc.port, code, tc.want)
		}
	}
	f.conf = []byte(strings.Replace(string(f.conf), `"443":{"HTTPS":true}`, `"443":{"HTTPS":true},"8852":{"HTTP":true}`, 1))
	if _, code := serveAdd(ctx, dir, 8852); code != "port-taken" {
		t.Errorf("a port the config has: %q", code)
	}

	// Kept, and served again by a helper started afresh.
	b, err := os.ReadFile(filepath.Join(configDir(), serveOwnFile))
	if err != nil || !strings.Contains(string(b), `"port":8850`) {
		t.Fatalf("kept: %q %v", b, err)
	}
	serveReset()
	if c, err := http.Get(proxy + "/"); err == nil {
		c.Body.Close()
		t.Fatal("still served after the reset")
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	serveStart(sctx)
	waitFor(t, func() bool {
		c, err := http.Get(proxy + "/")
		if err == nil {
			c.Body.Close()
		}
		return err == nil && c.StatusCode == 200
	})

	// Stopped: off the config, not served here, forgotten.
	if code := serveStop(ctx, 8850, "/", filepath.Join(home, "other"), ""); code != "changed" {
		t.Fatalf("stop of what the page did not see: %s", code)
	}
	if code := serveStop(ctx, 8850, "/", dir, ""); code != "" {
		t.Fatalf("stop: %s", code)
	}
	if web := f.doc(t)["Web"].(map[string]any); web["web-1.tail1234.ts.net:8850"] != nil {
		t.Errorf("still in the config: %v", web)
	}
	if _, ok := f.doc(t)["TCP"].(map[string]any)["8850"]; ok {
		t.Error("tcp still there")
	}
	if c, err := http.Get(proxy + "/"); err == nil {
		c.Body.Close()
		t.Error("still served after the stop")
	}
	if b, _ := os.ReadFile(filepath.Join(configDir(), serveOwnFile)); strings.Contains(string(b), "8850") {
		t.Errorf("still kept: %q", b)
	}
	if code := serveStop(ctx, 8850, "/", dir, ""); code != "not-served" {
		t.Errorf("stopped twice: %q", code)
	}
	if code := serveStop(ctx, 8852, "", "", ""); code != "" {
		t.Errorf("a port of someone else's: %q", code)
	}
}

// Refusals as the page reads them: the operator, the sudo rule for a
// folder Tailscale serves, a foreground session.
func TestServeRefusals(t *testing.T) {
	f := &serveFake{state: "Running"}
	home := serveUse(t, f)
	dir := filepath.Join(home, "site")
	serveMkdir(t, dir, map[string]string{"index.html": "x"})
	ctx := context.Background()
	f.postCode = http.StatusForbidden
	if _, code := serveAdd(ctx, dir, 8860); code != "ts-denied" {
		t.Errorf("not the operator: %q", code)
	}
	f.postCode = http.StatusUnauthorized
	if _, code := serveAdd(ctx, dir, 8860); code != "ts-admin" {
		t.Errorf("path handler, no sudo: %q", code)
	}
	if len(serveOwned()) != 0 {
		t.Errorf("kept a refused folder: %v", serveOwned())
	}
	f.postCode = 0
	f.conf = []byte(`{"Foreground":{"s1":{"TCP":{"8870":{"HTTP":true}},"Web":{"web-1.tail1234.ts.net:8870":{"Handlers":{"/":{"Path":"/tmp"}}}}}}}`)
	if code := serveStop(ctx, 8870, "/", "", ""); code != "foreground" {
		t.Errorf("foreground: %q", code)
	}
	f.state = "Stopped"
	if _, code := serveAdd(ctx, dir, 8861); code != "ts-stopped" {
		t.Errorf("stopped: %q", code)
	}
}

// A folder kept whose port someone took off the serve config while this
// helper was away is forgotten when it starts.
func TestServeStartForgetsWhatWasTakenAway(t *testing.T) {
	f := &serveFake{state: "Running"}
	home := serveUse(t, f)
	dir := filepath.Join(home, "site")
	serveMkdir(t, dir, map[string]string{"index.html": "x"})
	if _, code := serveAdd(context.Background(), dir, 8880); code != "" {
		t.Fatal(code)
	}
	serveReset()
	f.mu.Lock()
	f.conf = []byte("{}")
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveStart(ctx)
	waitFor(t, func() bool { return len(serveOwned()) == 0 })
	if b, _ := os.ReadFile(filepath.Join(configDir(), serveOwnFile)); strings.Contains(string(b), "8880") {
		t.Errorf("still kept: %q", b)
	}
}

// The Files command channel answers the three, behind its own gate.
func TestServeThroughFilesCommand(t *testing.T) {
	ff := newFilesFixture(t)
	f := &serveFake{state: "Running"}
	dial, tok := tsLocalDial, tsLocalToken
	t.Cleanup(func() { tsLocalDial, tsLocalToken = dial, tok; serveReset() })
	serveReset()
	tsLocalToken = func() string { return "" }
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	tsLocalDial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	dir := filepath.Join(ff.home, "Work")
	r := ff.command(t, ff.peer, "serve-add", map[string]any{"dir": dir, "port": 8890})
	if r.Code != 0 || !strings.Contains(r.Out, `"kind":"folder"`) {
		t.Fatalf("serve-add: %+v", r)
	}
	r = ff.command(t, ff.peer, "serve-list", map[string]any{})
	var l serveListBody
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &l) != nil || len(l.Items) != 1 || l.Items[0].Port != 8890 {
		t.Fatalf("serve-list: %+v", r)
	}
	if r = ff.command(t, ff.peer, "serve-stop", map[string]any{"port": 8890, "route": "/", "dir": dir}); r.Code != 0 {
		t.Fatalf("serve-stop: %+v", r)
	}
	if r = ff.command(t, ff.peer, "serve-stop", map[string]any{"port": 8890}); r.Error != "not-served" {
		t.Errorf("stopped twice: %+v", r)
	}
}

// One handler taken off a port that has others keeps them and the port;
// the last one takes the port with it; one serving something else than the
// page saw is left as it is.
func TestServeStopOneRoute(t *testing.T) {
	f := &serveFake{state: "Running", conf: []byte(`{"TCP":{"8443":{"HTTP":true}},"Web":{"web-1.tail1234.ts.net:8443":{"Handlers":{"/":{"Path":"/srv/site"},"/api":{"Proxy":"http://127.0.0.1:3000"}},"Extra":7}},"AllowFunnel":{"web-1.tail1234.ts.net:8443":true}}`)}
	serveUse(t, f)
	ctx := context.Background()
	if code := serveStop(ctx, 8443, "/api", "", "http://127.0.0.1:4000"); code != "changed" {
		t.Errorf("another proxy: %q", code)
	}
	if code := serveStop(ctx, 8443, "/api", "", "http://127.0.0.1:3000"); code != "" {
		t.Fatalf("stop /api: %q", code)
	}
	doc := f.doc(t)
	entry := doc["Web"].(map[string]any)["web-1.tail1234.ts.net:8443"].(map[string]any)
	hs := entry["Handlers"].(map[string]any)
	if hs["/api"] != nil || hs["/"] == nil || entry["Extra"] != 7.0 {
		t.Errorf("after /api: %v", entry)
	}
	if doc["TCP"].(map[string]any)["8443"] == nil || doc["AllowFunnel"].(map[string]any)["web-1.tail1234.ts.net:8443"] != true {
		t.Errorf("the port went with /api: %v", doc)
	}
	if code := serveStop(ctx, 8443, "/", "/srv/other", ""); code != "changed" {
		t.Errorf("another folder: %q", code)
	}
	if code := serveStop(ctx, 8443, "/", "/srv/site/", ""); code != "" {
		t.Fatalf("stop /: %q", code)
	}
	doc = f.doc(t)
	sub := func(k string) map[string]any { m, _ := doc[k].(map[string]any); return m }
	if sub("Web")["web-1.tail1234.ts.net:8443"] != nil || sub("TCP")["8443"] != nil || sub("AllowFunnel")["web-1.tail1234.ts.net:8443"] != nil {
		t.Errorf("the last handler left the port: %v", doc)
	}
}

// A folder served again on another local port than before (its old one
// taken meanwhile) has only its "/" pointed at the new one, the port's other
// routes kept, and the new one kept for the next start.
func TestServeStartRepoints(t *testing.T) {
	f := &serveFake{state: "Running"}
	home := serveUse(t, f)
	dir := filepath.Join(home, "site")
	serveMkdir(t, dir, map[string]string{"index.html": "x"})
	ctx := context.Background()
	if _, code := serveAdd(ctx, dir, 8881); code != "" {
		t.Fatal(code)
	}
	old := serveOwned()[8881].Local
	serveReset()
	// someone adds a route of their own beside it
	f.mu.Lock()
	f.conf = []byte(strings.Replace(string(f.conf), `"Handlers":{`, `"Handlers":{"/api":{"Proxy":"http://127.0.0.1:3000"},`, 1))
	f.mu.Unlock()
	hold, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(old))
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	serveStart(sctx)
	var now int
	waitFor(t, func() bool {
		now = serveOwned()[8881].Local
		b, _ := os.ReadFile(filepath.Join(configDir(), serveOwnFile))
		return now != old && strings.Contains(string(b), `"local":`+strconv.Itoa(now))
	})
	hs := f.doc(t)["Web"].(map[string]any)["web-1.tail1234.ts.net:8881"].(map[string]any)["Handlers"].(map[string]any)
	if hs["/"].(map[string]any)["Proxy"] != serveLocalURL(now) || hs["/api"].(map[string]any)["Proxy"] != "http://127.0.0.1:3000" {
		t.Errorf("handlers: %v", hs)
	}
	if c, _ := serveGet(t, serveLocalURL(now)+"/", "GET"); c != 200 {
		t.Errorf("served again: %d", c)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
