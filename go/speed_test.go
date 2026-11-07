package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

func speedCall(t *testing.T, h http.Handler, peer *key.NodePublic, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if peer != nil {
		req = req.WithContext(transport.WithPeer(req.Context(), *peer))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A browser on the list: a round trip, the bytes it asked for, and its
// upload counted.
func TestSpeedEndpoints(t *testing.T) {
	f := newFilesFixture(t)
	rec := speedCall(t, f.h, &f.peer, "GET", "/v1/speed/ping", nil)
	if rec.Code != 200 || rec.Body.String() != "{}" {
		t.Fatalf("ping: %d %q", rec.Code, rec.Body.String())
	}
	rec = speedCall(t, f.h, &f.peer, "GET", "/v1/speed/down?n=200000", nil)
	if rec.Code != 200 || rec.Body.Len() != 200000 || rec.Header().Get("Content-Length") != "200000" {
		t.Fatalf("down: %d %d", rec.Code, rec.Body.Len())
	}
	// Past the buffer's end it goes round again.
	rec = speedCall(t, f.h, &f.peer, "GET", "/v1/speed/down?n="+strconv.Itoa(speedBufSize*2+5), nil)
	if rec.Code != 200 || rec.Body.Len() != speedBufSize*2+5 {
		t.Fatalf("down past the buffer: %d %d", rec.Code, rec.Body.Len())
	}
	for _, q := range []string{"", "n=-1", "n=x", "n=" + strconv.FormatInt(speedDownMax+1, 10)} {
		if rec := speedCall(t, f.h, &f.peer, "GET", "/v1/speed/down?"+q, nil); rec.Code != 400 || errCodeOf(rec) != "bad-args" {
			t.Errorf("down %q: %d %s", q, rec.Code, rec.Body.String())
		}
	}
	rec = speedCall(t, f.h, &f.peer, "POST", "/v1/speed/up?n=70000", make([]byte, 70000))
	var got struct {
		N  int64   `json:"n"`
		Ms float64 `json:"ms"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.N != 70000 {
		t.Fatalf("up: %d %s", rec.Code, rec.Body.String())
	}
	// The wrong method on each.
	for _, c := range []struct{ m, p string }{{"POST", "/v1/speed/ping"}, {"POST", "/v1/speed/down?n=1"}, {"GET", "/v1/speed/up"}} {
		if rec := speedCall(t, f.h, &f.peer, c.m, c.p, nil); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", c.m, c.p, rec.Code)
		}
	}
	// The hello names it to a browser on the list.
	rec = speedCall(t, f.h, &f.peer, "GET", "/v1/hello", nil)
	fr, _ := transport.Decode(rec.Body.Bytes())
	var hello transport.Hello
	json.Unmarshal(fr.Body, &hello)
	if !containsStr(hello.Caps, transport.CapSpeed) || !containsStr(hello.Caps, transport.CapSpeedPeer) || !containsStr(hello.Caps, transport.CapSpeedNet) {
		t.Fatalf("hello caps: %v", hello.Caps)
	}
}

// A key that is let in but not on the list — a portable copy — is not
// given the bytes.
func TestSpeedNotForEveryKey(t *testing.T) {
	f := newFilesFixture(t)
	stranger := key.NewNode().Public()
	h := newDirectHandler()
	if rec := speedCall(t, h, &stranger, "GET", "/v1/speed/ping", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a key not on the list: %d", rec.Code)
	}
	_ = f
}

func signSpeedGrant(f *filesFixture, node key.NodePublic, roots ...string) grantCert {
	now := time.Now()
	c := grantCert{V: 1, ID: newGrantID(), Agent: agentID(), NK: node.String(), Caps: "speed", Roots: roots,
		IAT: now.Unix(), EXP: now.Add(15 * time.Minute).Unix()}
	c.By = base64.StdEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey))
	c.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, grantSigningInput(c)))
	return c
}

// A grant to measure names no path and reaches the Speed tab's three and
// nothing of the files; a grant to read reaches none of the three.
func TestSpeedGrantDoor(t *testing.T) {
	f := newGrantFixture(t)
	node := key.NewNode().Public()
	if r := f.enrol(t, signSpeedGrant(f, node, f.home)); r.Error != "bad-grant" {
		t.Fatalf("a speed grant naming a path: %+v", r)
	}
	g := signSpeedGrant(f, node)
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatalf("a speed grant: %+v", r)
	}
	if !containsKey(activeGrantNodes(), node) {
		t.Fatal("a speed grant does not let its key in")
	}
	if rec := f.grantCall(t, node, "GET", "/v1/speed/ping", nil); rec.Code != 200 {
		t.Fatalf("ping under a speed grant: %d %s", rec.Code, rec.Body.String())
	}
	rec := speedCall(t, f.h, &node, "GET", "/v1/speed/down?n=1000", nil)
	if rec.Code != 200 || rec.Body.Len() != 1000 {
		t.Fatalf("down under a speed grant: %d %d", rec.Code, rec.Body.Len())
	}
	if rec := speedCall(t, f.h, &node, "POST", "/v1/speed/up", make([]byte, 999)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"n":999`) {
		t.Fatalf("up under a speed grant: %d %s", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"/v1/files/grant/open", "/v1/files/grant/walk"} {
		rec := f.grantCall(t, node, "POST", p, map[string]string{"id": g.ID, "path": f.home, "in": f.home})
		if rec.Code != http.StatusForbidden || errCodeOf(rec) != "not-allowed" {
			t.Errorf("%s under a speed grant: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	for _, c := range []struct{ m, p string }{{"GET", "/v1/snapshot"}, {"POST", "/v1/files/put?s=x&o=0"}, {"GET", "/v1/music"}} {
		if rec := f.grantCall(t, node, c.m, c.p, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s under a speed grant: %d", c.m, c.p, rec.Code)
		}
	}
	// It ends itself.
	if rec := f.grantCall(t, node, "POST", "/v1/files/grant/done", map[string]string{"id": g.ID}); rec.Code != 200 {
		t.Fatalf("done: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.grantCall(t, node, "GET", "/v1/speed/ping", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("ping after its grant ended: %d", rec.Code)
	}

	// A copy's grant measures nothing.
	reader := key.NewNode().Public()
	if r := f.enrol(t, f.grantFor(reader, f.home)); r.Code != 0 {
		t.Fatal(r)
	}
	if rec := f.grantCall(t, reader, "GET", "/v1/speed/ping", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("ping under a copy's grant: %d", rec.Code)
	}
}

// The grant's bytes with no root: the count, then nothing (monitor.js
// speedGrant signs the same).
func TestSpeedGrantSigningInput(t *testing.T) {
	c := grantCert{ID: "0123456789abcdef", Agent: "ag", NK: "nodekey:00", Caps: "speed", IAT: 1, EXP: 2, By: "BY"}
	want := "mon-grant-v1\n16:0123456789abcdef\n2:ag\n10:nodekey:00\n5:speed\n1:0\n1:1\n1:2\n2:BY\n"
	if got := string(grantSigningInput(c)); got != want {
		t.Fatalf("signing input\n got %q\nwant %q", got, want)
	}
	// Kept and read back, an empty list stays a grant.
	c.V, c.Sig = 1, base64.StdEncoding.EncodeToString(make([]byte, 64))
	c.Agent, c.NK = "agent-1", key.NewNode().Public().String()
	c.By = base64.StdEncoding.EncodeToString(make([]byte, 32))
	b, _ := json.Marshal(c)
	if _, ok := parseGrantCert(string(b)); !ok {
		t.Fatalf("a kept speed grant does not read back: %s", b)
	}
}

// speedRoad is A's tunnel inside a test: a real server, so a download
// streams as it would, every request as from the measurement's key.
type speedRoad struct {
	srv *httptest.Server
	hc  *http.Client
}

func newSpeedRoad(h http.Handler, peer key.NodePublic) *speedRoad {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(transport.WithPeer(r.Context(), peer)))
	}))
	addr := srv.Listener.Addr().String()
	return &speedRoad{srv: srv, hc: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}}
}
func (s *speedRoad) HTTP() *http.Client               { return s.hc }
func (s *speedRoad) Route(ctx context.Context) string { return "direct" }
func (s *speedRoad) Close()                           { s.hc.CloseIdleConnections(); s.srv.Close() }

func speedReset() {
	speedJobs.Lock()
	for _, j := range speedJobs.m {
		j.mu.Lock()
		if j.cancel != nil {
			j.cancel()
		}
		j.mu.Unlock()
	}
	speedJobs.m = map[string]*speedJob{}
	speedJobs.Unlock()
}

func speedStatus(t *testing.T, f *filesFixture, job string) speedView {
	t.Helper()
	r := f.command(t, f.peer, "speed-status", map[string]string{"job": job})
	var v speedView
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &v) != nil {
		t.Fatalf("speed-status: %+v", r)
	}
	return v
}

// B measures the road to A: a key, a grant for it on A, the run — and the
// grant is over when it is.
func TestSpeedPeerRun(t *testing.T) {
	f := newGrantFixture(t)
	speedReset()
	oldDial, oldSelf, oldSec := speedDialA, fetchSelf, speedSecond
	t.Cleanup(func() { speedReset(); speedDialA, fetchSelf, speedSecond = oldDial, oldSelf, oldSec })
	speedSecond = 60 * time.Millisecond
	fetchSelf = func() string { return "the-other-machine" }
	var dialled fetchFrom
	speedDialA = func(ctx context.Context, from fetchFrom, priv key.NodePrivate) (fetchRoad, string) {
		dialled = from
		return newSpeedRoad(f.h, priv.Public()), "tailcat"
	}

	r := f.command(t, f.peer, "speed-key", map[string]string{"job": "job-0001"})
	var k struct {
		Pub string `json:"pub"`
	}
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &k) != nil {
		t.Fatalf("speed-key: %+v", r)
	}
	node, ok := exactNodeKey(k.Pub)
	if !ok {
		t.Fatalf("speed-key answered %q", k.Pub)
	}
	// The same job again is the same key.
	if r := f.command(t, f.peer, "speed-key", map[string]string{"job": "job-0001"}); !strings.Contains(r.Out, k.Pub) {
		t.Fatalf("speed-key again: %+v", r)
	}
	g := signSpeedGrant(f, node)
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatal(r)
	}
	run := map[string]any{"job": "job-0001", "grant": g.ID, "secs": 3,
		"from": map[string]any{"agent": agentID(), "addr": "tcTESTADDRESSFORAGRANT00"}}
	if r := f.command(t, f.peer, "speed-run", run); r.Code != 0 {
		t.Fatalf("speed-run: %+v", r)
	}
	// One at a time.
	f.command(t, f.peer, "speed-key", map[string]string{"job": "job-0002"})
	run2 := map[string]any{"job": "job-0002", "grant": g.ID, "from": map[string]any{"agent": agentID(), "addr": "tcTESTADDRESSFORAGRANT00"}}
	if r := f.command(t, f.peer, "speed-run", run2); r.Error != "busy" {
		t.Fatalf("a second measurement at once: %+v", r)
	}
	var v speedView
	filesWaitFor(t, "the measurement to end", func() bool {
		v = speedStatus(t, f, "job-0001")
		return speedFinished(v.St)
	})
	if v.St != "done" || v.Down <= 0 || v.Up <= 0 || v.Ping <= 0 || v.Road != "tailcat" || v.Route != "direct" {
		t.Fatalf("finished: %+v", v)
	}
	// The round trips: idle, and read while each way ran full.
	if v.DlLat <= 0 || v.UlLat <= 0 || len(v.Rtts) != speedPings-speedPingsSkip || len(v.DlRtts) == 0 || len(v.UlRtts) == 0 {
		t.Fatalf("round trips: %+v", v)
	}
	if dialled.Agent != agentID() || dialled.Addr != "tcTESTADDRESSFORAGRANT00" {
		t.Fatalf("dialled %+v", dialled)
	}
	if containsKey(activeGrantNodes(), node) {
		t.Fatal("the grant outlived the measurement")
	}
	// Forgotten on asking.
	if r := f.command(t, f.peer, "speed-stop", map[string]any{"job": "job-0001", "forget": true}); r.Code != 0 {
		t.Fatal(r)
	}
	if r := f.command(t, f.peer, "speed-status", map[string]string{"job": "job-0001"}); r.Error != "no-job" {
		t.Fatalf("status of a forgotten one: %+v", r)
	}
}

// The other machine answering at the address, or none: said, not measured.
func TestSpeedPeerWrongMachine(t *testing.T) {
	f := newGrantFixture(t)
	speedReset()
	oldDial, oldSelf := speedDialA, fetchSelf
	t.Cleanup(func() { speedReset(); speedDialA, fetchSelf = oldDial, oldSelf })
	fetchSelf = func() string { return "the-other-machine" }
	speedDialA = func(ctx context.Context, from fetchFrom, priv key.NodePrivate) (fetchRoad, string) {
		return newSpeedRoad(f.h, priv.Public()), "tailcat"
	}
	r := f.command(t, f.peer, "speed-key", map[string]string{"job": "job-0003"})
	var k struct {
		Pub string `json:"pub"`
	}
	json.Unmarshal([]byte(r.Out), &k)
	node, _ := exactNodeKey(k.Pub)
	g := signSpeedGrant(f, node)
	f.enrol(t, g)
	run := map[string]any{"job": "job-0003", "grant": g.ID, "from": map[string]any{"agent": "someone-else", "addr": "tcTESTADDRESSFORAGRANT00"}}
	if r := f.command(t, f.peer, "speed-run", run); r.Code != 0 {
		t.Fatal(r)
	}
	var v speedView
	filesWaitFor(t, "the measurement to end", func() bool {
		v = speedStatus(t, f, "job-0003")
		return speedFinished(v.St)
	})
	if v.St != "err" || v.Err != "wrong-machine" {
		t.Fatalf("another machine at the address: %+v", v)
	}
	// Measuring itself, and nonsense, are refused before anything runs.
	for _, from := range []map[string]any{
		{"agent": "the-other-machine", "addr": "tcTESTADDRESSFORAGRANT00"},
		{"agent": agentID(), "addr": "not an address"},
		{"agent": agentID()},
	} {
		f.command(t, f.peer, "speed-key", map[string]string{"job": "job-0004"})
		if r := f.command(t, f.peer, "speed-run", map[string]any{"job": "job-0004", "grant": g.ID, "from": from}); r.Error != "bad-args" {
			t.Errorf("from %v: %+v", from, r)
		}
	}
}

// A download that breaks off before the seconds are up is no measurement,
// whatever came before the break.
func TestSpeedPeerBrokenDownload(t *testing.T) {
	f := newGrantFixture(t)
	speedReset()
	oldDial, oldSelf, oldSec := speedDialA, fetchSelf, speedSecond
	t.Cleanup(func() { speedReset(); speedDialA, fetchSelf, speedSecond = oldDial, oldSelf, oldSec })
	speedSecond = 60 * time.Millisecond
	fetchSelf = func() string { return "the-other-machine" }
	speedDialA = func(ctx context.Context, from fetchFrom, priv key.NodePrivate) (fetchRoad, string) {
		cut := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/speed/down" {
				f.h.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(1<<20))
			w.Write(make([]byte, 100<<10))
			http.NewResponseController(w).Flush()
			panic(http.ErrAbortHandler)
		})
		return newSpeedRoad(cut, priv.Public()), "tailcat"
	}
	r := f.command(t, f.peer, "speed-key", map[string]string{"job": "job-0005"})
	var k struct {
		Pub string `json:"pub"`
	}
	json.Unmarshal([]byte(r.Out), &k)
	node, _ := exactNodeKey(k.Pub)
	g := signSpeedGrant(f, node)
	f.enrol(t, g)
	run := map[string]any{"job": "job-0005", "grant": g.ID, "secs": 3, "from": map[string]any{"agent": agentID(), "addr": "tcTESTADDRESSFORAGRANT00"}}
	if r := f.command(t, f.peer, "speed-run", run); r.Code != 0 {
		t.Fatal(r)
	}
	var v speedView
	filesWaitFor(t, "the measurement to end", func() bool {
		v = speedStatus(t, f, "job-0005")
		return speedFinished(v.St)
	})
	if v.St != "err" || v.Err != "unreachable" || v.Down != 0 {
		t.Fatalf("a download cut short: %+v", v)
	}
}

// With the console off a grant already given moves nothing; a browser on
// the list still measures.
func TestSpeedGrantFollowsTheConsole(t *testing.T) {
	f := newGrantFixture(t)
	node := key.NewNode().Public()
	if r := f.enrol(t, signSpeedGrant(f, node)); r.Code != 0 {
		t.Fatal(r)
	}
	if rec := f.grantCall(t, node, "GET", "/v1/speed/ping", nil); rec.Code != 200 {
		t.Fatalf("ping under a speed grant: %d", rec.Code)
	}
	t.Setenv("MON_CONSOLE", "0")
	for _, c := range []struct{ m, p string }{{"GET", "/v1/speed/ping"}, {"GET", "/v1/speed/down?n=10"}, {"POST", "/v1/speed/up"}} {
		if rec := f.grantCall(t, node, c.m, c.p, nil); rec.Code == 200 {
			t.Errorf("%s %s under a grant with the console off: %d", c.m, c.p, rec.Code)
		}
	}
	if rec := speedCall(t, f.h, &f.peer, "GET", "/v1/speed/ping", nil); rec.Code != 200 {
		t.Fatalf("a browser on the list with the console off: %d", rec.Code)
	}
}

// Each write of a download is given a deadline, never past its end.
func TestSpeedWriteDeadlines(t *testing.T) {
	var ds []time.Time
	t0 := time.Now()
	speedWrite(io.Discard, 300000, func(d time.Time) { ds = append(ds, d) })
	if len(ds) != 5 {
		t.Fatalf("%d deadlines for five writes", len(ds))
	}
	for _, d := range ds {
		if d.Before(t0) || d.After(time.Now().Add(speedStall)) {
			t.Fatalf("deadline %v", d.Sub(t0))
		}
	}
}

func TestSpeedLatency(t *testing.T) {
	mid, jit := speedLatency([]float64{10, 12, 11, 30, 10})
	if mid != 11 || jit < 10 || jit > 10.5 {
		t.Fatalf("mid %v jit %v", mid, jit)
	}
	if mid, jit := speedLatency(nil); mid != 0 || jit != 0 {
		t.Fatal("nothing measured")
	}
}

// A piece is credited after the first second only with its share of the
// time it was under way after it.
func TestSpeedMeterShare(t *testing.T) {
	t0 := time.Unix(1000, 0)
	m := &speedMeter{t0: t0, warm: t0.Add(time.Second)}
	m.piece(t0.Add(500*time.Millisecond), t0.Add(1500*time.Millisecond), 1000) // half after
	m.piece(t0.Add(100*time.Millisecond), t0.Add(900*time.Millisecond), 1000)  // none after
	m.piece(t0.Add(2*time.Second), t0.Add(3*time.Second), 1000)                // all after
	if m.got.Load() != 3000 || m.part.Load() != 1500 {
		t.Fatalf("got %d, part %d", m.got.Load(), m.part.Load())
	}
}

var _ = io.Discard

// fakeCloudflare answers as speed.cloudflare.com does, for the paths a
// measurement to the internet uses: a trace, downloads, uploads, each with
// Cloudflare's server timing.
func fakeCloudflare(t *testing.T, down func(w http.ResponseWriter, n int)) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	upBytes := new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Server-Timing", "cfSpeedEdge;dur=1, cfSpeedWorker;dur=2")
		w.Header().Add("Server-Timing", `cfL4;desc="?proto=TCP&rtt=1200&min_rtt=900&rtt_var=300&sent=40&recv=6&lost=0&retrans=2&sent_bytes=2859"`)
		switch r.URL.Path {
		case "/cdn-cgi/trace":
			io.WriteString(w, "fl=1\nh=speed.cloudflare.com\nip=203.0.113.9\ncolo=SJC\nloc=US\nhttp=http/1.1\n")
		case "/__down":
			n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
			down(w, n)
		case "/__up":
			b, _ := io.Copy(io.Discard, r.Body)
			upBytes.Add(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, upBytes
}

// This machine measures its own road to the internet: where it lands, the
// round trip idle and under load, each direction, the TCP connection —
// and never the address the trace said.
func TestSpeedNetRun(t *testing.T) {
	f := newGrantFixture(t)
	speedReset()
	oldBase, oldSec := speedNetBase, speedSecond
	t.Cleanup(func() { speedReset(); speedNetBase, speedSecond = oldBase, oldSec })
	speedSecond = 150 * time.Millisecond
	srv, up := fakeCloudflare(t, func(w http.ResponseWriter, n int) {
		w.Header().Set("Content-Length", strconv.Itoa(n))
		buf := make([]byte, 32<<10)
		for n > 0 {
			k := min(n, len(buf))
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	speedNetBase = srv.URL

	if r := f.command(t, f.peer, "speed-net", map[string]any{"job": "net-0001", "secs": 3}); r.Code != 0 {
		t.Fatalf("speed-net: %+v", r)
	}
	// One at a time, and a job id is used once.
	if r := f.command(t, f.peer, "speed-net", map[string]any{"job": "net-0002"}); r.Error != "busy" {
		t.Fatalf("a second measurement at once: %+v", r)
	}
	if r := f.command(t, f.peer, "speed-key", map[string]string{"job": "net-0001"}); r.Error != "busy" {
		t.Fatalf("a key for a measurement to the internet: %+v", r)
	}
	var v speedView
	filesWaitFor(t, "the measurement to end", func() bool {
		v = speedStatus(t, f, "net-0001")
		return speedFinished(v.St)
	})
	if v.St != "done" || !v.Net || v.Colo != "SJC" || v.Cc != "US" || v.Down <= 0 || v.Up <= 0 || v.Ping <= 0 {
		t.Fatalf("finished: %+v", v)
	}
	if v.DlLat <= 0 || v.UlLat <= 0 || len(v.Rtts) == 0 || len(v.DlRtts) == 0 || len(v.UlRtts) == 0 {
		t.Fatalf("no round trip under load: %+v", v)
	}
	if v.TCP == nil || v.TCP.Rtt != 1200 || v.TCP.Min != 900 || v.TCP.Retrans != 2 || v.TCP.Sent != 40 {
		t.Fatalf("tcp %+v", v.TCP)
	}
	if up.Load() <= 0 {
		t.Fatal("nothing went up")
	}
	r := f.command(t, f.peer, "speed-status", map[string]string{"job": "net-0001"})
	if strings.Contains(r.Out, "203.0.113.9") {
		t.Fatalf("the address was kept: %s", r.Out)
	}
	// After it, another may go.
	if r := f.command(t, f.peer, "speed-net", map[string]any{"job": "net-0003", "secs": 3}); r.Code != 0 {
		t.Fatalf("speed-net after the first: %+v", r)
	}
	if r := f.command(t, f.peer, "speed-stop", map[string]string{"job": "net-0003"}); r.Code != 0 {
		t.Fatal(r)
	}
	filesWaitFor(t, "the stopped one to end", func() bool {
		v = speedStatus(t, f, "net-0003")
		return speedFinished(v.St)
	})
	if v.St != "stopped" {
		t.Fatalf("stopped: %+v", v)
	}
}

// Cloudflare saying no is said as such.
func TestSpeedNetRefused(t *testing.T) {
	f := newGrantFixture(t)
	speedReset()
	oldBase, oldSec := speedNetBase, speedSecond
	t.Cleanup(func() { speedReset(); speedNetBase, speedSecond = oldBase, oldSec })
	speedSecond = 100 * time.Millisecond
	srv, _ := fakeCloudflare(t, func(w http.ResponseWriter, n int) {
		if n == 0 {
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	})
	speedNetBase = srv.URL
	if r := f.command(t, f.peer, "speed-net", map[string]any{"job": "net-0004", "secs": 3}); r.Code != 0 {
		t.Fatalf("speed-net: %+v", r)
	}
	var v speedView
	filesWaitFor(t, "the measurement to end", func() bool {
		v = speedStatus(t, f, "net-0004")
		return speedFinished(v.St)
	})
	if v.St != "err" || v.Err != "net-refused" {
		t.Fatalf("refused: %+v", v)
	}
}

func TestSpeedNetTiming(t *testing.T) {
	if ms := speedNetServerMs("cfSpeedEdge;dur=3, cfSpeedWorker;dur=21"); ms != 24 {
		t.Fatalf("summed %v", ms)
	}
	if ms := speedNetServerMs("cfRequestDuration;dur=7.5, cfSpeedWorker;dur=21"); ms != 7.5 {
		t.Fatalf("request duration %v", ms)
	}
	if ms := speedNetServerMs(""); ms != 0 {
		t.Fatalf("none %v", ms)
	}
	tcp := speedNetL4(`cfSpeedEdge;dur=3, cfL4;desc="?proto=TCP&rtt=995&min_rtt=964&retrans=0&sent=4"`)
	if tcp == nil || tcp.Rtt != 995 || tcp.Min != 964 || tcp.Retrans != 0 || tcp.Sent != 4 {
		t.Fatalf("l4 %+v", tcp)
	}
	if speedNetL4(`cfL4;desc="?proto=QUIC&rtt=995"`) != nil {
		t.Fatal("QUIC read as TCP")
	}
}

// An upload piece grows on a far road too: the round trip it waits for is
// not counted as its bytes moving.
func TestSpeedNextPiece(t *testing.T) {
	ms := time.Millisecond
	// Near: as before.
	if n := speedNextPiece(64<<10, 100*ms, ms, 4<<20); n != 128<<10 {
		t.Fatalf("near, quick: %d", n)
	}
	if n := speedNextPiece(1<<20, 1500*ms, ms, 4<<20); n != 512<<10 {
		t.Fatalf("near, slow: %d", n)
	}
	// 300 ms away, a piece that took 310 ms moved its bytes in 10: it grows.
	if n := speedNextPiece(64<<10, 310*ms, 300*ms, 16<<20); n != 128<<10 {
		t.Fatalf("far, quick: %d", n)
	}
	// 300 ms away, 800 ms of bytes moving is under 4 round trips: kept.
	if n := speedNextPiece(4<<20, 1100*ms, 300*ms, 16<<20); n != 4<<20 {
		t.Fatalf("far, steady: %d", n)
	}
	// Never past the bounds.
	if n := speedNextPiece(16<<20, 310*ms, 300*ms, 16<<20); n != 16<<20 {
		t.Fatalf("at the top: %d", n)
	}
	if n := speedNextPiece(speedPieceMin, 5*time.Second, ms, 4<<20); n != speedPieceMin {
		t.Fatalf("at the bottom: %d", n)
	}
}
