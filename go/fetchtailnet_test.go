package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// tnFetchBench is A's tailnet listener in the test, over A's own handler: the
// page's word on it (ip, port, key), the sealed questions it was asked, and
// a switch that makes it fail every one from then on.
type tnFetchBench struct {
	tn        map[string]any
	rpcs      atomic.Int32
	failAfter atomic.Int32 // questions answered before it stops answering (0: never stops)
	dials     atomic.Int32
}

func newTnFetchBench(t *testing.T, f *filesFixture, machineKey string) *tnFetchBench {
	t.Helper()
	b := &tnFetchBench{}
	ts := &tailnetServer{sessions: map[string]*tnSession{}}
	ts.handler.Store(f.h)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tn/rpc" {
			n := b.rpcs.Add(1)
			if fa := b.failAfter.Load(); fa > 0 && n > fa {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		ts.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	if machineKey == "" {
		mk, err := econPrivate()
		if err != nil {
			t.Fatal(err)
		}
		machineKey = econKeyPrefix + hex.EncodeToString(mk.PublicKey().Bytes())
	}
	b.tn = map[string]any{"ip": "100.64.0.7", "port": 8126, "key": machineKey}
	old := fetchDialTn
	fetchDialTn = func(ctx context.Context, tn *fetchTn, agent string, priv key.NodePrivate) fetchRoad {
		b.dials.Add(1)
		if tn == nil || tn.IP != "100.64.0.7" || tn.Port != 8126 {
			t.Errorf("the job was told of %+v", tn)
			return nil
		}
		rd, err := openTnRoad(ctx, srv.URL, tn.Key, agent, priv)
		if err != nil {
			return nil
		}
		return rd
	}
	t.Cleanup(func() { fetchDialTn = old })
	return b
}

func TestFetchGoesOverTheTailnetFirst(t *testing.T) {
	f := newFetchFixture(t)
	b := newTnFetchBench(t, f, "")
	src := filepath.Join(f.home, "Documents", "tn.bin")
	want := randomFile(t, src, 5<<20+77)
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")
	f.startFetch(t, fetchSpec{job: "job-tnet-0001", src: src, dir: dir, k: "partkey-tnet-0001", s: fi.Size(), m: fi.ModTime().Unix(), tn: b.tn})
	v := f.fetchUntil(t, "job-tnet-0001", finished)
	if v.St != "done" {
		t.Fatalf("job: %+v", v)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "tn.bin")); string(got) != string(want) {
		t.Fatal("the copy differs")
	}
	// The hello, the open, two pieces and the grant's end, all on the tailnet;
	// tailcat never dialled.
	if d := roadDials.Load(); d != 0 {
		t.Fatalf("tailcat dialled %d times", d)
	}
	if d, n := b.dials.Load(), b.rpcs.Load(); d != 1 || n < 5 {
		t.Fatalf("tailnet: %d dials, %d questions", d, n)
	}
}

// A road that breaks down on the way: the job goes on by tailcat, from the
// part it has.
func TestFetchGoesByTailcatWhenTheTailnetFails(t *testing.T) {
	f := newFetchFixture(t)
	b := newTnFetchBench(t, f, "")
	src := filepath.Join(f.home, "Documents", "tnfail.bin")
	want := randomFile(t, src, 9<<20)
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")
	// The hello, the open and the first piece go through; then the tailnet
	// stops answering.
	b.failAfter.Store(3)
	f.startFetch(t, fetchSpec{job: "job-tnfl-0001", src: src, dir: dir, k: "partkey-tnfl-0001", s: fi.Size(), m: fi.ModTime().Unix(), tn: b.tn})
	v := f.fetchUntil(t, "job-tnfl-0001", finished)
	if v.St != "done" {
		t.Fatalf("job: %+v", v)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "tnfail.bin")); string(got) != string(want) {
		t.Fatal("the copy differs")
	}
	if d := roadDials.Load(); d != 1 {
		t.Fatalf("tailcat dialled %d times", d)
	}
	// The rest came by tailcat from the part: the first piece was not asked
	// for again.
	if offs := pieceOffsets(); len(offs) == 0 || offs[0] == "0" {
		t.Fatalf("tailcat's pieces: %v", offs)
	}
}

// A listener that cannot prove it holds the key the page named is not A,
// whoever answers there: the job goes by tailcat and asks it nothing.
func TestFetchTrustsNoTailnetListenerWithoutTheKey(t *testing.T) {
	f := newFetchFixture(t)
	other, _ := tnNewKey(t)
	b := newTnFetchBench(t, f, econKeyPrefix+hex.EncodeToString(other.PublicKey().Bytes()))
	src := filepath.Join(f.home, "Documents", "tnkey.bin")
	want := randomFile(t, src, 1<<20)
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")
	f.startFetch(t, fetchSpec{job: "job-tnky-0001", src: src, dir: dir, k: "partkey-tnky-0001", s: fi.Size(), m: fi.ModTime().Unix(), tn: b.tn})
	v := f.fetchUntil(t, "job-tnky-0001", finished)
	if v.St != "done" {
		t.Fatalf("job: %+v", v)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "tnkey.bin")); string(got) != string(want) {
		t.Fatal("the copy differs")
	}
	if d, n := roadDials.Load(), b.rpcs.Load(); d != 1 || n != 0 {
		t.Fatalf("tailcat dialled %d times, the listener asked %d questions", d, n)
	}
}

// What the page says of A's listener is checked: an address outside
// Tailscale's range, or a key that is none, is no tailnet road at all.
func TestFetchTnArg(t *testing.T) {
	k := "nodekey:" + hex.EncodeToString(make([]byte, 32))
	good := &fetchTn{IP: "100.101.102.103", Port: 8126, Key: k}
	if fetchTnArg(good) == nil {
		t.Fatal("a tailnet listener refused")
	}
	for _, bad := range []*fetchTn{
		nil,
		{IP: "192.168.1.5", Port: 8126, Key: k},
		{IP: "127.0.0.1", Port: 8126, Key: k},
		{IP: "100.128.0.1", Port: 8126, Key: k},
		{IP: "fd7a:115c:a1e0::1", Port: 8126, Key: k},
		{IP: "100.101.102.103", Port: 0, Key: k},
		{IP: "100.101.102.103", Port: 70000, Key: k},
		{IP: "100.101.102.103", Port: 8126, Key: "nodekey:ABC"},
		{IP: "100.101.102.103", Port: 8126, Key: "privkey:" + hex.EncodeToString(make([]byte, 32))},
	} {
		if fetchTnArg(bad) != nil {
			t.Fatalf("taken: %+v", bad)
		}
	}
}

// A grant's key on the tailnet port: let in for its few paths, as on the
// tunnel, and not once the grant is gone.
func TestTailnetLetsAGrantInForItsPathsAlone(t *testing.T) {
	f := newGrantFixture(t)
	ts := &tailnetServer{sessions: map[string]*tnSession{}}
	ts.handler.Store(f.h)
	srv := httptest.NewServer(ts)
	t.Cleanup(srv.Close)
	static, pub := tnNewKey(t)
	node, ok := transport.ParseNodeKey(pub)
	if !ok {
		t.Fatal(pub)
	}
	if _, st := tnOpenAs(t, srv.URL, static, pub); st != http.StatusForbidden {
		t.Fatalf("a key with no grant: open answered %d", st)
	}
	g := f.grantFor(node, filepath.Join(f.home, "Documents"))
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatalf("grant: %+v", r)
	}
	c, st := tnOpenAs(t, srv.URL, static, pub)
	if st != 200 {
		t.Fatalf("a grant's key: open answered %d", st)
	}
	st, body := c.call(http.MethodGet, "/v1/hello", nil)
	fr, err := transport.Decode(body)
	if st != 200 || err != nil || fr.Type != transport.TypeHello || fr.AgentID != agentID() {
		t.Fatalf("hello: %d %s", st, body)
	}
	for _, q := range []struct{ m, p string }{
		{http.MethodPost, "/v1/command"}, {http.MethodGet, "/v1/snapshot"}, {http.MethodPost, "/v1/files/put"},
	} {
		if st, _ := c.call(q.m, q.p, nil); st != http.StatusForbidden {
			t.Fatalf("%s %s: %d", q.m, q.p, st)
		}
	}
	if err := revokeGrant(g.ID, agentID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.call(http.MethodGet, "/v1/hello", nil); st != http.StatusForbidden {
		t.Fatalf("hello after the grant went: %d", st)
	}
	if _, st := tnOpenAs(t, srv.URL, static, pub); st != http.StatusForbidden {
		t.Fatalf("open after the grant went: %d", st)
	}
}

// Whatever answers at the address may not send this machine elsewhere: a
// redirect is no session, and where it points is never asked.
func TestFetchTailnetFollowsNoRedirect(t *testing.T) {
	var elsewhere atomic.Int32
	far := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(far.Close)
	near := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, far.URL+"/inside", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(near.Close)
	other, _ := tnNewKey(t)
	if _, err := openTnRoad(context.Background(), near.URL, econKeyPrefix+hex.EncodeToString(other.PublicKey().Bytes()), "an-agent", key.NewNode()); err == nil {
		t.Fatal("a redirect opened a session")
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the redirect was followed %d times", n)
	}
}
