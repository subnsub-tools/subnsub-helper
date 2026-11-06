package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// testRoad is A's tunnel, inside the test: every request handed to A's
// handler as from the job's node key, a hook first that may fail it the
// way a dropped tunnel does.
type testRoad struct {
	h    http.Handler
	peer key.NodePublic
}

var roadHook struct {
	sync.Mutex
	f    func(r *http.Request) error
	offs []string // the o= of every piece asked for
}

func (t *testRoad) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/v1/files/file" {
		roadHook.Lock()
		roadHook.offs = append(roadHook.offs, r.URL.Query().Get("o"))
		roadHook.Unlock()
	}
	roadHook.Lock()
	hook := roadHook.f
	roadHook.Unlock()
	if hook != nil {
		if err := hook(r); err != nil {
			return nil, err
		}
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r.Clone(transport.WithPeer(r.Context(), t.peer)))
	return rec.Result(), nil
}
func (t *testRoad) HTTP() *http.Client               { return &http.Client{Transport: t} }
func (t *testRoad) Route(ctx context.Context) string { return "direct" }
func (t *testRoad) Close()                           {}

// roadDials counts the roads to A dialled (redialRoad dials again after
// questions fail in a row).
var roadDials atomic.Int32

func setRoadHook(f func(r *http.Request) error) {
	roadHook.Lock()
	roadHook.f = f
	roadHook.offs = nil
	roadHook.Unlock()
}

func pieceOffsets() []string {
	roadHook.Lock()
	defer roadHook.Unlock()
	return append([]string(nil), roadHook.offs...)
}

// fetchReset stops and forgets every job.
func fetchReset(t *testing.T) {
	t.Helper()
	fetches.Lock()
	var runs []*fetchRun
	for _, f := range fetches.m {
		runs = append(runs, f)
	}
	fetches.Unlock()
	for _, f := range runs {
		f.mu.Lock()
		if f.cancel != nil {
			f.stop = true
			f.cancel()
		}
		f.mu.Unlock()
	}
	filesWaitFor(t, "every job to end", func() bool {
		for _, f := range runs {
			f.mu.Lock()
			st := f.rec.St
			f.mu.Unlock()
			if st == "run" {
				return false
			}
		}
		return true
	})
	fetches.Lock()
	fetches.m = map[string]*fetchRun{}
	fetches.loaded = false
	fetches.Unlock()
}

// newFetchFixture is A and B in one process: A's handler serves the grant's
// key, B fetches from it through testRoad.
func newFetchFixture(t *testing.T) *filesFixture {
	t.Helper()
	f := newGrantFixture(t)
	fetchReset(t)
	oldDial, oldSelf, oldBack := fetchDial, fetchSelf, fetchBackoff
	roadDials.Store(0)
	fetchDial = func(addr string, priv key.NodePrivate) fetchRoad {
		roadDials.Add(1)
		return &testRoad{h: f.h, peer: priv.Public()}
	}
	fetchSelf = func() string { return "the-other-machine" }
	fetchBackoff = func(int) time.Duration { return 5 * time.Millisecond }
	setRoadHook(nil)
	t.Cleanup(func() {
		setRoadHook(nil)
		fetchReset(t)
		fetchDial, fetchSelf, fetchBackoff = oldDial, oldSelf, oldBack
	})
	return f
}

func randomFile(t *testing.T, p string, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	writeFile(t, p, b)
	return b
}

type fetchSpec struct {
	job, src, dir, k, mode, agent, addr string
	s, m                                int64
	tn                                  map[string]any // A's tailnet listener, when the page names one
}

// startFetch is the page's whole order: a key from B, a grant for it on A,
// the job to B. The job's id.
func (f *filesFixture) startFetch(t *testing.T, sp fetchSpec) string {
	t.Helper()
	r := f.command(t, f.peer, "fetch-key", map[string]string{"job": sp.job})
	var kb struct {
		Pub string `json:"pub"`
	}
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &kb) != nil {
		t.Fatalf("fetch-key: %+v", r)
	}
	node, ok := transport.ParseNodeKey(kb.Pub)
	if !ok {
		t.Fatalf("fetch-key answered %q", kb.Pub)
	}
	g := f.grantFor(node, sp.src)
	if r := f.enrol(t, g); r.Code != 0 {
		t.Fatalf("grant: %+v", r)
	}
	if sp.agent == "" {
		sp.agent = agentID()
	}
	if sp.addr == "" {
		sp.addr = "tcTESTADDRESSOFMACHINEA0"
	}
	from := map[string]any{"agent": sp.agent, "addr": sp.addr}
	if sp.tn != nil {
		from["tn"] = sp.tn
	}
	r = f.command(t, f.peer, "fetch", map[string]any{
		"job": sp.job, "from": from,
		"grant": g.ID, "dir": sp.dir, "mode": sp.mode,
		"items": []map[string]any{{"p": sp.src, "s": sp.s, "m": sp.m, "k": sp.k}},
	})
	if r.Code != 0 {
		t.Fatalf("fetch: %+v", r)
	}
	return g.ID
}

func (f *filesFixture) fetchStatus(t *testing.T, job string) fetchView {
	t.Helper()
	r := f.command(t, f.peer, "fetch-status", map[string]string{"job": job})
	var b struct {
		Jobs []fetchView `json:"jobs"`
	}
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &b) != nil || len(b.Jobs) != 1 {
		t.Fatalf("fetch-status: %+v", r)
	}
	return b.Jobs[0]
}

func (f *filesFixture) fetchUntil(t *testing.T, job string, done func(v fetchView) bool) fetchView {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		v := f.fetchStatus(t, job)
		if done(v) {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job never got there: %+v", v)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func finished(v fetchView) bool { return fetchFinished(v.St) }

func parts(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), filesPartPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestFetchCopiesAFileHelperToHelper(t *testing.T) {
	f := newFetchFixture(t)
	src := filepath.Join(f.home, "Documents", "big.bin")
	want := randomFile(t, src, 9<<20+123)
	mod := time.Unix(1700000000, 0)
	os.Chtimes(src, mod, mod)
	dir := filepath.Join(f.home, "Reports")
	grant := f.startFetch(t, fetchSpec{job: "job-copy-0001", src: src, dir: dir, k: "partkey-copy-0001", s: int64(len(want)), m: mod.Unix()})
	v := f.fetchUntil(t, "job-copy-0001", finished)
	if v.St != "done" || v.Got != int64(len(want)) || v.Items[0].Path != filepath.Join(dir, "big.bin") {
		t.Fatalf("job: %+v", v)
	}
	got, err := os.ReadFile(filepath.Join(dir, "big.bin"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("the copy differs (%v, %d bytes)", err, len(got))
	}
	if fi, _ := os.Stat(filepath.Join(dir, "big.bin")); !fi.ModTime().Equal(mod) {
		t.Fatalf("modified time %v", fi.ModTime())
	}
	if n := len(pieceOffsets()); n != 3 {
		t.Fatalf("%d pieces for 9 MB", n)
	}
	if p := parts(t, dir); len(p) != 0 {
		t.Fatalf("parts left: %v", p)
	}
	// The job ended its grant on A.
	for _, g := range activeGrants(agentID(), time.Now()) {
		if g.cert.ID == grant {
			t.Fatal("the grant outlived its job")
		}
	}
	// What the page is told carries no key and no address.
	r := f.command(t, f.peer, "fetch-status", map[string]string{})
	if strings.Contains(r.Out, "privkey:") || strings.Contains(r.Out, "tcTESTADDRESS") || !strings.Contains(r.Out, "job-copy-0001") {
		t.Fatalf("status says %s", r.Out)
	}
	if fi, err := os.Stat(fetchesPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("fetches file: %v %v", err, fi)
	}
	if b, _ := os.ReadFile(fetchesPath()); strings.Contains(string(b), "privkey:") {
		t.Fatal("a finished job's key is still kept")
	}
}

func TestFetchGoesOnAfterTheTunnelDrops(t *testing.T) {
	f := newFetchFixture(t)
	src := filepath.Join(f.home, "Documents", "drop.bin")
	want := randomFile(t, src, 9<<20)
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")
	n := 0
	setRoadHook(func(r *http.Request) error {
		if r.URL.Path == "/v1/files/file" {
			n++
			if n == 2 || n == 3 {
				return errors.New("tunnel dropped")
			}
		}
		return nil
	})
	f.startFetch(t, fetchSpec{job: "job-drop-0001", src: src, dir: dir, k: "partkey-drop-0001", s: fi.Size(), m: fi.ModTime().Unix()})
	v := f.fetchUntil(t, "job-drop-0001", finished)
	if v.St != "done" {
		t.Fatalf("job: %+v", v)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "drop.bin")); string(got) != string(want) {
		t.Fatal("the copy differs")
	}
	offs := pieceOffsets()
	if len(offs) != 5 || offs[1] != offs[2] || offs[2] != offs[3] {
		t.Fatalf("pieces asked for at %v", offs)
	}
	// Two failed in a row: the road to A dialled again from nothing.
	if d := roadDials.Load(); d != 2 {
		t.Fatalf("roads dialled: %d", d)
	}
}

// A's path is A's to judge: a Windows path is taken from a Linux or Mac
// page as it is, its name read across either separator.
func TestFetchTakesAPathAsTheOtherWritesIt(t *testing.T) {
	f := newFetchFixture(t)
	if r := f.command(t, f.peer, "fetch-key", map[string]string{"job": "job-win-00000001"}); r.Code != 0 {
		t.Fatal(r)
	}
	r := f.command(t, f.peer, "fetch", map[string]any{
		"job": "job-win-00000001", "from": map[string]string{"agent": "AAAAAAAAAAAA", "addr": "tcTESTADDRESSOFMACHINEA0"},
		"grant": "0123456789abcdef", "dir": filepath.Join(f.home, "Reports"), "mode": "keep",
		"items": []map[string]any{{"p": `C:\Users\u\Docs\report.pdf`, "s": 10, "m": 1700000000, "k": "partkey-win-00000001"}},
	})
	if r.Code != 0 {
		t.Fatalf("fetch of a Windows path: %+v", r)
	}
	fetches.Lock()
	run := fetches.m["job-win-00000001"]
	fetches.Unlock()
	run.mu.Lock()
	it := run.rec.Items[0]
	run.mu.Unlock()
	if it.P != `C:\Users\u\Docs\report.pdf` || it.N != "report.pdf" {
		t.Fatalf("the item: %+v", it)
	}
	for _, bad := range []string{"", "/a\x00b", "Documents/notes.txt", "C:report.pdf"} {
		r := f.command(t, f.peer, "fetch", map[string]any{
			"job": "job-win-00000002", "from": map[string]string{"agent": "AAAAAAAAAAAA", "addr": "tcTESTADDRESSOFMACHINEA0"},
			"grant": "0123456789abcdef", "dir": filepath.Join(f.home, "Reports"),
			"items": []map[string]any{{"p": bad, "s": 1, "m": 1, "k": "partkey-win-00000002"}},
		})
		if r.Code == 0 {
			t.Fatalf("fetch of %q taken", bad)
		}
	}
}

func TestFetchStopsWhenTheFileChanges(t *testing.T) {
	f := newFetchFixture(t)
	src := filepath.Join(f.home, "Documents", "moving.bin")
	randomFile(t, src, 6<<20)
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")
	n := 0
	setRoadHook(func(r *http.Request) error {
		if r.URL.Path == "/v1/files/file" {
			n++
			if n == 2 {
				later := time.Now().Add(time.Hour)
				os.Chtimes(src, later, later)
			}
		}
		return nil
	})
	f.startFetch(t, fetchSpec{job: "job-chg-00001", src: src, dir: dir, k: "partkey-chg-00001", s: fi.Size(), m: fi.ModTime().Unix()})
	v := f.fetchUntil(t, "job-chg-00001", finished)
	if v.St != "err" || v.Err != "changed" {
		t.Fatalf("job: %+v", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "moving.bin")); err == nil {
		t.Fatal("half of a changed file was named")
	}
	if p := parts(t, dir); len(p) != 0 {
		t.Fatalf("the changed file's part is kept: %v", p)
	}
	// Changed before it began: refused at the open.
	f.startFetch(t, fetchSpec{job: "job-chg-00002", src: src, dir: dir, k: "partkey-chg-00002", s: fi.Size(), m: fi.ModTime().Unix()})
	if v := f.fetchUntil(t, "job-chg-00002", finished); v.Err != "changed" {
		t.Fatalf("job: %+v", v)
	}
}

func TestFetchStoppedGoesOnFromItsPart(t *testing.T) {
	f := newFetchFixture(t)
	src := filepath.Join(f.home, "Documents", "stop.bin")
	want := randomFile(t, src, 10<<20)
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")
	n := 0
	setRoadHook(func(r *http.Request) error {
		if r.URL.Path == "/v1/files/file" {
			n++
			if n == 2 {
				// The page presses Stop while the second piece is asked for.
				runFetchCommand("fetch-stop", f.priv.Public().(ed25519.PublicKey), filesArgs{Job: "job-stop-0001"})
				return errors.New("stopped under it")
			}
		}
		return nil
	})
	f.startFetch(t, fetchSpec{job: "job-stop-0001", src: src, dir: dir, k: "partkey-stop-0001", s: fi.Size(), m: fi.ModTime().Unix()})
	if v := f.fetchUntil(t, "job-stop-0001", finished); v.St != "stopped" {
		t.Fatalf("job: %+v", v)
	}
	if p := parts(t, dir); len(p) != 1 {
		t.Fatalf("parts after a stop: %v", p)
	}
	// A new job for the same file and key: from the part, not from the start.
	setRoadHook(nil)
	f.startFetch(t, fetchSpec{job: "job-stop-0002", src: src, dir: dir, k: "partkey-stop-0001", s: fi.Size(), m: fi.ModTime().Unix()})
	if v := f.fetchUntil(t, "job-stop-0002", finished); v.St != "done" {
		t.Fatalf("job: %+v", v)
	}
	if offs := pieceOffsets(); len(offs) == 0 || offs[0] != "4194304" {
		t.Fatalf("the second job asked for pieces at %v", offs)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "stop.bin")); string(got) != string(want) {
		t.Fatal("the copy differs")
	}
	// Forgotten once the page has seen it.
	runFetchCommand("fetch-stop", f.priv.Public().(ed25519.PublicKey), filesArgs{Job: "job-stop-0002", Forget: true})
	if r := f.command(t, f.peer, "fetch-status", map[string]string{"job": "job-stop-0002"}); r.Error != "no-job" {
		t.Fatalf("a forgotten job: %+v", r)
	}
}

func TestFetchRefusals(t *testing.T) {
	f := newFetchFixture(t)
	src := filepath.Join(f.home, "Documents", "notes.txt")
	fi, _ := os.Stat(src)
	dir := filepath.Join(f.home, "Reports")

	// The address answers as another machine than the one named.
	f.startFetch(t, fetchSpec{job: "job-who-00001", src: src, dir: dir, k: "partkey-who-00001", s: fi.Size(), m: fi.ModTime().Unix(), agent: "somebody-else"})
	if v := f.fetchUntil(t, "job-who-00001", finished); v.Err != "wrong-machine" {
		t.Fatalf("job: %+v", v)
	}
	// From itself.
	r := f.command(t, f.peer, "fetch-key", map[string]string{"job": "job-self-0001"})
	if r.Code != 0 {
		t.Fatal(r)
	}
	r = f.command(t, f.peer, "fetch", map[string]any{"job": "job-self-0001", "from": map[string]string{"agent": "the-other-machine", "addr": "tcTESTADDRESSOFMACHINEA0"},
		"grant": "0123456789abcdef", "dir": dir, "items": []map[string]any{{"p": src, "s": 1, "m": 1, "k": "partkey-self-0001"}}})
	if r.Error != "same-machine" {
		t.Fatalf("a fetch from itself: %+v", r)
	}
	// With no key made for it first.
	r = f.command(t, f.peer, "fetch", map[string]any{"job": "job-none-0001", "from": map[string]string{"agent": agentID(), "addr": "tcTESTADDRESSOFMACHINEA0"},
		"grant": "0123456789abcdef", "dir": dir, "items": []map[string]any{{"p": src, "s": 1, "m": 1, "k": "partkey-none-0001"}}})
	if r.Error != "no-job" {
		t.Fatalf("a fetch with no key: %+v", r)
	}
	// A bad name here, a relative path there.
	for _, items := range [][]map[string]any{
		{{"p": src, "s": 1, "m": 1, "k": "partkey-bad-00001", "n": "../up"}},
		{{"p": "Documents/notes.txt", "s": 1, "m": 1, "k": "partkey-bad-00001"}},
		{{"p": src, "s": -1, "m": 1, "k": "partkey-bad-00001"}},
		{{"p": src, "s": 1, "m": 1, "k": "x"}},
	} {
		f.command(t, f.peer, "fetch-key", map[string]string{"job": "job-bad-00001"})
		r = f.command(t, f.peer, "fetch", map[string]any{"job": "job-bad-00001", "from": map[string]string{"agent": agentID(), "addr": "tcTESTADDRESSOFMACHINEA0"},
			"grant": "0123456789abcdef", "dir": dir, "items": items})
		if r.Code == 0 {
			t.Errorf("fetch took %v", items)
		}
	}
	// The grant revoked under it: the job stops, its part stays.
	big := filepath.Join(f.home, "Documents", "revoked.bin")
	randomFile(t, big, 6<<20)
	bfi, _ := os.Stat(big)
	n := 0
	setRoadHook(func(r *http.Request) error {
		if r.URL.Path == "/v1/files/file" {
			n++
			if n == 2 {
				for _, g := range activeGrants(agentID(), time.Now()) {
					revokeGrant(g.cert.ID, agentID(), time.Now())
				}
			}
		}
		return nil
	})
	f.startFetch(t, fetchSpec{job: "job-rev-00001", src: big, dir: dir, k: "partkey-rev-00001", s: bfi.Size(), m: bfi.ModTime().Unix()})
	if v := f.fetchUntil(t, "job-rev-00001", finished); v.Err != "grant-gone" {
		t.Fatalf("job: %+v", v)
	}
	if p := parts(t, dir); len(p) != 1 {
		t.Fatalf("parts after the grant went: %v", p)
	}
}

func TestFetchJobsSurviveARestart(t *testing.T) {
	scratchHome(t)
	fetchReset(t)
	t.Cleanup(func() { fetchReset(t) })
	node := key.NewNode()
	priv, _ := node.MarshalText()
	recs := []fetchRec{
		{Job: "job-kept-0001", St: "run", Node: string(priv), At: 1},
		{Job: "job-kept-0002", St: "run", At: 2},
		{Job: "job-kept-0003", St: "done", At: 3, End: time.Now().Unix()},
	}
	b, _ := json.Marshal(recs)
	os.MkdirAll(filepath.Dir(fetchesPath()), 0o700)
	os.WriteFile(fetchesPath(), b, 0o600)
	fetchLoad()
	fetches.Lock()
	defer fetches.Unlock()
	want := map[string]string{"job-kept-0001": "wait", "job-kept-0002": "err", "job-kept-0003": "done"}
	for job, st := range want {
		if f := fetches.m[job]; f == nil || f.rec.St != st {
			t.Errorf("%s after a restart: %+v", job, f)
		}
	}
}
