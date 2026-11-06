package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func probeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "subnsub-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestProbeConfigValidation(t *testing.T) {
	probeHome(t)
	bad := []string{
		`{"probes":[]}garbage`,
		`{"probes":[]}{"probes":[]}`,
		`{"probes":[{"name":"a","type":"ftp","url":"ftp://x"}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://user:pw@example.com"}]}`,
		`{"probes":[{"name":"a","type":"http","url":"example.com"}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://example.com","method":"POST"}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://example.com","method":"HEAD","keyword":"x"}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://example.com","expect":[42]}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://example.com","interval":5}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://example.com","retries":99}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://example.com","id":"has space"}]}`,
		`{"probes":[{"name":"a","type":"tcp","host":"db","port":0}]}`,
		`{"probes":[{"name":"a","type":"tcp","host":"","port":80}]}`,
		`{"probes":[{"name":"a","type":"tcp","host":"db","port":80,"keyword":"x"}]}`,
		`{"probes":[{"name":"a","type":"dns","host":"example.com","port":53}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://a.example","id":"x"},{"name":"b","type":"http","url":"https://b.example","id":"x"}]}`,
		`{"probes":[{"name":"a","type":"http","url":"https://a.example","bogus":1}]}`,
		`not json`,
	}
	for _, raw := range bad {
		if _, present, err := parseProbeConfig([]byte(raw)); err == nil || !present {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, present, err := parseProbeConfig([]byte("  \n")); err != nil || present {
		t.Fatalf("empty file: %v %v", present, err)
	}
	cfg, present, err := parseProbeConfig([]byte("\ufeff" + `[{"name":" Blog ","type":"HTTP","url":"https://blog.example.com/"},
		{"type":"tcp","host":"2001:db8::1","port":5432,"interval":30,"timeout":45,"retries":2,"tags":{"env":"prod","url":"x","ip":"y"}}]`))
	if err != nil || !present || len(cfg.Probes) != 2 {
		t.Fatalf("%v %v %+v", present, err, cfg)
	}
	a, b := cfg.Probes[0], cfg.Probes[1]
	if a.Name != "Blog" || a.Type != "http" || a.Method != "GET" || a.Interval != probeDefaultEvery || a.Timeout != probeDefaultTimeout || !strings.HasPrefix(a.ID, "p-") {
		t.Fatalf("defaults: %+v", a)
	}
	if b.Name != b.ID || b.Timeout != 30 || len(probeTags(b.Tags)) != 1 || probeTags(b.Tags)[0].Key != "env" {
		t.Fatalf("tcp: %+v tags %+v", b, probeTags(b.Tags))
	}
	// Same target, same id: history survives a rename.
	again, _, _ := parseProbeConfig([]byte(`[{"name":"Weblog","type":"http","url":"https://blog.example.com/"}]`))
	if again.Probes[0].ID != a.ID {
		t.Fatalf("id moved with the name: %s vs %s", again.Probes[0].ID, a.ID)
	}
	// …and is not the target's plain hash: without this machine's key the
	// id says nothing about where the probe points.
	plain := sha256.Sum256([]byte("http\x00https://blog.example.com/"))
	if a.ID == "p-"+base64.RawURLEncoding.EncodeToString(plain[:12]) {
		t.Fatal("derived id is an unkeyed hash of the target")
	}
	if key, err := os.ReadFile(filepath.Join(configDir(), probesKeyFile)); err != nil || len(key) != 32 {
		t.Fatalf("id key not kept: %v", err)
	}
}

func TestProbeHTTPAndTCP(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"status":"ok"}`))
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/teapot":
			w.WriteHeader(418)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	spec := func(path string) probeSpec {
		p := probeSpec{Name: "x", Type: "http", URL: srv.URL + path, Insecure: true}
		if err := normaliseProbe(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r := runProbe(t.Context(), spec("/ok"))
	if !r.ok || r.ms < 0 || r.certDays == nil || r.certValid == nil || !*r.certValid {
		t.Fatalf("ok: %+v", r)
	}
	if r = runProbe(t.Context(), spec("/redirect")); !r.ok {
		t.Fatalf("redirect followed: %+v", r)
	}
	if r = runProbe(t.Context(), spec("/teapot")); r.ok || r.err != "HTTP 418" {
		t.Fatalf("teapot: %+v", r)
	}
	p := spec("/teapot")
	p.Expect = []int{418}
	if r = runProbe(t.Context(), p); !r.ok {
		t.Fatalf("expected teapot: %+v", r)
	}
	p = spec("/ok")
	p.Keyword = `"status":"ok"`
	if r = runProbe(t.Context(), p); !r.ok {
		t.Fatalf("keyword: %+v", r)
	}
	p.Keyword = "absent"
	if r = runProbe(t.Context(), p); r.ok || r.err != "keyword not found" {
		t.Fatalf("keyword miss: %+v", r)
	}
	// Without insecure, the test server's self-signed certificate is a
	// verification failure — down, and the certificate reported invalid.
	p = spec("/ok")
	p.Insecure = false
	if r = runProbe(t.Context(), p); r.ok || r.certValid == nil || *r.certValid {
		t.Fatalf("unverified: %+v", r)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	tp := probeSpec{Name: "db", Type: "tcp", Host: "127.0.0.1", Port: port}
	if err := normaliseProbe(&tp); err != nil {
		t.Fatal(err)
	}
	if r = runProbe(t.Context(), tp); !r.ok {
		t.Fatalf("tcp: %+v", r)
	}
	ln.Close()
	if r = runProbe(t.Context(), tp); r.ok {
		t.Fatalf("closed port: %+v", r)
	}
	_ = tls.Config{}
}

func TestProbeStateAndService(t *testing.T) {
	run := &probeRun{spec: probeSpec{ID: "web", Name: "Web", Type: "http", Retries: 1}, rec: &probeRecord{}}
	at := 1_800_000_000.0
	// up, then one failure (a retry: pending, counts as up), then a second (down).
	probeRecordResult(run, probeResult{at: at, ok: true, ms: 12.5})
	s := serviceOf(run, at)
	if s.Status != serviceUp || s.ResponseMS == nil || *s.ResponseMS != 12.5 || s.Uptime24h == nil || *s.Uptime24h != 100 {
		t.Fatalf("up: %+v", s)
	}
	probeRecordResult(run, probeResult{at: at + 60, ok: false})
	if s = serviceOf(run, at+60); s.Status != servicePending || s.ResponseMS != nil || *s.Uptime24h != 100 {
		t.Fatalf("pending: %+v", s)
	}
	probeRecordResult(run, probeResult{at: at + 120, ok: false})
	if s = serviceOf(run, at+120); s.Status != serviceDown || *s.Uptime24h < 66.6 || *s.Uptime24h > 66.7 {
		t.Fatalf("down: %+v", s)
	}
	// A day later the hourly buckets have aged out of the 24 h window but the
	// daily ones still carry the year.
	if s = serviceOf(run, at+2*86400); s.Uptime24h != nil || s.Uptime30d == nil || *s.Uptime30d != *bucketRatio(run.rec.Days, 0) {
		t.Fatalf("windows: %+v", s)
	}
	run.spec.Maintenance = true
	if s = serviceOf(run, at); s.Status != serviceMaintenance {
		t.Fatalf("maintenance: %+v", s)
	}
	// The wire carries no target, whatever the spec holds.
	run.spec.URL, run.spec.Host = "https://secret.example/x", "db.internal"
	b, _ := json.Marshal(serviceOf(run, at))
	if strings.Contains(string(b), "secret.example") || strings.Contains(string(b), "db.internal") || strings.Contains(string(b), "url") {
		t.Fatalf("wire leaked a target: %s", b)
	}

	// Buckets: bounded, and a clock that steps back folds forward.
	var list []probeBucket
	for i := 0; i < probeHourKeep+10; i++ {
		list = bucketAdd(list, int64(i)*3600, true, probeHourKeep)
	}
	if len(list) != probeHourKeep || list[0].T != 10*3600 {
		t.Fatalf("hour ring: %d from %d", len(list), list[0].T)
	}
	list = bucketAdd(list, 0, false, probeHourKeep)
	if len(list) != probeHourKeep || list[len(list)-1].N != 2 {
		t.Fatalf("backwards clock: %+v", list[len(list)-1])
	}
	if got := cleanBuckets([]probeBucket{{T: 5, N: 1, OK: 1}, {T: 3, N: 1}, {T: 9, N: 1, OK: 2}, {T: 10, N: 2, OK: 1}, {T: 4102444800, N: 1, OK: 1}}, 10, 4000000000); len(got) != 2 || got[1].T != 10 {
		t.Fatalf("cleanBuckets: %+v", got)
	}
}

func TestProbesEndToEnd(t *testing.T) {
	dir := probeHome(t)
	t.Cleanup(func() {
		probes.Lock()
		probes.on, probes.runs, probes.order, probes.checked, probes.present, probes.cfgErr = false, nil, nil, false, false, ""
		probes.Unlock()
	})
	// No file: no source at all, the ordinary machine.
	if s, src := collectProbes(); s != nil || src != nil {
		t.Fatalf("no config: %+v %+v", s, src)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	defer srv.Close()
	cfgPath := filepath.Join(dir, probesFile)
	write := func(body string) {
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"name":"Lab","probes":[{"id":"web","name":"Web","type":"http","url":"` + srv.URL + `"},{"id":"parked","name":"Parked","type":"tcp","host":"127.0.0.1","port":9,"maintenance":true}]}`)
	// One-shot: a synchronous round.
	services, sources := collectProbes()
	if len(sources) != 1 || !sources[0].OK || sources[0].Name != "Lab" || len(services) != 2 {
		t.Fatalf("one-shot: %+v %+v", services, sources)
	}
	if services[0].Status != serviceUp || services[1].Status != serviceMaintenance {
		t.Fatalf("one-shot statuses: %+v", services)
	}
	// Broken file: a source that says so, and nothing pretending to be checked.
	write(`{"probes":[{"type":"nope"}]}`)
	if services, sources = collectProbes(); len(services) != 0 || len(sources) != 1 || sources[0].OK || sources[0].Error != "bad-config" {
		t.Fatalf("bad one-shot: %+v %+v", services, sources)
	}

	// The scheduler: loads, runs, records, saves; a broken rewrite keeps the
	// last good set; a fixed rewrite is picked up.
	write(`{"probes":[{"id":"web","name":"Web","type":"http","url":"` + srv.URL + `"}]}`)
	probes.Lock()
	probes.on, probes.sem, probes.runs = true, make(chan struct{}, probeWorkers), map[string]*probeRun{}
	probes.Unlock()
	probesReload(true)
	probesRunDue()
	for i := 0; i < 200; i++ {
		probes.Lock()
		done := probes.runs["web"].last != nil
		probes.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	services, sources = collectProbes()
	if len(services) != 1 || services[0].Status != serviceUp || services[0].Uptime24h == nil || !sources[0].OK {
		t.Fatalf("scheduled: %+v %+v", services, sources)
	}
	probesSave(true)
	if _, err := os.Stat(filepath.Join(dir, probesStateFile)); err != nil {
		t.Fatalf("state not saved: %v", err)
	}
	write(`{"probes":[{"type":"nope"}]}`)
	probesReload(true)
	if services, sources = collectProbes(); len(services) != 1 || sources[0].OK || sources[0].Error != "bad-config" {
		t.Fatalf("bad rewrite: %+v %+v", services, sources)
	}
	// A fresh process finds the saved buckets for a still-configured id.
	probes.Lock()
	probes.runs = map[string]*probeRun{}
	probes.Unlock()
	write(`{"probes":[{"id":"web","name":"Web","type":"http","url":"` + srv.URL + `"},{"id":"new","name":"New","type":"dns","host":"localhost"}]}`)
	probesReload(true)
	probes.Lock()
	web := probes.runs["web"]
	probes.Unlock()
	if web == nil || web.rec == nil || len(web.rec.Hours) != 1 || web.rec.Hours[0].OK != 1 {
		t.Fatalf("state not restored: %+v", web)
	}
	if services, sources = collectProbes(); len(services) != 2 || !sources[0].OK || services[1].Status != servicePending {
		t.Fatalf("fixed rewrite: %+v %+v", services, sources)
	}

	// A check in flight against the OLD terms of a rewritten probe reports
	// to nobody: the rewrite happens while a slow request hangs, the request
	// then fails, and the probe still shows the fresh start the reload gave it.
	release := make(chan struct{})
	var once sync.Once
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(500)
	}))
	defer slow.Close()
	defer once.Do(func() { close(release) })
	write(`{"probes":[{"id":"web","name":"Web","type":"http","url":"` + slow.URL + `"}]}`)
	probesReload(true)
	probesRunDue()
	for i := 0; i < 200; i++ {
		probes.Lock()
		started := probes.runs["web"].running
		probes.Unlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	write(`{"probes":[{"id":"web","name":"Web","type":"http","url":"` + srv.URL + `","maintenance":true}]}`)
	probesReload(true)
	once.Do(func() { close(release) })
	for i := 0; i < 200; i++ {
		probes.Lock()
		running := probes.runs["web"].running
		probes.Unlock()
		if !running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	probes.Lock()
	web = probes.runs["web"]
	probes.Unlock()
	if web.last != nil || web.fails != 0 || web.next != 0 || web.rec.Hours[0].N != 1 {
		t.Fatalf("stale result was recorded: last=%+v fails=%d next=%v hours=%+v", web.last, web.fails, web.next, web.rec.Hours)
	}
}
