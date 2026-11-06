package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// Point the config directory at a scratch HOME so nothing here touches the
// developer's real ~/.config/subnsub-helper.
func scratchHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(directEnvVar, "")
	os.Unsetenv(directEnvVar)
	t.Setenv(derpMapEnvVar, "")
	os.Unsetenv(derpMapEnvVar)
	return home
}

func TestDirectSwitchIsAFile(t *testing.T) {
	home := scratchHome(t)
	if directEnabled() {
		t.Fatal("direct is on with nothing written")
	}
	if err := setDirect(true); err != nil {
		t.Fatal(err)
	}
	if !directEnabled() {
		t.Fatal("direct is off after setDirect(true)")
	}
	fi, err := os.Stat(filepath.Join(home, ".config", "subnsub-helper", directFileName))
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("switch file: %v %v", err, fi)
	}
	if err := setDirect(false); err != nil {
		t.Fatal(err)
	}
	if directEnabled() {
		t.Fatal("direct is on after setDirect(false)")
	}
	// The environment wins over the file, both ways.
	setDirect(true)
	t.Setenv(directEnvVar, "0")
	if directEnabled() {
		t.Fatal("MON_DIRECT=0 did not override the file")
	}
	setDirect(false)
	t.Setenv(directEnvVar, "yes")
	if !directEnabled() {
		t.Fatal("MON_DIRECT=yes did not override the file")
	}
}

func TestTransportModeDefaultsToAuto(t *testing.T) {
	t.Setenv(transportEnvVar, "")
	if transportMode() != "auto" {
		t.Fatal("empty is not auto")
	}
	t.Setenv(transportEnvVar, " Relay ")
	if transportMode() != "relay" {
		t.Fatal("relay not recognised")
	}
	t.Setenv(transportEnvVar, "tailcat")
	if transportMode() != "tailcat" {
		t.Fatal("tailcat not recognised")
	}
	t.Setenv(transportEnvVar, "carrier-pigeon")
	if transportMode() != "auto" {
		t.Fatal("an unknown mode must fall back to auto, not be taken literally")
	}
}

func TestAllowlistAppendsAndStrikes(t *testing.T) {
	home := scratchHome(t)
	k1, k2 := key.NewNode().Public(), key.NewNode().Public()
	if got := loadAllowedClients(); len(got) != 0 {
		t.Fatalf("fresh install allows %d keys", len(got))
	}
	if err := allowClient(k1.String()); err != nil {
		t.Fatal(err)
	}
	if err := allowClient(k1.String()); err != nil {
		t.Fatalf("allowing twice must be a no-op, got %v", err)
	}
	if err := allowClient(k2.String() + " # second browser"); err != nil {
		t.Fatal(err)
	}
	got := loadAllowedClients()
	if len(got) != 2 || got[0] != k1 || got[1] != k2 {
		t.Fatalf("allowlist is %v", got)
	}
	path := filepath.Join(home, ".config", "subnsub-helper", allowedClientsFile)
	fi, _ := os.Stat(path)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("allowlist is %v, want owner-only", fi.Mode().Perm())
	}
	// Garbage is refused before it can reach the file.
	for _, bad := range []string{"", "nodekey:", "privkey:" + strings.Repeat("0", 64), "AAAA"} {
		if err := allowClient(bad); err == nil {
			t.Fatalf("%q was allowed", bad)
		}
	}
	if err := disallowClient(k1.String()); err != nil {
		t.Fatal(err)
	}
	got = loadAllowedClients()
	if len(got) != 1 || got[0] != k2 {
		t.Fatalf("after disallow: %v", got)
	}
	// Removing the last key leaves an empty file, and an empty list means
	// the tunnel refuses to start — never "allow everyone".
	if err := disallowClient(k2.String()); err != nil {
		t.Fatal(err)
	}
	if got := loadAllowedClients(); len(got) != 0 {
		t.Fatalf("after removing all: %v", got)
	}
	if err := disallowClient(k2.String()); err != nil {
		t.Fatalf("disallow on an absent key must be quiet: %v", err)
	}
}

func TestDerpMapURLRequiresHTTPS(t *testing.T) {
	home := scratchHome(t)
	if derpMapURL() != "" {
		t.Fatal("a fresh install has a DERP map override")
	}
	conf := filepath.Join(home, ".config", "subnsub-helper")
	os.MkdirAll(conf, 0o700)
	os.WriteFile(filepath.Join(conf, derpMapFileName), []byte("http://derp.example/derpmap.json\n"), 0o600)
	if derpMapURL() != "" {
		t.Fatal("a plain-http DERP map was accepted")
	}
	os.WriteFile(filepath.Join(conf, derpMapFileName), []byte("https://derp.example/derpmap.json\n"), 0o600)
	if derpMapURL() != "https://derp.example/derpmap.json" {
		t.Fatal("the file's URL was not read")
	}
	t.Setenv(derpMapEnvVar, "https://env.example/map.json")
	if derpMapURL() != "https://env.example/map.json" {
		t.Fatal("the environment did not win over the file")
	}
}

// What a watcher gets through the tunnel: exactly three answers, every one a
// frame this build's own decoder accepts, and observe is the only capability
// any of them names.
func TestDirectHandlerServesFramesOnly(t *testing.T) {
	scratchHome(t)
	h := newDirectHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	get := func(p string) (int, []byte) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf strings.Builder
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			buf.WriteString(sc.Text())
		}
		return resp.StatusCode, []byte(buf.String())
	}

	st, b := get("/v1/hello")
	if st != 200 {
		t.Fatalf("hello: %d", st)
	}
	f, body, err := directJSON(b)
	if err != nil || f.Type != transport.TypeHello {
		t.Fatalf("hello frame: %v %+v", err, f)
	}
	caps, _ := body["caps"].([]any)
	if len(caps) != 1 || caps[0] != transport.CapObserve {
		t.Fatalf("hello grants %v, want observe only", caps)
	}
	if body["carrier"] != "tailcat" || body["helper_version"] != helperVersion {
		t.Fatalf("hello body %v", body)
	}

	st, b = get("/v1/snapshot")
	if st != 200 {
		t.Fatalf("snapshot: %d", st)
	}
	f, body, err = directJSON(b)
	if err != nil || f.Type != transport.TypeSnapshot {
		t.Fatalf("snapshot frame: %v %+v", err, f)
	}
	if _, ok := body["providers"]; !ok {
		t.Fatalf("snapshot body is not a reading: %v", body)
	}
	if f.AgentID == "" {
		t.Fatal("snapshot frame carries no agent id")
	}

	// Anything else — including the paths the relay path answers — is a
	// refusal in frame form, never a handler.
	for _, p := range []string{"/", "/quota", "/events", "/v1/exec", "/v1/update", "/v1/sessions", "/v2/hello"} {
		st, b = get(p)
		if st != 404 {
			t.Fatalf("%s answered %d", p, st)
		}
		f, body, err := directJSON(b)
		if err != nil || f.Type != transport.TypeError || body["code"] != "unknown-frame" {
			t.Fatalf("%s refusal: %v %+v %v", p, err, f, body)
		}
	}
	resp, _ := http.Post(srv.URL+"/v1/snapshot", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 405 {
		t.Fatalf("POST answered %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// The stream opens with hello and a snapshot, then carries the host block —
// as SSE data lines that are frames — and it is capped.
// A self-hosted panel keeps its own copy of the browser client, which ends a
// stream at any frame type it does not know: the default stream may not grow
// one (monitor-docs.html promises this).
func TestDirectEventsStaysReadableByPublishedClients(t *testing.T) {
	scratchHome(t)
	startSysSampler()
	srv := httptest.NewServer(newDirectHandler())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for n < 5 && sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		f, err := transport.Decode([]byte(strings.TrimPrefix(line, "data: ")))
		if err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case transport.TypeHello, transport.TypeSnapshot, transport.TypeSystem:
		default:
			t.Fatalf("the default stream carried a %q frame, which published clients end the stream on", f.Type)
		}
		n++
	}
	if n < 5 {
		t.Fatalf("stream gave %d frames", n)
	}
}

func TestDirectEventsStreamShapeAndCap(t *testing.T) {
	scratchHome(t)
	startSysSampler()
	h := newDirectHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var types []string
	for sc.Scan() && len(types) < 3 {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		f, err := transport.Decode([]byte(strings.TrimPrefix(line, "data: ")))
		if err != nil {
			t.Fatalf("stream carried a frame this build refuses: %v", err)
		}
		types = append(types, f.Type)
	}
	if len(types) < 3 || types[0] != transport.TypeHello || types[1] != transport.TypeSnapshot || types[2] != transport.TypeSystem {
		t.Fatalf("stream opened with %v", types)
	}

	// Fill the remaining slots; the next open is refused with a frame.
	var held []*http.Response
	defer func() {
		for _, r := range held {
			r.Body.Close()
		}
	}()
	for i := 1; i < directMaxStreams; i++ {
		r, err := http.DefaultClient.Do(req.Clone(ctx))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, r)
	}
	r, err := http.DefaultClient.Do(req.Clone(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatalf("stream %d answered %d, want busy", directMaxStreams+1, r.StatusCode)
	}
}

// The relay push and the tunnel each get their own view of the sampler: a
// direct snapshot must not eat the series the next push is owed.
func TestDirectSnapshotDoesNotConsumeSeries(t *testing.T) {
	scratchHome(t)
	startSysSampler()
	// Two samples are the minimum for a series; the sampler ticks once a
	// second and the test cannot wait for it, so record one by hand.
	recordSysSample(collectSystem())
	time.Sleep(20 * time.Millisecond)
	recordSysSample(collectSystem())
	before := len(sampler.buf)
	_ = collectAllOpts(false)
	if sampler.sent != 0 && len(sampler.buf) == before {
		// sent is only ever moved by sampledSystem; an untouched mark after
		// the direct path proves the two do not share it.
		t.Fatalf("direct snapshot moved the relay's sent mark to %v", sampler.sent)
	}
	if sys := latestSystem(); sys == nil {
		t.Fatal("latestSystem returned nothing with samples recorded")
	}
	// And the consuming path still consumes.
	_ = collectAllOpts(true)
	if sampler.sent == 0 {
		t.Fatal("relay snapshot did not consume the series")
	}
}

// The dashboard's `allow` command: key on the list, switch set so a restart
// keeps the road, tunnel started once — and idempotent, because the page asks
// again whenever it cannot get an answer.
func TestRunAllowEnrolsAKeyAndStartsTheTunnelOnce(t *testing.T) {
	scratchHome(t)
	t.Setenv(transportEnvVar, "")
	os.Unsetenv(transportEnvVar)
	started := 0
	prev := startDirect
	startDirect = func() { started++ }
	t.Cleanup(func() { startDirect = prev; directOnce = sync.Once{} })
	directOnce = sync.Once{}

	pub := key.NewNode().Public().String()
	r := runAllow("cmd-1", pub)
	if r.Code != 0 || r.Error != "" || r.Kind != "allow" || r.Target != pub {
		t.Fatalf("allow: %+v", r)
	}
	if !directEnabled() {
		t.Error("the switch was not set: a restart would lose the road")
	}
	if got := loadAllowedClients(); len(got) != 1 || got[0].String() != pub {
		t.Errorf("allowlist = %v, want just %s", got, pub)
	}
	if started != 1 {
		t.Errorf("tunnel starts = %d, want 1", started)
	}
	// Asked again — the page repeats itself when it gets no answer.
	if r2 := runAllow("cmd-2", pub); r2.Code != 0 || r2.Error != "" {
		t.Errorf("second allow: %+v", r2)
	}
	if got := loadAllowedClients(); len(got) != 1 {
		t.Errorf("allowlist grew to %d entries for one key", len(got))
	}
	if started != 1 {
		t.Errorf("tunnel starts after a repeat = %d, want still 1", started)
	}
	// Not a key: refused before anything is written.
	if r3 := runAllow("cmd-3", "nodekey:zz"); r3.Code != -1 || r3.Error != "bad-key" {
		t.Errorf("bad key: %+v", r3)
	}
	// Pinned to the relay for this run: refused with its own reason, and the
	// list is not touched either.
	t.Setenv(transportEnvVar, "relay")
	other := key.NewNode().Public().String()
	if r4 := runAllow("cmd-4", other); r4.Code != -1 || r4.Error != "direct-off" {
		t.Errorf("relay-pinned: %+v", r4)
	}
	if got := loadAllowedClients(); len(got) != 1 {
		t.Errorf("relay-pinned allow wrote to the list: %v", got)
	}
}

// The switch goes on before the key goes on the list, so a failure between
// the two never leaves a key admitted under a result that said "failed".
func TestRunAllowSetsTheSwitchBeforeTheKey(t *testing.T) {
	home := scratchHome(t)
	t.Setenv(transportEnvVar, "")
	os.Unsetenv(transportEnvVar)
	prev := startDirect
	startDirect = func() {}
	t.Cleanup(func() { startDirect = prev; directOnce = sync.Once{} })
	directOnce = sync.Once{}
	// A config directory that exists but cannot take a new file.
	conf := configDir()
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(conf, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(conf, 0o700) })
	if os.Getuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	pub := key.NewNode().Public().String()
	r := runAllow("cmd-ro", pub)
	if r.Code != -1 || r.Error != "allow-failed" {
		t.Fatalf("read-only conf: %+v", r)
	}
	if got := loadAllowedClients(); len(got) != 0 {
		t.Errorf("a failed allow left a key on the list: %v (home %s)", got, home)
	}
}

// The tunnel's command door: the same envelope the mailbox carries, judged by
// the same code. Nothing here reaches a network — the handler is driven
// directly, as the gate would drive it for an admitted peer.
func TestTunnelRenamePersistsOnlySignedCommands(t *testing.T) {
	scratchHome(t)
	t.Setenv("MON_CONSOLE", "0")
	t.Setenv("MON_UPDATE", "0")
	h := newDirectHandler()
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	post := func(c consoleCmd) consoleResult {
		t.Helper()
		f, _ := transport.New(transport.TypeCommand, "", c.ID, transport.Command{Kind: c.Kind, Cmd: c.Cmd, Sig: c.Sig, At: c.IssuedAt})
		b, _ := transport.Encode(f)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/command", strings.NewReader(string(b))))
		if rec.Code != http.StatusOK {
			t.Fatalf("command status %d: %s", rec.Code, rec.Body.String())
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
	for i, name := range []string{"\u4e1c\u4eac\U0001f680", ""} {
		id := []string{"rename-set", "rename-clear"}[i]
		c := signedCmd(t, priv, agentID(), consoleCmd{ID: id, Kind: "rename", Cmd: name})
		bad := c
		bad.Cmd = "tampered"
		if res := post(bad); res.Error != "bad-signature" {
			t.Fatalf("altered name was not refused: %+v", res)
		}
		if res := post(c); res.Code != 0 || res.Error != "" || res.Out != name {
			t.Fatalf("rename failed: %+v", res)
		}
		if got := agentLabel(); got != name {
			t.Fatalf("live name %q, want %q", got, name)
		}
		if _, got := resolveAgent(configDir(), "", "old name"); got != name {
			t.Fatalf("restart name %q, want %q", got, name)
		}
		if res := post(c); res.Error != "replayed-command" {
			t.Fatalf("replay was not refused: %+v", res)
		}
	}
}

func TestTunnelCommandRoute(t *testing.T) {
	scratchHome(t)
	h := newDirectHandler()
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/command", strings.NewReader(body))
		h.ServeHTTP(rec, req)
		return rec
	}
	// A read verb on the write door.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/command", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/command = %d, want 405", rec.Code)
	}
	// Not a frame.
	if rec := post("{not json"); rec.Code != http.StatusBadRequest {
		t.Errorf("garbage = %d, want 400", rec.Code)
	}
	// A frame of the wrong type.
	f, _ := transport.New(transport.TypeHello, "", "x1", transport.Hello{Caps: []string{"observe"}})
	b, _ := transport.Encode(f)
	if rec := post(string(b)); rec.Code != http.StatusBadRequest {
		t.Errorf("hello on the command door = %d, want 400", rec.Code)
	}
	result := func(rec *httptest.ResponseRecorder, id string) consoleResult {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d, want 200: %s", id, rec.Code, rec.Body.String())
		}
		out, err := transport.Decode(rec.Body.Bytes())
		if err != nil || out.Type != transport.TypeResult || out.ID != id {
			t.Fatalf("%s: result frame %+v %v", id, out, err)
		}
		var res consoleResult
		if err := json.Unmarshal(out.Body, &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	caps := func() []string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/hello", nil))
		hf, _ := transport.Decode(rec.Body.Bytes())
		var hello transport.Hello
		json.Unmarshal(hf.Body, &hello)
		return hello.Caps
	}
	// Nothing pinned: the tunnel takes no command at all, whatever the
	// switches say — "allowed to watch" is not "allowed to command" — and the
	// hello names nothing but observe.
	t.Setenv("MON_CONSOLE", "1")
	f, _ = transport.New(transport.TypeCommand, "", "cmd-9", transport.Command{Kind: "inspect", Target: "process"})
	b, _ = transport.Encode(f)
	if res := result(post(string(b)), "cmd-9"); res.Code != -1 || res.Error != "unpinned" {
		t.Errorf("unpinned machine: %+v, want unpinned", res)
	}
	if c := caps(); len(c) != 1 || c[0] != transport.CapObserve {
		t.Errorf("unpinned hello caps = %v, want observe only", c)
	}
	// A dashboard key pinned: now the console capability is named (its
	// switch is on) and commands are judged by signature.
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	named, inspect := false, false
	for _, c := range caps() {
		if c == transport.CapConsole {
			named = true
		}
		if c == transport.CapInspect {
			inspect = true
		}
	}
	if !named {
		t.Errorf("pinned hello caps = %v, want console (its switch is on)", caps())
	}
	// Inspect is named exactly where /proc shows other processes: it is no
	// switch (2026-10-13), so the hello follows the probe.
	if inspect != diagnosticsAvailable() {
		t.Errorf("hello names inspect = %v, diagnostics available = %v: %v", inspect, diagnosticsAvailable(), caps())
	}
	// Unsigned, with a key pinned: refused as such.
	if res := result(post(string(b)), "cmd-9"); res.Error != "unsigned" {
		t.Errorf("unsigned on a pinned machine: %+v", res)
	}
	sign := func(id, kind, target, cmd string) transport.Command {
		at := time.Now().Unix()
		sig := ed25519.Sign(priv, commandSigningInput(agentID(), id, kind, target, at, cmd))
		return transport.Command{Kind: kind, Cmd: cmd, Target: target, Sig: base64.StdEncoding.EncodeToString(sig), At: at}
	}
	// Signed inspect: answered with a table where /proc allows, and with
	// the capability's own reason where it does not.
	f, _ = transport.New(transport.TypeCommand, "", "cmd-12", sign("cmd-12", "inspect", "process", ""))
	b, _ = transport.Encode(f)
	if res := result(post(string(b)), "cmd-12"); diagnosticsAvailable() && res.Error != "" {
		t.Errorf("signed inspect where /proc allows: %+v", res)
	} else if !diagnosticsAvailable() && res.Error != "diagnostics-off" {
		t.Errorf("signed inspect without /proc: %+v", res)
	}
	// Signed, unknown kind: answered too, so the page can say "too old".
	f, _ = transport.New(transport.TypeCommand, "", "cmd-13", sign("cmd-13", "teleport", "", ""))
	b, _ = transport.Encode(f)
	if res := result(post(string(b)), "cmd-13"); res.Error != "unknown-kind" {
		t.Errorf("unknown kind: %+v", res)
	}
	// A shell kind with no line: refused rather than run empty (before the
	// signature is even looked at, as on the mailbox).
	f, _ = transport.New(transport.TypeCommand, "", "cmd-14", transport.Command{Kind: "sh"})
	b, _ = transport.Encode(f)
	if res := result(post(string(b)), "cmd-14"); res.Error != "unknown-kind" {
		t.Errorf("empty sh: %+v", res)
	}
	// The same id twice is a replay.
	f, _ = transport.New(transport.TypeCommand, "", "cmd-13", sign("cmd-13", "teleport", "", ""))
	b, _ = transport.Encode(f)
	if res := result(post(string(b)), "cmd-13"); res.Error != "replayed-command" {
		t.Errorf("replayed id: %+v", res)
	}
}

// The machine's own history: readings fold into five-minute buckets in the
// dashboard's row shape, roll into the file on a boundary, and come back out
// with the bucket in progress appended.
func TestHistoryFoldsAndServes(t *testing.T) {
	scratchHome(t)
	sampler.Lock()
	sampler.on = true
	sampler.Unlock()
	hist.Lock()
	hist.loaded, hist.rows, hist.cur = false, nil, nil
	hist.Unlock()
	t.Cleanup(func() {
		sampler.Lock()
		sampler.on = false
		sampler.Unlock()
		hist.Lock()
		hist.loaded, hist.rows, hist.cur = false, nil, nil
		hist.Unlock()
	})
	f := func(v float64) *float64 { return &v }
	snap := &Snapshot{
		System: &System{CPUPercent: f(12.34), MemUsedPercent: f(50), DiskUsedPercent: f(70.06),
			DiskReadBps: f(1234), DiskWriteBps: f(9876),
			Mounts: []Mount{{Path: "/Data", UsedPercent: f(42)}, {Path: "/data", UsedPercent: f(61)}},
			Series: &SysSeries{CPU: []*float64{f(80.5), nil, f(20)}}},
		Providers: []Provider{{ID: "claude", OK: true, Limits: []Limit{{UsedPercent: 30}, {UsedPercent: 65.25}}},
			{ID: "codex", OK: false, Limits: []Limit{{UsedPercent: 99}}}},
		ServiceSources: []ServiceSource{{ID: "probes", OK: true}},
		Services:       []Service{{ID: "web", Source: "probes", Status: 1}, {ID: "orphan", Source: "gone", Status: 0}},
	}
	historyRecord(snap)
	historyRecord(&Snapshot{System: &System{CPUPercent: f(5), DiskUsedPercent: f(71),
		DiskReadBps: f(8000), DiskWriteBps: f(2000),
		Mounts: []Mount{{Path: "/Data", UsedPercent: f(75)}, {Path: "/missing"}}},
		ServiceSources: []ServiceSource{{ID: "probes", OK: true}},
		Services:       []Service{{ID: "web", Source: "probes", Status: 0}}})
	historyRecord(&Snapshot{System: &System{DiskUsedPercent: f(60)},
		ServiceSources: []ServiceSource{{ID: "probes", OK: true}},
		Services:       []Service{{ID: "web", Source: "probes", Status: 1}}})
	sec, pts := historyPoints()
	if sec != histBucketSec || len(pts) != 1 {
		t.Fatalf("points = %d rows (bucket %d), want the one in progress", len(pts), sec)
	}
	row := pts[0]
	// Ten columns, and an eleventh, the processes' names, when the sampler an
	// earlier test started has swept /proc twice by now (every 10 s; a busy
	// machine gets there first).
	if len(row) != 10 && (len(row) != 11 || row[10] == nil) {
		t.Fatalf("row width %d, want 10 (or 11 with the processes): %v", len(row), row)
	}
	if got := row[1].(float64); got != 80.5 {
		t.Errorf("cpu peak = %v, want 80.5 (the series lane, not the scalar)", got)
	}
	if got := row[3].(float64); got != 71 {
		t.Errorf("disk = %v, want the peak, 71", got)
	}
	if row[4] != nil {
		t.Errorf("swap = %v, want nil when never read", row[4])
	}
	q := row[7].(map[string]float64)
	if q["claude"] != 65.3 || len(q) != 1 {
		t.Errorf("quota = %v, want claude 65.3 only (codex was not ok)", q)
	}
	s := row[8].(map[string]int)
	if s["web"] != 0 || len(s) != 1 {
		t.Errorf("services = %v, want web:0 — the worst state seen in the bucket — and nothing for orphan (its source was down)", s)
	}
	sys := row[9].(map[string]float64)
	if sys["io_read"] != 8000 || sys["io_write"] != 9876 {
		t.Errorf("I/O peaks = %v, want asymmetric read=8000 write=9876", sys)
	}
	if sys["mount:/Data"] != 75 || sys["mount:/data"] != 61 {
		t.Errorf("mount peaks = %v, want case-sensitive identities and maxima", sys)
	}
	if _, ok := sys["mount:/missing"]; ok {
		t.Errorf("missing mount measurement became a value: %v", sys)
	}
	// A bucket from an earlier window rolls into the file when the next one
	// opens.
	hist.Lock()
	hist.cur.start -= 2 * histBucketSec
	hist.Unlock()
	historyRecord(&Snapshot{System: &System{CPUPercent: f(1)}})
	_, pts = historyPoints()
	if len(pts) != 2 {
		t.Fatalf("after rollover: %d rows, want archive + current", len(pts))
	}
	if _, err := os.Stat(filepath.Join(configDir(), histFileName)); err != nil {
		t.Errorf("history file not written: %v", err)
	}
	// A fresh process reads it back.
	hist.Lock()
	hist.loaded, hist.rows, hist.cur = false, nil, nil
	hist.Unlock()
	_, pts = historyPoints()
	if len(pts) != 1 {
		t.Errorf("reloaded archive: %d rows, want 1", len(pts))
	}
}

func TestHistoryMountPeakIsBoundedAndDeterministic(t *testing.T) {
	system := map[string]float64{"io_read": 1}
	for i := 39; i >= 0; i-- {
		mountPeak(system, fmt.Sprintf("mount:/m%02d", i), float64(i))
	}
	if len(system) != histMountMax+1 {
		t.Fatalf("system map has %d entries, want 32 mounts plus I/O", len(system))
	}
	for i := 0; i < histMountMax; i++ {
		if _, ok := system[fmt.Sprintf("mount:/m%02d", i)]; !ok {
			t.Errorf("deterministic cap omitted /m%02d: %v", i, system)
		}
	}
	if _, ok := system["mount:/m32"]; ok {
		t.Errorf("cap retained a path beyond the sorted first 32: %v", system)
	}
	mountPeak(system, "mount:/m00", 99)
	if system["mount:/m00"] != 99 {
		t.Errorf("existing mount did not keep its maximum: %v", system)
	}
}
