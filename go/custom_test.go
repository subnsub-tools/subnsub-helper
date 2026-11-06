package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func customHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "subnsub-helper", customDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCustomConfigValidation(t *testing.T) {
	bad := []string{
		`{"tiles":[]}garbage`,
		`{"tiles":[{"id":"a","value":1,"bogus":true}]}`,
		`{"tiles":[{"id":"a"}]}`,                                          // no value, no exec
		`{"tiles":[{"id":"has space","value":1}]}`,                        // id shape
		`{"tiles":[{"id":"a","value":1},{"id":"a","value":2}]}`,           // twice
		`{"tiles":[{"id":"a","type":"dial","value":1}]}`,                  // type
		`{"tiles":[{"id":"a","type":"gauge","value":1,"min":5,"max":1}]}`, // track
		`{"tiles":[{"id":"a","type":"number","value":1,"min":0}]}`,        // min on a number
		`{"tiles":[{"id":"a","value":1,"unit":"furlongs"}]}`,              // unit vocabulary
		`{"tiles":[{"id":"a","value":1,"unit":"bytes","suffix":"x"}]}`,    // both
		`{"tiles":[{"id":"a","value":1,"suffix":"kilowatt hours"}]}`,      // suffix length/space
		`{"tiles":[{"id":"a","type":"status","value":"meh"}]}`,            // state
		`{"tiles":[{"id":"a","type":"status","value":12}]}`,               // state as number
		`{"tiles":[{"id":"a","type":"text","value":"x","unit":"count"}]}`, // unit on text
		`{"tiles":[{"id":"a","value":1,"warn":90,"bad":50}]}`,             // bad below warn
		`{"tiles":[{"id":"a","value":1,"invert":true,"warn":10,"bad":50}]}`,
		`{"tiles":[{"id":"a","value":1,"alerts":false,"warn":5}]}`,
		`{"tiles":[{"id":"a","value":1,"icon":"Robot"}]}`,    // icon shape
		`{"tiles":[{"id":"a","value":1,"icon":"emoji:ab"}]}`, // ascii is not an emoji
		`{"tiles":[{"id":"a","value":1,"tint":"beige"}]}`,
		`{"tiles":[{"id":"a","value":1,"at":1700000000000}]}`, // milliseconds
		`{"tiles":[{"id":"a","value":1,"ttl":1}]}`,
		`{"tiles":[{"id":"a","value":1,"fold":"avg"}]}`,
		`{"tiles":[{"id":"a","type":"text","value":"x","history":true}]}`,
		`{"tiles":[{"id":"a","value":1,"interval":30}]}`,    // interval without exec
		`{"tiles":[{"id":"a","exec":"","type":"number"}]}`,  // empty command
		`{"tiles":[{"id":"a","exec":[],"type":"number"}]}`,  // empty argv
		`{"tiles":[{"id":"a","exec":"true","interval":1}]}`, // interval floor
		`{"tiles":[{"id":"a","value":1,"label":"x"}]}`,      // label on a number
		`{"tiles":[{"id":"a","value":1e20}]}`,               // too large to show
		`not json`,
	}
	for _, raw := range bad {
		if _, present, err := parseCustomConfig([]byte(raw)); err == nil || !present {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, present, err := parseCustomConfig([]byte("  \n")); err != nil || present {
		t.Fatalf("empty file: %v %v", present, err)
	}
	cfg, present, err := parseCustomConfig([]byte("\ufeff" + `[
		{"name": "GPU temp", "type": "gauge", "value": 71, "unit": "°C", "max": 100, "history": true},
		{"id": "ups", "type": "gauge", "value": "96%", "invert": true},
		{"id": "backup", "value": "OK", "label": "02:14 · 38 GB", "icon": "emoji:🛡️"},
		{"id": "build", "value": "v2026.09.17.2", "tint": "muted"},
		{"id": "solar", "value": 12.4, "suffix": "kWh", "at": 1789800000, "tags": {"site": "roof", "b": "2"}},
		{"id": "fan", "exec": "echo 1200", "unit": "rpm", "interval": 30, "timeout": 45}
	]`))
	if err != nil || !present || len(cfg.Tiles) != 6 {
		t.Fatalf("%v %v %+v", present, err, cfg)
	}
	gpu, ups, backup, build, solar, fan := cfg.Tiles[0], cfg.Tiles[1], cfg.Tiles[2], cfg.Tiles[3], cfg.Tiles[4], cfg.Tiles[5]
	if gpu.ID != "gpu-temp" || gpu.Unit != "celsius" || *gpu.Min != 0 || *gpu.Max != 100 || *gpu.Warn != 75 || *gpu.Bad != 90 || gpu.Fold != "" || *gpu.num != 71 {
		t.Fatalf("gpu defaults: %+v", gpu)
	}
	if ups.Name != "ups" || *ups.num != 96 || *ups.Warn != 25 || *ups.Bad != 10 || ups.Fold != "min" {
		t.Fatalf("inverted gauge: %+v warn %v bad %v", ups, *ups.Warn, *ups.Bad)
	}
	if backup.Type != "status" || backup.state != "ok" || backup.Label != "02:14 · 38 GB" || backup.Icon != "emoji:🛡️" {
		t.Fatalf("status: %+v", backup)
	}
	if build.Type != "text" || build.text != "v2026.09.17.2" || build.Warn != nil {
		t.Fatalf("text: %+v", build)
	}
	if solar.Type != "number" || solar.Suffix != "kWh" || *solar.TTL != tileDefaultTTL || len(tileTags(solar.Tags)) != 2 || tileTags(solar.Tags)[0].Key != "b" {
		t.Fatalf("number: %+v tags %+v", solar, tileTags(solar.Tags))
	}
	if !fan.hasExec() || fan.shell != "echo 1200" || fan.Interval != 30 || fan.Timeout != 30 || fan.Type != "number" {
		t.Fatalf("exec: %+v", fan)
	}
}

func TestCustomTileOfStale(t *testing.T) {
	cfg, _, err := parseCustomConfig([]byte(`[
		{"id": "fresh", "value": 1, "at": 1789800000, "ttl": 60},
		{"id": "static", "value": 2},
		{"id": "mtime", "value": 3, "ttl": 60}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	mod := time.Unix(1789800000, 0)
	at := 1789800030.0
	fresh := tileOf(&cfg.Tiles[0], "f", mod, at)
	if fresh.Stale || *fresh.At != 1789800000 || fresh.Source != "f" || *fresh.Value != 1 {
		t.Fatalf("fresh: %+v", fresh)
	}
	if old := tileOf(&cfg.Tiles[0], "f", mod, at+100); !old.Stale {
		t.Fatalf("should be stale: %+v", old)
	}
	if st := tileOf(&cfg.Tiles[1], "f", mod, at+1e6); st.Stale || *st.At != 1789800000 {
		t.Fatalf("a declaration never goes stale: %+v", st)
	}
	if m := tileOf(&cfg.Tiles[2], "f", mod, at+100); !m.Stale || *m.At != 1789800000 {
		t.Fatalf("mtime as at: %+v", m)
	}
}

func TestCustomExecOutput(t *testing.T) {
	spec := func(js string) tileSpec {
		cfg, _, err := parseCustomConfig([]byte("[" + js + "]"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Tiles[0]
	}
	// A bare number, with the noise a real command prints.
	tiles, err := parseExecOutput(spec(`{"id":"n","exec":"x","unit":"rpm"}`), "  1,200 rpm\nsecond line\n")
	if err != nil || len(tiles) != 1 || *tiles[0].num != 1200 || tiles[0].Unit != "rpm" || tiles[0].hasExec() {
		t.Fatalf("bare number: %v %+v", err, tiles)
	}
	if _, err := parseExecOutput(spec(`{"id":"n","exec":"x"}`), "not a number"); err == nil {
		t.Fatal("accepted text for a number")
	}
	if _, err := parseExecOutput(spec(`{"id":"n","exec":"x"}`), ""); err == nil {
		t.Fatal("accepted nothing")
	}
	// A state word and its label.
	tiles, err = parseExecOutput(spec(`{"id":"s","type":"status","exec":"x"}`), "DOWN since 02:14")
	if err != nil || tiles[0].state != "bad" || tiles[0].Label != "since 02:14" {
		t.Fatalf("status: %v %+v", err, tiles)
	}
	// An object over the entry: the command may move the value and the
	// label, not the id.
	tiles, err = parseExecOutput(spec(`{"id":"o","type":"gauge","exec":"x","max":200}`), `{"id":"other","value":150,"name":"Renamed","icon":"fan"}`)
	if err != nil || tiles[0].ID != "o" || *tiles[0].num != 150 || tiles[0].Name != "Renamed" || *tiles[0].Max != 200 || tiles[0].Icon != "fan" {
		t.Fatalf("object: %v %+v", err, tiles)
	}
	// An array under the entry: each inherits what it did not set.
	tiles, err = parseExecOutput(spec(`{"id":"g","exec":"x","group":"GPUs","unit":"celsius","type":"gauge","history":true}`),
		`[{"id":"gpu0","value":61},{"id":"gpu1","value":72,"unit":"percent","history":false}]`)
	if err != nil || len(tiles) != 2 {
		t.Fatalf("array: %v %+v", err, tiles)
	}
	if tiles[0].Group != "GPUs" || tiles[0].Unit != "celsius" || tiles[0].Type != "gauge" || tiles[0].History == nil || !*tiles[0].History {
		t.Fatalf("inherit: %+v", tiles[0])
	}
	if tiles[1].Unit != "percent" || tiles[1].History == nil || *tiles[1].History {
		t.Fatalf("override: %+v", tiles[1])
	}
	if _, err := parseExecOutput(spec(`{"id":"g","exec":"x"}`), `[{"id":"a","value":1,"exec":"rm -rf"}]`); err == nil {
		t.Fatal("a printed tile named a command")
	}
	if _, err := parseExecOutput(spec(`{"id":"g","exec":"x"}`), `[{"id":"a","value":1},{"id":"a","value":2}]`); err == nil {
		t.Fatal("duplicate printed ids")
	}
}

func TestCustomRunExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	cfg, _, err := parseCustomConfig([]byte(`[
		{"id": "ok", "exec": "printf 42", "interval": 5, "timeout": 5},
		{"id": "argv", "exec": ["printf", "%s", "7"], "interval": 5},
		{"id": "fails", "exec": "echo oops >&2; exit 3", "interval": 5},
		{"id": "slow", "exec": "sleep 5", "interval": 5, "timeout": 1},
		{"id": "words", "exec": "echo hello", "interval": 5}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	res := runExec(context.Background(), cfg.Tiles[0])
	if !res.ok || len(res.tiles) != 1 || *res.tiles[0].num != 42 {
		t.Fatalf("ok: %+v", res)
	}
	if res = runExec(context.Background(), cfg.Tiles[1]); !res.ok || *res.tiles[0].num != 7 {
		t.Fatalf("argv: %+v", res)
	}
	if res = runExec(context.Background(), cfg.Tiles[2]); res.ok || res.code != "exec-failed" || !strings.Contains(res.out, "oops") {
		t.Fatalf("fails: %+v", res)
	}
	start := time.Now()
	if res = runExec(context.Background(), cfg.Tiles[3]); res.ok || res.code != "exec-timeout" || time.Since(start) > 4*time.Second {
		t.Fatalf("slow: %+v after %v", res, time.Since(start))
	}
	if res = runExec(context.Background(), cfg.Tiles[4]); res.ok || res.code != "bad-output" {
		t.Fatalf("words: %+v", res)
	}
	// What the wire carries for each.
	s := &customSource{id: "t"}
	r := &execRun{spec: cfg.Tiles[2], last: &execResult{at: now(), code: "exec-failed"}}
	tiles := tilesOfRun(s, r, now())
	if len(tiles) != 1 || tiles[0].Error != "exec-failed" || tiles[0].Value != nil || tiles[0].ID != "fails" {
		t.Fatalf("never succeeded: %+v", tiles)
	}
	good := runExec(context.Background(), cfg.Tiles[0])
	r = &execRun{spec: cfg.Tiles[0], last: &execResult{at: now(), code: "exec-timeout"}, lastOK: &good}
	tiles = tilesOfRun(s, r, now())
	if tiles[0].Error != "exec-timeout" || *tiles[0].Value != 42 || tiles[0].Stale {
		t.Fatalf("last good with a fresh failure: %+v", tiles[0])
	}
	if tiles = tilesOfRun(s, r, now()+1000); !tiles[0].Stale {
		t.Fatalf("three intervals on: %+v", tiles[0])
	}
}

func TestCustomCollectOnceAndCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	dir := customHome(t)
	if tiles, sources := collectCustom(); tiles != nil || sources != nil {
		t.Fatalf("empty dir: %+v %+v", tiles, sources)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("lab.json", `{"name":"Lab","tiles":[{"id":"a","value":1,"history":true},{"id":"fan","exec":"printf 900","unit":"rpm"}]}`)
	write("broken.json", `{"tiles":[{"id":"x"}]}`)
	write("not an id!.json", `[{"id":"y","value":1}]`)
	write(".hidden.json", `[{"id":"z","value":1}]`)
	tiles, sources := collectCustom()
	if len(sources) != 2 || sources[0].ID != "broken" || sources[0].OK || sources[0].Error != "bad-config" || sources[1].ID != "lab" || !sources[1].OK || sources[1].Name != "Lab" {
		t.Fatalf("sources: %+v", sources)
	}
	if len(tiles) != 2 || tiles[0].ID != "a" || tiles[0].Source != "lab" || !tiles[0].History || tiles[1].ID != "fan" || *tiles[1].Value != 900 {
		t.Fatalf("tiles: %+v", tiles)
	}

	// The command-line file, as the daemon reads it.
	if code := runMetricCLI([]string{"set", "solar", "12.4", "--suffix", "kWh", "--icon", "sun", "--history", "--tag", "site=roof"}); code != 0 {
		t.Fatalf("set: %d", code)
	}
	if code := runMetricCLI([]string{"set", "backup", "ok", "--label", "02:14", "--icon", "shield"}); code != 0 {
		t.Fatalf("set status: %d", code)
	}
	if code := runMetricCLI([]string{"set", "note", "hello world", "--type", "text"}); code != 0 {
		t.Fatalf("set text: %d", code)
	}
	if code := runMetricCLI([]string{"set", "bad id", "1"}); code == 0 {
		t.Fatal("accepted a bad id")
	}
	if code := runMetricCLI([]string{"set", "x", "1", "--unit", "furlongs"}); code == 0 {
		t.Fatal("accepted a bad unit")
	}
	raw, err := os.ReadFile(filepath.Join(dir, customCLIFile))
	if err != nil {
		t.Fatal(err)
	}
	var cli customConfig
	if err := json.Unmarshal(raw, &cli); err != nil || len(cli.Tiles) != 3 {
		t.Fatalf("cli.json: %v %s", err, raw)
	}
	cfg, _, err := parseCustomConfig(raw)
	if err != nil {
		t.Fatalf("the daemon would refuse cli.json: %v\n%s", err, raw)
	}
	if cfg.Tiles[0].Suffix != "kWh" || cfg.Tiles[0].History == nil || !*cfg.Tiles[0].History || cfg.Tiles[0].Tags["site"] != "roof" || cfg.Tiles[1].state != "ok" || cfg.Tiles[1].Label != "02:14" || cfg.Tiles[2].text != "hello world" {
		t.Fatalf("cli tiles: %+v", cfg.Tiles)
	}
	// A second set keeps the fields the first one gave.
	if code := runMetricCLI([]string{"set", "solar", "13.1"}); code != 0 {
		t.Fatal("re-set")
	}
	raw, _ = os.ReadFile(filepath.Join(dir, customCLIFile))
	cfg, _, _ = parseCustomConfig(raw)
	if cfg.Tiles[0].Suffix != "kWh" || *cfg.Tiles[0].num != 13.1 {
		t.Fatalf("re-set lost fields: %+v", cfg.Tiles[0])
	}
	if code := runMetricCLI([]string{"rm", "note"}); code != 0 {
		t.Fatal("rm")
	}
	if code := runMetricCLI([]string{"rm", "note"}); code == 0 {
		t.Fatal("rm twice")
	}
	tiles, sources = collectCustom()
	if len(sources) != 3 || len(tiles) != 4 {
		t.Fatalf("after cli: %d sources %d tiles", len(sources), len(tiles))
	}
	if code := runMetricsCLI(nil); code != 2 {
		// broken.json is still there, so the terminal verb says so.
		t.Fatalf("metrics exit %d", code)
	}
}

func TestCustomEngineReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	dir := customHome(t)
	custom.Lock()
	custom.on, custom.sources, custom.runs, custom.checked = false, nil, nil, false
	custom.Unlock()
	path := filepath.Join(dir, "e.json")
	if err := os.WriteFile(path, []byte(`[{"id":"n","value":5},{"id":"c","exec":"printf 3","interval":5}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The engine, by hand: reload, run what is due, wait for it.
	custom.Lock()
	custom.on = true
	custom.sem = make(chan struct{}, execWorkers)
	custom.runs = map[string]*execRun{}
	custom.Unlock()
	defer func() {
		custom.Lock()
		custom.on, custom.sources, custom.runs = false, nil, nil
		custom.Unlock()
	}()
	customReload(true)
	customRunDue()
	deadline := time.Now().Add(5 * time.Second)
	for {
		custom.Lock()
		r := custom.runs["e/c"]
		done := r != nil && r.lastOK != nil
		custom.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	tiles, sources := collectCustom()
	if len(sources) != 1 || !sources[0].OK || len(tiles) != 2 || *tiles[0].Value != 5 || tiles[1].Value == nil || *tiles[1].Value != 3 {
		t.Fatalf("engine: %+v %+v", tiles, sources)
	}
	// A broken rewrite keeps the last good set and flags the source.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte(`[{"id":"n"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	customReload(true)
	tiles, sources = collectCustom()
	if len(sources) != 1 || sources[0].OK || sources[0].Error != "bad-config" || len(tiles) != 2 {
		t.Fatalf("bad rewrite: %+v %+v", tiles, sources)
	}
	// A changed command is a new run with no value yet.
	if err := os.WriteFile(path, []byte(`[{"id":"c","exec":"printf 4","interval":5}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	customReload(true)
	tiles, sources = collectCustom()
	if len(tiles) != 1 || tiles[0].Value != nil || tiles[0].Error != "" || !sources[0].OK {
		t.Fatalf("changed command: %+v", tiles)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	customReload(true)
	if tiles, sources = collectCustom(); tiles != nil || sources != nil {
		t.Fatalf("removed: %+v %+v", tiles, sources)
	}
}

func TestCustomHistoryFold(t *testing.T) {
	b := &histBucket{quota: map[string]float64{}, services: map[string]int{}, system: map[string]float64{}}
	snap := &Snapshot{Custom: []Tile{
		{ID: "t", Type: "gauge", Value: fp(50), History: true},
		{ID: "u", Type: "gauge", Value: fp(90), History: true, Fold: "min"},
		{ID: "x", Type: "text", History: true},
		{ID: "n", Type: "number", Value: fp(1)},
	}}
	// historyRecord wants the sampler on; drive the custom part directly.
	histCustomFold(b.system, snap.Custom, nil)
	snap.Custom[0].Value, snap.Custom[1].Value = fp(70), fp(80)
	histCustomFold(b.system, snap.Custom, nil)
	snap.Custom[0].Value, snap.Custom[1].Value = fp(60), fp(85)
	histCustomFold(b.system, snap.Custom, nil)
	if b.system["cmax:t"] != 70 || b.system["cmin:u"] != 80 || len(b.system) != 2 {
		t.Fatalf("fold: %+v", b.system)
	}
	// A status keeps the bucket's worst state as 0/1/2 under cmax:<id>;
	// pending, a stale value and a failed command write nothing.
	st := map[string]float64{}
	states := []Tile{{ID: "s", Type: "status", State: "ok", History: true, Fold: "min"}}
	histCustomFold(st, states, nil)
	states[0].State = "bad"
	histCustomFold(st, states, nil)
	states[0].State = "warn"
	histCustomFold(st, states, nil)
	histCustomFold(st, []Tile{
		{ID: "p", Type: "status", State: "pending", History: true},
		{ID: "q", Type: "status", State: "bad", History: true, Stale: true},
		{ID: "r", Type: "status", State: "bad", History: true, Error: "exec-failed"},
		{ID: "o", Type: "status", State: "ok", History: true},
	}, nil)
	if st["cmax:s"] != 2 || st["cmax:o"] != 0 || len(st) != 2 {
		t.Fatalf("status fold: %+v", st)
	}
	if _, ok := st["cmax:o"]; !ok {
		t.Fatalf("an ok bucket is a written zero, not an absence: %+v", st)
	}
	// The cap counts keys, so a ninth id is refused and an eighth existing
	// one still moves.
	many := []Tile{}
	for i := 0; i < 12; i++ {
		many = append(many, Tile{ID: "k" + itoa(i), Type: "number", Value: fp(float64(i)), History: true})
	}
	sys := map[string]float64{}
	histCustomFold(sys, many, nil)
	if len(sys) != histCustomMax || sys["cmax:k7"] != 7 {
		t.Fatalf("cap: %+v", sys)
	}
	many[7].Value = fp(70)
	histCustomFold(sys, many, nil)
	if sys["cmax:k7"] != 70 || len(sys) != histCustomMax {
		t.Fatalf("cap keeps moving: %+v", sys)
	}
}

// A quota entry (customquota.go): validated as one, carried as a tile, and
// at the snapshot an agent of its own — with the operator's words where the
// vendor's would be and a failure said the way the collectors say theirs.
func TestCustomQuota(t *testing.T) {
	bad := []string{
		`[{"id":"q","type":"quota"}]`,                                              // nothing to show
		`[{"id":"q","type":"quota","value":"lots"}]`,                               // a share is a number
		`[{"id":"q","type":"quota","windows":[{"key":"m"}]}]`,                      // no share
		`[{"id":"q","type":"quota","windows":[{"key":"a key","used_percent":1}]}]`, // key shape
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1},{"key":"m","used_percent":2}]}]`,
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":-1}]}]`,
		`[{"id":"q","type":"quota","windows":[{"key":"m","used":1,"total":2}]}]`, // figures without a unit
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"unit":"eur"}]}]`,
		`[{"id":"q","type":"quota","windows":[{"key":"m","used":1,"total":2,"unit":"gb"}]}]`, // bytes is the unit, not GB
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"cost":-0.5}]}]`,   // a cost is zero or above
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"cost":"$3"}]}]`,   // and a number
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"cost":2e9}]}]`,    // past the relay's bound
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"resets_at":"tomorrow"}]}]`,
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"minutes":0}]}]`,
		`[{"id":"q","type":"quota","value":10,"windows":[{"key":"m","used_percent":1}]}]`, // both shorthands
		`[{"id":"q","type":"quota","value":10,"unit":"percent"}]`,                         // a gauge's field
		`[{"id":"q","type":"quota","value":10,"history":true}]`,
		`[{"id":"q","type":"quota","error":"down","value":10}]`, // error or a reading
		`[{"id":"a-very-long-quota-id","type":"quota","value":10}]`,
		`[{"id":"q","value":10,"plan":"Pro"}]`,                                                  // a quota's field on a number
		`[{"id":"q","type":"quota","balance":"unknown"}]`,                                       // the relay keeps a balance with a figure in it
		`[{"id":"q","type":"quota","windows":[{"key":"m","used_percent":1,"resets_at":1e30}]}]`, // past the relay's epoch
	}
	for _, raw := range bad {
		if _, _, err := parseCustomConfig([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}

	cfg, _, err := parseCustomConfig([]byte(`[
	  {"id":"opencode","name":"OpenCode","type":"quota","plan":"Zen Pro","balance":12.5,
	   "windows":[{"key":"monthly","label":"30d","used":7.5,"total":20,"unit":"$","minutes":43200,"resets_at":"2090-01-01T00:00:00Z"},
	              {"label":"Weekly scoped","used_percent":100.04,"resets_at":3786912000000}]},
	  {"id":"bare","type":"quota","value":37.25},
	  {"id":"down","type":"quota","error":"not signed in — run opencode auth"},
	  {"id":"free","type":"quota","unlimited":true}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	at := 1789800000.0
	tile := tileOf(&cfg.Tiles[0], "own", time.Unix(1789800000, 0), at)
	if tile.Type != "quota" || tile.Plan != "Zen Pro" || tile.Balance != "12.5" || len(tile.Windows) != 2 {
		t.Fatalf("tile: %+v", tile)
	}
	w := tile.Windows[0]
	if w.Key != "monthly" || w.Label != "30d" || w.UsedPercent != 37.5 || w.Unit != "usd" || *w.Minutes != 43200 || *w.ResetsAt != 3786912000 {
		t.Errorf("window 0: %+v", w)
	}
	if w := tile.Windows[1]; w.Key != "weekly-scoped" || w.UsedPercent != 100.04 || *w.ResetsAt != 3786912000 {
		t.Errorf("window 1 (key from the label, milliseconds as seconds): %+v", w)
	}
	if b := tileOf(&cfg.Tiles[1], "own", time.Time{}, at); len(b.Windows) != 1 || b.Windows[0].Key != "usage" || b.Windows[0].UsedPercent != 37.25 {
		t.Errorf("a bare value is one window: %+v", b.Windows)
	}

	rest, own := splitQuota([]Tile{tile, {ID: "gpu", Type: "gauge", Value: fp(1)}, tileOf(&cfg.Tiles[1], "own", time.Time{}, at),
		tileOf(&cfg.Tiles[2], "own", time.Time{}, at), tileOf(&cfg.Tiles[3], "own", time.Time{}, at)}, at)
	if len(rest) != 1 || rest[0].ID != "gpu" || len(own) != 4 {
		t.Fatalf("split: %d tiles, %d agents", len(rest), len(own))
	}
	p := own[0]
	if p.ID != "custom-opencode" || p.Name != "OpenCode" || !p.OK || p.Source != "custom" || p.Collector == nil ||
		p.Collector.ID != "operator" || p.Collector.Method != "custom" || len(p.Collector.References) != 0 {
		t.Fatalf("agent: %+v", p)
	}
	if p.PlanType == nil || *p.PlanType != "Zen Pro" || p.Credits == nil || p.Credits.Balance != "12.5" || !p.Credits.HasCredits ||
		p.RecordedAt == nil || *p.RecordedAt != 1789800000 || p.CapturedAt != at {
		t.Errorf("plan, balance, dates: %+v %+v", p.PlanType, p.Credits)
	}
	if l := p.Limits[0]; l.Key != "monthly" || *l.WindowLabel != "30d" || l.UsedPercent != 37.5 || *l.UsedAmount != 7.5 ||
		*l.TotalAmount != 20 || l.Unit != "usd" || *l.WindowMinutes != 43200 || *l.ResetsAt != 3786912000 {
		t.Errorf("limit: %+v", l)
	}
	if l := p.Limits[1]; *l.WindowLabel != "Weekly scoped" || l.Unit != "" || l.UsedAmount != nil {
		t.Errorf("limit 1: %+v", l)
	}
	if d := own[2]; d.OK || d.Error != "no-readings" || d.Detail != "not signed in — run opencode auth" || d.DetailCode != "" {
		t.Errorf("the command's own error: %+v", d)
	}
	if f := own[3]; !f.OK || f.Credits == nil || !f.Credits.Unlimited || len(f.Limits) != 0 {
		t.Errorf("unlimited: %+v", f)
	}

	// A command that never answered, and one whose answer was not a reading.
	for code, want := range map[string][2]string{
		"exec-failed": {"cli-failed", "cli-timeout"}, "exec-timeout": {"cli-failed", "cli-timeout"},
		"bad-output": {"no-readings", "cli-shape"}, "": {"no-readings", "cli-nolines"},
	} {
		_, own := splitQuota([]Tile{{ID: "q", Name: "Q", Type: "quota", Error: code}}, at)
		if len(own) != 1 || own[0].OK || own[0].Error != want[0] || own[0].DetailArg != "the command for q" ||
			(code == "exec-failed" && own[0].DetailCode != "cli-failed") || (code != "exec-failed" && own[0].DetailCode != want[1]) {
			t.Errorf("%q: %+v", code, own[0])
		}
	}
	// More than the board seats are not agents at all.
	many := make([]Tile, maxQuotaTiles+2)
	for i := range many {
		many[i] = Tile{ID: "q" + strconv.Itoa(i), Type: "quota", Windows: []QuotaWindow{{Key: "usage", UsedPercent: 1}}}
	}
	if _, own := splitQuota(many, at); len(own) != maxQuotaTiles {
		t.Errorf("cap: %d", len(own))
	}

	// What a command prints: an object over the entry, a bare number, an
	// error after a reading and a reading after an error.
	spec := func(js string) tileSpec {
		cfg, _, err := parseCustomConfig([]byte("[" + js + "]"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Tiles[0]
	}
	tiles, err := parseExecOutput(spec(`{"id":"oc","type":"quota","exec":"x","plan":"Zen"}`), `{"windows":[{"key":"monthly","used_percent":40}],"balance":"3.00"}`)
	if err != nil || len(tiles) != 1 || tiles[0].Plan != "Zen" || len(tiles[0].Windows) != 1 || tiles[0].balance != "3.00" {
		t.Fatalf("object: %v %+v", err, tiles)
	}
	if tiles, err = parseExecOutput(spec(`{"id":"oc","type":"quota","exec":"x"}`), "62.5\n"); err != nil || tiles[0].Windows[0].Key != "usage" || *tiles[0].Windows[0].UsedPercent != 62.5 {
		t.Fatalf("bare: %v %+v", err, tiles)
	}
	if tiles, err = parseExecOutput(spec(`{"id":"oc","type":"quota","exec":"x","plan":"Zen"}`), `{"error":"cookie expired"}`); err != nil || tiles[0].Err != "cookie expired" || len(tiles[0].Windows) != 0 {
		t.Fatalf("error: %v %+v", err, tiles)
	}
	if _, err = parseExecOutput(spec(`{"id":"oc","type":"quota","exec":"x"}`), `{"value":"n/a"}`); err == nil {
		t.Fatal("accepted a non-number share")
	}
	over := spec(`{"id":"oc","type":"quota","error":"old"}`)
	mergeOver(&over, &tileSpec{Windows: []quotaWindowSpec{{Key: "usage", UsedPercent: fp(1)}}})
	if over.Err != "" || len(over.Windows) != 1 {
		t.Errorf("a reading over an error clears it: %+v", over)
	}
	mergeOver(&over, &tileSpec{Err: "gone"})
	if over.Err != "gone" || len(over.Windows) != 0 {
		t.Errorf("an error over a reading clears it: %+v", over)
	}
	// The value shorthand is a reading too, both ways round.
	mergeOver(&over, &tileSpec{Value: json.RawMessage("10")})
	if over.Err != "" || string(over.Value) != "10" {
		t.Errorf("a value over an error clears it: %+v", over)
	}
	mergeOver(&over, &tileSpec{Err: "gone"})
	if over.Err != "gone" || len(over.Value) != 0 {
		t.Errorf("an error over a value clears it: %+v", over)
	}
	mergeOver(&over, &tileSpec{Value: json.RawMessage("10")})
	mergeOver(&over, &tileSpec{Windows: []quotaWindowSpec{{Key: "m", UsedPercent: fp(2)}}})
	if len(over.Value) != 0 || len(over.Windows) != 1 {
		t.Errorf("windows over a value replace it: %+v", over)
	}
	// A reading the engine kept from an earlier run is not what the command
	// says now; a reading past its ttl is no reading.
	kept := Tile{ID: "q", Name: "Q", Type: "quota", Windows: []QuotaWindow{{Key: "usage", UsedPercent: 5}}, Error: "exec-timeout"}
	if _, own := splitQuota([]Tile{kept}, at); own[0].OK || own[0].DetailCode != "cli-timeout" {
		t.Errorf("the newest failure first: %+v", own[0])
	}
	kept.Error = ""
	kept.Stale = true
	if _, own := splitQuota([]Tile{kept}, at); own[0].OK || own[0].Error != "no-readings" || !strings.Contains(own[0].Detail, "ttl") {
		t.Errorf("stale is no reading: %+v", own[0])
	}
	// The relay keeps 24 providers of a reading; the operator's own fill
	// what the collectors left.
	if r := ownRoom(own[:3], 22); len(r) != 2 {
		t.Errorf("room: %d", len(r))
	}
	if r := ownRoom(own[:3], 30); len(r) != 0 {
		t.Errorf("no room: %d", len(r))
	}
	if s := tileValueText(tile); !strings.Contains(s, "Zen Pro") || !strings.Contains(s, "30d 37.5%") || !strings.Contains(s, "balance 12.5") {
		t.Errorf("metrics line: %q", s)
	}

	// A bill (metrics.d.examples/cloudflare.json): the period's bill in usd,
	// free allowances in count and bytes, one past its allowance with what
	// that has cost — carried to the wire as they were written.
	cfg, _, err = parseCustomConfig([]byte(`[
	  {"id":"cloudflare","name":"Cloudflare","type":"quota","plan":"Workers Paid",
	   "windows":[{"key":"bill","label":"Projected","used":5.52,"total":10,"unit":"usd","resets_at":3786912000},
	              {"key":"r2_storage","label":"R2 storage","used":41270000000,"total":10000000000,"unit":"Bytes","cost":0.4690,"resets_at":3786912000},
	              {"key":"do_requests","used":1331122,"total":1000000,"unit":"count","cost":0.049,"minutes":43200,"resets_at":3786912000},
	              {"key":"workers_req","used":2836832,"total":10000000,"unit":"count","cost":0,"minutes":43200,"resets_at":3786912000}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	bill := tileOf(&cfg.Tiles[0], "own", time.Unix(1789800000, 0), at)
	if len(bill.Windows) != 4 || bill.Windows[1].Unit != "bytes" || bill.Windows[1].UsedPercent != 412.7 ||
		bill.Windows[1].Cost == nil || *bill.Windows[1].Cost != 0.47 || bill.Windows[2].Unit != "count" || *bill.Windows[2].Cost != 0.05 {
		t.Fatalf("bill tile: %+v", bill.Windows)
	}
	_, own = splitQuota([]Tile{bill}, at)
	if l := own[0].Limits[1]; l.Unit != "bytes" || *l.UsedAmount != 41270000000 || *l.TotalAmount != 10000000000 || l.CostUSD == nil || *l.CostUSD != 0.47 {
		t.Errorf("bytes and cost on the wire: %+v", l)
	}
	if l := own[0].Limits[0]; l.Key != "bill" || l.Unit != "usd" || l.CostUSD != nil || l.WindowMinutes != nil {
		t.Errorf("the bill window: %+v", l)
	}
	if l := own[0].Limits[3]; l.CostUSD == nil || *l.CostUSD != 0 {
		t.Errorf("a zero cost is kept as written: %+v", l)
	}
	if s := tileValueText(bill); !strings.Contains(s, "R2 storage 412.7% ($0.47)") || strings.Contains(s, "workers_req 28.37% (") {
		t.Errorf("metrics line with costs: %q", s)
	}
	if b, err := json.Marshal(own[0].Limits[1]); err != nil || !strings.Contains(string(b), `"cost_usd":0.47`) {
		t.Errorf("wire name: %s %v", b, err)
	}
}
