package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func resetPushed() {
	pushed.Lock()
	pushed.tiles, pushed.order, pushed.conns = map[string]*pushedTile{}, nil, 0
	pushed.Unlock()
}

func TestPushApply(t *testing.T) {
	customHome(t)
	resetPushed()
	defer resetPushed()
	for _, c := range []struct{ line, want string }{
		{`{"id":"bench","name":"Bench","type":"gauge","value":41.5,"unit":"celsius","warn":60,"bad":80}`, "ok 1"},
		{`{"id":"bench","value":42.25}`, "ok 1"},
		{`[{"id":"a","value":1},{"id":"job","type":"status","value":"ok","label":"fine"}]`, "ok 2"},
		{`{"id":"x","exec":"rm -rf /"}`, "error: tile 1: a pushed tile may not name a command"},
		{`[{"id":"good","value":1},{"id":"bad id","value":2}]`, "error: tile 2:"},
		{`{"id":"nope","valeu":1}`, "error: not a tile"},
		{`not json`, "error: not a tile"},
		{`{"id":"two","value":1} {"id":"three","value":2}`, "error: not a tile"},
		{`{"id":"two","value":1} trailing`, "error: not a tile"},
		{`{"id":"inv","type":"gauge","value":20,"invert":true}`, "ok 1"},
		{`{"id":"inv","value":21}`, "ok 1"},
		{`{"id":"a","remove":true}`, "ok 1"},
		{`{"remove":true}`, "error: tile 1: remove needs"},
	} {
		if got := pushApply([]byte(c.line)); !strings.HasPrefix(got, c.want) {
			t.Fatalf("%s\n got %q\nwant %q…", c.line, got, c.want)
		}
	}
	// An absent invert keeps the earlier true; an explicit false takes it back.
	if got, _ := pushedTiles(now(), nil); len(got) != 3 || got[2].ID != "inv" || !got[2].Invert || got[2].Fold != "min" {
		t.Fatalf("invert kept: %+v", got)
	}
	if got := pushApply([]byte(`{"id":"inv","invert":false}`)); got != "ok 1" {
		t.Fatal(got)
	}
	if got, _ := pushedTiles(now(), nil); got[2].Invert || got[2].Fold != "" {
		t.Fatalf("invert cleared: %+v", got[2])
	}
	pushApply([]byte(`{"id":"inv","remove":true}`))
	tiles, newest := pushedTiles(now(), nil)
	if len(tiles) != 2 || newest == nil {
		t.Fatalf("tiles: %+v", tiles)
	}
	b := tiles[0]
	// The second push named only the value: the shape of the first stays.
	if b.ID != "bench" || b.Name != "Bench" || b.Type != "gauge" || b.Unit != "celsius" || b.Value == nil || *b.Value != 42.25 ||
		b.Warn == nil || *b.Warn != 60 || b.Source != pushSourceID || b.At == nil || b.Stale {
		t.Fatalf("merged tile: %+v", b)
	}
	if tiles[1].ID != "job" || tiles[1].State != "ok" || tiles[1].Text != "fine" {
		t.Fatalf("status: %+v", tiles[1])
	}
	// A batch with one bad tile landed nothing.
	for _, x := range tiles {
		if x.ID == "good" {
			t.Fatal("half a batch landed")
		}
	}
	// Dated on arrival with the default ttl: silence turns into stale, a day into gone.
	later, _ := pushedTiles(now()+tileDefaultTTL+5, nil)
	if len(later) != 2 || !later[0].Stale {
		t.Fatalf("stale: %+v", later)
	}
	if gone, _ := pushedTiles(now()+pushForgetAfter+5, nil); len(gone) != 0 {
		t.Fatalf("forgotten: %+v", gone)
	}
	// `list` answers JSON even when empty.
	if got := pushApply([]byte("list")); got != "[]" {
		t.Fatalf("list: %q", got)
	}
	// The table is bounded.
	resetPushed()
	for i := 0; i < maxTiles; i++ {
		if got := pushApply([]byte(fmt.Sprintf(`{"id":"k%d","value":%d}`, i, i))); got != "ok 1" {
			t.Fatal(got)
		}
	}
	if got := pushApply([]byte(`{"id":"one_more","value":1}`)); !strings.HasPrefix(got, "error: tile 1: at most") {
		t.Fatal(got)
	}
	if got := pushApply([]byte(`{"id":"k3","value":99}`)); got != "ok 1" {
		t.Fatalf("an existing id still moves when full: %s", got)
	}
}

func TestPushCollectAndSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path under a temp home")
	}
	dir := customHome(t)
	resetPushed()
	custom.Lock()
	custom.on, custom.sources, custom.runs, custom.checked = false, nil, nil, false
	custom.Unlock()
	if err := os.WriteFile(filepath.Join(dir, "lab.json"), []byte(`[{"id":"shared","value":1,"history":true},{"id":"file_only","value":2}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	custom.Lock()
	custom.on = true
	custom.sem = make(chan struct{}, execWorkers)
	custom.runs = map[string]*execRun{}
	custom.Unlock()
	pushed.Lock()
	pushed.on = false
	pushed.Unlock()
	defer func() {
		custom.Lock()
		custom.on, custom.sources, custom.runs = false, nil, nil
		custom.Unlock()
		resetPushed()
	}()
	customReload(true)
	startCustomPush()

	sock := pushSockPath()
	if len(sock) > 100 {
		t.Skipf("socket path too long for this platform: %d bytes", len(sock))
	}
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}
	defer c.Close()
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	r := bufio.NewReader(c)
	say := func(line string) string {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		out, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out)
	}
	if got := say(`[{"id":"shared","value":100},{"id":"live","value":7,"unit":"watts","history":true}]`); got != "ok 2" {
		t.Fatal(got)
	}
	if got := say(`{"id":"live","exec":"id"}`); !strings.HasPrefix(got, "error:") {
		t.Fatal(got)
	}
	var listed []Tile
	if err := json.Unmarshal([]byte(say("list")), &listed); err != nil || len(listed) != 2 {
		t.Fatalf("list: %v %+v", err, listed)
	}

	tiles, sources := collectCustom()
	ids := map[string]Tile{}
	for _, x := range tiles {
		ids[x.ID] = x
	}
	if len(tiles) != 3 || *ids["shared"].Value != 1 || ids["shared"].Source != "lab" {
		t.Fatalf("a file's tile wins over a pushed one of the same id: %+v", tiles)
	}
	if ids["live"].Source != pushSourceID || *ids["live"].Value != 7 || !ids["live"].History {
		t.Fatalf("pushed tile: %+v", ids["live"])
	}
	if len(sources) != 2 || sources[1].ID != pushSourceID || !sources[1].OK || sources[1].LastOKAt == nil {
		t.Fatalf("sources: %+v", sources)
	}
	// What `subnsub-helper metrics` would show for the running helper.
	if live := pushedFromSocket(); len(live) != 2 {
		t.Fatalf("pushedFromSocket: %+v", live)
	}
	// A second helper finds the socket answered and leaves it alone.
	pushed.Lock()
	pushed.on = false
	pushed.Unlock()
	startCustomPush()
	if got := say(`{"id":"live","value":8}`); got != "ok 1" {
		t.Fatalf("the first listener still owns the socket: %s", got)
	}
}
