package main

// Pushed tiles: the door for a process that already has the number.
//
// metrics.d/ is right for a cron job and for a command this helper runs on a
// timer. It is wrong for a daemon that reads a sensor every second: that is a
// file rewritten every second, a disk kept awake for a dashboard. So beside
// the directory there is a socket the same user can write to:
//
//	~/.config/subnsub-helper/metrics.sock
//
// One JSON value per line — a tile, or an array of tiles, with exactly the
// fields a file's tile takes (custom.go) — and one line back per line sent:
// "ok 2", or "error: …" saying what was wrong with it.
//
//	{"id":"bench_temp","name":"Bench","type":"gauge","value":41.5,"unit":"celsius"}
//	{"id":"bench_temp","value":42.1}           later pushes name only what moved
//	{"id":"bench_temp","remove":true}
//	list                                       the pushed tiles, as the wire sees them
//	{"declare":{"kind":"wipe","at":1790371049,"end":1790371965,"by":"restore-service"}}
//	                                           not a tile: an outage this machine
//	                                           could not see for itself (outages.go)
//
// A later push to the same id is laid over the earlier one, so a client sends
// the shape once and then the value. `at` is the moment of arrival unless the
// line says otherwise, and `ttl` defaults to five minutes as it does for any
// dated value: a daemon that dies leaves a stale tile, not a lie. Nothing is
// written to disk; a helper restart starts from nothing and a tile nobody has
// pushed for a day is forgotten.
//
// What a push may NOT do is name a command: `exec` is refused here. Anyone who
// can reach the socket can already write a file into metrics.d/, so this is
// not a privilege boundary — it keeps "things the helper runs" readable from
// the directory alone.
//
// The tiles ride under the source id "push" (joining push.json if the
// operator has one), after every file's tiles: a file that names the same id
// wins, the way an earlier file wins over a later one.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	pushSockName    = "metrics.sock"
	pushSourceID    = "push"
	pushLineMax     = 64 << 10
	pushConnMax     = 8
	pushIdle        = 10 * time.Minute
	pushForgetAfter = 86400.0
)

type pushedTile struct {
	spec tileSpec // normalised, exec-free
	raw  tileSpec // as pushed so far, merged: what the next push lays over
	at   float64  // when it last arrived
}

var pushed struct {
	sync.Mutex
	on    bool
	order []string
	tiles map[string]*pushedTile
	conns int
}

// pushLine is one tile as a client sends it, plus the one verb a tile needs.
//
// Invert shadows the embedded field on purpose: a file's `invert` is a plain
// bool because absent and false mean the same there, but a push is laid over
// an earlier one, and "invert": false has to be able to take an earlier true
// back.
type pushLine struct {
	tileSpec
	Invert *bool `json:"invert,omitempty"`
	Remove bool  `json:"remove,omitempty"`
}

func pushSockPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, pushSockName)
}

// startCustomPush opens the socket. Called by startCustom, once. A second
// helper on the same account (a `watch` beside the service) finds the socket
// answered and leaves it alone; a socket file nobody answers is a leftover
// from a process that was killed, and is replaced.
func startCustomPush() {
	pushed.Lock()
	if pushed.on {
		pushed.Unlock()
		return
	}
	pushed.on = true
	pushed.tiles = map[string]*pushedTile{}
	pushed.Unlock()

	path := pushSockPath()
	if path == "" {
		return
	}
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		c.Close()
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		why := err.Error()
		if len(path) > 100 {
			why += " — the path is longer than a unix socket address may be"
		}
		warnf("metrics: no push socket at %s: %s (metrics.d/ files still work)", path, why)
		return
	}
	// The directory is 0700 already; this is for a config dir someone opened up.
	os.Chmod(path, 0o600)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(time.Second)
				continue
			}
			go servePush(c)
		}
	}()
}

func servePush(c net.Conn) {
	defer c.Close()
	pushed.Lock()
	over := pushed.conns >= pushConnMax
	if !over {
		pushed.conns++
	}
	pushed.Unlock()
	if over {
		io.WriteString(c, "error: too many connections\n")
		return
	}
	defer func() {
		pushed.Lock()
		pushed.conns--
		pushed.Unlock()
	}()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 4<<10), pushLineMax)
	for {
		c.SetReadDeadline(time.Now().Add(pushIdle))
		if !sc.Scan() {
			if errors.Is(sc.Err(), bufio.ErrTooLong) {
				io.WriteString(c, fmt.Sprintf("error: a line is at most %d bytes\n", pushLineMax))
			}
			return
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(c, pushApply(line)+"\n"); err != nil {
			return
		}
	}
}

// pushApply takes one line and answers it. All-or-nothing per line: an array
// with one bad tile changes nothing, so a client never has to work out which
// half of its batch landed.
func pushApply(line []byte) string {
	if string(line) == "list" {
		tiles, _ := pushedTiles(now(), nil)
		if tiles == nil {
			tiles = []Tile{}
		}
		out, _ := json.Marshal(tiles)
		return string(out)
	}
	if reply, ok := pushDeclare(line); ok {
		return reply
	}
	var list []pushLine
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var err error
	if line[0] == '[' {
		err = dec.Decode(&list)
	} else {
		var one pushLine
		if err = dec.Decode(&one); err == nil {
			list = []pushLine{one}
		}
	}
	if err == nil {
		// One value per line: a second one, or anything else after the first,
		// is a line this helper did not fully understand, and the promise is
		// that such a line changes nothing.
		var extra json.RawMessage
		if more := dec.Decode(&extra); more != io.EOF {
			err = errors.New("one JSON value per line, and nothing after it")
		}
	}
	if err != nil {
		return "error: not a tile or an array of tiles: " + err.Error()
	}
	for i := range list {
		if list[i].Invert != nil {
			list[i].tileSpec.Invert = *list[i].Invert
		}
	}
	if len(list) == 0 {
		return "ok 0"
	}
	if len(list) > maxTiles {
		return fmt.Sprintf("error: %d tiles in one line, the dashboard shows at most %d", len(list), maxTiles)
	}
	if !pushSourceFits() {
		return fmt.Sprintf("error: metrics.d/ already holds %d files, which is every source the dashboard takes; remove one, or name one push.json", maxCustomFiles)
	}
	t := now()
	pushed.Lock()
	defer pushed.Unlock()
	// Work on a copy of the table; swap it in only if every tile was good.
	next := make(map[string]*pushedTile, len(pushed.tiles)+len(list))
	for k, v := range pushed.tiles {
		next[k] = v
	}
	order := append([]string(nil), pushed.order...)
	for i := range list {
		in := &list[i]
		where := fmt.Sprintf("tile %d", i+1)
		if len(bytes.TrimSpace(in.Exec)) > 0 {
			return "error: " + where + ": a pushed tile may not name a command; put exec entries in metrics.d/"
		}
		if len(bytes.TrimSpace(in.Actions)) > 0 {
			return "error: " + where + ": a pushed tile may not carry actions; declare them in metrics.d/"
		}
		id := strings.TrimSpace(in.ID)
		if in.Remove {
			if !tileIDRe.MatchString(id) {
				return "error: " + where + ": remove needs the tile's id"
			}
			if _, ok := next[id]; ok {
				delete(next, id)
				order = dropString(order, id)
			}
			continue
		}
		merged := in.tileSpec
		if old := next[id]; old != nil && id != "" {
			merged = old.raw
			mergeOver(&merged, &in.tileSpec)
			merged.ID = id
			if in.Invert != nil {
				merged.Invert = *in.Invert
			}
			if in.At == nil {
				merged.At = nil // the new value arrived now, whenever the last one was dated
			}
		}
		raw := merged
		spec := merged
		if spec.At == nil {
			spec.At = fp(t)
		}
		if err := normaliseTile(&spec, nil); err != nil {
			return "error: " + where + ": " + err.Error()
		}
		if _, ok := next[spec.ID]; !ok {
			if len(next) >= maxTiles {
				return fmt.Sprintf("error: %s: at most %d pushed tiles", where, maxTiles)
			}
			order = append(order, spec.ID)
		}
		raw.ID = spec.ID
		next[spec.ID] = &pushedTile{spec: spec, raw: raw, at: t}
	}
	pushed.tiles, pushed.order = next, order
	return fmt.Sprintf("ok %d", len(list))
}

// pushDeclare is the one line on the socket that is not a tile: an outside
// party filing an outage (outages.go) — the restore service that has just
// put this machine's state back onto a fresh disk and knows, as this process
// cannot, that the stretch before it was a wipe. Only an object whose sole
// key is `declare` is taken here; anything else falls through to the tile
// path and its own errors.
func pushDeclare(line []byte) (string, bool) {
	if !bytes.Contains(line, []byte(`"declare"`)) {
		return "", false
	}
	var wrap struct {
		Declare *outageDeclaration `json:"declare"`
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wrap); err != nil || wrap.Declare == nil {
		return "", false
	}
	var extra json.RawMessage
	if more := dec.Decode(&extra); more != io.EOF {
		return "error: declare: one JSON value per line, and nothing after it", true
	}
	o, err := outageDeclare(*wrap.Declare, time.Now())
	if err != nil {
		return "error: declare: " + err.Error(), true
	}
	warnf("outage: %s declared by %s over the socket: %d–%d", o.Kind, outageDeclareBy(*wrap.Declare), o.At, o.End)
	return fmt.Sprintf("ok declared %s %d-%d", o.Kind, o.At, o.End), true
}

func dropString(list []string, s string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// pushSourceFits: whether one more source id still fits what the relay takes
// (clean.js: eight). True when push.json exists — the pushed tiles join it.
func pushSourceFits() bool {
	custom.Lock()
	defer custom.Unlock()
	if len(custom.sources) < maxCustomFiles {
		return true
	}
	for _, s := range custom.sources {
		if s.id == pushSourceID {
			return true
		}
	}
	return false
}

// pushedTiles is the wire's view of the table at t, in the order the ids
// first arrived, skipping ids `taken` already holds. It also forgets what
// nobody has pushed for a day. The second result is the newest arrival.
func pushedTiles(t float64, taken map[string]bool) ([]Tile, *float64) {
	pushed.Lock()
	defer pushed.Unlock()
	var out []Tile
	var newest *float64
	for _, id := range append([]string(nil), pushed.order...) {
		p := pushed.tiles[id]
		if p == nil {
			continue
		}
		if t-p.at > pushForgetAfter {
			delete(pushed.tiles, id)
			pushed.order = dropString(pushed.order, id)
			continue
		}
		if newest == nil || p.at > *newest {
			newest = fp(p.at)
		}
		if taken[id] {
			continue
		}
		out = append(out, tileOf(&p.spec, pushSourceID, time.Time{}, t))
	}
	return out, newest
}

// `subnsub-helper metric push [LINE…]`: send lines to the running helper's
// socket without needing nc or socat — each argument is a line, or stdin is
// read when there are none — and print what came back.
func runMetricPush(args []string) int {
	path := pushSockPath()
	if path == "" {
		warnf("no home directory")
		return 1
	}
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		warnf("no helper is listening on %s (is the service running, and is it 2026.09.19.1 or newer?): %v", path, err)
		return 1
	}
	defer c.Close()
	replies := bufio.NewScanner(c)
	replies.Buffer(make([]byte, 0, 4<<10), 1<<20)
	code := 0
	send := func(line string) bool {
		line = strings.TrimSpace(line)
		if line == "" {
			return true
		}
		if strings.ContainsAny(line, "\r\n") {
			warnf("one JSON value per line")
			code = 2
			return true
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(c, line+"\n"); err != nil {
			warnf("%v", err)
			code = 1
			return false
		}
		if !replies.Scan() {
			warnf("the helper closed the connection")
			code = 1
			return false
		}
		reply := replies.Text()
		fmt.Println(reply)
		if strings.HasPrefix(reply, "error:") && code == 0 {
			code = 1
		}
		return true
	}
	if len(args) > 0 {
		for _, a := range args {
			if !send(a) {
				break
			}
		}
		return code
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 4<<10), pushLineMax)
	for in.Scan() {
		if !send(in.Text()) {
			return code
		}
	}
	if err := in.Err(); err != nil {
		// Most often a line over the limit: it was never sent, and a producer
		// piping into this has to be able to tell.
		warnf("stdin: %v (a line is at most %d bytes); nothing after it was sent", err, pushLineMax)
		return 1
	}
	return code
}
