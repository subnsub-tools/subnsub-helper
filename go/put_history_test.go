package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeOutHistory leaves a History connection at put.sock as out does and
// answers the ask with answer; it says on asked when it was asked.
func fakeOutHistory(t *testing.T, answer string) <-chan string {
	t.Helper()
	asked := make(chan string, 1)
	c, err := net.Dial("unix", putSockPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, "{\"op\":\"history\"}\n")
	go func() {
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			asked <- ""
			return
		}
		asked <- strings.TrimSpace(line)
		// One line, as out sends it.
		io.WriteString(c, strings.NewReplacer("\n", "", "\t", "").Replace(answer)+"\n")
	}()
	return asked
}

func waitHistoryParked(t *testing.T, n int) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if putHistoryWaiting() >= n {
			return
		}
	}
	t.Fatalf("%d History connections waiting, want %d", putHistoryWaiting(), n)
}

func putHistoryFixture(t *testing.T) *putFixture {
	t.Helper()
	f := newPutFixture(t)
	t.Setenv("MON_CONSOLE", "1")
	putLocal.Lock()
	putLocal.on = false
	putLocal.Unlock()
	startPutSocket()
	return f
}

func historyCommand(t *testing.T, f *putFixture, cmd string) (consoleResult, map[string]any) {
	t.Helper()
	r := f.command(t, "files", "put-history", cmd)
	var got map[string]any
	if r.Code == 0 {
		if err := json.Unmarshal([]byte(r.Out), &got); err != nil {
			t.Fatalf("put-history out: %v: %s", err, r.Out)
		}
	}
	return r, got
}

// The page's put-history reaches out through a waiting connection; the
// entries come back checked, newest first, and one out could not have sent
// is left out.
func TestPutHistoryAsksOut(t *testing.T) {
	f := putHistoryFixture(t)
	asked := fakeOutHistory(t, `{"entries":[
		{"id":"a","at":1000,"text":"older","state":"completed","secs":2.5},
		{"id":"b","at":3000,"text":"newest","state":"completed","secs":1},
		{"id":"c","at":2000,"text":"","state":"pending","secs":4},
		{"id":"","at":2500,"text":"no id","state":"completed","secs":1},
		{"id":"d","at":2600,"text":"odd state","state":"lost","secs":1},
		{"id":"e","at":0,"text":"no time","state":"completed","secs":1}
	]}`)
	waitHistoryParked(t, 1)
	if !putHere() {
		t.Fatal("a History connection waiting does not count as out on this Mac")
	}
	r, got := historyCommand(t, f, "{}")
	if r.Code != 0 {
		t.Fatalf("put-history: %+v", r)
	}
	var ask map[string]any
	if a := <-asked; json.Unmarshal([]byte(a), &ask) != nil || ask["ask"] != "history" || ask["max"] != float64(putHistoryOutBytes) {
		t.Fatalf("out was asked %q", a)
	}
	entries, _ := got["entries"].([]any)
	var ids []string
	for _, e := range entries {
		ids = append(ids, fmt.Sprint(e.(map[string]any)["id"]))
	}
	if strings.Join(ids, ",") != "b,c,a" || got["more"] != false {
		t.Fatalf("entries %v more %v", ids, got["more"])
	}
	if putHistoryWaiting() != 0 {
		t.Fatal("an asked connection is still waiting")
	}
}

// A long History comes in pages that fit one result frame, each going on
// from the last entry of the one before (entries of one millisecond
// included), and an entry over the limit is cut at a character. out here
// sends everything, as one that ignored the page asked for would.
func TestPutHistoryPages(t *testing.T) {
	f := putHistoryFixture(t)
	long := strings.Repeat("\u4e2d", putHistoryTextMax/3+10)
	var b strings.Builder
	b.WriteString(`{"entries":[`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		// Half of them share one millisecond.
		at := int64(100000 - i)
		if i >= 25 {
			at = 50000
		}
		e, _ := json.Marshal(putHistoryEntry{ID: fmt.Sprintf("e%02d", i), At: at, Text: long, State: "completed", Secs: 3})
		b.Write(e)
	}
	b.WriteString("]}")
	seen := map[string]bool{}
	before, beforeID := int64(0), ""
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("pages never end")
		}
		fakeOutHistory(t, b.String())
		waitHistoryParked(t, 1)
		r, got := historyCommand(t, f, fmt.Sprintf(`{"before":%d,"beforeId":%q}`, before, beforeID))
		if r.Code != 0 {
			t.Fatalf("page %d: %+v", page, r)
		}
		// What crosses the tunnel fits the result frame.
		if fr, _ := json.Marshal(r); len(fr) > 256<<10-4<<10 {
			t.Fatalf("page %d is %d bytes", page, len(fr))
		}
		entries, _ := got["entries"].([]any)
		if len(entries) == 0 {
			t.Fatalf("page %d is empty", page)
		}
		for _, x := range entries {
			e := x.(map[string]any)
			id := fmt.Sprint(e["id"])
			if seen[id] {
				t.Fatalf("%s came twice", id)
			}
			seen[id] = true
			text := e["text"].(string)
			if e["cut"] != true || len(text) > putHistoryTextMax || !strings.HasPrefix(long, text) {
				t.Fatalf("%s: cut %v, %d bytes", id, e["cut"], len(text))
			}
			before, beforeID = int64(e["at"].(float64)), id
		}
		if got["more"] != true {
			break
		}
	}
	if len(seen) != 50 {
		t.Fatalf("%d entries in all", len(seen))
	}
}

// Copies come with their app and what they hold; one with no kind out
// knows, or holding nothing it can say, is left out, and a dictation keeps
// nothing of a copy's.
func TestPutHistoryCopies(t *testing.T) {
	f := putHistoryFixture(t)
	app := strings.Repeat("\u00e9", putHistoryAppMax)
	fakeOutHistory(t, `{"entries":[
		{"id":"t","at":5000,"kind":"copy","what":"text","text":"copied","app":"`+app+`","state":"completed","secs":3,"w":10,"h":10},
		{"id":"i","at":4000,"kind":"copy","what":"image","text":"not shown","cut":true,"app":"Preview","w":1200,"h":800},
		{"id":"f","at":3000,"kind":"copy","what":"files","text":"a.pdf\nb.txt"},
		{"id":"x","at":2500,"kind":"copy","what":"color","text":"red"},
		{"id":"y","at":2400,"kind":"note","what":"text","text":"odd kind"},
		{"id":"d","at":2000,"text":"dictated","state":"completed","secs":1,"app":"Notes","what":"text"}
	]}`)
	waitHistoryParked(t, 1)
	r, got := historyCommand(t, f, "{}")
	if r.Code != 0 {
		t.Fatalf("put-history: %+v", r)
	}
	entries, _ := got["entries"].([]any)
	var ids []string
	byID := map[string]map[string]any{}
	for _, x := range entries {
		e := x.(map[string]any)
		ids = append(ids, fmt.Sprint(e["id"]))
		byID[fmt.Sprint(e["id"])] = e
	}
	if strings.Join(ids, ",") != "t,i,f,d" {
		t.Fatalf("entries %v", ids)
	}
	if e := byID["t"]; e["kind"] != "copy" || e["what"] != "text" || len(e["app"].(string)) > putHistoryAppMax || e["state"] != nil || e["secs"] != float64(0) || e["w"] != nil || e["h"] != nil {
		t.Fatalf("a text copy: %v", e)
	}
	if e := byID["i"]; e["w"] != float64(1200) || e["h"] != float64(800) || e["app"] != "Preview" || e["text"] != "" || e["cut"] != nil {
		t.Fatalf("an image copy: %v", e)
	}
	if e := byID["d"]; e["kind"] != nil || e["what"] != nil || e["app"] != nil || e["state"] != "completed" {
		t.Fatalf("a dictation: %v", e)
	}
}

// Where Show on the Dashboard is off, out says so and the page gets nothing
// but out-off, at once, with no other connection asked.
func TestPutHistoryOff(t *testing.T) {
	f := putHistoryFixture(t)
	// The newest waiting connection is asked first: the one that says off.
	fakeOutHistory(t, `{"entries":[{"id":"a","at":1000,"text":"kept back","state":"completed","secs":1}]}`)
	waitHistoryParked(t, 1)
	fakeOutHistory(t, `{"off":true}`)
	waitHistoryParked(t, 2)
	r, got := historyCommand(t, f, "{}")
	if r.Error != "out-off" || got != nil {
		t.Fatalf("off: %+v %v", r, got)
	}
	if putHistoryWaiting() != 1 {
		t.Fatalf("%d waiting: another connection was asked after off", putHistoryWaiting())
	}
}

// Without a History connection the page is told why: out is not running, or
// it is too old to leave one; without out at all, no-out.
func TestPutHistoryWhyNot(t *testing.T) {
	f := putHistoryFixture(t)
	if r, _ := historyCommand(t, f, "{}"); r.Error != "no-out" {
		t.Fatalf("no out on this Mac: %+v", r)
	}
	c, _, _ := dialPut(t, `{"op":"peers"}`)
	c.Close()
	if r, _ := historyCommand(t, f, "{}"); r.Error != "out-old" {
		t.Fatalf("an out that leaves no History connection: %+v", r)
	}
	// An out that has quit after leaving one is not running, and its
	// connection is let go as it goes.
	c, err := net.Dial("unix", putSockPath())
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "{\"op\":\"history\"}\n")
	waitHistoryParked(t, 1)
	c.Close()
	for end := time.Now().Add(5 * time.Second); putHistoryWaiting() > 0 && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	if putHistoryWaiting() != 0 {
		t.Fatal("a connection out has closed is still counted")
	}
	if r, _ := historyCommand(t, f, "{}"); r.Error != "out-not-running" {
		t.Fatalf("out gone: %+v", r)
	}
	// An answer that is not History is not passed on.
	fakeOutHistory(t, "not json")
	waitHistoryParked(t, 1)
	if r, _ := historyCommand(t, f, "{}"); r.Error != "unavailable" {
		t.Fatalf("an answer that is not History: %+v", r)
	}
}

// The page reaches out's History only where the console is on.
func TestPutHistoryConsoleGate(t *testing.T) {
	f := putHistoryFixture(t)
	fakeOutHistory(t, `{"entries":[]}`)
	waitHistoryParked(t, 1)
	t.Setenv("MON_CONSOLE", "0")
	if r, _ := historyCommand(t, f, "{}"); r.Error != "console-off" {
		t.Fatalf("console off: %+v", r)
	}
	if putHistoryWaiting() != 1 {
		t.Fatal("out was asked with the console off")
	}
}

// An out that takes the ask and never answers holds up the page's other
// commands no longer than it takes to verify this one.
func TestPutHistorySlowOutHoldsNothing(t *testing.T) {
	f := putHistoryFixture(t)
	c, err := net.Dial("unix", putSockPath())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "{\"op\":\"history\"}\n")
	waitHistoryParked(t, 1)
	slow := make(chan consoleResult, 1)
	start := time.Now()
	go func() { slow <- f.command(t, "files", "put-history", "{}") }()
	time.Sleep(200 * time.Millisecond)
	if r := f.command(t, "put-key", "", `["macStudy01"]`); r.Code != 0 {
		t.Fatalf("put-key: %+v", r)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("another command waited %v for out", d)
	}
	if r := <-slow; r.Error != "unavailable" || time.Since(start) > putHistoryWait+2*time.Second {
		t.Fatalf("an out that never answers: %+v after %v", r, time.Since(start))
	}
}
