package main

// out's History on the Monitor page's Clipboard tab.
//
// out on this Mac keeps a connection or two waiting at put.sock
// ({"op":"history"}, put.go). When the page asks (the files command
// put-history: the console's grant, to an allowlisted browser, over the
// tunnel alone), the newest of them is asked for one page,
// {"ask":"history","before":...,"beforeId":...,"max":...}, and out answers it as
// one line, {"entries":[...],"more":bool}, newest first, then closes it and
// leaves another. The entries are out's History (dictations) and, among
// them, what was copied on that Mac (out's clipboard history, kind "copy").
// out shows them only where its owner has turned on Show on the Dashboard
// there; with it off, out answers {"off":true}, and the page is told so
// (out-off) and given nothing. The helper keeps nothing: each ask reads out's list as it is
// at that moment. It checks what out sent, and holds the page to what one
// result frame carries even where out did not.
//
// A page goes on from the one before by the last entry it had: older than its
// time, or as old and with a smaller id, so two entries of one millisecond
// are not lost between pages.

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	// out keeps two waiting; more are its earlier ones.
	putHistoryParked = 4
	// out's answer to one ask, read whole before it is checked.
	putHistoryLineMax = 1 << 20
	// One ask, every waiting connection tried included: out on this Mac
	// answers in milliseconds, and the page's other commands wait meanwhile
	// only where the command door has not let go (direct.go lets go first).
	putHistoryWait = 3 * time.Second
	// Entries taken from one answer at most.
	putHistoryMaxEntries = 500
	// One entry's text as the page gets it, in bytes; longer is cut.
	putHistoryTextMax = 16 << 10
	// One page, measured as it travels: its JSON quoted again inside the
	// result frame (transport.Limits: 256 KB), with room for the envelope.
	putHistoryPageBytes = 192 << 10
	// What out is asked to keep a page to, as it measures it (its own JSON,
	// before the helper quotes it again).
	putHistoryOutBytes = 96 << 10
)

// putHistoryConn is one of out's connections waiting here. Its watcher reads
// it until out goes away (out sends nothing before it is asked), so that one
// out has left is not counted, and lets go of it when it is taken.
type putHistoryConn struct {
	c    net.Conn
	done chan struct{}
	// lost: out went away, or sent what it must not; set before done closes.
	lost bool
}

var putHistoryLocal struct {
	sync.Mutex
	conns []*putHistoryConn
}

// putHistorySeen: out on this Mac has left a History connection here since
// the helper started, so one missing now means out has quit, not that it is
// too old to leave one.
var putHistorySeen atomic.Bool

func putParkHistory(c net.Conn) {
	w := &putHistoryConn{c: c, done: make(chan struct{})}
	putHistorySeen.Store(true)
	putHistoryLocal.Lock()
	if len(putHistoryLocal.conns) >= putHistoryParked {
		// Its watcher finds it gone from the list and only stops.
		putHistoryLocal.conns[0].c.Close()
		putHistoryLocal.conns = putHistoryLocal.conns[1:]
	}
	putHistoryLocal.conns = append(putHistoryLocal.conns, w)
	putHistoryLocal.Unlock()
	go w.watch()
}

func (w *putHistoryConn) watch() {
	var b [1]byte
	_, err := w.c.Read(b[:])
	var ne net.Error
	taken := errors.As(err, &ne) && ne.Timeout()
	putHistoryLocal.Lock()
	for i, x := range putHistoryLocal.conns {
		if x == w {
			// Nobody took it: out has gone, or broke the protocol.
			putHistoryLocal.conns = append(putHistoryLocal.conns[:i], putHistoryLocal.conns[i+1:]...)
			w.c.Close()
			break
		}
	}
	putHistoryLocal.Unlock()
	w.lost = !taken
	close(w.done)
}

// putTakeHistory takes the newest waiting connection, its watcher stopped:
// the older ones are the likeliest to be from an out that has since quit.
func putTakeHistory() net.Conn {
	for {
		putHistoryLocal.Lock()
		n := len(putHistoryLocal.conns)
		if n == 0 {
			putHistoryLocal.Unlock()
			return nil
		}
		w := putHistoryLocal.conns[n-1]
		putHistoryLocal.conns = putHistoryLocal.conns[:n-1]
		putHistoryLocal.Unlock()
		w.c.SetReadDeadline(time.Now())
		<-w.done
		if w.lost {
			w.c.Close()
			continue
		}
		w.c.SetReadDeadline(time.Time{})
		return w.c
	}
}

func putHistoryWaiting() int {
	putHistoryLocal.Lock()
	defer putHistoryLocal.Unlock()
	return len(putHistoryLocal.conns)
}

func putHistoryReset() {
	putHistorySeen.Store(false)
	putHistoryLocal.Lock()
	conns := putHistoryLocal.conns
	putHistoryLocal.conns = nil
	putHistoryLocal.Unlock()
	for _, w := range conns {
		w.c.Close()
		<-w.done
	}
}

// putHistoryEntry is one entry of out's History as the page gets it.
type putHistoryEntry struct {
	ID string `json:"id"`
	// At: when it was recorded, Unix milliseconds.
	At   int64  `json:"at"`
	Text string `json:"text"`
	// State, of a dictation: recording, processing, pending (waiting for
	// the network), failed (to be tried again) or completed.
	State string  `json:"state,omitempty"`
	Secs  float64 `json:"secs"`
	// Cut: the text is longer than putHistoryTextMax and was cut there.
	Cut bool `json:"cut,omitempty"`
	// Kind: "copy" for something copied on the Mac, empty for a dictation.
	Kind string `json:"kind,omitempty"`
	// What a copy holds: text, an image, or files (their names in Text).
	What string `json:"what,omitempty"`
	// App: the name of the app it was copied in, when out knew it.
	App string `json:"app,omitempty"`
	// W, H: an image's size in pixels.
	W int `json:"w,omitempty"`
	H int `json:"h,omitempty"`
}

var putHistoryStates = map[string]bool{"recording": true, "processing": true, "pending": true, "failed": true, "completed": true}

var putHistoryWhat = map[string]bool{"text": true, "image": true, "files": true}

// putHistoryAppMax: an app's name as the page gets it, in bytes.
const putHistoryAppMax = 128

// errPutHistoryOff: out answered that Show on the Dashboard is off there.
var errPutHistoryOff = errors.New("off")

// putHistoryCut cuts s to at most n bytes, where a character starts.
func putHistoryCut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// putHistoryNewer orders entries newest first, and by id within a millisecond.
func putHistoryNewer(a, b putHistoryEntry) bool {
	if a.At != b.At {
		return a.At > b.At
	}
	return a.ID > b.ID
}

// putHistoryRead asks one waiting connection for a page of out's History.
func putHistoryRead(c net.Conn, arg filesArgs, deadline time.Time) ([]putHistoryEntry, bool, error) {
	ask, _ := json.Marshal(map[string]any{"ask": "history", "before": arg.Before, "beforeId": arg.BeforeID, "max": putHistoryOutBytes})
	c.SetDeadline(deadline)
	if _, err := c.Write(append(ask, '\n')); err != nil {
		return nil, false, err
	}
	r := bufio.NewReaderSize(c, 64<<10)
	var line []byte
	for {
		part, more, err := r.ReadLine()
		if err != nil {
			return nil, false, err
		}
		if len(line)+len(part) > putHistoryLineMax {
			return nil, false, errors.New("answer too long")
		}
		line = append(line, part...)
		if !more {
			break
		}
	}
	var answer struct {
		Entries []json.RawMessage `json:"entries"`
		More    bool              `json:"more"`
		Off     bool              `json:"off"`
	}
	if err := json.Unmarshal(line, &answer); err != nil {
		return nil, false, errors.New("bad answer")
	}
	if answer.Off {
		return nil, false, errPutHistoryOff
	}
	if answer.Entries == nil {
		return nil, false, errors.New("bad answer")
	}
	out := []putHistoryEntry{}
	for _, raw := range answer.Entries {
		if len(out) >= putHistoryMaxEntries {
			answer.More = true
			break
		}
		var e putHistoryEntry
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		if e.ID == "" || len(e.ID) > 64 || e.At <= 0 {
			continue
		}
		switch e.Kind {
		case "":
			if !putHistoryStates[e.State] {
				continue
			}
			e.What, e.App, e.W, e.H = "", "", 0, 0
		case "copy":
			if !putHistoryWhat[e.What] {
				continue
			}
			e.State, e.Secs = "", 0
		default:
			continue
		}
		if e.Secs < 0 || e.Secs > 1e6 {
			e.Secs = 0
		}
		if e.W < 0 || e.W > 1<<20 || e.H < 0 || e.H > 1<<20 {
			e.W, e.H = 0, 0
		}
		// An image is sent by its size alone; anything else has no size.
		if e.What == "image" {
			e.Text, e.Cut = "", false
		} else {
			e.W, e.H = 0, 0
		}
		e.App = putHistoryCut(e.App, putHistoryAppMax)
		if len(e.Text) > putHistoryTextMax {
			e.Text, e.Cut = putHistoryCut(e.Text, putHistoryTextMax), true
		}
		out = append(out, e)
	}
	return out, answer.More, nil
}

// runPutHistory answers the page's put-history: the newest entries after the
// one before names (before, Unix milliseconds, and beforeId; none for the
// newest of all) that fit one page.
func runPutHistory(arg filesArgs) (any, string) {
	present, _ := putPresence()
	if !present {
		return nil, "no-out"
	}
	if len(arg.BeforeID) > 64 {
		return nil, "bad-args"
	}
	deadline := time.Now().Add(putHistoryWait)
	var entries []putHistoryEntry
	more, got, tried := false, false, false
	for time.Now().Before(deadline) {
		c := putTakeHistory()
		if c == nil {
			break
		}
		tried = true
		e, m, err := putHistoryRead(c, arg, deadline)
		c.Close()
		if errors.Is(err, errPutHistoryOff) {
			return nil, "out-off"
		}
		if err == nil {
			entries, more, got = e, m, true
			break
		}
	}
	if !got {
		switch {
		case tried:
			return nil, "unavailable"
		case putHistorySeen.Load() || !putSeen.Load():
			return nil, "out-not-running"
		default:
			// out has asked other things here and never left a History
			// connection: it is from before the History was shown.
			return nil, "out-old"
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return putHistoryNewer(entries[i], entries[j]) })
	last := putHistoryEntry{ID: arg.BeforeID, At: arg.Before}
	page := []putHistoryEntry{}
	size := 0
	for _, e := range entries {
		if arg.Before > 0 && !putHistoryNewer(last, e) {
			continue
		}
		b, _ := json.Marshal(e)
		q, _ := json.Marshal(string(b))
		if len(page) > 0 && size+len(q)+1 > putHistoryPageBytes {
			more = true
			break
		}
		size += len(q) + 1
		page = append(page, e)
	}
	return map[string]any{"entries": page, "more": more}, ""
}
