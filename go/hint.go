package main

// The push response used to be discarded unread by every helper. It now
// carries one bit — `poll`: whether /commands is worth calling right now —
// and a machine that takes instructions reads it instead of asking on a
// timer. The reading it was going to send anyway is the request; this bit is
// the answer the cold poll existed to fetch. A relay computes it fresh on
// every push, so a hint lost with one response is re-sent by the next one,
// and the worst a wrong `true` costs is a single poll that finds nothing.
//
// A second bit rides beside it since 2026-09-12 — `watch`. Since 2026-09-28
// it means: a dashboard is open on this account AND this machine is set, in
// its card's Settings, to refresh its quota on its own. It feeds pace.go,
// which then asks the vendors on a ten-minute floor. That bit is for EVERY
// helper, so the body is read on every machine, under the same bound; `poll`
// is still acted on only where an instruction switch is on (console, remote
// update or diagnostics), because a monitoring-only helper never polls and
// the bit could tell it nothing.
//
// HINTS, not instructions. `poll` selects between sleeps that both end in
// the same guarded poll; it cannot select work, name a command, or shorten
// the floor consoleWait already enforces. `watch` counts only when it is
// read and says true: absent (an older relay), false or unreadable, the
// machine is on manual from that response on — an earlier true is taken
// back, not left to run out — and asks when Refresh quota is pressed. The most a
// hostile relay can buy with it is the floor — one call per vendor every
// ten minutes — which is what every machine did unasked until this build.

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

const (
	// A relay that answers a poll with `next` at or above this is saying
	// nobody is watching — the warm cadence is 10, the cold one 60, on both
	// relay implementations. At that point a hint-speaking relay's next
	// "come now" arrives on the push channel, so the poll timer stretches to
	// the safety interval rather than the relay's cold suggestion.
	hintDormantMin = 30

	// The timer that remains when hints have replaced it: long enough to be
	// noise in the request count, short enough that if a hint is ever lost
	// in a way the every-push resend does not cover, a queued update (the
	// longest-lived thing a mailbox holds) is still collected inside its
	// ten-minute window.
	//
	// A SHELL command lives only 90 seconds, and this net alone would not
	// save one — which is why it never has to. Every path that could delay
	// the real wake also wakes: a push that fails, a response that cannot be
	// read, a relay that stops speaking hints (see wakeNow's callers). What
	// remains uncovered is arithmetic, not failure: at the 60-second push
	// ceiling, interval plus collection plus the request deadline can brush
	// the command's own TTL — thinner than the old independent poll's
	// margin, and the price of riding the push at that cadence. At the
	// default 30 seconds the margin is wide.
	hintSafetyWait = 300 * time.Second

	// More than this from a relay is not the one-line object the hint is;
	// whatever it is, refuse to believe it. absorb reads one byte past this
	// and treats a body that big as not speaking the protocol — legacy mode,
	// which polls, the safe direction.
	hintMaxBody = 4096
)

const (
	// Nothing observed yet, or the last response did not carry the field:
	// poll on the timer, exactly as every helper did before the field
	// existed. Unknown and legacy collapse to the same behaviour on
	// purpose — the mode only matters once a hint has actually been seen.
	hintLegacy = iota
	// The last push response carried `poll`: the relay will say when to
	// come, and the timer becomes a safety net.
	hintSignal
)

// What one push response said, if it said anything. A pointer so that a JSON
// body without the field — an older relay that happens to answer in JSON —
// stays distinguishable from `poll: false`.
type pushHint struct {
	Poll *bool `json:"poll"`
	// A dashboard is open and this machine is set to refresh on its own.
	// Anything but a readable true is "no" (see pace.go).
	Watch *bool `json:"watch"`
	// Whether the relay knows of a newer published helper than the one that
	// pushed. True starts an update pass now (update.go nudgeUpdate), so a
	// release reaches the fleet within one push interval instead of within
	// the hour each machine's own timer happens to land on.
	Update *bool `json:"update"`
	// How far the relay's copy of this machine's outage record reaches, in
	// unix seconds (outages.go outageAcked). Absent from a relay that does
	// not keep the record.
	OutagesUntil *float64 `json:"outages_until"`
	// The same for the reach record (reach.go reachAcked).
	ReachUntil *float64 `json:"reach_until"`
	// How long, in seconds, a terminal session outlives its last page: the
	// account's allowance (pty.go). Bounded there, to between ptyQuietMax
	// and ptyKeepMax, so the most a relay can do with it is keep a shell
	// somebody opened here running for a week — never open one, never read
	// one, never past the ceiling its opener signed.
	PtyKeep *float64 `json:"pty_keep"`
}

// Where the push loop files what the relay said and the console loop asks.
// The wake channel holds one token, and ONLY the dormant wait listens to
// it: the warm ten-second cadence and every legacy sleep are plain timers,
// so a relay answering `true` on each push of a warm spell cannot compress
// them into the push cadence. A token that arrives while the loop is busy
// is not lost — it is banked and ends the next dormant wait at once, and
// the poll that triggers re-checks everything; a token is never trusted,
// only acted on. The one it costs: a token banked during a warm spell cuts
// the first dormant wait to nothing, one confirming poll per session end.
type hintBox struct {
	mu   sync.Mutex
	mode int
	wake chan struct{}
}

func newHintBox() *hintBox {
	return &hintBox{wake: make(chan struct{}, 1)}
}

// wakeNow ends the dormant wait, now or the next time one starts. Called
// for `poll: true`, and for every way the hint's promise can silently stop
// holding — a response that is not the protocol, one that cannot be read, a
// push that failed outright. A five-minute nap is only safe while the relay
// is demonstrably answering hints; the moment that is in doubt, the loop
// must wake and go look for itself, because a shell command it cannot see
// dies at ninety seconds.
func (b *hintBox) wakeNow() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// absorb files the body of one 200 push response. Mode follows the LATEST
// response rather than latching: a relay rolled back to a build without the
// field must take its helpers back to timer polling with it, or their
// consoles go quiet for minutes at a time with nothing to say why — and a
// waiter already five minutes deep must be pulled out (the wake below), not
// just have the next nap corrected.
func (b *hintBox) absorb(raw []byte) {
	var h pushHint
	parsed := len(raw) <= hintMaxBody && json.Unmarshal(raw, &h) == nil
	// The watch bit first, and on its own terms: it is read whether or not
	// this machine takes instructions. Only a readable true counts, and
	// anything else withdraws the last one.
	noteWatched(parsed && h.Watch != nil && *h.Watch)
	// The outage record's acknowledgement, read on every machine too.
	outageAcked(parsed, h.OutagesUntil)
	reachAcked(parsed, h.ReachUntil)
	if parsed && h.PtyKeep != nil && *h.PtyKeep > 0 && *h.PtyKeep < 1e9 {
		go ptySessions.setKeep(time.Duration(*h.PtyKeep) * time.Second)
	}
	if parsed && h.Update != nil && *h.Update {
		nudgeUpdate()
	}
	if b == nil {
		return
	}
	if !parsed || h.Poll == nil {
		b.mu.Lock()
		b.mode = hintLegacy
		b.mu.Unlock()
		b.wakeNow()
		return
	}
	b.mu.Lock()
	b.mode = hintSignal
	b.mu.Unlock()
	if *h.Poll {
		b.wakeNow()
	}
}

func (b *hintBox) signalMode() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mode == hintSignal
}

// dormantAwait sleeps for up to d, ending early on a wake — one that
// arrives mid-sleep, or one already banked while the caller was busy.
func (b *hintBox) dormantAwait(d time.Duration) {
	select {
	case <-b.wake:
	case <-time.After(d):
	}
}

// hintDormant is the one decision the hint buys: whether the sleep after a
// poll that found nothing is the plain timer this build always used, or the
// safety net. A legacy relay keeps the old cadence whatever it says, and a
// warm answer keeps its ten-second one even when hints are spoken — the
// interactive path must not change. Only the cold timer of a hint-speaking
// relay stretches: that is the poll whose answer now rides the push.
func hintDormant(signal bool, next int) bool {
	return signal && next >= hintDormantMin
}

// absorbHint disposes of one 200 push response body: read on every machine
// for the watch bit, and filed for polling only on a machine that takes
// instructions — see the top of this file. Read one byte past the bound, so
// "too big" is a fact rather than a truncation that might still parse.
func absorbHint(b *hintBox, body io.ReadCloser) {
	defer body.Close()
	takes := consoleEnabled() || updateAllowed() || diagnosticsEnabled()
	raw, err := io.ReadAll(io.LimitReader(body, hintMaxBody+1))
	if err != nil {
		// A blip mid-read says nothing about what the relay speaks, so the
		// mode keeps; but a dormant waiter must not sleep through it. Nothing
		// was learned about watchers either, which is not a yes.
		noteWatched(false)
		if takes {
			b.wakeNow()
		}
		return
	}
	if !takes {
		b = nil
	}
	b.absorb(raw)
}
