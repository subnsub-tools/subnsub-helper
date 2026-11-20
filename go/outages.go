package main

// Outages — the stretches this machine was not running, kept HERE beside the
// history (history.go) and served over the tunnel with it.
//
// The trend archive shows an outage only as buckets that are not there, and
// the page draws a line straight across them: a fifteen-minute suspend on a
// VM looked like fifteen quiet minutes. Nothing else on the tunnel road can
// know better — the only party that saw the machine stop is the machine, and
// with no relay in the self-hosted shape there is nobody else to ask. So the
// helper keeps the record itself, in seconds rather than five-minute buckets,
// and the page reads it with the history.
//
// Two kinds, told apart by who was running:
//
//   suspend  the process was alive and its one-second ticker came back to a
//            wall clock that had moved much further than a second. A VM the
//            host paused, a laptop lid, a container frozen — the machine as a
//            whole stopped. (A clock stepped forward by NTP looks the same
//            from here and is recorded the same; a running machine's clock
//            does not step by half a minute.)
//   down     the process was not running: a stamp this helper writes once a
//            minute was older, at start, than the threshold plus the minute
//            the process may have run on after writing it. A reboot, a
//            crash, a stopped service. The stamp is a minute coarse, so a
//            `down` may read up to a minute longer than it was.
//   wipe     the same stale stamp, found by a process whose state directory
//            came from a DIFFERENT installation than the one it is running
//            on (hostid.go): the machine was wiped and rebuilt and its state
//            restored from a backup. Told apart from `down` because the two
//            mean different things to whoever reads the record — a reboot
//            keeps every file that was on the disk, a rebuild keeps nothing
//            but what somebody copied back (user 2026-09-26).
//
// Neither is "the network was away". The machine cannot tell that from
// here, and this file does not pretend to: a tunnel nobody could reach while
// the helper ran on is not an outage in this record.
//
// A third voice, louder than either heuristic: whoever put the machine back
// can SAY what happened. The stamp and the host id are inferences — good
// ones, but a rebuild that landed before the host id existed read as a
// reboot (box, 2026-09-26 05:17 CST), and the user wanted the record to be
// told, not guessed. So a restore service declares the outage:
//
//   declared-outage   a JSON object left in the state directory before the
//                     helper starts — {"kind":"wipe","by":"restore-service"} —
//                     read once at boot, consumed, and filed with the kind
//                     it names. `at` and `end` are optional; absent, the
//                     start is the stamp and the end is now, as for a down.
//   metrics.sock      the same object on the socket, for a helper already
//                     running: {"declare":{"kind":"wipe","at":…,"end":…}}.
//                     A row already covering that stretch is relabelled
//                     rather than doubled (custompush.go).
//
// Bounded like the history: a row count and an age, whichever bites first,
// written whole on each new row (rare), write-then-rename, 0600.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// A gap shorter than this is the scheduler, a stop-the-world GC, or the
	// few seconds a self-update takes to swap the binary — none of them an
	// outage anyone wants listed.
	outageMinSec = 30
	// How long after boot a step of the clock back still puts the boot's
	// row right (outageTick): NTP's first sync, and a slow one.
	outageBootWatch = 30 * 60
	// The history's own reach (histKeepSec), and a cap under it that a
	// machine stopped ninety times a day (box, 2026-10-08) does not fill in a
	// month: 2 700 rows. A row is 30–34 bytes on disk, so the file is
	// ~140 KB at the very most — and the loader reads well past that
	// (outageReadMax). Until 2026-10-16 the cap was 2 000 rows (68 KB of
	// suspends) against a 64 KiB read limit: a full record read back as
	// nothing, and the next row filed overwrote the month (audit).
	outageKeep  = 4000
	outageKeepS = histKeepSec
	// What the loader reads, and what a save may write: twice the most the
	// cap can hold, so neither limit is ever the one that bites first.
	outageReadMax = 320 << 10
	outageFile    = "outages.json"
	outageStamp   = "last-tick"
	// How often the alive-stamp is rewritten. Once a minute is 1440 tiny
	// writes a day — the history already writes every five — and it bounds
	// how far a `down` can overstate itself.
	outageStampEvery = 60

	outageKindSuspend = "suspend"
	outageKindDown    = "down"
	outageKindWipe    = "wipe"

	// A declaration left beside the state by whoever restored it; read and
	// removed at boot. Its `at`/`end` are seconds and must be after this,
	// like the relay's own floor for a helper's `wiped` pair — a pair from
	// 1970 is a bug, not history.
	outageDeclareFile  = "declared-outage"
	outageDeclareMinS  = 1_600_000_000
	outageDeclareByMax = 64
)

func outageKindKnown(k string) bool {
	return k == outageKindSuspend || k == outageKindDown || k == outageKindWipe
}

// One row on the wire and in the file: [start_s, end_s, kind].
type outageRow = []any

type outage struct {
	At, End int64
	Kind    string
}

func (o outage) row() outageRow { return outageRow{float64(o.At), float64(o.End), o.Kind} }

var outages struct {
	sync.Mutex
	loaded bool
	rows   []outage
	// The last tick the sampler saw, with its monotonic reading, and the
	// last time the stamp file was written (unix seconds).
	prev    time.Time
	stamped int64
	// When this process began keeping the record (outageBoot), unix
	// seconds; the record's reach is at least from here (outageSince).
	booted int64
	// The row this process filed at boot, by its start and end (outageBootOn):
	// the one row whose end the clock at boot wrote, put right in outageTick
	// if that clock is then stepped back (audit 2026-10-16). Zero once the
	// clock has passed it.
	bootAt, bootEnd int64
}

// ── the relay's copy ─────────────────────────────────────────────────────
//
// The record above is exact and says why, and it lives on the one disk a
// wipe erases, behind the one tunnel an offline machine does not have. The
// relay's own record survives the machine but
// sees a stop only as the gap between two pushes, past 100 s. So the rows
// here ride the push the helper already makes (types.go `outages`), and
// the relay files them beside its own; what the page reads is the merge. Only
// what the relay has not
// acknowledged travels: each push response says how far its copy reaches
// (`outages_until`, hint.go), and the next push carries the rows newer than
// that — none, on an ordinary push. A relay that does not speak the field
// (the self-hosted one, an older build) gets the rows once and never again.
//
// The window is a week and
// the cap matches the relay's limit, so a machine coming
// back to a relay that forgot it sends a week at most, newest kept.
const (
	outagePushMax     = 200
	outagePushWindowS = 7 * 86400
)

var outagePush struct {
	sync.Mutex
	// How far the relay's copy reaches: the end of the newest row it has
	// said it holds. Zero until it has said anything.
	ack int64
	// The end of the newest row in the push on the wire, for a relay that
	// answers without the field: its answer is taken as the rows having
	// landed wherever they were going.
	sent int64
	// Which edition of the record the push on the wire carried. A
	// declaration between a push's assembly and its answer rewrites rows
	// and asks for the window again (outageResend); the answer to the
	// push before it must not then stand as the acknowledgement of rows
	// it never saw, so an answer only counts for the
	// edition it was sent for.
	gen, sentGen uint64
	// When a push's rows were the newest of more than the cap allows, the
	// start of the oldest row that went — the latest such cut, kept for the
	// life of the process: the relay's copy reaches back no further than
	// that, whatever the record here does (outageSince), and the rows cut
	// are acknowledged with the rest and never offered again.
	sentFrom int64
}

// outagePending is what the next push carries: the rows the relay has not
// acknowledged, oldest first, inside the window and the cap; wipes whatever
// their age, as the relay keeps those. Nil when there is nothing — the
// field is then absent from the push, which is the ordinary case.
func outagePending(now time.Time) []outageRow {
	outagePush.Lock()
	ack := outagePush.ack
	outagePush.Unlock()
	floor := now.Unix() - outagePushWindowS
	outages.Lock()
	defer outages.Unlock()
	outageLoad()
	var out []outageRow
	for _, o := range outages.rows {
		if o.End > ack && (o.End >= floor || o.Kind == outageKindWipe) {
			out = append(out, o.row())
		}
	}
	var from int64
	if len(out) > outagePushMax {
		out = out[len(out)-outagePushMax:]
		if f, ok := out[0][0].(float64); ok {
			from = int64(f)
		}
	}
	outagePush.Lock()
	if from > outagePush.sentFrom {
		outagePush.sentFrom = from
	}
	outagePush.Unlock()
	return out
}

// outageSent notes what a push carried (transport.go pushBody), for the
// answer that follows.
func outageSent(rows []outageRow) {
	var top int64
	for _, r := range rows {
		if len(r) == 3 {
			if end, ok := r[1].(float64); ok && int64(end) > top {
				top = int64(end)
			}
		}
	}
	outagePush.Lock()
	outagePush.sent = top
	outagePush.sentGen = outagePush.gen
	outagePush.Unlock()
}

// outageAcked files what the push response said (hint.go absorb). A
// response that is the protocol but carries no `outages_until` is a relay
// that does not keep the record: what was sent is taken as delivered, so
// the rows are not sent on every push forever. A response that was not the
// protocol says nothing. A relay's figure is taken as it is, lower
// included — a write that failed on its side is a lower figure on the next
// answer, and the rows go again (its upsert is idempotent).
func outageAcked(parsed bool, until *float64) {
	if !parsed {
		return
	}
	outagePush.Lock()
	defer outagePush.Unlock()
	if outagePush.sentGen != outagePush.gen {
		return
	}
	if until == nil {
		if outagePush.sent > outagePush.ack {
			outagePush.ack = outagePush.sent
		}
		return
	}
	if v := *until; v == v && v >= 0 && v < 1e12 {
		outagePush.ack = int64(v)
	}
}

// outageResend makes the next push carry the whole window again: a
// declaration (outageDeclareLocked) replaces rows the relay may already
// hold, and the relay keeps the newest word for each start.
func outageResend() {
	outagePush.Lock()
	outagePush.ack = 0
	outagePush.gen++
	outagePush.Unlock()
}

// outageSince is the earliest moment this record is known to reach back
// to: the oldest row it holds, or when this process began keeping it,
// whichever is earlier. From there to the latest push, a silence the relay
// heard with no row here under it was the road, not the machine — the
// ticker would have filed a jump. Zero when nothing is known yet.
func outageSince() int64 {
	outagePush.Lock()
	from := outagePush.sentFrom
	outagePush.Unlock()
	outages.Lock()
	defer outages.Unlock()
	outageLoad()
	since := outages.booted
	if len(outages.rows) > 0 && (since == 0 || outages.rows[0].At < since) {
		since = outages.rows[0].At
	}
	// Rows the cap kept home are rows the relay does not have: a reach
	// that claimed them would let a silence over one of them read as the
	// road. The relay keeps the earliest reach it was
	// ever told, so a push that fits under the cap later does not move it
	// back either — what went before the cut is simply not known there.
	if from > since {
		since = from
	}
	return since
}

func outagePath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, outageFile)
}

func outageStampPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, outageStamp)
}

func outageLoad() {
	if outages.loaded {
		return
	}
	outages.loaded = true
	p := outagePath()
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > outageReadMax {
		return
	}
	var rows []outageRow
	if json.Unmarshal(b, &rows) != nil {
		return
	}
	// Trusted only in shape: two numbers in order and a kind this build
	// knows. Anything else is dropped rather than served.
	for _, r := range rows {
		if len(r) != 3 {
			continue
		}
		at, ok1 := r[0].(float64)
		end, ok2 := r[1].(float64)
		kind, ok3 := r[2].(string)
		if !ok1 || !ok2 || !ok3 || end <= at || !outageKindKnown(kind) {
			continue
		}
		outages.rows = append(outages.rows, outage{At: int64(at), End: int64(end), Kind: kind})
	}
}

func outageSave() {
	p := outagePath()
	if p == "" {
		return
	}
	rows := make([]outageRow, 0, len(outages.rows))
	for _, o := range outages.rows {
		rows = append(rows, o.row())
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return
	}
	// Never a file the loader would refuse: the oldest rows go first. The
	// row cap keeps this from biting (outageKeep), but a record the loader
	// cannot read is the whole record lost, so the bound is enforced here
	// too rather than trusted.
	for len(b) > outageReadMax && len(rows) > 1 {
		rows = rows[len(rows)/8+1:]
		if b, err = json.Marshal(rows); err != nil {
			return
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp := p + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
	}
}

// outageTrim holds the record to its two bounds, as of `now`.
func outageTrim(now int64) {
	keep := outages.rows[:0]
	for _, o := range outages.rows {
		if now-o.End <= outageKeepS {
			keep = append(keep, o)
		}
	}
	outages.rows = keep
	for len(outages.rows) > outageKeep {
		outages.rows = outages.rows[1:]
	}
}

// outageAdd files one, newest last, and writes the file. Caller holds the lock.
func outageAdd(o outage) {
	if o.End-o.At < outageMinSec {
		return
	}
	outageLoad()
	// The same stretch twice (a restart that re-reads an old stamp) is one
	// outage, not two.
	for _, have := range outages.rows {
		if have.At == o.At && have.End == o.End {
			return
		}
	}
	outages.rows = append(outages.rows, o)
	outageTrim(o.End)
	outageSave()
}

// outageTick is the sampler's once-a-second call. `now` carries a monotonic
// reading (time.Now does); the wall clock's step since the previous tick,
// past the threshold, is a suspend that ended now.
func outageTick(now time.Time) {
	outages.Lock()
	defer outages.Unlock()
	if !outages.prev.IsZero() {
		if gap := outageGap(outages.prev, now); gap >= outageMinSec {
			outageAdd(outage{At: outages.prev.Unix(), End: now.Unix(), Kind: outageKindSuspend})
			// Awake again: put's tunnels to the other Macs start afresh (put.go).
			go putForgetClients()
		}
	}
	outages.prev = now
	s := now.Unix()
	// The clock stepped back after boot (a dual-boot box whose RTC held local
	// time, put right by NTP a minute in): the row filed at boot ended at the
	// wrong clock's "now", hours ahead, and would shade the record to the
	// present and hold the relay's acknowledgement in the future (audit
	// 2026-10-16). That row alone ends when the right clock first ran — no
	// other row is touched, since a clock that is behind for a while (a board
	// with no RTC, started on its last saved time) is no reason to cut the
	// record's rows. The stamp follows the clock back, or every later boot
	// would read as no time away.
	if outages.bootEnd > 0 {
		if s >= outages.bootEnd+outageBootWatch {
			outages.bootAt, outages.bootEnd = 0, 0
		} else if outages.bootEnd-s > outageStampEvery {
			for i := range outages.rows {
				if o := &outages.rows[i]; o.At == outages.bootAt && o.End == outages.bootEnd {
					if s-o.At >= outageMinSec {
						o.End = s
					} else {
						outages.rows = append(outages.rows[:i], outages.rows[i+1:]...)
					}
					outageSave()
					break
				}
			}
			outages.bootAt, outages.bootEnd = 0, 0
		}
	}
	if s-outages.stamped >= outageStampEvery || s < outages.stamped {
		outages.stamped = s
		outageWriteStamp(s)
	}
}

// outageGap is the wall-clock seconds between two ticks. The monotonic
// difference is deliberately NOT what is measured: on a paused VM the guest's
// monotonic clock stops with it and would report one second across a
// fifteen-minute hole. The wall clock is what the operator's day is on.
func outageGap(prev, now time.Time) int64 {
	return now.Unix() - prev.Unix()
}

func outageWriteStamp(s int64) {
	p := outageStampPath()
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp := p + ".new"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(s, 10)+"\n"), 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
	}
}

// outageBoot runs once when sampling starts: a stamp old enough is the
// stretch this process was not here for. The stamp is then brought to now so
// a second start (a self-update restarts the process, then the sampler) does
// not file the same stretch again.
//
// "Old enough" allows for the stamp's own coarseness: the process may have
// run on for up to outageStampEvery after writing it, so a gap that would
// fit inside that slack plus the threshold is not evidence of a real stop —
// a restart forty seconds after the last stamp was two seconds down, not
// forty. What IS filed still starts at the stamp, so a `down` reads up to a
// minute longer than it was; the alternative, starting it a minute later,
// would make a real ten-minute reboot read as nine.
func outageBoot(now time.Time) { outageBootOn(now, hostIdentity()) }

// outageBootOn is outageBoot with the running system's identity handed in
// (hostid.go). The stale stamp is filed as `wipe` instead of `down` when the
// state directory was last seen on a different installation; the identity
// is then brought up to date along with the stamp, so the next start — the
// self-update's restart, minutes later — compares against THIS machine.
//
// A declaration in the state directory (outageDeclareFile) outranks both: the
// party that restored the state knows what it restored it after. It is
// consumed here whatever it said, so a second start does not read it again.
func outageBootOn(now time.Time, cur string) {
	outages.Lock()
	defer outages.Unlock()
	stored := hostIDStored()
	declared := false
	if d, ok := outageDeclaredRead(); ok {
		if o, err := outageDeclareLocked(d, now); err != nil {
			warnf("outage: the declaration in %s was not filed: %v", outageDeclareFile, err)
		} else {
			warnf("outage: %s declared by %s: %d–%d", o.Kind, outageDeclareBy(d), o.At, o.End)
			declared = true
		}
	}
	if !declared {
		kind := outageKindDown
		if hostChanged(stored, cur) {
			kind = outageKindWipe
		}
		if last := outageStampRead(); last > 0 {
			// A stamp is written once a minute, so a gap under a minute and a
			// half is ordinarily the helper restarting, not the machine away.
			// But a machine that booted since the stamp WAS away, however
			// briefly: a fifty-second reboot otherwise left no row of its own,
			// and the relay's silence for it read as "the machine ran on"
			// (audit 2026-10-16).
			gap := now.Unix() - last
			boot := systemBootUnix()
			rebooted := boot > last && boot <= now.Unix()
			if last < now.Unix() && (gap >= outageMinSec+outageStampEvery || (rebooted && gap >= outageMinSec)) {
				outageAdd(outage{At: last, End: now.Unix(), Kind: kind})
				outages.bootAt, outages.bootEnd = last, now.Unix()
			}
		}
	}
	if cur != "" && stored != cur {
		hostIDWrite(cur)
	}
	outages.prev = now
	outages.stamped = now.Unix()
	if outages.booted == 0 {
		outages.booted = now.Unix()
	}
	outageWriteStamp(now.Unix())
}

// outageStampRead is the alive-stamp's value, or 0 when there is none.
func outageStampRead() int64 {
	p := outageStampPath()
	if p == "" {
		return 0
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || last <= 0 {
		return 0
	}
	return last
}

// ── declarations ───────────────────────────────────────────────────────

// outageDeclaration is what an outside party says happened: the kind, and
// optionally when. `by` names the party for the log; `confirmed_at` and
// `note` are carried for the same reason and never enter the record — the
// row stays [start, end, kind], the shape every reader already has.
type outageDeclaration struct {
	Kind        string   `json:"kind"`
	At          *float64 `json:"at,omitempty"`
	End         *float64 `json:"end,omitempty"`
	By          string   `json:"by,omitempty"`
	ConfirmedAt *float64 `json:"confirmed_at,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// outageDeclareBy is the declaration's provenance for one log line: who,
// and when they say they knew, and their note. Text from outside is cut to
// a length and stripped of anything that is not printable — a newline in a
// `note` must not become a second log line that says something else.
func outageDeclareBy(d outageDeclaration) string {
	by := outageLogText(d.By, outageDeclareByMax)
	if by == "" {
		by = "an unnamed caller"
	}
	if d.ConfirmedAt != nil && *d.ConfirmedAt == *d.ConfirmedAt {
		by += fmt.Sprintf(" (confirmed_at %d)", int64(*d.ConfirmedAt))
	}
	if note := outageLogText(d.Note, 200); note != "" {
		by += " — " + note
	}
	return by
}

// outageLogText keeps the printable, single-line part of an outside string,
// at most max runes.
func outageLogText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029' {
			r = ' '
		}
		b.WriteRune(r)
		if n++; n >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// outageDeclaredRead is the state directory's declaration, if there is one,
// removed as it is read. A file that is not a declaration is reported and
// removed too: leaving it would make every start say the same thing.
func outageDeclaredRead() (outageDeclaration, bool) {
	var d outageDeclaration
	dir := configDir()
	if dir == "" {
		return d, false
	}
	p := filepath.Join(dir, outageDeclareFile)
	b, err := os.ReadFile(p)
	if err != nil {
		return d, false
	}
	os.Remove(p)
	if len(b) > 4096 {
		warnf("outage: %s is %d bytes, which no declaration is; ignored", outageDeclareFile, len(b))
		return d, false
	}
	if err := json.Unmarshal(b, &d); err != nil {
		warnf("outage: %s is not a declaration: %v", outageDeclareFile, err)
		return d, false
	}
	return d, true
}

// outageDeclare files what the caller says, taking the lock. The socket
// path (custompush.go) comes through here.
func outageDeclare(d outageDeclaration, now time.Time) (outage, error) {
	outages.Lock()
	defer outages.Unlock()
	return outageDeclareLocked(d, now)
}

// outageDeclareLocked checks a declaration and files it. Caller holds the
// lock. The start defaults to the alive-stamp (the last time this helper
// was known to be running) and the end to now; both, when given, must be
// plausible seconds, in order, and not in the future. Rows already
// overlapping the stretch are all replaced by one row covering their union
// with the declared kind — the declaration is a correction as often as it
// is news — and the record is kept in time order afterwards, since a
// declaration may well be about last week: outageLastWipe reads the newest
// from the end, and the bounds trim from the front.
func outageDeclareLocked(d outageDeclaration, now time.Time) (outage, error) {
	kind := strings.TrimSpace(d.Kind)
	if !outageKindKnown(kind) {
		return outage{}, fmt.Errorf("kind must be %s, %s or %s", outageKindSuspend, outageKindDown, outageKindWipe)
	}
	nowS := now.Unix()
	pick := func(name string, v *float64, fallback int64) (int64, error) {
		if v == nil {
			return fallback, nil
		}
		f := *v
		if f != f || f < outageDeclareMinS || f > float64(nowS) {
			return 0, fmt.Errorf("%s must be unix seconds between %d and now", name, outageDeclareMinS)
		}
		return int64(f), nil
	}
	at, err := pick("at", d.At, outageStampRead())
	if err != nil {
		return outage{}, err
	}
	if at < outageDeclareMinS {
		return outage{}, errors.New("no start: give `at`, or restore the last-tick stamp beside the state")
	}
	end, err := pick("end", d.End, nowS)
	if err != nil {
		return outage{}, err
	}
	if end-at < outageMinSec {
		return outage{}, fmt.Errorf("end must be at least %d s after the start (got %d–%d)", outageMinSec, at, end)
	}
	o := outage{At: at, End: end, Kind: kind}
	outageLoad()
	keep := outages.rows[:0]
	for _, have := range outages.rows {
		if have.At <= o.End && have.End >= o.At {
			if have.At < o.At {
				o.At = have.At
			}
			if have.End > o.End {
				o.End = have.End
			}
			continue
		}
		keep = append(keep, have)
	}
	outages.rows = append(keep, o)
	sort.SliceStable(outages.rows, func(i, j int) bool { return outages.rows[i].At < outages.rows[j].At })
	outageTrim(nowS)
	outageSave()
	outageResend()
	return o, nil
}

// outageLastWipe is the most recent rebuild on record as [start_s, end_s],
// or nil. It rides the relay push (types.go `wiped`) so the hosted service
// holds the fact even when the machine's own file is never fetched — the
// relay saw the same stretch as a silence and can now say what it was.
func outageLastWipe() []int64 {
	outages.Lock()
	defer outages.Unlock()
	outageLoad()
	for i := len(outages.rows) - 1; i >= 0; i-- {
		if o := outages.rows[i]; o.Kind == outageKindWipe {
			return []int64{o.At, o.End}
		}
	}
	return nil
}

// outagePoints is what the tunnel serves beside the history: oldest first,
// as [start_s, end_s, kind] rows, never nil.
func outagePoints() []outageRow {
	outages.Lock()
	defer outages.Unlock()
	outageLoad()
	out := make([]outageRow, 0, len(outages.rows))
	for _, o := range outages.rows {
		out = append(out, o.row())
	}
	return out
}
