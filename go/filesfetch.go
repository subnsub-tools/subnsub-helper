package main

/* ── fetching files from another computer, helper to helper ──

   The other half of filesgrant.go. A copy from computer A to this one (B)
   is no longer carried by the page — A to DERP to the page to DERP to here
   — but fetched by this helper itself, from A's helper: over the tailnet
   where both are on one (fetchtailnet.go) and over tailcat, a direct UDP
   path where the two can reach each other, DERP where they cannot
   (PLAN-files-tailcat-direct.md), both at once (operator ruling 2026-11-15:
   where there is a tailnet, the tailnet and tailcat carry it together, and
   what one brings first ends the other's bringing of it; tailcat alone
   where there is none — in place of 2026-11-05's "first tailnet, then
   tailcat"). The page gives the orders and may then be closed; this machine
   keeps the job and finishes it.

   TWO ROADS. A file is fetched in pieces, and each road is a lane that
   asks for the next piece nobody has asked for, so the faster road brings
   more of the file and the two together more than either. A lane with
   nothing new to ask for — the end of the file, or the pieces ahead of a
   slow one filling the window — asks for the first piece the other is
   still bringing: the one that arrives first is written and the other's
   request for it is cancelled. Pieces are written in order, as before; a
   lane whose road fails gives its piece up to the other and dials again.

     fetch-key     B makes a tailcat node key for one job and answers its
                   public half. The private half never leaves this machine.
     (the page signs a read-only grant for that key and sends it to A)
     fetch         the job: which machine (its agent id, its tailcat address
                   and, where it has one, its tailnet listener),
                   the grant's id, the files (path, size, modified time, the
                   name here, the part's key), the folder here, keep or
                   replace. Kept in the fetches file and answered at once.
     fetch-status  how the jobs stand: each file's bytes, the rate, and the
                   roads: which carry it, how (direct, a peer relay, DERP)
                   and how many bytes came by each.
     fetch-stop    a job stopped (its parts stay, so a new job for the same
                   files goes on from them), or a finished one forgotten.

   WHO MAY. The gate is files' own (runFilesCommand): a pinned key, the
   console, the tunnel alone. What arrives here is written as the Files
   tab's puts are (fileswrite.go): a hidden part beside where it will live,
   in order, named only when every byte is there, by a link that never
   clobbers — the same part, under the same key, as the page's own carry,
   so a job resumes from where any earlier one stopped. The job is bound to
   the key that signed it: unpinned, it stops.

   WHAT B TRUSTS OF A. Nothing but bytes for a file it asked for: the size
   and time A answers must be the ones the page saw, A's hello must name the
   agent the page named, and every piece must be the length asked for. A
   changed file stops the job rather than mixing two versions. */

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	fetchesFile = "fetches"
	// Jobs fetching at once; the rest wait their turn.
	fetchRunMax = 4
	// Jobs kept, finished ones included.
	fetchKeep = 64
	// Files one job may name.
	fetchItemsMax = 64
	// A key nobody went on to fetch with is forgotten after this.
	fetchKeyWait = 10 * time.Minute
	// A finished job is kept this long for a page that comes back to it.
	fetchDoneKeep = 24 * time.Hour
	// A job that has moved no byte for this long gives up.
	fetchGiveUp = 10 * time.Minute
	// One question to A (a hello, an open) waits this long at most.
	fetchAsk = 45 * time.Second
	// A piece with no byte coming in for this long (the connection made,
	// the answer begun, its body) is given up and asked for again: a peer
	// that went away sends no reset through the tunnel, so the wait would
	// otherwise be the whole piece's.
	fetchPieceIdle = 30 * time.Second
	// Questions failed in a row before a road to A is dialled again from
	// nothing (fetchLane).
	fetchRedialAfter = 2
	// With two roads: how far past what is written pieces may be asked for.
	// It is what waits in memory for a slow piece ahead of it.
	fetchAhead = 8 << 20
	// With two roads a piece is at most this, about what its road moves in
	// fetchPieceAim, and the first one on a road fetchPieceFirst.
	fetchDualMax    = 2 << 20
	fetchPieceAim   = time.Second
	fetchPieceFirst = 256 << 10
	fetchPieceMin   = 64 << 10
	fetchAddrMax    = 1500
	// What fetch-status answers with at most, all jobs together.
	fetchStatusBytes = 160 << 10
	// How often the path to A is looked at while a job runs.
	fetchProbeEvery = 15 * time.Second
)

// fetchLaneLook is how often a lane whose road is resting looks again.
var fetchLaneLook = 2 * time.Second

var fetchAddrRe = regexp.MustCompile(`^tc[A-Za-z0-9_-]{16,}$`)

// fetchDial is how a job reaches A; a test puts its own road in its place.
var fetchDial = func(addr string, priv key.NodePrivate) fetchRoad {
	cl := &tailcat.Client{Server: tailcat.ConnBlob(addr), Key: priv, Logf: logger.Discard}
	return &tailcatRoad{cl: cl}
}

// fetchSelf is this machine's agent id, and fetchBackoff the wait before
// the n-th question asked again: a test, whose A and B are one process,
// puts its own in their place.
var fetchSelf = agentID

var fetchBackoff = func(n int) time.Duration {
	d := time.Duration(1<<min(n, 5)) * time.Second
	if d > 20*time.Second {
		d = 20 * time.Second
	}
	return d
}

// fetchRoad is a way to A: an HTTP client through its tunnel, the path the
// bytes take ("tailnet", "direct", "derp" or "" while unknown), and its end.
type fetchRoad interface {
	HTTP() *http.Client
	Route(ctx context.Context) string
	Close()
}

type tailcatRoad struct {
	cl *tailcat.Client
	hc *http.Client
}

func (t *tailcatRoad) HTTP() *http.Client {
	if t.hc == nil {
		t.hc = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return t.cl.DialTCPPort(ctx, directPort)
			},
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       time.Minute,
			ResponseHeaderTimeout: fetchPieceIdle,
		}}
	}
	return t.hc
}

// Route asks magicsock how a ping to A came back: a direct endpoint, or a
// DERP region (tailcat Client.DiscoPing, which also nudges a direct path
// along).
func (t *tailcatRoad) Route(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := t.cl.DiscoPing(ctx)
	if err != nil || r == nil {
		return ""
	}
	if r.Endpoint != "" {
		return "direct"
	}
	return "derp"
}

func (t *tailcatRoad) Close() {
	if t.hc != nil {
		t.hc.CloseIdleConnections()
	}
	t.cl.Close()
}

// fetchVia is a road that can say how it carries: the tailnet's, which asks
// the operating system's Tailscale (direct, peer-relay, derp).
type fetchVia interface {
	Via(ctx context.Context) string
}

// fetchLane is one road to A for a job — the tailnet's or tailcat's — and
// how it has done. Its road is dialled again from nothing when what is asked
// on it keeps failing: a tailcat client whose peer went away and came back
// (A's helper restarted, its network changed) does not always find it again
// by itself — seen in filesfetch_e2e_test.go, where the old client's dials
// waited on a handshake that never came while a new client got through at
// once. The old road is closed before the new one is dialled, so no two
// clients stand at DERP under the same key. A tailnet road that would not
// open is left alone for fetchTnRest.
type fetchLane struct {
	name string           // "tailnet" | "tailcat"
	dial func() fetchRoad // nil when the road would not open

	mu       sync.Mutex
	road     fetchRoad
	dialling chan struct{} // closed when the dial under way is over
	closed   bool          // the job is over: no road is dialled again
	rest     time.Time     // not dialled again before this
	fails    int           // asked and failed, in a row
	greeted  bool          // its hello named the machine the page named
	rate     float64       // bytes a second, as its last pieces came
	won      int64         // bytes of its pieces that were written
	via      string        // how it carries: direct, peer-relay, derp, "" unknown
}

// client is the road's HTTP client, the road dialled first when it is not
// up (a dial under way is waited for: opening a tailnet session is a round
// trip); nil while the road rests.
func (l *fetchLane) client() *http.Client {
	for {
		l.mu.Lock()
		if l.road != nil {
			hc := l.road.HTTP()
			l.mu.Unlock()
			return hc
		}
		if w := l.dialling; w != nil {
			l.mu.Unlock()
			<-w
			continue
		}
		if l.closed || time.Now().Before(l.rest) {
			l.mu.Unlock()
			return nil
		}
		w := make(chan struct{})
		l.dialling = w
		l.mu.Unlock()
		// Dialled outside the lock: the path's probe asks for the road
		// meanwhile.
		rd := l.dial()
		l.mu.Lock()
		l.dialling = nil
		late := l.closed && rd != nil
		switch {
		case late:
		case rd == nil:
			l.rest = time.Now().Add(fetchTnRest)
		default:
			l.road = rd
		}
		l.mu.Unlock()
		if late {
			// Dialled while the job ended: not kept.
			rd.Close()
		}
		close(w)
	}
}

// bad is a question on the lane that got no answer; after fetchRedialAfter
// in a row its road is closed, to be dialled again.
func (l *fetchLane) bad() {
	l.mu.Lock()
	l.fails++
	var old fetchRoad
	if l.fails%fetchRedialAfter == 0 {
		old, l.road, l.greeted = l.road, nil, false
	}
	l.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

func (l *fetchLane) good() {
	l.mu.Lock()
	l.fails = 0
	l.mu.Unlock()
}

// took is n bytes the lane brought in dt.
func (l *fetchLane) took(n int, dt time.Duration) {
	l.mu.Lock()
	l.fails = 0
	if n > 0 && dt > 0 {
		inst := float64(n) / dt.Seconds()
		if l.rate == 0 {
			l.rate = inst
		} else {
			l.rate = 0.6*l.rate + 0.4*inst
		}
	}
	l.mu.Unlock()
}

func (l *fetchLane) close() {
	l.mu.Lock()
	rd := l.road
	l.road, l.closed = nil, true
	l.mu.Unlock()
	if rd != nil {
		rd.Close()
	}
}

// look asks the lane's road how it carries now.
func (l *fetchLane) look(ctx context.Context) {
	l.mu.Lock()
	rd := l.road
	l.mu.Unlock()
	if rd == nil {
		return
	}
	via := rd.Route(ctx)
	if v, ok := rd.(fetchVia); ok {
		via = v.Via(ctx)
	} else if via == "tailnet" {
		via = ""
	}
	if via != "" {
		l.mu.Lock()
		l.via = via
		l.mu.Unlock()
	}
}

// fetchRoads is a job's roads to A: the tailnet's where A has a listener
// there, then tailcat's.
type fetchRoads struct {
	lanes []*fetchLane
}

// pick is the lane a question goes by: the one that has failed least of
// late, the tailnet's before tailcat's when they are even — so a question
// that keeps failing goes from one road to the other and back, and a road
// that has come back is found again — and the next when that one's road
// cannot be had.
func (r *fetchRoads) pick() (*fetchLane, *http.Client) {
	order := append([]*fetchLane{}, r.lanes...)
	fails := map[*fetchLane]int{}
	for _, l := range order {
		l.mu.Lock()
		fails[l] = l.fails
		l.mu.Unlock()
	}
	sort.SliceStable(order, func(a, b int) bool { return fails[order[a]] < fails[order[b]] })
	for _, l := range order {
		if hc := l.client(); hc != nil {
			return l, hc
		}
	}
	return nil, nil
}

// aim is how large a piece lane li asks for next. One road asks for the
// most A gives, as it always did. With two, about what the lane moves in
// fetchPieceAim — and less on the slower one, so that the faster does not
// fill the window before the slower's piece is in: a piece both would then
// bring twice.
func (r *fetchRoads) aim(li int, max int64) int64 {
	if len(r.lanes) < 2 {
		return max
	}
	if max > fetchDualMax {
		max = fetchDualMax
	}
	var mine, best float64
	for i, l := range r.lanes {
		l.mu.Lock()
		if i == li {
			mine = l.rate
		}
		if l.rate > best {
			best = l.rate
		}
		l.mu.Unlock()
	}
	n := int64(fetchPieceFirst)
	if mine > 0 {
		n = int64(mine * fetchPieceAim.Seconds())
		if mine < best {
			if m := int64(mine / best * float64(fetchAhead/2)); m < n {
				n = m
			}
		}
	}
	if n < fetchPieceMin {
		n = fetchPieceMin
	}
	if n > max {
		n = max
	}
	return n
}

func (r *fetchRoads) close() {
	for _, l := range r.lanes {
		l.close()
	}
}

// fetchRoadView is one road as fetch-status shows it.
type fetchRoadView struct {
	K   string `json:"k"`             // tailnet | tailcat
	Via string `json:"via,omitempty"` // direct | peer-relay | derp
	B   int64  `json:"b"`             // bytes it brought that were written
}

// views is the roads as they stand, and the one word older pages read: the
// road that brought the most ("tailnet", "direct", "derp").
func (r *fetchRoads) views() ([]fetchRoadView, string) {
	var out []fetchRoadView
	route, most := "", int64(-1)
	for _, l := range r.lanes {
		l.mu.Lock()
		up, won, via := l.road != nil, l.won, l.via
		l.mu.Unlock()
		if !up && won == 0 {
			continue
		}
		out = append(out, fetchRoadView{K: l.name, Via: via, B: won})
		if won > most {
			most = won
			if l.name == "tailnet" {
				route = "tailnet"
			} else if via == "direct" || via == "derp" {
				route = via
			}
		}
	}
	return out, route
}

// fetchPart is a piece of the file being fetched: asked for on one road, or
// on both when the other has nothing else to bring.
type fetchPart struct {
	off, n int64
	buf    []byte               // the piece, once a road brought it whole
	lane   int                  // the road that did
	by     []context.CancelFunc // each lane's asking for it, nil when it is not
	gone   bool                 // dropped: the part here was found again elsewhere
}

func (p *fetchPart) asked() bool {
	for _, c := range p.by {
		if c != nil {
			return true
		}
	}
	return false
}

// fetchSpread is one file's pieces, handed out to the lanes and gathered
// back in order.
type fetchSpread struct {
	mu     sync.Mutex
	ch     chan struct{} // closed, and made again, when something changed
	lanes  int
	size   int64
	max    int64        // a piece, at most
	have   int64        // written
	next   int64        // the first byte no lane was asked for
	parts  []*fetchPart // asked for and not yet written, in order
	tok    string       // the file as A opened it
	gen    int          // of tok
	reopen bool         // a lane found the token lapsed
	fatal  string       // a code that ends the job
}

func (s *fetchSpread) changedLocked() {
	close(s.ch)
	s.ch = make(chan struct{})
}

// end is a code after which the job cannot go on.
func (s *fetchSpread) end(code string) {
	s.mu.Lock()
	if s.fatal == "" {
		s.fatal = code
	}
	s.changedLocked()
	s.mu.Unlock()
}

// reset starts over from have: the part here turned out to hold something
// else than what was handed out (it was found again, or written elsewhere).
func (s *fetchSpread) reset(have int64) {
	s.mu.Lock()
	for _, p := range s.parts {
		p.gone = true
		for _, c := range p.by {
			if c != nil {
				c()
			}
		}
	}
	s.parts, s.have, s.next = nil, have, have
	s.changedLocked()
	s.mu.Unlock()
}

func (s *fetchSpread) pickLocked(li int, aim int64) *fetchPart {
	// One nobody is bringing: its road failed.
	for _, p := range s.parts {
		if p.buf == nil && !p.asked() {
			return p
		}
	}
	// A new one, while what is asked for stays within the window.
	if s.next < s.size && (len(s.parts) == 0 || s.next-s.have < fetchAhead) {
		n := s.size - s.next
		if n > aim {
			n = aim
		}
		if n > s.max {
			n = s.max
		}
		p := &fetchPart{off: s.next, n: n, by: make([]context.CancelFunc, s.lanes)}
		s.next += n
		s.parts = append(s.parts, p)
		return p
	}
	// Nothing new to ask for — the end of the file, or the window full
	// behind a piece the other road is still bringing: the first such piece
	// is asked for here as well, and whichever road brings it first ends
	// the other's asking.
	for _, p := range s.parts {
		if p.buf == nil && p.by[li] == nil {
			return p
		}
	}
	return nil
}

// take is the piece lane li fetches next, waited for: the piece, the
// context its asking lives in, and the file's token; nil when the file is
// over for the lane.
func (s *fetchSpread) take(ctx context.Context, li int, aim int64) (*fetchPart, context.Context, context.CancelFunc, string, int) {
	for {
		s.mu.Lock()
		if s.fatal != "" || ctx.Err() != nil {
			s.mu.Unlock()
			return nil, nil, nil, "", 0
		}
		if !s.reopen {
			if p := s.pickLocked(li, aim); p != nil {
				pctx, cancel := context.WithCancel(ctx)
				p.by[li] = cancel
				tok, gen := s.tok, s.gen
				s.mu.Unlock()
				return p, pctx, cancel, tok, gen
			}
		}
		ch := s.ch
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, nil, "", 0
		case <-ch:
		}
	}
}

// brought is lane li done asking for p: with the piece (buf), or without.
// It says whether the piece was the other road's already, or dropped — the
// lane's asking was ended for it, and its road is not to blame.
func (s *fetchSpread) brought(p *fetchPart, li int, buf []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.by[li] = nil
	if p.gone || p.buf != nil {
		return true
	}
	if buf != nil {
		p.buf, p.lane = buf, li
		for _, c := range p.by {
			if c != nil {
				c()
			}
		}
	}
	// Brought, or given up for the other lane to take.
	s.changedLocked()
	return false
}

// lapsed is a lane told the token is no longer A's (ten idle minutes, or A
// restarted): the file is opened again, and the lane waits for that.
func (s *fetchSpread) lapsed(ctx context.Context, gen int) bool {
	for {
		s.mu.Lock()
		if s.fatal != "" {
			s.mu.Unlock()
			return false
		}
		if s.gen != gen {
			s.mu.Unlock()
			return true
		}
		if !s.reopen {
			s.reopen = true
			s.changedLocked()
		}
		ch := s.ch
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-ch:
		}
	}
}

// idleReader cancels its piece when no byte has come in for a while.
type idleReader struct {
	r io.Reader
	t *time.Timer
}

func (i idleReader) Read(b []byte) (int, error) {
	n, err := i.r.Read(b)
	if n > 0 {
		i.t.Reset(fetchPieceIdle)
	}
	return n, err
}

type fetchFrom struct {
	Agent string   `json:"agent"`
	Addr  string   `json:"addr"`
	Tn    *fetchTn `json:"tn,omitempty"`
}

// fetchItem is one file of a job: what the page asked for, and how far it is.
type fetchItem struct {
	P string `json:"p"`           // on A
	S int64  `json:"s"`           // its size as the page saw it
	M int64  `json:"m"`           // its modified time, Unix seconds
	N string `json:"n,omitempty"` // its name here; A's name when empty
	K string `json:"k"`           // the part's key (fileswrite.go)

	St   string `json:"st,omitempty"` // "" waiting | run | done | err
	Got  int64  `json:"got,omitempty"`
	Path string `json:"path,omitempty"` // where it was put
	Err  string `json:"err,omitempty"`
}

// fetchRec is a job as it is kept.
type fetchRec struct {
	Job   string      `json:"job"`
	Agent string      `json:"agent"`
	Addr  string      `json:"addr,omitempty"`
	Tn    *fetchTn    `json:"tn,omitempty"` // A's tailnet listener, tried first
	Grant string      `json:"grant,omitempty"`
	Items []fetchItem `json:"items,omitempty"`
	Dir   string      `json:"dir,omitempty"`
	Mode  string      `json:"mode,omitempty"`
	Mv    bool        `json:"mv,omitempty"`   // the page moves: A's file goes to its trash once this is done
	Node  string      `json:"node,omitempty"` // the job's private node key, until it is over
	Pub   string      `json:"pub"`
	By    string      `json:"by"` // the pinned key that signed it, base64
	St    string      `json:"st"` // key | wait | run | done | err | stopped
	Err   string      `json:"err,omitempty"`
	Route string      `json:"route,omitempty"`
	At    int64       `json:"at"`
	End   int64       `json:"end,omitempty"`
}

type fetchRun struct {
	mu     sync.Mutex
	rec    fetchRec
	cancel context.CancelFunc
	stop   bool
	rate   float64
	roads  *fetchRoads // while it runs
}

var fetches = struct {
	sync.Mutex
	m      map[string]*fetchRun
	loaded bool
	saving sync.Mutex
}{m: map[string]*fetchRun{}}

func fetchesPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, fetchesFile)
}

func fetchFinished(st string) bool { return st == "done" || st == "err" || st == "stopped" }

// fetchLoad reads the kept jobs once: one that was running when this helper
// stopped runs again, from its parts.
func fetchLoad() {
	fetches.Lock()
	defer fetches.Unlock()
	if fetches.loaded {
		return
	}
	fetches.loaded = true
	path := fetchesPath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var recs []fetchRec
	if json.Unmarshal(b, &recs) != nil {
		return
	}
	for _, r := range recs {
		if !filesPutKRe.MatchString(r.Job) || fetches.m[r.Job] != nil {
			continue
		}
		if r.St == "run" {
			r.St = "wait"
		}
		if r.St == "wait" && r.Node == "" {
			r.St, r.Err = "err", "unavailable"
		}
		fetches.m[r.Job] = &fetchRun{rec: r}
	}
}

// fetchSave writes every job, beside the file and renamed over it, 0600.
func fetchSave() {
	fetches.saving.Lock()
	defer fetches.saving.Unlock()
	fetches.Lock()
	recs := make([]fetchRec, 0, len(fetches.m))
	for _, f := range fetches.m {
		f.mu.Lock()
		rec := f.rec
		// Its own items: the job's are written to while this is marshalled.
		rec.Items = append([]fetchItem(nil), f.rec.Items...)
		recs = append(recs, rec)
		f.mu.Unlock()
	}
	fetches.Unlock()
	sort.Slice(recs, func(i, j int) bool { return recs[i].At < recs[j].At })
	path := fetchesPath()
	if path == "" {
		return
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if err := writeFileAtomic(path, b); err != nil {
		warnf("files: could not keep the fetch jobs: %v", err)
	}
}

// fetchSweep forgets keys nobody used and jobs long finished. Under fetches.
func fetchSweepLocked(now time.Time) bool {
	changed := false
	for job, f := range fetches.m {
		f.mu.Lock()
		r := f.rec
		f.mu.Unlock()
		at := time.Unix(r.At, 0)
		if (r.St == "key" && now.Sub(at) > fetchKeyWait) || (fetchFinished(r.St) && now.Sub(time.Unix(r.End, 0)) > fetchDoneKeep) {
			delete(fetches.m, job)
			changed = true
		}
	}
	return changed
}

// fetchMakeRoom drops the oldest finished jobs until another fits. Under
// fetches. False when every kept job is still under way.
func fetchMakeRoomLocked() bool {
	for len(fetches.m) >= fetchKeep {
		old, at := "", int64(0)
		for job, f := range fetches.m {
			f.mu.Lock()
			r := f.rec
			f.mu.Unlock()
			if fetchFinished(r.St) && (old == "" || r.End < at) {
				old, at = job, r.End
			}
		}
		if old == "" {
			return false
		}
		delete(fetches.m, old)
	}
	return true
}

// fetchResume starts what was under way when the helper last stopped.
func fetchResume() {
	fetchLoad()
	fetchSchedule()
}

// fetchSchedule starts waiting jobs, oldest first, while there is room.
func fetchSchedule() {
	fetches.Lock()
	running := 0
	type queued struct {
		f  *fetchRun
		at int64
	}
	var waiting []queued
	for _, f := range fetches.m {
		f.mu.Lock()
		switch f.rec.St {
		case "run":
			running++
		case "wait":
			waiting = append(waiting, queued{f, f.rec.At})
		}
		f.mu.Unlock()
	}
	sort.Slice(waiting, func(i, j int) bool { return waiting[i].at < waiting[j].at })
	var start []*fetchRun
	for _, q := range waiting {
		f := q.f
		if running >= fetchRunMax {
			break
		}
		ctx, cancel := context.WithCancel(context.Background())
		f.mu.Lock()
		f.rec.St = "run"
		f.cancel = cancel
		f.stop = false
		f.mu.Unlock()
		running++
		start = append(start, f)
		go f.run(ctx)
	}
	fetches.Unlock()
	if len(start) > 0 {
		fetchSave()
	}
}

// runFetchCommand is the B side's commands. The caller (runFilesCommand)
// has checked the pin, the console and the tunnel; signer is the pinned key
// that signed this one.
func runFetchCommand(op string, signer ed25519.PublicKey, a filesArgs) (any, string) {
	fetchLoad()
	now := time.Now()
	by := base64.StdEncoding.EncodeToString(signer)
	if len(signer) == 0 {
		return nil, "not-allowed"
	}
	switch op {
	case "fetch-key":
		if !filesPutKRe.MatchString(a.Job) {
			return nil, "bad-args"
		}
		fetches.Lock()
		fetchSweepLocked(now)
		if f := fetches.m[a.Job]; f != nil {
			f.mu.Lock()
			r := f.rec
			f.mu.Unlock()
			fetches.Unlock()
			if r.St == "key" && r.By == by {
				return map[string]any{"pub": r.Pub}, ""
			}
			return nil, "busy"
		}
		if !fetchMakeRoomLocked() {
			fetches.Unlock()
			return nil, "busy"
		}
		node := key.NewNode()
		priv, err1 := node.MarshalText()
		pub, err2 := node.Public().MarshalText()
		if err1 != nil || err2 != nil {
			fetches.Unlock()
			return nil, "unavailable"
		}
		fetches.m[a.Job] = &fetchRun{rec: fetchRec{Job: a.Job, Node: string(priv), Pub: string(pub), By: by, St: "key", At: now.Unix()}}
		fetches.Unlock()
		fetchSave()
		return map[string]any{"pub": string(pub)}, ""

	case "fetch":
		items, dir, mode, code := fetchArgs(a)
		if code != "" {
			return nil, code
		}
		fetches.Lock()
		f := fetches.m[a.Job]
		if f == nil {
			fetches.Unlock()
			return nil, "no-job"
		}
		f.mu.Lock()
		if f.rec.St != "key" || f.rec.By != by {
			f.mu.Unlock()
			fetches.Unlock()
			return nil, "busy"
		}
		f.rec.Agent, f.rec.Addr, f.rec.Tn, f.rec.Grant = a.From.Agent, a.From.Addr, fetchTnArg(a.From.Tn), a.Grant
		f.rec.Items, f.rec.Dir, f.rec.Mode, f.rec.Mv = items, dir, mode, a.Mv
		f.rec.St, f.rec.At = "wait", now.Unix()
		f.mu.Unlock()
		fetches.Unlock()
		fetchSave()
		fetchSchedule()
		return map[string]any{"job": a.Job}, ""

	case "fetch-status":
		fetches.Lock()
		if fetchSweepLocked(now) {
			defer fetchSave()
		}
		var runs []*fetchRun
		for _, f := range fetches.m {
			runs = append(runs, f)
		}
		fetches.Unlock()
		var views []fetchView
		for _, f := range runs {
			v := f.view()
			if v.St == "key" || (a.Job != "" && v.Job != a.Job) {
				continue
			}
			views = append(views, v)
		}
		if a.Job != "" && len(views) == 0 {
			return nil, "no-job"
		}
		sort.Slice(views, func(i, j int) bool { return views[i].At > views[j].At })
		out, used := []fetchView{}, 0
		for _, v := range views {
			b, _ := json.Marshal(v)
			if used+len(b) > fetchStatusBytes {
				break
			}
			used += len(b)
			out = append(out, v)
		}
		return map[string]any{"jobs": out}, ""

	case "fetch-stop":
		if !filesPutKRe.MatchString(a.Job) {
			return nil, "bad-args"
		}
		fetches.Lock()
		f := fetches.m[a.Job]
		if f == nil {
			fetches.Unlock()
			return map[string]any{}, ""
		}
		f.mu.Lock()
		st := f.rec.St
		switch {
		case a.Forget && (fetchFinished(st) || st == "key"):
			delete(fetches.m, a.Job)
		case st == "run":
			f.stop = true
			if f.cancel != nil {
				f.cancel()
			}
		case st == "wait" || st == "key":
			f.rec.St, f.rec.End, f.rec.Node = "stopped", now.Unix(), ""
		}
		f.mu.Unlock()
		fetches.Unlock()
		fetchSave()
		return map[string]any{}, ""
	}
	return nil, "unknown-op"
}

// fetchArgs checks a fetch's arguments as written.
func fetchArgs(a filesArgs) ([]fetchItem, string, string, string) {
	if !filesPutKRe.MatchString(a.Job) || !cloneAgentRe.MatchString(a.From.Agent) || !cloneIDRe.MatchString(a.Grant) {
		return nil, "", "", "bad-args"
	}
	if a.From.Agent == fetchSelf() {
		return nil, "", "", "same-machine"
	}
	if len(a.From.Addr) > fetchAddrMax || !fetchAddrRe.MatchString(a.From.Addr) {
		return nil, "", "", "bad-args"
	}
	if len(a.Items) == 0 || len(a.Items) > fetchItemsMax {
		return nil, "", "", "bad-args"
	}
	dir, code := musicPathArg(a.Dir)
	if code != "" {
		return nil, "", "", code
	}
	mode := a.Mode
	switch mode {
	case "":
		mode = "keep"
	case "keep", "replace", "fail":
	default:
		return nil, "", "", "bad-args"
	}
	items := make([]fetchItem, 0, len(a.Items))
	for _, it := range a.Items {
		// A's path, in A's own way of writing one (a Windows path asked for
		// from a Mac): A judges it against the grant. Here it is only text.
		p := it.P
		if len(p) > 4096 || !utf8.ValidString(p) || strings.ContainsAny(p, "\x00\n\r") || !fetchAbsAnywhere(p) {
			return nil, "", "", "bad-path"
		}
		n := it.N
		if n == "" {
			n = p[strings.LastIndexAny(p, `/\`)+1:]
		}
		if _, code := filesNameArg(n); code != "" {
			return nil, "", "", code
		}
		if it.S < 0 || it.S > filesPutSize || it.M < 0 || it.M > filesTimeMax || !filesPutKRe.MatchString(it.K) {
			return nil, "", "", "bad-args"
		}
		items = append(items, fetchItem{P: p, S: it.S, M: it.M, N: n, K: it.K})
	}
	if code := filesLookDir(dir); code != "" {
		return nil, "", "", code
	}
	return items, dir, mode, ""
}

// fetchAbsAnywhere: a whole path on some computer, as that one writes it
// (/home/u/a, C:\Users\u\a, \\server\share\a), whatever this one is.
func fetchAbsAnywhere(p string) bool {
	switch {
	case strings.HasPrefix(p, "/"), strings.HasPrefix(p, `\\`):
		return true
	case len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}

// fetchView is a job as fetch-status shows it: no key, no address.
type fetchView struct {
	Job   string          `json:"job"`
	Agent string          `json:"agent"`
	St    string          `json:"st"`
	Err   string          `json:"err,omitempty"`
	Route string          `json:"route,omitempty"`
	Roads []fetchRoadView `json:"roads,omitempty"`
	Rate  int64           `json:"rate"`
	Got   int64           `json:"got"`
	Size  int64           `json:"size"`
	Dir   string          `json:"dir"`
	Mode  string          `json:"mode"`
	Mv    bool            `json:"mv,omitempty"`
	Grant string          `json:"grant,omitempty"`
	Items []fetchItem     `json:"items"`
	At    int64           `json:"at"`
	End   int64           `json:"end,omitempty"`
}

func (f *fetchRun) view() fetchView {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rec
	v := fetchView{Job: r.Job, Agent: r.Agent, St: r.St, Err: r.Err, Route: r.Route, Dir: r.Dir, Mode: r.Mode, Mv: r.Mv,
		Grant: r.Grant, Items: append([]fetchItem{}, r.Items...), At: r.At, End: r.End}
	for _, it := range r.Items {
		v.Size += it.S
		v.Got += it.Got
	}
	if r.St == "run" {
		v.Rate = int64(f.rate)
		if f.roads != nil {
			v.Roads, _ = f.roads.views()
		}
	}
	return v
}

// run is one job, to its end.
func (f *fetchRun) run(ctx context.Context) {
	st, why := f.work(ctx)
	f.mu.Lock()
	if f.stop {
		st, why = "stopped", ""
	}
	f.rec.St, f.rec.Err, f.rec.End, f.rec.Node = st, why, time.Now().Unix(), ""
	f.cancel = nil
	f.mu.Unlock()
	if why != "" {
		warnf("files: a fetch from another computer ended: %s", why)
	}
	fetchSave()
	fetchSchedule()
}

// fatalFetch: codes after which asking again cannot help.
func fatalFetch(code string) bool {
	switch code {
	case "not-allowed", "grant-gone", "wrong-machine", "changed", "unpinned", "console-off", "bad-path", "bad-name",
		"missing", "no-access", "not-a-file", "not-a-folder", "no-space", "exists", "changed-since", "bad-args", "stopped":
		return true
	}
	return false
}

// work fetches every file of the job; the state it ended in and why.
func (f *fetchRun) work(ctx context.Context) (string, string) {
	f.mu.Lock()
	r := f.rec
	r.Items = append([]fetchItem{}, f.rec.Items...)
	f.mu.Unlock()
	// Every file got there before a restart came between the last one and
	// the job's end: done, without asking A (whose grant may be ended).
	all := len(r.Items) > 0
	for _, it := range r.Items {
		all = all && it.St == "done"
	}
	if all {
		return "done", ""
	}
	var priv key.NodePrivate
	if priv.UnmarshalText([]byte(r.Node)) != nil {
		return "err", "unavailable"
	}
	signer := exactKey(r.By)
	pub := priv.Public()
	// The roads: the tailnet's where A has a listener there (this machine on
	// no tailnet, or a listener that would not open, is a lane that rests),
	// and tailcat's.
	roads := &fetchRoads{}
	if r.Tn != nil {
		roads.lanes = append(roads.lanes, &fetchLane{name: "tailnet", dial: func() fetchRoad { return fetchDialTn(ctx, r.Tn, r.Agent, priv) }})
	}
	roads.lanes = append(roads.lanes, &fetchLane{name: "tailcat", dial: func() fetchRoad { return fetchDial(r.Addr, priv) }})
	f.mu.Lock()
	f.roads = roads
	f.mu.Unlock()
	note := func() {
		_, rt := roads.views()
		f.mu.Lock()
		if rt != "" {
			f.rec.Route = rt
		}
		f.mu.Unlock()
	}
	defer func() {
		note()
		f.mu.Lock()
		f.roads = nil
		f.mu.Unlock()
		roads.close()
	}()
	// The paths, looked at now and then while the job runs.
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	go func() {
		clock := time.NewTimer(time.Second)
		defer clock.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-clock.C:
			}
			for _, l := range roads.lanes {
				l.look(pctx)
			}
			note()
			clock.Reset(fetchProbeEvery)
		}
	}()
	j := &fetchJob{f: f, ctx: ctx, roads: roads, rec: r, signer: signer, pub: pub, last: time.Now()}
	j.gctx, j.gcancel = context.WithCancel(ctx)
	// The hellos greet left on their way are over before the roads close:
	// none dials, or asks, on a road the job has let go.
	defer func() {
		j.gcancel()
		j.greets.Wait()
	}()
	if code := j.greet(); code != "" {
		return "err", code
	}
	for i := range r.Items {
		if r.Items[i].St == "done" {
			continue
		}
		if code := j.item(i); code != "" {
			f.mu.Lock()
			f.rec.Items[i].St, f.rec.Items[i].Err = "err", code
			f.mu.Unlock()
			// A job stopped may be ordered again under a new grant, and the
			// page revokes this one; one that cannot reach A cannot tell it.
			if code != "unreachable" && code != "stopped" {
				j.grantDone()
			}
			return "err", code
		}
	}
	j.grantDone()
	return "done", ""
}

// fetchJob is one run of a job: what it asks A with.
type fetchJob struct {
	f      *fetchRun
	ctx    context.Context
	roads  *fetchRoads
	rec    fetchRec
	signer ed25519.PublicKey
	pub    key.NodePublic
	last   time.Time // when a byte last moved, or the job began
	tries  int

	// greet's hellos: their context, ended with the job, and their count.
	gctx    context.Context
	gcancel context.CancelFunc
	greets  sync.WaitGroup
}

// still is what the job may not go on without: the key that signed it
// pinned, the console on, nobody having stopped it.
func (j *fetchJob) still() string {
	if j.ctx.Err() != nil {
		return "stopped"
	}
	if !trustsKey(j.signer) {
		return "unpinned"
	}
	if !filesOn() {
		return "console-off"
	}
	return ""
}

// again waits before asking again, longer each time, and gives up once no
// byte has moved for fetchGiveUp.
func (j *fetchJob) again() string {
	if time.Since(j.last) > fetchGiveUp {
		return "unreachable"
	}
	j.tries++
	select {
	case <-j.ctx.Done():
		return "stopped"
	case <-time.After(fetchBackoff(j.tries)):
	}
	return ""
}

func (j *fetchJob) moved() {
	j.last = time.Now()
	j.tries = 0
}

// ask is one question to A, asked again while A cannot be reached: by the
// first road that is up and has not just failed (the tailnet's before
// tailcat's), and by the other when that one does not answer.
func (j *fetchJob) ask(do func(ctx context.Context, l *fetchLane, hc *http.Client) string) string {
	for {
		if code := j.still(); code != "" {
			return code
		}
		code := "unreachable"
		l, hc := j.roads.pick()
		if hc != nil {
			ctx, cancel := context.WithTimeout(j.ctx, fetchAsk)
			code = do(ctx, l, hc)
			cancel()
		}
		if code == "not-allowed" {
			// The grant is gone: revoked, run out, or its key unpinned on A.
			return "grant-gone"
		}
		if code == "" || fatalFetch(code) {
			if l != nil {
				l.good()
			}
			return code
		}
		if l != nil {
			l.bad()
		}
		if why := j.again(); why != "" {
			return why
		}
	}
}

// helloOn asks the machine at the end of one road who it is: it must be the
// one the page named.
func (j *fetchJob) helloOn(ctx context.Context, hc *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://tailcat/v1/hello", nil)
	if err != nil {
		return "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "unreachable"
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "unreachable"
	}
	if resp.StatusCode != http.StatusOK {
		return frameCode(b, resp.StatusCode)
	}
	fr, err := transport.Decode(b)
	if err != nil || fr.Type != transport.TypeHello {
		return "bad-frame"
	}
	if fr.AgentID != j.rec.Agent {
		return "wrong-machine"
	}
	return ""
}

func (l *fetchLane) greet() {
	l.mu.Lock()
	l.greeted, l.fails = true, 0
	l.mu.Unlock()
}

// greet makes sure the machine at the address is the one the page named,
// on every road at once: the job goes on with the first that answers, and
// a road is asked for no piece before its own hello (lane). When none
// answers, the question is asked again as any other is (hello).
func (j *fetchJob) greet() string {
	ch := make(chan string, len(j.roads.lanes))
	for _, l := range j.roads.lanes {
		j.greets.Add(1)
		go func(l *fetchLane) {
			defer j.greets.Done()
			hc := l.client()
			if hc == nil || j.gctx.Err() != nil {
				ch <- "unreachable"
				return
			}
			ctx, cancel := context.WithTimeout(j.gctx, fetchAsk)
			defer cancel()
			code := j.helloOn(ctx, hc)
			switch {
			case j.gctx.Err() != nil:
				// The job ended under it: the road is not to blame.
				code = "unreachable"
			case code == "":
				l.greet()
			case code != "not-allowed" && !fatalFetch(code):
				l.bad()
			}
			ch <- code
		}(l)
	}
	for range j.roads.lanes {
		code := <-ch
		if code == "not-allowed" {
			code = "grant-gone"
		}
		if code == "" {
			j.moved()
			return ""
		}
		if fatalFetch(code) {
			return code
		}
	}
	return j.hello()
}

// hello is greet's question on one road at a time, asked again while A
// cannot be reached.
func (j *fetchJob) hello() string {
	code := j.ask(func(ctx context.Context, l *fetchLane, hc *http.Client) string {
		code := j.helloOn(ctx, hc)
		if code == "" {
			l.greet()
		}
		return code
	})
	if code == "" {
		j.moved()
	}
	return code
}

// open is the file opened on A under the grant, checked against what the
// page saw of it.
func (j *fetchJob) open(it fetchItem) (filesOpenBody, string) {
	var ob filesOpenBody
	code := j.ask(func(ctx context.Context, _ *fetchLane, hc *http.Client) string {
		ob = filesOpenBody{}
		return grantPost(ctx, hc, "/v1/files/grant/open", grantReq{ID: j.rec.Grant, Path: it.P}, &ob)
	})
	if code != "" {
		return ob, code
	}
	if ob.T == "" {
		return ob, "bad-frame"
	}
	if ob.S != it.S || ob.M != it.M {
		return ob, "changed"
	}
	return ob, ""
}

// piece is n bytes of the opened file from off, by one road: exactly that
// many, or why not. Its asking ends with ctx: when the job stops, or when
// the other road brought the same piece first.
func (j *fetchJob) piece(ctx context.Context, hc *http.Client, tok string, off, n int64) ([]byte, string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(fetchPieceIdle, cancel)
	defer idle.Stop()
	u := "http://tailcat/v1/files/file?s=" + tok + "&o=" + strconv.FormatInt(off, 10) + "&n=" + strconv.FormatInt(n, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		if j.ctx.Err() != nil {
			return nil, "stopped"
		}
		return nil, "unreachable"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, frameCode(b, resp.StatusCode)
	}
	b, err := io.ReadAll(idleReader{io.LimitReader(resp.Body, n+1), idle})
	if err != nil {
		if j.ctx.Err() != nil {
			return nil, "stopped"
		}
		return nil, "unreachable"
	}
	if int64(len(b)) != n {
		return nil, "changed"
	}
	return b, ""
}

// lane is one road at work on a file: it says hello where it has not, then
// asks for piece after piece until the file is over. A piece the road could
// not bring is given up for the other lane, and the road rests before it
// asks again.
func (j *fetchJob) lane(ctx context.Context, s *fetchSpread, li int) {
	l := j.roads.lanes[li]
	tries := 0
	rest := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	failed := func() bool {
		l.bad()
		tries++
		return rest(fetchBackoff(tries))
	}
	for ctx.Err() == nil {
		hc := l.client()
		if hc == nil {
			if !rest(fetchLaneLook) {
				return
			}
			continue
		}
		l.mu.Lock()
		greeted := l.greeted
		l.mu.Unlock()
		if !greeted {
			hctx, cancel := context.WithTimeout(ctx, fetchAsk)
			code := j.helloOn(hctx, hc)
			cancel()
			switch {
			case ctx.Err() != nil:
				return
			case code == "":
				l.greet()
			case code == "not-allowed":
				s.end("grant-gone")
				return
			case fatalFetch(code):
				s.end(code)
				return
			default:
				if !failed() {
					return
				}
				continue
			}
		}
		p, pctx, cancel, tok, gen := s.take(ctx, li, j.roads.aim(li, s.max))
		if p == nil {
			return
		}
		t0 := time.Now()
		buf, code := j.piece(pctx, hc, tok, p.off, p.n)
		cancel()
		if code != "" {
			buf = nil
		}
		others := s.brought(p, li, buf)
		switch {
		case code == "":
			l.took(len(buf), time.Since(t0))
			tries = 0
		case ctx.Err() != nil:
			return
		case others:
			// The other road brought it first, and ended this asking.
		case code == "no-file":
			if !s.lapsed(ctx, gen) {
				return
			}
		case code == "not-allowed":
			s.end("grant-gone")
			return
		case fatalFetch(code):
			s.end(code)
			return
		default:
			if !failed() {
				return
			}
		}
	}
}

// put is the part here for one file, opened or found again: its upload and
// how much it holds.
func (j *fetchJob) put(it fetchItem) (*filesPut, string, int64, string) {
	pb, code := filesPutStart(j.pub, j.signer, j.rec.Dir, it.N, it.S, it.K, j.rec.Mode, nil)
	if code != "" {
		return nil, "", 0, code
	}
	p := filesPutFind(pb.T, j.pub)
	if p == nil {
		return nil, "", 0, "unavailable"
	}
	return p, pb.T, pb.Have, ""
}

func (j *fetchJob) progress(i int, have int64, n int, dt time.Duration) {
	f := j.f
	f.mu.Lock()
	f.rec.Items[i].St, f.rec.Items[i].Got = "run", have
	if dt > 0 && n > 0 {
		inst := float64(n) / dt.Seconds()
		if f.rate == 0 {
			f.rate = inst
		} else {
			f.rate = 0.7*f.rate + 0.3*inst
		}
	}
	f.mu.Unlock()
}

// item fetches file i of the job: its pieces asked for by every road at
// once (lane), written here in order as they come.
func (j *fetchJob) item(i int) string {
	it := j.rec.Items[i]
	if code := j.still(); code != "" {
		return code
	}
	ob, code := j.open(it)
	if code != "" {
		return code
	}
	p, tok, have, code := j.put(it)
	if code != "" {
		return code
	}
	j.progress(i, have, 0, 0)
	stopPut := func() {
		// Its part stays, keyed, for the next job for the same file.
		filesPutForget(p)
		p.end("stopped", false)
	}
	max := int64(ob.Max)
	if max <= 0 || max > filesReadMax {
		max = filesReadMax
	}
	s := &fetchSpread{ch: make(chan struct{}), lanes: len(j.roads.lanes), size: it.S, max: max, have: have, next: have, tok: ob.T}
	ictx, icancel := context.WithCancel(j.ctx)
	var wg sync.WaitGroup
	// The lanes are over before this returns: nothing asks A for a file the
	// job has left.
	defer func() {
		icancel()
		wg.Wait()
	}()
	if have < it.S {
		for li := range j.roads.lanes {
			wg.Add(1)
			go func(li int) {
				defer wg.Done()
				j.lane(ictx, s, li)
			}(li)
		}
	}
	reopened := false
	var acc int
	accAt := time.Now()
	for have < it.S {
		s.mu.Lock()
		fatal, lapsed := s.fatal, s.reopen
		var part *fetchPart
		if fatal == "" && len(s.parts) > 0 && s.parts[0].buf != nil {
			part = s.parts[0]
			s.parts = s.parts[1:]
		}
		ch := s.ch
		s.mu.Unlock()
		// A piece that is here is written before anything else is looked
		// at: a job stopped keeps what it had fetched, in its part.
		code := ""
		if part == nil {
			code = j.still()
		}
		switch {
		case part != nil:
		case fatal == "changed":
			filesPutCancel(j.pub, tok)
			return fatal
		case fatal != "":
			stopPut()
			return fatal
		case code != "":
			stopPut()
			return code
		case time.Since(j.last) > fetchGiveUp:
			stopPut()
			return "unreachable"
		case lapsed:
			// The token lapsed on A (ten idle minutes, or A restarted).
			nob, code := j.open(it)
			if code != "" {
				stopPut()
				return code
			}
			s.mu.Lock()
			s.tok, s.reopen = nob.T, false
			s.gen++
			s.changedLocked()
			s.mu.Unlock()
			continue
		default:
			select {
			case <-ch:
			case <-j.ctx.Done():
			case <-time.After(time.Second):
			}
			continue
		}
		if part.off != have {
			s.reset(have)
			continue
		}
		got, wcode := p.write(j.ctx, have, part.buf)
		switch wcode {
		case "":
		case "no-put", "offset":
			// The upload here was ended (the sweep, a page's own put of
			// the same part): found again, from what the part holds.
			if reopened && wcode == "no-put" {
				return "unavailable"
			}
			reopened = true
			if p, tok, have, code = j.put(it); code != "" {
				return code
			}
			s.reset(have)
			continue
		case "gone":
			stopPut()
			return "stopped"
		default:
			stopPut()
			return wcode
		}
		reopened = false
		l := j.roads.lanes[part.lane]
		l.mu.Lock()
		l.won += part.n
		l.mu.Unlock()
		acc += int(got - have)
		have = got
		if got != part.off+part.n {
			// The part holds more than this piece put there: someone else
			// wrote it too. On from what it holds.
			s.reset(have)
		} else {
			s.mu.Lock()
			s.have = have
			s.changedLocked()
			s.mu.Unlock()
		}
		j.moved()
		if dt := time.Since(accAt); dt >= 500*time.Millisecond || have >= it.S {
			j.progress(i, have, acc, dt)
			acc, accAt = 0, time.Now()
		} else {
			j.progress(i, have, 0, 0)
		}
	}
	icancel()
	wg.Wait()
	// Every byte is in the part. A job stopped meanwhile, or one whose key
	// was unpinned, leaves it there, a part: the file is not named.
	if code := j.still(); code != "" {
		stopPut()
		return code
	}
	db, code := filesPutDone(j.pub, tok, it.M, j.rec.Mode)
	if code == "no-put" {
		// Ended between the last piece and now: found again, whole.
		if p, tok, have, code = j.put(it); code != "" {
			return code
		}
		if have != it.S {
			stopPut()
			return "unavailable"
		}
		db, code = filesPutDone(j.pub, tok, it.M, j.rec.Mode)
	}
	if code != "" {
		if p != nil {
			stopPut()
		}
		return code
	}
	j.f.mu.Lock()
	j.f.rec.Items[i].St, j.f.rec.Items[i].Got, j.f.rec.Items[i].Path, j.f.rec.Items[i].Err = "done", it.S, db.Path, ""
	j.f.mu.Unlock()
	fetchSave()
	return ""
}

// grantDone ends the grant on A: the job needs it no more. Best effort;
// it runs out on its own.
func (j *fetchJob) grantDone() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, hc := j.roads.pick(); hc != nil {
		grantPost(ctx, hc, "/v1/files/grant/done", grantReq{ID: j.rec.Grant}, nil)
	}
}
