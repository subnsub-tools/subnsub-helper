package main

/* ── measuring the road to another computer ──

   The Speed tab measures the road between two of the person's computers by
   asking one of them (B) to measure it: the bytes go between the two
   helpers, over the road a copy between them takes (filesfetch.go) — the
   tailnet where A has a listener there and B is on one, else tailcat,
   direct where the two can reach each other and through DERP where they
   cannot — and the page only asks how it went. A browser in between would
   measure itself.

     speed-key     B makes a tailcat node key for one measurement and
                   answers its public half. The private half stays here, in
                   memory: a measurement is over in a minute, and one cut
                   off by a restart is simply asked for again.
     (the page signs a grant with caps "speed" for that key and sends it
      to A: filesgrant.go; A then lets it reach speed.go's three paths)
     speed-run     the measurement: which machine (agent id, tailcat
                   address, its tailnet listener), the grant's id, how many
                   seconds each way. Answered at once.
     speed-status  how it stands: the phase, the round trip and its jitter,
                   each direction's rate, the rate right now, the road.
     speed-stop    stopped, or a finished one forgotten.
     speed-net     the road from here to the internet instead, measured
                   against Cloudflare's speed test (speednet.go); read and
                   stopped with the same two.

   WHO MAY is files' own gate (runFilesCommand): a pinned key, the console,
   the tunnel alone. A measurement is bound to the key that signed it and
   stops when that key is unpinned. One runs at a time here: two at once
   would each measure half the road. */

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	// Measurements kept, finished ones included.
	speedJobsKeep = 8
	// A key nobody went on to measure with is forgotten after this.
	speedKeyWait = 10 * time.Minute
	// A finished measurement is kept this long for the page to read.
	speedDoneKeep = 30 * time.Minute
	// Seconds each way, unless the page asks otherwise, and the bounds.
	speedSecsDefault = 8
	speedSecsMin     = 3
	speedSecsMax     = 20
	// Streams at once each way: one TCP connection rarely fills a road
	// with any distance in it.
	speedStreams = 4
	// Round trips for the latency, the first two of them not counted (a
	// connection being made, a path being found).
	speedPings     = 12
	speedPingsSkip = 2
	// How often the rate right now is read.
	speedTick = 250 * time.Millisecond
	// How long A may take to answer at all: a tailcat dial through DERP
	// takes seconds before the first byte.
	speedDialWait = 45 * time.Second
	// An upload piece: sized to take about half a second, between these.
	speedPieceMin = 64 << 10
	speedPieceMax = 4 << 20
	// How long the path is given to go direct before the clock starts.
	speedRouteWait = 3 * time.Second
)

// speedSecond is a second of measuring, and the first one of each direction
// is not counted: TCP is still finding out how fast it may go. A test makes
// it shorter.
var speedSecond = time.Second

// speedJob is one measurement.
type speedJob struct {
	mu     sync.Mutex
	job    string
	by     string // the pinned key that signed it, base64
	signer ed25519.PublicKey
	priv   key.NodePrivate
	pub    string
	from   fetchFrom
	grant  string
	secs   int
	st     string // key | dial | ping | down | up | done | err | stopped
	err    string
	road   string // tailnet | tailcat
	route  string // tailnet | direct | derp
	ping   float64
	jit    float64
	down   float64 // bits a second
	up     float64
	live   float64
	phase  time.Time
	at     time.Time
	end    time.Time
	cancel context.CancelFunc
	// A measurement to the internet (speednet.go): no key, no grant, no
	// other machine; the edge that answered, the country it puts this
	// machine in, the round trip under load each way, and the TCP
	// connection as Cloudflare's end saw it.
	net   bool
	colo  string
	cc    string
	dlLat float64
	dlJit float64
	ulLat float64
	ulJit float64
	tcp   *speedTCP
}

// speedView is a measurement as speed-status tells it.
type speedView struct {
	Job   string  `json:"job"`
	St    string  `json:"st"`
	Err   string  `json:"err,omitempty"`
	Road  string  `json:"road,omitempty"`
	Route string  `json:"route,omitempty"`
	Ping  float64 `json:"ping,omitempty"`
	Jit   float64 `json:"jit,omitempty"`
	Down  float64 `json:"down,omitempty"`
	Up    float64 `json:"up,omitempty"`
	Live  float64 `json:"live,omitempty"`
	Secs  int     `json:"secs"`
	T     int64   `json:"t"` // ms into the phase
	At    int64   `json:"at"`
	// speed-net's alone.
	Net   bool      `json:"net,omitempty"`
	Colo  string    `json:"colo,omitempty"`
	Cc    string    `json:"cc,omitempty"`
	DlLat float64   `json:"dlLat,omitempty"`
	DlJit float64   `json:"dlJit,omitempty"`
	UlLat float64   `json:"ulLat,omitempty"`
	UlJit float64   `json:"ulJit,omitempty"`
	TCP   *speedTCP `json:"tcp,omitempty"`
}

var speedJobs = struct {
	sync.Mutex
	m map[string]*speedJob
}{m: map[string]*speedJob{}}

func speedFinished(st string) bool { return st == "done" || st == "err" || st == "stopped" }

// speedSweepLocked forgets keys nobody used and measurements long over.
func speedSweepLocked(now time.Time) {
	for id, j := range speedJobs.m {
		j.mu.Lock()
		st, at, end := j.st, j.at, j.end
		j.mu.Unlock()
		if (st == "key" && now.Sub(at) > speedKeyWait) || (speedFinished(st) && now.Sub(end) > speedDoneKeep) {
			delete(speedJobs.m, id)
		}
	}
}

// speedRoomLocked makes room for one more, the oldest finished going
// first; false when every one kept is still wanted.
func speedRoomLocked() bool {
	for len(speedJobs.m) >= speedJobsKeep {
		oldest, when := "", time.Time{}
		for id, j := range speedJobs.m {
			j.mu.Lock()
			st, at := j.st, j.at
			j.mu.Unlock()
			if (speedFinished(st) || st == "key") && (oldest == "" || at.Before(when)) {
				oldest, when = id, at
			}
		}
		if oldest == "" {
			return false
		}
		delete(speedJobs.m, oldest)
	}
	return true
}

func (j *speedJob) view() speedView {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := speedView{Job: j.job, St: j.st, Err: j.err, Road: j.road, Route: j.route, Ping: j.ping, Jit: j.jit,
		Down: j.down, Up: j.up, Secs: j.secs, At: j.at.Unix(),
		Net: j.net, Colo: j.colo, Cc: j.cc, DlLat: j.dlLat, DlJit: j.dlJit, UlLat: j.ulLat, UlJit: j.ulJit, TCP: j.tcp}
	if j.st == "down" || j.st == "up" {
		v.Live = j.live
	}
	if !j.phase.IsZero() && !speedFinished(j.st) {
		v.T = time.Since(j.phase).Milliseconds()
	}
	return v
}

func (j *speedJob) set(f func(j *speedJob)) {
	j.mu.Lock()
	f(j)
	j.mu.Unlock()
}

// runSpeedCommand is B's four commands. The caller (runFilesCommand) has
// checked the pin, the console and the tunnel; signer is the pinned key that
// signed this one.
func runSpeedCommand(op string, signer ed25519.PublicKey, a filesArgs) (any, string) {
	if len(signer) == 0 {
		return nil, "not-allowed"
	}
	by := base64.StdEncoding.EncodeToString(signer)
	now := time.Now()
	if !filesPutKRe.MatchString(a.Job) {
		return nil, "bad-args"
	}
	speedJobs.Lock()
	defer speedJobs.Unlock()
	speedSweepLocked(now)
	j := speedJobs.m[a.Job]
	switch op {
	case "speed-key":
		if j != nil {
			j.mu.Lock()
			st, jby, pub := j.st, j.by, j.pub
			j.mu.Unlock()
			if st == "key" && jby == by {
				return map[string]any{"pub": pub}, ""
			}
			return nil, "busy"
		}
		if !speedRoomLocked() {
			return nil, "busy"
		}
		node := key.NewNode()
		pub, err := node.Public().MarshalText()
		if err != nil {
			return nil, "unavailable"
		}
		speedJobs.m[a.Job] = &speedJob{job: a.Job, by: by, signer: signer, priv: node, pub: string(pub), st: "key", at: now}
		return map[string]any{"pub": string(pub)}, ""

	case "speed-run":
		if j == nil {
			return nil, "no-job"
		}
		tn := fetchTnArg(a.From.Tn)
		if !cloneAgentRe.MatchString(a.From.Agent) || !cloneIDRe.MatchString(a.Grant) ||
			(a.From.Addr == "" && tn == nil) || (a.From.Addr != "" && (len(a.From.Addr) > fetchAddrMax || !fetchAddrRe.MatchString(a.From.Addr))) {
			return nil, "bad-args"
		}
		if a.From.Agent == fetchSelf() {
			return nil, "bad-args"
		}
		if speedBusyLocked(j) {
			return nil, "busy"
		}
		secs := speedSecsOf(a.Secs)
		j.mu.Lock()
		if j.st != "key" || j.by != by {
			j.mu.Unlock()
			return nil, "busy"
		}
		ctx, cancel := context.WithCancel(context.Background())
		j.from, j.grant, j.secs = fetchFrom{Agent: a.From.Agent, Addr: a.From.Addr, Tn: tn}, a.Grant, secs
		j.st, j.at, j.phase, j.cancel = "dial", now, now, cancel
		j.mu.Unlock()
		go j.run(ctx)
		return map[string]any{"job": a.Job}, ""

	case "speed-net":
		// A job id is used once: the page makes a new one for each run.
		if j != nil || speedBusyLocked(nil) || !speedRoomLocked() {
			return nil, "busy"
		}
		ctx, cancel := context.WithCancel(context.Background())
		j = &speedJob{job: a.Job, by: by, signer: signer, net: true, secs: speedSecsOf(a.Secs),
			st: "dial", at: now, phase: now, cancel: cancel}
		speedJobs.m[a.Job] = j
		go j.run(ctx)
		return map[string]any{"job": a.Job}, ""

	case "speed-status":
		if j == nil {
			return nil, "no-job"
		}
		v := j.view()
		if v.St == "key" {
			return nil, "no-job"
		}
		return v, ""

	case "speed-stop":
		if j == nil {
			return map[string]any{}, ""
		}
		j.mu.Lock()
		st, cancel := j.st, j.cancel
		j.mu.Unlock()
		switch {
		case speedFinished(st) || st == "key":
			if a.Forget || st == "key" {
				delete(speedJobs.m, a.Job)
			}
		case cancel != nil:
			cancel()
		}
		return map[string]any{}, ""
	}
	return nil, "unknown-op"
}

// speedBusyLocked: a measurement other than this one is under way here.
func speedBusyLocked(j *speedJob) bool {
	for _, o := range speedJobs.m {
		o.mu.Lock()
		st := o.st
		o.mu.Unlock()
		if o != j && st != "key" && !speedFinished(st) {
			return true
		}
	}
	return false
}

// speedSecsOf is the seconds each way a page asked for, within bounds.
func speedSecsOf(secs int) int {
	if secs == 0 {
		secs = speedSecsDefault
	}
	return max(speedSecsMin, min(secs, speedSecsMax))
}

// speedDialA is the road to A for a measurement: the tailnet first, where A
// has a listener there and this machine is on a tailnet, else tailcat.
// Variables, so a test puts its own roads in their place.
var speedDialA = func(ctx context.Context, from fetchFrom, priv key.NodePrivate) (fetchRoad, string) {
	if from.Tn != nil {
		if rd := fetchDialTn(ctx, from.Tn, from.Agent, priv); rd != nil {
			return rd, "tailnet"
		}
	}
	if from.Addr == "" {
		return nil, ""
	}
	return fetchDial(from.Addr, priv), "tailcat"
}

func (j *speedJob) run(ctx context.Context) {
	work := j.work
	if j.net {
		work = j.workNet
	}
	st, why := work(ctx)
	j.mu.Lock()
	if ctx.Err() != nil && st != "done" {
		st, why = "stopped", ""
	}
	j.st, j.err, j.end, j.live = st, why, time.Now(), 0
	j.cancel = nil
	j.mu.Unlock()
}

// still is what a measurement may not go on without.
func (j *speedJob) still(ctx context.Context) string {
	if ctx.Err() != nil {
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

func (j *speedJob) work(ctx context.Context) (string, string) {
	j.mu.Lock()
	from, priv, grant, secs := j.from, j.priv, j.grant, j.secs
	j.mu.Unlock()
	rd, road := speedDialA(ctx, from, priv)
	if rd == nil {
		return "err", "unreachable"
	}
	defer rd.Close()
	hc := rd.HTTP()
	// Whatever happens next, the grant ends with the measurement.
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		grantPost(dctx, hc, "/v1/files/grant/done", grantReq{ID: grant}, nil)
	}()
	j.set(func(j *speedJob) { j.road = road })

	// A, as the page named it. Through DERP the first answer takes a while.
	deadline := time.Now().Add(speedDialWait)
	for {
		if code := j.still(ctx); code != "" {
			return "err", code
		}
		code := speedHello(ctx, hc, from.Agent)
		if code == "" {
			break
		}
		if code != "unreachable" || time.Now().After(deadline) {
			return "err", code
		}
		select {
		case <-ctx.Done():
			return "err", "stopped"
		case <-time.After(time.Second):
		}
	}

	// The path: given a moment to go direct, since the first packets of a
	// tailcat road go through DERP while the two look for each other.
	routeOf := func() {
		if rt := rd.Route(ctx); rt != "" {
			j.set(func(j *speedJob) { j.route = rt })
		}
	}
	if road == "tailcat" {
		until := time.Now().Add(speedRouteWait)
		for {
			routeOf()
			j.mu.Lock()
			rt := j.route
			j.mu.Unlock()
			if rt == "direct" || time.Now().After(until) || ctx.Err() != nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	} else {
		routeOf()
	}

	// The round trip.
	j.set(func(j *speedJob) { j.st, j.phase = "ping", time.Now() })
	var rtts []float64
	for i := 0; i < speedPings; i++ {
		if code := j.still(ctx); code != "" {
			return "err", code
		}
		ms, code := speedPingOnce(ctx, hc)
		if code != "" {
			return "err", code
		}
		if i >= speedPingsSkip {
			rtts = append(rtts, ms)
		}
	}
	p, jit := speedLatency(rtts)
	j.set(func(j *speedJob) { j.ping, j.jit = p, jit })

	// Down, then up.
	dur := time.Duration(secs) * speedSecond
	j.set(func(j *speedJob) { j.st, j.phase = "down", time.Now() })
	down, code := j.measure(ctx, dur, func(c context.Context, stop time.Time, m *speedMeter) string {
		c, cancel := context.WithDeadline(c, stop)
		defer cancel()
		return speedDownStream(c, hc, m)
	})
	if code != "" {
		return "err", code
	}
	j.set(func(j *speedJob) { j.down, j.live = down, 0 })
	if road == "tailcat" {
		routeOf()
	}
	if code := j.still(ctx); code != "" {
		return "err", code
	}
	piece := int64(speedPieceMax)
	if road == "tailnet" {
		// What the tailnet road's client seals in one question
		// (fetchtailnet.go).
		piece = tailnetMaxFirst
	}
	rtt := time.Duration(p * float64(time.Millisecond))
	j.set(func(j *speedJob) { j.st, j.phase = "up", time.Now() })
	up, code := j.measure(ctx, dur, func(c context.Context, stop time.Time, m *speedMeter) string {
		return speedUpStream(c, stop, hc, m, piece, rtt)
	})
	if code != "" {
		return "err", code
	}
	j.set(func(j *speedJob) { j.up = up })
	if road == "tailcat" {
		routeOf()
	}
	return "done", ""
}

// speedMeter counts one direction's bytes: every one (for the rate right
// now), and the share of them that moved after the first second (for the
// result). A piece counted when it lands is spread over the time it was
// under way, so one begun before the first second ended and landing after
// it is not credited to the second whole.
type speedMeter struct {
	t0, warm time.Time
	got      atomic.Int64
	part     atomic.Int64
}

// arrived is n bytes that came in just now, a stream read at a time.
func (m *speedMeter) arrived(n int64) {
	m.got.Add(n)
	if !time.Now().Before(m.warm) {
		m.part.Add(n)
	}
}

// piece is n bytes that were under way from s and landed at e.
func (m *speedMeter) piece(s, e time.Time, n int64) {
	m.got.Add(n)
	from := s
	if m.warm.After(from) {
		from = m.warm
	}
	switch {
	case !e.After(s):
		if !e.Before(m.warm) {
			m.part.Add(n)
		}
	case e.After(from):
		m.part.Add(int64(float64(n) * float64(e.Sub(from)) / float64(e.Sub(s))))
	}
}

// measure runs speedStreams streams until dur is up (an upload's pieces
// under way then are let in, and the clock waits for them), reading the
// rate right now as it goes, and answers the rate over all but the first
// second.
func (j *speedJob) measure(ctx context.Context, dur time.Duration, stream func(context.Context, time.Time, *speedMeter) string) (float64, string) {
	t0 := time.Now()
	stop := t0.Add(dur)
	m := &speedMeter{t0: t0, warm: t0.Add(speedSecond)}
	// The last pieces' grace.
	sctx, cancel := context.WithDeadline(ctx, stop.Add(15*time.Second))
	defer cancel()
	var wg sync.WaitGroup
	codes := make([]string, speedStreams)
	for i := 0; i < speedStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = stream(sctx, stop, m)
		}(i)
	}
	last, lastGot := t0, int64(0)
	tick := time.NewTicker(speedTick)
	defer tick.Stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		select {
		case <-done:
			end := time.Now()
			total := m.got.Load()
			if ctx.Err() != nil {
				return 0, "stopped"
			}
			if code := j.still(ctx); code != "" {
				return 0, code
			}
			// A stream ends quietly only at the seconds' end (or the
			// grace's): one that broke off before says why, and the bytes
			// that came first are not a measurement.
			for _, c := range codes {
				if c != "" {
					return 0, c
				}
			}
			if total == 0 {
				return 0, "unreachable"
			}
			if end.Sub(m.warm) > speedSecond/2 && m.part.Load() > 0 {
				return float64(m.part.Load()) * 8 / end.Sub(m.warm).Seconds(), ""
			}
			return float64(total) * 8 / end.Sub(t0).Seconds(), ""
		case now := <-tick.C:
			g := m.got.Load()
			rate := float64(g-lastGot) * 8 / now.Sub(last).Seconds()
			last, lastGot = now, g
			j.set(func(j *speedJob) {
				// Eased, so the number can be read as it moves.
				if j.live == 0 {
					j.live = rate
				} else {
					j.live = j.live*0.6 + rate*0.4
				}
			})
		}
	}
}

// speedHello makes sure the machine that answers is the one the page named.
func speedHello(ctx context.Context, hc *http.Client, agent string) string {
	c, cancel := context.WithTimeout(ctx, speedDialWait)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, "http://tailcat/v1/hello", nil)
	if err != nil {
		return "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "stopped"
		}
		return "unreachable"
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "unreachable"
	}
	if resp.StatusCode != http.StatusOK {
		if code := frameCode(b, resp.StatusCode); code != "not-allowed" {
			return code
		}
		return "grant-gone"
	}
	fr, err := transport.Decode(b)
	if err != nil || fr.Type != transport.TypeHello {
		return "bad-frame"
	}
	if fr.AgentID != agent {
		return "wrong-machine"
	}
	return ""
}

func speedPingOnce(ctx context.Context, hc *http.Client) (float64, string) {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, "http://tailcat/v1/speed/ping", nil)
	if err != nil {
		return 0, "unavailable"
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, "stopped"
		}
		return 0, "unreachable"
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	ms := float64(time.Since(t0).Microseconds()) / 1000
	if resp.StatusCode != http.StatusOK {
		return 0, speedCode(b, resp.StatusCode)
	}
	return ms, ""
}

// speedCode is why A said no: an A from before the Speed tab answers its
// paths not-allowed (a grant's door) or unknown-frame.
func speedCode(b []byte, status int) string {
	switch code := frameCode(b, status); code {
	case "not-allowed":
		return "grant-gone"
	case "unknown-frame", "status-404":
		return "unsupported"
	default:
		return code
	}
}

// speedLatency is the middle of the round trips and how much one differs
// from the next, on average.
func speedLatency(ms []float64) (float64, float64) {
	if len(ms) == 0 {
		return 0, 0
	}
	var jit float64
	for i := 1; i < len(ms); i++ {
		d := ms[i] - ms[i-1]
		if d < 0 {
			d = -d
		}
		jit += d
	}
	if len(ms) > 1 {
		jit /= float64(len(ms) - 1)
	}
	s := append([]float64{}, ms...)
	sort.Float64s(s)
	mid := s[len(s)/2]
	if len(s)%2 == 0 {
		mid = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return mid, jit
}

// speedBusyWait is how long a stream waits when A has no stream to spare:
// the ones the last direction left behind are still noticing they were hung
// up on.
const speedBusyWait = 150 * time.Millisecond

// speedDownStream reads one download until its context ends: another when
// one comes to its end first.
func speedDownStream(ctx context.Context, hc *http.Client, m *speedMeter) string {
	for {
		code := speedDownOnce(ctx, hc, m)
		if ctx.Err() != nil {
			return ""
		}
		if code == "more" {
			continue
		}
		if code != "busy" {
			return code
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(speedBusyWait):
		}
	}
}

func speedDownOnce(ctx context.Context, hc *http.Client, m *speedMeter) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://tailcat/v1/speed/down?n="+strconv.FormatInt(speedDownMax, 10), nil)
	if err != nil {
		return "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ""
		}
		return "unreachable"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return speedCode(b, resp.StatusCode)
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			m.arrived(int64(n))
		}
		switch {
		case err == nil:
		case ctx.Err() != nil:
			// The seconds are up: hung up on purpose.
			return ""
		case errors.Is(err, io.EOF):
			return "more"
		default:
			return "unreachable"
		}
	}
}

// speedUpStream sends pieces until stop, each counted when A says it has
// it, each sized by speedNextPiece.
func speedUpStream(ctx context.Context, stop time.Time, hc *http.Client, m *speedMeter, most int64, rtt time.Duration) string {
	size := int64(speedPieceMin)
	buf := speedBuf()
	for ctx.Err() == nil && time.Now().Before(stop) {
		body := make([]byte, 0, size)
		for int64(len(body)) < size {
			body = append(body, buf[:min(int64(len(buf)), size-int64(len(body)))]...)
		}
		t0 := time.Now()
		n, code := speedUpOnce(ctx, hc, body)
		if code == "busy" && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(speedBusyWait):
			}
			continue
		}
		if code != "" {
			if ctx.Err() != nil {
				return ""
			}
			return code
		}
		m.piece(t0, time.Now(), n)
		size = speedNextPiece(size, time.Since(t0), rtt, most)
	}
	return ""
}

// speedNextPiece sizes the next upload piece from how long the last one
// took: doubled while its bytes took under a quarter of a second, halved
// once they took over a second. A piece's time less the idle round trip is
// what its bytes took — the answer it waits for is a round trip of nothing
// moving — and the bounds grow with the round trip, so that on a far road
// the wait stays a small share of each piece instead of the ceiling on the
// rate.
func speedNextPiece(size int64, took, rtt time.Duration, most int64) int64 {
	moving := took - rtt
	switch {
	case moving < max(250*time.Millisecond, 2*rtt) && size < most:
		return min(size*2, most)
	case moving > max(time.Second, 4*rtt) && size > speedPieceMin:
		return max(size/2, speedPieceMin)
	}
	return size
}

func speedUpOnce(ctx context.Context, hc *http.Client, body []byte) (int64, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://tailcat/v1/speed/up?n="+strconv.Itoa(len(body)), bytes.NewReader(body))
	if err != nil {
		return 0, "unavailable"
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "unreachable"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return 0, speedCode(b, resp.StatusCode)
	}
	var out struct {
		N int64 `json:"n"`
	}
	if json.Unmarshal(b, &out) != nil || out.N != int64(len(body)) {
		return 0, "bad-frame"
	}
	return out.N, ""
}
