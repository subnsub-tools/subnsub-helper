package main

// Two ways to get readings out: a local listener for the demo page, and the
// outbound push that makes watching a remote machine possible.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pages allowed to read from the local listener. A wide-open localhost port
// would let ANY page you happen to visit read your plan and quota.
var allowedOrigins = map[string]bool{
	"http://localhost:8124":     true,
	"http://127.0.0.1:8124":     true,
	"http://localhost:8125":     true,
	"http://127.0.0.1:8125":     true,
	"https://www.200000.live":   true,
	"https://200000.live":       true,
	"https://tools.subnsub.com": true,
	"https://tool.subnsub.com":  true,
}

// Concurrent /events streams, and why /events is stricter than /quota: a
// request with no Origin cannot READ the response cross-origin, but it can
// still hold a stream open, and enough of them starve the real page. /quota
// stays open to curl for debugging — it answers and hangs up.
const maxStreams = 8

var streams struct {
	sync.Mutex
	n int
}

func serve(port int) {
	mux := http.NewServeMux()

	mux.HandleFunc("/quota", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !allowedOrigins[origin] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		cors(w, origin)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(dump(collectAll()))
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if !allowedOrigins[origin] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		streams.Lock()
		if streams.n >= maxStreams {
			streams.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		streams.n++
		streams.Unlock()
		defer func() { streams.Lock(); streams.n--; streams.Unlock() }()

		cors(w, origin)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)

		/* A client that stops reading would otherwise block Fprintf forever,
		   holding a stream slot for good. A blanket WriteTimeout on the server
		   cannot express this — it would also kill healthy long-lived streams —
		   so the deadline is refreshed per write instead. */
		rc := http.NewResponseController(w)
		for {
			// Collect first, then arm the deadline: it bounds the WRITE, and
			// a collection that runs a vendor's CLI (kiro-cli 30 s, agy 45 s)
			// would otherwise spend the window before the first byte went out
			// and close a healthy stream (direct.go's
			// stream already orders it this way).
			body := dump(collectAll())
			if err := rc.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", body); err != nil {
				return // client went away or stopped reading
			}
			if err := rc.Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	})

	// 127.0.0.1, never 0.0.0.0 — this must not be reachable from the network.
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	warnf("subnsub-helper serving on http://%s  (/quota, /events)", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// No WriteTimeout: /events is a long-lived stream and a global write
		// deadline would cut it off. That handler sets its own per-write
		// deadline instead.
		IdleTimeout: 60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		warnf("listener stopped: %v", err)
	}
}

func cors(w http.ResponseWriter, origin string) {
	if allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
}

// The push interval is FIXED at 30 s and is not a setting. `connect` takes no interval
// any more, no environment variable reads one, and the relay enforces the
// same floor on its side (a push inside 25 s of the
// last accepted one is answered 429 with Retry-After, and the loop below
// sleeps exactly that), so a rebuilt helper gains nothing by trying.
// Everything else the helper says to the relay already rides
// this push or its answer: the console polls only when the answer says the
// mailbox has something (hint.go), sessions sync sends nothing when nothing
// is new, and the version check is hourly.
//
// minInterval / maxInterval still bound `watch`, the local printer, which
// talks to nobody.
const (
	defaultInterval = 30.0
	minInterval     = 5.0
	maxInterval     = 60.0
	// The least time between two SENDS, whatever the period arithmetic says:
	// just under the period less its jitter, and over the relay's 25 s floor
	// with the network's variance to spare.
	minSendGap = 28 * time.Second
	// A dual-stack machine ordinarily lets Go choose between A and AAAA. That
	// is the right default for generic HTTP, but this particular connection is
	// also how the relay observes the machine's egress address. Give IPv4 a
	// short first attempt so the dashboard gets the useful NAT/public-v4
	// address when the machine has one, then fall back to the ordinary dual-
	// stack dial rather than taking an IPv6-only machine offline.
	relayIPv4Timeout = 3 * time.Second
)

// Wrap a dial function with the relay's address-family preference. Kept at
// the dial boundary — rather than asking a third-party "what is my IP" service
// and putting its answer in the payload — so the address remains an observation
// made by the relay, not a claim made by the helper. (The machine's IPv4 is the
// one exception, reported beside it as public_ipv4 for when this preference
// cannot work: see ipv4.go.)
func ipv4FirstDialContext(
	dial func(context.Context, string, string) (net.Conn, error),
	timeout time.Duration,
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// http.Transport asks for "tcp". Preserve an explicit tcp4/tcp6 (and
		// any non-TCP caller) rather than changing a choice already made above
		// this layer.
		if network != "tcp" {
			return dial(ctx, network, address)
		}

		v4ctx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dial(v4ctx, "tcp4", address)
		cancel()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return dial(ctx, network, address)
	}
}

func relayTransport() *http.Transport {
	// Clone the standard transport instead of constructing a partial one: its
	// proxy support, HTTP/2 settings, pooling and timeouts should stay exactly
	// as Go ships them. Only address-family selection is special here.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = ipv4FirstDialContext(transport.DialContext, relayIPv4Timeout)
	return transport
}

// Dial out and push readings, forever.
//
// This is the shape that matters: the machine you want to watch is usually one
// you cannot reach — behind NAT, behind a cloud firewall, on a laptop that
// moves. Nothing here listens; it only makes outbound HTTPS, which is the one
// thing that works everywhere.
func connect(base, token string) {
	every := defaultInterval
	url := strings.TrimRight(base, "/") + "/push"
	// The token is not fixed for the life of the process: it expires, and it is
	// traded for a fresh one before it does. See renew.go for why that happens
	// against the site rather than against the relay, and why renewal never
	// trusts anything a relay answers. The push response — once discarded
	// unread by everyone — is now read on every machine, under the rule and
	// the bound in hint.go: two bits, whether to poll for work (acted on
	// only where an instruction switch is on) and whether this machine is
	// watched and set to refresh its quota on its own (pace.go, every
	// machine).
	renew := newRenewer(base)
	// The console runs beside this loop, not inside it: a held poll must never
	// delay a reading, and a command that takes 30 seconds must not make the
	// machine look silent for 30 seconds. It shares the token through a box
	// rather than a copy, because renewal rotates that string underneath it.
	tok := &tokenBox{}
	tok.set(token)
	// The account keys on every reading are HMACs under this token's account
	// part (accountkey.go) — seeded once, because a renewal keeps that part.
	setAccountRoom(token)
	// The channel back: each push response may say whether /commands has
	// anything, and the console loop stretches its idle timer when the relay
	// has taken over the pacing. Written by this loop, read by that one.
	hints := newHintBox()
	go consoleLoop(base, tok, hints)
	// And the archive, on its own clock for the same reason: a backfill that
	// takes ten minutes must not delay a single reading, and a relay that is
	// refusing chunks must not be able to make this machine look silent. It
	// checks its own switch on every pass and does nothing at all while that
	// switch is off, which is every install until an operator says otherwise.
	go syncLoop(base, tok)
	// And the update timer, which does nothing at all until an operator has
	// turned on both remote updates and autoupdate at the machine
	// (update.go), and re-reads both switches on every pass.
	startAutoUpdate()
	// And the direct tunnel, when this machine's operator switched it on:
	// independent of the push in every way — its own clock, its own peers,
	// its own switch — so a tunnel that misbehaves can cost nothing but its
	// own watchers. It is also the console's only road (console.go): commands
	// ride it from a pinned browser, never the relay's mailbox.
	// MON_TRANSPORT=relay keeps it down for a run without touching the switch
	// (see direct.go), and with it the console.
	if directEnabled() {
		ensureDirect()
	}
	// Started before the first collection, so no push ever measures the system
	// for itself — the first one to do that would take the baseline every
	// subsequent sample's delta is measured against (see sampler.go).
	startSysSampler()
	startProbes()
	startCustom()
	startSpaces(base, tok)
	startIPv4()
	// And the reach record's probe (reach.go): idle until a push fails.
	go reachLoop()
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: relayTransport(),
		// Refuse redirects here too. The relay token is a bearer secret — it
		// can push readings and read them — and Go's default client keeps
		// Authorization across a redirect to the same domain or a subdomain,
		// judging by host alone without checking the scheme. So an https→http
		// hop on the same host would put the token on the wire in clear. The
		// Claude collector already refuses; this path is no different.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	fails := 0
	// When the previous push was SENT. The period is measured from the start
	// of a round (below), which keeps the cadence at `every` whatever the
	// collection costs — but it also means two sends can land closer than
	// `every` when one round's collection was slow and the next's was
	// instant (10 s of collecting, then a cached round,
	// is a 20 s gap on the wire). The relay's floor (25 s) judges arrivals,
	// so sends keep a floor of their own, just under the period.
	var lastSent time.Time

	for {
		// The period is measured from HERE, so collecting and sending are
		// inside it rather than added to it: a sleep of `every` after a push
		// that took eight seconds to collect made the real cadence `every`
		// plus eight, and the relay's offline line (90 s) and the presence
		// threshold (100 s) are set against the cadence, not the sleep.
		started := time.Now()
		// Before the push, not after: a token that expires between two pushes
		// would otherwise cost a failed report and a card that goes silent for
		// an interval, for a renewal that was already due.
		if renew.due(token, time.Now(), false) {
			token = renew.attempt(token, time.Now())
			tok.set(token)
		}

		body := dump(pushBody())
		if !lastSent.IsZero() {
			if gap := minSendGap - time.Since(lastSent); gap > 0 {
				time.Sleep(gap)
			}
		}
		lastSent = time.Now()
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			warnf("cannot build request")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		// Bearer, not a query parameter: a token in the URL ends up in the
		// relay's request logs and every proxy in between.
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "subnsub-helper")

		wait := every
		// A wait the relay dictated (Retry-After) counts from the response,
		// not from the start of the round: the subtraction below is for the
		// period, and taking this round's collection off a relay's number
		// would land the retry inside the same floor.
		fixedWait := false
		resp, err := client.Do(req)
		switch {
		case err != nil:
			fails++
			warnf("push failed")
			reachRelayLost(time.Now())
			// No response, no hint — and the backoff below stretches the gap
			// past a shell command's whole lifetime. If anything is waiting,
			// only a poll can find it now, so the console loop is woken on
			// every path that fails to deliver a hint (see hint.go).
			hints.wakeNow()
			wait = every * math.Min(math.Pow(2, float64(fails)), 10)
		case resp.StatusCode == 200:
			reachRelayHeard(time.Now())
			absorbHint(hints, resp.Body)
			if fails > 0 {
				warnf("reconnected")
			}
			fails = 0
			token = renew.afterPush(200, token, time.Now())
		case resp.StatusCode == 429:
			// The relay is pacing the ROOM, not rejecting us: several machines
			// share one, and two that started together collide.
			//
			// Backing off by whole multiples of a fixed cadence is exactly the
			// wrong answer here — the phase between two helpers never changes,
			// so the pair that collided once collides on every subsequent
			// round, forever. A short RANDOM wait is what breaks the lock:
			// after it, the two are no longer in step.
			// The relay may say how long: its per-machine floor answers with
			// the seconds left until the next push it will accept (Retry-After),
			// and sleeping exactly that costs one request instead of a retry
			// every few seconds until the floor passes. Bounded, because the
			// header is the relay's word and the push loop is the machine's
			// heartbeat: never longer than the offline line.
			retryAfter := 0.0
			if v, err := strconv.ParseFloat(strings.TrimSpace(resp.Header.Get("Retry-After")), 64); err == nil && v > 0 && v <= 60 {
				retryAfter = v
			}
			resp.Body.Close()
			warnf("relay is pacing us; retrying shortly")
			hints.wakeNow() // a paced push carried no hint either
			if retryAfter > 0 {
				wait = retryAfter + jitter()
				fixedWait = true
			} else {
				wait = 2 + 3*jitter()
			}
		default:
			// 4xx means this client is wrong (bad token, room not enabled) and
			// retrying at speed won't fix it. Back off rather than hammer.
			code := resp.StatusCode
			// 409 is the relay saying the ROOM is full of machines that are all
			// still reporting — nothing wrong with this client or its token, and
			// the operator's fix is on the dashboard (forget one) or in the
			// plan. The body says so in words; a bounded slice of it goes to
			// the log, because "push rejected: 409" alone sends somebody
			// reading it to the token first.
			if code == 409 {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
				resp.Body.Close()
				warnf("push rejected: %d (%s)", code, strings.Map(printableASCII, strings.TrimSpace(string(b))))
			} else {
				resp.Body.Close()
				warnf("push rejected: %d", code)
			}
			fails++
			reachRelayLost(time.Now())
			hints.wakeNow() // rejected pushes carry no hint; see the err case
			// 401/403 is the relay saying this token is not (or is no longer)
			// one it will take — the other moment worth asking the site for a
			// new one. What that means for the renewal state lives in
			// afterPush, so the tests exercise the same path this does.
			token = renew.afterPush(code, token, time.Now())
			wait = every * math.Min(math.Pow(2, float64(fails)), 10)
		}
		// Whatever the branch above did to the token, the console loop is
		// holding the old one until told. One line here rather than three
		// inside the switch: every path leaves through it.
		tok.set(token)
		// Spread the steady-state cadence too, by a few percent. Machines
		// installed in one sitting otherwise stay in lockstep for as long as
		// they run, and the collision that costs one of them a push is the same
		// collision every time.
		if wait == every {
			wait = every * (0.95 + 0.1*jitter())
		}
		// Less what this round already spent; never to zero (the relay's
		// per-machine gap is 2 s, and a hot loop is the one thing the sleep
		// must never become).
		if spent := time.Since(started).Seconds(); spent > 0 && !fixedWait {
			wait -= spent
		}
		if wait < 1 {
			wait = 1
		}
		// A refresh pressed on the page ends this sleep early (pushWake), so
		// the figures it asked for ride the next push now rather than up to
		// a minute later. One token, and only a sleep listens: a wake that
		// lands mid-push is banked and ends the following sleep at once.
		select {
		case <-pushWake:
		case <-time.After(time.Duration(wait * float64(time.Second))):
		}
	}
}

// pushWake ends the push loop's current sleep. Holds one token; see the
// select above.
var pushWake = make(chan struct{}, 1)

func wakePush() {
	select {
	case pushWake <- struct{}{}:
	default:
	}
}

// A float in [0,1), from the system CSPRNG.
//
// crypto/rand rather than math/rand because this binary already imports it for
// the token and the machine id, and pulling in a second generator to seed for
// scheduling noise buys nothing. A failure falls back to no jitter, which is
// the pre-jitter behaviour rather than a hang.
func jitter() float64 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return float64(uint16(b[0])<<8|uint16(b[1])) / 65536.0
}

// A usable number of seconds, whatever was passed in.
//
// math.Min/Max propagate NaN rather than rejecting it, and a NaN or negative
// duration makes time.Sleep return immediately — turning the push loop into a
// hot loop against the relay. Anything that is not a finite positive number
// falls back to the default.
func clampInterval(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return defaultInterval
	}
	if v < minInterval {
		return minInterval
	}
	if v > maxInterval {
		return maxInterval
	}
	return v
}

// printableASCII keeps a relay's error body fit for a log line: one line, no
// control characters, nothing that a terminal would interpret. Anything else
// is dropped rather than escaped — the words are what matter.
func printableASCII(r rune) rune {
	if r >= 0x20 && r <= 0x7e {
		return r
	}
	return -1
}

// Beacon is what the relay push shrinks to once this machine's tunnel is up
// (user 2026-09-01: a machine on the direct road must not hold a relay seat).
// Enough for a dashboard to find the road — the address — and to know what
// the machine will do and whether it takes a signed enrolment; no reading, no
// history, a few hundred bytes. The relay files it outside the room's seats.
type Beacon struct {
	Beacon        bool    `json:"beacon"`
	CapturedAt    float64 `json:"captured_at"`
	AgentID       string  `json:"agent_id,omitempty"`
	AgentLabel    string  `json:"agent_name,omitempty"`
	Rename        bool    `json:"rename"`
	HelperVersion string  `json:"helper_version,omitempty"`
	DirectAddr    string  `json:"direct_addr"`
	// The console's spare-road key (econ.go): carried here too, so a machine
	// whose own tunnel is up but whose WATCHER cannot reach it can still use
	// the sealed relay road.
	Econ        string `json:"econ,omitempty"`
	Console     bool   `json:"exec"`
	Update      bool   `json:"upd"`
	AutoUpdate  bool   `json:"auto"`
	Diagnostics bool   `json:"diag"`
	Signed      bool   `json:"sgn"`
	// Whether a pinned browser may press this machine's tiles (tileaction.go).
	Act bool `json:"act"`
	// Whether this machine takes the `myip` command (myip.go).
	MyIP bool `json:"myip"`
	// The other namespaces' exits ride the beacon too (spaces.go): on the
	// direct road the beacon is the only thing of this machine's the relay
	// sees, and the relay is what turns a stamp into an address.
	Spaces []Space `json:"spaces,omitempty"`
	// And the last rebuild (types.go Wiped): the relay's record of a wiped
	// machine must not depend on which road it came back on.
	Wiped []int64 `json:"wiped,omitempty"`
	// And the record's unacknowledged rows (types.go Outages): on the
	// direct road the relay is still the record's one durable home.
	Outages      []outageRow `json:"outages,omitempty"`
	OutagesSince int64       `json:"outages_since,omitempty"`
	// And the reach record's (types.go Reach).
	Reach []outageRow `json:"reach,omitempty"`
	// And the archive's newest closed five-minute buckets, without process
	// names (history.go historyCoarseClosed): the relay files them, so a
	// browser that cannot reach the tunnel still has a trend to draw.
	Hist []histRow `json:"hist,omitempty"`
	// And the machine's own IPv4 (ipv4.go), for the card the beacon makes
	// before the tunnel connects.
	PublicIPv4 string      `json:"public_ipv4,omitempty"`
	PublicCC   string      `json:"public_cc,omitempty"`
	UpdateNext int64       `json:"update_next,omitempty"`
	UpdateLast *updateLast `json:"update_last,omitempty"`
}

// beaconHistRows: how many closed five-minute buckets ride each beacon.
const beaconHistRows = 2

// beaconMode: whether a machine with its tunnel up sends the relay a beacon
// instead of the reading. On by default; MON_BEACON=off keeps the full push
// for a fleet that wants the relay's history too.
func beaconMode() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MON_BEACON"))) {
	case "0", "off", "false", "no":
		return false
	}
	return true
}

// pushBody is one relay push: the whole reading while the machine has no
// tunnel, the beacon once it does. The reading is collected either way — the
// collection is what records history and feeds the sampler.
func pushBody() any {
	snap := collectAll()
	// What this push carries of the outage record, for the answer that
	// acknowledges it (outages.go outageAcked), and of the reach record.
	outageSent(snap.Outages)
	reachSent(snap.Reach)
	if addr := directAddress(); addr != "" && beaconMode() {
		return Beacon{Beacon: true, CapturedAt: snap.CapturedAt, AgentID: snap.AgentID,
			AgentLabel: snap.AgentLabel, HelperVersion: helperVersion, DirectAddr: addr,
			Rename: snap.Rename, Econ: snap.Econ,
			Console: snap.Console, Update: snap.Update, AutoUpdate: snap.AutoUpdate, Diagnostics: snap.Diagnostics, Signed: snap.Signed, Act: snap.Act, MyIP: snap.MyIP,
			Spaces: snap.Spaces, Wiped: snap.Wiped, Outages: snap.Outages, OutagesSince: snap.OutagesSince, Reach: snap.Reach,
			Hist:       historyCoarseClosed(beaconHistRows),
			PublicIPv4: snap.PublicIPv4, PublicCC: snap.PublicCC,
			UpdateNext: snap.UpdateNext, UpdateLast: snap.UpdateLast}
	}
	return snap
}
