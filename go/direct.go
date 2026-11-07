package main

// Direct mode — a watcher's browser reaching this machine with no relay,
// no account and no server of ours in between.
//
// The page is a static display terminal, the bytes travel over a
// WireGuard tunnel bootstrapped through a DERP relay (transport/tailcat.go),
// and nothing about this machine is stored anywhere but here and in the
// watcher's own browser. What we do NOT do on this road, and say so on the
// page: see the data, promise an SLA, or carry the traffic.
//
// THE SWITCH IS A FILE, EXACTLY LIKE THE CONSOLE'S. `direct` exists in the
// config directory or it does not; nothing reads its contents. It is written
// by the installer when asked (--direct) or by `subnsub-helper direct on`,
// at the machine, by somebody who already has a shell here. The relay cannot
// flip it and neither can the page.
//
// WHO MAY WATCH IS A SECOND FILE, `allowed-clients`, one tailcat node public
// key per line — the same shape as trusted-keys, for the same reason: the
// list is appended by the installer (--allow) or `subnsub-helper allow`, and
// a key struck from it stops being served on its next request. With the list
// empty the tunnel does not start at all. An open tunnel is a lab, not a
// product.
//
// WHAT A WATCHER GETS BY BEING ALLOWED IS OBSERVE, AND ONLY OBSERVE: hello,
// one snapshot, a stream of snapshots and 1 Hz host health. The tunnel DOES
// also carry commands now — the console's shell lines and terminals travel
// this road and no other (console.go: a plain line is refused from the relay
// outright), and so may update, rename, inspect and the rest — but the
// `command` handler below takes them only from a machine that has PINNED a
// dashboard key (signing.go) and only under the same switches that gate the
// relay road, so "allowed to watch" never quietly becomes "allowed to
// command". A frame type this build
// does not know is refused by transport.Decode before it is looked at.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	// The file whose EXISTENCE turns direct mode on. Content is ignored.
	directFileName = "direct"
	// One tailcat node public key per line: the browsers allowed in.
	allowedClientsFile = "allowed-clients"
	// Where the running tunnel writes its address for `subnsub-helper
	// address` and the installer's closing message. 0600, like the token —
	// the address is a bearer capability for reaching this node.
	addressFileName = "address"
	// An alternate DERP map, for a self-hosted derper. https URL, one line.
	derpMapFileName = "derpmap"

	// Turning it on for one run without touching the filesystem — a test, a
	// container. Environment wins over the file, as with every other switch.
	directEnvVar = "MON_DIRECT"
	// The same for the DERP map.
	derpMapEnvVar = "MON_DERPMAP"
	// Which carriers run: "auto" (whatever is configured — the relay push
	// when there is a token, the tunnel when the switch is on, both when
	// both), "relay" (the push only, whatever the switch says) or "tailcat"
	// (the tunnel only, whatever the token says). auto is the default and
	// the other two are for forcing a fallback during the migration the
	// plan describes.
	transportEnvVar = "MON_TRANSPORT"

	// The one TCP port served inside the tunnel.
	directPort = 7770
	// Concurrent event streams per machine. Each costs one goroutine and
	// one write a second; the number is small because the page opens one
	// per watching tab and a fleet of tabs is not a use case this carries.
	directMaxStreams = 4
	// How often the stream re-sends the whole reading. Quota providers are
	// rate-limited upstream and a faster cadence buys nothing but load.
	directSnapshotEvery = 30 * time.Second
	// How often the stream sends the host-health block: the cadence the
	// page's dials are built for.
	directSystemEvery = time.Second
	// How long the loop waits between looks at the allowlist file.
	directAllowPoll = 10 * time.Second
	// A snapshot answered to one watcher is good for the next one this long:
	// the collectors shell out to a dozen CLIs, and two tabs must not double
	// that.
	directSnapshotCache = 10 * time.Second
)

// ── switches ───────────────────────────────────────────────────────────

func transportMode() string {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(transportEnvVar))); v {
	case "relay", "tailcat":
		return v
	}
	return "auto"
}

// directEnabled is consulted at startup and re-read by nothing: unlike the
// console, which polls a mailbox and can stop asking, a tunnel that is up
// stays up until the process restarts. Turning direct off is `direct off`
// and a restart, and the verb says so.
func directEnabled() bool {
	if v, ok := os.LookupEnv(directEnvVar); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "on", "true", "yes":
			return true
		}
		return false
	}
	dir := configDir()
	if dir == "" {
		return false
	}
	fi, err := os.Lstat(filepath.Join(dir, directFileName))
	return err == nil && fi.Mode().IsRegular()
}

func setDirect(on bool) error {
	dir := configDir()
	if dir == "" {
		return errString("no config directory")
	}
	path := filepath.Join(dir, directFileName)
	if !on {
		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func derpMapURL() string {
	if v := strings.TrimSpace(os.Getenv(derpMapEnvVar)); v != "" {
		if strings.HasPrefix(v, "https://") {
			return v
		}
		warnf("%s is not an https:// URL; ignoring it", derpMapEnvVar)
	}
	dir := configDir()
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, derpMapFileName))
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(b))
	if !strings.HasPrefix(v, "https://") {
		return ""
	}
	return v
}

// ── allowlist ──────────────────────────────────────────────────────────

func allowedClientsPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, allowedClientsFile)
}

// loadAllowedClients reads the list fresh every time. Read on every request
// rather than cached, because removing a key has to be the fast direction.
func loadAllowedClients() []key.NodePublic {
	path := allowedClientsPath()
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []key.NodePublic
	for _, line := range strings.Split(string(b), "\n") {
		if k, ok := transport.ParseNodeKey(line); ok {
			out = append(out, k)
		}
	}
	return out
}

func allowClient(line string) error {
	k, ok := transport.ParseNodeKey(line)
	if !ok {
		return errString("not a tailcat node key (nodekey:<64 hex>)")
	}
	path := allowedClientsPath()
	if path == "" {
		return errString("no config directory to write to")
	}
	for _, have := range loadAllowedClients() {
		if have == k {
			return nil // already allowed; saying so twice is not an error
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(k.String() + "\n")
	return err
}

func disallowClient(line string) error {
	want, ok := transport.ParseNodeKey(line)
	if !ok {
		return errString("not a tailcat node key (nodekey:<64 hex>)")
	}
	path := allowedClientsPath()
	if path == "" {
		return errString("no config directory")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var keep []string
	for _, l := range strings.Split(string(body), "\n") {
		if k, ok := transport.ParseNodeKey(l); ok && k == want {
			continue
		}
		if strings.TrimSpace(l) != "" {
			keep = append(keep, l)
		}
	}
	out := ""
	if len(keep) > 0 {
		out = strings.Join(keep, "\n") + "\n"
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ── the daemon side ────────────────────────────────────────────────────

// ── the tunnel as the rest of the process sees it ─────────────────────

var (
	directAddrMu sync.Mutex
	directAddr   string // the ConnBlob while the carrier is up, "" otherwise
	directOnce   sync.Once
	// What ensureDirect starts, once. A variable so a test of the `allow`
	// path can count starts instead of reaching a real DERP. Assigned in
	// init rather than here: runDirect → the tunnel's command route →
	// runAllow → ensureDirect → this, and Go refuses that cycle in a
	// package-level initialiser.
	startDirect func()
)

func init() {
	startDirect = func() { go runDirect(context.Background()) }
}

// The running carrier's admit, for a portable copy enrolled between two
// looks at the allowlist (clone.go): the copy's command line is typically
// waiting for its handshake the moment it is enrolled. nil while no carrier
// is up; serveDirect's poll admits anything this misses.
var directAdmit struct {
	sync.Mutex
	f func(key.NodePublic)
}

func setDirectAdmit(f func(key.NodePublic)) {
	directAdmit.Lock()
	directAdmit.f = f
	directAdmit.Unlock()
}

func admitNow(k key.NodePublic) {
	directAdmit.Lock()
	f := directAdmit.f
	directAdmit.Unlock()
	if f != nil {
		f(k)
	}
}

// How a stream tells a browser that is reading from a path gone dark
// (events, reach.go): the peer's received bytes are looked at this often,
// and a stream counts as acknowledged while they moved within the second.
const (
	streamAckEvery    = 5 * time.Second
	streamAckedWithin = 15 * time.Second
)

// The running carrier's probe of its DERP relay (transport ProbeRelay), for
// the reach record (reach.go): whether this machine can be reached over
// tailcat while the relay push is failing. nil while no carrier is up.
var directProbeF struct {
	sync.Mutex
	f func(context.Context) error
}

func setDirectProbe(f func(context.Context) error) {
	directProbeF.Lock()
	directProbeF.f = f
	directProbeF.Unlock()
}

func directProbe() func(context.Context) error {
	directProbeF.Lock()
	defer directProbeF.Unlock()
	return directProbeF.f
}

// directAddress is the tunnel's current address, or "" while it is down.
// Read by every relay push (types.go) so the dashboard learns the road.
func directAddress() string {
	directAddrMu.Lock()
	defer directAddrMu.Unlock()
	return directAddr
}

func setDirectAddress(s string) {
	directAddrMu.Lock()
	directAddr = s
	directAddrMu.Unlock()
}

// ensureDirect starts the tunnel loop, once per process, unless the run is
// forced onto the relay. Called at startup when the switch is on, and by the
// `allow` command when a dashboard enrolls itself on a machine whose switch
// was off — runDirect waits for the allowlist it was just given and comes up
// on its own. Returns whether the loop is (now) running.
func ensureDirect() bool {
	if transportMode() == "relay" {
		return false
	}
	directOnce.Do(startDirect)
	return true
}

// runAllow answers the dashboard's `allow` command: put the browser's node
// key on this machine's allowlist, set the switch so a restart keeps the
// road, and start the tunnel if it is not running. The result carries the
// address if the carrier is already up; otherwise the next relay push does
// (direct_addr), which is the ordinary case — the carrier takes a second or
// two to reach a DERP.
//
// Taken only from a browser this machine trusts — the caller (console.go)
// refuses it on a machine with no pinned key, unlike every other kind, because
// a key on the allowlist is standing access rather than one command. Not
// behind the console switch beyond that: what it grants is the read-only
// telemetry the sender already receives through the relay.
func runAllow(id, target string) consoleResult {
	start := time.Now()
	r := consoleResult{ID: id, Kind: "allow", Target: target}
	if _, ok := transport.ParseNodeKey(target); !ok {
		r.Code, r.Error = -1, "bad-key"
		return r
	}
	if transportMode() == "relay" {
		r.Code, r.Error = -1, "direct-off"
		return r
	}
	// The switch first, the key second: a switch that is on with no key is a
	// tunnel waiting for one, whereas a key on the list with the switch still
	// off would be access granted under a result that said it was not.
	if err := setDirect(true); err != nil {
		warnf("direct: could not set the switch: %v", err)
		r.Code, r.Error = -1, "allow-failed"
		return r
	}
	if err := allowClient(target); err != nil {
		warnf("direct: could not allow a dashboard's key: %v", err)
		r.Code, r.Error = -1, "allow-failed"
		return r
	}
	ensureDirect()
	warnf("direct: a dashboard enrolled its browser key; the tunnel is on")
	r.Out = directAddress()
	r.Ms = time.Since(start).Milliseconds()
	return r
}

// runDirect keeps the tunnel up for as long as ctx lives: waits for an
// allowlist if there is none, starts the carrier, publishes the address,
// admits keys added to the file while running, and restarts the carrier if
// it dies. It never returns early on an error — a tunnel that could not come
// up is retried, because the alternative is a machine that silently stops
// being watchable after one bad DERP fetch.
func runDirect(ctx context.Context) {
	startSysSampler()
	startProbes()
	startCustom()
	startIPv4()
	go runTailnet(ctx)
	musicStart()
	// Copies from another computer that were under way when this helper
	// last stopped (filesfetch.go).
	fetchResume()
	conf := configDir()
	if conf == "" {
		warnf("direct: no home directory, cannot keep a tunnel identity")
		return
	}
	waited := false
	for ctx.Err() == nil {
		if len(loadAllowedClients()) == 0 {
			if !waited {
				warnf("direct: no browser is allowed yet — run:  subnsub-helper allow <nodekey:...>")
				warnf("direct: (the key is shown on the Monitor page; the tunnel starts when one is added)")
				waited = true
			}
			if !sleepCtx(ctx, directAllowPoll) {
				return
			}
			continue
		}
		waited = false
		h := newDirectHandler()
		tc, err := transport.StartTailcat(transport.TailcatConfig{
			StateDir:   conf,
			DERPMapURL: derpMapURL(),
			Port:       directPort,
			// The file, the portable copies still current (clone.go) and
			// the read-only grants another computer is copying under
			// (filesgrant.go).
			Allowed: func() []key.NodePublic {
				return append(append(loadAllowedClients(), activeCloneNodes()...), activeGrantNodes()...)
			},
			Handler: h,
		})
		if err != nil {
			warnf("direct: tunnel did not start: %v", err)
			if !sleepCtx(ctx, 30*time.Second) {
				return
			}
			continue
		}
		h.carrier = tc
		setDirectAdmit(func(k key.NodePublic) {
			if !tc.Known(k) {
				tc.AddAllowed(k)
			}
		})
		publishAddress(conf, tc)
		setDirectAddress(tc.ConnBlob())
		setDirectProbe(tc.ProbeRelay)
		how := ""
		if tc.ByName() {
			how = ", dialed by name: this machine's DNS sends the relay elsewhere"
		}
		if derp := derpMapURL(); derp != "" {
			warnf("direct: up via your DERP map (region %d%s)", tc.Region(), how)
		} else {
			warnf("direct: up via the public tailcat DERP (region %d%s) — best effort, no guarantee", tc.Region(), how)
		}
		// A browser waiting to hear this node's address (pairing.go), for as
		// long as this carrier lives: the address it hands over is this one.
		pctx, pcancel := context.WithCancel(ctx)
		go runPairing(pctx, conf, tc)
		serveDirect(ctx, tc)
		pcancel()
		setDirectProbe(nil)
		setDirectAdmit(nil)
		tc.Close()
		setDirectAddress("")
		if ctx.Err() != nil {
			return
		}
		warnf("direct: tunnel stopped; restarting")
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
	}
}

// serveDirect watches the allowlist for additions until the carrier stops.
func serveDirect(ctx context.Context, tc *transport.Tailcat) {
	t := time.NewTicker(directAllowPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-tc.Done():
			if err != nil {
				warnf("direct: %v", err)
			}
			return
		case <-t.C:
			for _, k := range loadAllowedClients() {
				if !tc.Known(k) {
					tc.AddAllowed(k)
					warnf("direct: allowed a new browser")
				}
			}
			for _, k := range append(activeCloneNodes(), activeGrantNodes()...) {
				if !tc.Known(k) {
					tc.AddAllowed(k)
				}
			}
		}
	}
}

func publishAddress(conf string, tc *transport.Tailcat) {
	blob := tc.ConnBlob()
	warnf("direct: this machine's address (paste it on the Monitor page):")
	warnf("  %s", blob)
	path := filepath.Join(conf, addressFileName)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(blob+"\n"), 0o600); err == nil {
		os.Rename(tmp, path)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// ── what the tunnel serves ─────────────────────────────────────────────

type directHandler struct {
	mux     *http.ServeMux
	carrier *transport.Tailcat
	// The terminal's sessions (pty.go): the process's one table, not this
	// handler's — a handler is made anew for every carrier, and a session
	// outlives a carrier rebuild so the page can attach again by its token.
	ptys *ptyHub
	// The screens' sessions (screen.go), likewise the process's one table.
	screens *screenHub

	streams struct {
		sync.Mutex
		n int
	}
	snap struct {
		sync.Mutex
		at   time.Time
		body []byte
	}
}

func newDirectHandler() *directHandler {
	h := &directHandler{mux: http.NewServeMux(), ptys: ptySessions, screens: screenSessions}
	h.mux.HandleFunc("/v1/hello", h.hello)
	h.mux.HandleFunc("/v1/snapshot", h.snapshot)
	h.mux.HandleFunc("/v1/events", h.events)
	h.mux.HandleFunc("/v1/command", h.command)
	h.mux.HandleFunc("/v1/history", h.history)
	h.mux.HandleFunc("/v1/pty/out", h.ptyOut)
	h.mux.HandleFunc("/v1/pty/in", h.ptyIn)
	h.mux.HandleFunc("/v1/pty/resize", h.ptyResize)
	h.mux.HandleFunc("/v1/pty/close", h.ptyClose)
	// A machine's screen (screen.go): its own VNC server's bytes, both ways.
	h.mux.HandleFunc("/v1/screen/out", h.screenOut)
	h.mux.HandleFunc("/v1/screen/in", h.screenIn)
	h.mux.HandleFunc("/v1/screen/beat", h.screenBeat)
	h.mux.HandleFunc("/v1/screen/close", h.screenClose)
	// The shared music (music.go): reads only, for an allowlisted key.
	h.mux.HandleFunc("/v1/music", h.musicStatus)
	h.mux.HandleFunc("/v1/music/index", h.musicIndex)
	h.mux.HandleFunc("/v1/music/file", h.musicFile)
	h.mux.HandleFunc("/v1/music/art", h.musicArt)
	// The Files tab (files.go): a search's hits and an opened file's pieces,
	// by the token a signed command gave this peer.
	h.mux.HandleFunc("/v1/files/search", h.filesSearch)
	h.mux.HandleFunc("/v1/files/file", h.filesFile)
	// A piece of a file coming in (fileswrite.go), by the token a signed
	// put gave this peer.
	h.mux.HandleFunc("/v1/files/put", h.filesPutPiece)
	// The Speed tab's end of a measurement (speed.go): bytes down, bytes up,
	// a round trip.
	h.mux.HandleFunc("/v1/speed/ping", h.speed)
	h.mux.HandleFunc("/v1/speed/down", h.speed)
	h.mux.HandleFunc("/v1/speed/up", h.speed)
	// What this machine's Tailscale knows of its network (tsview.go): reads
	// only, for an allowlisted key.
	h.mux.HandleFunc("/v1/tailnet", h.tailnetView)
	h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.refuse(w, http.StatusNotFound, "unknown-frame")
	})
	return h
}

func (h *directHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Reads are GET; the writes are POST /v1/command, a terminal's input
	// and the pieces of a file the Files tab puts here. Anything else is not
	// a frame this road knows.
	switch r.URL.Path {
	case "/v1/command", "/v1/pty/in", "/v1/pty/resize", "/v1/pty/close", "/v1/files/put",
		"/v1/screen/in", "/v1/screen/beat", "/v1/screen/close",
		"/v1/files/grant/open", "/v1/files/grant/walk", "/v1/files/grant/done", "/v1/speed/up":
		if r.Method != http.MethodPost {
			h.refuse(w, http.StatusMethodNotAllowed, "unknown-frame")
			return
		}
	default:
		if r.Method != http.MethodGet {
			h.refuse(w, http.StatusMethodNotAllowed, "unknown-frame")
			return
		}
	}
	// Each road gates before this (Gate on the tunnel, tailnetAdmitted per
	// request on the tailnet); the door checks again, so a peer that is
	// neither on the allowlist file nor a current portable copy is turned
	// away whatever it asks, before any signature is looked at. A request
	// with no attributed peer (a test driving the handler) has none to check.
	if k, ok := transport.PeerFromContext(r.Context()); ok && !tailnetAdmitted(k) {
		// A key let in by a read-only grant alone (filesgrant.go): its few
		// paths and nothing the mux would answer anyone else.
		if len(grantsForNode(k, time.Now())) > 0 {
			h.grantServe(w, r, k)
			return
		}
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	h.mux.ServeHTTP(w, r)
}

// history serves the machine's own trend archive — see history.go for why it
// lives here and not on the relay — and, beside it, the stretches the machine
// was not running (outages.go): the archive's holes, in seconds and with a
// reason, which the buckets alone cannot say.
// history answers GET /v1/history[?step=60|300][&from=<s>][&to=<s>]: one
// page of the machine's archive at the asked step (historyServe), newest
// first within the span, as many rows as the history frame holds, with
// `more` saying whether to come back for older ones (to=<this page's from>).
// Without parameters it is what it always was — five-minute rows, the newest
// that fit — so a page from before the minutes still draws. The outage record
// rides on every page; it is small and the reader may start anywhere.
func (h *directHandler) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	num := func(k string) int64 {
		s := strings.TrimSpace(q.Get(k))
		if s == "" || len(s) > 12 {
			return 0
		}
		var n int64
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + int64(c-'0')
		}
		return n
	}
	step := int(num("step"))
	if !histStepOK(step) {
		step = histCoarseSec
	}
	from, to := num("from"), num("to")
	outs := outagePoints()
	if outs == nil {
		outs = []outageRow{}
	}
	// What the points may take: the frame's limit less the envelope and the
	// outages. Measured, not guessed — the outage list is bounded but not
	// fixed. Should the frame still not fit (a row far wider than the
	// estimate), halve the budget and try again rather than answer nothing.
	overhead := 4 << 10
	if ob, err := json.Marshal(outs); err == nil {
		overhead += len(ob)
	}
	budget := transport.Limits[transport.TypeHistory] - overhead
	var b []byte
	for attempt := 0; attempt < 4; attempt++ {
		s := historyServe(step, from, to, budget)
		points := s.Points
		if points == nil {
			points = []histRow{}
		}
		f, err := transport.New(transport.TypeHistory, agentID(), r.Header.Get("X-Request-Id"),
			map[string]any{"bucket_sec": s.Step, "points": points, "outages": outs,
				"from": s.From, "newest": s.Newest, "oldest": s.Oldest, "more": s.More})
		if err == nil {
			b, err = transport.Encode(f)
		}
		if err == nil {
			break
		}
		if !errors.Is(err, transport.ErrTooLarge) || budget < 16<<10 {
			h.refuse(w, http.StatusInternalServerError, "unavailable")
			return
		}
		budget /= 2
		b = nil
	}
	if b == nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// directCaps is what this machine will do for a tunnel peer right now: observe
// always (the gate already admitted the key), and each command kind only while
// its own switch is on — the page offers a control only for a capability the
// hello names, and re-reads it on every hello.
func directCaps() []string {
	caps := []string{transport.CapObserve}
	// Commands over the tunnel need a pinned key (see command); a machine
	// with none has no command capabilities to name, whatever its switches.
	if !loadTrust().sealed {
		return caps
	}
	caps = append(caps, transport.CapRename)
	if consoleEnabled() {
		caps = append(caps, transport.CapConsole)
		// The terminal is the console's own grant, on a platform that has
		// pseudo-terminals (pty.go).
		if ptySupported {
			caps = append(caps, transport.CapTerminal)
		}
	}
	// Portable copies (clone.go): named wherever a key is pinned, console or
	// not, so a dashboard can always REVOKE one; an enrolment is refused with
	// console-off where the console is.
	caps = append(caps, transport.CapClone)
	if updateAllowed() {
		caps = append(caps, transport.CapUpdate)
	}
	if diagnosticsEnabled() {
		caps = append(caps, transport.CapInspect)
	}
	// Tile actions: named wherever a key is pinned, whether or not anything
	// is declared yet. The hello is read once per tunnel, and an action
	// written into metrics.d after the page connected would otherwise stay
	// unpressable until it reconnected. What is declared is in the tiles;
	// a press on nothing is refused with no-action.
	caps = append(caps, transport.CapAct)
	// The My IP check (myip.go): wherever runMyIP would take it — an origin
	// configured and a mailbox switch on, the same gate it applies.
	if myipAvailable() {
		caps = append(caps, transport.CapMyIP)
	}
	return caps
}

// directCapsFor is directCaps with what belongs to the asking key alone:
// music is read by the browsers on the allowlist, not by a portable copy.
func directCapsFor(r *http.Request) []string {
	caps := directCaps()
	music, files := musicOn(), filesOn()
	if k, ok := transport.PeerFromContext(r.Context()); ok {
		for _, a := range loadAllowedClients() {
			if a == k {
				// The Speed tab's end of a measurement (speed.go): to every
				// browser on the list, whatever the switches.
				caps = append(caps, transport.CapSpeed)
				// The map of who reaches whom on its tailnet (tsview.go):
				// read-only, whatever the switches.
				caps = append(caps, transport.CapTailnetMap)
				// The machine's screen (screen.go): the console's grant, to a
				// browser on the list and not a portable copy, where a key is
				// pinned.
				if screenEnabled() && loadTrust().sealed {
					caps = append(caps, transport.CapScreen)
				}
				if music {
					caps = append(caps, transport.CapMusic)
				}
				// The Files tab's look at the disks (files.go) and its
				// changes to them (fileswrite.go): the console's grant, to
				// the same browsers music is.
				if files {
					caps = append(caps, transport.CapFiles, transport.CapFilesWrite)
					// Copies between two computers helper to helper
					// (filesgrant.go, filesfetch.go): this one lets another
					// read under a grant, and fetches from one itself.
					if directAddress() != "" {
						caps = append(caps, transport.CapFilesGrant)
					}
					caps = append(caps, transport.CapFilesFetch)
					// A measurement between this computer and another
					// (speedpeer.go): run from here, or measured here under
					// a grant — the console's grant, as a copy's is.
					caps = append(caps, transport.CapSpeedPeer)
					// Its own road to the internet (speednet.go).
					caps = append(caps, transport.CapSpeedNet)
				}
				return caps
			}
		}
	}
	return caps
}

// command is the mailbox's other door, and the console's only one: the same
// command envelope, POSTed through the tunnel by an allowed browser instead of
// collected from the relay. A shell line comes this way or not at all — the
// mailbox refuses one (mailboxRefusal). The gate has admitted the peer's key; the command's own signature is
// still checked by verifyCommand exactly as on the relay road, and each kind's
// switch by runCommand. The answer is the console result document in a result
// frame, so the page feeds it to the code it already has for the relay's
// /result frames.
func (h *directHandler) command(w http.ResponseWriter, r *http.Request) {
	limit := transport.Limits[transport.TypeCommand]
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(body) > limit {
		h.refuse(w, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	f, err := transport.Decode(body)
	if err != nil || f.Type != transport.TypeCommand {
		h.refuse(w, http.StatusBadRequest, "bad-frame")
		return
	}
	var cmd transport.Command
	if len(f.Body) == 0 || json.Unmarshal(f.Body, &cmd) != nil {
		h.refuse(w, http.StatusBadRequest, "bad-frame")
		return
	}
	// The id is the signature's anchor and the replay guard's key; a command
	// with none is not one that can be judged. Bounded like the relay bounds it.
	if f.ID == "" || len(f.ID) > 40 || len(cmd.Cmd) > 2000 || len(cmd.Target) > 80 {
		h.refuse(w, http.StatusBadRequest, "bad-frame")
		return
	}
	c := consoleCmd{ID: f.ID, Kind: cmd.Kind, Cmd: cmd.Cmd, Target: cmd.Target, Sig: cmd.Sig, IssuedAt: cmd.At}
	id := agentID()
	// A portable copy's tunnel peer is judged by the copy's own key and
	// certificate, and by nothing else (clone.go verifyCloneCommand): its
	// signature counts only from its own peer, and only for the kinds the
	// certificate grants.
	var clone *activeClone
	peer, hasPeer := transport.PeerFromContext(r.Context())
	if hasPeer {
		if a, ok := cloneForNode(peer, id, time.Now()); ok {
			clone = &a
		}
	}
	// Judged again once the command gate is held: the wait can be thirty
	// seconds, and a copy that expired or was revoked in it must not run on
	// the strength of the look taken before.
	verify := func() string {
		if clone != nil {
			now := time.Now()
			a, ok := cloneForNode(peer, id, now)
			if !ok {
				return "clone-expired"
			}
			clone = &a
			return verifyCloneCommand(c, id, a, now)
		}
		return verifyCommand(c, id, loadTrust(), time.Now())
	}
	var res consoleResult
	swap := false
	// The one difference from the mailbox road, and it is a tightening: the
	// tunnel takes a command only from a machine that has PINNED a dashboard
	// key, so that "allowed to watch" (the tailcat key on the list) never
	// quietly becomes "allowed to command". With nothing
	// pinned, verifyCommand would wave everything through unsigned — right
	// for a mailbox the relay already gates by account, wrong for a road
	// whose only gate is a watcher's key. directCaps says the same in the
	// hello, so the page never offers what this refuses.
	if !loadTrust().sealed {
		res = consoleResult{ID: c.ID, Kind: c.Kind, Target: c.Target, Code: -1, Error: "unpinned"}
	} else if (c.Kind == "" || c.Kind == "sh") && c.Cmd == "" {
		res = consoleResult{ID: c.ID, Code: -1, Error: "unknown-kind"}
	} else {
		// The gate before the verdict (see cmdGate), bounded by the request:
		// a browser that has gone away holds nothing, and one still waiting
		// is told "busy" rather than left for as long as a shell line runs.
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if !acquireCmd(ctx) {
			if r.Context().Err() != nil {
				return
			}
			res = consoleResult{ID: c.ID, Kind: c.Kind, Target: c.Target, Code: -1, Error: "busy"}
		} else if why := verify(); why != "" {
			releaseCmd()
			res = consoleResult{ID: c.ID, Kind: c.Kind, Target: c.Target, Code: -1, Error: why}
		} else if c.Kind == "pty" {
			// A terminal session (pty.go): this road's alone, opened by a
			// signed command like any other and answered with its token.
			releaseCmd()
			res = consoleResult{ID: c.ID, Kind: "pty", Code: -1, Error: "not-allowed"}
			if peer, ok := transport.PeerFromContext(r.Context()); ok {
				signer := commandSigner(c, id, loadTrust())
				if clone != nil {
					signer = clone.sign
				}
				if tok, sid, why := h.ptys.open(peer, signer, c.Target); why != "" {
					res.Error = why
				} else {
					// The token is the page's; the id is the session's,
					// for coming back to it (pty-attach) once the token
					// is gone with the page.
					res = consoleResult{ID: c.ID, Kind: "pty", Code: 0, Out: tok, Target: sid}
				}
			}
		} else if c.Kind == "pty-attach" {
			// Back to a session that is running (pty.go): a token for this
			// peer, the keyboard with it. A portable copy only to the
			// sessions it opened.
			releaseCmd()
			res = consoleResult{ID: c.ID, Kind: "pty-attach", Code: -1, Error: "not-allowed"}
			if peer, ok := transport.PeerFromContext(r.Context()); ok {
				var own ed25519.PublicKey
				signer := commandSigner(c, id, loadTrust())
				if clone != nil {
					own, signer = clone.sign, clone.sign
				}
				if tok, keys, why := h.ptys.attach(peer, c.Target, own, signer); why != "" {
					res.Error = why
				} else {
					// The id, and "/w" where the keys stayed with
					// another page.
					sid := strings.TrimSuffix(c.Target, "/w")
					if !keys {
						sid += "/w"
					}
					res = consoleResult{ID: c.ID, Kind: "pty-attach", Code: 0, Out: tok, Target: sid}
				}
			}
		} else if c.Kind == "screen" {
			// A screen session (screen.go): this road's alone, like a
			// terminal, and not a portable copy's — its certificate names
			// nothing of it.
			releaseCmd()
			res = consoleResult{ID: c.ID, Kind: "screen", Code: -1, Error: "not-allowed"}
			if peer, ok := transport.PeerFromContext(r.Context()); ok && clone == nil {
				if tok, why := h.screens.open(peer, commandSigner(c, id, loadTrust())); why != "" {
					res.Error = why
				} else {
					res = consoleResult{ID: c.ID, Kind: "screen", Code: 0, Out: tok}
				}
			}
		} else if c.Kind == "files" {
			// The Files tab (files.go): this road's alone, and bound to the
			// peer that asked — a search's and a file's tokens are good on
			// its tunnel only. Not a portable copy's: its certificate names
			// nothing of this.
			if clone != nil {
				res = consoleResult{ID: c.ID, Kind: "files", Target: c.Target, Code: -1, Error: "not-allowed"}
			} else {
				res = runFilesCommand(c, peer, hasPeer, commandSigner(c, id, loadTrust()))
			}
			releaseCmd()
		} else {
			res, swap = runCommand(c)
			releaseCmd()
		}
	}
	res.Agent = id
	out, err := transport.New(transport.TypeResult, id, c.ID, res)
	var b []byte
	if err == nil {
		b, err = transport.Encode(out)
	}
	if err != nil {
		// The result outgrew its frame (a shell line printed more than the
		// ceiling): answer with the bounded part rather than nothing.
		if len(res.Out) > 8<<10 {
			res.Out = res.Out[:8<<10]
		}
		res.Truncated = true
		if out, err2 := transport.New(transport.TypeResult, id, c.ID, res); err2 == nil {
			b, err = transport.Encode(out)
		}
	}
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
	if swap {
		// The update installed a new binary: deliver this answer, then hand
		// over — the same handover the mailbox path makes, a moment later so
		// the bytes above reach the tunnel first. If it returns, the handover
		// did not happen and this helper simply keeps serving the version it
		// is already running. See restart.go.
		http.NewResponseController(w).Flush()
		go func() {
			time.Sleep(time.Second)
			restartSelf()
		}()
	}
}

func (h *directHandler) refuse(w http.ResponseWriter, status int, code string) {
	refuseAs(w, agentID(), status, code)
}

func refuseAs(w http.ResponseWriter, agent string, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if f, err := transport.New(transport.TypeError, agent, "", transport.Error{Code: code}); err == nil {
		if b, err := transport.Encode(f); err == nil {
			w.Write(b)
		}
	}
}

func (h *directHandler) helloFrame(r *http.Request) ([]byte, error) {
	carrier := "tailcat"
	if tailnetRequest(r) {
		carrier = "tailnet"
	}
	f, err := transport.New(transport.TypeHello, agentID(), r.Header.Get("X-Request-Id"), transport.Hello{
		HelperVersion: helperVersion,
		Caps:          directCapsFor(r),
		Carrier:       carrier,
		Tailnet:       tailnetRoadNow(),
	})
	if err != nil {
		return nil, err
	}
	return transport.Encode(f)
}

func (h *directHandler) hello(w http.ResponseWriter, r *http.Request) {
	b, err := h.helloFrame(r)
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
	// A browser that says hello here knows this node's own address: a
	// pairing waiting for that browser is over (pairing.go).
	if k, ok := transport.PeerFromContext(r.Context()); ok {
		notePeerHello(k)
	}
}

// quotaAutoAsked reports whether a tunnel reader opened its stream saying
// this machine is set to refresh its quota on its own (the card's
// Settings). One exact value; anything else is manual.
func quotaAutoAsked(r *http.Request) bool {
	return r.URL.Query().Get("quota") == "auto"
}

// snapshotFrame is the whole reading, in the frame the page already knows
// how to render — the relay push's document, unchanged. Memoised briefly
// so two watchers do not run the collectors twice.
func (h *directHandler) snapshotFrame(fresh bool, only string) ([]byte, error) {
	h.snap.Lock()
	defer h.snap.Unlock()
	// A peer reading this machine asks the vendors nothing by reading. What
	// makes it a watcher is its stream, opened saying so (events); what
	// asks now is the press below (pace.go).
	if fresh {
		// The page's refresh press: every quota provider asks its vendor
		// once at this collection (each keeps its own gap between presses),
		// and the answer is not the one cached for the next tab. With
		// `only`, the one provider whose tile was pressed.
		quotaForceFor(only)
	} else if h.snap.body != nil && time.Since(h.snap.at) < directSnapshotCache {
		return h.snap.body, nil
	}
	// The relay push consumes the sampler's series; this path must not, or
	// the two would starve each other of the thirty seconds each expects.
	snap := collectAllOpts(false)
	f, err := transport.New(transport.TypeSnapshot, agentID(), "", snap)
	if err != nil {
		return nil, err
	}
	b, err := transport.Encode(f)
	if err != nil {
		return nil, err
	}
	h.snap.at = time.Now()
	h.snap.body = b
	return b, nil
}

func (h *directHandler) snapshot(w http.ResponseWriter, r *http.Request) {
	// `only` names one provider's tile for the press (pace.go); anything that
	// could not be an id is refused rather than widened to every vendor.
	only := r.URL.Query().Get("only")
	if only != "" && !forceTarget(only) {
		h.refuse(w, http.StatusBadRequest, "bad-request")
		return
	}
	b, err := h.snapshotFrame(r.URL.Query().Get("fresh") != "", only)
	if err != nil {
		// Most likely the reading outgrew its ceiling. That is a bug worth a
		// loud line here rather than a quiet 500 — but the line must not
		// carry the reading.
		warnf("direct: snapshot frame refused: %v", err)
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func systemFrame() ([]byte, error) {
	sys := latestSystem()
	if sys == nil {
		return nil, errors.New("no sample yet")
	}
	f, err := transport.New(transport.TypeSystem, agentID(), "", sys)
	if err != nil {
		return nil, err
	}
	return transport.Encode(f)
}

// events is the stream: hello, then a snapshot, then the host-health block
// every second and the snapshot every thirty, as server-sent events whose
// data lines are frames. It is exactly the local /events shape carried over
// the tunnel, which is what the plan asked for, with three additions the
// tunnel needs — a slot cap, a per-write deadline, and a periodic re-check
// that the peer is still allowed, since a stream outlives the request the
// gate looked at.
//
// A PUBLISHED PROMISE: self-hosted panels keep their own copy of the browser
// client, and that client ends a stream at any frame type it does not know.
// So this default stream stays hello, snapshot and system; a new type goes out
// only to a reader that asks for it in the query. New fields in a body are
// fine. TestDirectEventsStaysReadableByPublishedClients holds this, and
// infra/monitor-client-compat.mjs holds the release to it.
func (h *directHandler) events(w http.ResponseWriter, r *http.Request) {
	h.streams.Lock()
	if h.streams.n >= directMaxStreams {
		h.streams.Unlock()
		h.refuse(w, http.StatusServiceUnavailable, "busy")
		return
	}
	h.streams.n++
	h.streams.Unlock()
	defer func() { h.streams.Lock(); h.streams.n--; h.streams.Unlock() }()

	peer, _ := transport.PeerFromContext(r.Context())
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	// Whether the browser is still taking the frames: the bytes the tunnel
	// has received from it (its acknowledgements) moved in the last
	// streamAckedWithin, looked at every streamAckEvery. A flush only says
	// the socket's buffer took the bytes, which it goes on doing for a while
	// after the path has gone dark (review 2026-10-24).
	var rxN int64 = -1
	var rxAt, rxLooked time.Time
	acked := func(now time.Time) bool {
		// The tailnet road's acknowledgements are the operating system's own,
		// out of sight here: no evidence either way, so none is claimed.
		if h.carrier == nil || tailnetRequest(r) {
			return false
		}
		if now.Sub(rxLooked) >= streamAckEvery {
			rxLooked = now
			if n, ok := h.carrier.PeerRx(peer); ok {
				if rxN >= 0 && n > rxN {
					rxAt = now
				}
				rxN = n
			}
		}
		return !rxAt.IsZero() && now.Sub(rxAt) <= streamAckedWithin
	}
	emit := func(b []byte) bool {
		if err := rc.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		if rc.Flush() != nil {
			return false
		}
		// A frame that left for a browser that is still acknowledging what
		// it reads is the machine answering end to end — evidence for the
		// reach record while the relay push is failing (reach.go), and
		// nothing otherwise.
		if now := time.Now(); acked(now) {
			reachNote(now, reachKindTunnel)
		}
		return true
	}
	if b, err := h.helloFrame(r); err == nil && !emit(b) {
		return
	}
	// What the reader said when it opened the stream holds for the stream
	// and ends with it: a page that changes the setting opens a new one,
	// and a browser that went away stops counting when its stream does.
	if quotaAutoAsked(r) {
		defer streamWatched()()
	}
	if b, err := h.snapshotFrame(false, ""); err == nil && !emit(b) {
		return
	}
	sysT := time.NewTicker(directSystemEvery)
	defer sysT.Stop()
	snapT := time.NewTicker(directSnapshotEvery)
	defer snapT.Stop()
	gateT := time.NewTicker(directAllowPoll)
	defer gateT.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sysT.C:
			if b, err := systemFrame(); err == nil && !emit(b) {
				return
			}
		case <-snapT.C:
			if b, err := h.snapshotFrame(false, ""); err == nil && !emit(b) {
				return
			}
		case <-gateT.C:
			// Revocation reaches an open stream here: the key was struck
			// from the file, so the stream ends. The page sees the close
			// and, on reconnecting, the gate's 403.
			if tailnetRequest(r) {
				if !tailnetAdmitted(peer) {
					return
				}
			} else if h.carrier != nil {
				if k, ok := h.carrier.PeerKey(r.RemoteAddr); !ok || k != peer {
					return
				}
			}
		}
	}
}

// ── CLI ────────────────────────────────────────────────────────────────

// directRecordLoop keeps the archive on a machine with no relay to push to
// (no token, or MON_TRANSPORT=tailcat): a collection every
// push interval, as the relay loop makes one, whether or not anybody is
// watching. Started by main for that case ALONE: beside a relay push it
// would take the sampler's series out from under it.
// This collection takes the sampler's
// series, as the relay push does; the tunnel's snapshots never take it, so
// the two cannot starve each other.
func directRecordLoop(ctx context.Context) {
	every := time.Duration(defaultInterval * float64(time.Second))
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			collectAllOpts(true)
		}
	}
}

func runDirectCLI(args []string) int {
	if len(args) > 0 {
		on := args[0] == "on" || args[0] == "1" || args[0] == "true" || args[0] == "yes"
		off := args[0] == "off" || args[0] == "0" || args[0] == "false" || args[0] == "no"
		if !on && !off {
			warnf("say 'direct on' or 'direct off'")
			return 2
		}
		if err := setDirect(on); err != nil {
			warnf("could not change the direct setting: %v", err)
			return 1
		}
	}
	if directEnabled() {
		fmt.Printf("on   (%s)\n", agentID())
		if n := len(loadAllowedClients()); n == 0 {
			fmt.Println("no browser is allowed yet, so the tunnel is not running —")
			fmt.Println("  subnsub-helper allow <nodekey:...>   (the key is on the Monitor page)")
		} else {
			fmt.Printf("%d browser key(s) allowed\n", n)
		}
	} else {
		fmt.Printf("off  (%s)\n", agentID())
	}
	if len(args) > 0 {
		fmt.Println("takes effect when the helper restarts (systemctl --user restart subnsub-helper,")
		fmt.Println("or re-run the installer)")
	}
	return 0
}

func runAllowCLI(args []string) int {
	if len(args) == 0 {
		keys := loadAllowedClients()
		if len(keys) == 0 {
			fmt.Println("no browser keys allowed — the direct tunnel does not start until one is")
			return 0
		}
		fmt.Printf("%d browser key(s) may reach this machine directly:\n", len(keys))
		for _, k := range keys {
			fmt.Println("  " + k.String())
		}
		return 0
	}
	if err := allowClient(args[0]); err != nil {
		warnf("could not allow that key: %v", err)
		return 1
	}
	fmt.Printf("allowed (%s)\n", agentID())
	if !directEnabled() {
		fmt.Println("note: direct mode is off; 'subnsub-helper direct on' and a restart turn the tunnel on")
	}
	return 0
}

func runDisallowCLI(args []string) int {
	if len(args) == 0 {
		warnf("say 'disallow <nodekey:...>' — 'allow' with no argument lists them")
		return 2
	}
	if err := disallowClient(args[0]); err != nil {
		warnf("could not remove that key: %v", err)
		return 1
	}
	fmt.Println("removed; that browser is refused from its next request on")
	return 0
}

// runAddressCLI prints the tunnel address a watcher pastes, if the daemon
// has published one, and this machine's own node key either way.
func runAddressCLI() int {
	conf := configDir()
	if conf == "" {
		warnf("no config directory")
		return 1
	}
	pub, err := transport.PublicKeyOf(conf)
	if err != nil {
		warnf("could not read the tunnel identity: %v", err)
		return 1
	}
	b, err := os.ReadFile(filepath.Join(conf, addressFileName))
	if err == nil && strings.TrimSpace(string(b)) != "" {
		fmt.Println(strings.TrimSpace(string(b)))
	} else if directEnabled() {
		fmt.Println("(no address yet — the tunnel publishes one once it is up)")
	} else {
		fmt.Println("(direct mode is off — 'subnsub-helper direct on')")
	}
	fmt.Printf("node key: %s\n", pub.String())
	if s := pairingStatusLine(conf, time.Now()); s != "" {
		fmt.Println(s)
	}
	return 0
}

// directStatus is the line the installer and `direct` print about where the
// bytes go, so the person at the machine hears it in the same words the page
// uses.
func directStatusLine() string {
	if derp := derpMapURL(); derp != "" {
		return "direct: ON — tunnelled via your own DERP map"
	}
	return "direct: ON — tunnelled via the public tailcat DERP (best effort, no guarantee)"
}

// directJSON is a convenience for tests: the body of a frame, decoded.
func directJSON(b []byte) (transport.Frame, map[string]any, error) {
	f, err := transport.Decode(b)
	if err != nil {
		return f, nil, err
	}
	var body map[string]any
	if len(f.Body) > 0 {
		if err := json.Unmarshal(f.Body, &body); err != nil {
			return f, nil, err
		}
	}
	return f, body, nil
}
