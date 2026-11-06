package main

// The roads out, measured — and the fastest one taken for the helper's own
// downloads.
//
// A router that sends some traffic through a VPN in a namespace of its own
// has two ways to the internet, and the helper, started by init, sits on the
// native one. On the GL-MT3000 that native uplink is a Chinese line on which
// the release host answers at ten kilobytes a second: every hourly update
// pass ran out its five minutes two megabytes in, while the Tailscale
// namespace beside it would have fetched the binary in twenty seconds (operator
// ruling 2026-10-13: report the network conditions of both namespaces at
// once, and download helper updates through whichever is faster).
//
// So every few minutes the helper fetches the first quarter megabyte of a
// published binary from its own namespace and from each named one (the
// spaces spaces.go already enters, by the same spaceDial), and records how
// long the first byte took and how fast the bytes came. The reading carries
// one Road per way out — the card shows it under each Exit — and the
// updater (update.go) tries the roads in order of measured speed, moving to
// the next when one stalls. A machine with one namespace measures one road
// and behaves exactly as before, except that a stalled download is now
// abandoned in thirty seconds rather than five minutes.
//
// The sample is deliberately small and from the release host itself: it is
// the bytes the updater will actually need, over the connection it will
// actually make, and a quarter megabyte every five minutes is nothing even
// on a metered line. The name "" is the helper's own namespace.

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	roadsEvery        = 5 * time.Minute
	roadsFirstGap     = 20 * time.Second
	roadsSampleBytes  = 256 << 10
	roadsSampleBudget = 12 * time.Second
	// The sample asset: the one target every release publishes. Which
	// platform's bytes come back does not matter; their speed does.
	roadsSampleAsset = "subnsub-helper-linux-amd64"
	roadsEnvVar      = "MON_ROADS"
	roadDialTimeout  = 5 * time.Second
	// A download that moves nothing for this long is on a dead or crawling
	// road; the next road is tried rather than the budget waited out.
	roadStall = 30 * time.Second
)

// Road is one way out, as the helper measured it against the release host.
type Road struct {
	Name      string   `json:"name"` // "" for the helper's own namespace
	OK        bool     `json:"ok"`
	TTFBMs    *float64 `json:"ttfb_ms,omitempty"`
	KBps      *float64 `json:"kbps,omitempty"`
	Error     string   `json:"error,omitempty"` // timeout · unreachable · refused
	CheckedAt float64  `json:"checked_at"`
}

var roads struct {
	sync.Mutex
	on   bool
	list []Road
}

func roadsOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(roadsEnvVar))) {
	case "0", "off", "false", "no":
		return true
	}
	return false
}

// roadNames: the helper's own namespace first, then the named ones the
// spaces loop would probe (same filter, same cap).
func roadNames() []string {
	out := []string{""}
	if spacesAvailable() {
		out = append(out, spacesPick(spacesFound())...)
	}
	return out
}

// startRoads begins the measuring loop, once per process, beside the update
// timer: whichever daemon mode runs, the updater wants the measurement.
func startRoads() {
	if roadsOff() {
		return
	}
	roads.Lock()
	if roads.on {
		roads.Unlock()
		return
	}
	roads.on = true
	roads.Unlock()
	go func() {
		time.Sleep(roadsFirstGap)
		for {
			roadsPass(updateBaseURL())
			time.Sleep(roadsEvery)
		}
	}()
}

func updateBaseURL() string {
	if v := strings.TrimSpace(os.Getenv(updateBaseEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return updateBase
}

// roadsPass measures every road once and keeps the list.
func roadsPass(base string) []Road {
	var out []Road
	for _, name := range roadNames() {
		if r := roadMeasure(base, name); r != nil {
			out = append(out, *r)
		}
	}
	roads.Lock()
	roads.list = out
	roads.Unlock()
	return out
}

func roadsSnapshot() []Road {
	roads.Lock()
	defer roads.Unlock()
	if len(roads.list) == 0 {
		return nil
	}
	return append([]Road(nil), roads.list...)
}

// roadsRanked: the roads to try for a download, fastest measured first,
// then the unmeasured named ones, and the helper's own namespace always
// present — first when nothing has been measured yet, last otherwise, so
// a machine with one way out is unchanged.
func roadsRanked() []string {
	snap := roadsSnapshot()
	type cand struct {
		name string
		kbps float64
	}
	var ok []cand
	seen := map[string]bool{}
	for _, r := range snap {
		seen[r.Name] = true
		if r.OK && r.KBps != nil {
			ok = append(ok, cand{r.Name, *r.KBps})
		}
	}
	sort.SliceStable(ok, func(i, j int) bool { return ok[i].kbps > ok[j].kbps })
	var out []string
	for _, c := range ok {
		out = append(out, c.name)
	}
	for _, name := range roadNames() {
		if !contains(out, name) && !seen[name] {
			out = append(out, name)
		}
	}
	if !contains(out, "") {
		out = append(out, "")
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// netnsSay: one sentence for the log, the installer and `netns`.
func netnsSay() string {
	ni := netnsInfo()
	if ni == nil {
		return "network namespaces are not something this platform shows; this helper runs in the only one"
	}
	all := append([]string(nil), ni.Names...)
	if ni.Own == "init" || ni.Own == "unnamed" {
		all = append([]string{ni.Own}, all...)
	}
	word := "network namespaces"
	if ni.Count == 1 {
		word = "network namespace"
	}
	return itoa(ni.Count) + " " + word + " (" + strings.Join(all, ", ") + "); this helper runs in " + ni.Own
}

func roadLabel(name string) string {
	if name == "" {
		return "own namespace"
	}
	return "namespace " + name
}

// roadClient: an HTTP client whose connections leave by the named road.
// The name is resolved in the helper's own namespace (the one with a
// resolver the operator set up), IPv4 first as the relay's transport
// dials, and only the connection is made from inside the other namespace.
// Keep-alives are off on a namespace road: a pooled connection belongs to
// the thread that made it, and that thread is gone (spaceDial).
func roadClient(name string, timeout time.Duration) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if name == "" {
		base.DialContext = ipv4FirstDialContext(base.DialContext, relayIPv4Timeout)
	} else {
		base.DisableKeepAlives = true
		base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var tries []net.IP
			for _, want4 := range []bool{true, false} {
				for _, ip := range ips {
					if (ip.IP.To4() != nil) == want4 {
						tries = append(tries, ip.IP)
						break
					}
				}
			}
			if len(tries) == 0 {
				return nil, &net.DNSError{Err: "no address", Name: host}
			}
			var entered atomic.Bool
			var last error
			for _, ip := range tries {
				dctx, stop := context.WithTimeout(ctx, roadDialTimeout)
				conn, err := spaceDial(dctx, name, net.JoinHostPort(ip.String(), port), &entered)
				stop()
				if err == nil {
					return conn, nil
				}
				last = err
				if !entered.Load() || ctx.Err() != nil {
					break
				}
			}
			return nil, last
		}
	}
	return &http.Client{
		Transport: base,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// roadMeasure fetches the sample from one road: the first byte's delay and
// the rate the rest came at. A road that cannot be entered (no such
// namespace, no permission) is not reported at all — it is not a road.
func roadMeasure(base, name string) *Road {
	ctx, cancel := context.WithTimeout(context.Background(), roadsSampleBudget)
	defer cancel()
	client := roadClient(name, 0)
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/"+roadsSampleAsset, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "subnsub-helper")
	req.Header.Set("Range", "bytes=0-"+itoa(roadsSampleBytes-1))
	out := &Road{Name: name, CheckedAt: now()}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if name != "" && !roadEntered(err) {
			return nil
		}
		out.Error = "unreachable"
		if ne, ok := err.(net.Error); ok && ne.Timeout() || ctx.Err() != nil {
			out.Error = "timeout"
		}
		return out
	}
	defer resp.Body.Close()
	ttfb := float64(time.Since(started).Milliseconds())
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		out.Error = "refused"
		return out
	}
	readStart := time.Now()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, roadsSampleBytes))
	el := time.Since(readStart).Seconds()
	if n <= 0 {
		out.Error = "timeout"
		if ctx.Err() == nil {
			out.Error = "unreachable"
		}
		return out
	}
	if el < 0.001 {
		el = 0.001
	}
	kbps := float64(n) / 1024 / el
	out.OK, out.TTFBMs, out.KBps = true, &ttfb, &kbps
	return out
}

// roadEntered: whether a failure on a namespace road happened after the
// namespace was reached. spaceDial reports "no such namespace" and "no
// permission" as plain errors before entering; those roads do not exist
// for this process and are left off the list rather than shown as down.
func roadEntered(err error) bool {
	if err == nil {
		return true
	}
	s := err.Error()
	return !(strings.Contains(s, "no such file") || strings.Contains(s, "permission denied") ||
		strings.Contains(s, "operation not permitted") || strings.Contains(s, "no side thread"))
}

// progressReader counts bytes as they pass and stamps the moment of the
// last one, for the stall watchdog that cancels a crawling download.
type progressReader struct {
	r    io.Reader
	n    atomic.Int64
	last atomic.Int64 // unix nanoseconds of the last byte
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.n.Add(int64(n))
		p.last.Store(time.Now().UnixNano())
	}
	return n, err
}

// watchStall cancels ctx when the reader has moved nothing for roadStall.
// Returns a stop function and a flag that says whether the stall fired.
func watchStall(ctx context.Context, cancel context.CancelFunc, p *progressReader) (stop func(), stalled *atomic.Bool) {
	stalled = &atomic.Bool{}
	done := make(chan struct{})
	p.last.Store(time.Now().UnixNano())
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, p.last.Load())) > roadStall {
					stalled.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(done) }, stalled
}
