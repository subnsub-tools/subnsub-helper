package main

/* ── measuring the road from this computer to the internet ──

   speed-net asks this machine to measure its own line, as the Speed tab
   measures the browser's: against Cloudflare's speed test
   (speed.cloudflare.com), whichever of its edges is nearest answering. The
   page reads it with speed-status and stops it with speed-stop, as it does
   a measurement between two computers (speedpeer.go), and the same gate
   lets it in: a pinned key, the console, the tunnel.

   What is learned of the far end is the edge's code and the country it puts
   this machine in (/cdn-cgi/trace). The address it sees is in the same
   answer and is read past, never kept or sent on.

   Plain HTTP/1.1, each stream on a connection of its own: one HTTP/2
   connection would carry all four streams down a single TCP road. A round
   trip is the time to the first byte less the time Cloudflare's end says it
   spent (its Server-Timing), as the browser's engine counts it. */

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// speedNetBase is Cloudflare's speed test. A variable, so a test puts its
// own server in its place.
var speedNetBase = "https://speed.cloudflare.com"

const (
	// One download asks for this much and another follows: Cloudflare
	// refuses 100 MB and more.
	speedNetDownBytes = 50_000_000
	// The largest upload piece (the browser's engine sends up to 50 MB).
	speedNetPieceMax = 16 << 20
	// A round trip that takes longer than this is not one.
	speedNetPingWait = 5 * time.Second
	// Round trips that may go missing before the line is said to be
	// unreachable: one lost on a busy line is not a broken one.
	speedNetPingMiss = 4
)

var (
	speedNetColoRe = regexp.MustCompile(`^[A-Z]{3}$`)
	speedNetCcRe   = regexp.MustCompile(`^[A-Z]{2}$`)
	speedNetReqRe  = regexp.MustCompile(`(?i)(?:^|,)\s*cfReq(?:uest)?Dur(?:ation)?;\s*dur=([0-9.]+)`)
	speedNetDurRe  = regexp.MustCompile(`(?i)(?:^|,)\s*cfSpeed[a-z]*;\s*dur=([0-9.]+)`)
	speedNetL4Re   = regexp.MustCompile(`(?i)(?:^|,)\s*cfL4;[^,]*?desc="\??([^"]*)"`)
)

// speedTCP is the TCP connection as Cloudflare's end saw it (its cfL4
// server timing): the round trip and its least in microseconds, segments
// sent and sent again.
type speedTCP struct {
	Rtt     float64 `json:"rtt"`
	Min     float64 `json:"min,omitempty"`
	Retrans float64 `json:"retrans"`
	Sent    float64 `json:"sent"`
}

// speedNetClient makes connections of its own for one measurement, closed
// with it. HTTP/2 is left out (TLSNextProto), redirects are not followed.
func speedNetClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConnsPerHost:   speedStreams + 2,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func speedNetReq(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, speedNetBase+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "subnsub-monitor/"+helperVersion)
	return req, nil
}

// speedNetCode is why the speed test's server could not be had.
func speedNetCode(ctx context.Context, err error, status int) string {
	switch {
	case ctx.Err() != nil:
		return "stopped"
	case err != nil:
		return "net-unreachable"
	case status == http.StatusTooManyRequests || status == http.StatusForbidden:
		return "net-refused"
	default:
		return "net-status-" + strconv.Itoa(status)
	}
}

func (j *speedJob) workNet(ctx context.Context) (string, string) {
	hc := speedNetClient()
	defer hc.CloseIdleConnections()
	// The round trips under load go on a client of their own, so that a
	// stream's connection is never one of theirs.
	pc := speedNetClient()
	defer pc.CloseIdleConnections()
	j.mu.Lock()
	secs := j.secs
	j.mu.Unlock()

	// Where it lands.
	if code := j.still(ctx); code != "" {
		return "err", code
	}
	colo, cc, code := speedNetTrace(ctx, hc)
	if code != "" {
		return "err", code
	}
	j.set(func(j *speedJob) { j.colo, j.cc = colo, cc })

	// The round trip, on the connection the trace left open.
	j.set(func(j *speedJob) { j.st, j.phase = "ping", time.Now() })
	var rtts []float64
	miss := 0
	for i := 0; i < speedPings; i++ {
		if code := j.still(ctx); code != "" {
			return "err", code
		}
		ms, _, code := speedNetPing(ctx, hc)
		switch {
		case code == "stopped" || code == "net-refused" || (code != "" && miss >= speedNetPingMiss):
			return "err", code
		case code != "":
			miss++
		case i >= speedPingsSkip:
			rtts = append(rtts, ms)
		}
	}
	if len(rtts) == 0 {
		return "err", "net-unreachable"
	}
	p, jit := speedLatency(rtts)
	j.set(func(j *speedJob) { j.ping, j.jit = p, jit })

	// Down, then up, each with its round trip under load.
	dur := time.Duration(secs) * speedSecond
	j.set(func(j *speedJob) { j.st, j.phase = "down", time.Now() })
	down, lat, code := j.measureNet(ctx, pc, dur, func(c context.Context, stop time.Time, m *speedMeter) string {
		c, cancel := context.WithDeadline(c, stop)
		defer cancel()
		return speedNetDownStream(c, hc, m)
	})
	if code != "" {
		return "err", code
	}
	dl, dj := speedLatency(lat)
	j.set(func(j *speedJob) { j.down, j.live, j.dlLat, j.dlJit = down, 0, dl, dj })
	if code := j.still(ctx); code != "" {
		return "err", code
	}
	rtt := time.Duration(p * float64(time.Millisecond))
	j.set(func(j *speedJob) { j.st, j.phase = "up", time.Now() })
	up, lat, code := j.measureNet(ctx, pc, dur, func(c context.Context, stop time.Time, m *speedMeter) string {
		return speedNetUpStream(c, stop, hc, m, rtt)
	})
	if code != "" {
		return "err", code
	}
	ul, uj := speedLatency(lat)
	j.set(func(j *speedJob) { j.up, j.ulLat, j.ulJit = up, ul, uj })

	// The connection the last pieces went on, as Cloudflare's end saw it:
	// a nicety, a run is not lost for want of it.
	if _, tcp, code := speedNetPing(ctx, hc); code == "" && tcp != nil {
		j.set(func(j *speedJob) { j.tcp = tcp })
	}
	return "done", ""
}

// measureNet is measure, with the round trip read on pc every so often
// while the streams run (from the first second on, as the rate is).
func (j *speedJob) measureNet(ctx context.Context, pc *http.Client, dur time.Duration, stream func(context.Context, time.Time, *speedMeter) string) (float64, []float64, string) {
	lctx, stop := context.WithCancel(ctx)
	warm := time.Now().Add(speedSecond)
	got := make(chan []float64, 1)
	go func() { got <- speedNetLoaded(lctx, pc, warm) }()
	rate, code := j.measure(ctx, dur, stream)
	stop()
	lat := <-got
	if code == "unreachable" {
		code = "net-unreachable"
	}
	return rate, lat, code
}

// speedNetLoaded reads the round trip every 0.4 s while a direction is
// under load.
func speedNetLoaded(ctx context.Context, pc *http.Client, warm time.Time) []float64 {
	var out []float64
	for {
		select {
		case <-ctx.Done():
			return out
		case <-time.After(speedSecond * 2 / 5):
		}
		ms, _, code := speedNetPing(ctx, pc)
		if code == "" && ctx.Err() == nil && !time.Now().Before(warm) {
			out = append(out, ms)
		}
	}
}

// speedNetTrace is the edge that answers and the country it puts this
// machine in. The trace also says the address it sees: not kept.
func speedNetTrace(ctx context.Context, hc *http.Client) (string, string, string) {
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := speedNetReq(c, http.MethodGet, "/cdn-cgi/trace", nil)
	if err != nil {
		return "", "", "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", speedNetCode(ctx, err, 0)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return "", "", speedNetCode(ctx, nil, resp.StatusCode)
	}
	var colo, cc string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 16<<10))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		switch {
		case !ok:
		case k == "colo" && speedNetColoRe.MatchString(v):
			colo = v
		case k == "loc" && speedNetCcRe.MatchString(v):
			cc = v
		}
	}
	return colo, cc, ""
}

// speedNetPing is one round trip: from the request written to the answer's
// first byte, less what Cloudflare's end spent on it. It also answers the
// connection's TCP facts where the answer carries them.
func speedNetPing(ctx context.Context, hc *http.Client) (float64, *speedTCP, string) {
	c, cancel := context.WithTimeout(ctx, speedNetPingWait)
	defer cancel()
	// Atomics: the hooks run on the connection's own goroutines.
	var wrote, first atomic.Int64
	t0 := time.Now()
	c = httptrace.WithClientTrace(c, &httptrace.ClientTrace{
		WroteRequest:         func(httptrace.WroteRequestInfo) { wrote.Store(int64(time.Since(t0))) },
		GotFirstResponseByte: func() { first.Store(int64(time.Since(t0))) },
	})
	req, err := speedNetReq(c, http.MethodGet, "/__down?bytes=0", nil)
	if err != nil {
		return 0, nil, "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, speedNetCode(ctx, err, 0)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, speedNetCode(ctx, nil, resp.StatusCode)
	}
	w, f := wrote.Load(), first.Load()
	if w <= 0 || f < w {
		return 0, nil, "net-unreachable"
	}
	timing := strings.Join(resp.Header.Values("Server-Timing"), ", ")
	ms := float64(time.Duration(f-w).Microseconds())/1000 - speedNetServerMs(timing)
	return max(ms, 0.1), speedNetL4(timing), ""
}

// speedNetServerMs is the time Cloudflare's end says it spent: its request
// duration where it gives one, else the sum of its speed test's parts.
func speedNetServerMs(timing string) float64 {
	if m := speedNetReqRe.FindStringSubmatch(timing); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && v > 0 {
			return v
		}
	}
	var sum float64
	for _, m := range speedNetDurRe.FindAllStringSubmatch(timing, -1) {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && v > 0 {
			sum += v
		}
	}
	return sum
}

// speedNetL4 reads cfL4's desc: proto=TCP&rtt=…&min_rtt=…&retrans=…&sent=….
func speedNetL4(timing string) *speedTCP {
	m := speedNetL4Re.FindStringSubmatch(timing)
	if m == nil {
		return nil
	}
	kv := map[string]float64{}
	proto := ""
	for _, part := range strings.Split(m[1], "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if k == "proto" {
			proto = v
			continue
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			kv[k] = f
		}
	}
	if proto != "TCP" || kv["rtt"] <= 0 {
		return nil
	}
	return &speedTCP{Rtt: kv["rtt"], Min: kv["min_rtt"], Retrans: kv["retrans"], Sent: kv["sent"]}
}

// speedNetDownStream reads one download after another until its context
// ends.
func speedNetDownStream(ctx context.Context, hc *http.Client, m *speedMeter) string {
	for {
		code := speedNetDownOnce(ctx, hc, m)
		if ctx.Err() != nil {
			return ""
		}
		if code != "more" {
			return code
		}
	}
}

func speedNetDownOnce(ctx context.Context, hc *http.Client, m *speedMeter) string {
	req, err := speedNetReq(ctx, http.MethodGet, "/__down?bytes="+strconv.Itoa(speedNetDownBytes), nil)
	if err != nil {
		return "unavailable"
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ""
		}
		return "net-unreachable"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return speedNetCode(ctx, nil, resp.StatusCode)
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
			return ""
		case errors.Is(err, io.EOF):
			return "more"
		default:
			return "net-unreachable"
		}
	}
}

// speedNetUpStream sends pieces until stop, each counted when Cloudflare
// answers for it, each sized by speedNextPiece.
func speedNetUpStream(ctx context.Context, stop time.Time, hc *http.Client, m *speedMeter, rtt time.Duration) string {
	size := int64(speedPieceMin)
	for ctx.Err() == nil && time.Now().Before(stop) {
		t0 := time.Now()
		if code := speedNetUpOnce(ctx, hc, size); code != "" {
			if ctx.Err() != nil {
				return ""
			}
			return code
		}
		m.piece(t0, time.Now(), size)
		size = speedNextPiece(size, time.Since(t0), rtt, speedNetPieceMax)
	}
	return ""
}

// speedRepeat reads its buffer over and over: a piece of any size without
// holding one that size.
type speedRepeat struct {
	b []byte
	i int
}

func (r *speedRepeat) Read(p []byte) (int, error) {
	n := copy(p, r.b[r.i:])
	r.i = (r.i + n) % len(r.b)
	return n, nil
}

func speedNetUpOnce(ctx context.Context, hc *http.Client, size int64) string {
	req, err := speedNetReq(ctx, http.MethodPost, "/__up", io.LimitReader(&speedRepeat{b: speedBuf()}, size))
	if err != nil {
		return "unavailable"
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return speedNetCode(ctx, err, 0)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return speedNetCode(ctx, nil, resp.StatusCode)
	}
	return ""
}
