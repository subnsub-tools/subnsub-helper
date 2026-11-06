package main

// Service probes: the helper's own uptime checks.
//
// An HTTP / TCP / DNS prober driven by a file the operator writes on the
// machine, with uptime bookkeeping.
//
// The Service / ServiceSource wire shapes carry no
// URL, host, port or credential, and a prober that knows all of those is the
// place that promise is easiest to break. So the configuration lives in
// ~/.config/subnsub-helper/probes.json, owner-only, read by this process and
// nobody else, and the reading carries the operator's LABEL for a probe, its
// kind, its state and its numbers — never its target. The relay applies the
// same allowlist again, and the page has no
// field to show a target in even if one arrived.
//
//   {
//     "name": "Home services",              optional label for this machine's set
//     "probes": [
//       {"name": "Blog", "type": "http", "url": "https://blog.example.com"},
//       {"name": "API",  "type": "http", "url": "https://api.example.com/health",
//        "expect": [200, 204], "keyword": "\"ok\"", "interval": 30, "retries": 2},
//       {"name": "Postgres", "type": "tcp", "host": "10.0.0.5", "port": 5432},
//       {"name": "Zone",     "type": "dns", "host": "example.com",
//        "tags": {"env": "prod"}}
//     ]
//   }
//
// A bare array of probes is accepted too. Fields and defaults:
//
//   id           optional; [A-Za-z0-9_-]{1,48}. Derived from the target when
//                absent, so a probe keeps its history across a rename and
//                loses it when it is pointed somewhere else.
//   name         the label the dashboard shows (defaults to the id)
//   type         http | tcp | dns
//   url          http: the URL to fetch (http:// or https://, no userinfo)
//   host, port   tcp: what to connect to; dns: the name to resolve (no port)
//   interval     seconds between checks, 15…3600, default 60
//   timeout      seconds per check, 1…60, default 10
//   method       http: GET (default) or HEAD
//   expect       http: acceptable status codes, default 200…299
//   keyword      http: text the body must contain (first 1 MiB)
//   insecure     http: skip TLS verification; the certificate is then judged
//                by its dates alone
//   retries      failed checks tolerated before "down" (shown as "pending"
//                meanwhile), default 0
//   maintenance  true parks the probe: reported as maintenance, never checked
//   tags         free labels shown on the card; keys that look like a target
//                or a credential are dropped (privateTagKey)
//
// The file is re-read whenever it changes on disk; a broken file keeps the
// last good set running and flags the source as bad-config, and
// `subnsub-helper probes` on the machine says what is wrong. Results are
// summarised into hourly buckets for two days and daily buckets for a year
// in probes-state.json beside the config, which is what the 24 h / 30 d /
// 365 d uptime figures are computed from — nothing finer is kept, and nothing
// is kept at all about WHY a check failed.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	probesFile      = "probes.json"
	probesStateFile = "probes-state.json"
	probesKeyFile   = "probes.key"
	probeSourceID   = "probes"
	// The relay admits 64 services per machine (clean.js SERVICE_MAX); a
	// 65th would be dropped there, so it is refused here where the operator
	// can see why.
	maxProbes     = 64
	maxProbesFile = 256 << 10
	maxProbeState = 4 << 20
	maxProbeBody  = 1 << 20
	maxProbeTags  = 8

	probeDefaultEvery   = 60.0
	probeMinEvery       = 15.0
	probeMaxEvery       = 3600.0
	probeDefaultTimeout = 10.0
	probeMaxTimeout     = 60.0
	probeMaxRetries     = 10
	probeMaxRedirects   = 5
	probeWorkers        = 8
	probeTick           = 5 * time.Second
	probeSaveEvery      = 60.0
	probeRereadEvery    = 300.0

	probeHourKeep = 48  // hourly buckets: two days, so "24 h" is always whole
	probeDayKeep  = 400 // daily buckets: a year and change
)

// Service and ServiceSource are the wire. They predate this file (the Kuma
// reader used the same shapes) and the relay's allowlist is written against
// them: a new field here is a field clean.js drops until it is taught it.
type ServiceTag struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}
type Service struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Type       string       `json:"type,omitempty"`
	Status     int          `json:"status"` // 0 down, 1 up, 2 pending, 3 maintenance
	ResponseMS *float64     `json:"response_ms,omitempty"`
	Uptime24h  *float64     `json:"uptime_24h,omitempty"`
	Uptime30d  *float64     `json:"uptime_30d,omitempty"`
	Uptime365d *float64     `json:"uptime_365d,omitempty"`
	CertValid  *bool        `json:"cert_valid,omitempty"`
	CertDays   *float64     `json:"cert_days,omitempty"`
	Source     string       `json:"source"`
	Tags       []ServiceTag `json:"tags,omitempty"`
}
type ServiceSource struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	LastOKAt *float64 `json:"last_ok_at,omitempty"`
}

const (
	serviceDown        = 0
	serviceUp          = 1
	servicePending     = 2
	serviceMaintenance = 3
)

// ── configuration ──────────────────────────────────────────────────────────

type probeSpec struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Interval    float64           `json:"interval"`
	Timeout     float64           `json:"timeout"`
	Method      string            `json:"method"`
	Expect      []int             `json:"expect"`
	Keyword     string            `json:"keyword"`
	Insecure    bool              `json:"insecure"`
	Retries     int               `json:"retries"`
	Maintenance bool              `json:"maintenance"`
	Tags        map[string]string `json:"tags"`
}

type probeConfig struct {
	Name   string      `json:"name"`
	Probes []probeSpec `json:"probes"`
}

var probeIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)

func probesPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, probesFile)
}

// readPrivateFile is installedEnv's discipline for a file in the config
// directory: a regular file, checked on the open handle, refused whole when
// over the cap. Returns (nil, nil) when there is no such file.
func readPrivateFile(path string, max int) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	buf := make([]byte, max+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	if n > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return buf[:n], nil
}

// loadProbeConfig reads and validates the file. present is false when there
// is no file at all — the ordinary state of a machine that runs no probes,
// which reports no source rather than an empty one.
func loadProbeConfig() (cfg probeConfig, present bool, err error) {
	path := probesPath()
	if path == "" {
		return cfg, false, nil
	}
	raw, err := readPrivateFile(path, maxProbesFile)
	if err != nil {
		return cfg, true, err
	}
	if raw == nil {
		return cfg, false, nil
	}
	return parseProbeConfig(raw)
}

func parseProbeConfig(raw []byte) (cfg probeConfig, present bool, err error) {
	body := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if body == "" {
		return cfg, false, nil
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if strings.HasPrefix(body, "[") {
		err = dec.Decode(&cfg.Probes)
	} else {
		err = dec.Decode(&cfg)
	}
	if err == nil {
		// One document and nothing after it. A second value — or half of
		// one — is not "the first value plus noise", it is a file that is
		// not what it seems, and the last good set stays.
		if _, tail := dec.Token(); tail != io.EOF {
			err = errors.New("trailing data after the JSON document")
		}
	}
	if err != nil {
		return cfg, true, fmt.Errorf("probes.json: %v", err)
	}
	cfg.Name = cleanText(cfg.Name, 48)
	if len(cfg.Probes) > maxProbes {
		return cfg, true, fmt.Errorf("probes.json: %d probes, the dashboard shows at most %d per machine", len(cfg.Probes), maxProbes)
	}
	seen := map[string]bool{}
	for i := range cfg.Probes {
		p := &cfg.Probes[i]
		if err := normaliseProbe(p); err != nil {
			return cfg, true, fmt.Errorf("probes.json: probe %d (%s): %v", i+1, p.Name, err)
		}
		if seen[p.ID] {
			return cfg, true, fmt.Errorf("probes.json: probe %d (%s): id %q is used twice", i+1, p.Name, p.ID)
		}
		seen[p.ID] = true
	}
	return cfg, true, nil
}

// normaliseProbe fills defaults and refuses what cannot be checked. The
// target fields are validated but never copied anywhere the reading can see.
func normaliseProbe(p *probeSpec) error {
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.URL = strings.TrimSpace(p.URL)
	p.Host = strings.TrimSpace(p.Host)
	p.Name = cleanText(p.Name, 80)
	var target string
	switch p.Type {
	case "http":
		if p.Host != "" || p.Port != 0 {
			return errors.New("an http probe takes a url, not host/port")
		}
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return errors.New("url must be http:// or https:// with a host and no credentials")
		}
		p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
		switch p.Method {
		case "":
			p.Method = "GET"
		case "GET", "HEAD":
		default:
			return errors.New("method must be GET or HEAD")
		}
		if p.Method == "HEAD" && p.Keyword != "" {
			return errors.New("keyword needs a body, so it cannot go with HEAD")
		}
		for _, c := range p.Expect {
			if c < 100 || c > 599 {
				return fmt.Errorf("expect: %d is not an HTTP status", c)
			}
		}
		if len(p.Keyword) > 256 {
			return errors.New("keyword is longer than 256 bytes")
		}
		target = u.String()
	case "tcp":
		if p.URL != "" {
			return errors.New("a tcp probe takes host and port, not a url")
		}
		if p.Host == "" || (strings.ContainsAny(p.Host, " /:@") && net.ParseIP(p.Host) == nil) {
			return errors.New("host must be a hostname or an IP address")
		}
		if p.Port < 1 || p.Port > 65535 {
			return errors.New("port must be 1…65535")
		}
		target = net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	case "dns":
		if p.URL != "" || p.Port != 0 {
			return errors.New("a dns probe takes a host only")
		}
		if p.Host == "" || strings.ContainsAny(p.Host, " /:@") {
			return errors.New("host must be a name to resolve")
		}
		target = p.Host
	default:
		return errors.New("type must be http, tcp or dns")
	}
	if p.Keyword != "" && p.Type != "http" {
		return errors.New("keyword only applies to http probes")
	}
	if p.Insecure && p.Type != "http" {
		return errors.New("insecure only applies to http probes")
	}
	if len(p.Expect) > 0 && p.Type != "http" {
		return errors.New("expect only applies to http probes")
	}
	p.ID = strings.TrimSpace(p.ID)
	if p.ID == "" {
		p.ID = derivedProbeID(p.Type, target)
	} else if !probeIDRe.MatchString(p.ID) {
		return errors.New("id may only use letters, digits, - and _ (48 at most)")
	}
	if p.Name == "" {
		p.Name = p.ID
	}
	switch {
	case p.Interval == 0:
		p.Interval = probeDefaultEvery
	case p.Interval < probeMinEvery || p.Interval > probeMaxEvery:
		return fmt.Errorf("interval must be %v…%v seconds", probeMinEvery, probeMaxEvery)
	}
	switch {
	case p.Timeout == 0:
		p.Timeout = probeDefaultTimeout
	case p.Timeout < 1 || p.Timeout > probeMaxTimeout:
		return fmt.Errorf("timeout must be 1…%v seconds", probeMaxTimeout)
	}
	if p.Timeout > p.Interval {
		p.Timeout = p.Interval
	}
	if p.Retries < 0 || p.Retries > probeMaxRetries {
		return fmt.Errorf("retries must be 0…%d", probeMaxRetries)
	}
	if len(p.Tags) > maxProbeTags*2 {
		return fmt.Errorf("at most %d tags", maxProbeTags)
	}
	return nil
}

// derivedProbeID names a probe after its target without saying what the
// target is. A plain hash would: the id travels to the relay and the
// dashboard, and "hash of type+target" is a dictionary attack away from
// 10.0.0.5:5432 for anyone holding it. So it is an HMAC under a key that
// exists only on this machine — random, owner-only, minted on first use
// beside the config — which keeps the id stable across renames and restarts
// and worthless to anyone who has not read that file.
func derivedProbeID(typ, target string) string {
	mac := hmac.New(sha256.New, probeIDKey())
	mac.Write([]byte(typ + "\x00" + target))
	return "p-" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
}

var probeKey struct {
	sync.Once
	key []byte
}

func probeIDKey() []byte {
	probeKey.Do(func() {
		dir := configDir()
		path := filepath.Join(dir, probesKeyFile)
		if dir != "" {
			if raw, err := readPrivateFile(path, 256); err == nil && len(raw) >= 32 {
				probeKey.key = raw
				return
			}
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic("probes: no randomness: " + err.Error())
		}
		probeKey.key = key
		if dir == "" {
			return
		}
		// Persist, so ids outlive this process; a machine that cannot keep
		// the file gets per-run ids and a line saying why the dashboard's
		// service history will restart with the helper.
		if err := os.MkdirAll(dir, 0o700); err == nil {
			tmp := path + ".new"
			if err := os.WriteFile(tmp, key, 0o600); err == nil {
				err = os.Rename(tmp, path)
			}
			if err != nil {
				warnf("probes: could not keep the id key (%v): derived probe ids change on every restart", err)
			}
		}
	})
	return probeKey.key
}

// ── one check ──────────────────────────────────────────────────────────────

type probeResult struct {
	at        float64
	ok        bool
	ms        float64
	certValid *bool
	certDays  *float64
	// Why, for the operator's terminal only. Never leaves the process.
	err string
}

func runProbe(ctx context.Context, p probeSpec) probeResult {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Timeout*float64(time.Second)))
	defer cancel()
	start := time.Now()
	var res probeResult
	switch p.Type {
	case "http":
		res = probeHTTP(ctx, p)
	case "tcp":
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
		if err != nil {
			res.err = err.Error()
		} else {
			c.Close()
			res.ok = true
		}
	case "dns":
		addrs, err := net.DefaultResolver.LookupHost(ctx, p.Host)
		switch {
		case err != nil:
			res.err = err.Error()
		case len(addrs) == 0:
			res.err = "no addresses"
		default:
			res.ok = true
		}
	}
	res.at = now()
	res.ms = float64(time.Since(start).Microseconds()) / 1000
	res.ms = float64(int(res.ms*10+0.5)) / 10
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && !res.ok {
		res.err = "timed out after " + strconv.FormatFloat(p.Timeout, 'f', -1, 64) + " s"
	}
	return res
}

func probeHTTP(ctx context.Context, p probeSpec) probeResult {
	var res probeResult
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		res.err = "no http transport"
		return res
	}
	tr = tr.Clone()
	tr.DisableKeepAlives = true
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: p.Insecure} //nolint:gosec // the operator asked, per probe
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= probeMaxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, nil)
	if err != nil {
		res.err = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "subnsub-helper/"+helperVersion)
	req.Header.Set("Accept", "*/*")
	r, err := client.Do(req)
	if err != nil {
		res.err = err.Error()
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			res.certValid = bp(false)
		}
		return res
	}
	defer r.Body.Close()
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		nowT := time.Now()
		days := leaf.NotAfter.Sub(nowT).Hours() / 24
		res.certDays = fp(float64(int(days*10)) / 10)
		// Verified by the handshake unless the operator turned that off, in
		// which case the dates are all we can vouch for.
		res.certValid = bp(!nowT.Before(leaf.NotBefore) && nowT.Before(leaf.NotAfter))
	}
	if !statusExpected(r.StatusCode, p.Expect) {
		res.err = "HTTP " + strconv.Itoa(r.StatusCode)
		return res
	}
	if p.Keyword != "" {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxProbeBody))
		if err != nil {
			res.err = "body: " + err.Error()
			return res
		}
		if !strings.Contains(string(b), p.Keyword) {
			res.err = "keyword not found"
			return res
		}
	}
	res.ok = true
	return res
}

func statusExpected(code int, expect []int) bool {
	if len(expect) == 0 {
		return code >= 200 && code <= 299
	}
	for _, c := range expect {
		if c == code {
			return true
		}
	}
	return false
}

// ── bookkeeping ────────────────────────────────────────────────────────────

// A bucket is how many checks fell in a window and how many passed. Hourly
// for two days, daily for a year: enough for the three uptime figures the
// card shows, and small enough that sixty probes' worth rewrites in a blink.
type probeBucket struct {
	T  int64 `json:"t"`
	OK int   `json:"ok"`
	N  int   `json:"n"`
}
type probeRecord struct {
	Hours []probeBucket `json:"h,omitempty"`
	Days  []probeBucket `json:"d,omitempty"`
}
type probeStateFile struct {
	V      int                     `json:"v"`
	Probes map[string]*probeRecord `json:"probes"`
}

func (r *probeRecord) add(at float64, ok bool) {
	r.Hours = bucketAdd(r.Hours, int64(at)/3600*3600, ok, probeHourKeep)
	r.Days = bucketAdd(r.Days, int64(at)/86400*86400, ok, probeDayKeep)
}

func bucketAdd(list []probeBucket, t int64, ok bool, keep int) []probeBucket {
	n := len(list)
	if n == 0 || list[n-1].T != t {
		if n > 0 && list[n-1].T > t {
			// The clock went backwards. Fold into the newest bucket rather
			// than open one in the past.
			t = list[n-1].T
		} else {
			list = append(list, probeBucket{T: t})
			n++
		}
	}
	b := &list[n-1]
	b.N++
	if ok {
		b.OK++
	}
	if n > keep {
		list = append(list[:0], list[n-keep:]...)
	}
	return list
}

// ratio over the buckets from `since` on, as a percentage; nil with no data.
func bucketRatio(list []probeBucket, since int64) *float64 {
	var ok, n int
	for _, b := range list {
		if b.T >= since {
			ok += b.OK
			n += b.N
		}
	}
	if n == 0 {
		return nil
	}
	v := float64(ok) * 100 / float64(n)
	return fp(float64(int(v*1000+0.5)) / 1000)
}

// ── the engine ─────────────────────────────────────────────────────────────

type probeRun struct {
	spec probeSpec
	// Bumped whenever the spec changes under a running check, so the check
	// that was started against the OLD spec finds out on return and reports
	// nothing: its result describes a target that is no longer configured.
	gen     int
	next    float64
	running bool
	fails   int
	last    *probeResult
	rec     *probeRecord
}

var probes struct {
	sync.Mutex
	on bool
	// The config as last read, and what the file looked like then. A change
	// in size or mtime is a re-read; a re-read that fails keeps `runs` and
	// records the failure for the source.
	cfg     probeConfig
	present bool
	cfgErr  string
	cfgOKAt *float64
	fileMod time.Time
	fileLen int64
	readAt  float64
	checked bool
	runs    map[string]*probeRun
	order   []string
	dirty   bool
	savedAt float64
	sem     chan struct{}
}

// startProbes begins the background scheduler. Idempotent, like
// startSysSampler, and called from the same places: the long-running modes.
// A one-shot collection (`subnsub-helper` with no verb) never calls this
// and runs one round synchronously instead — see collectProbes.
func startProbes() {
	probes.Lock()
	if probes.on {
		probes.Unlock()
		return
	}
	probes.on = true
	probes.sem = make(chan struct{}, probeWorkers)
	probes.runs = map[string]*probeRun{}
	probes.Unlock()
	probesReload(true)
	go func() {
		t := time.NewTicker(probeTick)
		defer t.Stop()
		for range t.C {
			probesReload(false)
			probesRunDue()
			probesSave(false)
		}
	}()
}

// probesReload re-reads the file when it changed (or on `force`), rebuilding
// the run table so probes that survived keep their streak and their
// history, new ones start at once, and removed ones take their records with
// them — the state file is bounded by the config, not by everything that
// was ever configured.
func probesReload(force bool) {
	path := probesPath()
	probes.Lock()
	defer probes.Unlock()
	var mod time.Time
	var size int64
	if path != "" {
		if fi, err := os.Lstat(path); err == nil {
			mod, size = fi.ModTime(), fi.Size()
		}
	}
	// Size and mtime catch every ordinary edit; an edit of the same length
	// inside one mtime tick would not show, so the file is also re-read on
	// a slow clock regardless. Reading it is cheap and the run table is
	// rebuilt only where the spec actually changed.
	if !force && probes.checked && mod.Equal(probes.fileMod) && size == probes.fileLen &&
		now()-probes.readAt < probeRereadEvery {
		return
	}
	probes.checked, probes.fileMod, probes.fileLen, probes.readAt = true, mod, size, now()
	cfg, present, err := loadProbeConfig()
	if err != nil {
		probes.cfgErr = "bad-config"
		probes.present = true
		warnf("probes: %v (the last good configuration keeps running)", err)
		return
	}
	probes.cfgErr = ""
	probes.present = present
	t := now()
	probes.cfgOKAt = &t
	if !present {
		cfg = probeConfig{}
	}
	if len(probes.runs) == 0 && len(cfg.Probes) > 0 {
		probesLoadState(cfg)
	}
	probes.cfg = cfg
	keep := map[string]*probeRun{}
	order := make([]string, 0, len(cfg.Probes))
	for _, p := range cfg.Probes {
		r := probes.runs[p.ID]
		if r == nil {
			r = &probeRun{}
		}
		if r.rec == nil {
			r.rec = &probeRecord{}
		}
		// A changed probe is a new probe with an old history: it checks on
		// its new terms from now, its streak starts over, and whatever check
		// is in flight against the previous terms is disowned (gen).
		if !reflect.DeepEqual(r.spec, p) {
			r.gen++
			r.next = 0
			r.fails = 0
			r.last = nil
		}
		r.spec = p
		keep[p.ID] = r
		order = append(order, p.ID)
	}
	if len(keep) != len(probes.runs) {
		probes.dirty = true
	}
	probes.runs, probes.order = keep, order
}

// probesLoadState brings the buckets back from the last run of this process,
// for the ids still configured. Called with the lock held, once, before the
// first round; a state file that cannot be read is a year of uptime figures
// starting over, which is annoying and nothing worse.
func probesLoadState(cfg probeConfig) {
	dir := configDir()
	if dir == "" {
		return
	}
	raw, err := readPrivateFile(filepath.Join(dir, probesStateFile), maxProbeState)
	if err != nil || raw == nil {
		return
	}
	var st probeStateFile
	if json.Unmarshal(raw, &st) != nil || st.V != 1 {
		return
	}
	for _, p := range cfg.Probes {
		rec := st.Probes[p.ID]
		if rec == nil {
			continue
		}
		t := int64(now())
		rec.Hours = cleanBuckets(rec.Hours, probeHourKeep, t/3600*3600)
		rec.Days = cleanBuckets(rec.Days, probeDayKeep, t/86400*86400)
		probes.runs[p.ID] = &probeRun{rec: rec}
	}
}

// cleanBuckets refuses a hand-edited file's nonsense rather than dividing by
// it: buckets in order, counts sane, none later than the bucket we are in
// now (a bucket from 2099 would be counted in every window AND, being the
// newest, would swallow every result after it — bucketAdd folds a clock
// that went backwards into the newest bucket), and the newest `keep` only.
func cleanBuckets(list []probeBucket, keep int, latest int64) []probeBucket {
	out := list[:0]
	var last int64
	for _, b := range list {
		if b.T <= last || b.T > latest || b.N < 0 || b.OK < 0 || b.OK > b.N || b.N > 1<<20 {
			continue
		}
		out = append(out, b)
		last = b.T
	}
	if len(out) > keep {
		out = out[len(out)-keep:]
	}
	return out
}

func probesRunDue() {
	t := now()
	probes.Lock()
	var due []*probeRun
	for _, id := range probes.order {
		r := probes.runs[id]
		if r.running || r.spec.Maintenance || r.next > t {
			continue
		}
		r.running = true
		due = append(due, r)
	}
	probes.Unlock()
	for _, r := range due {
		r := r
		spec, gen := r.spec, r.gen
		go func() {
			probes.sem <- struct{}{}
			res := runProbe(context.Background(), spec)
			<-probes.sem
			probes.Lock()
			r.running = false
			// The table may have been rebuilt underneath us, or this probe
			// rewritten: a result for terms that are no longer configured
			// reports to nobody, and the rewritten probe keeps the immediate
			// first check the reload gave it.
			if probes.runs[spec.ID] == r && r.gen == gen {
				r.next = now() + spec.Interval
				probeRecordResult(r, res)
				probes.dirty = true
			}
			probes.Unlock()
		}()
	}
}

func probeRecordResult(r *probeRun, res probeResult) {
	r.last = &res
	if res.ok {
		r.fails = 0
	} else {
		r.fails++
	}
	// A retry in progress is not downtime yet — it becomes one when the
	// retries are spent. The bucket agrees with the card.
	r.rec.add(res.at, res.ok || r.fails <= r.spec.Retries)
}

// probesSave writes the buckets, at most once a minute unless forced. Same
// write-then-rename, owner-only discipline as the id and the name.
func probesSave(force bool) {
	probes.Lock()
	if !probes.dirty || (!force && now()-probes.savedAt < probeSaveEvery) {
		probes.Unlock()
		return
	}
	st := probeStateFile{V: 1, Probes: map[string]*probeRecord{}}
	for id, r := range probes.runs {
		if r.rec != nil && (len(r.rec.Hours) > 0 || len(r.rec.Days) > 0) {
			// Copies, not slice headers: the marshal below runs unlocked
			// while checks keep counting into these buckets.
			st.Probes[id] = &probeRecord{
				Hours: append([]probeBucket(nil), r.rec.Hours...),
				Days:  append([]probeBucket(nil), r.rec.Days...),
			}
		}
	}
	probes.dirty = false
	probes.savedAt = now()
	probes.Unlock()
	dir := configDir()
	if dir == "" {
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, probesStateFile)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		warnf("probes: could not save history: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		warnf("probes: could not save history: %v", err)
	}
}

// serviceOf is the reading's view of one probe: label, kind, state and
// numbers. The spec's target fields are right there and none of them is
// copied; that is the whole privacy story, so keep it in one place.
func serviceOf(r *probeRun, t float64) Service {
	s := Service{ID: r.spec.ID, Name: r.spec.Name, Type: r.spec.Type, Source: probeSourceID,
		Tags: probeTags(r.spec.Tags)}
	switch {
	case r.spec.Maintenance:
		s.Status = serviceMaintenance
	case r.last == nil:
		s.Status = servicePending
	case r.last.ok:
		s.Status = serviceUp
	case r.fails <= r.spec.Retries:
		s.Status = servicePending
	default:
		s.Status = serviceDown
	}
	if r.last != nil {
		if r.last.ok {
			s.ResponseMS = fp(r.last.ms)
		}
		s.CertValid, s.CertDays = r.last.certValid, r.last.certDays
	}
	if r.rec != nil {
		s.Uptime24h = bucketRatio(r.rec.Hours, int64(t)-86400)
		s.Uptime30d = bucketRatio(r.rec.Days, int64(t)-30*86400)
		s.Uptime365d = bucketRatio(r.rec.Days, int64(t)-365*86400)
	}
	return s
}

// collectProbes is what the snapshot carries. With the scheduler running it
// is a read of the table; without one (a one-shot `subnsub-helper`) it runs
// every probe once, in parallel, and reports that — so the JSON a person
// prints at the terminal shows their services too, without the daemon.
func collectProbes() ([]Service, []ServiceSource) {
	probes.Lock()
	on := probes.on
	probes.Unlock()
	if !on {
		return collectProbesOnce()
	}
	probes.Lock()
	defer probes.Unlock()
	if !probes.present {
		return nil, nil
	}
	src := ServiceSource{ID: probeSourceID, Name: probes.cfg.Name, OK: probes.cfgErr == "", Error: probes.cfgErr, LastOKAt: probes.cfgOKAt}
	t := now()
	out := make([]Service, 0, len(probes.order))
	for _, id := range probes.order {
		out = append(out, serviceOf(probes.runs[id], t))
	}
	return out, []ServiceSource{src}
}

func collectProbesOnce() ([]Service, []ServiceSource) {
	cfg, present, err := loadProbeConfig()
	if !present {
		return nil, nil
	}
	src := ServiceSource{ID: probeSourceID, Name: cfg.Name}
	if err != nil {
		src.Error = "bad-config"
		return nil, []ServiceSource{src}
	}
	t := now()
	src.OK, src.LastOKAt = true, &t
	runs := probeRound(cfg)
	out := make([]Service, 0, len(runs))
	for _, r := range runs {
		out = append(out, serviceOf(r, now()))
	}
	return out, []ServiceSource{src}
}

// probeRound checks every probe in the set once, in parallel, bounded by the
// same worker count as the scheduler. No history: a round that ran once has
// nothing to summarise.
func probeRound(cfg probeConfig) []*probeRun {
	sem := make(chan struct{}, probeWorkers)
	runs := make([]*probeRun, len(cfg.Probes))
	var wg sync.WaitGroup
	for i, p := range cfg.Probes {
		runs[i] = &probeRun{spec: p}
		if p.Maintenance {
			continue
		}
		wg.Add(1)
		go func(r *probeRun) {
			defer wg.Done()
			sem <- struct{}{}
			res := runProbe(context.Background(), r.spec)
			<-sem
			r.last = &res
			if !res.ok {
				r.fails = r.spec.Retries + 1
			}
		}(runs[i])
	}
	wg.Wait()
	return runs
}

// ── the terminal ───────────────────────────────────────────────────────────

// `subnsub-helper probes`: read the file, say what is wrong with it, run one
// round and print each probe's verdict — WITH the reason, because this is
// the operator's own terminal on the operator's own machine, the one place
// the target and the error may appear.
func runProbesCLI(args []string) int {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		default:
			warnf("usage: subnsub-helper probes [--json]")
			return 2
		}
	}
	path := probesPath()
	cfg, present, err := loadProbeConfig()
	if err != nil {
		warnf("%v", err)
		return 2
	}
	if !present {
		warnf("no probes configured: write %s (see the helper README for the format)", path)
		return 2
	}
	runs := probeRound(cfg)
	if asJSON {
		out := make([]Service, 0, len(runs))
		for _, r := range runs {
			out = append(out, serviceOf(r, now()))
		}
		fmt.Println(string(dumpIndent(out)))
	}
	down := 0
	for _, r := range runs {
		s := serviceOf(r, now())
		verdict := "up"
		switch s.Status {
		case serviceDown:
			verdict, down = "DOWN", down+1
		case servicePending:
			verdict = "pending"
		case serviceMaintenance:
			verdict = "maintenance"
		}
		line := fmt.Sprintf("%-11s %-32s %-4s", verdict, r.spec.Name, r.spec.Type)
		if r.last != nil && r.last.ok {
			line += fmt.Sprintf(" %8.1f ms", r.last.ms)
		}
		if s.CertDays != nil {
			line += fmt.Sprintf("  TLS %.0f d", *s.CertDays)
			if s.CertValid != nil && !*s.CertValid {
				line += " (invalid)"
			}
		}
		if r.last != nil && !r.last.ok {
			line += "  " + r.last.err
		}
		if !asJSON {
			fmt.Println(line)
		} else {
			warnf("%s", line)
		}
	}
	if down > 0 {
		return 1
	}
	return 0
}

// ── text ───────────────────────────────────────────────────────────────────

// probeTags: the operator's labels, cleaned and bounded, minus any whose KEY
// suggests it holds a target or a credential. The value is not inspected —
// "env: prod" is fine and "env: https://…" is the operator's own choice to
// publish — but a key like "url" or "token" is refused whatever its value.
func probeTags(m map[string]string) []ServiceTag {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !privateTagKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxProbeTags {
		keys = keys[:maxProbeTags]
	}
	out := make([]ServiceTag, 0, len(keys))
	for _, raw := range keys {
		k := cleanText(raw, 24)
		v := cleanText(m[raw], 48)
		if k != "" {
			out = append(out, ServiceTag{k, v})
		}
	}
	return out
}

// privateTagKey mirrors clean.js's PRIVATE_TAG_KEY: the two are one rule.
func privateTagKey(key string) bool {
	lower := strings.ToLower(key)
	for _, part := range []string{
		"url", "uri", "host", "port", "user", "pass", "token", "secret",
		"auth", "credential", "endpoint", "address",
	} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	if strings.Contains(lower, "api") && strings.Contains(lower, "key") {
		return true
	}
	for _, part := range strings.FieldsFunc(lower, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if part == "ip" {
			return true
		}
	}
	return lower == "ip"
}
