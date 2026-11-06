package main

// CLI Proxy API: the quota of every credential a local proxy holds.
//
// CLI Proxy API (router-for-me/CLIProxyAPI, "CPA") is a proxy people run on
// their own machine to pool the OAuth credentials of several AI coding tools
// behind one endpoint. It keeps those credentials, refreshes them, and — the
// part that matters here — will make an authenticated request to the vendor
// on a caller's behalf: POST /v0/management/api-call with a credential's
// auth_index and a request whose `$TOKEN$` placeholder CPA fills in itself.
// Its management console reads every account's quota exactly that way, and so
// does this: the vendor endpoints and headers come from adapters.json, the
// credential never crosses into this process, and the answer is the same
// percentage every other provider here publishes.
//
// Which puts this on a rung of its own, and the rung has to be named
// honestly: what this program holds is CPA's MANAGEMENT KEY. That key is not a
// vendor credential, but it is not nothing either — it is the key to a service
// that holds every vendor credential, and CPA scopes it to nothing narrower.
// So it is treated like the Claude token (0600 under the install directory,
// never published, never in an error line), it is only ever sent to the
// address the operator configured (loopback, or HTTPS), and the only
// management endpoints this program will call are the two above. Nothing
// here downloads a credential file, and nothing here writes one.
//
// Precedence: a vendor CPA holds a credential for is
// read through CPA and the native collector's reading for that vendor is set
// aside; a vendor CPA has no credential for keeps its native collector. CPA
// itself being unreachable or refusing the key costs nothing native — the
// natives run regardless — and shows as one failed `cpa` tile that names what
// to fix. See mergeCPA in types.go.
//
// One CPA credential is one tile. The first credential of a vendor takes the
// vendor's plain id ("claude") so it lands where the native reading used to;
// the rest take an ordinal suffix ("claude@2"), and every one carries the
// account it belongs to in `account`, which is how the page tells them apart.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	cpaURLEnv     = "MON_CPA_URL"
	cpaKeyEnv     = "MON_CPA_KEY"
	cpaDefaultURL = "http://127.0.0.1:8317"

	// The credential list changes when somebody logs a tool in, which is
	// rarely; the quota behind each is a vendor call and takes provhttp's
	// floor. Both are throttled independently of the push loop.
	cpaListInterval = 120.0
	cpaTimeout      = 15 * time.Second
	cpaMaxBody      = 1 << 20
	// Tiles are a finite resource on a card and rows are a finite resource in
	// the relay (it keeps 24 provider ids per frame). Sorted by auth_index,
	// so which credentials make the cut is stable across pushes.
	cpaMaxPerVendor = 6
	cpaMaxCreds     = 18
	cpaParallel     = 4
)

// The hosts an adapter may name. The table can move a path, a header or a
// field; it cannot point a credential at a new origin, because that is the
// one change that would turn a table update into a token exfiltration.
var cpaHostSuffixes = []string{
	"api.anthropic.com",
	"chatgpt.com",
	"googleapis.com",
	"api.kimi.com",
	// Kimi's international accounts answer on kimi.ai (2026.10.07.2).
	"api.kimi.ai",
	"grok.com",
	"api.x.ai",
	// Devin's seat-management service, read through CPA (2026.10.07.2).
	"server.codeium.com",
}

func cpaHostAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	for _, s := range cpaHostSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

type cpaConfig struct {
	base *url.URL
	key  string
}

// The operator's CPA settings, or a config with no base when there are none.
// The second value is a detail code when the settings are unusable.
func loadCPAConfig() (cpaConfig, string) {
	f := installedEnv()
	rawURL := strings.TrimSpace(envSetting(cpaURLEnv, f))
	key := strings.TrimSpace(envSetting(cpaKeyEnv, f))
	var c cpaConfig
	if rawURL == "" && key == "" {
		return c, ""
	}
	if rawURL == "" {
		rawURL = cpaDefaultURL
	}
	if key == "" || strings.IndexFunc(key, unicode.IsControl) >= 0 || len(key) > 512 {
		return c, "cpa-url"
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, "cpa-url"
	}
	host := u.Hostname()
	loop := strings.EqualFold(host, "localhost") ||
		(net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	if u.Scheme != "https" && !loop {
		// A management key over plain HTTP to another machine is a key on
		// the wire; the same rule the relay token follows.
		return c, "cpa-url"
	}
	u.Path = strings.TrimRight(u.Path, "/")
	c.base, c.key = u, key
	return c, ""
}

// What CPA said about one credential, kept to the fields the adapters can
// use. `raw` is the listing entry as sent, for the templates; it is never
// published and never logged.
type cpaCred struct {
	index   string
	vendor  string
	name    string
	account string
	raw     map[string]any
}

// The result of one pass: the readings, and — when CPA itself was the problem
// — what was wrong, for this program's own log. Never for the wire: CPA is a
// channel, not a vendor, and a channel is not a tile.
type cpaResult struct {
	configured bool
	providers  []Provider
	status     *Provider
}

var cpaCache struct {
	sync.Mutex
	listedAt float64
	creds    []cpaCred
	// The last listing that FAILED, and why: a listing is asked for on
	// every push, and a failure holds its answer for cpaListInterval too
	// so a CPA that is down or answering 401/404 is not asked every push.
	failAt  float64
	failWhy string
	per     map[string]*provCache
	// The last line said about the proxy itself, so a broken key is logged
	// once and not every thirty seconds.
	lastSaid string
}

// Say what is wrong with the proxy, once per distinct cause; clear when it
// answers again.
func cpaSay(p *Provider) {
	msg := ""
	if p != nil {
		msg = "cpa: " + p.Detail
	}
	cpaCache.Lock()
	changed := msg != cpaCache.lastSaid
	cpaCache.lastSaid = msg
	cpaCache.Unlock()
	if changed && msg != "" {
		warnf("%s", msg)
	}
}

func collectCPA() (out cpaResult) {
	defer func() {
		if r := recover(); r != nil {
			p := Provider{ID: "cpa", Name: "CLI Proxy API", Source: "cpa", CapturedAt: now()}
			p.failWith("collector-crashed", "collector-panic")
			cpaSay(&p)
			out = cpaResult{configured: true, status: &p}
		}
	}()
	cfg, code := loadCPAConfig()
	if cfg.base == nil && code == "" {
		return cpaResult{}
	}
	out.configured = true
	status := Provider{ID: "cpa", Name: "CLI Proxy API", Source: "cpa", CapturedAt: now()}
	if code != "" {
		status.failWith("unreachable", "cpa-url")
		cpaSay(&status)
		out.status = &status
		return out
	}

	creds, code := cpaListCreds(cfg)
	if code != "" {
		switch code {
		case "cpa-down":
			status.failWith("unreachable", "cpa-down")
		case "cpa-key":
			status.failWith("api-error", "cpa-key")
		case "cpa-off":
			status.failWith("api-error", "cpa-off")
		default:
			status.failWith("api-error", "cpa-shape")
		}
		cpaSay(&status)
		out.status = &status
		return out
	}
	cpaSay(nil)
	if len(creds) == 0 {
		return out
	}

	adapters := currentAdapters()
	results := make([]Provider, len(creds))
	var wg sync.WaitGroup
	sem := make(chan struct{}, cpaParallel)
	// Ids: the first of a vendor is the vendor; the rest are numbered. A
	// credential that produces nothing at all (an unknown vendor) does not
	// consume a number. Settled before the fetch, because each cache answers
	// to a press on its own tile by that id (pace.go).
	ids := make([]string, len(creds))
	seen := map[string]int{}
	for i, cr := range creds {
		ad := adapters.Vendors[cr.vendor]
		if ad == nil {
			continue
		}
		seen[ad.Provider]++
		ids[i] = ad.Provider
		if n := seen[ad.Provider]; n > 1 {
			ids[i] = ad.Provider + "@" + strconv.Itoa(n)
		}
		wg.Add(1)
		go func(i int, cr cpaCred, ad *vendorAdapter) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cache := cpaCacheFor(cr.index)
			results[i] = cache.collectAs(cpaMark(ids[i]), func() Provider {
				return safeCollect(ad.Provider, func() Provider { return cpaFetch(cfg, ad, cr) })
			})
		}(i, cr, ad)
	}
	wg.Wait()

	for i := range results {
		p := results[i]
		if p.ID == "" {
			continue
		}
		p.ID = ids[i]
		p.Account = creds[i].account
		if id := cpaAccountID(adapters.Vendors[creds[i].vendor], creds[i].raw); id != "" {
			p.AccountKey = accountKey(vendorOfID(p.ID), id)
		}
		out.providers = append(out.providers, p)
	}
	return out
}

// The ChatGPT account a Codex credential is, from the one place its own
// request already names it: the Chatgpt-Account-Id header, filled from the
// credential as the request fills it. ~/.codex/auth.json is keyed by that
// account (accountkey.go), not by the e-mail CPA names the credential after
// — one e-mail can hold a personal and a team account — so without this the
// same account read through CPA on one machine and from its file on another
// were two tiles. "" for any other vendor, or a credential that names none.
func cpaAccountID(ad *vendorAdapter, raw map[string]any) string {
	if ad == nil || ad.Provider != "codex" {
		return ""
	}
	for _, rq := range ad.Requests {
		for k, v := range rq.Headers {
			if strings.EqualFold(k, "Chatgpt-Account-Id") {
				if id := strings.TrimSpace(adapterTemplate(v, nil, raw)); id != "" {
					return id
				}
			}
		}
	}
	return ""
}

func cpaCacheFor(index string) *provCache {
	cpaCache.Lock()
	defer cpaCache.Unlock()
	if cpaCache.per == nil {
		cpaCache.per = map[string]*provCache{}
	}
	c := cpaCache.per[index]
	if c == nil {
		c = &provCache{}
		cpaCache.per[index] = c
	}
	return c
}

// The credentials CPA holds, from its listing — cached for cpaListInterval,
// and served stale rather than blank when a fresh listing fails.
func cpaListCreds(cfg cpaConfig) ([]cpaCred, string) {
	cpaCache.Lock()
	defer cpaCache.Unlock()
	t := now()
	if cpaCache.creds != nil && t-cpaCache.listedAt < cpaListInterval {
		return cpaCache.creds, ""
	}
	// A listing that failed within the interval is answered from that
	// failure, the way a success is answered from its listing: stale
	// credentials while they are not too old, otherwise the same reason.
	stale := func() ([]cpaCred, string, bool) {
		if cpaCache.creds != nil && t-cpaCache.listedAt < provStaleMax {
			return cpaCache.creds, "", true
		}
		return nil, "", false
	}
	if cpaCache.failAt > 0 && t-cpaCache.failAt < cpaListInterval {
		if cpaCache.failWhy == "cpa-down" {
			if creds, why, ok := stale(); ok {
				return creds, why
			}
		}
		return nil, cpaCache.failWhy
	}
	fail := func(why string) ([]cpaCred, string) {
		cpaCache.failAt, cpaCache.failWhy = t, why
		return nil, why
	}
	status, body, err := cpaRequest(cfg, "GET", "/v0/management/auth-files", nil)
	if err != nil {
		cpaCache.failAt, cpaCache.failWhy = t, "cpa-down"
		if creds, why, ok := stale(); ok {
			return creds, why
		}
		return nil, "cpa-down"
	}
	switch {
	case status == 401 || status == 403:
		return fail("cpa-key")
	case status == 404:
		return fail("cpa-off")
	case status != 200:
		return fail("cpa-shape")
	}
	creds, ok := parseCPAListing(body)
	if !ok {
		return fail("cpa-shape")
	}
	cpaCache.failAt, cpaCache.failWhy = 0, ""
	cpaCache.creds, cpaCache.listedAt = creds, t
	// Caches for credentials that are gone would otherwise live forever.
	if cpaCache.per != nil {
		keep := map[string]bool{}
		for _, c := range creds {
			keep[c.index] = true
		}
		for k := range cpaCache.per {
			if !keep[k] {
				delete(cpaCache.per, k)
			}
		}
	}
	return creds, ""
}

// CPA's vendor names, folded onto the adapter table's: the console accepts
// `provider` or `type`, snake or kebab, and calls xAI three things.
func cpaVendor(raw map[string]any) string {
	v, _ := raw["provider"].(string)
	if v == "" {
		v, _ = raw["type"].(string)
	}
	v = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), "_", "-")
	switch v {
	case "x-ai", "grok":
		return "xai"
	}
	return v
}

func parseCPAListing(body []byte) ([]cpaCred, bool) {
	var doc any
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	var files []any
	switch d := doc.(type) {
	case []any:
		files = d
	case map[string]any:
		files, _ = d["files"].([]any)
		if files == nil {
			if _, has := d["files"]; !has {
				return nil, false
			}
		}
	default:
		return nil, false
	}
	var out []cpaCred
	perVendor := map[string]int{}
	for _, f := range files {
		raw, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if dis, ok := adapterBool(raw["disabled"]); ok && dis {
			continue
		}
		vendor := cpaVendor(raw)
		if vendor == "" {
			continue
		}
		index := adapterStr(raw["auth_index"], 64)
		if index == "" {
			index = adapterStr(raw["authIndex"], 64)
		}
		if index == "" {
			continue
		}
		name := adapterStr(raw["name"], 120)
		account := adapterStr(raw["email"], 60)
		if account == "" {
			// The file name carries the account for every OAuth credential
			// CPA writes ("claude-someone@example.com.json"); the api-key
			// kind has no account and its `account` field IS the key, which
			// is why that field is never read here.
			account = strings.TrimSuffix(name, ".json")
		}
		out = append(out, cpaCred{index: index, vendor: vendor, name: name,
			account: cleanText(account, 60), raw: raw})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, aerr := strconv.ParseFloat(out[i].index, 64)
		b, berr := strconv.ParseFloat(out[j].index, 64)
		if aerr == nil && berr == nil && a != b {
			return a < b
		}
		if out[i].index != out[j].index {
			return out[i].index < out[j].index
		}
		return out[i].name < out[j].name
	})
	var kept []cpaCred
	for _, c := range out {
		if perVendor[c.vendor] >= cpaMaxPerVendor || len(kept) >= cpaMaxCreds {
			continue
		}
		perVendor[c.vendor]++
		kept = append(kept, c)
	}
	return kept, true
}

// One management request. The error is a category, never transport text —
// the URL carries nothing secret, but the habit is the point.
func cpaRequest(cfg cpaConfig, method, path string, body []byte) (int, []byte, error) {
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	var req *http.Request
	var err error
	if rd != nil {
		req, err = http.NewRequest(method, cfg.base.String()+path, rd)
	} else {
		req, err = http.NewRequest(method, cfg.base.String()+path, nil)
	}
	if err != nil {
		return 0, nil, errors.New("bad request")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.key)
	req.Header.Set("User-Agent", "subnsub-helper")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout: cpaTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errProvRedirect
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, nil, errProvRedirect
	}
	data, err := readBounded(resp.Body, cpaMaxBody)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// A vendor request made by CPA on a credential's behalf. Returns the vendor's
// status and body; `cpaErr` is set when CPA itself, not the vendor, failed.
func cpaAPICall(cfg cpaConfig, index, method, target string, header map[string]string, data string) (status int, body []byte, cpaErr string) {
	payload, err := json.Marshal(map[string]any{
		"auth_index": index,
		"method":     method,
		"url":        target,
		"header":     header,
		"data":       data,
	})
	if err != nil {
		return 0, nil, "cpa-shape"
	}
	st, raw, err := cpaRequest(cfg, "POST", "/v0/management/api-call", payload)
	if err != nil {
		return 0, nil, "cpa-down"
	}
	switch {
	case st == 401 || st == 403:
		return 0, nil, "cpa-key"
	case st == 404:
		return 0, nil, "cpa-off"
	case st != 200:
		return 0, nil, "cpa-shape"
	}
	var env struct {
		StatusCode any             `json:"status_code"`
		Body       json.RawMessage `json:"body"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return 0, nil, "cpa-shape"
	}
	sc, ok := adapterNum(anyOf(env.StatusCode))
	if !ok {
		return 0, nil, "cpa-shape"
	}
	// The vendor body arrives either as the JSON CPA received (an object) or
	// as text (a string holding JSON); both end up as bytes here.
	var asText string
	if len(env.Body) > 0 && env.Body[0] == '"' {
		if json.Unmarshal(env.Body, &asText) == nil {
			return int(sc), []byte(asText), ""
		}
	}
	return int(sc), []byte(env.Body), ""
}

func anyOf(v any) any {
	switch x := v.(type) {
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return v
}

// The reading for one CPA credential: the table's requests, sent by CPA.
func cpaFetch(cfg cpaConfig, ad *vendorAdapter, cr cpaCred) Provider {
	p := Provider{ID: ad.Provider, Name: ad.Name, Source: "cpa", CapturedAt: now()}
	send := func(method, target string, header map[string]string, data string) (int, []byte, *Provider) {
		status, body, cpaErr := cpaAPICall(cfg, cr.index, method, target, header, data)
		switch cpaErr {
		case "":
			return status, body, nil
		case "cpa-down":
			p.failWith("unreachable", "cpa-down")
		case "cpa-key":
			p.failWith("api-error", "cpa-key")
		case "cpa-off":
			p.failWith("api-error", "cpa-off")
		default:
			p.failWith("api-error", "cpa-shape")
		}
		q := p
		return 0, nil, &q
	}
	out := adapterFetch(p, ad, cr.raw, "cpa", send)
	adapterKeep("cpa:"+cr.index, &out, now())
	return out
}

// How a request reaches the vendor: CPA on the credential's behalf, or this
// program with the token filled in (local.go). A channel that failed hands
// back a finished failure of its own and the reading is that.
type adapterSender func(method, target string, header map[string]string, data string) (status int, body []byte, channelFail *Provider)

// Every request in the adapter, then the table over the answers.
func adapterFetch(p Provider, ad *vendorAdapter, cred map[string]any, channel string, send adapterSender) Provider {
	fail := func(err, code string, arg ...string) Provider {
		p.failWith(err, code, arg...)
		return p
	}
	docs := map[string]any{}
	var firstErr *Provider
	noteErr := func(err, code string, arg ...string) {
		if firstErr != nil {
			return
		}
		q := p
		q.failWith(err, code, arg...)
		firstErr = &q
	}
	credCtx := adapterCtx{cred}
	for _, r := range ad.Requests {
		if r.Channel != "" && r.Channel != channel {
			continue
		}
		// Anything the template could not fill is not sent half-filled.
		missing := ""
		for field, tpl := range r.Requires {
			if adapterTemplate(tpl, credCtx, cred) == "" {
				missing = field
				break
			}
		}
		if missing != "" {
			if r.Optional {
				continue
			}
			return fail("api-error", "cpa-cred-field", missing)
		}
		header := map[string]string{}
		for k, v := range r.headersFor(channel) {
			val := adapterTemplate(v, credCtx, cred)
			if val == "" || strings.ContainsAny(val, "\r\n") {
				continue
			}
			header[k] = val
		}
		data := ""
		if r.Body != "" {
			data = adapterTemplate(r.Body, credCtx, cred)
			// A template value with a quote in it would splice into the JSON
			// body; nothing this reads (a project id, an account id) has one.
			if !json.Valid([]byte(data)) {
				if r.Optional {
					continue
				}
				return fail("api-error", "cpa-cred-field", "body")
			}
		}
		method := strings.ToUpper(r.Method)
		if method == "" {
			method = "GET"
		}
		got := false
		for _, target := range append([]string{r.URL}, r.Fallback...) {
			// Filled, then checked: the allow-list is asked about the URL
			// that is actually sent.
			target = adapterTemplateURL(target, credCtx, cred)
			if !cpaHostAllowed(target) {
				return fail("api-error", "adapter-host", hostOf(target))
			}
			status, body, channelFail := send(method, target, header, data)
			if channelFail != nil {
				// The channel itself failed — CPA timed out on a slow
				// vendor, the local request never completed. For a request
				// the reading can do without, that costs the fields it would
				// have filled and nothing else.
				if r.Optional {
					noteErr(channelFail.Error, channelFail.DetailCode, channelFail.DetailArg)
					break
				}
				return *channelFail
			}
			switch {
			case status >= 200 && status < 300:
				var doc any
				if json.Unmarshal(body, &doc) != nil || doc == nil {
					noteErr("api-error", "http-shape")
					continue
				}
				docs[r.ID] = doc
				got = true
			case status == 401:
				noteErr("token-expired", "http-401")
			case status == 403:
				noteErr("api-error", "http-403")
			case status == 429:
				noteErr("rate-limited", "http-429")
			default:
				noteErr("api-error", "http-status", itoa(status))
			}
			if got {
				break
			}
		}
		if !got && !r.Optional {
			if firstErr != nil {
				return *firstErr
			}
			return fail("api-error", "http-shape")
		}
	}
	if len(docs) == 0 {
		if firstErr != nil {
			return *firstErr
		}
		return fail("no-readings", "no-window")
	}

	reading := adapterRun(ad, docs, cred, now())
	// The plan chip: the vendor's answer first, the credential file's word
	// for it when the answer has none. Set before the windows are counted,
	// so an answer with no window still names the plan — the native road
	// that runs next (local.go collectLocalOr) keeps it.
	if reading.Plan == "" && ad.Credential != nil && ad.Credential.Plan != nil {
		reading.Plan = adapterPick(ad.Credential.Plan, docs, cred)
	}
	if reading.Tier == "" && ad.Credential != nil && ad.Credential.Tier != nil {
		reading.Tier = adapterPick(ad.Credential.Tier, docs, cred)
	}
	if reading.Plan != "" {
		p.PlanType = sp(reading.Plan)
	}
	if reading.Tier != "" {
		p.RateLimitTier = sp(reading.Tier)
	}
	if len(reading.Limits) == 0 {
		return fail("no-readings", "no-window")
	}
	p.OK = true
	p.RecordedAt = fp(now())
	p.Limits = reading.Limits
	p.Credits = reading.Credits
	p.Resets = reading.Resets
	p.setPlanDate(reading.PlanAt, reading.PlanKind)
	p.planClaim = reading.PlanFromClaim
	p.Limited = reading.Limited
	return p
}

// A body up to `limit` bytes; one byte past it and the whole answer is
// refused, so a truncated document is never parsed as a complete one.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, errors.New("read failed")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response too large")
	}
	return data, nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	return u.Hostname()
}
