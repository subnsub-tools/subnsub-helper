package main

// Shared plumbing for the credential-holding collectors (Claude was the first;
// Copilot and Kimi joined it). Two pieces live here, and both
// exist because the fourth copy of either would have drifted from the third:
//
// THE CACHE FLOOR. Every one of these is a real request to someone else's
// service, and the push loop's 30s would be 2,880 calls a day per machine per
// provider. The rules are amp.go's, which found them the hard way:
//   - the floor is on ATTEMPTS, not successes, so an outage does not turn the
//     floor off exactly when hammering helps least;
//   - inside the floor a stale-but-real reading is served over a fresh error,
//     up to a staleness bound past which the error is the truth;
//   - CapturedAt says when we looked, RecordedAt when it was fetched, so a
//     cached reading visibly ages on the page.
//
// THE REQUEST SHAPE. Same non-negotiables as claude.go, because these carry
// credentials: redirects refused outright (Go's client forwards Authorization
// on same-host hops — a redirect anywhere is a token handed to whoever named
// the Location), bounded reads, and NO error text derived from the transport —
// an http error can quote the URL and the Authorization header, and these
// failures are PUBLISHED.

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"sync"
	"time"
)

const (
	// The least gap between two ATTEMPTS at one provider, so a vendor that is
	// failing is not retried on every push. Successes are paced by pace.go:
	// a real call when a refresh is pressed, or on quotaFloor while watched.
	provMinInterval = 120.0
	// How long a cached success outlives failures. Three floors' worth: a
	// reading ten minutes old that the vendor would not refresh is still a
	// better answer than the refusal for a while, as it was at five times
	// the old two-minute floor.
	provStaleMax    = 1800.0
	provTimeout     = 10 * time.Second
	provMaxBody     = 512 * 1024
	provBackoffBase = 60.0   // first pause after a 429, doubling
	provBackoffMax  = 1800.0 // and never longer than this
)

type provCache struct {
	sync.Mutex
	last        *Provider // last SUCCESSFUL reading
	fetchedAt   float64
	fail        *Provider // last failure, served while the floor holds
	attemptedAt float64
	// A 429 backs off exponentially, the way claude.go always did: a vendor
	// that is rate limiting is left alone rather than asked again in two
	// minutes, because asking again is what keeps the limit in place (found
	// 2026-09-09: a limit that would not clear while the loop kept trying).
	strikes   float64
	coolUntil float64
	// Whether a real call is due at all: a refresh pressed on the page, or
	// watched and past the floor (see pace.go).
	pace paceMark
}

// collectAs is collect for a cache whose tile is only known per collection
// (a CPA credential: the second account of a vendor is `vendor@2`).
//
// A cache that changes name — an account removed, the rest renumbered —
// starts level with its new name's count: what it had honoured was counted
// under the old one, and the difference must not read as a press.
func (c *provCache) collectAs(id string, fetch func() Provider) Provider {
	c.Lock()
	if c.pace.id != id {
		c.pace.id = id
		c.pace.consume()
	}
	c.Unlock()
	return c.collect(fetch)
}

// The serve/floor/fetch dance every cached collector does, in one place.
// fetch runs with the lock held — same as every existing collector, and
// deliberate: two pushes racing would otherwise both call the vendor.
func (c *provCache) collect(fetch func() Provider) Provider {
	p, _ := c.collectAsked(fetch)
	return p
}

// collectAsked is collect, saying as well whether fetch ran — whether this
// collection made a real call or served what it held. A caller with a second
// road to the same vendor (collectLocalOr) takes it only when this one was
// really asked, so a reading that merely aged cannot start a call of its own.
func (c *provCache) collectAsked(fetch func() Provider) (Provider, bool) {
	c.Lock()
	defer c.Unlock()

	t := now()
	serve := func(p *Provider) Provider {
		out := *p
		out.CapturedAt = t // when we looked; RecordedAt still says when fetched
		return out
	}

	if t < c.coolUntil {
		// Cooling down after a 429: the last real reading, else the refusal.
		// Checked before the pacing question, so a refresh pressed on the
		// page cannot poke a vendor that is already saying no — and the
		// press is consumed, not banked for when the backoff ends.
		c.pace.consume()
		if c.last != nil && t-c.fetchedAt < provStaleMax {
			return serve(c.last), false
		}
		if c.fail != nil {
			return serve(c.fail), false
		}
	}
	// Not due (no press, and not watched or the floor holds): the last success stands
	// whatever its age — recorded_at carries the truth — unless a failure
	// has happened since and the success has aged past the stale window. A
	// cache holding nothing at all asks anyway: a blank tile is not a
	// reading, and that first ask is one call per process start at most.
	if !c.pace.due(t, c.fetchedAt, c.attemptedAt, provMinInterval, c.last != nil) && (c.last != nil || c.fail != nil) {
		if c.last != nil && (c.fail == nil || t-c.fetchedAt < provStaleMax) {
			return serve(c.last), false
		}
		return serve(c.fail), false
	}

	c.attemptedAt = t
	p := fetch()
	if p.OK {
		c.last, c.fetchedAt, c.fail = &p, t, nil
		c.strikes, c.coolUntil = 0, 0
		return p, true
	}
	c.fail = &p
	if p.Error == "rate-limited" {
		c.strikes++
		pause := provBackoffBase * math.Pow(2, c.strikes-1)
		if pause > provBackoffMax {
			pause = provBackoffMax
		}
		c.coolUntil = t + pause
	}
	if c.last != nil && t-c.fetchedAt < provStaleMax {
		return serve(c.last), true
	}
	c.last = nil
	return p, true
}

var errProvRedirect = errors.New("redirect refused")

// One authenticated request, returning status and a bounded body. The error is
// a bare category — never the transport's text, for the reason at the top.
func provRequest(method, url string, header map[string]string, body []byte) (int, []byte, error) {
	return provRequestTimeout(method, url, header, body, provTimeout)
}

// The same request on a deadline of the caller's choosing: for a side
// question a reading can do without (Grok's reset coupons), which must not
// hold the reading itself for the full provTimeout when the vendor stalls.
func provRequestTimeout(method, url string, header map[string]string, body []byte, timeout time.Duration) (int, []byte, error) {
	if timeout <= 0 || timeout > provTimeout {
		timeout = provTimeout
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, nil, errors.New("bad request")
	}
	req.Header.Set("User-Agent", "subnsub-helper")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := &http.Client{
		Timeout: timeout,
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, provMaxBody+1))
	if err != nil {
		return resp.StatusCode, nil, errors.New("read failed")
	}
	if int64(len(data)) > provMaxBody {
		// A quota endpoint answering in megabytes is not the endpoint we think
		// it is. Refuse the whole reading rather than parse a prefix.
		return resp.StatusCode, nil, errors.New("response too large")
	}
	return resp.StatusCode, data, nil
}
