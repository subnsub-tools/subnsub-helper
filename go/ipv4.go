package main

// The machine's public IPv4 address, as a public "what is my IP" service
// answers it — and the country that service places the address in.
//
// THE ONE ADDRESS THE HELPER REPORTS FOR ITSELF. Everywhere else the egress
// on the card is an observation (transport.go, spaces.go): the address the
// relay saw a connection arrive from. That cannot answer two cases (operator
// ruling 2026-10-08: when the exit has both an IPv4 and an IPv6 address,
// show the IPv4 first):
//
//   - A push that reaches the relay over IPv6 shows the IPv6 alone, however
//     much IPv4 the machine has. transport.go's IPv4-first dial covers an
//     ordinary dual-stack machine, but not one behind a platform proxy that
//     re-resolves every hostname and prefers AAAA (box, 2026-10-07: its pushes
//     arrive from 2a09:bac…, its IPv4-only destinations see 104.28.x).
//   - The self-hosted direct road has no relay at all, so nothing observes.
//
// So every half hour the helper asks a service over IPv4 — forced, even
// when the service has both records — and puts the answer in its reading as
// `public_ipv4`. The card's folded strip and Exit tile show it, on the hosted
// site and the self-hosted one alike; an address the relay saw a push arrive
// from is a line of the open card's Exit record, never the chip.
//
// The default service is Cloudflare's cdn-cgi/trace page, which answers with
// key=value lines: `ip=` is the address and `loc=` the country Cloudflare
// places it in. It is asked at the IP literal 1.1.1.1, not at a hostname:
// a machine behind a platform proxy that re-resolves every hostname itself
// and prefers AAAA (box) would otherwise reach a dual-stack name over IPv6
// whatever this dialer asks for, and the trace would answer with the IPv6
// the relay can already see — 2026.10.09.1 shipped with www.cloudflare.com
// and box lost its address and flag for an hour. A literal has no AAAA to
// prefer, and no fake DNS answer to be given either. The country rides beside the address as `public_cc`, and the
// flag the page draws on the chip is that country's: the same geolocation
// the hosted relay uses for the address IT sees, applied here to the address
// the chip actually shows — and the one flag a self-hosted dashboard, which
// has no relay to observe anything, can have at all (user 2026-10-09).
//
// MON_IPV4 picks the service: unset → 1.1.1.1, "off" → no lookup at all,
// an https URL → that one. A custom service may answer in the same key=value
// form (then its loc= is taken too) or with the bare address (no country, so
// no flag). Read from the environment first and then from the private config
// beside the token, where install.sh keeps what the install line said — so
// the service, which never sees the installing shell, does what that line
// asked.

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	ipv4EnvVar     = "MON_IPV4"
	ipv4DefaultURL = "https://1.1.1.1/cdn-cgi/trace"
	ipv4Every      = 30 * time.Minute
	ipv4Retry      = 5 * time.Minute
	// How long an answer outlives the lookups that fail after it: through a
	// slow minute at the service, not past a machine that lost its IPv4.
	ipv4Stale    = 2 * time.Hour
	ipv4FirstGap = 3 * time.Second
	ipv4Timeout  = 10 * time.Second
	// A trace page is a dozen short lines; a bare address is one. Anything
	// past this is not an answer.
	ipv4BodyMax = 4096
)

var ipv4State struct {
	sync.Mutex
	addr string
	cc   string
	at   time.Time
	once sync.Once
}

// ipv4Source is MON_IPV4 read: the URL to ask, or "" for no lookup.
func ipv4Source() string {
	v := strings.TrimSpace(envSetting(ipv4EnvVar, installedEnv()))
	switch strings.ToLower(v) {
	case "":
		return ipv4DefaultURL
	case "0", "off", "false", "no":
		return ""
	}
	if !strings.HasPrefix(v, "https://") {
		return ""
	}
	return v
}

// ipv4Public: the answer, if it is one public IPv4 address, in its canonical
// form. A private, shared (100.64/10), loopback, link-local, multicast or
// reserved address is no machine's public exit, whatever the service says;
// nor is one of the special-use blocks — the documentation ranges, the 6to4
// anycast, and 198.18/15, the benchmark block a platform proxy hands out as
// fake DNS answers (box: 198.18.0.1).
func ipv4Public(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil || strings.Contains(strings.TrimSpace(s), ":") {
		return ""
	}
	if v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsMulticast() ||
		v4.IsUnspecified() || v4[0] == 0 || v4[0] >= 240 ||
		(v4[0] == 100 && v4[1]&0xc0 == 64) ||
		(v4[0] == 192 && v4[1] == 0 && (v4[2] == 0 || v4[2] == 2)) ||
		(v4[0] == 192 && v4[1] == 88 && v4[2] == 99) ||
		(v4[0] == 198 && v4[1]&0xfe == 18) ||
		(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
		(v4[0] == 203 && v4[1] == 0 && v4[2] == 113) {
		return ""
	}
	return v4.String()
}

// countryCode: two upper-case letters, or "". Cloudflare answers XX when it
// cannot place an address and T1 for a Tor exit; neither is a country.
func countryCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' || s == "XX" || s == "T1" {
		return ""
	}
	return s
}

// ipv4Parse reads an answer: the key=value lines of a cdn-cgi/trace page
// (`ip=` and `loc=`), or a bare address from a service that answers with
// one. A country only ever comes with an address; the address never
// depends on the country.
func ipv4Parse(body string) (addr, cc string) {
	if !strings.Contains(body, "=") {
		return ipv4Public(body), ""
	}
	for _, ln := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			addr = ipv4Public(v)
		case "loc":
			cc = countryCode(v)
		}
	}
	if addr == "" {
		return "", ""
	}
	return addr, cc
}

// ipv4Lookup asks once. "" on any failure: no answer, not an address, or a
// service that refused.
func ipv4Lookup(src string) (addr, cc string) {
	dialer := &net.Dialer{Timeout: ipv4Timeout}
	client := &http.Client{
		Timeout: ipv4Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			// IPv4 or nothing: a dual-stack service asked over IPv6 would
			// answer with the IPv6 the relay can already see.
			DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp4", addr)
			},
			TLSHandshakeTimeout: ipv4Timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "subnsub-helper/"+helperVersion)
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ipv4BodyMax+1))
	if err != nil || len(body) > ipv4BodyMax {
		return "", ""
	}
	return ipv4Parse(string(body))
}

// startIPv4 begins the loop, once, whichever road the machine reports on.
// A failed lookup keeps the last answer for ipv4Stale: an address does not
// stop being the machine's because a service was slow for a minute.
func startIPv4() {
	ipv4State.once.Do(func() {
		src := ipv4Source()
		if src == "" {
			return
		}
		go func() {
			time.Sleep(ipv4FirstGap)
			for {
				wait := ipv4Every
				if a, cc := ipv4Lookup(src); a != "" {
					ipv4State.Lock()
					ipv4State.addr, ipv4State.cc, ipv4State.at = a, cc, time.Now()
					ipv4State.Unlock()
				} else {
					wait = ipv4Retry
				}
				time.Sleep(wait)
			}
		}()
	})
}

// ipv4Snapshot is what a reading (or a beacon) carries: the address and
// the country it came with, or neither.
func ipv4Snapshot() (addr, cc string) {
	ipv4State.Lock()
	defer ipv4State.Unlock()
	if ipv4State.addr == "" || time.Since(ipv4State.at) > ipv4Stale {
		return "", ""
	}
	return ipv4State.addr, ipv4State.cc
}
