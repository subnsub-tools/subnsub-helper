package main

// A second way out — the egress of each extra network namespace.
//
// A router that sends some traffic through a VPN has two exits, and the card
// showed one: the address the relay saw THIS process push from (user
// 2026-09-20, a GL-MT3000 with a Tailscale exit in its own namespace). The
// helper stays where it is, in the namespace it was started in, and reports
// from there as before. Every five minutes it also makes ONE request from
// inside each named namespace (`ip netns add`'s, under /run/netns) and the
// card's Network section grows a group per namespace.
//
// THE ADDRESS IS STILL AN OBSERVATION, NOT A CLAIM. transport.go explains why
// the egress on the card is what the relay saw rather than what a "what is my
// IP" service told the helper (ipv4.go is the single, labelled exception: the
// machine's own IPv4). So the request made from inside
// the namespace goes to the relay too (/whoami), and what comes back is a
// STAMP — the address, country and city the edge saw, sealed with the relay's
// own key and bound to this machine's id. The helper cannot read it as
// anything but bytes and carries it in its next push; the relay opens it and
// writes the fields itself. A helper that invents a stamp gets no address.
//
// What the helper does say for itself is what any probe says: whether the
// request got through, and how long it took.
//
// NOT HERE: a DNS check through the namespace's resolver. The relay's address
// is resolved in the helper's own namespace and only the connection is made
// from the other one, so "the VPN is up but its DNS is broken" reads as up.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	spacesEnvVar  = "MON_NETNS"
	spacesMax     = 4
	spacesEvery   = 5 * time.Minute
	spacesTimeout = 15 * time.Second
	// One address's share of that. The relay usually has an A and an AAAA
	// and a namespace may route only one family: a black-holed first address
	// must leave the second its turn, and the request its time.
	spaceDialTimeout = 4 * time.Second
	spaceStampMax    = 512
	spacesFirstGap   = 5 * time.Second
	// A relay that does not know /whoami (self-hosted, or older than this
	// helper) is asked again this rarely.
	spacesUnsupportedEvery = time.Hour
)

// Space is one extra namespace's exit, as the helper can know it.
type Space struct {
	Name      string   `json:"name"`
	OK        bool     `json:"ok"`
	RTTMs     *float64 `json:"rtt_ms,omitempty"`
	Error     string   `json:"error,omitempty"` // timeout · unreachable · refused
	CheckedAt float64  `json:"checked_at"`
	// The relay's sealed observation. Opaque here; see the header.
	Stamp string `json:"stamp,omitempty"`
}

var spaces struct {
	sync.Mutex
	on   bool
	list []Space
}

// spaceNameOK: the names this will report. `ip netns add` takes nearly any
// filename; the card takes this alphabet, and a container runtime's
// per-pod namespaces (cni-<uuid>) are not exits anyone asked to watch.
func spaceNameOK(name string) bool {
	if name == "" || len(name) > 32 || strings.HasPrefix(name, "cni-") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return name != "." && name != ".."
}

// spacesWanted is MON_NETNS: unset → every named namespace, "off" → none,
// "a,b" → only those.
func spacesWanted() (all bool, only map[string]bool) {
	v := strings.TrimSpace(os.Getenv(spacesEnvVar))
	switch strings.ToLower(v) {
	case "":
		return true, nil
	case "0", "off", "false", "no":
		return false, nil
	}
	only = map[string]bool{}
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); spaceNameOK(n) {
			only[n] = true
		}
	}
	return false, only
}

func spacesPick(found []string) []string {
	all, only := spacesWanted()
	var out []string
	for _, n := range found {
		if spaceNameOK(n) && (all || only[n]) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(out) > spacesMax {
		out = out[:spacesMax]
	}
	return out
}

// startSpaces begins the loop, once, beside the relay push. It needs the
// relay's token (the stamp comes from the relay), so a tunnel-only install
// with no relay loop does not run it.
func startSpaces(base string, tok *tokenBox) {
	if !spacesAvailable() {
		return
	}
	spaces.Lock()
	if spaces.on {
		spaces.Unlock()
		return
	}
	spaces.on = true
	spaces.Unlock()
	go func() {
		time.Sleep(spacesFirstGap)
		for {
			wait := spacesEvery
			if spacesPass(base, tok.get()) {
				wait = spacesUnsupportedEvery
			}
			time.Sleep(wait)
		}
	}()
}

// spacesPass probes every namespace once. Reports whether the relay turned
// out not to have /whoami at all.
func spacesPass(base, token string) (unsupported bool) {
	names := spacesPick(spacesFound())
	var out []Space
	for _, name := range names {
		sp, status := spaceProbe(base, token, name)
		if status == http.StatusNotFound || status == http.StatusNotImplemented {
			unsupported = true
			break
		}
		if sp != nil {
			out = append(out, *sp)
		}
	}
	if unsupported {
		out = nil
	}
	spaces.Lock()
	spaces.list = out
	spaces.Unlock()
	return unsupported
}

// spacesSnapshot is what a reading (or a beacon) carries.
func spacesSnapshot() []Space {
	spaces.Lock()
	defer spaces.Unlock()
	if len(spaces.list) == 0 {
		return nil
	}
	return append([]Space(nil), spaces.list...)
}

// spaceProbe asks the relay who it sees, from inside one namespace. A nil
// Space means "say nothing about this one": it is the helper's own
// namespace, or one this process may not enter — an unprivileged helper on a
// server has no business listing namespaces it cannot look out of.
func spaceProbe(base, token, name string) (*Space, int) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/whoami")
	if err != nil || u.Hostname() == "" {
		return nil, 0
	}
	q := u.Query()
	q.Set("agent", agentID())
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), spacesTimeout)
	defer cancel()
	// Resolved HERE, in the helper's namespace, and only dialled from there:
	// the other namespace's resolver may be a loopback that means something
	// else inside it. IPv4 first, for the reason transport.go gives.
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80"}[u.Scheme]
		if port == "" {
			port = "443"
		}
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, 0 // this machine cannot resolve the relay at all: not the namespace's fault
	}
	// One address per family, IPv4 first.
	var tries []net.IP
	for _, want4 := range []bool{true, false} {
		for _, ip := range ips {
			if (ip.IP.To4() != nil) == want4 {
				tries = append(tries, ip.IP)
				break
			}
		}
	}

	// Set by the dialling thread the moment it is inside the namespace, read
	// here after the request is over — which can be BEFORE the dial returns
	// (a timeout), hence atomic and hence not a return value.
	var entered atomic.Bool
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			// The transport's own context is detached from the request's
			// deadline for a dial; the probe's is the one that must bound it.
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				var last error
				for _, ip := range tries {
					dctx, stop := context.WithTimeout(ctx, spaceDialTimeout)
					conn, err := spaceDial(dctx, name, net.JoinHostPort(ip.String(), port), &entered)
					stop()
					if err == nil {
						return conn, nil
					}
					last = err
					if !entered.Load() || ctx.Err() != nil {
						break // could not enter, or out of time: the next address will not help
					}
				}
				return nil, last
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "subnsub-helper")

	started := time.Now()
	resp, err := client.Do(req)
	out := &Space{Name: name, CheckedAt: now()}
	if err != nil {
		if !entered.Load() {
			return nil, 0
		}
		out.Error = "unreachable"
		if ne, ok := err.(net.Error); ok && ne.Timeout() || ctx.Err() != nil {
			out.Error = "timeout"
		}
		return out, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out.Error = "refused"
		return out, resp.StatusCode
	}
	var body struct {
		Stamp string `json:"stamp"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) != nil ||
		body.Stamp == "" || len(body.Stamp) > spaceStampMax {
		out.Error = "refused"
		return out, resp.StatusCode
	}
	ms := float64(time.Since(started).Milliseconds())
	out.OK, out.RTTMs, out.Stamp = true, &ms, body.Stamp
	return out, resp.StatusCode
}
