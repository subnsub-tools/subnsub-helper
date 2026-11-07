package main

// How the browser's machine and this one reach each other on the tailnet, as
// `tailscale ping --until-direct=false <that machine>` answers it: one disco
// ping from this machine's tailscaled to the address the browser's request
// came from, and the way its pong came back — straight between the two
// (direct, with the endpoint it used), through a peer relay (another node of
// the tailnet relaying UDP), or through a DERP server (with its region) — and
// how long it took. It is the same LocalAPI call the command makes
// (POST /localapi/v0/ping?type=disco), read as data rather than its printed
// line. The dashboard asks every few seconds while a terminal or a screen of
// this machine is open over the tailnet road, so it shows which of the three
// carries what is typed, and the round trip it costs.
//
// Answered on the tailnet road alone: on the tunnel the browser is not a node
// of the tailnet, so there is nothing to ping.

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"
)

const (
	// As long as `tailscale ping` waits for one pong.
	tsPingTimeout = 5 * time.Second
	// An answer is kept this long: two windows of one machine, or one page
	// drawing again, do not each ping.
	tsPingTTL = 2 * time.Second
	// Peers remembered at most; a page asks for its own machine's only.
	tsPingMaxPeers = 64
)

// tsPingBody is the answer to GET /v1/tsping.
//
//	ok    whether a pong came back
//	why   when not: "absent" (no tailscaled answered), "local" (the browser
//	      is on this machine), "no-pong" (tailscaled answered without one),
//	      "timeout", "error"
//	ms    the pong's round trip, in milliseconds
//	via   "direct", "peer-relay" or "derp"
//	where the endpoint (ip:port) for direct, the relay's ip:port for a peer
//	      relay, the region's code for DERP
//	node  the browser machine's name on the tailnet
type tsPingBody struct {
	V     int     `json:"v"`
	OK    bool    `json:"ok"`
	Why   string  `json:"why,omitempty"`
	MS    float64 `json:"ms"`
	Via   string  `json:"via,omitempty"`
	Where string  `json:"where,omitempty"`
	Node  string  `json:"node,omitempty"`
	At    int64   `json:"at"`
}

type tsPingSlot struct {
	mu   sync.Mutex
	at   time.Time
	body *tsPingBody
}

var tsPingCache struct {
	sync.Mutex
	m map[netip.Addr]*tsPingSlot
}

// tsPingNow pings ip, or answers what a ping of it said less than tsPingTTL
// ago. Asks for one address wait for the one ping under way.
func tsPingNow(ip netip.Addr) *tsPingBody {
	tsPingCache.Lock()
	if tsPingCache.m == nil {
		tsPingCache.m = map[netip.Addr]*tsPingSlot{}
	}
	s := tsPingCache.m[ip]
	if s == nil {
		if len(tsPingCache.m) >= tsPingMaxPeers {
			// Room made from the ones not being pinged: one under way keeps
			// its slot, so the next ask for it still waits on it.
			for a, o := range tsPingCache.m {
				if o.mu.TryLock() {
					delete(tsPingCache.m, a)
					o.mu.Unlock()
				}
			}
		}
		s = &tsPingSlot{}
		tsPingCache.m[ip] = s
	}
	tsPingCache.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.body != nil && time.Since(s.at) < tsPingTTL {
		return s.body
	}
	ctx, cancel := context.WithTimeout(context.Background(), tsPingTimeout)
	defer cancel()
	b := tsPingRead(ctx, ip)
	s.body, s.at = b, time.Now()
	return b
}

// tsLocalPing is ipnstate.PingResult, the fields read here.
type tsLocalPing struct {
	Err            string
	LatencySeconds float64
	NodeName       string
	Endpoint       string
	PeerRelay      string
	DERPRegionID   int
	DERPRegionCode string
	IsLocalIP      bool
}

func tsPingRead(ctx context.Context, ip netip.Addr) *tsPingBody {
	out := &tsPingBody{V: 1, At: time.Now().Unix()}
	q := url.Values{"ip": {ip.String()}, "type": {"disco"}}
	st, b, err := tsLocal(ctx, http.MethodPost, "ping?"+q.Encode())
	switch {
	case errors.Is(err, errTSAbsent):
		out.Why = "absent"
	case ctx.Err() != nil:
		out.Why = "timeout"
	case err != nil:
		out.Why = "error"
	}
	if out.Why != "" {
		return out
	}
	if st != http.StatusOK {
		// The LocalAPI says a failed ping as an error body; a ping that ran
		// out of time inside tailscaled says so in it.
		out.Why = "no-pong"
		if e := strings.ToLower(string(b)); strings.Contains(e, "timeout") || strings.Contains(e, "deadline") {
			out.Why = "timeout"
		}
		return out
	}
	var pr tsLocalPing
	if json.Unmarshal(b, &pr) != nil {
		out.Why = "error"
		return out
	}
	return tsPingFrom(out, &pr)
}

// tsPingFrom reads the pong as the command prints it: a peer relay first,
// then DERP, else the endpoint it came straight from.
func tsPingFrom(out *tsPingBody, pr *tsLocalPing) *tsPingBody {
	if pr.IsLocalIP {
		out.Why = "local"
		return out
	}
	if pr.Err != "" {
		out.Why = "no-pong"
		return out
	}
	switch {
	case pr.PeerRelay != "":
		out.Via = "peer-relay"
		// "ip:port:vni:N": the relay's address, without the session's number.
		w := pr.PeerRelay
		if i := strings.Index(w, ":vni:"); i >= 0 {
			w = w[:i]
		}
		out.Where = tsClean(w, 64)
	case pr.DERPRegionID != 0:
		out.Via = "derp"
		out.Where = tsClean(pr.DERPRegionCode, 16)
	case pr.Endpoint != "":
		out.Via = "direct"
		out.Where = tsClean(pr.Endpoint, 64)
	default:
		out.Why = "no-pong"
		return out
	}
	ms := pr.LatencySeconds * 1000
	if math.IsNaN(ms) || math.IsInf(ms, 0) || ms < 0 {
		ms = 0
	}
	out.OK = true
	out.MS = math.Round(ms*10) / 10
	out.Node = tsClean(pr.NodeName, tsViewNameMax)
	return out
}

// tailnetPing answers GET /v1/tsping on the tailnet road: the path to the
// machine the request came from, for a browser on the allowlist.
func (h *directHandler) tailnetPing(w http.ResponseWriter, r *http.Request) {
	if !tailnetRequest(r) {
		h.refuse(w, http.StatusNotFound, "not-tailnet")
		return
	}
	k, ok := transport.PeerFromContext(r.Context())
	listed := false
	if ok {
		for _, a := range loadAllowedClients() {
			if a == k {
				listed = true
				break
			}
		}
	}
	if !listed {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		h.refuse(w, http.StatusBadRequest, "no-peer")
		return
	}
	b, err := json.Marshal(tsPingNow(ap.Addr().Unmap()))
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}
