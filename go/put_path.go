package main

// What out shows of the way to another of the owner's Macs while it works its
// screen (user 2026-11-22: when working a Mac remotely, show everything,
// whether it goes by DERP, a peer relay or directly, and
// `tailscale ping --c 0 --until-direct=false`): put.sock
// {"op":"path","agent":"…"} answers {"ok":true}, then a line a second until
// out closes the connection, for at most putPathMax. Each road is pinged on its
// own, so one that times out does not hold up the other, and each ping is a
// line of its own:
//
//	{"at": ms, "tailnet": {ok, ms, via, where, node, why}}
//	{"at": ms, "tailcat": {ok, ms, via, where, node, why}}
//
// From a Mac that is not on a tailnet itself and reaches the other Mac's door
// through a router that is (put_tailnet.go), tailnet is the time a TCP
// connection to that door takes, via "router", where the door's address.
//
// tailnet is this Mac's Tailscale pinging the other Mac's tailnet address as
// `tailscale ping --until-direct=false` does (tsping.go: via is direct,
// peer-relay or derp, where the endpoint, the relay or the region), where both
// are on one and this helper knows that address (put_tailnet.go). tailcat is
// the tunnel's own disco ping, read the same way, where this helper has a
// client to that Mac. A road with nothing to ping says null, a second at a
// time, so that out stops showing what it said last as the path.

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	putPathEvery = time.Second
	putPathMax   = 6 * time.Hour
	// One tunnel ping, at most.
	putPathTailcatWait = 3 * time.Second
)

func putPathServe(c net.Conn, agent string) {
	defer c.Close()
	if _, ok := putPeerByAgent(agent); !ok {
		putAnswer(c, map[string]any{"ok": false, "error": "unknown-peer"})
		return
	}
	if putAnswer(c, map[string]any{"ok": true}) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), putPathMax)
	defer cancel()
	go func() {
		// out closing its end ends the pings.
		var b [64]byte
		for {
			if _, err := c.Read(b[:]); err != nil {
				cancel()
				return
			}
		}
	}()
	var mu sync.Mutex
	say := func(road string, b *tsPingBody) bool {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			return false
		}
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if putAnswer(c, map[string]any{"at": time.Now().UnixMilli(), road: b}) != nil {
			cancel()
			return false
		}
		return true
	}
	roads := []struct {
		name  string
		probe func(context.Context, string) *tsPingBody
	}{{"tailnet", putPathTailnet}, {"tailcat", putPathTailcat}}
	var wg sync.WaitGroup
	for _, road := range roads {
		road := road
		wg.Add(1)
		go func() {
			defer wg.Done()
			tick := time.NewTicker(putPathEvery)
			defer tick.Stop()
			for {
				if !say(road.name, road.probe(ctx, agent)) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
	}
	wg.Wait()
}

// putPathTailnet: this Mac's Tailscale pinging the peer's tailnet address, or
// nil where there is none to ping.
func putPathTailnet(ctx context.Context, agent string) *tsPingBody {
	if tailnetOff() {
		return nil
	}
	putTn.Lock()
	a := putTn.addr[agent]
	putTn.Unlock()
	if putTnSelf() == "" {
		// No Tailscale here to ping with: the door itself, while this Mac
		// gets to it.
		if a == "" || !putTnReachable(agent) {
			return nil
		}
		out := &tsPingBody{V: 1, At: time.Now().Unix()}
		took, err := putTnKnock(ctx, a)
		if err != nil {
			out.Why = "timeout"
			return out
		}
		out.OK, out.MS, out.Via, out.Where = true, float64(took.Microseconds()/100)/10, "router", a
		return out
	}
	ap, err := netip.ParseAddrPort(a)
	if err != nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, tsPingTimeout)
	defer cancel()
	return tsPingRead(pctx, ap.Addr())
}

// putPathTailcat: the tunnel's disco ping to the peer, or nil where this
// helper has no client to it.
func putPathTailcat(ctx context.Context, agent string) *tsPingBody {
	putClients.Lock()
	pc := putClients.m[agent]
	putClients.Unlock()
	if pc == nil {
		return nil
	}
	out := &tsPingBody{V: 1, At: time.Now().Unix()}
	pctx, cancel := context.WithTimeout(ctx, putPathTailcatWait)
	defer cancel()
	r, err := pc.cl.DiscoPing(pctx)
	switch {
	case pctx.Err() != nil:
		out.Why = "timeout"
		return out
	case err != nil || r == nil:
		out.Why = "error"
		return out
	}
	return tsPingFrom(out, &tsLocalPing{Err: r.Err, LatencySeconds: r.LatencySeconds, NodeName: r.NodeName, Endpoint: r.Endpoint,
		PeerRelay: r.PeerRelay, DERPRegionID: int(r.DERPRegionID), DERPRegionCode: r.DERPRegionCode})
}
