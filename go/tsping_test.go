package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// The pong read as `tailscale ping` prints it: a peer relay first, then
// DERP, else the endpoint it came straight from.
func TestTSPingFrom(t *testing.T) {
	cases := []struct {
		name string
		in   tsLocalPing
		want tsPingBody
	}{
		{"direct", tsLocalPing{LatencySeconds: 0.01234, NodeName: "macbook", Endpoint: "203.0.113.7:41641"},
			tsPingBody{OK: true, MS: 12.3, Via: "direct", Where: "203.0.113.7:41641", Node: "macbook"}},
		{"derp", tsLocalPing{LatencySeconds: 0.081, NodeName: "macbook", DERPRegionID: 7, DERPRegionCode: "tok", Endpoint: "x"},
			tsPingBody{OK: true, MS: 81, Via: "derp", Where: "tok", Node: "macbook"}},
		{"peer relay", tsLocalPing{LatencySeconds: 0.04, PeerRelay: "198.51.100.2:7777:vni:12", DERPRegionID: 7},
			tsPingBody{OK: true, MS: 40, Via: "peer-relay", Where: "198.51.100.2:7777"}},
		{"local", tsLocalPing{IsLocalIP: true, Err: "is local Tailscale IP"}, tsPingBody{Why: "local"}},
		{"no pong", tsLocalPing{Err: "no matching peer"}, tsPingBody{Why: "no-pong"}},
		{"nothing said", tsLocalPing{LatencySeconds: 0.01}, tsPingBody{Why: "no-pong"}},
	}
	for _, c := range cases {
		got := tsPingFrom(&tsPingBody{V: 1}, &c.in)
		c.want.V = 1
		if *got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, *got, c.want)
		}
	}
}

func tsPingReset(t *testing.T) {
	t.Helper()
	clear := func() {
		tsPingCache.Lock()
		tsPingCache.m = nil
		tsPingCache.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

func tsPingCall(t *testing.T, h http.Handler, peer *key.NodePublic, remote string, tailnet bool) (*httptest.ResponseRecorder, tsPingBody) {
	t.Helper()
	req := httptest.NewRequest("GET", "/v1/tsping", nil)
	req.RemoteAddr = remote
	ctx := req.Context()
	if peer != nil {
		ctx = transport.WithPeer(ctx, *peer)
	}
	if tailnet {
		ctx = context.WithValue(ctx, tailnetCtxKey{}, true)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))
	var b tsPingBody
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
	}
	return rec, b
}

// On the tailnet road, to a browser on the list: tailscaled pings the
// address the request came from, once within the TTL.
func TestTailnetPing(t *testing.T) {
	f := newFilesFixture(t)
	tsPingReset(t)
	fake := &tsFake{ping: map[string]any{"NodeName": "macbook", "LatencySeconds": 0.0231, "Endpoint": "", "PeerRelay": "",
		"DERPRegionID": 21, "DERPRegionCode": "tok"}}
	tsUse(t, fake)
	rec, b := tsPingCall(t, f.h, &f.peer, "100.64.0.9:51234", true)
	if rec.Code != 200 || !b.OK || b.Via != "derp" || b.Where != "tok" || b.MS != 23.1 || b.Node != "macbook" {
		t.Fatalf("ping: %d %+v", rec.Code, b)
	}
	if len(fake.pingQ) != 1 || fake.pingQ[0] != "ip=100.64.0.9&type=disco" {
		t.Fatalf("asked: %v", fake.pingQ)
	}
	tsPingCall(t, f.h, &f.peer, "100.64.0.9:51235", true)
	if len(fake.pingQ) != 1 {
		t.Errorf("asked again within the TTL: %v", fake.pingQ)
	}
	// Another machine is its own ping; an IPv6 tailnet address too.
	tsPingCall(t, f.h, &f.peer, "[fd7a:115c:a1e0::9]:4000", true)
	if len(fake.pingQ) != 2 || fake.pingQ[1] != "ip=fd7a%3A115c%3Aa1e0%3A%3A9&type=disco" {
		t.Errorf("asked: %v", fake.pingQ)
	}
}

// Not on the tailnet road, not on the list, no tailscaled, no pong.
func TestTailnetPingRefused(t *testing.T) {
	f := newFilesFixture(t)
	tsPingReset(t)
	fake := &tsFake{ping: map[string]any{"Endpoint": "203.0.113.7:41641", "LatencySeconds": 0.002}}
	tsUse(t, fake)
	if rec, _ := tsPingCall(t, f.h, &f.peer, "100.64.0.9:1", false); rec.Code != http.StatusNotFound {
		t.Errorf("tunnel: %d", rec.Code)
	}
	other := key.NewNode().Public()
	if rec, _ := tsPingCall(t, f.h, &other, "100.64.0.9:1", true); rec.Code != http.StatusForbidden {
		t.Errorf("not listed: %d", rec.Code)
	}
	if rec, _ := tsPingCall(t, f.h, nil, "100.64.0.9:1", true); rec.Code != http.StatusForbidden {
		t.Errorf("no key: %d", rec.Code)
	}
	if len(fake.pingQ) != 0 {
		t.Errorf("pinged for a refusal: %v", fake.pingQ)
	}
	fake.pingCode = http.StatusInternalServerError
	if rec, b := tsPingCall(t, f.h, &f.peer, "100.64.0.9:1", true); rec.Code != 200 || b.OK || b.Why != "timeout" {
		t.Errorf("no pong: %d %+v", rec.Code, b)
	}
	tsPingReset(t)
	tsUse(t, nil)
	if rec, b := tsPingCall(t, f.h, &f.peer, "100.64.0.10:1", true); rec.Code != 200 || b.OK || b.Why != "absent" {
		t.Errorf("absent: %d %+v", rec.Code, b)
	}
}
