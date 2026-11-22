package main

import (
	"encoding/json"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
)

// The path op says, a line a second, how the tailnet and the tunnel reach the
// other Mac, as `tailscale ping --until-direct=false` would.
func TestPutPath(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	tsUse(t, &tsFake{ping: map[string]any{"LatencySeconds": 0.0042, "Endpoint": "192.168.1.5:41641", "NodeName": "study."}})
	tun := &fakeTunnel{ping: &ipnstate.PingResult{LatencySeconds: 0.031, DERPRegionID: 7, DERPRegionCode: "tok", NodeName: "study"}}
	withFakeTunnels(t, f, tun, tun)
	putTnSet("macStudy01", "100.101.1.2:41641")
	c, r, out := dialPut(t, `{"op":"path","agent":"macStudy01"}`)
	defer c.Close()
	if out["ok"] != true {
		t.Fatalf("path: %v", out)
	}
	// Each road a line of its own, two of each within a few seconds.
	seen := map[string]int{}
	for seen["tailnet"] < 2 || seen["tailcat"] < 2 {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("after %v: %v", seen, err)
		}
		var got struct {
			At      int64       `json:"at"`
			Tailnet *tsPingBody `json:"tailnet"`
			Tailcat *tsPingBody `json:"tailcat"`
		}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if got.At == 0 || (got.Tailnet == nil) == (got.Tailcat == nil) {
			t.Fatalf("one road a line: %q", line)
		}
		if b := got.Tailnet; b != nil {
			if !b.OK || b.Via != "direct" || b.Where != "192.168.1.5:41641" || b.MS != 4.2 {
				t.Fatalf("tailnet %+v", b)
			}
			seen["tailnet"]++
		}
		if b := got.Tailcat; b != nil {
			if !b.OK || b.Via != "derp" || b.Where != "tok" || b.MS != 31 {
				t.Fatalf("tailcat %+v", b)
			}
			seen["tailcat"]++
		}
	}
	c.Close()
	c2, _, out := dialPut(t, `{"op":"path","agent":"macNobody"}`)
	c2.Close()
	if out["ok"] != false || out["error"] != "unknown-peer" {
		t.Fatalf("an unknown Mac: %v", out)
	}
}

// A road with nothing to ping says null: here this helper does not know the
// other Mac's tailnet address.
func TestPutPathNoRoad(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	tun := &fakeTunnel{ping: &ipnstate.PingResult{LatencySeconds: 0.031, Endpoint: "203.0.113.9:41641", NodeName: "study"}}
	withFakeTunnels(t, f, tun, tun)
	c, r, out := dialPut(t, `{"op":"path","agent":"macStudy01"}`)
	defer c.Close()
	if out["ok"] != true {
		t.Fatalf("path: %v", out)
	}
	nulls, pongs := 0, 0
	for nulls < 1 || pongs < 1 {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		if v, ok := got["tailnet"]; ok {
			if string(v) != "null" {
				t.Fatalf("tailnet with no address: %q", line)
			}
			nulls++
		}
		if _, ok := got["tailcat"]; ok {
			pongs++
		}
	}
}
