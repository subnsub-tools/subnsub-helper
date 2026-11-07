package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// tsFake stands in for tailscaled's LocalAPI: the status and the rules it
// answers, or the status codes it refuses with.
type tsFake struct {
	status     any
	rules      any
	statusCode int
	rulesCode  int
	asked      []string
}

func (f *tsFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.asked = append(f.asked, r.Method+" "+r.URL.Path)
	switch r.URL.Path {
	case "/localapi/v0/status":
		if f.statusCode != 0 {
			w.WriteHeader(f.statusCode)
			return
		}
		json.NewEncoder(w).Encode(f.status)
	case "/localapi/v0/debug-packet-filter-rules":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if f.rulesCode != 0 {
			w.WriteHeader(f.rulesCode)
			fmt.Fprint(w, `{"error":"debug access denied"}`)
			return
		}
		json.NewEncoder(w).Encode(f.rules)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// tsUse points the LocalAPI at f (nil: nothing answers) and clears the cache.
func tsUse(t *testing.T, f *tsFake) {
	t.Helper()
	dial, tok, addrs, cloud := tsLocalDial, tsLocalToken, tsLocalAddrs, tsSelfCloud
	t.Cleanup(func() {
		tsLocalDial, tsLocalToken, tsLocalAddrs, tsSelfCloud = dial, tok, addrs, cloud
		tsViewCache.Lock()
		tsViewCache.body = nil
		tsViewCache.Unlock()
	})
	tsViewCache.Lock()
	tsViewCache.body = nil
	tsViewCache.Unlock()
	tsLocalToken = func() string { return "" }
	tsLocalAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("10.0.0.30"), netip.MustParseAddr("127.0.0.1")}
	}
	tsSelfCloud = func() bool { return true }
	if f == nil {
		tsLocalDial = func(context.Context) (net.Conn, error) {
			return nil, errors.New("open \\\\.\\pipe\\tailscaled: The system cannot find the file specified.")
		}
		return
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	tsLocalDial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func tsStatusDoc(state string) map[string]any {
	return map[string]any{
		"BackendState":   state,
		"CurrentTailnet": map[string]any{"Name": "someone@example.com", "MagicDNSSuffix": "tail1234.ts.net"},
		"Self": map[string]any{
			"ID": "nSELF", "HostName": "instance-1", "DNSName": "web-1.tail1234.ts.net.", "OS": "linux",
			"TailscaleIPs": []string{"100.91.179.57", "fd7a:115c:a1e0::1"},
			"Addrs":        []string{"64.110.110.13:41641", "10.0.0.30:41641", "172.17.0.1:41641"},
			"Online":       false,
		},
		"Peer": map[string]any{
			"nodekey:aa": map[string]any{
				"ID": "nB", "HostName": "mac", "DNSName": "macbook.tail1234.ts.net.", "OS": "macOS",
				"TailscaleIPs": []string{"100.64.0.2", "fd7a:115c:a1e0::77"}, "Online": true,
				"Addrs": []string{"203.0.114.9:5555", "192.168.1.20:41641"},
			},
			"nodekey:bb": map[string]any{
				"ID": "nA", "HostName": "vps\x07", "DNSName": "", "OS": "linux", "Tags": []string{"tag:server"},
				"TailscaleIPs": []string{"100.64.0.3"}, "Online": false,
				"Addrs": []string{"45.1.2.3:41641", "[2001:db8::1]:41641"},
			},
			"nodekey:cc": map[string]any{
				"ID": "nV6", "HostName": "v6only", "OS": "linux", "TailscaleIPs": []string{"fd7a:115c:a1e0::9"},
			},
		},
	}
}

func tsRulesDoc() []map[string]any {
	return []map[string]any{
		{
			"SrcIPs": []string{"100.64.0.2", "fd7a:115c:a1e0::2", "100.64.0.0/10", "100.64.0.2", "100.64.0.5-100.64.0.9", "bogus"},
			"DstPorts": []map[string]any{
				{"IP": "100.91.179.57", "Ports": map[string]any{"First": 22, "Last": 22}},
				{"IP": "fd7a:115c:a1e0::1", "Ports": map[string]any{"First": 22, "Last": 22}},
				{"IP": "100.91.179.57", "Ports": map[string]any{"First": 22, "Last": 22}},
				{"IP": "100.64.0.3", "Ports": map[string]any{"First": 9, "Last": 3}},
			},
		},
		{"SrcIPs": []string{"*"}, "DstPorts": []map[string]any{{"IP": "*", "Ports": map[string]any{"First": 0, "Last": 65535}}}, "IPProto": []int{1, 58, 999}},
		// A capability grant opens no port.
		{"SrcIPs": []string{"100.64.0.2"}, "CapGrant": []map[string]any{{"Dsts": []string{"100.91.179.57/32"}, "Caps": []string{"tailscale.com/cap/relay-target"}}}},
		// Its source is no device here: nothing left of it.
		{"SrcIPs": []string{"fd7a:115c:a1e0::2"}, "DstPorts": []map[string]any{{"IP": "100.91.179.57", "Ports": map[string]any{"First": 80, "Last": 80}}}},
		// Devices by their IPv6 addresses only: each by its IPv4 one.
		{"SrcIPs": []string{"fd7a:115c:a1e0::/120"}, "DstPorts": []map[string]any{{"IP": "fd7a:115c:a1e0::1", "Ports": map[string]any{"First": 443, "Last": 443}}}, "IPProto": []int{6}},
	}
}

func tsGet(t *testing.T, h http.Handler, peer *key.NodePublic) (*httptest.ResponseRecorder, tsViewBody) {
	t.Helper()
	rec := speedCall(t, h, peer, "GET", "/v1/tailnet", nil)
	var b tsViewBody
	if rec.Code == 200 {
		f, err := transport.Decode(rec.Body.Bytes())
		if err != nil || f.Type != transport.TypeTailnet {
			t.Fatalf("frame: %v %+v", err, f)
		}
		if err := json.Unmarshal(f.Body, &b); err != nil {
			t.Fatal(err)
		}
	}
	return rec, b
}

// A machine whose helper may read the rules: its devices and its rules, as
// the map reads them.
func TestTailnetViewOK(t *testing.T) {
	f := newFilesFixture(t)
	fake := &tsFake{status: tsStatusDoc("Running"), rules: tsRulesDoc()}
	tsUse(t, fake)
	rec, b := tsGet(t, f.h, &f.peer)
	if rec.Code != 200 || b.State != "ok" || b.V != 1 || b.Net != "tail1234.ts.net" || b.Cut || b.Partial {
		t.Fatalf("view: %d %+v", rec.Code, b)
	}
	if b.Self == nil || b.Self.ID != "nSELF" || b.Self.Name != "web-1" || b.Self.IP != "100.91.179.57" || !b.Self.On || b.Self.Pub != "cloud" {
		t.Fatalf("self: %+v", b.Self)
	}
	// Sorted by name; the IPv6-only device has no place in an IPv4 rule set.
	if len(b.Peers) != 2 || b.Peers[0].Name != "macbook" || b.Peers[1].Name != "vps" {
		t.Fatalf("peers: %+v", b.Peers)
	}
	// Its own public endpoint and a LAN one: a router's address, not its own.
	if b.Peers[0].Pub != "" || !b.Peers[0].On {
		t.Errorf("macbook: %+v", b.Peers[0])
	}
	if b.Peers[1].Pub != "addr" || b.Peers[1].On || len(b.Peers[1].Tags) != 1 || b.Peers[1].Tags[0] != "tag:server" {
		t.Errorf("vps: %+v", b.Peers[1])
	}
	if len(b.Rules) != 3 {
		t.Fatalf("rules: %+v", b.Rules)
	}
	r0 := b.Rules[0]
	if strings.Join(r0.Src, " ") != "100.64.0.2 100.64.0.0/10 100.64.0.5-100.64.0.9" {
		t.Errorf("src: %v", r0.Src)
	}
	if len(r0.Dst) != 1 || r0.Dst[0] != (tsViewDst{IP: "100.91.179.57", F: 22, L: 22}) || len(r0.Proto) != 0 {
		t.Errorf("dst: %+v", r0)
	}
	r1 := b.Rules[1]
	if len(r1.Src) != 1 || r1.Src[0] != "*" || r1.Dst[0] != (tsViewDst{IP: "*", F: 0, L: 65535}) || fmt.Sprint(r1.Proto) != "[1 58]" {
		t.Errorf("rule 1: %+v", r1)
	}
	// The IPv6-only device (::9) has no IPv4 address to be drawn by.
	r2 := b.Rules[2]
	src := append([]string(nil), r2.Src...)
	sort.Strings(src)
	if strings.Join(src, " ") != "100.64.0.2 100.91.179.57" || len(r2.Dst) != 1 || r2.Dst[0] != (tsViewDst{IP: "100.91.179.57", F: 443, L: 443}) || fmt.Sprint(r2.Proto) != "[6]" {
		t.Errorf("rule 2: %+v", r2)
	}
	// Asked once within the TTL.
	tsGet(t, f.h, &f.peer)
	if len(fake.asked) != 2 {
		t.Errorf("asked: %v", fake.asked)
	}
	// The hello names it.
	rec = speedCall(t, f.h, &f.peer, "GET", "/v1/hello", nil)
	fr, _ := transport.Decode(rec.Body.Bytes())
	var hello transport.Hello
	json.Unmarshal(fr.Body, &hello)
	if !containsStr(hello.Caps, transport.CapTailnetMap) {
		t.Fatalf("hello caps: %v", hello.Caps)
	}
}

// A public address on an interface says so outside any cloud, and a cloud VM
// behind a NAT gateway (its port changed on the way out) is not taken for one.
func TestTailnetViewSelfPub(t *testing.T) {
	tsUse(t, nil)
	tsLocalAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("45.1.2.3")} }
	tsSelfCloud = func() bool { return false }
	if got := tsSelfPub(nil); got != "addr" {
		t.Errorf("public interface: %q", got)
	}
	tsLocalAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.0.0.30")} }
	if got := tsSelfPub([]string{"64.110.110.13:41641", "10.0.0.30:41641"}); got != "" {
		t.Errorf("not a cloud: %q", got)
	}
	tsSelfCloud = func() bool { return true }
	if got := tsSelfPub([]string{"64.110.110.13:60123", "10.0.0.30:41641"}); got != "" {
		t.Errorf("behind a gateway: %q", got)
	}
	if got := tsSelfPub([]string{"[::ffff:64.110.110.13]:41641", "10.0.0.30:41641"}); got != "cloud" {
		t.Errorf("mapped: %q", got)
	}
}

// Without the operator's rights: the devices, and a word that says why there
// are no rules.
func TestTailnetViewDenied(t *testing.T) {
	f := newFilesFixture(t)
	tsUse(t, &tsFake{status: tsStatusDoc("Running"), rulesCode: http.StatusForbidden})
	rec, b := tsGet(t, f.h, &f.peer)
	if rec.Code != 200 || b.State != "denied" || len(b.Peers) != 2 || b.Self == nil || len(b.Rules) != 0 || b.Rules == nil {
		t.Fatalf("denied: %d %+v", rec.Code, b)
	}
}

func TestTailnetViewNotRunning(t *testing.T) {
	f := newFilesFixture(t)
	for _, c := range []struct {
		fake *tsFake
		want string
	}{
		{&tsFake{status: tsStatusDoc("NeedsLogin")}, "stopped"},
		{&tsFake{status: tsStatusDoc("Stopped")}, "stopped"},
		{&tsFake{statusCode: http.StatusInternalServerError}, "error"},
		{&tsFake{status: "nonsense"}, "error"},
		{&tsFake{status: tsStatusDoc("Running"), rulesCode: http.StatusInternalServerError}, "error"},
		{nil, "absent"},
	} {
		tsUse(t, c.fake)
		rec, b := tsGet(t, f.h, &f.peer)
		if rec.Code != 200 || b.State != c.want || b.Peers == nil || b.Rules == nil {
			t.Errorf("want %s: %d %+v", c.want, rec.Code, b)
		}
		if c.want != "error" && c.want != "stopped" && c.want != "absent" && b.Self == nil {
			t.Errorf("want %s: no self", c.want)
		}
	}
}

// Only a browser on the list; a portable copy or a stranger is refused, and
// so is a request no road attributed.
func TestTailnetViewGate(t *testing.T) {
	f := newFilesFixture(t)
	tsUse(t, &tsFake{status: tsStatusDoc("Running"), rules: tsRulesDoc()})
	stranger := key.NewNode().Public()
	if rec, _ := tsGet(t, f.h, &stranger); rec.Code != http.StatusForbidden {
		t.Errorf("stranger: %d", rec.Code)
	}
	if rec := speedCall(t, f.h.mux, nil, "GET", "/v1/tailnet", nil); rec.Code != http.StatusForbidden || errCodeOf(rec) != "not-allowed" {
		t.Errorf("no peer: %d %s", rec.Code, rec.Body.String())
	}
	if rec := speedCall(t, f.h, &f.peer, "POST", "/v1/tailnet", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	// The tailnet road serves it as the tunnel does.
	if !tailnetInnerOK("/v1/tailnet") {
		t.Error("/v1/tailnet is not served on the tailnet road")
	}
}

// A network larger than a frame: cut to fit, and said so.
func TestTailnetViewFits(t *testing.T) {
	f := newFilesFixture(t)
	st := tsStatusDoc("Running")
	peers := map[string]any{}
	for i := 0; i < 3000; i++ {
		peers[fmt.Sprintf("nodekey:%d", i)] = map[string]any{
			"ID": fmt.Sprintf("n%05d", i), "HostName": fmt.Sprintf("host-%05d-with-a-long-name", i), "OS": "linux",
			"TailscaleIPs": []string{fmt.Sprintf("100.%d.%d.%d", 64+i/65536, (i/256)%256, i%256)}, "Online": true,
		}
	}
	st["Peer"] = peers
	var rules []map[string]any
	for i := 0; i < 5000; i++ {
		src := make([]string, 20)
		for j := range src {
			src[j] = fmt.Sprintf("100.65.%d.%d", i%256, j)
		}
		rules = append(rules, map[string]any{"SrcIPs": src, "DstPorts": []map[string]any{{"IP": "100.91.179.57", "Ports": map[string]any{"First": i % 65535, "Last": i % 65535}}}})
	}
	tsUse(t, &tsFake{status: st, rules: rules})
	rec, b := tsGet(t, f.h, &f.peer)
	if rec.Code != 200 || !b.Cut || !b.Partial || b.State != "ok" || len(b.Rules) == 0 || len(b.Peers) == 0 {
		t.Fatalf("fit: %d cut=%v partial=%v rules=%d peers=%d", rec.Code, b.Cut, b.Partial, len(b.Rules), len(b.Peers))
	}
	if rec.Body.Len() > transport.Limits[transport.TypeTailnet] {
		t.Fatalf("frame %d over the limit", rec.Body.Len())
	}
}

func TestTSAddrSpec(t *testing.T) {
	for in, want := range map[string]string{
		"*": "*", " 100.64.0.1 ": "100.64.0.1", "100.64.0.9/10": "100.64.0.0/10",
		"100.64.0.1-100.64.0.4": "100.64.0.1-100.64.0.4", "100.64.0.4-100.64.0.1": "",
		"fd7a::1": "", "fd7a::/48": "", "::ffff:100.64.0.1-100.64.0.2": "", "x": "", "": "",
	} {
		got, ok := tsAddrSpec(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	v6 := []tsV6{{netip.MustParseAddr("fd7a::1"), "100.64.0.1"}, {netip.MustParseAddr("fd7a::5"), "100.64.0.5"}, {netip.MustParseAddr("fd7b::1"), "100.64.0.9"}}
	for in, want := range map[string]string{
		"100.64.0.7": "100.64.0.7", "fd7a::1": "100.64.0.1", "fd7a::2": "", "fd7a::/64": "100.64.0.1 100.64.0.5",
		"fd7a::2-fd7a::9": "100.64.0.5", "fd7a::9-fd7a::2": "", "fd7a::/200": "", "x": "",
	} {
		if got := strings.Join(tsSpecs(in, v6), " "); got != want {
			t.Errorf("specs %q: %q", in, got)
		}
	}
	if got := tsClean("ab\x00c"+strings.Repeat("é", 40), 10); got != "abcééé" {
		t.Errorf("clean: %q", got)
	}
}
