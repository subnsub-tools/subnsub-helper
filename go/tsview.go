package main

// What this machine's Tailscale knows of its network, for the dashboard's map
// of who can reach whom on the tailnet. Read from the local tailscaled's
// LocalAPI when a browser asks:
//
//	status                     every device: name, OS, tags, online, address,
//	                           and the endpoints it announces
//	debug-packet-filter-rules  the access rules the control plane sent this
//	                           machine: every rule that lets something reach
//	                           it, with each rule's full destination list
//
// So each machine knows for certain who may reach it, and something of who
// may reach the others. The page joins what every machine says.
//
// Reading the rules takes LocalAPI write access: root or the Tailscale
// operator on Linux (sudo tailscale set --operator=$USER), any local user on
// Windows, the app's own token on macOS. Without it the answer says "denied"
// and still carries the devices. Nothing here changes Tailscale.
//
// Served over the direct roads alone (the tunnel and the tailnet listener),
// to a browser on the allowlist, and never sent to the relay: the shape of a
// private network is not the relay's to hold.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
)

const (
	tsViewTimeout = 5 * time.Second
	// An answer is kept this long: several pages, or one page drawing again,
	// do not each knock on tailscaled.
	tsViewTTL = 15 * time.Second
	// What is read of the LocalAPI's answers at most; a large tailnet's
	// status is a few MB.
	tsViewReadMax  = 32 << 20
	tsViewMaxNodes = 2000
	tsViewMaxRules = 4000
	// Source and destination entries across all rules.
	tsViewMaxAddrs = 40000
	tsViewNameMax  = 63
	tsViewTagMax   = 80
	tsViewTagsMax  = 16
)

// tsViewBody is the tailnet frame's body.
type tsViewBody struct {
	V int `json:"v"`
	// ok: devices and rules. denied: devices, but this helper may not read
	// the rules. stopped: Tailscale is installed and not running or not
	// logged in. absent: no tailscaled answered. error: it answered nonsense.
	State string `json:"state"`
	OS    string `json:"os"`
	// Which tailnet: its MagicDNS suffix, the same for every machine on it.
	Net   string       `json:"net,omitempty"`
	Self  *tsViewNode  `json:"self,omitempty"`
	Peers []tsViewNode `json:"peers"`
	Rules []tsViewRule `json:"rules"`
	// Cut: the network was larger than one frame holds, and the rest left out.
	Cut bool `json:"cut,omitempty"`
	// Partial: some of the rules are among what was left out, so what they
	// do not open on this machine is not known to be shut.
	Partial bool  `json:"partial,omitempty"`
	At      int64 `json:"at"`
}

type tsViewNode struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	OS   string   `json:"os,omitempty"`
	Tags []string `json:"tags,omitempty"`
	IP   string   `json:"ip"`
	On   bool     `json:"on"`
	// Why the node is taken to face the internet: "addr" when it holds a
	// public address itself, "cloud" (this machine only) when it is a cloud
	// VM whose public address maps straight onto it. Empty when nothing says
	// so, which is not the same as "it does not".
	Pub string `json:"pub,omitempty"`
}

type tsViewRule struct {
	Src []string    `json:"src"`
	Dst []tsViewDst `json:"dst"`
	// IP protocol numbers; empty means TCP, UDP and ICMP.
	Proto []int `json:"proto,omitempty"`
}

type tsViewDst struct {
	IP string `json:"ip"`
	F  uint16 `json:"f"`
	L  uint16 `json:"l"`
}

// The LocalAPI's documents, as much of them as is read here.
type tsLocalStatus struct {
	BackendState   string
	Self           *tsLocalPeer
	Peer           map[string]*tsLocalPeer
	CurrentTailnet *struct{ MagicDNSSuffix string }
}

type tsLocalPeer struct {
	ID           string
	HostName     string
	DNSName      string
	OS           string
	Tags         []string
	TailscaleIPs []string
	Online       bool
	Addrs        []string
}

type tsLocalRule struct {
	SrcIPs   []string
	DstPorts []struct {
		IP    string
		Ports struct{ First, Last uint16 }
	}
	IPProto []int
}

// tsLocalDial reaches tailscaled: the macOS app's local port where there is
// one, else the platform's socket or pipe. A variable for the tests.
var tsLocalDial = func(ctx context.Context) (net.Conn, error) {
	if port, _, err := safesocket.LocalTCPPortAndToken(); err == nil {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(port))
	}
	return safesocket.ConnectContext(ctx, paths.DefaultTailscaledSocket())
}

// tsLocalToken is the macOS app's LocalAPI token, "" elsewhere.
var tsLocalToken = func() string {
	if _, tok, err := safesocket.LocalTCPPortAndToken(); err == nil {
		return tok
	}
	return ""
}

var errTSAbsent = errors.New("tailscaled not reachable")

// tsLocal asks the LocalAPI one thing: the answer's status and body, or
// errTSAbsent when nothing answered.
func tsLocal(ctx context.Context, method, path string) (int, []byte, error) {
	// Any failure to reach it, whatever the platform calls it (a missing
	// socket, a pipe nobody serves, the app not running), is "absent".
	var dialFailed atomic.Bool
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := tsLocalDial(ctx)
			if err != nil {
				dialFailed.Store(true)
			}
			return c, err
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://local-tailscaled.sock/localapi/v0/"+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Tailscale-Cap", strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
	if tok := tsLocalToken(); tok != "" {
		req.SetBasicAuth("", tok)
	}
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		if dialFailed.Load() {
			return 0, nil, errTSAbsent
		}
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, tsViewReadMax+1))
	if err != nil {
		return res.StatusCode, nil, err
	}
	if len(b) > tsViewReadMax {
		return res.StatusCode, nil, errors.New("answer too large")
	}
	return res.StatusCode, b, nil
}

var tsViewCache struct {
	sync.Mutex
	at   time.Time
	body *tsViewBody
}

// tsViewNow is the machine's view, read afresh at most every tsViewTTL.
func tsViewNow() *tsViewBody {
	tsViewCache.Lock()
	defer tsViewCache.Unlock()
	if tsViewCache.body != nil && time.Since(tsViewCache.at) < tsViewTTL {
		return tsViewCache.body
	}
	ctx, cancel := context.WithTimeout(context.Background(), tsViewTimeout)
	defer cancel()
	b := tsViewRead(ctx)
	tsViewCache.body, tsViewCache.at = b, time.Now()
	return b
}

func tsViewRead(ctx context.Context) *tsViewBody {
	out := &tsViewBody{V: 1, OS: runtime.GOOS, Peers: []tsViewNode{}, Rules: []tsViewRule{}, At: time.Now().Unix()}
	code, raw, err := tsLocal(ctx, http.MethodGet, "status")
	switch {
	case errors.Is(err, errTSAbsent):
		out.State = "absent"
		return out
	case err != nil:
		out.State = "error"
		return out
	case code == http.StatusForbidden:
		out.State = "denied"
		return out
	case code != http.StatusOK:
		out.State = "error"
		return out
	}
	var st tsLocalStatus
	if json.Unmarshal(raw, &st) != nil || st.Self == nil {
		out.State = "error"
		return out
	}
	if st.BackendState != "Running" {
		out.State = "stopped"
		return out
	}
	if st.CurrentTailnet != nil {
		out.Net = tsClean(st.CurrentTailnet.MagicDNSSuffix, 120)
	}
	self, ok := tsNode(st.Self)
	if !ok {
		out.State = "error"
		return out
	}
	self.On = true
	self.Pub = tsSelfPub(st.Self.Addrs)
	out.Self = &self
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		if n, ok := tsNode(p); ok {
			if tsAllPublic(p.Addrs) {
				n.Pub = "addr"
			}
			out.Peers = append(out.Peers, n)
		}
	}
	sort.Slice(out.Peers, func(i, j int) bool {
		a, b := strings.ToLower(out.Peers[i].Name), strings.ToLower(out.Peers[j].Name)
		if a != b {
			return a < b
		}
		return out.Peers[i].ID < out.Peers[j].ID
	})
	if len(out.Peers) > tsViewMaxNodes {
		out.Peers, out.Cut = out.Peers[:tsViewMaxNodes], true
	}

	code, raw, err = tsLocal(ctx, http.MethodPost, "debug-packet-filter-rules")
	switch {
	case err == nil && code == http.StatusForbidden:
		out.State = "denied"
		return out
	case err != nil || code != http.StatusOK:
		out.State = "error"
		return out
	}
	var rules []tsLocalRule
	if json.Unmarshal(raw, &rules) != nil {
		out.State = "error"
		return out
	}
	out.State = "ok"
	all := make([]*tsLocalPeer, 0, len(st.Peer)+1)
	all = append(all, st.Self)
	for _, p := range st.Peer {
		if p != nil {
			all = append(all, p)
		}
	}
	out.Rules, out.Partial = tsRules(rules, tsV6Map(all))
	out.Cut = out.Cut || out.Partial
	tsFit(out)
	return out
}

// tsNode is a device as the frame carries it; false when it has no IPv4
// address on the tailnet, the one every rule names it by.
func tsNode(p *tsLocalPeer) (tsViewNode, bool) {
	ip := ""
	for _, a := range p.TailscaleIPs {
		if v, err := netip.ParseAddr(a); err == nil && v.Is4() {
			ip = v.String()
			break
		}
	}
	if ip == "" {
		return tsViewNode{}, false
	}
	// The name the admin console shows: the first label of its MagicDNS
	// name, which an admin may have changed from the host's own.
	name := strings.SplitN(strings.TrimSuffix(p.DNSName, "."), ".", 2)[0]
	if name == "" {
		name = p.HostName
	}
	name = tsClean(name, tsViewNameMax)
	if name == "" {
		name = ip
	}
	n := tsViewNode{ID: tsClean(p.ID, 64), Name: name, OS: tsClean(p.OS, 24), IP: ip, On: p.Online}
	if n.ID == "" {
		n.ID = ip
	}
	for _, t := range p.Tags {
		if t = tsClean(t, tsViewTagMax); t != "" && len(n.Tags) < tsViewTagsMax {
			n.Tags = append(n.Tags, t)
		}
	}
	return n, true
}

// tsClean keeps a string printable and short.
func tsClean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > max {
		// Cut at a byte count, and a rune split there dropped.
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// tsPublic4 is an IPv4 address the internet routes: not private, shared
// (CGNAT, which is also Tailscale's own range), loopback, link-local,
// benchmarking or reserved.
func tsPublic4(a netip.Addr) bool {
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range tsNotPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var tsNotPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// tsEndpoints splits the IPv4 endpoints a node announces into public and
// private ones, as ip:port.
func tsEndpoints(addrs []string) (pub, priv []netip.AddrPort) {
	for _, s := range addrs {
		ap, err := netip.ParseAddrPort(s)
		if err != nil || !ap.Addr().Unmap().Is4() {
			continue
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if tsPublic4(ap.Addr()) {
			pub = append(pub, ap)
		} else if ap.Addr().IsPrivate() {
			priv = append(priv, ap)
		}
	}
	return pub, priv
}

// tsAllPublic: the node announces public IPv4 endpoints and no private one,
// so a public address is its own rather than a router's in front of it.
func tsAllPublic(addrs []string) bool {
	pub, priv := tsEndpoints(addrs)
	return len(pub) > 0 && len(priv) == 0
}

// tsLocalAddrs is this machine's interface addresses. A variable for the
// tests.
var tsLocalAddrs = func() []netip.Addr {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// tsSelfCloud says whether this machine is a cloud's VM. A variable for the
// tests.
var tsSelfCloud = func() bool {
	d := machineDevice()
	return d != nil && tsCloudVendors[d.Vendor] && (d.Form == formVM || d.Form == formServer)
}

// The names device.go's cloudOf gives.
var tsCloudVendors = map[string]bool{
	"Oracle Cloud": true, "Amazon EC2": true, "Azure": true, "Google Cloud": true,
	"DigitalOcean": true, "Hetzner": true, "Vultr": true, "Akamai": true,
	"Alibaba Cloud": true, "Tencent Cloud": true, "Scaleway": true, "OpenStack": true,
}

// tsSelfPub is why this machine faces the internet, or "". A public address
// on one of its own interfaces says so outright. A cloud VM is reached
// through a public address its provider maps onto a private one, port for
// port, so the port tailscaled listens on comes back unchanged from the
// internet's side; a VM behind a shared NAT gateway does not see that.
func tsSelfPub(endpoints []string) string {
	for _, a := range tsLocalAddrs() {
		if tsPublic4(a) {
			return "addr"
		}
	}
	if !tsSelfCloud() {
		return ""
	}
	pub, priv := tsEndpoints(endpoints)
	for _, p := range pub {
		for _, q := range priv {
			if p.Port() == q.Port() {
				return "cloud"
			}
		}
	}
	return ""
}

// tsAddrSpec keeps an IPv4 source or destination as the rules write it — an
// address, a prefix, a range "a-b" or "*"; false for anything else.
func tsAddrSpec(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return s, true
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 == nil && err2 == nil && a.Is4() && b.Is4() && !b.Less(a) {
			return a.String() + "-" + b.String(), true
		}
		return "", false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err == nil && p.Addr().Is4() {
			return p.Masked().String(), true
		}
		return "", false
	}
	a, err := netip.ParseAddr(s)
	if err == nil && a.Is4() {
		return a.String(), true
	}
	return "", false
}

// tsV6 is a device's IPv6 tailnet address and its IPv4 one.
type tsV6 struct {
	a  netip.Addr
	v4 string
}

// tsV6Map pairs each device's IPv6 tailnet addresses with its IPv4 one: a
// rule may name a device by either, and the map draws devices.
func tsV6Map(nodes []*tsLocalPeer) []tsV6 {
	var out []tsV6
	for _, p := range nodes {
		v4 := ""
		var v6 []netip.Addr
		for _, a := range p.TailscaleIPs {
			v, err := netip.ParseAddr(a)
			switch {
			case err != nil:
			case v.Is4():
				if v4 == "" {
					v4 = v.String()
				}
			case v.Is6():
				v6 = append(v6, v.WithZone(""))
			}
		}
		if v4 == "" {
			continue
		}
		for _, a := range v6 {
			out = append(out, tsV6{a, v4})
		}
	}
	return out
}

// tsSpecs is one source or destination as IPv4 specs (tsAddrSpec). An IPv6
// one — an address, a prefix or a range — becomes the IPv4 address of each
// device whose IPv6 address it holds; an IPv6 address no device here has
// names nothing that can reach this machine or be reached from it.
func tsSpecs(s string, v6 []tsV6) []string {
	if v, ok := tsAddrSpec(s); ok {
		return []string{v}
	}
	s = strings.TrimSpace(s)
	var in func(netip.Addr) bool
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil || !a.Is6() || !b.Is6() || b.Less(a) {
			return nil
		}
		a, b = a.WithZone(""), b.WithZone("")
		in = func(x netip.Addr) bool { return !x.Less(a) && !b.Less(x) }
	} else if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is6() {
			return nil
		}
		in = p.Masked().Contains
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is6() {
			return nil
		}
		a = a.WithZone("")
		in = func(x netip.Addr) bool { return x == a }
	}
	var out []string
	for _, d := range v6 {
		if in(d.a) {
			out = append(out, d.v4)
		}
	}
	return out
}

// tsRules is the rules as the frame carries them: network rules only (a
// capability grant opens no port), each device by its IPv4 address, each
// entry once; true when some were left out.
func tsRules(in []tsLocalRule, v6 []tsV6) ([]tsViewRule, bool) {
	out := []tsViewRule{}
	n := 0
	for _, r := range in {
		if len(r.DstPorts) == 0 {
			continue
		}
		if len(out) >= tsViewMaxRules || n >= tsViewMaxAddrs {
			return out, true
		}
		var vr tsViewRule
		seen := map[string]bool{}
		for _, s := range r.SrcIPs {
			for _, v := range tsSpecs(s, v6) {
				if !seen[v] {
					seen[v] = true
					vr.Src = append(vr.Src, v)
				}
			}
		}
		seenDst := map[tsViewDst]bool{}
		for _, d := range r.DstPorts {
			f, l := d.Ports.First, d.Ports.Last
			if l < f {
				continue
			}
			for _, v := range tsSpecs(d.IP, v6) {
				dd := tsViewDst{IP: v, F: f, L: l}
				if !seenDst[dd] {
					seenDst[dd] = true
					vr.Dst = append(vr.Dst, dd)
				}
			}
		}
		if n+len(vr.Src)+len(vr.Dst) > tsViewMaxAddrs {
			return out, true
		}
		if len(vr.Src) == 0 || len(vr.Dst) == 0 {
			continue
		}
		for _, p := range r.IPProto {
			if p >= 0 && p <= 255 && len(vr.Proto) < 16 {
				vr.Proto = append(vr.Proto, p)
			}
		}
		n += len(vr.Src) + len(vr.Dst)
		out = append(out, vr)
	}
	return out, false
}

// tsFit trims the view until its frame is under the type's ceiling: rules
// first, then devices, each halved, and says it was cut.
func tsFit(b *tsViewBody) {
	limit := transport.Limits[transport.TypeTailnet] - 4<<10
	for {
		raw, err := json.Marshal(b)
		if err != nil || len(raw) <= limit {
			return
		}
		b.Cut = true
		switch {
		case len(b.Rules) > 1:
			b.Rules, b.Partial = b.Rules[:len(b.Rules)/2], true
		case len(b.Peers) > 1:
			b.Peers = b.Peers[:len(b.Peers)/2]
		default:
			b.Rules, b.Peers, b.Partial = []tsViewRule{}, []tsViewNode{}, true
			return
		}
	}
}

// tailnetView answers GET /v1/tailnet: this machine's view, to a browser on
// the allowlist.
func (h *directHandler) tailnetView(w http.ResponseWriter, r *http.Request) {
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
	f, err := transport.New(transport.TypeTailnet, agentID(), r.Header.Get("X-Request-Id"), tsViewNow())
	var b []byte
	if err == nil {
		b, err = transport.Encode(f)
	}
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}
