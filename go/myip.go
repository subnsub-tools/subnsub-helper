package main

// The My IP check, asked FROM this machine — the `myip` command.
//
// The dashboard's Exit tile used to open a record of what the card already
// knew about a way out: the address the relay saw, where the edge places it,
// whose network it is. A press now opens the My IP page's own result for that
// way out instead (the reputation ledger, the
// registry record, the reverse name, the TLS the edge agreed, both families).
//
// THE PAGE CANNOT ASK FOR IT. Two of My IP's endpoints answer only about the
// address that is calling them — /api/iprep and /api/rdap take no ?ip=, on
// purpose (so they can never be scripted into a free
// bulk-reputation API) — and /api/ip is nothing but a description of the
// caller. A browser that asked would get its own answers. So the machine asks,
// over its own way out, and hands the answers back as they came.
//
// WHAT IS ASKED, and why each:
//
//	ip    /api/ip            the edge's description of this connection: the
//	                         address, its geolocation, its AS, the TLS and
//	                         HTTP the edge agreed, the edge node
//	ip4   /api/ip over IPv4  the same, forced onto each family, so the page's
//	ip6   /api/ip over IPv6  IPv6 Readiness card has this machine's two
//	                         addresses instead of a browser's
//	rep   /api/iprep         the reputation signals for the address
//	rdap  /api/rdap          the registry record for its block
//	trace /cdn-cgi/trace     WARP, Gateway, SNI and the key-exchange group
//
// The four without a family describe ONE address. They share one transport,
// `ip` goes first, and the rest follow on the connection it opened (HTTP/2
// multiplexes them), so a dual-stack machine cannot answer `ip` over IPv6 and
// `rep` over IPv4 and have the page score one address with another's lists.
// The two forced ones run beside them on their own transports.
//
// NOT A CLAIM THE RELAY CAN CHECK. The Exit record's address is an observation
// (transport.go, spaces.go): the relay saw a connection arrive and sealed what
// it saw. These answers are bodies this helper read and passes on — a machine
// that lied could hand the page any answers it liked. The page labels the
// result as the machine's own report; nothing here feeds the card's egress.
//
// A CLOSED REQUEST. The dashboard names a namespace or nothing; the origin is
// this machine's setting (MON_MYIP), never a field of the command, and the six
// paths are fixed here. A command cannot point this machine at an address of
// anyone's choosing, which is the whole difference between this and a fetch.
//
// IN ANOTHER NAMESPACE (target = its name, spaces.go): the origin is resolved
// in the helper's own namespace and only the connection is made from inside
// the other one (spaceDial), as the namespace probe does and for its reason —
// the other namespace's resolver may be a loopback that means something else
// in there. No proxy: a proxy variable describes the helper's own way out.
//
// MON_MYIP picks the origin: unset → https://ip.200000.live, "off" → the
// command is refused (myip-off) and not offered, an https origin → that one
// (a self-hosted copy of the site serves the same four paths).
//
// THE ANSWER is one compact JSON document in the result's Out:
//
//	{"v":1,"origin":"https://ip.200000.live","ns":"","at":1792300000,
//	 "p":{"ip":{"s":200,"ms":84,"b":{…}},"ip4":{…},"ip6":{"e":"unreachable"},
//	      "rep":{…},"rdap":{…},"trace":{"s":200,"ms":31,"b":"fl=…\nip=…\n"}}}
//
// A probe that answered carries its status, its time and its body — the JSON
// endpoints' bodies embedded as JSON, the trace's as a string. One that did
// not carries why (myipErr*), and the status when there was one. The command
// succeeds whatever the probes did: "no IPv6 here" is an answer, and the page
// is the one that knows how to say it.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	myipEnvVar     = "MON_MYIP"
	myipDefaultURL = "https://ip.200000.live"
	// Each request's own deadline; the registry lookup tries two registries
	// in series at four seconds each (myip.js RDAP_MS), so it gets more.
	myipTimeout     = 10 * time.Second
	myipRdapTimeout = 12 * time.Second
	// The whole command: `ip`, then the rest after it, with room. Under the
	// console's 30 s so a tunnel caller waiting on the gate is answered.
	myipBudget = 25 * time.Second
	// One candidate address inside another namespace (spaceProbe's figure).
	myipDialTimeout = spaceDialTimeout
	// The largest answer any of the six gives is a few hundred bytes
	// (measured 2026-10-18: ip 399, iprep 521, rdap 344, trace 209).
	// Anything past this is not one of them.
	myipBodyMax = 8 << 10
	// What the serialised report keeps free beside Out (consoleReport sizes
	// the whole document against consoleMaxBody and halves Out to fit —
	// which would leave half a JSON document, so Out is sized here first).
	myipEnvelopeRoom = 2 << 10
)

// Why a probe has no body. A closed set: the page translates each.
const (
	myipErrTimeout     = "timeout"
	myipErrUnreachable = "unreachable"
	myipErrRefused     = "refused"       // an HTTP status other than 200
	myipErrBadAnswer   = "bad-answer"    // not JSON, not an object, or empty
	myipErrTooBig      = "too-big"       // past myipBodyMax, or dropped to fit Out
	myipErrFamily      = "family"        // ip4/ip6: answered from the other family
	myipErrOther       = "other-address" // rep/rdap/trace: about another address than ip's
)

// Test seams. Nil in a running helper: the system's dialer and roots.
var (
	myipDialHook func(ctx context.Context, network, addr string) (net.Conn, error)
	myipTLS      *tls.Config
)

type myipProbe struct {
	S  int             `json:"s,omitempty"`
	Ms *int64          `json:"ms,omitempty"`
	B  json.RawMessage `json:"b,omitempty"`
	E  string          `json:"e,omitempty"`
}

type myipProbes struct {
	IP    myipProbe `json:"ip"`
	IP4   myipProbe `json:"ip4"`
	IP6   myipProbe `json:"ip6"`
	Rep   myipProbe `json:"rep"`
	Rdap  myipProbe `json:"rdap"`
	Trace myipProbe `json:"trace"`
}

type myipOut struct {
	V      int        `json:"v"`
	Origin string     `json:"origin"`
	NS     string     `json:"ns"`
	At     int64      `json:"at"`
	P      myipProbes `json:"p"`
}

// myipSource is MON_MYIP read: the origin to ask, or "" for none. An origin
// only — scheme, host, optional port — because the paths are this file's: a
// value with a path, a query, credentials or a fragment is not an origin and
// switches the check off rather than being half-used.
func myipSource() string {
	v := strings.TrimSpace(envSetting(myipEnvVar, installedEnv()))
	switch strings.ToLower(v) {
	case "":
		return myipDefaultURL
	case "0", "off", "false", "no":
		return ""
	}
	v = strings.TrimSuffix(v, "/")
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		strings.ContainsAny(v, "?#") {
		return ""
	}
	return "https://" + u.Host
}

// myipAvailable: whether this machine takes the command now — an origin to
// ask, and the mailbox gate `refresh` passes (a switch that lets it take
// instructions at all). The reading's `myip` and the tunnel's capability say
// exactly this, so the page offers only what runMyIP would do.
func myipAvailable() bool {
	return myipSource() != "" && (consoleEnabled() || updateAllowed() || diagnosticsEnabled())
}

// myipTargetOK: the helper's own namespace, or one the card shows as an exit
// of its own (spacesPick: a name the card takes, inside MON_NETNS).
func myipTargetOK(t string) bool {
	if t == "" {
		return true
	}
	if !spacesAvailable() || !spaceNameOK(t) {
		return false
	}
	for _, n := range spacesPick(spacesFound()) {
		if n == t {
			return true
		}
	}
	return false
}

func runMyIP(c consoleCmd) (res consoleResult) {
	res = consoleResult{ID: c.ID, Kind: "myip", Target: c.Target, Code: -1}
	started := time.Now()
	defer func() { res.Ms = time.Since(started).Milliseconds() }()
	if c.Cmd != "" {
		res.Error = "bad-request"
		return res
	}
	src := myipSource()
	if src == "" {
		res.Error = "myip-off"
		return res
	}
	if !consoleEnabled() && !updateAllowed() && !diagnosticsEnabled() {
		res.Error = "no-mailbox"
		return res
	}
	if !myipTargetOK(c.Target) {
		res.Error = "bad-target"
		return res
	}
	o := myipRun(src, c.Target)
	res.Code = 0
	res.Out = myipEncode(&o)
	return res
}

// myipRun asks the six questions and waits for every answer, bounded by
// myipBudget whatever the network does.
func myipRun(src, ns string) myipOut {
	ctx, cancel := context.WithTimeout(context.Background(), myipBudget)
	defer cancel()
	out := myipOut{V: 1, Origin: src, NS: ns, At: time.Now().Unix()}
	def := myipClient(ns, "tcp", true)
	c4 := myipClient(ns, "tcp4", false)
	c6 := myipClient(ns, "tcp6", false)
	defer def.CloseIdleConnections()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); out.P.IP4 = myipGet(ctx, c4, src+"/api/ip", myipTimeout, 4) }()
	go func() { defer wg.Done(); out.P.IP6 = myipGet(ctx, c6, src+"/api/ip", myipTimeout, 6) }()

	// First, alone: the connection the other three then ride.
	out.P.IP = myipGet(ctx, def, src+"/api/ip", myipTimeout, 0)
	wg.Add(3)
	go func() { defer wg.Done(); out.P.Rep = myipGet(ctx, def, src+"/api/iprep", myipTimeout, 0) }()
	go func() { defer wg.Done(); out.P.Rdap = myipGet(ctx, def, src+"/api/rdap", myipRdapTimeout, 0) }()
	go func() { defer wg.Done(); out.P.Trace = myipGet(ctx, def, src+"/cdn-cgi/trace", myipTimeout, -1) }()
	wg.Wait()
	myipSameAddress(&out.P)
	return out
}

// myipSameAddress keeps the report about one address. The three that follow
// /api/ip ride its connection when that speaks HTTP/2; over HTTP/1.1 (an
// origin of the operator's own), or after the connection dropped, they open
// others, and on a machine with more than one route another connection can
// leave from another address. An answer about
// another address is not this way out's: given up, never mixed in.
func myipSameAddress(p *myipProbes) {
	ip := myipAnswerIP(p.IP, false)
	if ip == "" {
		return
	}
	for _, x := range []struct {
		pr    *myipProbe
		trace bool
	}{{&p.Rep, false}, {&p.Rdap, false}, {&p.Trace, true}} {
		if a := myipAnswerIP(*x.pr, x.trace); a != "" && a != ip {
			*x.pr = myipProbe{S: x.pr.S, E: myipErrOther}
		}
	}
}

// myipAnswerIP: the address an answer is about, in canonical form — the
// `ip` of a JSON answer, the `ip=` line of the trace — or "" when it names
// none.
func myipAnswerIP(p myipProbe, trace bool) string {
	if p.B == nil {
		return ""
	}
	var s string
	if trace {
		var t string
		if json.Unmarshal(p.B, &t) != nil {
			return ""
		}
		for _, ln := range strings.Split(t, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok && k == "ip" {
				s = v
				break
			}
		}
	} else {
		var a struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(p.B, &a) != nil {
			return ""
		}
		s = a.IP
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// myipClient: one transport, its family, its namespace. keep is the default
// family's shared connection (keep-alives, HTTP/2); the forced families make
// one request each and close.
func myipClient(ns, network string, keep bool) *http.Client {
	tr := &http.Transport{
		// A copy each: the HTTP/2 transport writes "h2" into the config it
		// is given, and a shared one would make the HTTP/1-only forced
		// families offer it too.
		TLSClientConfig:     myipTLS.Clone(),
		TLSHandshakeTimeout: myipTimeout,
		ForceAttemptHTTP2:   keep,
		DisableKeepAlives:   !keep,
		IdleConnTimeout:     30 * time.Second,
	}
	switch {
	case myipDialHook != nil:
		tr.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			return myipDialHook(ctx, network, addr)
		}
	case ns == "":
		// The machine's own way out, proxy and all — what a browser on it
		// would use (ipv4.go's arrangement, with the family left open for
		// the default).
		tr.Proxy = http.ProxyFromEnvironment
		d := &net.Dialer{Timeout: myipTimeout}
		tr.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	default:
		tr.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			return myipSpaceDial(ctx, ns, network, addr)
		}
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// myipSpaceDial: the origin resolved here, dialled from inside ns — every
// candidate of the family in the resolver's order, until one connects or
// the namespace turns out not to be enterable.
func myipSpaceDial(ctx context.Context, ns, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		found, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range found {
			ips = append(ips, a.IP)
		}
	}
	var last error = errors.New("no address of that family")
	for _, ip := range ips {
		v4 := ip.To4() != nil
		if (network == "tcp4" && !v4) || (network == "tcp6" && v4) {
			continue
		}
		var entered atomic.Bool
		dctx, stop := context.WithTimeout(ctx, myipDialTimeout)
		conn, err := spaceDial(dctx, ns, net.JoinHostPort(ip.String(), port), &entered)
		stop()
		if err == nil {
			return conn, nil
		}
		last = err
		if !entered.Load() || ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// myipGet asks one question. fam: 4 or 6 for a forced family (the answer's
// address must be of it), 0 for a JSON answer in any family, -1 for the
// trace's text.
func myipGet(parent context.Context, client *http.Client, u string, timeout time.Duration, fam int) myipProbe {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return myipProbe{E: myipErrUnreachable}
	}
	req.Header.Set("User-Agent", "subnsub-helper/"+helperVersion)
	if fam >= 0 {
		req.Header.Set("Accept", "application/json")
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return myipProbe{E: myipNetErr(ctx, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, myipBodyMax))
		return myipProbe{S: resp.StatusCode, E: myipErrRefused}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, myipBodyMax+1))
	if err != nil {
		return myipProbe{S: resp.StatusCode, E: myipNetErr(ctx, err)}
	}
	ms := time.Since(started).Milliseconds()
	p := myipProbe{S: resp.StatusCode, Ms: &ms}
	if len(body) > myipBodyMax {
		return myipProbe{S: resp.StatusCode, E: myipErrTooBig}
	}
	b, why := myipBody(body, fam)
	if why != "" {
		return myipProbe{S: resp.StatusCode, E: why}
	}
	p.B = b
	return p
}

// myipBody is an answer judged and made ready to embed: a JSON object,
// compacted, with a forced family's address checked against the family; or
// the trace's text as a JSON string.
func myipBody(body []byte, fam int) (json.RawMessage, string) {
	if fam < 0 {
		if len(bytes.TrimSpace(body)) == 0 {
			return nil, myipErrBadAnswer
		}
		s, _ := json.Marshal(string(body))
		return s, ""
	}
	t := bytes.TrimSpace(body)
	if len(t) == 0 || t[0] != '{' || !json.Valid(t) {
		return nil, myipErrBadAnswer
	}
	var buf bytes.Buffer
	if json.Compact(&buf, t) != nil {
		return nil, myipErrBadAnswer
	}
	if fam == 4 || fam == 6 {
		var a struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(t, &a) != nil || !myipFamilyOK(a.IP, fam) {
			return nil, myipErrFamily
		}
	}
	return buf.Bytes(), ""
}

// myipFamilyOK: the address is one of that family. An IPv4-mapped IPv6
// (::ffff:a.b.c.d) is IPv4 that arrived dressed as six — not an IPv6 exit.
func myipFamilyOK(s string, fam int) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	if fam == 4 {
		return ip.To4() != nil && !strings.Contains(s, ":")
	}
	return ip.To4() == nil && strings.Contains(s, ":")
}

func myipNetErr(ctx context.Context, err error) string {
	var ne net.Error
	if (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return myipErrTimeout
	}
	return myipErrUnreachable
}

// myipEncode is the document, sized to travel: under the console's output
// cap, and with room in the serialised report beside it (myipEnvelopeRoom).
// Over that — which no real answer comes near — bodies are given up whole,
// the largest-and-least-needed first, rather than cut: half a JSON document
// is no answer at all.
func myipEncode(o *myipOut) string {
	drop := []*myipProbe{&o.P.Rdap, &o.P.Rep, &o.P.Trace, &o.P.IP6, &o.P.IP4, &o.P.IP}
	for i := 0; ; i++ {
		b, err := json.Marshal(o)
		if err != nil {
			b = []byte(`{"v":1}`)
		}
		if myipFits(b) {
			return string(b)
		}
		for i < len(drop) && drop[i].B == nil {
			i++
		}
		if i >= len(drop) {
			return string(b)
		}
		*drop[i] = myipProbe{S: drop[i].S, E: myipErrTooBig}
	}
}

func myipFits(b []byte) bool {
	if len(b) > consoleMaxOutput {
		return false
	}
	enc, err := json.Marshal(string(b))
	return err == nil && len(enc) <= consoleMaxBody-myipEnvelopeRoom
}
