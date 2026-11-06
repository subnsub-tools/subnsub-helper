package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"subnsubmonitor/transport"
)

func TestMyIPSource(t *testing.T) {
	for in, want := range map[string]string{
		"":                            myipDefaultURL,
		"off":                         "",
		"OFF":                         "",
		"0":                           "",
		"no":                          "",
		"false":                       "",
		"https://ip.example.net":      "https://ip.example.net",
		"https://ip.example.net/":     "https://ip.example.net",
		"https://ip.example.net:8443": "https://ip.example.net:8443",
		"  https://ip.example.net  ":  "https://ip.example.net",
		"http://ip.example.net":       "",
		"https://ip.example.net/ip":   "",
		"https://ip.example.net/?x=1": "",
		"https://ip.example.net#f":    "",
		"https://u:p@ip.example.net":  "",
		"https://":                    "",
		"ftp://ip.example.net":        "",
		"ip.example.net":              "",
	} {
		t.Setenv(myipEnvVar, in)
		if got := myipSource(); got != want {
			t.Errorf("MON_MYIP=%q: myipSource() = %q, want %q", in, got, want)
		}
	}
}

// The installer's private config is read like MON_IPV4's: a line there
// switches the check off for the service, which never sees the shell.
func TestMyIPSourceInstalledConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(myipEnvVar, "x")
	if err := os.Unsetenv(myipEnvVar); err != nil {
		t.Fatal(err)
	}
	conf := configDir()
	if conf == "" {
		t.Skip("no config dir on this platform")
	}
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := myipSource(); got != myipDefaultURL {
		t.Fatalf("nothing configured: myipSource() = %q, want the default", got)
	}
	if err := os.WriteFile(filepath.Join(conf, tokenEnvFile), []byte("SUBNSUB_MONITOR_TOKEN=x\nMON_MYIP=off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := myipSource(); got != "" {
		t.Fatalf("MON_MYIP=off in the installed config: myipSource() = %q, want none", got)
	}
}

func TestMyIPTarget(t *testing.T) {
	if !myipTargetOK("") {
		t.Fatal("the helper's own namespace refused")
	}
	for _, bad := range []string{"..", ".", "a b", "../etc", "cni-1234", strings.Repeat("a", 33), "x/y", "nonexistent-ns-0"} {
		if myipTargetOK(bad) {
			t.Errorf("target %q accepted", bad)
		}
	}
}

func TestMyIPFamily(t *testing.T) {
	for _, c := range []struct {
		ip  string
		fam int
		ok  bool
	}{
		{"203.0.113.5", 4, true},
		{"203.0.113.5", 6, false},
		{"2001:db8::5", 6, true},
		{"2001:db8::5", 4, false},
		{"::ffff:203.0.113.5", 6, false},
		{"::ffff:203.0.113.5", 4, false},
		{"", 4, false},
		{"not an address", 6, false},
	} {
		if got := myipFamilyOK(c.ip, c.fam); got != c.ok {
			t.Errorf("myipFamilyOK(%q, %d) = %v, want %v", c.ip, c.fam, got, c.ok)
		}
	}
}

func TestMyIPBody(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		fam  int
		want string
		why  string
	}{
		"object compacted": {"{ \"ip\": \"203.0.113.5\",\n \"version\": 4 }", 0, `{"ip":"203.0.113.5","version":4}`, ""},
		"array":            {`["x"]`, 0, "", myipErrBadAnswer},
		"empty":            {"  ", 0, "", myipErrBadAnswer},
		"not json":         {"ip=203.0.113.5", 0, "", myipErrBadAnswer},
		"broken json":      {`{"ip":`, 0, "", myipErrBadAnswer},
		"family ok":        {`{"ip":"203.0.113.5"}`, 4, `{"ip":"203.0.113.5"}`, ""},
		"family other":     {`{"ip":"2001:db8::5"}`, 4, "", myipErrFamily},
		"family missing":   {`{"version":6}`, 6, "", myipErrFamily},
		"trace":            {"fl=1\nip=203.0.113.5\n", -1, `"fl=1\nip=203.0.113.5\n"`, ""},
		"trace empty":      {"\n", -1, "", myipErrBadAnswer},
	} {
		got, why := myipBody([]byte(c.in), c.fam)
		if why != c.why || string(got) != c.want {
			t.Errorf("%s: myipBody = %s, %q; want %s, %q", name, got, why, c.want, c.why)
		}
	}
}

func TestMyIPNetErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if got := myipNetErr(ctx, errors.New("connection refused")); got != myipErrUnreachable {
		t.Errorf("refused dial: %q", got)
	}
	if got := myipNetErr(ctx, context.DeadlineExceeded); got != myipErrTimeout {
		t.Errorf("deadline: %q", got)
	}
	cancel()
	if got := myipNetErr(ctx, errors.New("anything")); got != myipErrTimeout {
		t.Errorf("after the context ended: %q", got)
	}
}

// A body of n bytes as a JSON object (few quotes, so escaping barely grows it).
func myipBig(n int) json.RawMessage {
	return json.RawMessage(`{"x":"` + strings.Repeat("a", n) + `"}`)
}

func myipOK(b json.RawMessage) myipProbe {
	ms := int64(1)
	return myipProbe{S: 200, Ms: &ms, B: b}
}

func TestMyIPEncodeFits(t *testing.T) {
	// Over the cap by one body: the registry record goes, nothing else.
	o := myipOut{V: 1, Origin: myipDefaultURL}
	o.P.IP = myipOK(myipBig(4000))
	o.P.Rep = myipOK(myipBig(6000))
	o.P.Rdap = myipOK(myipBig(7000))
	s := myipEncode(&o)
	if !myipFits([]byte(s)) || !json.Valid([]byte(s)) {
		t.Fatalf("encoded does not fit or is not JSON: %d bytes", len(s))
	}
	var back myipOut
	if err := json.Unmarshal([]byte(s), &back); err != nil {
		t.Fatal(err)
	}
	if back.P.Rdap.E != myipErrTooBig || back.P.Rdap.S != 200 || back.P.Rdap.B != nil {
		t.Errorf("rdap: %+v", back.P.Rdap)
	}
	if back.P.Rep.B == nil || back.P.IP.B == nil {
		t.Errorf("dropped more than it had to: rep %+v ip %+v", back.P.Rep.E, back.P.IP.E)
	}

	// Every body large: given up in order — rdap, rep, trace, ip6 — until
	// the rest fits; ip4 and ip are kept.
	o = myipOut{V: 1, Origin: myipDefaultURL}
	for _, p := range []*myipProbe{&o.P.IP, &o.P.IP4, &o.P.IP6, &o.P.Rep, &o.P.Rdap} {
		*p = myipOK(myipBig(7000))
	}
	tr, _ := json.Marshal(strings.Repeat("t", 7000))
	o.P.Trace = myipOK(tr)
	s = myipEncode(&o)
	back = myipOut{}
	if !myipFits([]byte(s)) || json.Unmarshal([]byte(s), &back) != nil {
		t.Fatalf("encoded does not fit or is not JSON: %d bytes", len(s))
	}
	for name, p := range map[string]myipProbe{"rdap": back.P.Rdap, "rep": back.P.Rep, "trace": back.P.Trace, "ip6": back.P.IP6} {
		if p.E != myipErrTooBig {
			t.Errorf("%s kept: %+v", name, p.E)
		}
	}
	if back.P.IP4.B == nil || back.P.IP.B == nil {
		t.Errorf("ip4/ip dropped: %q %q", back.P.IP4.E, back.P.IP.E)
	}

	// Ordinary answers are untouched.
	o = myipOut{V: 1, Origin: myipDefaultURL}
	o.P.IP = myipOK(json.RawMessage(`{"ip":"203.0.113.5"}`))
	if s = myipEncode(&o); !strings.Contains(s, `"ip":{"s":200,"ms":1,"b":{"ip":"203.0.113.5"}}`) {
		t.Errorf("small document changed: %s", s)
	}
}

// One family's pretend site: the four paths, answering for addr.
func myipSite(t *testing.T, addr string, conns *atomic.Int32, rdapStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	ua := func(r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "subnsub-helper/") {
			t.Errorf("%s asked without the helper's User-Agent: %q", r.URL.Path, r.Header.Get("User-Agent"))
		}
	}
	fam := 4
	if strings.Contains(addr, ":") {
		fam = 6
	}
	mux.HandleFunc("/api/ip", func(w http.ResponseWriter, r *http.Request) {
		ua(r)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"` + addr + `","version":` + map[int]string{4: "4", 6: "6"}[fam] + `,"country":"JP","asn":64500,"asOrganization":"Example <Net>"}`))
	})
	mux.HandleFunc("/api/iprep", func(w http.ResponseWriter, r *http.Request) {
		ua(r)
		w.Write([]byte(`{"ip":"` + addr + `","signals":{"tor":{"hit":false,"n":1}}}`))
	})
	mux.HandleFunc("/api/rdap", func(w http.ResponseWriter, r *http.Request) {
		ua(r)
		if rdapStatus != http.StatusOK {
			w.WriteHeader(rdapStatus)
			return
		}
		w.Write([]byte(`{"ip":"` + addr + `","record":{"cidr":"203.0.113.0/24","registry":"ARIN"}}`))
	})
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		ua(r)
		w.Write([]byte("fl=1\nip=" + addr + "\nkex=X25519MLKEM768\n"))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew && conns != nil {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// myipHarness points the command at two pretend sites, one per family: a
// forced-IPv6 dial lands on six, everything else on four. The origin is
// four's, so the certificate (httptest's, for 127.0.0.1) matches on both.
func myipHarness(t *testing.T, four, six *httptest.Server, sixDown bool) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(consoleEnvVar, "1")
	t.Setenv(myipEnvVar, four.URL)
	pool := x509.NewCertPool()
	pool.AddCert(four.Certificate())
	myipTLS = &tls.Config{RootCAs: pool}
	myipDialHook = func(ctx context.Context, network, _ string) (net.Conn, error) {
		target := four.Listener.Addr().String()
		if network == "tcp6" {
			if sixDown {
				return nil, errors.New("network is unreachable")
			}
			target = six.Listener.Addr().String()
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}
	t.Cleanup(func() { myipTLS, myipDialHook = nil, nil })
}

func TestMyIPRun(t *testing.T) {
	var conns atomic.Int32
	four := myipSite(t, "203.0.113.7", &conns, http.StatusOK)
	six := myipSite(t, "2001:db8::7", nil, http.StatusOK)
	myipHarness(t, four, six, false)

	res := runMyIP(consoleCmd{ID: "m1", Kind: "myip"})
	if res.Code != 0 || res.Error != "" || res.Kind != "myip" || res.Truncated {
		t.Fatalf("result: %+v", res)
	}
	t.Logf("Out: %s", res.Out)
	var o struct {
		V      int    `json:"v"`
		Origin string `json:"origin"`
		NS     string `json:"ns"`
		At     int64  `json:"at"`
		P      map[string]struct {
			S  int             `json:"s"`
			Ms *int64          `json:"ms"`
			B  json.RawMessage `json:"b"`
			E  string          `json:"e"`
		} `json:"p"`
	}
	if err := json.Unmarshal([]byte(res.Out), &o); err != nil {
		t.Fatal(err)
	}
	if o.V != 1 || o.Origin != four.URL || o.NS != "" || o.At == 0 || len(o.P) != 6 {
		t.Fatalf("document: %+v", o)
	}
	addr := func(name string) string {
		var a struct {
			IP string `json:"ip"`
		}
		json.Unmarshal(o.P[name].B, &a)
		return a.IP
	}
	for name, want := range map[string]string{"ip": "203.0.113.7", "ip4": "203.0.113.7", "ip6": "2001:db8::7", "rep": "203.0.113.7", "rdap": "203.0.113.7"} {
		p := o.P[name]
		if p.S != 200 || p.Ms == nil || p.E != "" || addr(name) != want {
			t.Errorf("%s: %+v (address %q, want %q)", name, p, addr(name), want)
		}
	}
	var trace string
	if json.Unmarshal(o.P["trace"].B, &trace) != nil || !strings.Contains(trace, "kex=X25519MLKEM768") {
		t.Errorf("trace: %s", o.P["trace"].B)
	}
	// One connection for the four that describe one address (HTTP/2 carries
	// rep, rdap and trace on the one `ip` opened), one for forced IPv4.
	if n := conns.Load(); n != 2 {
		t.Errorf("connections to the IPv4 site: %d, want 2 (default + forced IPv4)", n)
	}
}

func TestMyIPRunFailures(t *testing.T) {
	four := myipSite(t, "203.0.113.7", nil, http.StatusServiceUnavailable)
	// Answers IPv6 requests with an IPv4 address: a forced family that did
	// not hold (a proxy that re-resolved, say).
	wrong := myipSite(t, "198.51.100.9", nil, http.StatusOK)
	myipHarness(t, four, wrong, false)
	res := runMyIP(consoleCmd{ID: "m2", Kind: "myip"})
	if res.Code != 0 {
		t.Fatalf("result: %+v", res)
	}
	var o struct {
		P map[string]map[string]any `json:"p"`
	}
	if err := json.Unmarshal([]byte(res.Out), &o); err != nil {
		t.Fatal(err)
	}
	if o.P["rdap"]["e"] != myipErrRefused || o.P["rdap"]["s"] != float64(503) {
		t.Errorf("rdap: %v", o.P["rdap"])
	}
	if o.P["ip6"]["e"] != myipErrFamily {
		t.Errorf("ip6 answered by the other family: %v", o.P["ip6"])
	}
	if _, ok := o.P["ip"]["b"]; !ok {
		t.Errorf("ip lost with the others: %v", o.P["ip"])
	}

	// No IPv6 at all: said, and the rest still answered.
	myipHarness(t, four, wrong, true)
	res = runMyIP(consoleCmd{ID: "m3", Kind: "myip"})
	o.P = nil
	if res.Code != 0 || json.Unmarshal([]byte(res.Out), &o) != nil {
		t.Fatalf("result: %+v", res)
	}
	if o.P["ip6"]["e"] != myipErrUnreachable {
		t.Errorf("ip6 with no route: %v", o.P["ip6"])
	}
	if _, ok := o.P["ip4"]["b"]; !ok {
		t.Errorf("ip4 lost with ip6: %v", o.P["ip4"])
	}
}

func TestMyIPRefusals(t *testing.T) {
	four := myipSite(t, "203.0.113.7", nil, http.StatusOK)
	myipHarness(t, four, four, true)
	if r := runMyIP(consoleCmd{ID: "r1", Kind: "myip", Cmd: "ls"}); r.Error != "bad-request" || r.Code != -1 || r.Out != "" {
		t.Errorf("a line with it: %+v", r)
	}
	if r := runMyIP(consoleCmd{ID: "r2", Kind: "myip", Target: "../x"}); r.Error != "bad-target" {
		t.Errorf("bad namespace: %+v", r)
	}
	if r := runMyIP(consoleCmd{ID: "r3", Kind: "myip", Target: "nonexistent-ns-0"}); r.Error != "bad-target" {
		t.Errorf("absent namespace: %+v", r)
	}
	// Through runCommand, as either road delivers it.
	if r, swap := runCommand(consoleCmd{ID: "r4", Kind: "myip"}); r.Code != 0 || swap || r.Kind != "myip" {
		t.Errorf("runCommand: %+v", r)
	}
	t.Setenv(myipEnvVar, "off")
	if r := runMyIP(consoleCmd{ID: "r5", Kind: "myip"}); r.Error != "myip-off" {
		t.Errorf("switched off: %+v", r)
	}
	if myipAvailable() {
		t.Error("available while off")
	}
}

// The tunnel names the check where a key is pinned and the check is on; the
// reading says the same.
func TestMyIPCaps(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(consoleEnvVar, "1")
	t.Setenv(myipEnvVar, "")
	has := func() bool {
		return strings.Contains(","+strings.Join(directCaps(), ",")+",", ","+transport.CapMyIP+",")
	}
	if has() {
		t.Fatal("myip named with nothing pinned")
	}
	if err := os.MkdirAll(filepath.Dir(trustedKeysPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustedKeysPath(), []byte("not-a-key-but-pins-the-machine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Fatalf("caps without myip: %v", directCaps())
	}
	if !myipAvailable() {
		t.Fatal("not available with the console on")
	}
	t.Setenv(myipEnvVar, "off")
	if has() {
		t.Fatal("myip named while MON_MYIP=off")
	}
}

// An answer about another address than /api/ip's is given up, not mixed
// into the report (a second connection over HTTP/1.1, another route).
func TestMyIPSameAddress(t *testing.T) {
	js := func(s string) json.RawMessage { return json.RawMessage(s) }
	tr := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	p := myipProbes{
		IP:    myipProbe{S: 200, B: js(`{"ip":"2001:db8::7","version":6}`)},
		Rep:   myipProbe{S: 200, B: js(`{"ip":"2001:0db8:0:0::7","signals":{}}`)},
		Rdap:  myipProbe{S: 200, B: js(`{"ip":"203.0.113.9","record":{}}`)},
		Trace: myipProbe{S: 200, B: tr("fl=1\nip=203.0.113.9\nkex=X25519\n")},
	}
	myipSameAddress(&p)
	if p.Rep.B == nil || p.Rep.E != "" {
		t.Fatalf("the same address written another way was dropped: %+v", p.Rep)
	}
	if p.Rdap.B != nil || p.Rdap.E != myipErrOther || p.Rdap.S != 200 {
		t.Fatalf("rdap about another address kept: %+v", p.Rdap)
	}
	if p.Trace.B != nil || p.Trace.E != myipErrOther {
		t.Fatalf("trace about another address kept: %+v", p.Trace)
	}
	q := myipProbes{IP: myipProbe{E: myipErrTimeout}, Rep: myipProbe{S: 200, B: js(`{"ip":"203.0.113.9"}`)}}
	myipSameAddress(&q)
	if q.Rep.B == nil {
		t.Fatal("with no address of its own to compare, nothing is dropped")
	}
}
