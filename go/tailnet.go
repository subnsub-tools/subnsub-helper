package main

// The tailnet road: a machine that is on a Tailscale network also answers there.
//
// A browser cannot go direct over tailcat, because a page has no UDP socket and
// the tunnel's WebAssembly build rides DERP alone. A browser on a computer that
// runs Tailscale does not need one: it asks for this machine's address like any
// other, and the operating system's Tailscale carries the bytes over UDP when it
// can. So a machine on a tailnet listens on its tailnet address, and the page
// goes there first and comes back to the tunnel when that does not answer.
//
// WHAT THE NETWORK IS NOT TRUSTED FOR. The tunnel admits a key at WireGuard, and
// a key not on the list cannot even finish a handshake. This port has none of
// that: anything on the tailnet can reach it, and whoever runs a tailnet's
// control plane decides who holds an address on it. So nothing here rests on
// the network. A reader opens a session with the machine's X25519 key, which it
// learned through the tunnel (hello), and with its own key, which must be on the
// machine's list, or be the key of another computer's helper fetching files
// from here under a read-only grant (filesgrant.go, filesfetch.go), which gets
// the grant's few paths and nothing else. Every request and every response
// inside is sealed to that session. What a peer on the tailnet sees of this
// port is that it exists.
//
//	derive: HKDF-SHA256 over DH(reader, machine) || DH(reader's ephemeral,
//	        machine's ephemeral), so a key taken later opens no recorded session
//	POST /tn/open  {v, c: reader key, e: its ephemeral, n: nonce}
//	               → {v, s: session, e, n, a: agent id, m: proof of the key}
//	POST /tn/rpc?s=<session>  nonce || AES-256-GCM({q: seq, m, p, b})
//	               → records: u32 length || AES-256-GCM(kind || bytes)
//
// Requests are plain text/plain POSTs, which a page may send without a preflight.
// Any origin may read the answers, since none of them mean anything without a
// key: a panel of one's own works here as it does on the tunnel.
//
// Off with MON_TAILNET=off.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"subnsubmonitor/transport"
	"tailscale.com/types/key"
)

const (
	tailnetPort    = 8126
	tailnetPoll    = time.Minute
	tailnetSalt    = "subnsub-monitor tailnet v1"
	tailnetConfirm = "tailnet open confirm\n"
	tailnetDNS     = "100.100.100.100:53"
	tailnetMaxOpen = 1 << 10
	tailnetMaxSID  = 1 << 10
	// A sealed request: a command, or a piece of a file coming in (1 MiB at
	// most on this road, base64 inside the sealed JSON; fileswrite.go). A
	// session that has not proven its key yet (a token from /tn/open, which
	// any caller naming an allowed key is given) is read no further than a
	// command needs: the page's first request on one is a hello.
	tailnetMaxRPC   = 1536 << 10
	tailnetMaxFirst = 256 << 10
	// How long a session already proven has to send one: a piece over a
	// slow road outlasts the server's ten seconds.
	tailnetRPCRead  = time.Minute
	tailnetRecord   = 32 << 10
	tailnetSessions = 64
	// A session nobody has used, and how long an answer to /tn/open stays good
	// for the first request that proves the key.
	tailnetIdle     = 30 * time.Minute
	tailnetUnproven = 30 * time.Second
	tailnetWindow   = 1024

	tnKindHead = 1
	tnKindData = 2
	tnKindEnd  = 3
)

var (
	tailnetCGNAT   = netip.MustParsePrefix("100.64.0.0/10")
	tailnetIfaceRe = regexp.MustCompile(`(?i)^(tailscale|utun)`)
	tailnetHostRe  = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)
	tailnetRoad    atomic.Pointer[transport.TailnetRoad]
	tailnetServe   = &tailnetServer{sessions: map[string]*tnSession{}}
)

type tailnetCtxKey struct{}

// tailnetRequest says whether this request came in on the tailnet road.
func tailnetRequest(r *http.Request) bool {
	v, _ := r.Context().Value(tailnetCtxKey{}).(bool)
	return v
}

// tailnetRoadNow is what the hello says of this road, or nil.
func tailnetRoadNow() *transport.TailnetRoad { return tailnetRoad.Load() }

func tailnetOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MON_TAILNET"))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// tailnetAdmitted is the tunnel's list, read afresh, so a key struck from the
// file is struck here on its next request.
func tailnetAdmitted(k key.NodePublic) bool {
	for _, a := range loadAllowedClients() {
		if a == k {
			return true
		}
	}
	_, ok := cloneForNode(k, agentID(), time.Now())
	return ok
}

// tailnetLetIn is who this port opens a session for: the list, and a key
// holding a read-only grant here, which the door then keeps to the grant's
// paths (directHandler.ServeHTTP).
func tailnetLetIn(k key.NodePublic) bool { return tailnetAdmitted(k) || grantHeld(k) }

// ── finding the network ─────────────────────────────────────────────────

// tailnetDiscover finds this machine's Tailscale address from its interfaces, and
// its name from Tailscale's own resolver, which needs neither the CLI nor its
// socket, whatever they are called and wherever they were put here. A carrier's
// NAT uses the same address range, so an address on an interface not named like
// Tailscale's counts only if Tailscale's resolver knows it.
func tailnetDiscover(ctx context.Context) (ip, host string, ok bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is4() || !tailnetCGNAT.Contains(addr) {
				continue
			}
			name := tailnetNameOf(ctx, addr.String())
			if name == "" && !tailnetIfaceRe.MatchString(ifc.Name) {
				continue
			}
			return addr.String(), name, true
		}
	}
	return "", "", false
}

func tailnetNameOf(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", tailnetDNS)
	}}
	names, err := res.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.ToLower(strings.TrimSuffix(names[0], "."))
	if !tailnetHostRe.MatchString(name) {
		return ""
	}
	return name
}

// runTailnet keeps the listener on the machine's current tailnet address for as
// long as ctx lives: up when Tailscale comes up, moved when the address moves,
// gone when it goes, each within a poll.
func runTailnet(ctx context.Context) {
	if tailnetOff() {
		return
	}
	// Its own handler, not the tunnel's, which is made anew at every attempt to
	// bring a carrier up: what it counts must outlive those, and the terminal's
	// table and the machine's list are the process's either way.
	tailnetServe.handler.Store(newDirectHandler())
	var (
		srv     *http.Server
		boundIP string
		port    = tailnetPort
	)
	stop := func() {
		tailnetRoad.Store(nil)
		if srv != nil {
			srv.Close()
			srv = nil
		}
		boundIP = ""
	}
	defer stop()
	for {
		ip, host, ok := tailnetDiscover(ctx)
		// Nobody on the list means nobody it could answer: the same rule that
		// keeps the tunnel from starting.
		if !ok || len(loadAllowedClients()) == 0 {
			if boundIP != "" {
				warnf("tailnet: off this network")
			}
			stop()
		} else {
			if ip != boundIP {
				stop()
				ln, err := net.Listen("tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
				if err != nil {
					// Somebody else's port: any other will do, since the hello
					// says which, and it is kept for as long as this runs.
					ln, err = net.Listen("tcp4", net.JoinHostPort(ip, "0"))
				}
				if err != nil {
					warnf("tailnet: could not listen on %s: %v", ip, err)
				} else {
					port = ln.Addr().(*net.TCPAddr).Port
					srv = &http.Server{
						Handler:           tailnetServe,
						ReadHeaderTimeout: 5 * time.Second,
						ReadTimeout:       10 * time.Second,
						IdleTimeout:       2 * time.Minute,
						MaxHeaderBytes:    8 << 10,
					}
					go srv.Serve(ln)
					boundIP = ip
					warnf("tailnet: answering on %s:%d", ip, port)
				}
			}
			if boundIP != "" {
				if road := tailnetRoadFor(host, boundIP, port); road != nil {
					tailnetRoad.Store(road)
				}
			}
		}
		if !sleepCtx(ctx, tailnetPoll) {
			return
		}
	}
}

func tailnetRoadFor(host, ip string, port int) *transport.TailnetRoad {
	k, err := econPrivate()
	if err != nil {
		return nil
	}
	return &transport.TailnetRoad{Host: host, IP: ip, Port: port,
		Key: econKeyPrefix + hex.EncodeToString(k.PublicKey().Bytes())}
}

// ── sessions ────────────────────────────────────────────────────────────

type tnSession struct {
	id     string
	peer   key.NodePublic
	inKey  cipher.AEAD
	outKey []byte
	used   time.Time
	active int
	// Which request numbers this session has seen: the highest, and a window
	// under it, since two requests may arrive in either order.
	top  uint64
	seen [tailnetWindow / 64]uint64
}

// fresh marks q seen, and says whether it had not been.
func (s *tnSession) fresh(q uint64) bool {
	if q == 0 {
		return false
	}
	if q > s.top {
		if d := q - s.top; d >= tailnetWindow {
			s.seen = [tailnetWindow / 64]uint64{}
		} else {
			// By the distance, not up to q: q may be the largest number there is.
			for n := uint64(1); n <= d; n++ {
				i := s.top + n
				s.seen[i%tailnetWindow/64] &^= 1 << (i % 64)
			}
		}
		s.top = q
	} else if s.top-q >= tailnetWindow {
		return false
	}
	w, b := q%tailnetWindow/64, uint64(1)<<(q%64)
	if s.seen[w]&b != 0 {
		return false
	}
	s.seen[w] |= b
	return true
}

type tailnetServer struct {
	handler  atomic.Pointer[directHandler]
	mu       sync.Mutex
	sessions map[string]*tnSession

	tokenOnce sync.Once
	tokenKey  cipher.AEAD
}

// tailnetToken is what a session is until its first request. A key's public half
// is not a secret, so opening proves nothing, and nothing an open asks for may
// cost a real session its seat: until the holder uses it, the session lives only
// in this sealed token, handed back as its id. Sealed under a key this process
// made for the purpose, so a restart ends them all, as it ends the table.
type tailnetToken struct {
	Peer string `json:"p"`
	In   []byte `json:"i"`
	Out  []byte `json:"o"`
	Born int64  `json:"b"`
}

func (t *tailnetServer) tokens() cipher.AEAD {
	t.tokenOnce.Do(func() {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		aead, err := tailnetAEAD(k)
		if err != nil {
			panic(err)
		}
		t.tokenKey = aead
	})
	return t.tokenKey
}

func (t *tailnetServer) mintToken(tok tailnetToken) (string, error) {
	b, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t.tokens().Seal(nonce, nonce, b, []byte("tn-sid"))), nil
}

// fromToken is the session a token describes, still within its time, or nil.
func (t *tailnetServer) fromToken(sid string, now time.Time) *tnSession {
	if len(sid) > tailnetMaxSID {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(sid)
	if err != nil || len(raw) < 12 {
		return nil
	}
	plain, err := t.tokens().Open(nil, raw[:12], raw[12:], []byte("tn-sid"))
	if err != nil {
		return nil
	}
	var tok tailnetToken
	if json.Unmarshal(plain, &tok) != nil || now.Sub(time.Unix(tok.Born, 0)) > tailnetUnproven {
		return nil
	}
	var node key.NodePublic
	if node.UnmarshalText([]byte(tok.Peer)) != nil {
		return nil
	}
	aead, err := tailnetAEAD(tok.In)
	if err != nil {
		return nil
	}
	return &tnSession{id: sid, peer: node, inKey: aead, outKey: tok.Out, used: now}
}

// seat puts a proven session in the table, letting go of whichever idle one is
// oldest if there is no room. Every session in use and no room: refused. Called
// with t.mu held.
func (t *tailnetServer) seat(s *tnSession, now time.Time) bool {
	var oldest *tnSession
	for id, o := range t.sessions {
		if o.active > 0 {
			continue
		}
		if now.Sub(o.used) > tailnetIdle {
			delete(t.sessions, id)
			continue
		}
		if oldest == nil || o.used.Before(oldest.used) {
			oldest = o
		}
	}
	if len(t.sessions) >= tailnetSessions {
		if oldest == nil {
			return false
		}
		delete(t.sessions, oldest.id)
	}
	t.sessions[s.id] = s
	return true
}

func tailnetKeys(ss, ee []byte, info string) (in, out []byte, err error) {
	ikm := append(append([]byte(nil), ss...), ee...)
	b, err := hkdf.Key(sha256.New, ikm, []byte(tailnetSalt), info, 64)
	if err != nil {
		return nil, nil, err
	}
	return b[:32], b[32:], nil
}

func tailnetAEAD(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randHex(n int) (string, []byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(b), b, nil
}

// ── the port ────────────────────────────────────────────────────────────

func (t *tailnetServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" {
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Local-Network", "true")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.URL.Path {
	case "/tn/open":
		t.open(w, r)
	case "/tn/rpc":
		t.rpc(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (t *tailnetServer) open(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, tailnetMaxOpen+1))
	if err != nil || len(b) > tailnetMaxOpen {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var q struct {
		V int    `json:"v"`
		C string `json:"c"`
		E string `json:"e"`
		N string `json:"n"`
	}
	if json.Unmarshal(b, &q) != nil || q.V != 1 || len(q.N) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(q.N); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	peer, ok := econParsePublic(q.C)
	var node key.NodePublic
	if !ok || node.UnmarshalText([]byte(q.C)) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The list first: a key not on it costs this machine nothing, and is told
	// nothing but no.
	if !tailnetLetIn(node) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	eRaw, err := hex.DecodeString(q.E)
	if err != nil || len(eRaw) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	peerE, err := ecdh.X25519().NewPublicKey(eRaw)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	mine, err := econPrivate()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// ECDH refuses a peer on the small subgroup, which would make either secret
	// a constant.
	ss, err1 := mine.ECDH(peer)
	ee, err2 := eph.ECDH(peerE)
	if err1 != nil || err2 != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sn, _, err := randHex(16)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	agent := agentID()
	eHex := hex.EncodeToString(eph.PublicKey().Bytes())
	info := strings.Join([]string{agent, econKeyPrefix + hex.EncodeToString(mine.PublicKey().Bytes()), q.C,
		strings.ToLower(q.E), eHex, strings.ToLower(q.N), sn}, "\n")
	in, out, err := tailnetKeys(ss, ee, info)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	sid, err := t.mintToken(tailnetToken{Peer: q.C, In: in, Out: out, Born: time.Now().Unix()})
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	m := hmac.New(sha256.New, out)
	m.Write([]byte(tailnetConfirm + sid))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"v": 1, "s": sid, "e": eHex, "n": sn, "a": agent,
		"m": hex.EncodeToString(m.Sum(nil))})
}

// tailnetInnerOK is the part of the tunnel's surface this road serves.
func tailnetInnerOK(p string) bool {
	switch p {
	case "/v1/hello", "/v1/snapshot", "/v1/events", "/v1/command", "/v1/history",
		"/v1/pty/out", "/v1/pty/in", "/v1/pty/resize", "/v1/pty/close",
		"/v1/music", "/v1/music/index", "/v1/music/file", "/v1/music/art",
		"/v1/files/search", "/v1/files/file", "/v1/files/put",
		"/v1/files/grant/open", "/v1/files/grant/walk", "/v1/files/grant/done",
		"/v1/tailnet":
		return true
	}
	// The Speed tab's end of a measurement (speed.go).
	return speedPath(p)
}

func (t *tailnetServer) rpc(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("s")
	now := time.Now()
	t.mu.Lock()
	s := t.sessions[sid]
	t.mu.Unlock()
	limit := tailnetMaxFirst
	if s != nil {
		// A session that has proven its key may take its time over a big
		// request (a piece of a file); one that has not, the server's ten
		// seconds and a command's size.
		http.NewResponseController(w).SetReadDeadline(now.Add(tailnetRPCRead))
		limit = tailnetMaxRPC
	} else {
		s = t.fromToken(sid, now)
	}
	// 410 asks the reader to open another: a helper that restarted knows no
	// session, and that is the ordinary way to learn it.
	if s == nil {
		w.WriteHeader(http.StatusGone)
		return
	}
	sealed, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(sealed) > limit || len(sealed) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	plain, err := s.inKey.Open(nil, sealed[:12], sealed[12:], []byte("c\n"+sid))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var q struct {
		Q uint64 `json:"q"`
		M string `json:"m"`
		P string `json:"p"`
		B string `json:"b"`
	}
	if json.Unmarshal(plain, &q) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The key is proven by now. A session that was only its token takes a seat,
	// unless a request ahead of this one just took it.
	t.mu.Lock()
	if cur := t.sessions[sid]; cur != nil {
		s = cur
	} else if !t.seat(s, now) {
		t.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !s.fresh(q.Q) {
		t.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.active++
	s.used = time.Now()
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		s.active--
		s.used = time.Now()
		t.mu.Unlock()
	}()
	// The whole request is in: from here a long answer must not trip the
	// server's read deadline.
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/octet-stream")

	rw, err := newTnWriter(w, rc, s, sid, q.Q)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer rw.finish()
	h := t.handler.Load()
	inner, ierr := url.ParseRequestURI(q.P)
	body, berr := base64.StdEncoding.DecodeString(q.B)
	switch {
	case h == nil:
		refuseAs(rw, agentID(), http.StatusServiceUnavailable, "unavailable")
	case ierr != nil || berr != nil || !tailnetInnerOK(inner.Path):
		refuseAs(rw, agentID(), http.StatusNotFound, "unknown-frame")
	case !tailnetLetIn(s.peer):
		// Struck since the session opened: told as the tunnel's gate tells it,
		// and the session goes with it.
		t.mu.Lock()
		delete(t.sessions, sid)
		t.mu.Unlock()
		refuseAs(rw, agentID(), http.StatusForbidden, "not-allowed")
	default:
		ctx := context.WithValue(transport.WithPeer(r.Context(), s.peer), tailnetCtxKey{}, true)
		req := r.Clone(ctx)
		req.Method = q.M
		req.URL = inner
		req.RequestURI = q.P
		req.Header = http.Header{}
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.ContentLength = int64(len(body))
		h.ServeHTTP(rw, req)
	}
}

// tnWriter is what a handler of the tunnel writes to on this road: its status
// and bytes go out as sealed records. The response controller's calls land here,
// the deadlines passed on to the real connection.
type tnWriter struct {
	w      http.ResponseWriter
	rc     *http.ResponseController
	aead   cipher.AEAD
	aad    []byte
	header http.Header
	buf    []byte
	sent   bool
	n      uint64
	failed error
}

func newTnWriter(w http.ResponseWriter, rc *http.ResponseController, s *tnSession, sid string, q uint64) (*tnWriter, error) {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], q)
	m := hmac.New(sha256.New, s.outKey)
	m.Write([]byte("r"))
	m.Write(seq[:])
	aead, err := tailnetAEAD(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	return &tnWriter{w: w, rc: rc, aead: aead, aad: []byte("s\n" + sid), header: http.Header{}}, nil
}

func (t *tnWriter) Header() http.Header { return t.header }

func (t *tnWriter) record(kind byte, b []byte) error {
	if t.failed != nil {
		return t.failed
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], t.n)
	t.n++
	ct := t.aead.Seal(nil, nonce[:], append([]byte{kind}, b...), t.aad)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := t.w.Write(l[:]); err != nil {
		t.failed = err
		return err
	}
	if _, err := t.w.Write(ct); err != nil {
		t.failed = err
		return err
	}
	return nil
}

func (t *tnWriter) WriteHeader(status int) {
	if t.sent {
		return
	}
	t.sent = true
	m := map[string]any{"s": status, "t": t.header.Get("Content-Type")}
	// The length, when the handler gave one (the music reads do): the page
	// counts the data records against it, so an answer cut short is not taken
	// for the whole of one.
	if l, err := strconv.ParseInt(t.header.Get("Content-Length"), 10, 64); err == nil && l >= 0 {
		m["l"] = l
	}
	head, _ := json.Marshal(m)
	t.record(tnKindHead, head)
}

func (t *tnWriter) Write(b []byte) (int, error) {
	if !t.sent {
		t.WriteHeader(http.StatusOK)
	}
	if t.failed != nil {
		return 0, t.failed
	}
	t.buf = append(t.buf, b...)
	for len(t.buf) >= tailnetRecord {
		if err := t.record(tnKindData, t.buf[:tailnetRecord]); err != nil {
			return 0, err
		}
		t.buf = t.buf[tailnetRecord:]
	}
	return len(b), nil
}

// FlushError is what http.ResponseController.Flush looks for.
func (t *tnWriter) FlushError() error {
	if !t.sent {
		t.WriteHeader(http.StatusOK)
	}
	if len(t.buf) > 0 {
		if err := t.record(tnKindData, t.buf); err != nil {
			return err
		}
		t.buf = t.buf[:0]
	}
	if t.failed != nil {
		return t.failed
	}
	return t.rc.Flush()
}

func (t *tnWriter) SetReadDeadline(d time.Time) error  { return t.rc.SetReadDeadline(d) }
func (t *tnWriter) SetWriteDeadline(d time.Time) error { return t.rc.SetWriteDeadline(d) }

// The request's body came whole inside the sealed request, so there is nothing
// to read and write at once.
func (t *tnWriter) EnableFullDuplex() error { return nil }

// finish ends the answer. A reader takes an answer with no end record as cut off.
func (t *tnWriter) finish() {
	if !t.sent {
		t.WriteHeader(http.StatusOK)
	}
	if len(t.buf) > 0 {
		t.record(tnKindData, t.buf)
		t.buf = nil
	}
	if err := t.record(tnKindEnd, nil); err != nil && !errors.Is(err, net.ErrClosed) {
		return
	}
	t.rc.Flush()
}
