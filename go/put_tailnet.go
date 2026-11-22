package main

// put over the tailnet: when two of the owner's Macs are on the same Tailscale
// network, out's streams between them go through it first — the operating
// system's Tailscale carries them, directly where it can — and through tailcat
// when that does not answer (user 2026-11-22: the tailnet first, tailcat when it
// does not get through).
//
// THE DOOR. The tailnet road (tailnet.go) takes POST /tn/put with Upgrade:
// put-tn and Put-From naming the caller's agent id. Nothing there rests on the
// network: the connection becomes a Noise IK session (controlbase, as
// Tailscale's own control protocol has it) in which each side proves the key
// the tunnel knows it by. The caller's static key is the one it dials this Mac
// from (its put-peers entry here); this Mac's is the one it dials the caller
// from (putKeyFor), which the caller's own list holds for it. A caller whose
// key is not its entry's is let go before anything reaches out. Inside the
// session the stream is put's as on the tunnel: GET /v1/put/stream with
// Upgrade: put, answered as putServe answers it (putServeConn).
//
// WHERE THE OTHER MAC LISTENS. put-peers holds tunnel addresses only. Each
// helper names its tailnet road in the put upgrade, both ways (Put-Tailnet:
// ip:port), and the other keeps it in memory for that peer. The tunnel is
// authenticated, and an address that is not the peer's gets nowhere anyway:
// the session there would not prove the peer's key. So the first stream
// after a helper starts goes by tailcat, and the next ones try the tailnet.
//
// A MAC BEHIND A ROUTER ON THE TAILNET. A Mac with no Tailscale of its own can
// still be where a tailnet address is reached: its router is on the tailnet
// and carries the LAN there (user 2026-11-22: why tailcat and not the tailnet —
// this Mac goes to m2 through the router, and the router goes there directly).
// Such a Mac has no door of its own, so the others never call it by the
// tailnet, but it calls theirs: the door asks nothing of where a caller comes
// from, only its key. So that a Mac with no such router does not lose
// putTnWait on every stream, the peer's door is tried apart from any stream
// (putTnProbe: a TCP connection to it, when the address is learned and every
// putTnReachEvery after), and streams go there only while it last answered.
//
// FALLING BACK. The tailnet gets putTnWait to have the stream's answer begun;
// then the stream goes by tailcat in the time left, as it always did. A peer
// whose tailnet did not answer is not tried there again for putTnRest.

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"

	"subnsubmonitor/transport"
)

const (
	putTnPath    = "/tn/put"
	putTnUpgrade = "put-tn"
	// The header each side names its tailnet road in, and the one the caller
	// names itself in at the door.
	putTnHeader     = "Put-Tailnet"
	putTnFromHeader = "Put-From"
	// The Noise session's protocol version: this one.
	putTnVersion = 1
	// How long the tailnet has to have the stream's answer begun, and how long
	// a peer whose tailnet did not answer is left to tailcat.
	putTnRest = time.Minute
	// Handshakes at the door at once; more are refused.
	putTnHandshakes = 8
	// The door's handshake and the stream's request, at most this long.
	putTnHandshakeWait = 5 * time.Second
	// From a Mac that is not on a tailnet itself: how long a peer's door has
	// to take a connection, and how long what it did is believed.
	putTnProbeWait  = 3 * time.Second
	putTnReachEvery = 5 * time.Minute
)

// putTnWait is the tailnet's time to answer before tailcat is tried; a test
// shortens it.
var putTnWait = 2 * time.Second

var putTn struct {
	sync.Mutex
	addr map[string]string    // agent id → its tailnet road, as it said it
	rest map[string]time.Time // agent id → not tried on the tailnet before this
	// agent id → whether its door took a connection from this Mac, which is
	// not on a tailnet itself, and when that was last tried.
	reach map[string]putTnReach
}

var putTnBusy atomic.Int32

// putTnSelf is this Mac's tailnet road as the other helper is told it, or ""
// where it has none.
func putTnSelf() string {
	if tailnetOff() {
		return ""
	}
	r := tailnetRoadNow()
	if r == nil || r.IP == "" || r.Port <= 0 {
		return ""
	}
	return net.JoinHostPort(r.IP, strconv.Itoa(r.Port))
}

// putTnValid is v, an address on a tailnet (Tailscale's 100.64.0.0/10, the
// road's IPv4) and a port, or "" when it is not one.
func putTnValid(v string) string {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(v))
	if err != nil || ap.Port() == 0 || !ap.Addr().Is4() {
		return ""
	}
	if !netip.MustParsePrefix("100.64.0.0/10").Contains(ap.Addr()) {
		return ""
	}
	return ap.String()
}

type putTnReach struct {
	addr   string
	ok     bool
	at     time.Time
	trying bool
}

// putTnLearn keeps what a peer said of its tailnet road; a word that is not
// an address keeps what was known.
func putTnLearn(agent, v string) {
	a := putTnValid(v)
	if agent == "" || a == "" {
		return
	}
	putTn.Lock()
	if putTn.addr == nil {
		putTn.addr = map[string]string{}
	}
	if putTn.addr[agent] != a {
		// A new address is tried at once.
		delete(putTn.rest, agent)
	}
	putTn.addr[agent] = a
	putTn.Unlock()
	if putTnSelf() == "" {
		// Whether this Mac gets there at all is found out before a stream asks.
		putTnReachable(agent)
	}
}

// putTnFor is where the peer listens on the tailnet, when this Mac knows
// where, the peer has not just failed there, and this Mac is on a tailnet or
// was last seen to get to that door without being on one.
func putTnFor(agent string) string {
	if tailnetOff() {
		return ""
	}
	if putTnSelf() == "" && !putTnReachable(agent) {
		return ""
	}
	putTn.Lock()
	defer putTn.Unlock()
	if time.Now().Before(putTn.rest[agent]) {
		return ""
	}
	return putTn.addr[agent]
}

// putTnReachable says whether the peer's door last took a connection from
// this Mac, and has it tried again, apart from the caller, when that is not
// known of the address the peer now has or was found out putTnReachEvery ago.
func putTnReachable(agent string) bool {
	putTn.Lock()
	defer putTn.Unlock()
	addr := putTn.addr[agent]
	if addr == "" {
		return false
	}
	r := putTn.reach[agent]
	if r.addr != addr {
		r = putTnReach{addr: addr}
	}
	if !r.trying && time.Since(r.at) >= putTnReachEvery {
		r.trying = true
		go putTnProbe(agent, addr)
	}
	if putTn.reach == nil {
		putTn.reach = map[string]putTnReach{}
	}
	putTn.reach[agent] = r
	return r.ok
}

// putTnProbe tries the peer's door once and keeps what it did.
func putTnProbe(agent, addr string) {
	_, err := putTnKnock(context.Background(), addr)
	putTn.Lock()
	defer putTn.Unlock()
	if putTn.reach == nil || putTn.reach[agent].addr != addr {
		return
	}
	putTn.reach[agent] = putTnReach{addr: addr, ok: err == nil, at: time.Now()}
}

// putTnKnock is a TCP connection to a door, made and let go: how long it
// took, which is the way there and back once.
func putTnKnock(ctx context.Context, addr string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, putTnProbeWait)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return 0, err
	}
	took := time.Since(start)
	c.Close()
	return took, nil
}

func putTnFailed(agent string) {
	putTn.Lock()
	defer putTn.Unlock()
	if putTn.rest == nil {
		putTn.rest = map[string]time.Time{}
	}
	putTn.rest[agent] = time.Now().Add(putTnRest)
	// Not on a tailnet itself, this Mac does not go back there until the door
	// is seen to take a connection again.
	if r, ok := putTn.reach[agent]; ok {
		r.ok, r.at = false, time.Now()
		putTn.reach[agent] = r
	}
}

// putMachineKeys are the put keys as the Noise session takes them: the same
// Curve25519 keys, under controlbase's types.
func putMachinePrivate(k key.NodePrivate) (key.MachinePrivate, error) {
	raw := k.Raw32()
	var m key.MachinePrivate
	err := m.UnmarshalText([]byte("privkey:" + hex.EncodeToString(raw[:])))
	return m, err
}

func putMachinePublic(k key.NodePublic) key.MachinePublic {
	raw := k.Raw32()
	var m key.MachinePublic
	if m.UnmarshalText([]byte("mkey:"+hex.EncodeToString(raw[:]))) != nil {
		return key.MachinePublic{}
	}
	return m
}

// bufConn is a connection read through the reader that read its first bytes.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// errPutTnSkip: no tailnet stream was tried (no road, or none known).
var errPutTnSkip = errors.New("no tailnet road to the peer")

// putTnDial opens a Noise session with the peer at its tailnet door, by
// deadline, which stays set on the session (controlbase clears its own).
// self is this Mac's agent id.
func putTnDial(p putPeer, self, addr string, deadline time.Time) (net.Conn, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	priv, err := putKeyFor(p.Agent)
	if err != nil {
		return nil, err
	}
	mp, err := putMachinePrivate(priv)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(deadline)
	head := "POST " + putTnPath + " HTTP/1.1\r\nHost: tailnet\r\nUpgrade: " + putTnUpgrade + "\r\nConnection: Upgrade\r\n" +
		putTnFromHeader + ": " + self + "\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(raw, head); err != nil {
		raw.Close()
		return nil, err
	}
	br := bufio.NewReader(raw)
	status, upgraded, _, _, err := putReadHeadAs(br, putTnUpgrade)
	if err != nil || status != http.StatusSwitchingProtocols || !upgraded {
		raw.Close()
		if err == nil {
			err = fmt.Errorf("tailnet door answered %d", status)
		}
		return nil, err
	}
	sc, err := controlbase.Client(ctx, bufConn{raw, br}, mp, putMachinePublic(p.node), putTnVersion)
	if err != nil {
		raw.Close()
		return nil, err
	}
	sc.SetDeadline(deadline)
	return sc, nil
}

// putConnectTailnet opens the stream to the peer through the tailnet, as
// putConnect does through tailcat: the connection and its reader once the
// other side has taken it; a refusal's code when the peer's put said no, or
// "unreachable" when its answer began and broke off (the stream may have
// reached put there: not tried again by tailcat); an error when the tailnet
// did not carry it (tailcat is tried then). self is this Mac's agent id.
func putConnectTailnet(p putPeer, self string, deadline time.Time) (net.Conn, *bufio.Reader, string, error) {
	addr := putTnFor(p.Agent)
	if addr == "" {
		return nil, nil, "", errPutTnSkip
	}
	tnDeadline := time.Now().Add(putTnWait)
	if deadline.Before(tnDeadline) {
		tnDeadline = deadline
	}
	sc, err := putTnDial(p, self, addr, tnDeadline)
	if err != nil {
		return nil, nil, "", err
	}
	if _, err := io.WriteString(sc, "GET "+putStreamPath+" HTTP/1.1\r\nHost: tailnet\r\nUpgrade: put\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		sc.Close()
		return nil, nil, "", err
	}
	nr := bufio.NewReader(sc)
	if _, err := nr.Peek(1); err != nil {
		sc.Close()
		return nil, nil, "", err
	}
	// An answer has begun: whatever happens now, it is the answer.
	status, upgraded, code, _, err := putReadHeadAs(nr, "put")
	if err != nil {
		sc.Close()
		return nil, nil, "unreachable", nil
	}
	if status != http.StatusSwitchingProtocols || !upgraded {
		sc.Close()
		if code == "" {
			code = "refused"
		}
		// The peer's put answered: tailcat would hear the same.
		return nil, nil, code, nil
	}
	return sc, nr, "", nil
}

// putTailnetServe is the door on the tailnet road: a listed peer that proves
// its key gets the stream to put here, as through the tunnel.
func putTailnetServe(w http.ResponseWriter, r *http.Request) {
	if tailnetOff() || !strings.EqualFold(r.Header.Get("Upgrade"), putTnUpgrade) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	agent := r.Header.Get(putTnFromHeader)
	p, ok := putPeerByAgent(agent)
	if !ok || p.node.IsZero() {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// A seat at the door, held through the handshake and the stream's request.
	if putTnBusy.Add(1) > putTnHandshakes {
		putTnBusy.Add(-1)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer putTnBusy.Add(-1)
	priv, err := putKeyFor(p.Agent)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	mp, err := putMachinePrivate(priv)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(putTnHandshakeWait))
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+putTnUpgrade+"\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		conn.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), putTnHandshakeWait)
	defer cancel()
	sc, err := controlbase.Server(ctx, bufConn{conn, brw.Reader}, mp, nil)
	if err != nil {
		conn.Close()
		return
	}
	// The caller is who it said only if its key is that peer's.
	if sc.Peer() != putMachinePublic(p.node) {
		sc.Close()
		return
	}
	// From here the peer's removal ends this connection (putCut); and its entry
	// is read again, for one removed or rekeyed while it shook hands.
	untrack := putTrack(p.Agent, sc)
	if cur, ok := putPeerByAgent(p.Agent); !ok || cur.node != p.node {
		untrack()
		sc.Close()
		return
	}
	putServeConn(sc, p, untrack)
}

// putReadAsk reads the stream's request on the session — at most putHeadMax
// bytes of it, and nothing past it — for its method, path and upgrade.
func putReadAsk(r *bufio.Reader) (method, path, upgrade string, err error) {
	total := 0
	line := func() (string, error) {
		var b []byte
		for {
			c, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			total++
			if total > putHeadMax {
				return "", errors.New("request head too long")
			}
			if c == '\n' {
				return strings.TrimRight(string(b), "\r"), nil
			}
			b = append(b, c)
		}
	}
	first, err := line()
	if err != nil {
		return "", "", "", err
	}
	parts := strings.Split(first, " ")
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return "", "", "", errors.New("not an HTTP request")
	}
	for {
		l, err := line()
		if err != nil {
			return "", "", "", err
		}
		if l == "" {
			break
		}
		if i := strings.IndexByte(l, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(l[:i]), "Upgrade") {
			upgrade = strings.TrimSpace(l[i+1:])
		}
	}
	return parts[0], parts[1], upgrade, nil
}

// putServeConn is putServe on a connection of its own (the tailnet's Noise
// session): the request for the stream, then the stream to put here. done
// lets go of the connection's tracking so far, once the stream's own holds it
// or it is over.
func putServeConn(conn net.Conn, p putPeer, done func()) {
	conn.SetDeadline(time.Now().Add(putTnHandshakeWait))
	br := bufio.NewReader(conn)
	method, path, upgrade, err := putReadAsk(br)
	refuse := func(status int, code string) {
		defer done()
		var body []byte
		if f, err := transport.New(transport.TypeError, agentID(), "", transport.Error{Code: code}); err == nil {
			body, _ = transport.Encode(f)
		}
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", status, http.StatusText(status), len(body))
		conn.Write(body)
		conn.Close()
	}
	if err != nil {
		done()
		conn.Close()
		return
	}
	if path != putStreamPath || method != http.MethodGet || !strings.EqualFold(upgrade, "put") {
		refuse(http.StatusForbidden, "not-allowed")
		return
	}
	if !putStreamStart() {
		refuse(http.StatusServiceUnavailable, "busy")
		return
	}
	header, _ := json.Marshal(map[string]string{"from": p.Agent, "name": p.Name})
	local := putTakeAccept(append(header, '\n'))
	if local == nil {
		putStreamEnd()
		refuse(http.StatusServiceUnavailable, "put-not-running")
		return
	}
	conn.SetDeadline(time.Time{})
	untrack := putTrack(p.Agent, local, conn)
	done()
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: put\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		untrack()
		putStreamEnd()
		conn.Close()
		local.Close()
		return
	}
	go func() {
		defer putStreamEnd()
		defer untrack()
		// What the peer sent after its request, read with it, goes first.
		putPipe(local, local, conn, br)
	}()
}
