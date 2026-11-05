package transport

// The tailcat carrier: a WireGuard tunnel with DERP as the rendezvous and
// relay of last resort, no Tailscale account or control plane involved
// (github.com/tailscale/tailcat, BSD-3-Clause — see NOTICE).
//
// Shape, and why it is a SERVER here even though the helper's whole design
// is "nothing listens": the tunnel's listening side opens no TCP port on
// this machine. It dials OUT to a DERP relay and waits there, exactly as the
// relay push dials out to monitor.subnsub.com. A browser holding this
// machine's address dials the same relay, the two sides meet, and from then
// on the bytes are end-to-end encrypted between them — the relay sees
// ciphertext, and so does anyone running it. What the machine exposes is
// one TCP port INSIDE that tunnel, served by an http.Handler the caller
// supplies, and only to clients whose node key is on the allowlist.
//
// UDP first, DERP when it must. magicsock binds one UDP socket on an
// ephemeral port and tries a direct path to every peer that can take one;
// DERP — always TCP, TLS on 443 — carries whatever no direct path forms
// for. Every browser is such a peer (a browser has no UDP), so browsers
// stay on DERP; a native peer (another tailcat, a future app) goes direct.
// What reaches a handler through that socket is still only WireGuard from
// an admitted key: the allowlist gates it exactly as it gates DERP.
//
// THE PRICE, stated so nobody rediscovers it as a bug: the moment a peer's
// handshake completes, tailcat sends it a disco CallMeMaybe naming every UDP
// endpoint this machine knows — the STUN-learned public ip:port and the
// addresses of its interfaces — sealed to that peer's key, so the peer can
// read them. That is how a direct path forms at all, and upstream has no
// per-peer filter. The peers are the browsers the owner allowed and the
// portable copies the owner made (clone.go).
//
// Three boundaries, and where each is enforced:
//
//   - WireGuard-level admission (Server.AllowedClients): a key not on the
//     list is silently ignored at the handshake — it cannot even learn that
//     the server exists. Set at Start and grown at runtime by AddAllowed.
//   - Application-level admission (Gate): every HTTP request is mapped back
//     to the node key that sent it and checked against the CURRENT list, the
//     one the caller re-reads from disk. This is the online revocation point:
//     the upstream library can add an allowed client but cannot remove one,
//     so a key struck from the
//     file stops being served here, on its next request, without a restart.
//   - Capability (the handler): being admitted grants OBSERVE and nothing
//     else.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// TailcatConfig is what StartTailcat needs. Every field but Handler and
// Allowed has a usable zero value.
type TailcatConfig struct {
	// StateDir holds the node key and the pinned DERP region. It is created
	// 0700 and refused if it is wider than that: the key inside it IS this
	// machine's transport identity.
	StateDir string
	// DERPMapURL, when set, replaces the public tailcat.dev map — this is
	// how a self-hosted derper becomes the rendezvous. Empty means the
	// public map, which the plan permits for personal use and demos and
	// which the page says out loud is best-effort.
	DERPMapURL string
	// Port is the one TCP port served inside the tunnel. Every other port is
	// dropped by the packet filter before it reaches a handler.
	Port uint16
	// Allowed returns the CURRENT allowlist. Called at Start (and refused if
	// it answers with nothing — an open server is a lab, not a product) and
	// again on every request by Gate, so the caller decides how fresh
	// "current" is by how it implements this.
	Allowed func() []key.NodePublic
	// Handler serves requests that arrive through the tunnel and passed the
	// gate. It sees a request whose context carries the peer's key (see
	// PeerFromContext).
	Handler http.Handler
	// Logf receives the library's own chatter. Nil discards it, which is the
	// right default: the tunnel's debug log names DERP endpoints and peer
	// addresses, and the plan keeps those out of ordinary product logs.
	Logf logger.Logf
}

// Tailcat is a running carrier. Construct with StartTailcat.
type Tailcat struct {
	cfg    TailcatConfig
	srv    *tailcat.Server
	ln     *memListener
	httpd  *http.Server
	key    key.NodePrivate
	psk    tailcat.PresharedKey
	region tailcfg.DERPRegionID
	reg    *tailcfg.DERPRegion // the region started in, as it is dialed (ProbeRelay)
	byName bool
	blob   string

	mu       sync.Mutex
	allowed  map[key.NodePublic]bool // what the tunnel has been told so far
	closed   bool
	serveErr chan error
}

// ErrNoAllowedClients is what StartTailcat returns when the allowlist is
// empty. Refused rather than started open: a server that admits every key
// is exactly what the lab ran and exactly what the plan forbids in a
// product, and "it works until somebody adds a key" would make the unsafe
// state the one that appears to function.
var ErrNoAllowedClients = errors.New("transport: no allowed clients; refusing to start an open tunnel")

const (
	nodeKeyFile = "tailcat.key"
	regionFile  = "tailcat.region"
	pskFile     = "tailcat.psk"
)

// StartTailcat brings the tunnel up and starts serving cfg.Handler on
// cfg.Port inside it. It returns once the DERP connection is established and
// the address (ConnBlob) is known.
func StartTailcat(cfg TailcatConfig) (*Tailcat, error) {
	if cfg.Handler == nil {
		return nil, errors.New("transport: tailcat needs a handler")
	}
	if cfg.Port == 0 {
		return nil, errors.New("transport: tailcat needs a served port")
	}
	if cfg.Allowed == nil {
		return nil, ErrNoAllowedClients
	}
	allowed := cfg.Allowed()
	if len(allowed) == 0 {
		return nil, ErrNoAllowedClients
	}
	k, err := loadOrCreateKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	logf := cfg.Logf
	if logf == nil {
		logf = logger.Discard
	}
	t := &Tailcat{
		cfg:      cfg,
		key:      k,
		psk:      loadOrCreatePSK(cfg.StateDir, logf),
		allowed:  map[key.NodePublic]bool{},
		serveErr: make(chan error, 1),
	}
	for _, a := range allowed {
		t.allowed[a] = true
	}

	// The region is pinned after the first start so the address survives
	// restarts: a blob embeds the region it was minted for (and the
	// pre-shared key, kept beside it — loadOrCreatePSK), and picking a
	// fresh one by latency each boot would hand every watcher a machine
	// that moved. If the pinned region has vanished from the map, the pin
	// is dropped and the pick runs again — an address change beats a
	// helper that will not start.
	pinned := readRegion(cfg.StateDir)
	reg, byName, err := chooseRegion(cfg.DERPMapURL, pinned, logf)
	if err != nil {
		return nil, err
	}
	srv, err := t.start(reg, logf)
	if err != nil {
		return nil, err
	}
	t.srv = srv
	t.blob = string(srv.ConnBlob())
	t.region = reg.RegionID
	t.reg = reg
	t.byName = byName
	if t.region != pinned {
		if werr := writeRegion(cfg.StateDir, t.region); werr != nil {
			logf("tailcat: could not pin DERP region: %v", werr)
		}
	}

	t.httpd = &http.Server{
		Handler:           t.Gate(cfg.Handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// No WriteTimeout: the events stream is long-lived and sets its own
		// per-write deadline, exactly as the local listener does.
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 8 << 10,
	}
	go func() {
		err := t.httpd.Serve(t.ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.serveErr <- err
		}
		close(t.serveErr)
	}()
	return t, nil
}

// chooseRegion returns the DERP region to start in: the pinned one while the
// map still has it, otherwise the nearest by netcheck, otherwise any.
//
// The helper chooses instead of letting tailcat.Server pick, because the pick
// cannot be read back. tailcat drops region IDs from an address to save bytes
// and ParseAddr numbers the regions it decodes from 1, so the ID taken off the
// started server's address was 1 on every machine — a region the public map
// does not have. Each restart found that pin gone and picked again; a machine
// that cannot measure latency picked at random, producing a new
// address on every restart and probing all regions' relays on every pick.
func chooseRegion(derpMapURL string, pinned tailcfg.DERPRegionID, logf logger.Logf) (*tailcfg.DERPRegion, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := []any{tailcat.ExpandForServer}
	if derpMapURL != "" {
		opts = append(opts, tailcat.DERPMapURL(derpMapURL))
	}
	dm, err := tailcat.FetchDERPMap(ctx, opts...)
	if err != nil {
		// The pin survives a failed fetch: the caller retries, and picking
		// afresh over a blip would rotate the address every watcher holds.
		return nil, false, fmt.Errorf("tailcat: DERP map: %w", err)
	}
	return pickRegion(ctx, dm, pinned, tailcat.PickBestRegion, lookupIPv4, logf)
}

// pickRegion is chooseRegion's decision over a fetched map. best measures the
// regions (tailcat.PickBestRegion, or a stand-in in tests) and lookup is this
// machine's DNS. It returns a copy the caller may keep, already rewritten to
// dial by name where DNS says so (dialByName), and whether it was.
//
// When it has to measure, the rewrite runs first and over every region:
// netcheck probes the relays it is handed, and probing a sandbox's relays by
// IP is the very approval request the rewrite exists to avoid.
// In such a sandbox the relay whose name is already approved is
// the one that answers, so that is the region it settles on.
func pickRegion(ctx context.Context, dm *tailcfg.DERPMap, pinned tailcfg.DERPRegionID,
	best func(context.Context, *tailcfg.DERPMap) (tailcfg.DERPRegionID, error),
	lookup func(context.Context, string) ([]netip.Addr, error), logf logger.Logf) (*tailcfg.DERPRegion, bool, error) {
	var ids []tailcfg.DERPRegionID
	if dm != nil {
		for _, id := range slices.Sorted(maps.Keys(dm.Regions)) {
			if r := dm.Regions[id]; r != nil && len(r.Nodes) > 0 {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, false, errors.New("tailcat: the DERP map has no regions")
	}
	if pinned != 0 {
		if slices.Contains(ids, pinned) {
			r := dm.Regions[pinned].Clone()
			return r, dialByName(ctx, r, lookup, logf), nil
		}
		logf("tailcat: pinned DERP region %d is gone; picking again", pinned)
	}
	dm = dm.Clone()
	byName := map[tailcfg.DERPRegionID]bool{}
	for _, id := range ids {
		byName[id] = dialByName(ctx, dm.Regions[id], lookup, logf)
	}
	id, err := best(ctx, dm)
	if err != nil {
		logf("tailcat: could not measure the DERP regions (%v); taking any", err)
	}
	if !slices.Contains(ids, id) {
		// Nothing measured — as tailcat does, any region rather than none.
		id = ids[rand.IntN(len(ids))]
	}
	return dm.Regions[id], byName[id], nil
}

// dialByName makes the DERP connection dial a relay by its host name, not by
// the address the map lists, wherever this machine's DNS puts that name
// somewhere else, and reports whether it did for any relay of reg.
//
// derphttp dials the map's IP literals and asks DNS only for a node that has
// none. Where DNS answers with a different address, the network in between
// routes by name: a sandbox's transparent egress (where DNS hands
// out its gateway, which forwards by name and asks the owner to approve every
// bare IP), or a fake-ip proxy
// on a desktop. Dialing the name goes the way every HTTPS request on that
// machine goes, and the way the watching browser reaches the same relay. Where
// DNS agrees with the map, or does not answer, nothing changes: the literal
// dial keeps working when DNS does not.
//
// The literals leave the address too, so a native peer reaching this machine
// resolves the relay's name as well; a browser always does.
func dialByName(ctx context.Context, reg *tailcfg.DERPRegion, lookup func(context.Context, string) ([]netip.Addr, error), logf logger.Logf) bool {
	byName := false
	for _, n := range reg.Nodes {
		if n == nil || n.HostName == "" {
			continue
		}
		listed, err := netip.ParseAddr(n.IPv4)
		if err != nil || !listed.Is4() {
			continue // no literal to compare (dialled by name already, or "none")
		}
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		got, err := lookup(lctx, n.HostName)
		cancel()
		if err != nil || len(got) == 0 {
			continue
		}
		if slices.ContainsFunc(got, func(a netip.Addr) bool { return a.Unmap() == listed }) {
			continue
		}
		logf("tailcat: DNS puts %s at %v, not the map's %v; dialing it by name", n.HostName, got, listed)
		n.IPv4 = ""
		if _, err := netip.ParseAddr(n.IPv6); err == nil {
			n.IPv6 = "" // by name over IPv6 too; "none" stays none
		}
		byName = true
	}
	return byName
}

func lookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
}

func (t *Tailcat) start(reg *tailcfg.DERPRegion, logf logger.Logf) (*tailcat.Server, error) {
	ln := newMemListener(t.cfg.Port)
	port := t.cfg.Port
	srv := &tailcat.Server{
		Key:          t.key,
		PresharedKey: t.psk,
		Logf:         logf,
		Region:       reg,
		// Defence in depth: the packet filter admits only the one served
		// port, and OnTCP is the per-port gate behind it. A dial to any
		// other port times out at the filter — no RST, nothing to probe.
		ServedTCPPorts: []filter.PortRange{{First: port, Last: port}},
		OnTCP: func(p uint16) func(net.Conn) {
			if p != port {
				return nil
			}
			return ln.deliver
		},
	}
	for k := range t.allowed {
		srv.AllowedClients = append(srv.AllowedClients, k)
	}
	if err := srv.Start(); err != nil {
		ln.Close()
		return nil, fmt.Errorf("tailcat: start: %w", err)
	}
	t.ln = ln
	return srv, nil
}

// ProbeRelay reports whether this machine can reach the DERP relay its tunnel
// waits at, right now: a TLS connection to the region, dialed and verified by
// the very path the tunnel's own DERP client takes (derphttp DialRegionTLS,
// the one tailscale's netcheck uses — the environment's proxy, IPv4 and IPv6
// raced, each node given its own short timeout before the next, the map's
// CertName honoured) against the region as the tunnel dials it (dialByName
// has already rewritten it where DNS disagrees with the map). The tunnel's own
// connection is the library's and its health cannot be read back, so this is
// a fresh one, opened and closed. A connection that verifies is a machine a
// browser could reach over tailcat — the helper's evidence, while its relay
// push is failing, that it was online all the same (reach.go). A captive
// portal or a firewall that lets nothing through fails it, as it should.
func (t *Tailcat) ProbeRelay(ctx context.Context) error {
	if t == nil || t.reg == nil {
		return errors.New("tailcat: no region to probe")
	}
	c := derphttp.NewNetcheckClient(logger.Discard, netmon.NewStatic())
	conn, closer, _, err := c.DialRegionTLS(ctx, t.reg)
	if err != nil {
		return err
	}
	conn.Close()
	closer.Close()
	return nil
}

// PeerRx is how many bytes this machine has received from the peer over the
// tunnel so far, and whether the tunnel knows the peer. A browser that is
// reading a stream acknowledges what it reads, so the count moves while the
// frames arrive; a path gone dark stops it, while writes into the socket's
// buffer can go on succeeding for a while yet (reach.go evidence).
func (t *Tailcat) PeerRx(k key.NodePublic) (int64, bool) {
	if t == nil || t.srv == nil {
		return 0, false
	}
	st := t.srv.Status()
	if st == nil {
		return 0, false
	}
	p, ok := st.Peer[k]
	if !ok || p == nil {
		return 0, false
	}
	return p.RxBytes, true
}

// ConnBlob is this machine's address on the tunnel: what a watcher pastes to
// reach it. It is a bearer capability for REACHING the node — not for
// reading anything, which the allowlist gates — and the plan says to treat
// it as such: shown once at the machine, written 0600, never in a URL.
func (t *Tailcat) ConnBlob() string { return t.blob }

// Public is this machine's node public key.
func (t *Tailcat) Public() key.NodePublic { return t.key.Public() }

// Region is the DERP region this address is minted for.
func (t *Tailcat) Region() int { return int(t.region) }

// ByName reports whether the relay is dialed by host name because this
// machine's DNS sends that name elsewhere (see dialByName).
func (t *Tailcat) ByName() bool { return t.byName }

// AddAllowed admits k at the WireGuard layer without a restart. The caller
// calls this when it sees a key added to the allowlist on disk; there is no
// counterpart for removal (upstream has none), which is why Gate re-checks
// the current list on every request instead.
func (t *Tailcat) AddAllowed(k key.NodePublic) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.allowed[k] {
		return
	}
	t.allowed[k] = true
	t.srv.AddAllowedClient(k)
}

// Known reports whether k has been handed to the tunnel already, so a
// caller polling the file can tell an addition from a line it has seen.
func (t *Tailcat) Known(k key.NodePublic) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.allowed[k]
}

// Close tears the tunnel down. Idempotent.
func (t *Tailcat) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if t.httpd != nil {
		t.httpd.Shutdown(ctx)
	}
	if t.ln != nil {
		t.ln.Close()
	}
	if t.srv != nil {
		return t.srv.Close()
	}
	return nil
}

// Done yields once the HTTP server inside the tunnel has stopped, with the
// error that stopped it (nil on a clean Close).
func (t *Tailcat) Done() <-chan error { return t.serveErr }

// ── peer identity ─────────────────────────────────────────────────────

type peerKeyCtx struct{}

// PeerFromContext returns the node key of the tunnel peer that made this
// request, as established by Gate. ok is false outside a gated request.
func PeerFromContext(ctx context.Context) (k key.NodePublic, ok bool) {
	k, ok = ctx.Value(peerKeyCtx{}).(key.NodePublic)
	return
}

// WithPeer returns ctx carrying k as the request's tunnel peer — what Gate
// does for a real request, offered so a handler can be exercised in a test
// without a tunnel. On a request path it is used by the tailnet road alone
// (main package, tailnet.go), whose peer is whoever proved that key to open
// the sealed session the request came in; on the tunnel the peer is whoever
// the tunnel attributed it to, and nothing else.
func WithPeer(ctx context.Context, k key.NodePublic) context.Context {
	return context.WithValue(ctx, peerKeyCtx{}, k)
}

// Gate wraps h so that every request is attributed to the node key that
// sent it and refused unless that key is on the allowlist AS OF NOW.
//
// Attribution works because the tunnel gives each peer a deterministic
// address derived from its key (see addrForKey), so the request's remote
// address names the key without any header the peer could forge. A request
// whose address matches no currently-allowed key is refused with 403 and
// an error frame — including a key that was allowed at Start and has since
// been removed from the file, which is the whole point.
func (t *Tailcat) Gate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k, ok := t.PeerKey(r.RemoteAddr)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			if f, err := New(TypeError, "", "", Error{Code: "not-allowed"}); err == nil {
				if b, err := Encode(f); err == nil {
					w.Write(b)
				}
			}
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKeyCtx{}, k)))
	})
}

// PeerKey maps a request's remote address to the allowed key that owns it,
// consulting the caller's CURRENT allowlist rather than the tunnel's memory.
func (t *Tailcat) PeerKey(remote string) (key.NodePublic, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return key.NodePublic{}, false
	}
	for _, k := range t.cfg.Allowed() {
		if addrForKey(k) == addr {
			return k, true
		}
	}
	return key.NodePublic{}, false
}

// addrForKey is the tunnel address tailcat assigns a node: Tailscale's ULA
// prefix fd7a:115c:a1e0::/48 with the next 80 bits taken from the node key.
// Mirrors the upstream (unexported) derivation; the test pins it against a
// live handshake so a change upstream fails loudly here rather than
// silently turning the gate into a wall.
func addrForKey(k key.NodePublic) netip.Addr {
	var a [16]byte
	r := k.Raw32()
	a[0], a[1], a[2], a[3], a[4], a[5] = 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0
	copy(a[6:], r[:10])
	return netip.AddrFrom16(a)
}

// There is deliberately no server-side "which path is this peer on". The
// library's Status() builds without WantPeers, so peers never appear in it;
// the path a watcher is on is measured by the watcher (DiscoPing in
// tailcat-web's client.path()), which is also the side that shows it.

// ── key and region persistence ────────────────────────────────────────
// Key persistence rules: an unreadable key must never be silently replaced (that is
// an identity rotation every watcher would experience as the machine going
// dark), creation is atomic, and both the file and its directory must be
// owner-only or the whole thing is refused.

func loadOrCreateKey(dir string) (key.NodePrivate, error) {
	var zero key.NodePrivate
	if dir == "" {
		return zero, errors.New("transport: no state directory for the tunnel key")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return zero, err
	}
	if err := requireOwnerOnly(dir); err != nil {
		return zero, err
	}
	path := filepath.Join(dir, nodeKeyFile)
	k, err := readKeyFile(path)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return zero, err
	}
	nk := key.NewNode()
	text, err := nk.MarshalText()
	if err != nil {
		return zero, err
	}
	tmp, err := os.CreateTemp(dir, nodeKeyFile+".tmp-*") // 0600 by contract
	if err != nil {
		return zero, err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(text, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return zero, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return zero, err
	}
	// Link, not rename: rename would overwrite a key a racing process just
	// published. Link fails with EEXIST instead, and the loser adopts the
	// winner's key by re-reading.
	if err := os.Link(tmpName, path); err != nil {
		os.Remove(tmpName)
		if errors.Is(err, fs.ErrExist) {
			return readKeyFile(path)
		}
		return zero, err
	}
	os.Remove(tmpName)
	return nk, nil
}

func readKeyFile(path string) (key.NodePrivate, error) {
	var zero key.NodePrivate
	fi, err := os.Lstat(path)
	if err != nil {
		return zero, err // includes fs.ErrNotExist for the caller to test
	}
	if !fi.Mode().IsRegular() {
		return zero, fmt.Errorf("%s is not a regular file (mode %v); refusing to use it", path, fi.Mode())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return zero, fmt.Errorf("%s is group/other-accessible (%v); chmod 600 it and retry", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	var k key.NodePrivate
	if err := k.UnmarshalText([]byte(strings.TrimSpace(string(b)))); err != nil {
		return zero, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	if k.IsZero() {
		return zero, fmt.Errorf("%s holds an all-zero key; delete it to generate a real one", path)
	}
	return k, nil
}

// requireOwnerOnly makes the state directory owner-only, tightening it if
// it is wider. Tightening rather than refusing, because the directory is
// the helper's own config dir and earlier installs created it
// through the installer's mkdir under the login umask — 0755 on most
// systems — which would otherwise leave direct mode refusing to start on
// existing installations. Only a
// directory this user owns can be chmod'ed, so a directory that cannot be
// tightened is still refused.
func requireOwnerOnly(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("%s is group/other-accessible (%v) and could not be tightened: %w", dir, fi.Mode().Perm(), err)
	}
	fi, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is still group/other-accessible (%v); chmod 700 it and retry", dir, fi.Mode().Perm())
	}
	return nil
}

// PublicKeyOf reads the persisted node key's public half without starting
// anything — for `subnsub-monitor address` and the installer, which need
// the identity before (or without) a running tunnel. It creates the key if
// there is none, under the same rules as the running carrier.
func PublicKeyOf(stateDir string) (key.NodePublic, error) {
	k, err := loadOrCreateKey(stateDir)
	if err != nil {
		return key.NodePublic{}, err
	}
	return k.Public(), nil
}

// loadOrCreatePSK is the tunnel's WireGuard pre-shared key, kept beside the
// node key. It is part of the address, and tailcat makes a new one on every
// start when it is not given one — so until 2026-10-17 every restart handed
// out a new address, whatever the key and region files said (the docs and
// comments claimed otherwise). Kept, the address changes only when the node
// key, the region or this file does. A file that cannot be read or written
// costs a new address, never a start.
func loadOrCreatePSK(dir string, logf logger.Logf) tailcat.PresharedKey {
	if dir == "" {
		return tailcat.NewPresharedKey()
	}
	path := filepath.Join(dir, pskFile)
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 == 0 {
		if b, err := os.ReadFile(path); err == nil {
			var p tailcat.PresharedKey
			if p.UnmarshalText([]byte(strings.TrimSpace(string(b)))) == nil && !p.IsZero() {
				return p
			}
		}
	}
	p := tailcat.NewPresharedKey()
	text, _ := p.MarshalText()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(text, '\n'), 0o600); err != nil {
		logf("tailcat: could not keep the pre-shared key: %v", err)
		return p
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		logf("tailcat: could not keep the pre-shared key: %v", err)
	}
	return p
}

func readRegion(dir string) tailcfg.DERPRegionID {
	if dir == "" {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(dir, regionFile))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 0
	}
	return tailcfg.DERPRegionID(n)
}

func writeRegion(dir string, r tailcfg.DERPRegionID) error {
	if dir == "" || r == 0 {
		return nil
	}
	path := filepath.Join(dir, regionFile)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(int(r))+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParseNodeKey accepts one allowlist line — a "nodekey:<64 hex>" public key,
// optionally followed by a comment — and returns the key, or ok=false.
// Comments and blank lines are skipped so the file can be annotated by
// whoever administers the machine, exactly as trusted-keys is.
func ParseNodeKey(line string) (key.NodePublic, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return key.NodePublic{}, false
	}
	if i := strings.IndexAny(line, " \t"); i > 0 {
		line = line[:i]
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(line)); err != nil || k.IsZero() {
		return key.NodePublic{}, false
	}
	return k, true
}
