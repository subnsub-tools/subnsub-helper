package main

// Screen — the machine's own VNC server, carried by the direct tunnel.
//
// WHAT IT IS. A page that may open a terminal here (pty.go) may also see and
// work this machine's screen: the helper connects to the VNC server already
// running on this machine — macOS Screen Sharing, a Linux desktop's remote
// desktop, wayvnc, x11vnc, TightVNC on Windows — at 127.0.0.1:5900, and
// carries its bytes to the page and back unchanged. The page's viewer
// (noVNC) speaks VNC to that server itself: the server asks for its own
// password, or the Mac's user name and password, and the helper sees only
// bytes. It never starts, configures or bypasses a VNC server, and it dials
// nothing but this machine's own loopback address.
//
// WHO MAY OPEN ONE. Exactly who may open a terminal, by the same gates: the
// peer's key is on the allowlist, the console switch is on at the machine,
// and the opening is a `screen` command SIGNED by a dashboard key this
// machine has pinned (direct.go's command). The relay's mailbox never
// carries this kind: runCommand does not know it, so it is refused there as
// any unknown kind is. A portable copy's certificate names nothing of it, so
// a copy has no screen. MON_SCREEN=off turns it off while leaving the
// terminal on.
//
// WHAT THE SIGNATURE BUYS. As for a terminal: the command answers with a
// session token, 128 random bits, good only on the tunnel of the peer that
// opened it. The streams that follow (out, in, beat, close) carry the token
// and are not signed one by one.
//
// ONE STREAM, NO RESUMING. VNC cannot pick up in the middle of a session, so
// unlike a terminal nothing is kept for a page that comes back: the output is
// read by one GET, and when that GET ends for any reason the session ends
// with it and the page opens a new one.
//
// BOUNDS. Three sessions at once. A session nobody has shown a sign of life
// on (bytes sent, or the page's beat) for screenQuietMax is ended, and so is
// every session the moment the console is switched off, the last key is
// unpinned, or the opener's key leaves the allowlist (sweep).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	screenEnvVar      = "MON_SCREEN"
	screenPortEnvVar  = "MON_SCREEN_PORT"
	screenDefaultPort = 5900
	screenMaxSessions = 3
	// The page beats every 45 seconds while it holds a session (monitor.js
	// PTY_BEAT); this is several of those.
	screenQuietMax = 3 * time.Minute
	// How long the VNC server has to answer the connection and to say it is
	// one (its version line).
	screenDialWait  = 3 * time.Second
	screenHelloWait = 5 * time.Second
	// One write either way; a reader or a server this slow is gone.
	screenWriteWait  = 30 * time.Second
	screenSweepEvery = 5 * time.Second
	screenChunk      = 64 << 10
)

var screenTokenRe = regexp.MustCompile(`^[a-f0-9]{32}$`)

// What every VNC server says first: "RFB 003.008\n" and its kin.
var screenHelloRe = regexp.MustCompile(`^RFB [0-9]{3}\.[0-9]{3}\n$`)

type screenSess struct {
	token string
	peer  key.NodePublic
	// The pinned key that signed the opening: unpinning it ends the session.
	signer ed25519.PublicKey
	conn   net.Conn
	// The server's version line, read to know it is VNC, sent to the page
	// before anything else.
	hello []byte

	mu      sync.Mutex
	seen    time.Time
	ended   bool
	done    chan struct{} // closed when the session ends
	reading bool          // the one output stream has been taken
	writing bool          // one input stream at a time
}

type screenHub struct {
	mu      sync.Mutex
	sess    map[string]*screenSess
	pending int // openings still dialling, counted against the ceiling
	// Whether a tunnel key is still on the allowlist, and whether a signing
	// key is still pinned; nil admits (a test).
	allowed func(key.NodePublic) bool
	trusted func(ed25519.PublicKey) bool
	// Where the VNC server is; a test points it at its own listener.
	addrs    func() []string
	sweeping bool
}

func newScreenHub() *screenHub {
	return &screenHub{sess: map[string]*screenSess{}, addrs: screenAddrs}
}

// The process's sessions, one table whatever becomes of the tunnel's carrier.
var screenSessions = func() *screenHub {
	hub := newScreenHub()
	hub.allowed = func(k key.NodePublic) bool {
		for _, a := range loadAllowedClients() {
			if a == k {
				return true
			}
		}
		return false
	}
	hub.trusted = trustsKey
	return hub
}()

// screenOff reports MON_SCREEN=off (or 0, false, no).
func screenOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(screenEnvVar))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// screenEnabled is whether a screen may be opened here now: the console's
// switch, and the screen's own.
func screenEnabled() bool { return consoleEnabled() && !screenOff() }

// screenPort is the VNC server's port on this machine: 5900, or
// MON_SCREEN_PORT (a server on display :1 listens on 5901).
func screenPort() int {
	if v := strings.TrimSpace(os.Getenv(screenPortEnvVar)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return screenDefaultPort
}

// screenAddrs is where to look for the VNC server: this machine's own
// loopback addresses, and nowhere else.
func screenAddrs() []string {
	p := strconv.Itoa(screenPort())
	return []string{net.JoinHostPort("127.0.0.1", p), net.JoinHostPort("::1", p)}
}

// dial connects to the VNC server and reads its version line.
func (hub *screenHub) dial() (net.Conn, []byte, error) {
	var last error = errors.New("no address")
	for _, a := range hub.addrs() {
		c, err := net.DialTimeout("tcp", a, screenDialWait)
		if err != nil {
			last = err
			continue
		}
		c.SetReadDeadline(time.Now().Add(screenHelloWait))
		hello := make([]byte, 12)
		if _, err := io.ReadFull(c, hello); err != nil || !screenHelloRe.Match(hello) {
			c.Close()
			if err == nil {
				err = errors.New("not a VNC server")
			}
			last = err
			continue
		}
		c.SetReadDeadline(time.Time{})
		return c, hello, nil
	}
	return nil, nil, last
}

// open connects a session for peer. The caller has verified the command's
// signature and that a key is pinned. Returns the token, or a refusal code.
func (hub *screenHub) open(peer key.NodePublic, signer ed25519.PublicKey) (string, string) {
	if !consoleEnabled() {
		return "", "console-off"
	}
	if screenOff() {
		return "", "screen-off"
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "unavailable"
	}
	hub.mu.Lock()
	if len(hub.sess)+hub.pending >= screenMaxSessions {
		hub.mu.Unlock()
		return "", "busy"
	}
	hub.pending++
	hub.mu.Unlock()
	conn, hello, err := hub.dial()
	hub.mu.Lock()
	hub.pending--
	if err != nil {
		hub.mu.Unlock()
		warnf("screen: no VNC server at port %d: %v", screenPort(), err)
		return "", "no-vnc"
	}
	s := &screenSess{
		token: hex.EncodeToString(raw[:]), peer: peer, signer: signer, conn: conn, hello: hello,
		seen: time.Now(), done: make(chan struct{}),
	}
	hub.sess[s.token] = s
	n := len(hub.sess)
	if !hub.sweeping {
		hub.sweeping = true
		go hub.watch()
	}
	hub.mu.Unlock()
	warnf("screen: session opened (%d of %d)", n, screenMaxSessions)
	return s.token, ""
}

// watch sweeps every screenSweepEvery until no session is left.
func (hub *screenHub) watch() {
	t := time.NewTicker(screenSweepEvery)
	defer t.Stop()
	for range t.C {
		hub.sweep(time.Now())
		hub.mu.Lock()
		if len(hub.sess) == 0 {
			hub.sweeping = false
			hub.mu.Unlock()
			return
		}
		hub.mu.Unlock()
	}
}

// end closes a session: the connection to the VNC server is closed, and
// every stream on it wakes to find it over. Safe to call twice.
func (hub *screenHub) end(s *screenSess) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	close(s.done)
	s.mu.Unlock()
	s.conn.Close()
	hub.mu.Lock()
	delete(hub.sess, s.token)
	n := len(hub.sess)
	hub.mu.Unlock()
	warnf("screen: session ended (%d left)", n)
}

func (hub *screenHub) endAll() {
	hub.mu.Lock()
	all := make([]*screenSess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	hub.mu.Unlock()
	for _, s := range all {
		hub.end(s)
	}
}

// sweep ends what may no longer run: every session once the console or the
// screen is off, one whose opener's key left the allowlist or whose signing
// key was unpinned, one whose page has gone quiet.
func (hub *screenHub) sweep(t time.Time) {
	hub.mu.Lock()
	allowed, trusted := hub.allowed, hub.trusted
	all := make([]*screenSess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	hub.mu.Unlock()
	if len(all) == 0 {
		return
	}
	open := screenEnabled()
	for _, s := range all {
		s.mu.Lock()
		quiet := t.Sub(s.seen) > screenQuietMax
		s.mu.Unlock()
		if !open || quiet || (allowed != nil && !allowed(s.peer)) || (trusted != nil && !trusted(s.signer)) {
			hub.end(s)
		}
	}
}

// find is the session a request names, for the peer that opened it and no
// other; a sign of life either way.
func (hub *screenHub) find(r *http.Request) *screenSess {
	peer, ok := transport.PeerFromContext(r.Context())
	if !ok {
		return nil
	}
	tok := r.URL.Query().Get("s")
	if !screenTokenRe.MatchString(tok) {
		return nil
	}
	hub.mu.Lock()
	s := hub.sess[tok]
	hub.mu.Unlock()
	if s == nil || s.peer != peer {
		return nil
	}
	s.mu.Lock()
	ended := s.ended
	s.seen = time.Now()
	s.mu.Unlock()
	if ended {
		return nil
	}
	return s
}

// screenOut is GET /v1/screen/out?s=…: the VNC server's bytes, from its
// first, until either end lets go — and then the session is over.
func (h *directHandler) screenOut(w http.ResponseWriter, r *http.Request) {
	s := h.screens.find(r)
	if s == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	s.mu.Lock()
	if s.reading {
		s.mu.Unlock()
		h.refuse(w, http.StatusConflict, "busy")
		return
	}
	s.reading = true
	s.mu.Unlock()
	defer h.screens.end(s)
	// A page that goes away mid-read ends the session, which closes the
	// connection and so the read below.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-r.Context().Done():
			h.screens.end(s)
		case <-s.done:
		case <-stop:
		}
	}()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Now().Add(screenWriteWait))
	if _, err := w.Write(s.hello); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}
	buf := make([]byte, screenChunk)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			rc.SetWriteDeadline(time.Now().Add(screenWriteWait))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if ferr := rc.Flush(); ferr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// screenIn is POST /v1/screen/in?s=…: what the page sends the VNC server, for
// as long as the body stays open — one long body on the tunnel, a piece per
// request on the tailnet road. Ends with the body, or with the session.
func (h *directHandler) screenIn(w http.ResponseWriter, r *http.Request) {
	s := h.screens.find(r)
	if s == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	s.mu.Lock()
	if s.writing {
		s.mu.Unlock()
		h.refuse(w, http.StatusConflict, "busy")
		return
	}
	s.writing = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.writing = false
		s.mu.Unlock()
	}()
	rc := http.NewResponseController(w)
	// As for a terminal's input (pty.go ptyIn): full duplex and no
	// keep-alive, so the answer can go out under a body the page has not
	// ended, and no read deadline, since a viewer is silent while nobody
	// moves the mouse. What ends a stream nobody is behind is the session's
	// quiet limit.
	rc.EnableFullDuplex()
	w.Header().Set("Connection", "close")
	rc.SetReadDeadline(time.Time{})
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, screenChunk)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.seen = time.Now()
				s.mu.Unlock()
				s.conn.SetWriteDeadline(time.Now().Add(screenWriteWait))
				if _, werr := s.conn.Write(buf[:n]); werr != nil {
					result <- werr
					return
				}
			}
			if rerr != nil {
				if rerr == io.EOF {
					rerr = nil
				}
				result <- rerr
				return
			}
		}
	}()
	select {
	case err := <-result:
		if err != nil {
			s.mu.Lock()
			ended := s.ended
			s.mu.Unlock()
			if ended {
				h.refuse(w, http.StatusGone, "no-session")
				return
			}
			h.refuse(w, http.StatusBadRequest, "stream-broken")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	case <-s.done:
		// The reader is parked in a body read; make it return.
		rc.SetReadDeadline(time.Now())
		h.refuse(w, http.StatusGone, "no-session")
	}
}

// screenBeat is POST /v1/screen/beat?s=…: the page saying it is still there.
func (h *directHandler) screenBeat(w http.ResponseWriter, r *http.Request) {
	if h.screens.find(r) == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// screenClose is POST /v1/screen/close?s=…: the page ending its session.
func (h *directHandler) screenClose(w http.ResponseWriter, r *http.Request) {
	if s := h.screens.find(r); s != nil {
		h.screens.end(s)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
