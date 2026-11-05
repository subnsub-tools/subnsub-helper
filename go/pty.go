package main

// Terminal — a real one, carried by the direct tunnel.
//
// WHAT IT IS. The console (console.go) runs one `sh -c` per line: no
// terminal, no input, thirty seconds, sixteen kilobytes. Nothing interactive
// survives that — not `cd`, not an editor, not an agent's own interface. This
// is the other thing: one login shell on a pseudo-terminal, kept for as long
// as the page that opened it is there, its bytes streamed both ways.
//
// WHO MAY OPEN ONE. Exactly who may run a console line through the tunnel,
// and by the same three gates: the peer's key is on the allowlist (the
// tunnel's own gate), the console switch is on at the machine, and the
// opening is a `pty` command SIGNED by a dashboard key this machine has
// pinned (verifyCommand, in direct.go's command) — an unpinned machine has no
// terminal, as it has no tunnel console. The relay's mailbox never carries
// this kind: runCommand does not know it, so it is refused there as any
// unknown kind is.
//
// WHAT THE SIGNATURE BUYS. The signed command answers with a session token:
// 128 random bits, good only on the tunnel of the peer that opened it. The
// streams that follow (out, in, resize, close) carry the token and are not
// signed one by one — a keystroke is not a command — so the token is the
// capability and the tunnel is its channel: WireGuard between this machine
// and one allowlisted key.
//
// BOUNDS. Six sessions at once. A session nobody has shown a sign of life on
// (bytes typed, or the page's own heartbeat on /v1/pty/resize) for
// ptyQuietMax is ended — a tab that closed, a tunnel that never came back —
// and so is every session the moment the console is switched off, the last
// key is unpinned, or the opener's key leaves the allowlist (sweep). The
// last ptyRing bytes of output are kept so a page whose tunnel was rebuilt
// under it can attach again and see where it was.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	// Several per machine, as an editor keeps several tabs (user 2026-10-06).
	ptyMaxSessions = 6
	// Output kept for a page that attaches again.
	ptyRing = 256 << 10
	// The longest a session lives with no sign of life from its page. The
	// page beats every ptyBeat-ish seconds while it holds one (monitor.js).
	ptyQuietMax = 3 * time.Minute
	// One write to the browser; a reader this slow is gone.
	ptyWriteWait = 30 * time.Second
	// How often the rules above are re-read while a session exists: the
	// longest a shell outlives `console off`.
	ptySweepEvery = 5 * time.Second
	ptyChunk      = 32 << 10
	// The window a shell may be given. Bounded so a number from the wire is
	// never an allocation in somebody's curses library.
	ptyMaxCols = 500
	ptyMaxRows = 200
)

var ptyTokenRe = regexp.MustCompile(`^[a-f0-9]{32}$`)
var ptySizeRe = regexp.MustCompile(`^([0-9]{1,3})x([0-9]{1,3})$`)

type ptySess struct {
	token string
	peer  key.NodePublic
	// The pinned key that signed the opening. The session is that key's:
	// unpinning it ends the session, whatever else is still pinned.
	signer ed25519.PublicKey
	tty    *os.File
	kill   func()

	mu sync.Mutex
	// The output so far: the last ptyRing bytes of it, and how many bytes
	// there have been in all — a reader's place is a count, so it can tell
	// what it missed from what has not happened yet.
	ring   []byte
	total  int64
	notify chan struct{} // closed and replaced on every write, and at the end
	ended  bool
	seen   time.Time
	// One input stream at a time: a second is a second keyboard.
	typing bool
}

type ptyHub struct {
	mu   sync.Mutex
	sess map[string]*ptySess
	// Whether a tunnel key is still on the allowlist, and whether a signing
	// key is still pinned; nil admits (a test).
	allowed func(key.NodePublic) bool
	trusted func(ed25519.PublicKey) bool
	// The sweeper runs only while there is a session to sweep, and on its
	// own clock rather than the carrier's: a tunnel that never comes back is
	// exactly when a session must still be ended.
	sweeping bool
}

func newPtyHub() *ptyHub { return &ptyHub{sess: map[string]*ptySess{}} }

// The process's sessions. One table whatever becomes of the tunnel's carrier
// (direct.go makes a handler per carrier), so the ceiling counts every shell
// there is and a token still names its session after a rebuild.
var ptySessions = func() *ptyHub {
	hub := newPtyHub()
	hub.allowed = func(k key.NodePublic) bool {
		for _, a := range loadAllowedClients() {
			if a == k {
				return true
			}
		}
		// A portable copy's session lasts while the copy does (clone.go).
		_, ok := cloneForNode(k, agentID(), time.Now())
		return ok
	}
	hub.trusted = func(k ed25519.PublicKey) bool { return trustsKey(k) || cloneSignerActive(k) }
	return hub
}()

func ptySize(target string) (cols, rows int, ok bool) {
	m := ptySizeRe.FindStringSubmatch(target)
	if m == nil {
		return 0, 0, false
	}
	cols, _ = strconv.Atoi(m[1])
	rows, _ = strconv.Atoi(m[2])
	if cols < 2 || rows < 2 || cols > ptyMaxCols || rows > ptyMaxRows {
		return 0, 0, false
	}
	return cols, rows, true
}

// open starts a shell for peer, sized by the command's target ("COLSxROWS").
// The caller has verified the command's signature and that a key is pinned.
// Returns the token, or a refusal code.
func (hub *ptyHub) open(peer key.NodePublic, signer ed25519.PublicKey, target string) (string, string) {
	if !consoleEnabled() {
		return "", "console-off"
	}
	if !ptySupported {
		return "", "pty-unsupported"
	}
	cols, rows, ok := ptySize(target)
	if !ok {
		return "", "bad-target"
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.sess) >= ptyMaxSessions {
		return "", "busy"
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "unavailable"
	}
	tty, kill, wait, err := ptyStart(cols, rows)
	if err != nil {
		warnf("terminal: could not start a shell: %v", err)
		return "", "pty-failed"
	}
	s := &ptySess{
		token: hex.EncodeToString(raw[:]), peer: peer, signer: signer, tty: tty, kill: kill,
		notify: make(chan struct{}), seen: time.Now(),
	}
	hub.sess[s.token] = s
	warnf("terminal: session opened (%d of %d)", len(hub.sess), ptyMaxSessions)
	go hub.pump(s, wait)
	if !hub.sweeping {
		hub.sweeping = true
		go hub.watch()
	}
	return s.token, ""
}

// watch sweeps every ptySweepEvery until no session is left.
func (hub *ptyHub) watch() {
	t := time.NewTicker(ptySweepEvery)
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

// pump copies the shell's output into the ring until the shell is gone.
func (hub *ptyHub) pump(s *ptySess, wait func()) {
	buf := make([]byte, ptyChunk)
	for {
		n, err := s.tty.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.ring = append(s.ring, buf[:n]...)
			if over := len(s.ring) - ptyRing; over > 0 {
				s.ring = append(s.ring[:0], s.ring[over:]...)
			}
			s.total += int64(n)
			// An ended session's channel is closed for good (end).
			if !s.ended {
				close(s.notify)
				s.notify = make(chan struct{})
			}
			s.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	hub.end(s)
	wait()
}

// end closes a session: the shell and everything it started are hung up on,
// and every reader is woken to find it over. Safe to call twice.
func (hub *ptyHub) end(s *ptySess) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	close(s.notify)
	s.mu.Unlock()
	s.kill()
	hub.mu.Lock()
	delete(hub.sess, s.token)
	n := len(hub.sess)
	hub.mu.Unlock()
	warnf("terminal: session ended (%d left)", n)
}

func (hub *ptyHub) endAll() {
	hub.mu.Lock()
	all := make([]*ptySess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	hub.mu.Unlock()
	for _, s := range all {
		hub.end(s)
	}
}

// sweep ends what may no longer run: every session once the console is off,
// one whose opener's tunnel key left the allowlist or whose signing key was
// unpinned, one whose page has gone quiet.
func (hub *ptyHub) sweep(t time.Time) {
	hub.mu.Lock()
	allowed, trusted := hub.allowed, hub.trusted
	all := make([]*ptySess, 0, len(hub.sess))
	for _, s := range hub.sess {
		all = append(all, s)
	}
	hub.mu.Unlock()
	if len(all) == 0 {
		return
	}
	open := consoleEnabled()
	for _, s := range all {
		s.mu.Lock()
		quiet := t.Sub(s.seen) > ptyQuietMax
		s.mu.Unlock()
		if !open || quiet || (allowed != nil && !allowed(s.peer)) || (trusted != nil && !trusted(s.signer)) {
			hub.end(s)
		}
	}
}

// find is the session a request names, for the peer that opened it and no
// other; a sign of life either way.
func (hub *ptyHub) find(r *http.Request) *ptySess {
	peer, ok := transport.PeerFromContext(r.Context())
	if !ok {
		return nil
	}
	tok := r.URL.Query().Get("s")
	if !ptyTokenRe.MatchString(tok) {
		return nil
	}
	hub.mu.Lock()
	s := hub.sess[tok]
	hub.mu.Unlock()
	if s == nil || s.peer != peer {
		return nil
	}
	s.mu.Lock()
	s.seen = time.Now()
	s.mu.Unlock()
	return s
}

// ptyOut is GET /v1/pty/out?s=…: the shell's output, from the oldest byte
// still held, then as it comes, until the session ends (a clean EOF).
func (h *directHandler) ptyOut(w http.ResponseWriter, r *http.Request) {
	s := h.ptys.find(r)
	if s == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()
	var pos int64 = -1
	for {
		s.mu.Lock()
		start := s.total - int64(len(s.ring))
		if pos < start {
			pos = start
		}
		chunk := append([]byte(nil), s.ring[pos-start:]...)
		pos = s.total
		ended := s.ended
		wake := s.notify
		s.mu.Unlock()
		if len(chunk) > 0 {
			rc.SetWriteDeadline(time.Now().Add(ptyWriteWait))
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			continue
		}
		if ended {
			return
		}
		select {
		case <-wake:
		case <-r.Context().Done():
			return
		}
	}
}

// ptyIn is POST /v1/pty/in?s=…: what is typed, for as long as the body stays
// open. Ends with the body, or with the session.
func (h *directHandler) ptyIn(w http.ResponseWriter, r *http.Request) {
	s := h.ptys.find(r)
	if s == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	s.mu.Lock()
	if s.typing {
		s.mu.Unlock()
		h.refuse(w, http.StatusConflict, "busy")
		return
	}
	s.typing = true
	done := s.notify
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.typing = false
		s.mu.Unlock()
	}()
	rc := http.NewResponseController(w)
	// Full duplex, and no keep-alive: the answer must be able to go out
	// under a body the browser has not ended, where the server would first
	// try to read the rest of that body and hold the answer until then.
	rc.EnableFullDuplex()
	w.Header().Set("Connection", "close")
	// The tunnel's server gives a request ten seconds to be read; a keyboard
	// is silent for longer than that. No deadline here: what ends a stream
	// nobody is behind is the session's own quiet limit (sweep), which wakes
	// the read below.
	rc.SetReadDeadline(time.Time{})
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 8<<10)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.seen = time.Now()
				s.mu.Unlock()
				if _, werr := s.tty.Write(buf[:n]); werr != nil {
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
	// The session ending is one of the things that end this request; the
	// notify channel is closed on every write too, so look again each time.
	for {
		select {
		case err := <-result:
			// A body that ended is the page letting go; one that broke is
			// not the shell ending, and must not read as that — the page
			// attaches again on anything but "no session".
			if err != nil {
				h.refuse(w, http.StatusBadRequest, "stream-broken")
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		case <-done:
			s.mu.Lock()
			ended := s.ended
			done = s.notify
			s.mu.Unlock()
			if ended {
				// The reader is parked in a body read; make it return.
				rc.SetReadDeadline(time.Now())
				h.refuse(w, http.StatusGone, "no-session")
				return
			}
		}
	}
}

// ptyResize is POST /v1/pty/resize?s=…&c=…&r=…: the window's new size — and,
// sent with the size it already has, the page's heartbeat.
func (h *directHandler) ptyResize(w http.ResponseWriter, r *http.Request) {
	s := h.ptys.find(r)
	if s == nil {
		h.refuse(w, http.StatusNotFound, "no-session")
		return
	}
	q := r.URL.Query()
	cols, rows, ok := ptySize(q.Get("c") + "x" + q.Get("r"))
	if !ok {
		h.refuse(w, http.StatusBadRequest, "bad-frame")
		return
	}
	ptyResizeTTY(s.tty, cols, rows)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// ptyClose is POST /v1/pty/close?s=…: the page ending its session.
func (h *directHandler) ptyClose(w http.ResponseWriter, r *http.Request) {
	if s := h.ptys.find(r); s != nil {
		h.ptys.end(s)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
