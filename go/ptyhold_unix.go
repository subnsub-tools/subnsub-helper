//go:build linux || darwin || freebsd

package main

// The terminal's shells live outside this process (user 2026-11-07: a
// terminal opened on the panel must stay alive when the browser closes).
//
// WHY A PROCESS OF ITS OWN. A shell on a pseudo-terminal lives as long as
// somebody holds the terminal's master end. Held by the helper, it died with
// the helper: an update's exec, a crash, a service restart all closed the
// master, and the kernel hung up on everything the shell had started — an
// agent half way through its work included. So each session's master is held
// by a small process of its own, the HOLDER: this same binary run as
// `pty-hold`, in a session of its own (setsid), and where a systemd user
// manager runs the helper, in a scope of its own, so stopping the service
// does not take it. The helper speaks to it over a Unix socket in its config
// directory (mode 0700, socket 0600), and finds every holder still running
// there when it starts again (ptyHub.adopt).
//
// WHAT IT KEEPS. The shell, the last ptyRing bytes of its output (what a page
// that attaches again is replayed), the terminal's size, and the clock that
// ends it: a session ends when nobody has shown a sign of life on it for its
// keep — the account's allowance, which the relay says on every push and the
// helper passes on — and never later than the ceiling the opening command
// carried, signed by the browser that opened it. The holder enforces both on
// its own, so a helper that never comes back cannot leave a shell running for
// ever: the longest any session outlives its last page is ptyKeepMax.
//
// WHAT ENDS IT, besides the shell exiting and the clock: the helper asking
// (a page closed the tab, the console was switched off, the key that opened
// it was unpinned), SIGTERM, and its socket file going — `--uninstall`
// removes the config directory, and with it every holder's way in.
//
// THE PROTOCOL, one connection per request: a JSON line ({"op": …}), then
//   info    → one JSON line (ptyHoldInfo), and the connection closes
//   out     → the output, from the oldest byte still held, then as it comes,
//             until the shell ends (EOF)
//   in      → raw bytes after the line, written to the terminal, until EOF
//   resize, beat, keep, nudge, end → one JSON line ({"ok": true})
//   wait    → one JSON line once the session has ended
// Nothing here is reachable except by the user the helper runs as, who could
// already do anything the shell can.

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ptyHoldVersion = 1
	// A request's first line; anything longer is not this protocol.
	ptyHoldLine = 1 << 10
	// How long the helper waits for a holder it started to answer.
	ptyHoldUp = 5 * time.Second
	// How often a holder looks at its clock and its socket.
	ptyHoldTick = 10 * time.Second
)

// ptyHoldDir is where the holders' sockets are: the helper's config
// directory, so --uninstall takes them with everything else.
func ptyHoldDir() string {
	d := configDir()
	if d == "" {
		return ""
	}
	return filepath.Join(d, "pty")
}

// ptyHolder is one session's holder. run serves it until the session ends;
// the `pty-hold` verb calls it in a process of its own, and the tests in the
// test's own process.
type ptyHolder struct {
	id     string
	sock   string
	signer string
	at     time.Time
	ceil   time.Duration

	tty  *os.File
	kill func()
	wait func()
	ln   *net.UnixListener
	fi   os.FileInfo

	mu     sync.Mutex
	ring   []byte
	total  int64
	notify chan struct{}
	ended  bool
	seen   time.Time
	keep   time.Duration
	cols   int
	rows   int
	conns  map[net.Conn]struct{}
	// The connections reading the output, left to finish what the ring
	// still holds when the session ends (review: a last line printed
	// before `exit` must reach the page).
	outs map[net.Conn]bool
	// Closed once the session has ended, and done once its shell is reaped.
	over chan struct{}
	done chan struct{}
}

func newPtyHolder(dir, id string, cols, rows int, keep, ceil time.Duration, signer string) *ptyHolder {
	now := time.Now()
	return &ptyHolder{
		id: id, sock: ptyHoldSock(dir, id), signer: signer, at: now, ceil: clampKeep(ceil),
		notify: make(chan struct{}), seen: now, keep: clampKeep(keep), cols: cols, rows: rows,
		conns: map[net.Conn]struct{}{}, outs: map[net.Conn]bool{}, over: make(chan struct{}), done: make(chan struct{}),
	}
}

// start opens the socket and the shell. The socket first: a holder that
// cannot be reached must not leave a shell behind.
func (h *ptyHolder) start() error {
	dir := filepath.Dir(h.sock)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	os.Chmod(dir, 0o700)
	os.Remove(h.sock)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.sock, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	os.Chmod(h.sock, 0o600)
	fi, err := os.Lstat(h.sock)
	if err != nil {
		ln.Close()
		return err
	}
	tty, kill, wait, err := ptyStart(h.cols, h.rows)
	if err != nil {
		ln.Close()
		os.Remove(h.sock)
		return err
	}
	h.ln, h.fi, h.tty, h.kill, h.wait = ln, fi, tty, kill, wait
	return nil
}

// run serves the session until it ends, and cleans up after it.
func (h *ptyHolder) run() {
	go h.pump()
	go h.watch()
	for {
		c, err := h.ln.Accept()
		if err != nil {
			break
		}
		h.mu.Lock()
		if h.ended {
			h.mu.Unlock()
			c.Close()
			continue
		}
		h.conns[c] = struct{}{}
		h.mu.Unlock()
		go h.serve(c)
	}
	<-h.done
}

func (h *ptyHolder) untilLocked() time.Time {
	k := h.keep
	if h.ceil < k {
		k = h.ceil
	}
	return h.seen.Add(k)
}

// end is the session's end, whatever brought it: the shell is hung up on,
// the socket goes, and every connection is closed. Safe to call twice.
func (h *ptyHolder) end() {
	h.mu.Lock()
	if h.ended {
		h.mu.Unlock()
		return
	}
	h.ended = true
	close(h.notify)
	close(h.over)
	conns := make([]net.Conn, 0, len(h.conns))
	for c := range h.conns {
		if !h.outs[c] {
			conns = append(conns, c)
		}
	}
	h.mu.Unlock()
	// Only our own socket: a file that is no longer the one this holder
	// made (a holder of the same id after a restart, however unlikely) is
	// left alone.
	if fi, err := os.Lstat(h.sock); err == nil && os.SameFile(fi, h.fi) {
		os.Remove(h.sock)
	}
	h.ln.Close()
	h.kill()
	for _, c := range conns {
		c.Close()
	}
	// The shell and what it started reaped (wait lasts until the last
	// signal has gone out); by then a reader has had its time to take the
	// rest of the output, and one still at it is closed.
	go func() {
		h.wait()
		h.mu.Lock()
		rest := make([]net.Conn, 0, len(h.conns))
		for c := range h.conns {
			rest = append(rest, c)
		}
		h.mu.Unlock()
		for _, c := range rest {
			c.Close()
		}
		close(h.done)
	}()
}

func (h *ptyHolder) pump() {
	buf := make([]byte, ptyChunk)
	for {
		n, err := h.tty.Read(buf)
		if n > 0 {
			h.mu.Lock()
			h.ring = append(h.ring, buf[:n]...)
			if over := len(h.ring) - ptyRing; over > 0 {
				h.ring = append(h.ring[:0], h.ring[over:]...)
			}
			h.total += int64(n)
			if !h.ended {
				close(h.notify)
				h.notify = make(chan struct{})
			}
			h.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	h.end()
}

// watch ends the session once its clock has run out, or once its socket
// is gone (the config directory removed: the helper uninstalled).
func (h *ptyHolder) watch() {
	t := time.NewTicker(ptyHoldTick)
	defer t.Stop()
	for {
		select {
		case <-h.done:
			return
		case now := <-t.C:
			if h.check(now) {
				return
			}
		}
	}
}

// check is one look: ends the session, and answers true, where it is over.
func (h *ptyHolder) check(now time.Time) bool {
	h.mu.Lock()
	over := now.After(h.untilLocked())
	ended := h.ended
	h.mu.Unlock()
	if ended {
		return true
	}
	fi, err := os.Lstat(h.sock)
	if over || err != nil || !os.SameFile(fi, h.fi) {
		h.end()
		return true
	}
	return false
}

func (h *ptyHolder) lifeSign() {
	h.mu.Lock()
	h.seen = time.Now()
	h.mu.Unlock()
}

func (h *ptyHolder) info() ptyHoldInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	in := ptyHoldInfo{
		V: ptyHoldVersion, ID: h.id, At: h.at.Unix(), Seen: h.seen.Unix(), Until: h.untilLocked().Unix(),
		Keep: int64(h.keep / time.Second), Ceil: int64(h.ceil / time.Second), Signer: h.signer,
		Cols: h.cols, Rows: h.rows, Total: h.total, Ended: h.ended,
	}
	if !h.ended {
		in.Prog = ptyProgName(ptyForeground(h.tty))
	}
	return in
}

func (h *ptyHolder) forget(c net.Conn) {
	h.mu.Lock()
	delete(h.conns, c)
	delete(h.outs, c)
	h.mu.Unlock()
	c.Close()
}

func (h *ptyHolder) serve(c net.Conn) {
	defer h.forget(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(c, ptyHoldLine)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return
	}
	var q ptyHoldReq
	if json.Unmarshal(line, &q) != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	ok := func() {
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("{\"ok\":true}\n"))
	}
	switch q.Op {
	case "info":
		b, _ := json.Marshal(h.info())
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		c.Write(append(b, '\n'))
	case "out":
		h.mu.Lock()
		h.outs[c] = true
		h.mu.Unlock()
		h.serveOut(c, br)
	case "in":
		h.serveIn(br)
	case "resize":
		if q.Cols < 2 || q.Rows < 2 || q.Cols > ptyMaxCols || q.Rows > ptyMaxRows {
			return
		}
		h.mu.Lock()
		h.cols, h.rows = q.Cols, q.Rows
		h.seen = time.Now()
		h.mu.Unlock()
		ptyResizeTTY(h.tty, q.Cols, q.Rows)
		ok()
	case "beat":
		h.lifeSign()
		ok()
	case "keep":
		h.mu.Lock()
		h.keep = clampKeep(time.Duration(q.Keep) * time.Second)
		h.mu.Unlock()
		ok()
	case "nudge":
		h.nudge()
		ok()
	case "end":
		ok()
		h.end()
	case "wait":
		gone := make(chan struct{})
		go func() {
			io.Copy(io.Discard, br)
			close(gone)
		}()
		select {
		case <-h.over:
		case <-gone:
			return
		}
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("{\"ended\":true}\n"))
	}
}

// nudge makes a full-screen program draw itself again, for a page that has
// just attached and holds only the bytes the ring kept: a size one row short
// for a moment, then the size it had. A shell at its prompt is left alone —
// it would print the prompt a second time.
func (h *ptyHolder) nudge() {
	h.mu.Lock()
	cols, rows, ended := h.cols, h.rows, h.ended
	h.mu.Unlock()
	if ended || rows < 3 || ptyIsShell(ptyProgName(ptyForeground(h.tty))) {
		return
	}
	ptyResizeTTY(h.tty, cols, rows-1)
	time.Sleep(60 * time.Millisecond)
	h.mu.Lock()
	cols, rows = h.cols, h.rows
	h.mu.Unlock()
	ptyResizeTTY(h.tty, cols, rows)
}

func (h *ptyHolder) serveOut(c net.Conn, br *bufio.Reader) {
	gone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, br)
		close(gone)
	}()
	var pos int64
	for {
		h.mu.Lock()
		start := h.total - int64(len(h.ring))
		if pos < start {
			pos = start
		}
		chunk := append([]byte(nil), h.ring[pos-start:]...)
		pos = h.total
		ended := h.ended
		wake := h.notify
		h.mu.Unlock()
		if len(chunk) > 0 {
			c.SetWriteDeadline(time.Now().Add(ptyWriteWait))
			if _, err := c.Write(chunk); err != nil {
				return
			}
			continue
		}
		if ended {
			return
		}
		select {
		case <-wake:
		case <-gone:
			return
		}
	}
}

func (h *ptyHolder) serveIn(br *bufio.Reader) {
	buf := make([]byte, 8<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			h.lifeSign()
			if _, werr := h.tty.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ptyIsShell: whether a program in a terminal's foreground is the shell
// itself, at its prompt.
func ptyIsShell(name string) bool {
	switch strings.TrimPrefix(name, "-") {
	case "", "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh", "ash", "busybox", "nu", "elvish", "xonsh":
		return true
	}
	return false
}

/* ── the `pty-hold` verb ─────────────────────────────────────────────── */

// runPtyHold is `subnsub-helper pty-hold`, which nobody types: the helper
// runs it to start a session's holder. Stage 1 is the helper's child and
// only starts stage 2 — in a scope of its own where systemd runs the helper,
// in a session of its own everywhere — waits for it to answer, and exits, so
// the holder is nobody's child and the helper has nothing to reap.
func runPtyHold(args []string) int {
	fs := flag.NewFlagSet("pty-hold", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stage := fs.Int("stage", 1, "")
	dir := fs.String("dir", "", "")
	id := fs.String("id", "", "")
	size := fs.String("size", "", "")
	keep := fs.Int64("keep", 0, "")
	ceil := fs.Int64("ceil", 0, "")
	signer := fs.String("signer", "", "")
	if fs.Parse(args) != nil || !ptyIDRe.MatchString(*id) || *dir == "" || !filepath.IsAbs(*dir) {
		return 2
	}
	cols, rows, _, ok := ptyTarget(*size)
	if !ok {
		return 2
	}
	if *signer != "" {
		if b, err := base64.StdEncoding.DecodeString(*signer); err != nil || len(b) != ed25519.PublicKeySize {
			return 2
		}
	}
	if *stage != 2 {
		return ptyHoldLaunch(*dir, *id, args)
	}
	// A holder is small and lives long: keep its heap that way.
	debug.SetGCPercent(25)
	debug.SetMemoryLimit(32 << 20)
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	h := newPtyHolder(*dir, *id, cols, rows, time.Duration(*keep)*time.Second, time.Duration(*ceil)*time.Second, *signer)
	if err := h.start(); err != nil {
		return 1
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-term
		h.end()
	}()
	h.run()
	return 0
}

// ptyHoldLaunch is stage 1.
func ptyHoldLaunch(dir, id string, args []string) int {
	exe := ptyHoldExe()
	if exe == "" {
		return 1
	}
	two := append([]string{"pty-hold"}, args...)
	two = append(two, "-stage", "2")
	var tries [][]string
	if sd := ptySystemdRun(id); sd != nil {
		tries = append(tries, append(append(sd, exe), two...))
	}
	tries = append(tries, append([]string{exe}, two...))
	sock := ptyHoldSock(dir, id)
	for _, argv := range tries {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = os.Environ()
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			continue
		}
		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()
		if ptyHoldAwait(sock, exited) {
			cmd.Process.Release()
			return 0
		}
		select {
		case <-exited:
		default:
			cmd.Process.Kill()
			<-exited
		}
	}
	return 1
}

// ptyHoldAwait: whether the holder at sock answers before it exits or
// ptyHoldUp passes.
func ptyHoldAwait(sock string, exited <-chan struct{}) bool {
	deadline := time.Now().Add(ptyHoldUp)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("unix", sock, 500*time.Millisecond); err == nil {
			c.Close()
			return true
		}
		select {
		case <-exited:
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

// ptySystemdRun is the command line that puts the holder in a scope of its
// own, where systemd runs this helper: without it, stopping or restarting
// the service would take every holder in its control group. Nil elsewhere.
func ptySystemdRun(id string) []string {
	if os.Getenv("INVOCATION_ID") == "" {
		return nil
	}
	bin, err := exec.LookPath("systemd-run")
	if err != nil {
		return nil
	}
	argv := []string{bin}
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil && strings.Contains(string(b), "/user@") {
		argv = append(argv, "--user")
	} else if os.Getuid() != 0 {
		return nil
	}
	return append(argv, "--scope", "--quiet", "--collect", "--unit=subnsub-pty-"+id, "--")
}

// ptyHoldExe is the binary to run as a holder: this one, by the path it was
// installed at — after an update's rename, /proc/self/exe names a file that
// is gone (restart.go).
func ptyHoldExe() string {
	if p := installedAt(); p != "" {
		return p
	}
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(p, " (deleted)")
}

// ptyHoldSpawn starts a session's holder and waits until it answers.
func ptyHoldSpawn(dir, id string, cols, rows int, keep, ceil time.Duration, signer ed25519.PublicKey) error {
	exe := ptyHoldExe()
	if exe == "" {
		return errors.New("no binary to run")
	}
	sg := ""
	if len(signer) == ed25519.PublicKeySize {
		sg = base64.StdEncoding.EncodeToString(signer)
	}
	cmd := exec.Command(exe, "pty-hold", "-dir", dir, "-id", id, "-size", fmt.Sprintf("%dx%d", cols, rows),
		"-keep", strconv.FormatInt(int64(keep/time.Second), 10), "-ceil", strconv.FormatInt(int64(ceil/time.Second), 10),
		"-signer", sg)
	cmd.Env = os.Environ()
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(3 * ptyHoldUp):
		cmd.Process.Kill()
		<-done
		return errors.New("the holder did not come up")
	}
}
