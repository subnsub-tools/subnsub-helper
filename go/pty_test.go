//go:build linux || darwin || freebsd

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// The process's own table starts its holders in this process too: the
// test binary is not a helper that knows `pty-hold`.
func init() {
	ptySessions.spawn = testPtySpawn
	// The tests' shells keep no history: hung up on, bash writes it to the
	// test's HOME, a temporary directory the test is removing by then.
	os.Setenv("HISTFILE", "")
}

// testPtyHub is a table whose holders run in the test's own process, in a
// directory short enough for a socket's path.
func testPtyHub(t *testing.T) *ptyHub {
	t.Helper()
	dir, err := os.MkdirTemp("", "pty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	hub := newPtyHub()
	hub.dir = dir
	hub.spawn = testPtySpawn
	t.Cleanup(hub.endAll)
	return hub
}

func testPtySpawn(dir, id string, cols, rows int, keep, ceil time.Duration, signer ed25519.PublicKey) error {
	sg := ""
	if signer != nil {
		sg = base64.StdEncoding.EncodeToString(signer)
	}
	h := newPtyHolder(dir, id, cols, rows, keep, ceil, sg)
	if err := h.start(); err != nil {
		return err
	}
	go h.run()
	return nil
}

// testPtyOut follows a session's output at its holder.
type testPtyOut struct {
	c    net.Conn
	got  chan string
	seen string
}

func testPtyRead(t *testing.T, sock string) *testPtyOut {
	t.Helper()
	c, err := ptyStream(sock, "out")
	if err != nil {
		t.Fatalf("out: %v", err)
	}
	o := &testPtyOut{c: c, got: make(chan string, 256)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				o.got <- string(buf[:n])
			}
			if err != nil {
				close(o.got)
				return
			}
		}
	}()
	t.Cleanup(func() { c.Close() })
	return o
}

func (o *testPtyOut) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !strings.Contains(o.seen, want) {
		select {
		case s, ok := <-o.got:
			if !ok {
				t.Fatalf("output ended before %q: %q", want, o.seen)
			}
			o.seen += s
		case <-deadline:
			t.Fatalf("no %q in the output: %q", want, o.seen)
		}
	}
}

func (o *testPtyOut) waitEnd(t *testing.T) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-o.got:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the output did not end")
		}
	}
}

func testPtyType(t *testing.T, sock, text string) {
	t.Helper()
	c, err := ptyStream(sock, "in")
	if err != nil {
		t.Fatalf("in: %v", err)
	}
	c.Write([]byte(text))
	// Each line on a connection of its own: the holder has written it to
	// the terminal when it hangs up, so the next one cannot overtake it.
	if u, ok := c.(*net.UnixConn); ok {
		u.CloseWrite()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		io.Copy(io.Discard, c)
	}
	c.Close()
}

func (hub *ptyHub) testSess(id string) *ptySess {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	return hub.sess[id]
}

func (hub *ptyHub) testCount() int {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	return len(hub.sess)
}

// A session is a shell that keeps its state between lines — the thing the
// console is not — sized as asked, and gone when ended.
func TestPtySessionKeepsAShell(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	hub := testPtyHub(t)
	peer := key.NewNode().Public()
	tok, sid, why := hub.open(peer, nil, "100x30")
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	if !ptyTokenRe.MatchString(tok) || !ptyIDRe.MatchString(sid) || tok[:16] == sid {
		t.Fatalf("token %q, id %q", tok, sid)
	}
	s := hub.testSess(sid)
	if s == nil {
		t.Fatal("no session behind the id")
	}
	out := testPtyRead(t, s.sock)
	testPtyType(t, s.sock, "MON_PTY_T=kept\n")
	testPtyType(t, s.sock, "echo got-$MON_PTY_T-$(stty size | tr ' ' x)\n")
	out.waitFor(t, "got-kept-30x100")
	if err := ptyAsk(s.sock, ptyHoldReq{Op: "resize", Cols: 90, Rows: 20}, nil); err != nil {
		t.Fatal(err)
	}
	testPtyType(t, s.sock, "echo now-$(stty size | tr ' ' x)\n")
	out.waitFor(t, "now-20x90")
	hub.end(s)
	out.waitEnd(t)
	if n := hub.testCount(); n != 0 {
		t.Errorf("an ended session must leave the table: %d", n)
	}
	hub.end(s) // twice is once
	if _, err := os.Lstat(s.sock); err == nil {
		t.Error("an ended session's socket must go")
	}
}

func TestPtyTarget(t *testing.T) {
	for _, c := range []struct {
		in         string
		cols, rows int
		ceil       time.Duration
		ok         bool
	}{
		{"80x24", 80, 24, ptyKeepMax, true},
		{"80x24/3600", 80, 24, time.Hour, true},
		{"500x200/604800", 500, 200, 7 * 24 * time.Hour, true},
		{"80x24/", 0, 0, 0, false},
		{"80x24/-1", 0, 0, 0, false},
		{"80x24/12345678", 0, 0, 0, false},
		{"80x24 3600", 0, 0, 0, false},
	} {
		cols, rows, ceil, ok := ptyTarget(c.in)
		if ok != c.ok || cols != c.cols || rows != c.rows || (ok && ceil != c.ceil) {
			t.Errorf("%q: %d %d %v %v", c.in, cols, rows, ceil, ok)
		}
	}
	if clampKeep(time.Second) != ptyQuietMax || clampKeep(30*24*time.Hour) != ptyKeepMax || clampKeep(time.Hour) != time.Hour {
		t.Error("the keep must stay between the quiet limit and a week")
	}
}

func TestPtyOpenGates(t *testing.T) {
	peer := key.NewNode().Public()
	t.Setenv(consoleEnvVar, "0")
	if _, _, why := testPtyHub(t).open(peer, nil, "80x24"); why != "console-off" {
		t.Errorf("console off must refuse: %q", why)
	}
	if _, _, why := testPtyHub(t).attach(peer, "0123456789abcdef", nil, nil); why != "console-off" {
		t.Errorf("console off must refuse an attach: %q", why)
	}
	t.Setenv(consoleEnvVar, "1")
	for _, bad := range []string{"", "80", "80x", "1x1", "9999x24", "80x24x1", "axb"} {
		if _, _, why := testPtyHub(t).open(peer, nil, bad); why != "bad-target" {
			t.Errorf("size %q must be refused: %q", bad, why)
		}
	}
	hub := testPtyHub(t)
	for i := 0; i < ptyMaxSessions; i++ {
		if _, _, why := hub.open(peer, nil, "80x24"); why != "" {
			t.Fatalf("session %d refused: %s", i, why)
		}
	}
	if _, _, why := hub.open(peer, nil, "80x24"); why != "busy" {
		t.Errorf("past the ceiling must be busy: %q", why)
	}
	for _, bad := range []string{"", "nope", "0123456789ABCDEF", "0123456789abcdef0"} {
		if _, _, why := hub.attach(peer, bad, nil, nil); why != "bad-target" {
			t.Errorf("attach to %q: %q", bad, why)
		}
	}
	if _, _, why := hub.attach(peer, "0123456789abcdef", nil, nil); why != "no-session" {
		t.Errorf("attach to nothing: %q", why)
	}
}

// The holder's own clock: a session nobody has shown a sign of life on for
// its keep (never past the signed ceiling) ends, and so does one whose
// socket was taken away.
func TestPtyHolderClock(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	dir, _ := os.MkdirTemp("", "pty")
	defer os.RemoveAll(dir)
	h := newPtyHolder(dir, "00000000000000a1", 80, 24, time.Hour, 2*time.Hour, "")
	if err := h.start(); err != nil {
		t.Fatal(err)
	}
	go h.run()
	defer h.end()
	in := h.info()
	if in.Keep != 3600 || in.Ceil != 7200 || in.Until-in.Seen != 3600 {
		t.Fatalf("keep %d ceil %d until-seen %d", in.Keep, in.Ceil, in.Until-in.Seen)
	}
	// The relay raises the keep: the ceiling still holds.
	if err := ptyAsk(h.sock, ptyHoldReq{Op: "keep", Keep: 7 * 24 * 3600}, nil); err != nil {
		t.Fatal(err)
	}
	if in := h.info(); in.Until-in.Seen != 7200 {
		t.Errorf("past the ceiling: %d", in.Until-in.Seen)
	}
	if h.check(time.Now().Add(time.Hour)) {
		t.Fatal("within its keep a session must run")
	}
	if !h.check(time.Now().Add(2*time.Hour + time.Minute)) {
		t.Fatal("past its keep a session must end")
	}
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the shell was not reaped")
	}

	h2 := newPtyHolder(dir, "00000000000000a2", 80, 24, time.Hour, time.Hour, "")
	if err := h2.start(); err != nil {
		t.Fatal(err)
	}
	go h2.run()
	defer h2.end()
	os.Remove(h2.sock)
	if !h2.check(time.Now()) {
		t.Fatal("a holder whose socket is gone must end")
	}
}

// A helper that restarts finds the sessions still running, and a page
// comes back to one by its id: the output it missed is replayed.
func TestPtyOutlivesTheHelper(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	first := testPtyHub(t)
	peer := key.NewNode().Public()
	_, sid, why := first.open(peer, nil, "80x24")
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	s := first.testSess(sid)
	testPtyType(t, s.sock, "echo before-$((6*7))\n")
	testPtyRead(t, s.sock).waitFor(t, "before-42")

	// The next process: a table of its own over the same directory.
	next := newPtyHub()
	next.dir = first.dir
	next.spawn = testPtySpawn
	if l := next.list(); len(l) != 1 || l[0].ID != sid || l[0].Until <= time.Now().Unix() {
		t.Fatalf("the next process must find the session: %+v", l)
	}
	// Nobody holds the keys in the new process: a watcher gets them.
	tok, keys, why := next.attach(peer, sid+"/w", nil, nil)
	if why != "" || !ptyTokenRe.MatchString(tok) || !keys {
		t.Fatalf("attach: %q %v %q", tok, keys, why)
	}
	out := testPtyRead(t, next.testSess(sid).sock)
	out.waitFor(t, "before-42")
	testPtyType(t, s.sock, "echo after\n")
	out.waitFor(t, "after")
	next.endAll()
	out.waitEnd(t)
	// A socket nobody answers on is cleared, not adopted.
	os.WriteFile(ptyHoldSock(first.dir, "00000000000000ff"), nil, 0o600)
	third := newPtyHub()
	third.dir = first.dir
	if l := third.list(); len(l) != 0 {
		t.Errorf("nothing runs: %+v", l)
	}
	if _, err := os.Lstat(ptyHoldSock(first.dir, "00000000000000ff")); err == nil {
		t.Error("a dead socket must be cleared")
	}
}

// What the push lists: the session's id and its foreground program.
func TestPtyListNamesTheProgram(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	if ptyProgName(os.Getpid()) == "" {
		t.Skip("no process names here")
	}
	hub := testPtyHub(t)
	_, sid, why := hub.open(key.NewNode().Public(), nil, "80x24")
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	s := hub.testSess(sid)
	out := testPtyRead(t, s.sock)
	testPtyType(t, s.sock, "echo up; exec sleep 300\n")
	out.waitFor(t, "up")
	deadline := time.Now().Add(10 * time.Second)
	for {
		l := hub.list()
		if len(l) == 1 && l[0].ID == sid && l[0].Prog == "sleep" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("list: %+v", l)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := ptyProgClean("-zsh"); got != "zsh" {
		t.Errorf("clean: %q", got)
	}
	if got := ptyProgClean("a b/cé" + strings.Repeat("x", 40)); got != "abc"+strings.Repeat("x", 29) {
		t.Errorf("clean: %q", got)
	}
}

// The sweep: console off ends every session; a session whose signing key
// was unpinned ends; a token whose tunnel key left the allowlist goes.
func TestPtySweep(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	hub := testPtyHub(t)
	kept, gone := key.NewNode().Public(), key.NewNode().Public()
	pinned, _, _ := ed25519.GenerateKey(nil)
	dropped, _, _ := ed25519.GenerateKey(nil)
	hub.allowed = func(k key.NodePublic) bool { return k == kept }
	hub.trusted = func(k ed25519.PublicKey) bool { return k.Equal(pinned) }
	tokKept, sidKept, _ := hub.open(kept, pinned, "80x24")
	tokGone, _, _ := hub.open(gone, pinned, "80x24")
	_, sidDropped, _ := hub.open(kept, dropped, "80x24")
	hub.sweep(time.Now())
	hub.mu.Lock()
	_, a := hub.toks[tokKept]
	_, b := hub.toks[tokGone]
	hub.mu.Unlock()
	if !a || b {
		t.Errorf("tokens after the sweep: kept %v, gone %v", a, b)
	}
	if hub.testSess(sidDropped) != nil || hub.testSess(sidKept) == nil || hub.testCount() != 2 {
		t.Errorf("sessions after the sweep: %d", hub.testCount())
	}
	// A token from an attach signed by a key since unpinned goes, with its
	// channel closed (which ends its streams); the session stays.
	other, _, _ := ed25519.GenerateKey(nil)
	hub.trusted = func(k ed25519.PublicKey) bool { return k.Equal(pinned) || k.Equal(other) }
	tokOther, _, why := hub.attach(kept, sidKept, nil, other)
	if why != "" {
		t.Fatalf("attach: %s", why)
	}
	hub.mu.Lock()
	rec := hub.toks[tokOther]
	hub.mu.Unlock()
	hub.trusted = func(k ed25519.PublicKey) bool { return k.Equal(pinned) }
	hub.sweep(time.Now())
	select {
	case <-rec.gone:
	default:
		t.Error("an unpinned signer's token must be let go")
	}
	if hub.testSess(sidKept) == nil {
		t.Error("the session outlives a token let go")
	}
	t.Setenv(consoleEnvVar, "0")
	hub.sweep(time.Now())
	if n := hub.testCount(); n != 0 {
		t.Errorf("console off must end every session: %d left", n)
	}
}

// The keep the relay says reaches every holder.
func TestPtySetKeep(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	hub := testPtyHub(t)
	_, sid, _ := hub.open(key.NewNode().Public(), nil, "80x24/86400")
	s := hub.testSess(sid)
	var in ptyHoldInfo
	ptyAsk(s.sock, ptyHoldReq{Op: "info"}, &in)
	if in.Keep != int64(ptyQuietMax/time.Second) || in.Ceil != 86400 {
		t.Fatalf("before the relay says: keep %d ceil %d", in.Keep, in.Ceil)
	}
	hub.setKeep(7 * 24 * time.Hour)
	ptyAsk(s.sock, ptyHoldReq{Op: "info"}, &in)
	if in.Keep != 7*24*3600 || in.Until-in.Seen != 86400 {
		t.Errorf("after: keep %d, until-seen %d", in.Keep, in.Until-in.Seen)
	}
	// A new session starts with what the relay said.
	_, sid2, _ := hub.open(key.NewNode().Public(), nil, "80x24")
	ptyAsk(hub.testSess(sid2).sock, ptyHoldReq{Op: "info"}, &in)
	if in.Keep != 7*24*3600 {
		t.Errorf("a new session's keep: %d", in.Keep)
	}
}

// The streams as the page uses them: output down a GET, keys up a POST whose
// body stays open, the size by a POST of its own — for the peer that holds
// the token and nobody else; and the keys move to the page that came back
// last.
func TestPtyStreamsOverTheHandler(t *testing.T) {
	scratchHome(t)
	t.Setenv(consoleEnvVar, "1")
	owner, other := key.NewNode().Public(), key.NewNode().Public()
	for _, k := range []key.NodePublic{owner, other} {
		if err := allowClient(k.String()); err != nil {
			t.Fatal(err)
		}
	}
	h := newDirectHandler()
	h.ptys = testPtyHub(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := owner
		if r.Header.Get("X-Test-Peer") == "other" {
			k = other
		}
		h.ServeHTTP(w, r.WithContext(transport.WithPeer(r.Context(), k)))
	}))
	defer srv.Close()
	do := func(method, path, peer string, body io.Reader) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, body)
		if peer != "" {
			req.Header.Set("X-Test-Peer", peer)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}
	tok, sid, why := h.ptys.open(owner, nil, "80x24")
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	// Another allowed browser's tunnel, the right token: no session.
	if resp := do("GET", "/v1/pty/out?s="+tok, "other", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another peer must find no session: %v", resp.StatusCode)
	}
	// A read is a GET and a write a POST.
	if resp := do("POST", "/v1/pty/out?s="+tok, "", nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST to the output stream must be refused: %v", resp.StatusCode)
	}

	out := do("GET", "/v1/pty/out?s="+tok, "", nil)
	if out.StatusCode != http.StatusOK {
		t.Fatalf("output stream: %v", out.StatusCode)
	}
	defer out.Body.Close()
	got := make(chan string, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := out.Body.Read(buf)
			if n > 0 {
				got <- string(buf[:n])
			}
			if err != nil {
				close(got)
				return
			}
		}
	}()
	seen := ""
	waitFor := func(want string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for !strings.Contains(seen, want) {
			select {
			case s, ok := <-got:
				if !ok {
					t.Fatalf("stream ended before %q: %q", want, seen)
				}
				seen += s
			case <-deadline:
				t.Fatalf("no %q on the stream: %q", want, seen)
			}
		}
	}

	pr, pw := io.Pipe()
	inDone := make(chan int, 1)
	go func() {
		resp, err := srv.Client().Post(srv.URL+"/v1/pty/in?s="+tok, "application/octet-stream", pr)
		if err != nil {
			inDone <- 0
			return
		}
		resp.Body.Close()
		inDone <- resp.StatusCode
	}()
	pw.Write([]byte("echo typed-$((40+2))\n"))
	waitFor("typed-42")

	if resp := do("POST", "/v1/pty/resize?s="+tok+"&c=120&r=40", "", nil); resp.StatusCode != http.StatusNoContent || resp.Header.Get("X-Pty-Keys") != "" {
		t.Fatalf("resize: %v", resp.StatusCode)
	}
	if resp := do("POST", "/v1/pty/resize?s="+tok+"&c=0&r=40", "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a size out of bounds must be refused: %v", resp.StatusCode)
	}
	pw.Write([]byte("echo sized-$(stty size | tr ' ' x)\n"))
	waitFor("sized-40x120")

	// The other browser comes back to the session: the keys are its, the
	// owner's open input stream is cut as taken, and the owner's next
	// input is refused as taken; its size is only a sign of life.
	// A watcher first: the keys stay where they are.
	tokW, keysW, why := h.ptys.attach(other, sid+"/w", nil, nil)
	if why != "" || keysW {
		t.Fatalf("watch: %v %s", keysW, why)
	}
	if resp := do("POST", "/v1/pty/in?s="+tokW, "other", strings.NewReader("echo no\n")); resp.StatusCode != http.StatusLocked {
		t.Errorf("a watcher's input must be refused: %d", resp.StatusCode)
	}
	tok2, keys2, why := h.ptys.attach(other, sid, nil, nil)
	if why != "" || !keys2 {
		t.Fatalf("attach: %v %s", keys2, why)
	}
	// The owner's open stream stays open — it is one with the output on
	// the tunnel's carrier — until it types, which is refused as taken.
	select {
	case code := <-inDone:
		t.Fatalf("the owner's stream must stay open until it types: %d", code)
	case <-time.After(300 * time.Millisecond):
	}
	pw.Write([]byte("echo lost\n"))
	select {
	case code := <-inDone:
		if code != http.StatusLocked {
			t.Errorf("the owner's stream must end as taken: %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the owner's typing was not refused")
	}
	pw.Close()
	if resp := do("POST", "/v1/pty/in?s="+tok, "", strings.NewReader("echo no\n")); resp.StatusCode != http.StatusLocked {
		t.Errorf("the owner's input after the attach must be refused: %d", resp.StatusCode)
	}
	if resp := do("POST", "/v1/pty/resize?s="+tok+"&c=60&r=20", "", nil); resp.StatusCode != http.StatusNoContent || resp.Header.Get("X-Pty-Keys") != "taken" {
		t.Errorf("a watcher's resize: %v %q", resp.StatusCode, resp.Header.Get("X-Pty-Keys"))
	}
	if resp := do("POST", "/v1/pty/in?s="+tok2, "other", strings.NewReader("echo sized-again-$(stty size | tr ' ' x)\n")); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("the new owner's input: %d", resp.StatusCode)
	}
	waitFor("sized-again-40x120")

	// The shell exits: the output stream ends cleanly, and the tokens name
	// nothing.
	do("POST", "/v1/pty/in?s="+tok2, "other", strings.NewReader("exit\n"))
	deadline := time.After(10 * time.Second)
	for open := true; open; {
		select {
		case _, ok := <-got:
			open = ok
		case <-deadline:
			t.Fatal("the output stream did not end with the shell")
		}
	}
	deadline2 := time.Now().Add(10 * time.Second)
	for h.ptys.testCount() != 0 {
		if time.Now().After(deadline2) {
			t.Fatal("the session did not leave the table")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp := do("POST", "/v1/pty/resize?s="+tok2+"&c=80&r=24", "other", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("an ended session's token must name nothing: %v", resp.StatusCode)
	}
}

// Ending a session takes what the shell started with it: a foreground job
// in a process group of its own, deaf to the hangup.
func TestPtyEndKillsTheForegroundJob(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	hub := testPtyHub(t)
	_, sid, why := hub.open(key.NewNode().Public(), nil, "80x24")
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	s := hub.testSess(sid)
	out := testPtyRead(t, s.sock)
	testPtyType(t, s.sock, "sh -c 'trap \"\" HUP; echo job-$$-$((1+1))up; exec sleep 300'\n")
	out.waitFor(t, "-2up")
	i := strings.LastIndex(out.seen, "job-")
	var pid int
	if _, err := fmt.Sscanf(out.seen[i:], "job-%d-2up", &pid); err != nil || pid <= 1 {
		t.Fatalf("no pid in %q", out.seen)
	}
	hub.end(s)
	deadline := time.Now().Add(8 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the foreground job %d outlived its session", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The holder as its own process, the way the helper starts it: it answers,
// it outlives the call that started it, and it ends when asked.
func TestPtyHoldProcess(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	if os.Getenv("PTY_HOLD_E2E") == "" {
		t.Skip("set PTY_HOLD_E2E=<path to a built helper> to run")
	}
	noteInstalledAt(os.Getenv("PTY_HOLD_E2E"))
	defer noteInstalledAt("")
	dir, _ := os.MkdirTemp("", "pty")
	defer os.RemoveAll(dir)
	id := "00000000000000b1"
	if err := ptyHoldSpawn(dir, id, 80, 24, time.Hour, time.Hour, nil); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	sock := ptyHoldSock(dir, id)
	var in ptyHoldInfo
	if err := ptyAsk(sock, ptyHoldReq{Op: "info"}, &in); err != nil || in.ID != id || in.Keep != 3600 {
		t.Fatalf("info: %+v %v", in, err)
	}
	out := testPtyRead(t, sock)
	testPtyType(t, sock, "echo proc-$((2*21))\n")
	out.waitFor(t, "proc-42")
	ptyAsk(sock, ptyHoldReq{Op: "end"}, nil)
	out.waitEnd(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(sock); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the holder's socket outlived it")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
