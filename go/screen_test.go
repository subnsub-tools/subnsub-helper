package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// fakeVNC is a listener that says what a VNC server says first, then answers
// every read with "echo:" and what it read. It returns its address and a
// channel that is closed when a connection it accepted is closed by the
// other end.
func fakeVNC(t *testing.T, hello string) (string, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	gone := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(hello))
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(append([]byte("echo:"), buf[:n]...))
					}
					if err != nil {
						gone <- struct{}{}
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), gone
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func TestScreenOpenGates(t *testing.T) {
	peer := key.NewNode().Public()
	addr, _ := fakeVNC(t, "RFB 003.008\n")
	hub := newScreenHub()
	hub.addrs = func() []string { return []string{addr} }
	defer hub.endAll()

	t.Setenv(consoleEnvVar, "0")
	if _, why := hub.open(peer, nil); why != "console-off" {
		t.Errorf("console off must refuse: %q", why)
	}
	t.Setenv(consoleEnvVar, "1")
	t.Setenv(screenEnvVar, "off")
	if _, why := hub.open(peer, nil); why != "screen-off" {
		t.Errorf("MON_SCREEN=off must refuse: %q", why)
	}
	t.Setenv(screenEnvVar, "")

	// Nothing listening, or something that is not VNC: no screen.
	none := newScreenHub()
	none.addrs = func() []string { return []string{closedPort(t)} }
	if _, why := none.open(peer, nil); why != "no-vnc" {
		t.Errorf("no listener must be no-vnc: %q", why)
	}
	web, _ := fakeVNC(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	other := newScreenHub()
	other.addrs = func() []string { return []string{web} }
	if _, why := other.open(peer, nil); why != "no-vnc" {
		t.Errorf("a server that is not VNC must be no-vnc: %q", why)
	}

	for i := 0; i < screenMaxSessions; i++ {
		tok, why := hub.open(peer, nil)
		if why != "" {
			t.Fatalf("session %d refused: %s", i, why)
		}
		if !screenTokenRe.MatchString(tok) {
			t.Fatalf("token shape: %q", tok)
		}
	}
	if _, why := hub.open(peer, nil); why != "busy" {
		t.Errorf("past the ceiling must be busy: %q", why)
	}
}

// Only the loopback addresses, at 5900 or the port MON_SCREEN_PORT names.
func TestScreenAddrs(t *testing.T) {
	t.Setenv(screenPortEnvVar, "")
	if got := strings.Join(screenAddrs(), " "); got != "127.0.0.1:5900 [::1]:5900" {
		t.Errorf("default: %q", got)
	}
	t.Setenv(screenPortEnvVar, "5901")
	if got := strings.Join(screenAddrs(), " "); got != "127.0.0.1:5901 [::1]:5901" {
		t.Errorf("MON_SCREEN_PORT: %q", got)
	}
	for _, bad := range []string{"0", "65536", "x", "-1", "10.0.0.1:5900"} {
		t.Setenv(screenPortEnvVar, bad)
		if screenPort() != screenDefaultPort {
			t.Errorf("%q must fall back to the default", bad)
		}
	}
}

// A session whose page has gone quiet, or once the console is off, is ended.
func TestScreenSweep(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	addr, gone := fakeVNC(t, "RFB 003.008\n")
	hub := newScreenHub()
	hub.addrs = func() []string { return []string{addr} }
	defer hub.endAll()
	peer := key.NewNode().Public()
	count := func() int { hub.mu.Lock(); defer hub.mu.Unlock(); return len(hub.sess) }
	if _, why := hub.open(peer, nil); why != "" {
		t.Fatalf("open refused: %s", why)
	}
	hub.sweep(time.Now())
	if count() != 1 {
		t.Fatal("a live session must survive the sweep")
	}
	hub.sweep(time.Now().Add(screenQuietMax + time.Second))
	if count() != 0 {
		t.Fatalf("the sweep must end a quiet session: %d left", count())
	}
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("ending a session must close its connection to the server")
	}
	if _, why := hub.open(peer, nil); why != "" {
		t.Fatalf("open refused: %s", why)
	}
	t.Setenv(consoleEnvVar, "0")
	hub.sweep(time.Now())
	if count() != 0 {
		t.Errorf("console off must end every session: %d left", count())
	}
}

// The streams as the page uses them, for the peer that opened the session and
// nobody else; one reader, and the session over when that reader lets go.
func TestScreenStreamsOverTheHandler(t *testing.T) {
	scratchHome(t)
	t.Setenv(consoleEnvVar, "1")
	owner, other := key.NewNode().Public(), key.NewNode().Public()
	for _, k := range []key.NodePublic{owner, other} {
		if err := allowClient(k.String()); err != nil {
			t.Fatal(err)
		}
	}
	addr, gone := fakeVNC(t, "RFB 003.008\n")
	h := newDirectHandler()
	h.screens = newScreenHub()
	h.screens.addrs = func() []string { return []string{addr} }
	defer h.screens.endAll()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := owner
		if r.Header.Get("X-Test-Peer") == "other" {
			k = other
		}
		h.ServeHTTP(w, r.WithContext(transport.WithPeer(r.Context(), k)))
	}))
	defer srv.Close()
	tok, why := h.screens.open(owner, nil)
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	q := "?s=" + tok

	req, _ := http.NewRequest("GET", srv.URL+"/v1/screen/out"+q, nil)
	req.Header.Set("X-Test-Peer", "other")
	if resp, err := srv.Client().Do(req); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another peer must find no session: %v %v", resp, err)
	}
	if resp, _ := srv.Client().Post(srv.URL+"/v1/screen/out"+q, "", nil); resp == nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST to the output stream must be refused: %v", resp)
	}
	if resp, _ := srv.Client().Get(srv.URL + "/v1/screen/beat" + q); resp == nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET of the beat must be refused: %v", resp)
	}

	out, err := srv.Client().Get(srv.URL + "/v1/screen/out" + q)
	if err != nil || out.StatusCode != http.StatusOK {
		t.Fatalf("output stream: %v %v", out, err)
	}
	defer out.Body.Close()
	got := make(chan []byte, 64)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		buf := make([]byte, 4096)
		for {
			n, err := out.Body.Read(buf)
			if n > 0 {
				got <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	var seen []byte
	waitFor := func(want string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for !bytes.Contains(seen, []byte(want)) {
			select {
			case b := <-got:
				seen = append(seen, b...)
			case <-deadline:
				t.Fatalf("no %q in the output: %q", want, seen)
			}
		}
	}
	waitFor("RFB 003.008\n")
	if !bytes.HasPrefix(seen, []byte("RFB 003.008\n")) {
		t.Fatalf("the server's version line must come first: %q", seen)
	}

	// A second reader: refused, the first keeps its stream.
	if resp, _ := srv.Client().Get(srv.URL + "/v1/screen/out" + q); resp == nil || resp.StatusCode != http.StatusConflict {
		t.Errorf("a second reader must be refused: %v", resp)
	}
	// Input as the tailnet road sends it, a piece per request, and as the
	// tunnel sends it, one body.
	if resp, err := srv.Client().Post(srv.URL+"/v1/screen/in"+q, "application/octet-stream", strings.NewReader("one")); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("a piece of input: %v %v", resp, err)
	}
	waitFor("echo:one")
	pr, pw := io.Pipe()
	inDone := make(chan *http.Response, 1)
	go func() {
		resp, _ := srv.Client().Post(srv.URL+"/v1/screen/in"+q, "application/octet-stream", pr)
		inDone <- resp
	}()
	pw.Write([]byte("two"))
	waitFor("echo:two")
	pw.Close()
	if resp := <-inDone; resp == nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("a body that ends is the page letting go of input: %v", resp)
	}
	if resp, _ := srv.Client().Post(srv.URL+"/v1/screen/beat"+q, "", nil); resp == nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("beat on a live session: %v", resp)
	}
	// Closing ends the output stream and the server's connection.
	if resp, _ := srv.Client().Post(srv.URL+"/v1/screen/close"+q, "", nil); resp == nil || resp.StatusCode != http.StatusNoContent {
		t.Errorf("close: %v", resp)
	}
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("closing must end the output stream")
	}
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("closing must close the connection to the server")
	}
	if resp, _ := srv.Client().Post(srv.URL+"/v1/screen/beat"+q, "", nil); resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("beat after close must find no session: %v", resp)
	}
}

// A reader that goes away takes the session with it: VNC cannot resume.
func TestScreenReaderGoneEndsSession(t *testing.T) {
	scratchHome(t)
	t.Setenv(consoleEnvVar, "1")
	owner := key.NewNode().Public()
	if err := allowClient(owner.String()); err != nil {
		t.Fatal(err)
	}
	addr, gone := fakeVNC(t, "RFB 003.008\n")
	h := newDirectHandler()
	h.screens = newScreenHub()
	h.screens.addrs = func() []string { return []string{addr} }
	defer h.screens.endAll()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(transport.WithPeer(r.Context(), owner)))
	}))
	defer srv.Close()
	tok, why := h.screens.open(owner, nil)
	if why != "" {
		t.Fatalf("open refused: %s", why)
	}
	out, err := srv.Client().Get(srv.URL + "/v1/screen/out?s=" + tok)
	if err != nil || out.StatusCode != http.StatusOK {
		t.Fatalf("output stream: %v %v", out, err)
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(out.Body, buf); err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	srv.CloseClientConnections()
	select {
	case <-gone:
	case <-time.After(10 * time.Second):
		t.Fatal("a reader that went away must end the session")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.screens.mu.Lock()
		n := len(h.screens.sess)
		h.screens.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions left", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The relay's mailbox never opens a screen.
func TestScreenNotOnTheMailbox(t *testing.T) {
	t.Setenv(consoleEnvVar, "1")
	res, _ := runCommand(consoleCmd{ID: "x", Kind: "screen"})
	if res.Code != -1 || res.Error != "tunnel-only" {
		t.Errorf("the mailbox must refuse a screen: %+v", res)
	}
}
