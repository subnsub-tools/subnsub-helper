package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"

	"subnsubmonitor/transport"
)

// withTailnetRoad puts this Mac on a tailnet for a test.
func withTailnetRoad(t *testing.T, ip string, port int) {
	t.Helper()
	was := tailnetRoad.Load()
	tailnetRoad.Store(&transport.TailnetRoad{IP: ip, Port: port})
	t.Cleanup(func() { tailnetRoad.Store(was) })
}

func putTnReset(t *testing.T) {
	t.Helper()
	reset := func() {
		putTn.Lock()
		putTn.addr, putTn.rest, putTn.reach = nil, nil, nil
		putTn.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func putTnSet(agent, addr string) {
	putTn.Lock()
	defer putTn.Unlock()
	if putTn.addr == nil {
		putTn.addr = map[string]string{}
	}
	putTn.addr[agent] = addr
}

func putTnResting(agent string) bool {
	putTn.Lock()
	defer putTn.Unlock()
	return time.Now().Before(putTn.rest[agent])
}

// putTnPair has this process play both Macs: macA calls macB at macB's
// tailnet door. The list holds each as the other sees it: macA by the key it
// dials macB from, macB by the key it dials macA from, which it proves itself
// with at its door. callerKey replaces macA's, for a caller that is not it.
func putTnPair(t *testing.T, f *putFixture, callerKey key.NodePublic) putPeer {
	t.Helper()
	kB, err := putKeyFor("macB")
	if err != nil {
		t.Fatal(err)
	}
	kA, err := putKeyFor("macA")
	if err != nil {
		t.Fatal(err)
	}
	if callerKey.IsZero() {
		callerKey = kB.Public()
	}
	f.addPeer(t, "macA", "Desk A", testPutAddr(t), callerKey)
	f.addPeer(t, "macB", "Desk B", testPutAddr(t), kA.Public())
	srv := httptest.NewServer(http.HandlerFunc(putTailnetServe))
	t.Cleanup(srv.Close)
	putTnSet("macB", strings.TrimPrefix(srv.URL, "http://"))
	b, _ := putPeerByAgent("macB")
	return b
}

// A stream through the tailnet door, both ways, as through the tunnel; it ends
// once the caller is taken off the list.
func TestPutTailnetStream(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	b := putTnPair(t, f, key.NodePublic{})
	local, app := net.Pipe()
	putPark(local)
	defer app.Close()
	// put here reads its header as the stream is handed to it, and then the bytes.
	app.SetDeadline(time.Now().Add(10 * time.Second))
	ar := bufio.NewReader(app)
	heard := make(chan string, 1)
	go func() {
		line, err := ar.ReadString('\n')
		got := make([]byte, 5)
		if err == nil {
			_, err = io.ReadFull(ar, got)
		}
		heard <- fmt.Sprintf("%s|%s|%v", strings.TrimSpace(line), got, err)
	}()
	nc, nr, code, err := putConnectTailnet(b, "macA", time.Now().Add(10*time.Second))
	if err != nil || code != "" {
		t.Fatalf("open: %q %v", code, err)
	}
	defer nc.Close()
	nc.SetDeadline(time.Time{})
	io.WriteString(nc, "hello")
	if h := <-heard; !strings.Contains(h, `"from":"macA"`) || !strings.Contains(h, `"name":"Desk A"`) || !strings.HasSuffix(h, "|hello|<nil>") {
		t.Fatalf("put heard %q", h)
	}
	app.Write([]byte("back"))
	nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(nr, got); err != nil || string(got) != "back" {
		t.Fatalf("from put: %q %v", got, err)
	}
	if r := f.command(t, "put-peer", "macA", ""); r.Code != 0 {
		t.Fatal(r)
	}
	if _, err := nr.ReadByte(); err == nil {
		t.Fatal("the stream outlived its peer's removal")
	}
}

// A caller that cannot prove the key its entry holds, or that names no entry,
// gets nothing: no stream reaches put.
func TestPutTailnetRefusesOthers(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	b := putTnPair(t, f, key.NewNode().Public())
	local, app := net.Pipe()
	putPark(local)
	defer app.Close()
	if _, _, code, err := putConnectTailnet(b, "macA", time.Now().Add(10*time.Second)); err == nil || code != "" {
		t.Fatalf("a caller with another key was let in: %q %v", code, err)
	}
	if _, _, code, err := putConnectTailnet(b, "macNobody", time.Now().Add(10*time.Second)); err == nil || code != "" {
		t.Fatalf("an unlisted caller was let in: %q %v", code, err)
	}
	putLocal.Lock()
	waiting := len(putLocal.accepts)
	putLocal.Unlock()
	if waiting != 1 {
		t.Fatalf("put's waiting connection was taken: %d left", waiting)
	}
}

// A tailnet that refuses, or says nothing, is given up for tailcat within the
// same open, and not tried again for a while.
func TestPutTailnetFallsBack(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	wasWait := putTnWait
	putTnWait = 300 * time.Millisecond
	t.Cleanup(func() { putTnWait = wasWait })
	withFakeTunnels(t, f, &fakeTunnel{}, &fakeTunnel{}, &fakeTunnel{})
	// Refused.
	putTnSet("macStudy01", "127.0.0.1:1")
	c, _, out := dialPut(t, `{"op":"open","agent":"macStudy01"}`)
	c.Close()
	if out["ok"] != true || out["route"] == "tailnet" {
		t.Fatalf("open: %v", out)
	}
	if !putTnResting("macStudy01") {
		t.Fatal("a tailnet that refused is tried again at once")
	}
	// Silent: a listener that takes the connection and never answers.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	putTnReset(t)
	putTnSet("macStudy01", ln.Addr().String())
	started := time.Now()
	c, _, out = dialPut(t, `{"op":"open","agent":"macStudy01"}`)
	c.Close()
	if out["ok"] != true || out["route"] == "tailnet" || time.Since(started) > 3*time.Second {
		t.Fatalf("open: %v after %v", out, time.Since(started))
	}
}

// Each side names its tailnet road in the upgrade through the tunnel, and the
// other keeps it: the door's address, through the tunnel's own say-so.
func TestPutTailnetLearned(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	// The answering side: what the caller names is kept, and this Mac's road is named back.
	peer := key.NewNode().Public()
	f.addPeer(t, "macStudy01", "Study", testPutAddr(t), peer)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.h.ServeHTTP(w, r.WithContext(transport.WithPeer(r.Context(), peer)))
	}))
	defer srv.Close()
	local, app := net.Pipe()
	putPark(local)
	defer app.Close()
	go io.Copy(io.Discard, app)
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET "+putStreamPath+" HTTP/1.1\r\nHost: tailcat\r\nUpgrade: put\r\nConnection: Upgrade\r\n"+putTnHeader+": 100.101.102.103:41641\r\n\r\n")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get(putTnHeader) != "100.100.7.7:41641" {
		t.Fatalf("answer %v %v", resp, err)
	}
	putTn.Lock()
	learned := putTn.addr["macStudy01"]
	putTn.Unlock()
	if learned != "100.101.102.103:41641" {
		t.Fatalf("learned %q", learned)
	}
	// The calling side: the answer's road is kept, and the ask named this Mac's.
	putTnReset(t)
	tun := &fakeTunnel{tn: "100.101.9.9:41641"}
	withFakeTunnels(t, f, tun, tun)
	c2, _, out := dialPut(t, `{"op":"open","agent":"macStudy01"}`)
	c2.Close()
	if out["ok"] != true {
		t.Fatalf("open: %v", out)
	}
	if !strings.Contains(tun.asked, putTnHeader+": 100.100.7.7:41641") {
		t.Fatalf("the ask did not name this Mac's road: %q", tun.asked)
	}
	putTn.Lock()
	learned = putTn.addr["macStudy01"]
	putTn.Unlock()
	if learned != "100.101.9.9:41641" {
		t.Fatalf("learned %q", learned)
	}
}

func TestPutTailnetAddress(t *testing.T) {
	for v, want := range map[string]string{
		"100.100.1.2:41641": "100.100.1.2:41641",
		" 100.64.0.1:80 ":   "100.64.0.1:80",
		"100.127.255.1:9":   "100.127.255.1:9",
		"100.128.0.1:9":     "",
		"192.168.1.4:9":     "",
		"100.64.0.1:0":      "",
		"[fd7a::1]:9":       "",
		"name:9":            "",
		"":                  "",
	} {
		if got := putTnValid(v); got != want {
			t.Errorf("putTnValid(%q) = %q, want %q", v, got, want)
		}
	}
}

// A listed peer that sends a request head without end is cut off, and nothing
// reaches put.
func TestPutTailnetAskBounded(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	b := putTnPair(t, f, key.NodePublic{})
	local, app := net.Pipe()
	putPark(local)
	defer app.Close()
	sc, err := putTnDial(b, "macA", putTnFor("macB"), time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	go io.WriteString(sc, "GET "+putStreamPath+" HTTP/1.1\r\nX: "+strings.Repeat("a", 2*putHeadMax))
	sc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := sc.Read(make([]byte, 64)); err == nil {
		t.Fatalf("an endless head was answered (%d bytes)", n)
	}
	putLocal.Lock()
	waiting := len(putLocal.accepts)
	putLocal.Unlock()
	if waiting != 1 {
		t.Fatalf("put's waiting connection was taken: %d left", waiting)
	}
}

// fakeTnDoor answers at the tailnet door as macB would, then does then.
func fakeTnDoor(t *testing.T, then func(c net.Conn)) string {
	t.Helper()
	kA, err := putKeyFor("macA")
	if err != nil {
		t.Fatal(err)
	}
	mp, err := putMachinePrivate(kA)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+putTnUpgrade+"\r\nConnection: Upgrade\r\n\r\n")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sc, err := controlbase.Server(ctx, bufConn{conn, brw.Reader}, mp, nil)
		if err != nil {
			conn.Close()
			return
		}
		then(sc)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// A door that shakes hands and then says nothing is given up within the
// tailnet's time, for tailcat; one whose answer began and broke off is the
// answer, and tailcat is not tried.
func TestPutTailnetAfterHandshake(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	withTailnetRoad(t, "100.100.7.7", 41641)
	wasWait := putTnWait
	putTnWait = 400 * time.Millisecond
	t.Cleanup(func() { putTnWait = wasWait })
	b := putTnPair(t, f, key.NodePublic{})
	silent := make(chan struct{})
	t.Cleanup(func() { close(silent) })
	putTnSet("macB", fakeTnDoor(t, func(c net.Conn) { <-silent; c.Close() }))
	started := time.Now()
	_, _, code, err := putConnectTailnet(b, "macA", time.Now().Add(10*time.Second))
	if err == nil || code != "" || time.Since(started) > 2*time.Second {
		t.Fatalf("a silent door: %q %v after %v", code, err, time.Since(started))
	}
	putTnSet("macB", fakeTnDoor(t, func(c net.Conn) {
		io.Copy(io.Discard, io.LimitReader(c, 10))
		io.WriteString(c, "HTTP/1.1 101 Swi")
		c.Close()
	}))
	if _, _, code, err := putConnectTailnet(b, "macA", time.Now().Add(10*time.Second)); err != nil || code != "unreachable" {
		t.Fatalf("a broken-off answer: %q %v", code, err)
	}
}

// A Mac that is not on a tailnet itself calls a peer's door there while the
// door is seen to take a connection from it (a router carries it); a door
// that takes none is left alone; a stream waits at most putTnQuickWait for a
// door not tried lately; and a "no" found out long ago is not believed.
func TestPutTailnetBehindRouter(t *testing.T) {
	f := newPutFixture(t)
	putTnReset(t)
	was := tailnetRoad.Load()
	tailnetRoad.Store(nil)
	t.Cleanup(func() { tailnetRoad.Store(was) })
	b := putTnPair(t, f, key.NodePublic{})
	start := time.Now()
	if putTnFor("macB") == "" {
		t.Fatal("a door that takes connections was not called")
	}
	if d := time.Since(start); d > putTnQuickWait+500*time.Millisecond {
		t.Fatalf("finding out held the caller %v", d)
	}
	// A "no" found out long ago (this Mac slept, or was elsewhere) is found
	// out again by the stream.
	putTn.Lock()
	putTn.reach["macB"] = putTnReach{addr: putTn.addr["macB"], at: time.Now().Add(-2 * putTnReachFresh)}
	putTn.Unlock()
	if putTnFor("macB") == "" {
		t.Fatal("an old no kept a door that takes connections from being called")
	}
	local, app := net.Pipe()
	putPark(local)
	defer app.Close()
	go io.Copy(io.Discard, app)
	nc, _, code, err := putConnectTailnet(b, "macA", time.Now().Add(10*time.Second))
	if err != nil || code != "" {
		t.Fatalf("open: %q %v", code, err)
	}
	nc.Close()
	// The way there as out is told it: the door's own answer, by the router.
	if p := putPathTailnet(context.Background(), "macB"); p == nil || !p.OK || p.Via != "router" || p.Where == "" {
		t.Fatalf("path %+v", p)
	}
	// One that fails there is not called again until its door is seen to answer.
	putTnFailed("macB")
	putTn.Lock()
	delete(putTn.rest, "macB")
	putTn.Unlock()
	if a := putTnFor("macB"); a != "" {
		t.Fatalf("called again at once after failing: %q", a)
	}
	// A door nothing listens at.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	putTnSet("macStudy01", dead)
	if a := putTnFor("macStudy01"); a != "" {
		t.Fatalf("a door that takes no connection was called: %q", a)
	}
	// Found out once, it is not knocked at again by the next stream.
	putTn.Lock()
	at := putTn.reach["macStudy01"].at
	putTn.Unlock()
	if a := putTnFor("macStudy01"); a != "" || at.IsZero() {
		t.Fatalf("a door that takes no connection: %q, found out at %v", a, at)
	}
	putTn.Lock()
	again := putTn.reach["macStudy01"].at
	putTn.Unlock()
	if !again.Equal(at) {
		t.Fatalf("a fresh no was knocked at again (%v, then %v)", at, again)
	}
	if p := putPathTailnet(context.Background(), "macStudy01"); p != nil {
		t.Fatalf("path to a door not reached: %+v", p)
	}
	// With the tailnet off, nothing.
	t.Setenv("MON_TAILNET", "off")
	if a := putTnFor("macB"); a != "" {
		t.Fatalf("called with the tailnet off: %q", a)
	}
	// Nor is a door a peer then names tried.
	putTnLearn("macLate", "100.100.1.2:8126")
	putTn.Lock()
	r := putTn.reach["macLate"]
	putTn.Unlock()
	if r.trying || !r.at.IsZero() {
		t.Fatalf("a door was tried with the tailnet off: %+v", r)
	}
}
