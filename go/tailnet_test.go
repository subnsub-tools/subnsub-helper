package main

import (
	"bytes"
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
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"
	"tailscale.com/types/key"
)

// tnReader is the reader's half of tailnet.go in Go, written from the wire
// format and not sharing its code: the browser's half is monitor-direct.js, and
// infra/monitor-tailnet-e2e.mjs runs that one against a real helper.
type tnReader struct {
	t      *testing.T
	url    string
	sid    string
	in     cipher.AEAD
	out    []byte
	seq    uint64
	peer   string
	static *ecdh.PrivateKey
}

func tnNewKey(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, "nodekey:" + hex.EncodeToString(k.PublicKey().Bytes())
}

func tnPost(t *testing.T, url string, body []byte) (int, []byte) {
	t.Helper()
	r, err := http.Post(url, "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, b
}

func tnOpenAs(t *testing.T, url string, static *ecdh.PrivateKey, pub string) (*tnReader, int) {
	t.Helper()
	eph, _ := tnNewKey(t)
	nc := make([]byte, 16)
	rand.Read(nc)
	ePub := hex.EncodeToString(eph.PublicKey().Bytes())
	q, _ := json.Marshal(map[string]any{"v": 1, "c": pub, "e": ePub, "n": hex.EncodeToString(nc)})
	st, b := tnPost(t, url+"/tn/open", q)
	if st != 200 {
		return nil, st
	}
	var a struct {
		V          int
		S, E, N, A string
		M          string
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	mine, err := econPrivate()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := static.ECDH(mine.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	eRaw, _ := hex.DecodeString(a.E)
	peerE, err := ecdh.X25519().NewPublicKey(eRaw)
	if err != nil {
		t.Fatal(err)
	}
	ee, err := eph.ECDH(peerE)
	if err != nil {
		t.Fatal(err)
	}
	machine := "nodekey:" + hex.EncodeToString(mine.PublicKey().Bytes())
	info := strings.Join([]string{a.A, machine, pub, ePub, a.E, hex.EncodeToString(nc), a.N}, "\n")
	bits, err := hkdf.Key(sha256.New, append(append([]byte{}, ss...), ee...), []byte(tailnetSalt), info, 64)
	if err != nil {
		t.Fatal(err)
	}
	proof := hmac.New(sha256.New, bits[32:])
	proof.Write([]byte(tailnetConfirm + a.S))
	got, _ := hex.DecodeString(a.M)
	if !hmac.Equal(proof.Sum(nil), got) {
		t.Fatal("the machine's proof does not check")
	}
	aead, err := tailnetAEAD(bits[:32])
	if err != nil {
		t.Fatal(err)
	}
	return &tnReader{t: t, url: url, sid: a.S, in: aead, out: bits[32:], peer: pub, static: static}, 200
}

func (c *tnReader) seal(q uint64, m, p string, body []byte) []byte {
	plain, _ := json.Marshal(map[string]any{"q": q, "m": m, "p": p, "b": base64.StdEncoding.EncodeToString(body)})
	nonce := make([]byte, 12)
	rand.Read(nonce)
	return append(nonce, c.in.Seal(nil, nonce, plain, []byte("c\n"+c.sid))...)
}

// parse reads sealed records: the inner status and the bytes, or an error for a
// cut-off answer or one that does not open.
func (c *tnReader) parse(q uint64, wire []byte) (int, []byte, error) {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], q)
	m := hmac.New(sha256.New, c.out)
	m.Write([]byte("r"))
	m.Write(seq[:])
	aead, err := tailnetAEAD(m.Sum(nil))
	if err != nil {
		return 0, nil, err
	}
	status, n := 0, uint64(0)
	var body []byte
	for len(wire) >= 4 {
		l := binary.BigEndian.Uint32(wire)
		if int(l) > len(wire)-4 {
			break
		}
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], n)
		n++
		rec, err := aead.Open(nil, nonce[:], wire[4:4+l], []byte("s\n"+c.sid))
		if err != nil {
			return 0, nil, fmt.Errorf("record %d: %w", n, err)
		}
		wire = wire[4+l:]
		switch rec[0] {
		case tnKindHead:
			var h struct{ S int }
			json.Unmarshal(rec[1:], &h)
			status = h.S
		case tnKindData:
			body = append(body, rec[1:]...)
		case tnKindEnd:
			return status, body, nil
		}
	}
	return 0, nil, errors.New("cut off")
}

func (c *tnReader) call(m, p string, body []byte) (int, []byte) {
	c.t.Helper()
	c.seq++
	st, wire := tnPost(c.t, c.url+"/tn/rpc?s="+c.sid, c.seal(c.seq, m, p, body))
	if st != 200 {
		c.t.Fatalf("%s %s: outer status %d", m, p, st)
	}
	inner, b, err := c.parse(c.seq, wire)
	if err != nil {
		c.t.Fatalf("%s %s: %v", m, p, err)
	}
	return inner, b
}

// tnBench is one machine with this reader's key on its list, behind a real
// HTTP server like the one runTailnet makes.
func tnBench(t *testing.T) (string, *ecdh.PrivateKey, string, *tailnetServer) {
	t.Helper()
	scratchHome(t)
	static, pub := tnNewKey(t)
	if err := allowClient(pub); err != nil {
		t.Fatal(err)
	}
	ts := &tailnetServer{sessions: map[string]*tnSession{}}
	ts.handler.Store(newDirectHandler())
	srv := httptest.NewServer(ts)
	t.Cleanup(srv.Close)
	return srv.URL, static, pub, ts
}

func TestTailnetSessionAndCORS(t *testing.T) {
	url, static, pub, _ := tnBench(t)
	c, st := tnOpenAs(t, url, static, pub)
	if st != 200 {
		t.Fatalf("a listed key: open answered %d", st)
	}
	inner, b := c.call("GET", "/v1/hello", nil)
	if inner != 200 {
		t.Fatalf("hello: inner status %d", inner)
	}
	f, err := transport.Decode(b)
	if err != nil || f.Type != transport.TypeHello {
		t.Fatalf("hello: %v %s", err, b)
	}
	var hello transport.Hello
	if err := json.Unmarshal(f.Body, &hello); err != nil || hello.Carrier != "tailnet" {
		t.Fatalf("hello's carrier: %v %+v", err, hello)
	}

	// Any origin may read: the answers mean nothing without a key.
	req, _ := http.NewRequest("POST", url+"/tn/open", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://panel.example")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.Header.Get("Access-Control-Allow-Origin") != "https://panel.example" || r.Header.Get("Vary") != "Origin" {
		t.Fatalf("CORS: %v", r.Header)
	}
	// Nothing but the two routes, and only POST.
	for _, p := range []string{"/", "/v1/hello", "/quota"} {
		g, err := http.Get(url + p)
		if err != nil {
			t.Fatal(err)
		}
		g.Body.Close()
		if g.StatusCode != 404 {
			t.Fatalf("GET %s answered %d", p, g.StatusCode)
		}
	}
	if st, _ := tnPost(t, url+"/v1/hello", nil); st != 404 {
		t.Fatalf("the tunnel's surface is open unsealed: %d", st)
	}
}

func TestTailnetRefusesWhoIsNotListed(t *testing.T) {
	url, _, _, ts := tnBench(t)
	other, otherPub := tnNewKey(t)
	if _, st := tnOpenAs(t, url, other, otherPub); st != 403 {
		t.Fatalf("a key not on the list: open answered %d", st)
	}
	if len(ts.sessions) != 0 {
		t.Fatalf("a refused key left %d sessions", len(ts.sessions))
	}
	// Claiming a listed key without holding it: the session opens, since the
	// machine cannot tell yet, and nothing can be done with it.
	_, listed := tnNewKey(t)
	if err := allowClient(listed); err != nil {
		t.Fatal(err)
	}
	eph, _ := tnNewKey(t)
	q, _ := json.Marshal(map[string]any{"v": 1, "c": listed, "e": hex.EncodeToString(eph.PublicKey().Bytes()), "n": strings.Repeat("ab", 16)})
	st, b := tnPost(t, url+"/tn/open", q)
	if st != 200 {
		t.Fatalf("open: %d", st)
	}
	var a struct{ S string }
	json.Unmarshal(b, &a)
	key32 := make([]byte, 32)
	rand.Read(key32)
	guess, _ := tailnetAEAD(key32)
	nonce := make([]byte, 12)
	plain, _ := json.Marshal(map[string]any{"q": 1, "m": "GET", "p": "/v1/hello", "b": ""})
	sealed := append(nonce, guess.Seal(nil, nonce, plain, []byte("c\n"+a.S))...)
	if st, b := tnPost(t, url+"/tn/rpc?s="+a.S, sealed); st != 400 || len(b) != 0 {
		t.Fatalf("a request not sealed to the session: %d %q", st, b)
	}
}

func TestTailnetRejectsReplayAndTampering(t *testing.T) {
	url, static, pub, _ := tnBench(t)
	c, _ := tnOpenAs(t, url, static, pub)
	sealed := c.seal(7, "GET", "/v1/hello", nil)
	rpc := url + "/tn/rpc?s=" + c.sid
	if st, _ := tnPost(t, rpc, sealed); st != 200 {
		t.Fatalf("first: %d", st)
	}
	if st, _ := tnPost(t, rpc, sealed); st != 400 {
		t.Fatalf("the same request again: %d", st)
	}
	if st, _ := tnPost(t, rpc, c.seal(7, "GET", "/v1/hello", nil)); st != 400 {
		t.Fatalf("the same number again: %d", st)
	}
	// Out of order is fine; another session's sealing is not.
	if st, _ := tnPost(t, rpc, c.seal(6, "GET", "/v1/hello", nil)); st != 200 {
		t.Fatalf("an earlier number not yet seen: %d", st)
	}
	flip := c.seal(8, "GET", "/v1/hello", nil)
	flip[len(flip)-1] ^= 1
	if st, _ := tnPost(t, rpc, flip); st != 400 {
		t.Fatalf("a changed request: %d", st)
	}
	c2, _ := tnOpenAs(t, url, static, pub)
	if st, _ := tnPost(t, rpc, c2.seal(9, "GET", "/v1/hello", nil)); st != 400 {
		t.Fatalf("another session's request: %d", st)
	}
	if st, _ := tnPost(t, url+"/tn/rpc?s=nope", c.seal(10, "GET", "/v1/hello", nil)); st != 410 {
		t.Fatalf("no such session: %d", st)
	}
	// An answer changed on the way does not open, and a cut one is not short.
	st, wire := tnPost(t, rpc, c.seal(11, "GET", "/v1/hello", nil))
	if st != 200 {
		t.Fatal(st)
	}
	bad := append([]byte{}, wire...)
	bad[10] ^= 1
	if _, _, err := c.parse(11, bad); err == nil {
		t.Fatal("a changed answer opened")
	}
	if _, _, err := c.parse(11, wire[:len(wire)-20]); err == nil {
		t.Fatal("a cut answer read as whole")
	}
	if _, _, err := c.parse(12, wire); err == nil {
		t.Fatal("an answer read as another request's")
	}
}

func TestTailnetSurfaceAndStruckKey(t *testing.T) {
	url, static, pub, ts := tnBench(t)
	c, _ := tnOpenAs(t, url, static, pub)
	for _, p := range []string{"/v1/pipe", "/v1/pair", "/nope"} {
		if inner, _ := c.call("POST", p, nil); inner != 404 {
			t.Fatalf("%s rides this road: %d", p, inner)
		}
	}
	// Struck from the list: the next request is told as the tunnel's gate tells
	// it, the session is gone, and no new one opens.
	var nk key.NodePublic
	if err := nk.UnmarshalText([]byte(pub)); err != nil {
		t.Fatal(err)
	}
	if err := disallowClient(pub); err != nil {
		t.Fatal(err)
	}
	if inner, _ := c.call("GET", "/v1/hello", nil); inner != 403 {
		t.Fatalf("a struck key: %d", inner)
	}
	if len(ts.sessions) != 0 {
		t.Fatalf("a struck key keeps %d sessions", len(ts.sessions))
	}
	if inner, _ := c.call("GET", "/v1/hello", nil); inner != 403 {
		t.Fatalf("after being struck: %d", inner)
	}
	if _, st := tnOpenAs(t, url, static, pub); st != 403 {
		t.Fatalf("a struck key opened again: %d", st)
	}
}

func TestTailnetEventsStreamSealed(t *testing.T) {
	url, static, pub, _ := tnBench(t)
	c, _ := tnOpenAs(t, url, static, pub)
	r, err := http.Post(url+"/tn/rpc?s="+c.sid, "text/plain", bytes.NewReader(c.seal(1, "GET", "/v1/events", nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	// Records come while the stream is open: the hello's frame, unasked, within a
	// moment and long before any end.
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], 1)
	m := hmac.New(sha256.New, c.out)
	m.Write([]byte("r"))
	m.Write(seq[:])
	aead, _ := tailnetAEAD(m.Sum(nil))
	read := func(n uint64) []byte {
		var l [4]byte
		if _, err := io.ReadFull(r.Body, l[:]); err != nil {
			t.Fatal(err)
		}
		ct := make([]byte, binary.BigEndian.Uint32(l[:]))
		if _, err := io.ReadFull(r.Body, ct); err != nil {
			t.Fatal(err)
		}
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], n)
		rec, err := aead.Open(nil, nonce[:], ct, []byte("s\n"+c.sid))
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	done := make(chan []byte, 1)
	go func() {
		if rec := read(0); rec[0] != tnKindHead {
			t.Errorf("first record kind %d", rec[0])
		}
		done <- read(1)
	}()
	select {
	case rec := <-done:
		if rec[0] != tnKindData || !bytes.HasPrefix(rec[1:], []byte("data: ")) || !bytes.Contains(rec, []byte(`"hello"`)) {
			t.Fatalf("second record: %q", rec[:min(len(rec), 80)])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no frame while the stream is open: nothing flushed")
	}
}

func TestTailnetPtyRoad(t *testing.T) {
	url, static, pub, ts := tnBench(t)
	c, _ := tnOpenAs(t, url, static, pub)
	if !ptySupported {
		t.Skip("no terminal on this platform")
	}
	if err := setConsole(true); err != nil {
		t.Fatal(err)
	}
	var nk key.NodePublic
	if err := nk.UnmarshalText([]byte(pub)); err != nil {
		t.Fatal(err)
	}
	hub := ts.handler.Load().ptys
	tok, _, why := hub.open(nk, nil, "80x24")
	if why != "" {
		t.Fatalf("no terminal: %s", why)
	}
	t.Cleanup(hub.endAll)
	// The shell's output as a sealed stream, read as it comes.
	c.seq++
	r, err := http.Post(url+"/tn/rpc?s="+c.sid, "text/plain", bytes.NewReader(c.seal(c.seq, "GET", "/v1/pty/out?s="+tok, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], c.seq)
	m := hmac.New(sha256.New, c.out)
	m.Write([]byte("r"))
	m.Write(seq[:])
	aead, _ := tailnetAEAD(m.Sum(nil))
	seen := make(chan string, 64)
	go func() {
		for n := uint64(0); ; n++ {
			var l [4]byte
			if _, err := io.ReadFull(r.Body, l[:]); err != nil {
				return
			}
			ct := make([]byte, binary.BigEndian.Uint32(l[:]))
			if _, err := io.ReadFull(r.Body, ct); err != nil {
				return
			}
			var nonce [12]byte
			binary.BigEndian.PutUint64(nonce[4:], n)
			rec, err := aead.Open(nil, nonce[:], ct, []byte("s\n"+c.sid))
			if err != nil {
				return
			}
			if rec[0] == tnKindData {
				seen <- string(rec[1:])
			}
		}
	}()
	// What is typed goes a piece at a time, as a page sends it: each piece a
	// request whose body ends, and the session stays.
	for _, piece := range []string{"echo $((6", "*7))tn", "-ok\n"} {
		if inner, b := c.call("POST", "/v1/pty/in?s="+tok, []byte(piece)); inner != 204 {
			t.Fatalf("typing %q: %d %s", piece, inner, b)
		}
	}
	got, deadline := "", time.After(10*time.Second)
	for !strings.Contains(got, "42tn-ok") {
		select {
		case s := <-seen:
			got += s
		case <-deadline:
			t.Fatalf("the shell's answer never came: %q", got)
		}
	}
	if inner, _ := c.call("POST", "/v1/pty/resize?s="+tok+"&c=100&r=30", nil); inner != 204 && inner != 200 {
		t.Fatalf("resize: %d", inner)
	}
	// A token that is not this key's is no session.
	if inner, _ := c.call("POST", "/v1/pty/in?s="+strings.Repeat("0", 32), []byte("x")); inner != 404 {
		t.Fatalf("no such token: %d", inner)
	}
}

func TestTailnetSeenWindow(t *testing.T) {
	s := &tnSession{}
	for _, q := range []uint64{1, 3, 2, 500} {
		if !s.fresh(q) {
			t.Fatalf("%d is new", q)
		}
	}
	for _, q := range []uint64{1, 3, 2, 500, 0} {
		if s.fresh(q) {
			t.Fatalf("%d seen twice", q)
		}
	}
	if !s.fresh(5000) {
		t.Fatal("a jump")
	}
	if s.fresh(5000 - tailnetWindow) {
		t.Fatal("older than the window is refused")
	}
	if !s.fresh(5000 - tailnetWindow + 1) {
		t.Fatal("inside the window")
	}
	// A position reused as the window moves past it is not an old one.
	if !s.fresh(5000 + tailnetWindow - 1) {
		t.Fatal("moved")
	}
	// The largest number there is must not wrap the walk to it.
	end := &tnSession{}
	done := make(chan bool, 1)
	go func() {
		ok := end.fresh(math.MaxUint64-1) && end.fresh(math.MaxUint64)
		done <- ok && !end.fresh(math.MaxUint64)
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("the top of the range")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the walk to the largest number never ended")
	}
	if s.fresh(5000 + tailnetWindow - 1) {
		t.Fatal("repeat")
	}
}

func TestTailnetSessionsAreBounded(t *testing.T) {
	ts := &tailnetServer{sessions: map[string]*tnSession{}}
	now := time.Now()
	for i := 0; i < tailnetSessions; i++ {
		id := fmt.Sprint(i)
		if !ts.seat(&tnSession{id: id, used: now.Add(time.Duration(i) * time.Second)}, now) {
			t.Fatal("room")
		}
	}
	if !ts.seat(&tnSession{id: "a", used: now}, now) {
		t.Fatal("the oldest idle one gives way")
	}
	if _, kept := ts.sessions["0"]; kept {
		t.Fatal("the oldest idle one stayed")
	}
	if len(ts.sessions) != tailnetSessions {
		t.Fatalf("%d sessions", len(ts.sessions))
	}
	// All in use: refused, not evicted.
	for _, s := range ts.sessions {
		s.active = 1
	}
	if ts.seat(&tnSession{id: "c", used: now}, now) {
		t.Fatal("a session in use was put out")
	}
	// Long unused ones are cleared on the way.
	for _, s := range ts.sessions {
		s.active = 0
		s.used = now.Add(-2 * tailnetIdle)
	}
	ts.seat(&tnSession{id: "d", used: now}, now)
	if len(ts.sessions) != 1 {
		t.Fatalf("%d left after the idle ones went", len(ts.sessions))
	}
}

// An open proves nothing, since a key's public half is not a secret: however many
// come, they take no seat from a session in use, and only the holder's first
// request makes one.
func TestTailnetOpensCostNoSeat(t *testing.T) {
	url, static, pub, ts := tnBench(t)
	c, _ := tnOpenAs(t, url, static, pub)
	c.call("GET", "/v1/hello", nil)
	for i := 0; i < tailnetSessions*3; i++ {
		eph, _ := tnNewKey(t)
		q, _ := json.Marshal(map[string]any{"v": 1, "c": pub, "e": hex.EncodeToString(eph.PublicKey().Bytes()), "n": strings.Repeat("ab", 16)})
		if st, _ := tnPost(t, url+"/tn/open", q); st != 200 {
			t.Fatalf("open: %d", st)
		}
	}
	if n := len(ts.sessions); n != 1 {
		t.Fatalf("opens took %d seats", n-1)
	}
	if inner, _ := c.call("GET", "/v1/hello", nil); inner != 200 {
		t.Fatalf("the session in use: %d", inner)
	}
	// A token past its time is no session, and one that was changed never was.
	c2, _ := tnOpenAs(t, url, static, pub)
	if ts.fromToken(c2.sid, time.Now().Add(2*tailnetUnproven)) != nil {
		t.Fatal("a token outlived its time")
	}
	if ts.fromToken(c2.sid[:len(c2.sid)-2]+"AA", time.Now()) != nil {
		t.Fatal("a changed token opened")
	}
	if ts.fromToken(strings.Repeat("A", tailnetMaxSID+1), time.Now()) != nil {
		t.Fatal("no limit on a token")
	}
}
