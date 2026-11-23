package applehp

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func freeUDPPair(t *testing.T) (int, int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		p := a.LocalAddr().(*net.UDPAddr).Port
		b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p + 1})
		a.Close()
		if err != nil {
			continue
		}
		b.Close()
		return p, p + 1
	}
	t.Fatal("no two free UDP ports in a row")
	return 0, 0
}

// testFrames is a stream of made-up pictures: a key frame too long for one
// packet, then pictures that are not key frames.
func testFrames() (sps, pps []byte, frames [][][]byte) {
	sps = append([]byte{0x67}, AddEmulationPrevention(encodeTestSPS(100, 52, 8))...)
	pps = []byte{0x68, 0xce, 0x38, 0x80}
	idr := append([]byte{0x65, 0x88}, bytes.Repeat([]byte{0xab}, 5000)...)
	p1 := append([]byte{0x41, 0xe0}, bytes.Repeat([]byte{0xcd}, 300)...)
	p2 := append([]byte{0x41, 0xe0}, bytes.Repeat([]byte{0xef}, 1500)...)
	return sps, pps, [][][]byte{{idr}, {p1}, {p2}, {p1}, {p2}, {p1}}
}

type gathered struct {
	mu       sync.Mutex
	configs  int
	frames   int
	keys     int
	firstKey bool
	idrLen   int
	audio    [][]byte
	stores   int
	cursor   []byte
	selects  []uint32
	layouts  [][4]int
	clips    []string
}

func (g *gathered) handler() Handler {
	return Handler{
		VideoConfig: func(sps, pps []byte) { g.mu.Lock(); g.configs++; g.mu.Unlock() },
		VideoFrame: func(ts uint32, key bool, nalus [][]byte) {
			g.mu.Lock()
			if g.frames == 0 {
				g.firstKey = key
			}
			g.frames++
			if key {
				g.keys++
				g.idrLen = len(nalus[0])
			}
			g.mu.Unlock()
		},
		Audio: func(ts uint32, seq uint16, pt byte, payload []byte) {
			g.mu.Lock()
			if len(g.audio) < 64 {
				g.audio = append(g.audio, payload)
			}
			g.mu.Unlock()
		},
		CursorStore: func(id uint32, hx, hy, w, h int, rgba []byte) {
			g.mu.Lock()
			g.stores++
			g.cursor = append([]byte{byte(hx), byte(hy), byte(w), byte(h)}, rgba...)
			g.mu.Unlock()
		},
		CursorSelect: func(id uint32) { g.mu.Lock(); g.selects = append(g.selects, id); g.mu.Unlock() },
		Layout: func(sw, sh, bw, bh int) {
			g.mu.Lock()
			g.layouts = append(g.layouts, [4]int{sw, sh, bw, bh})
			g.mu.Unlock()
		},
		Clipboard: func(s string) { g.mu.Lock(); g.clips = append(g.clips, s); g.mu.Unlock() },
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunAgainstMockHost(t *testing.T) {
	sps, pps, frames := testFrames()
	cp, vp := freeUDPPair(t)
	host := &MockHost{Username: "alice", Password: "pw", Width: 1280, Height: 720, SPS: sps, PPS: pps, Frames: frames, FPS: 30,
		Audio: [][]byte{{1, 2, 3}, {4, 5, 6, 7}}, ClientCtrlPort: cp, ClientVideoPort: vp}
	if err := host.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	cfg := DefaultConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = host.Port()
	cfg.Username, cfg.Password = "alice", "pw"
	cfg.UDPBindAddr = "127.0.0.1"
	cfg.UDPCtrlPort, cfg.UDPVideoPort = cp, vp
	cfg.WarmupTCP = false
	cfg.AudioEnabled = true
	cfg.Curtain = true
	cfg.Width, cfg.Height = 1280, 720
	cfg.MaxBitrate = 8_000_000

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	sess, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sess.Close()
	if sess.CanvasW != 1280 || sess.CanvasH != 720 {
		t.Fatalf("canvas %dx%d", sess.CanvasW, sess.CanvasH)
	}
	g := &gathered{}
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- sess.Run(runCtx, g.handler()) }()

	waitFor(t, "pictures and sound", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.frames >= 8 && g.keys >= 1 && len(g.audio) >= 4 && g.stores == 1 && len(g.selects) >= 2 && len(g.layouts) >= 1
	})
	g.mu.Lock()
	if !g.firstKey || g.configs != 1 || g.idrLen != 5002 {
		t.Fatalf("first frame key=%v configs=%d idr=%d", g.firstKey, g.configs, g.idrLen)
	}
	if !bytes.Equal(g.audio[0][:1], []byte{1}) && !bytes.Equal(g.audio[0][:1], []byte{4}) {
		t.Fatalf("audio payload %x", g.audio[0])
	}
	// Hot spot 1,1; 2 by 2; red at half alpha.
	if want := append([]byte{1, 1, 2, 2}, bytes.Repeat([]byte{0xff, 0, 0, 0x80}, 4)...); !bytes.Equal(g.cursor, want) {
		t.Fatalf("cursor %x", g.cursor)
	}
	if g.layouts[0] != [4]int{1280, 720, 1280, 720} {
		t.Fatalf("layout %v", g.layouts[0])
	}
	g.mu.Unlock()
	if _, arms, _ := host.Counts(); arms < 2 {
		t.Fatalf("armed %d times, want one at the start and one for the layout", arms)
	}

	// What a viewer sends arrives as it was sent.
	if err := sess.SendPointer(1, 640, 360); err != nil {
		t.Fatal(err)
	}
	if err := sess.SendKey(true, 0xff0d); err != nil {
		t.Fatal(err)
	}
	if err := sess.SendKey(false, 0xff0d); err != nil {
		t.Fatal(err)
	}
	if err := sess.SendCutText("café"); err != nil {
		t.Fatal(err)
	}
	if err := sess.SendCutText("\u4f60\u597d"); err == nil {
		t.Fatal("text outside Latin-1 was sent as cut text")
	}
	// Text Latin-1 holds goes as cut text; any other as a whole clipboard,
	// which the host reads as the Mac does.
	if err := sess.SendClipboard("na\u00efve"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"\u4f60\u597d\uff0c\u4e16\u754c", "caf\u00e9 \U0001f600\n\u65e5\u672c\u8a9e"} {
		if err := sess.SendClipboard(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := sess.SendClipboard("\u4f60\xff"); err == nil {
		t.Fatal("text that is not UTF-8 was sent")
	}
	waitFor(t, "the viewer's input", func() bool {
		return len(host.Pointers()) == 1 && len(host.Keys()) == 2 && len(host.CutTexts()) == 2 && len(host.Clipboards()) == 2
	})
	if c := host.CutTexts()[1]; c != "na\u00efve" {
		t.Fatalf("cut text %q", c)
	}
	if c := host.Clipboards(); c[0] != "\u4f60\u597d\uff0c\u4e16\u754c" || c[1] != "caf\u00e9 \U0001f600\n\u65e5\u672c\u8a9e" {
		t.Fatalf("clipboards %q", c)
	}
	if p := host.Pointers()[0]; p != (MockPointer{1, 640, 360}) {
		t.Fatalf("pointer %+v", p)
	}
	if k := host.Keys(); !k[0].Down || k[0].Keysym != 0xff0d || k[1].Down {
		t.Fatalf("keys %+v", k)
	}
	if c := host.CutTexts()[0]; c != "café" {
		t.Fatalf("cut text %q", c)
	}

	// The host's clipboard, twice: the second rides the same zlib stream or
	// its own, and is read either way.
	for _, s := range []string{"one \u4f60\u597d", "two"} {
		if err := host.SendClipboard(s); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the clipboard", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.clips) == 2 })
	g.mu.Lock()
	if g.clips[0] != "one \u4f60\u597d" || g.clips[1] != "two" {
		t.Fatalf("clipboard %q", g.clips)
	}
	keysBefore, framesBefore := g.keys, g.frames
	g.mu.Unlock()

	// A new size: asked for, answered with a layout, offered for again, and
	// the pictures come back from a key frame.
	if err := sess.Resize(1600, 900, 1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the resized stream", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		last := g.layouts[len(g.layouts)-1]
		return last == [4]int{1600, 900, 1600, 900} && g.keys > keysBefore && g.frames > framesBefore+5
	})
	if offers, _, _ := host.Counts(); offers != 2 {
		t.Fatalf("offers %d, want 2", offers)
	}
	if r := host.Resizes(); len(r) < 2 || r[len(r)-1] != [2]int{1600, 900} {
		t.Fatalf("resizes %v", r)
	}
	sess.runMu.Lock()
	cw, ch := sess.CanvasW, sess.CanvasH
	sess.runMu.Unlock()
	if cw != 1600 || ch != 900 {
		t.Fatalf("canvas after resize %dx%d", cw, ch)
	}
	if st := sess.Stats(); st.VideoBad != 0 || st.AudioBad != 0 || st.Frames == 0 {
		t.Fatalf("stats %+v", st)
	}

	stopRun()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestRunEndsWithTheHost(t *testing.T) {
	sps, pps, frames := testFrames()
	cp, vp := freeUDPPair(t)
	host := &MockHost{Username: "alice", Password: "pw", SPS: sps, PPS: pps, Frames: frames, ClientCtrlPort: cp, ClientVideoPort: vp}
	if err := host.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	cfg := DefaultConfig()
	cfg.Host, cfg.Port = "127.0.0.1", host.Port()
	cfg.Username, cfg.Password = "alice", "wrong"
	cfg.UDPBindAddr, cfg.UDPCtrlPort, cfg.UDPVideoPort = "127.0.0.1", cp, vp
	cfg.WarmupTCP = false
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := Connect(ctx, cfg); err == nil {
		t.Fatal("a wrong password signed in")
	}
	cfg.Password = "pw"
	sess, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sess.Close()
	if err := sess.Resize(1600, 900, 1); err == nil {
		t.Fatal("a session on the physical display took a resize")
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(ctx, Handler{}) }()
	time.Sleep(300 * time.Millisecond)
	host.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run ended without an error when the host went")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not notice the host going")
	}
}

func TestChunkInflater(t *testing.T) {
	a := bytes.Repeat([]byte{1, 2, 3, 4}, 50)
	b := bytes.Repeat([]byte{9, 8, 7}, 40)
	// One stream, flushed after each piece.
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(a)
	zw.Flush()
	p1 := append([]byte(nil), zb.Bytes()...)
	zb.Reset()
	zw.Write(b)
	zw.Flush()
	p2 := append([]byte(nil), zb.Bytes()...)
	c := &chunkInflater{}
	if got, err := c.inflate(p1, len(a)); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("first piece: %v", err)
	}
	if got, err := c.inflate(p2, len(b)); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("second piece of one stream: %v", err)
	}
	// A stream per piece.
	whole := func(d []byte) []byte {
		var z bytes.Buffer
		w := zlib.NewWriter(&z)
		w.Write(d)
		w.Close()
		return z.Bytes()
	}
	c = &chunkInflater{}
	if got, err := c.inflate(whole(a), len(a)); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("first whole stream: %v", err)
	}
	if got, err := c.inflate(whole(b), len(b)); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("second whole stream: %v", err)
	}
	if _, err := c.inflate([]byte{1, 2, 3}, 10); err == nil {
		t.Fatal("rubbish inflated")
	}
}

func TestParseUpdateAcrossRecords(t *testing.T) {
	host := &MockHost{Width: 800, Height: 600, BackingW: 1600, BackingH: 1200}
	msg := host.metadata()
	rc, err := NewRecordCipher(make([]byte, 36), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	// The layout's arming is written somewhere: a connection nobody reads.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	tc, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	s := &Session{Cipher: rc, tcp: tc.(*net.TCPConn)}
	// Cut anywhere, the head asks for more and hands nothing over.
	for cut := 4; cut < len(msg); cut += 7 {
		var n int
		h := Handler{CursorSelect: func(uint32) { n++ }, CursorStore: func(uint32, int, int, int, int, []byte) { n++ },
			Layout: func(int, int, int, int) { n++ }}
		if _, st := s.parseUpdate(msg[:cut], &runState{}, h); st != parseMore {
			t.Fatalf("cut at %d of %d: status %v", cut, len(msg), st)
		}
		if n != 0 {
			t.Fatalf("cut at %d: %d events handed over early", cut, n)
		}
	}
	// Whole, it is all handed over, in order.
	var got []string
	h := Handler{
		Layout:       func(sw, sh, bw, bh int) { got = append(got, "layout") },
		CursorStore:  func(uint32, int, int, int, int, []byte) { got = append(got, "store") },
		CursorSelect: func(uint32) { got = append(got, "select") },
	}
	rs := &runState{}
	if n, st := s.parseUpdate(msg, rs, h); st != parseOK || n != len(msg) {
		t.Fatalf("whole update: took %d of %d, status %v", n, len(msg), st)
	}
	if want := "layout store select select"; strings.Join(got, " ") != want {
		t.Fatalf("events %q, want %q", strings.Join(got, " "), want)
	}
	if rs.scaledW != 800 || rs.backingH != 1200 {
		t.Fatalf("layout kept as %dx%d / %dx%d", rs.scaledW, rs.scaledH, rs.backingW, rs.backingH)
	}
	// An encoding nobody knows ends the update there, keeping what came
	// before it.
	bad := append([]byte(nil), msg...)
	binary.BigEndian.PutUint16(bad[2:4], 5)
	bad = append(bad, make([]byte, 12)...)
	binary.BigEndian.PutUint32(bad[len(bad)-4:], 0x7777)
	var n int
	if _, st := s.parseUpdate(bad, &runState{}, Handler{CursorSelect: func(uint32) { n++ }}); st != parseLost || n != 2 {
		t.Fatalf("unknown encoding: status %v, %d cursor events", st, n)
	}
}

// A display of the session's own on a Mac that reads a mode the other way
// round, and on one that makes the size asked for only at a pixel a point:
// the session asks again until the display is the size it asked for, and the
// pointer goes to the display's pixels.
func TestOwnDisplayIsTheSizeAskedFor(t *testing.T) {
	defer hostForm.Store(formPointsFirst)
	for _, c := range []struct {
		name               string
		pixelsFirst, plain bool
		first, second      [4]int
		asks               int
		pointer            [2]int
	}{
		{"points first", false, false, [4]int{1000, 600, 2000, 1200}, [4]int{1200, 700, 2400, 1400}, 2, [2]int{801, 601}},
		{"pixels first", true, false, [4]int{1000, 600, 2000, 1200}, [4]int{1200, 700, 2400, 1400}, 3, [2]int{801, 601}},
		{"a pixel a point", false, true, [4]int{1000, 600, 1000, 600}, [4]int{1200, 700, 1200, 700}, 4, [2]int{400, 300}},
	} {
		t.Run(c.name, func(t *testing.T) {
			hostForm.Store(formPointsFirst)
			sps, pps, frames := testFrames()
			cp, vp := freeUDPPair(t)
			host := &MockHost{Username: "alice", Password: "pw", Width: 1280, Height: 720, SPS: sps, PPS: pps, Frames: frames, FPS: 30,
				ClientCtrlPort: cp, ClientVideoPort: vp, PixelsFirst: c.pixelsFirst, PlainOnly: c.plain}
			if err := host.Listen("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			cfg := DefaultConfig()
			cfg.Host, cfg.Port = "127.0.0.1", host.Port()
			cfg.Username, cfg.Password = "alice", "pw"
			cfg.UDPBindAddr, cfg.UDPCtrlPort, cfg.UDPVideoPort = "127.0.0.1", cp, vp
			cfg.WarmupTCP = false
			cfg.Curtain = true
			cfg.Width, cfg.Height, cfg.HiDPIScale = 1000, 600, 2
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			sess, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			defer sess.Close()
			g := &gathered{}
			done := make(chan error, 1)
			go func() { done <- sess.Run(ctx, g.handler()) }()
			settled := func(want [4]int) {
				t.Helper()
				waitFor(t, fmt.Sprintf("a display of %v", want), func() bool {
					g.mu.Lock()
					defer g.mu.Unlock()
					return len(g.layouts) > 0 && g.layouts[len(g.layouts)-1] == want
				})
				// Nothing more is asked for once it is.
				time.Sleep(2 * displaySettle)
				g.mu.Lock()
				defer g.mu.Unlock()
				if last := g.layouts[len(g.layouts)-1]; last != want {
					t.Fatalf("the display went on to %v, want %v", last, want)
				}
			}
			settled(c.first)
			if err := sess.SendPointer(0, 400, 300); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the pointer", func() bool { return len(host.Pointers()) == 1 })
			if p := host.Pointers()[0]; p.X != c.pointer[0] || p.Y != c.pointer[1] {
				t.Fatalf("the pointer went to %d,%d, want %v", p.X, p.Y, c.pointer)
			}
			// Another size is asked for the way the host took the first.
			before := len(host.Resizes())
			if err := sess.Resize(1200, 700, 2); err != nil {
				t.Fatal(err)
			}
			settled(c.second)
			if n := len(host.Resizes()) - before; n != 1 {
				t.Fatalf("the second size took %d asks, want 1", n)
			}
			if n := len(host.Resizes()); n != c.asks {
				t.Fatalf("%d asks in all, want %d", n, c.asks)
			}
			cancel()
			<-done
		})
	}
}

// A standard session: no media is offered, the picture comes whole as
// rectangles of pixels (deflated and raw, across records) and then where it
// changed, whichever way round the host writes a pixel, and the pointer still
// goes.
func TestStandardSession(t *testing.T) {
	for _, big := range []bool{false, true} {
		host := &MockHost{Username: "alice", Password: "pw", Width: 320, Height: 200, PixelsBig: big}
		if err := host.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		cfg := DefaultConfig()
		cfg.Host, cfg.Port = "127.0.0.1", host.Port()
		cfg.Username, cfg.Password = "alice", "pw"
		cfg.WarmupTCP = false
		cfg.Standard = true
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		sess, err := Connect(ctx, cfg)
		if err != nil {
			t.Fatalf("Connect (big %v): %v", big, err)
		}
		var mu sync.Mutex
		var fb []byte
		fw, fh, ends, sizes, stores, rows := 0, 0, 0, 0, 0, 0
		h := Handler{
			PictureSize: func(w, h int) {
				mu.Lock()
				fw, fh, fb = w, h, make([]byte, w*h*4)
				sizes++
				mu.Unlock()
			},
			Picture: func(x, y, w, h int, pix []byte) {
				mu.Lock()
				defer mu.Unlock()
				if x+w > fw || y+h > fh || len(pix) != w*h*4 {
					t.Errorf("rectangle %dx%d at %d,%d with %d bytes, in a picture of %dx%d", w, h, x, y, len(pix), fw, fh)
					return
				}
				for r := 0; r < h; r++ {
					copy(fb[((y+r)*fw+x)*4:], pix[r*w*4:(r+1)*w*4])
				}
				rows += h
			},
			PictureEnd:  func() { mu.Lock(); ends++; mu.Unlock() },
			CursorStore: func(uint32, int, int, int, int, []byte) { mu.Lock(); stores++; mu.Unlock() },
		}
		runCtx, stopRun := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- sess.Run(runCtx, h) }()

		want := append([]byte(nil), host.screen()...)
		for i := 3; i < len(want); i += 4 {
			want[i] = 0xff
		}
		waitFor(t, "the whole picture", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return ends >= 1 && stores == 1 && fw == 320 && fh == 200 && bytes.Equal(fb, want)
		})
		if err := host.SendPicture(7, 9, 10, 5, bytes.Repeat([]byte{1, 2, 3, 0}, 50)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the rectangle that changed", func() bool {
			mu.Lock()
			defer mu.Unlock()
			at := (9*320 + 7) * 4
			return bytes.Equal(fb[at:at+4], []byte{1, 2, 3, 0xff}) && bytes.Equal(fb[at-4:at], want[at-4:at])
		})
		if err := sess.SendPointer(1, 5, 6); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the pointer", func() bool { p := host.Pointers(); return len(p) == 1 && p[0] == MockPointer{1, 5, 6} })
		if offers, arms, _ := host.Counts(); offers != 0 || arms < 1 {
			t.Fatalf("offers %d, arms %d", offers, arms)
		}
		if st := sess.Stats(); st.Frames < 2 || st.Bytes == 0 {
			t.Fatalf("stats %+v", st)
		}
		// Every picture the armings brought has been read (two rectangles
		// each), so nothing more comes but what is sent from here.
		waitFor(t, "the armings' pictures", func() bool { _, arms, _ := host.Counts(); return sess.Stats().Pictures >= 2*arms+1 })
		// A rectangle sent twice is the viewer's once: the second time it
		// has it. The whole picture the viewer asks for again is, all of it.
		twice := bytes.Repeat([]byte{4, 5, 6, 0}, 50)
		if err := host.SendPicture(7, 9, 10, 5, twice); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the rectangle sent once", func() bool {
			mu.Lock()
			defer mu.Unlock()
			at := (9*320 + 7) * 4
			return bytes.Equal(fb[at:at+4], []byte{4, 5, 6, 0xff})
		})
		mu.Lock()
		was := ends
		mu.Unlock()
		same, frames := sess.Stats().Same, sess.Stats().Frames
		if err := host.SendPicture(7, 9, 10, 5, twice); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the rectangle sent again", func() bool { return sess.Stats().Same > same })
		mu.Lock()
		if ends != was || sess.Stats().Frames != frames {
			t.Fatalf("a rectangle the viewer had was passed on: %d updates ended, %d before", ends, was)
		}
		rows = 0
		mu.Unlock()
		// One row of a rectangle changed: that row alone.
		again := append([]byte(nil), twice...)
		copy(again[2*10*4:], bytes.Repeat([]byte{9, 8, 7, 0}, 10))
		if err := host.SendPicture(7, 9, 10, 5, again); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the row that changed", func() bool {
			mu.Lock()
			defer mu.Unlock()
			at := (11*320 + 7) * 4
			return rows == 1 && bytes.Equal(fb[at:at+4], []byte{9, 8, 7, 0xff})
		})
		mu.Lock()
		rows = 0
		mu.Unlock()
		sess.RequestKeyframe()
		waitFor(t, "the whole picture again", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return rows >= 200
		})
		mu.Lock()
		if sizes != 1 {
			t.Fatalf("the picture's size was said %d times", sizes)
		}
		mu.Unlock()
		if err := sess.SetMaxBitrate(1_000_000); err != nil {
			t.Fatal(err)
		}
		stopRun()
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if offers, _, _ := host.Counts(); offers != 0 {
			t.Fatal("a standard session offered media")
		}
		cancel()
		sess.Close()
		host.Close()
	}
}

func TestPixelFormats(t *testing.T) {
	// Five, six and five bits, low byte first: all red, then all blue.
	f := PixelFormat{BitsPerPixel: 16, Depth: 16, TrueColor: true, RedMax: 31, GreenMax: 63, BlueMax: 31, RedShift: 11, GreenShift: 5}
	if !f.usable() {
		t.Fatal("16 bits not usable")
	}
	if got := f.bgra([]byte{0x00, 0xf8, 0x1f, 0x00}, 2); !bytes.Equal(got, []byte{0, 0, 255, 255, 255, 0, 0, 255}) {
		t.Fatalf("16 bits: %v", got)
	}
	if (PixelFormat{BitsPerPixel: 8}).usable() || (PixelFormat{}).usable() {
		t.Fatal("a format with no colors of its own is usable")
	}
	if got := parsePixelFormat(BuildSetPixelFormat(pixelsBGRX)[4:]); got != pixelsBGRX {
		t.Fatalf("format written and read: %+v", got)
	}
}
