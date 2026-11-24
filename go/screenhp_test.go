package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"subnsubmonitor/applehp"
)

// hpMock starts a stand-in for a Mac's Screen Sharing on a port whose UDP
// twin and the one after are free, where a stream session's sockets go.
func hpMock(t *testing.T, password string) *applehp.MockHost {
	t.Helper()
	// HEVC as an M1 Pro's Screen Sharing sent it (2026-11-25).
	vps, _ := hex.DecodeString("40010c01ffff040800000300be080000030000961b0240")
	sps, _ := hex.DecodeString("420101040800000300be080000030000969000384400498f8fc40ddc8a465cfe27e17f437ea5370c0d010080")
	pps, _ := hex.DecodeString("4401c072f05b24")
	idr := append([]byte{20 << 1, 0x01}, bytes.Repeat([]byte{0xab}, 4000)...)
	p := append([]byte{1 << 1, 0x01}, bytes.Repeat([]byte{0xcd}, 200)...)
	for i := 0; i < 40; i++ {
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := u.LocalAddr().(*net.UDPAddr).Port
		u2, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port + 1})
		u.Close()
		if err != nil {
			continue
		}
		u2.Close()
		h := &applehp.MockHost{Username: "alice", Password: password, Width: 1280, Height: 720, HEVC: true, VPS: vps, SPS: sps, PPS: pps,
			Frames: [][][]byte{{idr}, {p}, {p}, {p}, {p}, {p}, {p}, {p}}, FPS: 30, Audio: [][]byte{{1, 2, 3}}}
		if err := h.Listen("127.0.0.1:" + strconv.Itoa(port)); err != nil {
			continue
		}
		t.Cleanup(h.Close)
		return h
	}
	t.Fatal("no port for the mock host")
	return nil
}

// hpLoopbackOnly tries the loopback route alone, where the mock is.
func hpLoopbackOnly(t *testing.T) {
	t.Helper()
	hpRouteList = func() []hpRoute { return []hpRoute{{name: "lo", local: "127.0.0.1", host: "127.0.0.1"}} }
	t.Cleanup(func() { hpRouteList = hpRoutes })
}

type swFrame struct {
	kind byte
	body []byte
}

// hpViewer is the viewer's end of a session: what the helper says comes
// through frames, and what the viewer says is written to w.
type hpViewer struct {
	t      *testing.T
	w      net.Conn
	frames chan swFrame
}

func newHPViewer(t *testing.T, port int) (*hpViewer, chan struct{}) {
	t.Helper()
	helperEnd, viewerEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		screenHPCarry(helperEnd, newHPScreen(), port)
		helperEnd.Close()
		close(done)
	}()
	v := &hpViewer{t: t, w: viewerEnd, frames: make(chan swFrame, 4096)}
	go func() {
		defer close(v.frames)
		var head [4]byte
		for {
			if _, err := io.ReadFull(viewerEnd, head[:]); err != nil {
				return
			}
			n := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
			body := make([]byte, n)
			if _, err := io.ReadFull(viewerEnd, body); err != nil {
				return
			}
			v.frames <- swFrame{head[0], body}
		}
	}()
	t.Cleanup(func() { viewerEnd.Close() })
	return v, done
}

func (v *hpViewer) send(kind byte, body []byte) {
	v.t.Helper()
	if _, err := v.w.Write(hpWire(kind, body)); err != nil {
		v.t.Fatal(err)
	}
}

func (v *hpViewer) control(m map[string]any) {
	v.t.Helper()
	b, _ := json.Marshal(m)
	v.send(swFromControl, b)
}

// status waits for the next status, passing over other frames.
func (v *hpViewer) status(within time.Duration) map[string]any {
	v.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case f, ok := <-v.frames:
			if !ok {
				v.t.Fatal("the session ended without a status")
			}
			if f.kind != swToStatus {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(f.body, &m); err != nil {
				v.t.Fatalf("status is not JSON: %q", f.body)
			}
			return m
		case <-deadline:
			v.t.Fatal("no status")
		}
	}
}

func waitHP(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A session from the viewer's side: the hello, the sign-in, the frames as
// ScreenWire has them, and the pointer, keys, wheel and text reaching the Mac
// as Screen Sharing takes them.
func TestScreenHPSession(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	v, done := newHPViewer(t, host.Port())

	hello := v.status(5 * time.Second)
	if hello["s"] != "hello" || hello["signin"] != true || hello["v"].(float64) != 3 {
		t.Fatalf("hello %v", hello)
	}
	// The first word in two pieces: a frame is not a write.
	b, _ := json.Marshal(map[string]any{"t": "open", "codecs": []string{"hevc", "avc"}, "user": "alice", "password": "pw", "audio": true, "kbps": 6000})
	open := hpWire(swFromControl, b)
	if _, err := v.w.Write(open[:7]); err != nil {
		t.Fatal(err)
	}
	if _, err := v.w.Write(open[7:]); err != nil {
		t.Fatal(err)
	}

	seen := map[byte]int{}
	var config []byte
	live := false
	deadline := time.After(40 * time.Second)
	for !live || seen[swToVideoFrame] < 10 || seen[swToAudio] < 3 || seen[swToCursorStore] < 1 || seen[swToLayout] < 1 {
		select {
		case f, ok := <-v.frames:
			if !ok {
				t.Fatalf("the session ended: %v", seen)
			}
			seen[f.kind]++
			switch f.kind {
			case swToStatus:
				var m map[string]any
				json.Unmarshal(f.body, &m)
				switch m["s"] {
				case "end":
					t.Fatalf("the session ended: %v", m)
				case "live":
					live = true
					if m["w"].(float64) != 1280 || m["cw"].(float64) != 1280 || m["codec"] != "hevc" || m["input"] != true {
						t.Fatalf("live says %v", m)
					}
				}
			case swToVideoConfig:
				config = f.body
				if len(config) < 8 || config[0] != swCodecHEVC || config[1] != 1 {
					t.Fatalf("configuration %x", config)
				}
			case swToVideoFrame:
				if config == nil {
					t.Fatal("a frame came before the configuration")
				}
				if n := int(binary.BigEndian.Uint32(f.body[5:9])); 9+n > len(f.body) {
					t.Fatalf("a frame's first unit runs past it: %d of %d", n, len(f.body))
				}
			case swToAudio:
				if f.body[0] != swAudioELD || len(f.body) < 8 {
					t.Fatalf("audio %x", f.body)
				}
			case swToCursorStore:
				if len(f.body) < 13 || f.body[12] < 1 {
					t.Fatalf("cursor %x", f.body[:min(len(f.body), 13)])
				}
			case swToLayout:
				if len(f.body) != 8 {
					t.Fatalf("layout %x", f.body)
				}
			}
		case <-deadline:
			t.Fatalf("timed out: %v", seen)
		}
	}
	go func() {
		for range v.frames {
		}
	}()

	// The right button as ScreenWire has it (4) is Screen Sharing's 2.
	v.send(swFromPointer, []byte{4, 0, 100, 0, 50})
	waitHP(t, "the pointer", func() bool {
		for _, p := range host.Pointers() {
			if p.Mask == 2 && p.X == 100 && p.Y == 50 {
				return true
			}
		}
		return false
	})
	// Command is Super; a is a.
	v.send(swFromKey, []byte{1, 0, 0x37})
	v.send(swFromKey, []byte{1, 0, 0x00})
	v.send(swFromKey, []byte{0, 0, 0x00})
	v.send(swFromKey, []byte{0, 0, 0x37})
	// Fn has no keysym and is not sent.
	v.send(swFromKey, []byte{1, 0, 0x3F})
	v.control(map[string]any{"t": "text", "text": "\u00e9\u4e2d"})
	waitHP(t, "the keys", func() bool { return len(host.Keys()) >= 8 })
	want := []applehp.MockKey{{Down: true, Keysym: 0xffeb}, {Down: true, Keysym: 'a'}, {Down: false, Keysym: 'a'}, {Down: false, Keysym: 0xffeb},
		{Down: true, Keysym: 0xe9}, {Down: false, Keysym: 0xe9}, {Down: true, Keysym: 0x01004e2d}, {Down: false, Keysym: 0x01004e2d}}
	if got := host.Keys(); len(got) != len(want) {
		t.Fatalf("keys %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("keys %v, want %v", got, want)
			}
		}
	}
	// The wheel: 9 pixels down are two ticks, the one left over waits; the
	// right button is let go first (held, it would go with each tick).
	v.send(swFromPointer, []byte{0, 0, 100, 0, 50})
	waitHP(t, "the button let go", func() bool {
		ps := host.Pointers()
		return len(ps) > 0 && ps[len(ps)-1].Mask == 0
	})
	before := len(host.Pointers())
	v.send(swFromScroll, []byte{0, 0, 0, 9, 0, 10, 0, 20})
	waitHP(t, "the wheel", func() bool { return len(host.Pointers()) >= before+4 })
	ticks := 0
	for _, p := range host.Pointers()[before:] {
		if p.Mask == 0x10 && p.X == 10 && p.Y == 20 {
			ticks++
		}
	}
	if ticks != 2 {
		t.Fatalf("ticks %d in %v", ticks, host.Pointers()[before:])
	}

	// The quality at once: the media is offered again.
	offers, _, _ := host.Counts()
	v.control(map[string]any{"t": "kbps", "kbps": 3000})
	waitHP(t, "the second offer", func() bool { n, _, _ := host.Counts(); return n > offers })
	// Clipboard text Latin-1 holds, as cut text.
	v.control(map[string]any{"t": "clip", "text": "plain caf\u00e9"})
	waitHP(t, "the clipboard", func() bool { c := host.CutTexts(); return len(c) > 0 && c[len(c)-1] == "plain caf\u00e9" })

	// The viewer goes: so does the session, and the next may come.
	v.w.Close()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("the session did not end with its viewer")
	}
	if screenHPBusy.Load() {
		t.Fatal("the session ended and still holds the Mac")
	}
}

// High Performance is HEVC or nothing: a viewer that does not take it is
// told so before anything is asked of the Mac.
func TestScreenHPOnlyHEVC(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	for _, codecs := range [][]string{{"avc"}, nil} {
		v, _ := newHPViewer(t, host.Port())
		hello := v.status(5 * time.Second)
		if c, _ := hello["codecs"].([]any); len(c) != 1 || c[0] != "hevc" {
			t.Fatalf("hello offers %v", hello["codecs"])
		}
		v.control(map[string]any{"t": "open", "codecs": codecs, "user": "alice", "password": "pw"})
		for {
			m := v.status(10 * time.Second)
			if m["s"] == "end" {
				if m["why"] != "no-hp" {
					t.Fatalf("codecs %v ended with %v", codecs, m)
				}
				break
			}
			if m["s"] == "live" {
				t.Fatalf("codecs %v went live", codecs)
			}
		}
	}
}

// A wrong password is told as such, and a second viewer while one is
// watching is told the Mac is busy.
func TestScreenHPAuthAndBusy(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")

	bad, badDone := newHPViewer(t, host.Port())
	bad.status(5 * time.Second)
	bad.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "nope"})
	for {
		m := bad.status(30 * time.Second)
		if m["s"] == "end" {
			if m["why"] != "auth" {
				t.Fatalf("a wrong password ended with %v", m)
			}
			break
		}
	}
	<-badDone

	first, firstDone := newHPViewer(t, host.Port())
	first.status(5 * time.Second)
	first.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "pw"})
	for {
		m := first.status(30 * time.Second)
		if m["s"] == "live" {
			break
		}
		if m["s"] == "end" {
			t.Fatalf("the first session ended: %v", m)
		}
	}
	go func() {
		for range first.frames {
		}
	}()
	second, secondDone := newHPViewer(t, host.Port())
	second.status(5 * time.Second)
	second.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "pw"})
	if m := second.status(10 * time.Second); m["s"] != "end" || m["why"] != "busy" {
		t.Fatalf("a second session got %v", m)
	}
	<-secondDone
	first.w.Close()
	<-firstDone
}

// The stream's numbers come every two seconds once it is live; the viewer
// saying it observes reaches the Mac without ending anything.
func TestScreenHPStats(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	v, done := newHPViewer(t, host.Port())
	v.status(5 * time.Second)
	v.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "pw"})
	for {
		m := v.status(30 * time.Second)
		if m["s"] == "end" {
			t.Fatalf("ended: %v", m)
		}
		if m["s"] == "live" {
			break
		}
	}
	v.control(map[string]any{"t": "mode", "observe": true})
	for {
		m := v.status(6 * time.Second)
		if m["s"] == "end" {
			t.Fatalf("ended: %v", m)
		}
		if m["s"] == "stats" {
			if m["fps"].(float64) <= 0 || m["kbps"].(float64) <= 0 {
				t.Fatalf("stats %v", m)
			}
			break
		}
	}
	// Observe reached the Mac's Screen Sharing as its SetMode.
	if modes := host.Modes(); len(modes) != 1 || modes[0] {
		t.Fatalf("modes %v", modes)
	}
	v.w.Close()
	<-done
}

// Nothing comes from a viewer that never says its first word: the session
// is let go.
func TestScreenHPNoOpen(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	helperEnd, viewerEnd := net.Pipe()
	defer viewerEnd.Close()
	go io.Copy(io.Discard, viewerEnd)
	done := make(chan struct{})
	go func() {
		screenHPCarry(helperEnd, newHPScreen(), 1)
		close(done)
	}()
	viewerEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a session whose viewer left before opening did not end")
	}
}

// Text with what Latin-1 has not reaches the Mac's clipboard whole; text too
// long for one message does not go, and the viewer is told.
func TestScreenHPClipboardAnyText(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	v, done := newHPViewer(t, host.Port())
	v.status(5 * time.Second)
	v.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "pw"})
	for {
		m := v.status(30 * time.Second)
		if m["s"] == "live" {
			break
		}
		if m["s"] == "end" {
			t.Fatalf("ended: %v", m)
		}
	}
	v.control(map[string]any{"t": "clip", "text": "\u4f60\u597d\uff0c\u4e16\u754c \U0001f600"})
	waitHP(t, "the clipboard", func() bool {
		c := host.Clipboards()
		return len(c) == 1 && c[0] == "\u4f60\u597d\uff0c\u4e16\u754c \U0001f600"
	})
	// 80,000 characters that do not repeat: under the helper's limit, and
	// more than one message holds however it is packed.
	long := make([]rune, 80000)
	x := uint32(1)
	for i := range long {
		x = x*1664525 + 1013904223
		long[i] = rune(0x4e00 + (x>>8)%20000)
	}
	v.control(map[string]any{"t": "clip", "text": string(long)})
	for {
		m := v.status(10 * time.Second)
		if m["s"] == "clip" {
			if m["ok"] != false {
				t.Fatalf("clip status %v", m)
			}
			break
		}
	}
	if c := host.Clipboards(); len(c) != 1 {
		t.Fatalf("clipboards %d, want the first alone", len(c))
	}
	v.w.Close()
	<-done
}

// A size asked for while the session is still signing in is the size the
// display ends at: the viewer does not ask for it again.
func TestScreenHPSizeWhileSigningIn(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	v, done := newHPViewer(t, host.Port())
	v.status(5 * time.Second)
	v.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "pw", "own": true, "w": 1000, "h": 600, "scale": 1})
	v.control(map[string]any{"t": "size", "w": 1200, "h": 700, "scale": 2})
	want, got := [4]int{1200, 700, 2400, 1400}, [4]int{}
	deadline := time.After(45 * time.Second)
	for got != want {
		select {
		case f, ok := <-v.frames:
			if !ok {
				t.Fatalf("the session ended; layout %v", got)
			}
			if f.kind == swToLayout && len(f.body) == 8 {
				got = [4]int{int(binary.BigEndian.Uint16(f.body[0:2])), int(binary.BigEndian.Uint16(f.body[2:4])),
					int(binary.BigEndian.Uint16(f.body[4:6])), int(binary.BigEndian.Uint16(f.body[6:8]))}
			}
			if f.kind == swToStatus && bytes.Contains(f.body, []byte(`"end"`)) {
				t.Fatalf("ended: %s", f.body)
			}
		case <-deadline:
			t.Fatalf("layout %v, want %v", got, want)
		}
	}
	if r := host.Resizes(); len(r) == 0 || r[len(r)-1] != [2]int{1200, 700} {
		t.Fatalf("asked for %v", r)
	}
	v.w.Close()
	<-done
}

func TestMacKeysym(t *testing.T) {
	for code, want := range map[uint16]uint32{0x37: 0xffeb, 0x36: 0xffec, 0x3A: 0xffe7, 0x3D: 0xffe8, 0x3B: 0xffe3, 0x38: 0xffe1,
		0x00: 'a', 0x12: '1', 0x24: 0xff0d, 0x33: 0xff08, 0x75: 0xffff, 0x7E: 0xff52, 0x3F: 0} {
		if got := macKeysym(code); got != want {
			t.Errorf("macKeysym(%#x) = %#x, want %#x", code, got, want)
		}
	}
	for r, want := range map[rune]uint32{'a': 'a', 'é': 0xe9, '\u4e2d': 0x01004e2d, '\n': 0xff0d, '\t': 0xff09, 0x7f: 0, 0x85: 0, '😀': 0x0101f600} {
		if got := runeKeysym(r); got != want {
			t.Errorf("runeKeysym(%q) = %#x, want %#x", r, got, want)
		}
	}
}

// A display of the session's own at twice as many pixels as points: asked for
// in points, said so in live and in the layout (not the size of the display
// before it, which the handshake gives), and resized the same way.
func TestScreenHPOwnDisplay(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	v, done := newHPViewer(t, host.Port())
	v.status(5 * time.Second)
	v.control(map[string]any{"t": "open", "codecs": []string{"hevc"}, "user": "alice", "password": "pw", "own": true, "w": 1000, "h": 600, "scale": 2})
	layout := func(want [4]int, within time.Duration) map[string]any {
		t.Helper()
		var live map[string]any
		var got [4]int
		deadline := time.After(within)
		for got != want {
			select {
			case f, ok := <-v.frames:
				if !ok {
					t.Fatalf("the session ended; layout %v", got)
				}
				switch f.kind {
				case swToLayout:
					if len(f.body) == 8 {
						got = [4]int{int(binary.BigEndian.Uint16(f.body[0:2])), int(binary.BigEndian.Uint16(f.body[2:4])),
							int(binary.BigEndian.Uint16(f.body[4:6])), int(binary.BigEndian.Uint16(f.body[6:8]))}
					}
				case swToStatus:
					var m map[string]any
					json.Unmarshal(f.body, &m)
					if m["s"] == "end" {
						t.Fatalf("ended: %v", m)
					}
					if m["s"] == "live" {
						live = m
					}
				}
			case <-deadline:
				t.Fatalf("layout %v, want %v", got, want)
			}
		}
		return live
	}
	live := layout([4]int{1000, 600, 2000, 1200}, 30*time.Second)
	for live == nil {
		m := v.status(30 * time.Second)
		if m["s"] == "end" {
			t.Fatalf("ended: %v", m)
		}
		if m["s"] == "live" {
			live = m
		}
	}
	if live["w"].(float64) != 1000 || live["h"].(float64) != 600 || live["cw"].(float64) != 2000 {
		t.Fatalf("live says %v", live)
	}
	if r := host.Resizes(); len(r) != 1 || r[0] != [2]int{1000, 600} {
		t.Fatalf("asked for %v", r)
	}
	v.control(map[string]any{"t": "size", "w": 1200, "h": 700, "scale": 2})
	layout([4]int{1200, 700, 2400, 1400}, 30*time.Second)
	if r := host.Resizes(); r[len(r)-1] != [2]int{1200, 700} {
		t.Fatalf("asked for %v", r)
	}
	v.w.Close()
	<-done
}

// A standard session from the viewer's side: the hello offers it, no video
// and no sound come, the picture comes whole in pieces of deflated pixels
// and then where it changed, and the pointer reaches the Mac.
func TestScreenStandardSession(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	const w, h = 1280, 720
	host.Screen = make([]byte, w*h*4)
	for i := 0; i < w*h; i++ {
		host.Screen[i*4], host.Screen[i*4+1], host.Screen[i*4+2] = byte(i), byte(i>>8), byte(i>>16)
	}
	want := append([]byte(nil), host.Screen...)
	for i := 3; i < len(want); i += 4 {
		want[i] = 0xff
	}
	v, done := newHPViewer(t, host.Port())
	if hello := v.status(5 * time.Second); hello["s"] != "hello" || hello["standard"] != true {
		t.Fatalf("hello %v", hello)
	}
	v.control(map[string]any{"t": "open", "user": "alice", "password": "pw", "standard": true, "own": true, "audio": true})

	var fb []byte
	fw, fh, shown, pieces := 0, 0, 0, 0
	live := false
	// take reads frames until ok says so.
	take := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.After(40 * time.Second)
		for !ok() {
			select {
			case f, open := <-v.frames:
				if !open {
					t.Fatalf("the session ended waiting for %s", what)
				}
				switch f.kind {
				case swToStatus:
					var m map[string]any
					json.Unmarshal(f.body, &m)
					switch m["s"] {
					case "end":
						t.Fatalf("the session ended: %v", m)
					case "live":
						live = true
						if m["standard"] != true || m["audio"] != false || m["own"] != false || m["codec"] != "pixels" ||
							m["w"].(float64) != w || m["cw"].(float64) != w || m["ch"].(float64) != h {
							t.Fatalf("live says %v", m)
						}
					}
				case swToVideoConfig, swToVideoFrame, swToAudio:
					t.Fatalf("a standard session sent a frame of kind %d", f.kind)
				case swToLayout:
					pw, ph := int(binary.BigEndian.Uint16(f.body[4:6])), int(binary.BigEndian.Uint16(f.body[6:8]))
					if pw != fw || ph != fh {
						fw, fh, fb = pw, ph, make([]byte, pw*ph*4)
					}
				case swToPicture:
					if len(f.body) < 9 {
						t.Fatalf("picture frame of %d bytes", len(f.body))
					}
					x, y := int(binary.BigEndian.Uint16(f.body[0:2])), int(binary.BigEndian.Uint16(f.body[2:4]))
					rw, rh := int(binary.BigEndian.Uint16(f.body[4:6])), int(binary.BigEndian.Uint16(f.body[6:8]))
					if f.body[8]&1 != 0 {
						shown++
						continue
					}
					pieces++
					pix, err := io.ReadAll(flate.NewReader(bytes.NewReader(f.body[9:])))
					if err != nil || len(pix) != rw*rh*4 || x+rw > fw || y+rh > fh {
						t.Fatalf("piece %dx%d at %d,%d: %d bytes, %v (picture %dx%d)", rw, rh, x, y, len(pix), err, fw, fh)
					}
					if len(pix) > hpPictureBand {
						t.Fatalf("a piece of %d bytes of pixels", len(pix))
					}
					for r := 0; r < rh; r++ {
						copy(fb[((y+r)*fw+x)*4:], pix[r*rw*4:(r+1)*rw*4])
					}
				}
			case <-deadline:
				t.Fatalf("timed out waiting for %s (live %v, shown %d, pieces %d)", what, live, shown, pieces)
			}
		}
	}
	take("the whole picture", func() bool { return live && shown >= 1 && bytes.Equal(fb, want) })
	if pieces < 4 {
		t.Fatalf("the picture came in %d pieces", pieces)
	}
	before := shown
	if err := host.SendPicture(100, 50, 20, 10, bytes.Repeat([]byte{9, 8, 7, 0}, 200)); err != nil {
		t.Fatal(err)
	}
	at := (50*w + 100) * 4
	take("the rectangle that changed", func() bool { return shown > before && bytes.Equal(fb[at:at+4], []byte{9, 8, 7, 0xff}) })
	v.send(swFromPointer, []byte{1, 0, 40, 0, 30})
	waitHP(t, "the pointer", func() bool { p := host.Pointers(); return len(p) == 1 && p[0].X == 40 && p[0].Y == 30 })
	if offers, _, _ := host.Counts(); offers != 0 {
		t.Fatalf("a standard session offered media %d times", offers)
	}
	v.w.Close()
	<-done
}

func TestStandardRoutes(t *testing.T) {
	got := hpStandardRoutes([]hpRoute{
		{name: "a", local: "192.168.1.5"}, {name: "a-reuse", local: "192.168.1.5", reusePort: true},
		{name: "lo", local: "127.0.0.1"}, {name: "lo-reuse", local: "127.0.0.1", reusePort: true}})
	if len(got) != 2 || got[0].name != "lo" || got[1].name != "a" {
		t.Fatalf("routes %v", got)
	}
}
