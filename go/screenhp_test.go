package main

import (
	"bytes"
	"encoding/binary"
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
	sps := []byte{0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9, 0x40, 0x50, 0x05, 0xbb, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0xc0, 0xf1, 0x83, 0x19, 0x60}
	pps := []byte{0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0}
	idr := append([]byte{0x65, 0x88}, bytes.Repeat([]byte{0xab}, 4000)...)
	p := append([]byte{0x41, 0xe0}, bytes.Repeat([]byte{0xcd}, 200)...)
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
		h := &applehp.MockHost{Username: "alice", Password: password, Width: 1280, Height: 720, SPS: sps, PPS: pps,
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
					if m["w"].(float64) != 1280 || m["cw"].(float64) != 1280 || m["codec"] != "avc" || m["input"] != true {
						t.Fatalf("live says %v", m)
					}
				}
			case swToVideoConfig:
				config = f.body
				if len(config) < 8 || config[0] != swCodecAVC || config[1] != 1 {
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
	// Clipboard text Screen Sharing takes, and text it does not: the viewer
	// hears of the second.
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

// A wrong password is told as such, and a second viewer while one is
// watching is told the Mac is busy.
func TestScreenHPAuthAndBusy(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")

	bad, badDone := newHPViewer(t, host.Port())
	bad.status(5 * time.Second)
	bad.control(map[string]any{"t": "open", "user": "alice", "password": "nope"})
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
	first.control(map[string]any{"t": "open", "user": "alice", "password": "pw"})
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
	second.control(map[string]any{"t": "open", "user": "alice", "password": "pw"})
	if m := second.status(10 * time.Second); m["s"] != "end" || m["why"] != "busy" {
		t.Fatalf("a second session got %v", m)
	}
	<-secondDone
	first.w.Close()
	<-firstDone
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

// Text with what Latin-1 has not is refused, and the viewer told.
func TestScreenHPClipboardRefused(t *testing.T) {
	t.Setenv(screenHPEnvVar, "on")
	hpLoopbackOnly(t)
	host := hpMock(t, "pw")
	v, done := newHPViewer(t, host.Port())
	v.status(5 * time.Second)
	v.control(map[string]any{"t": "open", "user": "alice", "password": "pw"})
	for {
		m := v.status(30 * time.Second)
		if m["s"] == "live" {
			break
		}
		if m["s"] == "end" {
			t.Fatalf("ended: %v", m)
		}
	}
	v.control(map[string]any{"t": "clip", "text": "\u4f60\u597d"})
	for {
		m := v.status(10 * time.Second)
		if m["s"] == "clip" {
			if m["ok"] != false {
				t.Fatalf("clip status %v", m)
			}
			break
		}
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
