package applehp

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The answer a 2018 Mac mini (Macmini8,1, Intel, macOS 15) gave an H.264 offer on 2026-11-22: a
// framebuffer update whose 0x3f2 rectangle holds the audio plist and then the video plist. The
// size is only in the second.
func TestRealAnswerCanvas(t *testing.T) {
	raw, err := os.ReadFile("testdata/answer-macmini8-1-h264.hex")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if blobs := ExtractPlistMediaBlobs(msg); len(blobs) != 2 {
		t.Fatalf("plists with a media blob = %d, want 2", len(blobs))
	}
	if w, h, _, ok := canvasFromBlob(ExtractPlistMediaBlobs(msg)[0]); ok {
		t.Fatalf("the audio plist gave a size (%dx%d)", w, h)
	}
	w, h, _, ok := ExtractCanvasDims(msg)
	if !ok || w != 1920 || h != 1080 {
		t.Fatalf("ExtractCanvasDims = (%d,%d,%v), want 1920x1080", w, h, ok)
	}
}

func srpChallengeBody() []byte {
	body := []byte{0x00, 0x02, 0x00}
	body = append(body, make([]byte, srpModulusLen)...)
	body[3] = 0xff
	body = append(body, 0x00, 0x01, 0x05, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x02, 0x00)
	b := make([]byte, srpModulusLen)
	b[srpModulusLen-1] = 7
	body = append(body, b...)
	body = append(body, 0, 0, 0, 0, 0, 0, 0x03, 0xe8)
	opt := "mda=SHA-512"
	body = append(body, 0x00, byte(len(opt)))
	return append(body, opt...)
}

// The SRP challenge as macOS 15 frames it (a 10-byte header) and as the specification has it
// (9 bytes); a header whose length word matches neither is refused.
func TestSRPChallengeHeaders(t *testing.T) {
	body := srpChallengeBody()
	n := len(body)
	ten := append([]byte{0x00, 0x00, 0x00, 0x02, byte((n + 4) >> 8), byte(n + 4), 0, 0, byte(n >> 8), byte(n)}, body...)
	nine := append([]byte{0x02, 0, 0, byte((n + 4) >> 8), byte(n + 4), 0, 0, byte(n >> 8), byte(n)}, body...)
	for name, msg := range map[string][]byte{"ten": ten, "nine": nine} {
		ch, err := parseSRPChallenge(msg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ch.g.Int64() != 5 || len(ch.salt) != 32 || ch.iterations != 1000 || string(ch.cap) != "mda=SHA-512" || ch.Nb[0] != 0xff || ch.B.Int64() != 7 {
			t.Fatalf("%s: parsed g=%v salt=%d iterations=%d cap=%q N[0]=%x B=%v", name, ch.g, len(ch.salt), ch.iterations, ch.cap, ch.Nb[0], ch.B)
		}
	}
	bad := append([]byte(nil), ten...)
	bad[9]++
	if _, err := parseSRPChallenge(bad); err == nil {
		t.Fatal("a challenge whose length matches neither header was taken")
	}
}

// A blob that says a field is longer than it is, or longer than anything can be, gives no size
// and does not panic.
func TestCanvasFromHostileBlob(t *testing.T) {
	for _, raw := range [][]byte{
		{0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0x2a, 0x04, 0x22, 0xff, 0xff, 0x7f},
		{0x2a, 0x7f, 0x20, 0x80, 0x05},
	} {
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		zw.Write(raw)
		zw.Close()
		if w, h, _, ok := canvasFromBlob(zb.Bytes()); ok {
			t.Fatalf("%x gave %dx%d", raw, w, h)
		}
	}
	if pls := answerPlists([]byte{0x00, 0x12, 0, 2, 0, 9, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}); pls != nil {
		t.Fatal("nine plists in five slots were taken")
	}
}
