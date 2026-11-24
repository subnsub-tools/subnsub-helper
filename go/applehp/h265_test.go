package applehp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The parameter sets an M1 Pro's Screen Sharing sent (macOS 27.2.1, one tile,
// 2026-11-25): Range Extensions, level 5, 4:4:4, 8 bits.
var (
	testHEVCVPS, _ = hex.DecodeString("40010c01ffff040800000300be080000030000961b0240")
	testHEVCSPS, _ = hex.DecodeString("420101040800000300be080000030000969000384400498f8fc40ddc8a465cfe27e17f437ea5370c0d010080")
	testHEVCPPS, _ = hex.DecodeString("4401c072f05b24")
)

func TestReassembleHEVC(t *testing.T) {
	ap := []byte{HEVCNALAP << 1, 1}
	for _, u := range [][]byte{testHEVCVPS, testHEVCSPS, testHEVCPPS} {
		ap = binary.BigEndian.AppendUint16(ap, uint16(len(u)))
		ap = append(ap, u...)
	}
	idr := append([]byte{20 << 1, 1}, bytes.Repeat([]byte{0xab}, 3000)...)
	var pays [][]byte
	pays = append(pays, ap)
	rest := idr[2:]
	for first := true; len(rest) > 0; first = false {
		n := min(len(rest), 1200)
		fh := byte(20)
		if first {
			fh |= 0x80
		}
		if n == len(rest) {
			fh |= 0x40
		}
		pays = append(pays, append([]byte{HEVCNALFU << 1, 1, fh}, rest[:n]...))
		rest = rest[n:]
	}
	trail := []byte{1 << 1, 1, 0xd0, 0x02}
	pays = append(pays, trail)
	got := ReassembleHEVC(pays)
	want := [][]byte{testHEVCVPS, testHEVCSPS, testHEVCPPS, idr, trail}
	if len(got) != len(want) {
		t.Fatalf("%d units, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("unit %d: %x…, want %x…", i, got[i][:min(8, len(got[i]))], want[i][:min(8, len(want[i]))])
		}
	}
	if !HEVCIsKey(HEVCNALType(idr[0])) || HEVCIsKey(HEVCNALType(trail[0])) {
		t.Fatal("key frames misread")
	}
	// A fragment whose start was lost is let go.
	if got := ReassembleHEVC(pays[2:3]); len(got) != 0 {
		t.Fatalf("a middle fragment alone made %d units", len(got))
	}
}

func TestHEVCDecoderRecord(t *testing.T) {
	b := HEVCDecoderRecord(testHEVCVPS, testHEVCSPS, testHEVCPPS)
	if len(b) < 23 || b[0] != 1 {
		t.Fatalf("record %x", b)
	}
	if b[1]&0x1f != 4 || b[12] != 150 {
		t.Fatalf("profile %d level %d, want 4 and 150", b[1]&0x1f, b[12])
	}
	if b[16]&3 != 3 || b[17]&7 != 0 || b[18]&7 != 0 {
		t.Fatalf("chroma %d depths %d %d, want 4:4:4 at 8 bits", b[16]&3, b[17]&7, b[18]&7)
	}
	if b[21]&3 != 3 {
		t.Fatal("lengths are not four bytes")
	}
	// The arrays, as out reads them (ScreenWire.hevcParameterSets).
	at := 22
	n := int(b[at])
	at++
	var sets [][]byte
	for i := 0; i < n; i++ {
		count := int(binary.BigEndian.Uint16(b[at+1:]))
		at += 3
		for j := 0; j < count; j++ {
			l := int(binary.BigEndian.Uint16(b[at:]))
			at += 2
			sets = append(sets, b[at:at+l])
			at += l
		}
	}
	if at != len(b) || len(sets) != 3 || !bytes.Equal(sets[0], testHEVCVPS) || !bytes.Equal(sets[1], testHEVCSPS) || !bytes.Equal(sets[2], testHEVCPPS) {
		t.Fatalf("arrays %d sets, end %d of %d", len(sets), at, len(b))
	}
	if HEVCDecoderRecord(testHEVCVPS, nil, testHEVCPPS) != nil {
		t.Fatal("a record without its sequence set")
	}
}
