package applehp

import (
	"encoding/binary"
	"strings"
)

// HEVC as Screen Sharing sends it in a High Performance session asked for
// "hevc" (seen 2026-11-25 from macOS 27 on an M1 Pro): RTP as RFC 7798 has
// it, with no decoding order numbers. A NAL unit alone, an aggregation packet
// (48) holding several (the video, sequence and picture parameter sets before
// each key frame), or a fragmentation unit (49) of a large one. Range
// Extensions profile, 4:4:4. Asked for more than one tile a picture, the Mac
// sends each tile as a stream of its own (an SSRC and parameter sets each);
// asked for one, the whole picture is one stream.
const (
	HEVCNALVPS byte = 32
	HEVCNALSPS byte = 33
	HEVCNALPPS byte = 34
	HEVCNALAUD byte = 35
	HEVCNALAP  byte = 48
	HEVCNALFU  byte = 49
)

// HEVCNALType is a NAL unit's type, from the first byte of its header.
func HEVCNALType(b0 byte) byte { return (b0 >> 1) & 0x3f }

// HEVCIsKey is whether a NAL unit of this type starts a picture that stands
// alone (IRAP: BLA, IDR or CRA).
func HEVCIsKey(t byte) bool { return t >= 16 && t <= 21 }

func isHEVC(codec string) bool { return strings.EqualFold(codec, "hevc") }

// ReassembleHEVC makes the NAL units of an access unit from its RTP payloads,
// in order.
func ReassembleHEVC(payloads [][]byte) [][]byte {
	var out [][]byte
	var fu []byte
	active := false
	for _, pay := range payloads {
		if len(pay) < 3 {
			continue
		}
		switch t := HEVCNALType(pay[0]); {
		case t == HEVCNALFU:
			fh := pay[2]
			if fh&0x80 != 0 {
				fu = make([]byte, 2, 2+len(pay)-3)
				fu[0] = pay[0]&0x81 | (fh&0x3f)<<1
				fu[1] = pay[1]
				active = true
			} else if !active {
				continue
			}
			fu = append(fu, pay[3:]...)
			if fh&0x40 != 0 {
				out = append(out, fu)
				fu, active = nil, false
			}
		case t == HEVCNALAP:
			for p := 2; p+2 <= len(pay); {
				n := int(binary.BigEndian.Uint16(pay[p:]))
				p += 2
				if n < 2 || p+n > len(pay) {
					break
				}
				out = append(out, append([]byte(nil), pay[p:p+n]...))
				p += n
			}
		case t < HEVCNALAP:
			out = append(out, append([]byte(nil), pay...))
		}
	}
	return out
}

// HEVCDecoderRecord is the decoder configuration (hvcC, ISO/IEC 14496-15)
// for these parameter sets, with four bytes of length before each NAL unit;
// nil when they are not whole.
func HEVCDecoderRecord(vps, sps, pps []byte) []byte {
	if len(vps) < 3 || len(sps) < 3 || len(pps) < 3 {
		return nil
	}
	r := RemoveEmulationPrevention(sps[2:])
	if len(r) < 13 {
		return nil
	}
	chroma, depthY, depthC, ok := hevcFormat(r)
	if !ok {
		chroma, depthY, depthC = 1, 0, 0
	}
	b := []byte{1}
	// Profile space, Main or High, and profile; compatibility flags; constraint flags; level.
	b = append(b, r[1:13]...)
	b = append(b, 0xf0, 0x00, 0xfc, 0xfc|byte(chroma), 0xf8|byte(depthY), 0xf8|byte(depthC), 0, 0)
	layers := (r[0]>>1)&7 + 1
	b = append(b, layers<<3|(r[0]&1)<<2|3)
	b = append(b, 3)
	for _, u := range [][]byte{vps, sps, pps} {
		b = append(b, 0x80|HEVCNALType(u[0]))
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint16(b, uint16(len(u)))
		b = append(b, u...)
	}
	return b
}

// hevcFormat reads a sequence parameter set (without its NAL header and
// emulation prevention) as far as its chroma format and bit depths.
func hevcFormat(r []byte) (chroma, depthY, depthC uint32, ok bool) {
	br := NewBitReader(r)
	first, err := br.ReadBits(8)
	if err != nil {
		return 0, 0, 0, false
	}
	sub := int(first>>1) & 7
	// The general profile (88 bits) and level (8).
	for i := 0; i < 12; i++ {
		if _, err := br.ReadBits(8); err != nil {
			return 0, 0, 0, false
		}
	}
	profile := make([]bool, sub)
	level := make([]bool, sub)
	for i := 0; i < sub; i++ {
		p, err1 := br.ReadBits(1)
		l, err2 := br.ReadBits(1)
		if err1 != nil || err2 != nil {
			return 0, 0, 0, false
		}
		profile[i], level[i] = p == 1, l == 1
	}
	if sub > 0 {
		for i := sub; i < 8; i++ {
			if _, err := br.ReadBits(2); err != nil {
				return 0, 0, 0, false
			}
		}
	}
	for i := 0; i < sub; i++ {
		skip := 0
		if profile[i] {
			skip += 88
		}
		if level[i] {
			skip += 8
		}
		for ; skip > 0; skip -= 8 {
			if _, err := br.ReadBits(8); err != nil {
				return 0, 0, 0, false
			}
		}
	}
	if _, err := br.ReadUE(); err != nil { // sps_seq_parameter_set_id
		return 0, 0, 0, false
	}
	if chroma, err = br.ReadUE(); err != nil || chroma > 3 {
		return 0, 0, 0, false
	}
	if chroma == 3 {
		if _, err := br.ReadBits(1); err != nil {
			return 0, 0, 0, false
		}
	}
	for i := 0; i < 2; i++ { // width and height
		if _, err := br.ReadUE(); err != nil {
			return 0, 0, 0, false
		}
	}
	window, err := br.ReadBits(1)
	if err != nil {
		return 0, 0, 0, false
	}
	if window == 1 {
		for i := 0; i < 4; i++ {
			if _, err := br.ReadUE(); err != nil {
				return 0, 0, 0, false
			}
		}
	}
	if depthY, err = br.ReadUE(); err != nil || depthY > 7 {
		return 0, 0, 0, false
	}
	if depthC, err = br.ReadUE(); err != nil || depthC > 7 {
		return 0, 0, 0, false
	}
	return chroma, depthY, depthC, true
}
