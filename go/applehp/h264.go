package applehp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	AppleAVCConfigMarker byte = 0x92

	H264NALSliceNonIDR byte = 1
	H264NALSliceIDR    byte = 5
	H264NALSPS         byte = 7
	H264NALPPS         byte = 8
	H264NALSTAPA       byte = 24
	H264NALFUA         byte = 28
	H264NALFUB         byte = 29
)

// ParseAVCConfig extracts the raw SPS and PPS NAL bytes (without Annex-B start
// codes) from Apple's 0x92 RTP packet carrying an avc1/avcC sample entry.
func ParseAVCConfig(payload []byte) (sps, pps []byte, ok bool) {
	start := 0
	if a1 := bytes.Index(payload, []byte("avc1")); a1 >= 0 {
		start = a1
	}
	rel := bytes.Index(payload[start:], []byte("avcC"))
	if rel < 0 {
		return nil, nil, false
	}
	p := start + rel + 4
	if p+6 > len(payload) {
		return nil, nil, false
	}
	numSPS := int(payload[p+5] & 0x1f)
	p += 6
	for i := 0; i < numSPS; i++ {
		if p+2 > len(payload) {
			return nil, nil, false
		}
		ln := int(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2
		if p+ln > len(payload) {
			return nil, nil, false
		}
		if sps == nil && ln > 0 {
			sps = append([]byte(nil), payload[p:p+ln]...)
		}
		p += ln
	}
	if p+1 > len(payload) {
		return nil, nil, false
	}
	numPPS := int(payload[p])
	p++
	for i := 0; i < numPPS; i++ {
		if p+2 > len(payload) {
			return nil, nil, false
		}
		ln := int(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2
		if p+ln > len(payload) {
			return nil, nil, false
		}
		if pps == nil && ln > 0 {
			pps = append([]byte(nil), payload[p:p+ln]...)
		}
		p += ln
	}
	if len(sps) == 0 || len(pps) == 0 {
		return nil, nil, false
	}
	return sps, pps, true
}

// ReassembleH264 depacketizes one RTP timestamp group of Apple H.264 payloads
// into raw NAL units (no Annex-B start codes). FU-A and single NALs are DON-less.
func ReassembleH264(payloads [][]byte) [][]byte {
	var out [][]byte
	var fuBuf []byte
	fuActive := false

	for _, pay := range payloads {
		if len(pay) == 0 {
			continue
		}
		b0 := pay[0]
		if b0 == AppleAVCConfigMarker {
			continue
		}
		t := b0 & 0x1f
		switch {
		case t == H264NALFUA || t == H264NALFUB:
			don := 0
			if t == H264NALFUB {
				don = 2
			}
			dataOff := 2 + don
			if len(pay) < dataOff {
				continue
			}
			fuHdr := pay[1]
			start := fuHdr&0x80 != 0
			end := fuHdr&0x40 != 0
			innerType := fuHdr & 0x1f
			if start {
				nalHdr := (b0 & 0xe0) | innerType
				fuBuf = make([]byte, 1, 1+len(pay)-dataOff)
				fuBuf[0] = nalHdr
				fuBuf = append(fuBuf, pay[dataOff:]...)
				fuActive = true
				if end {
					out = append(out, fuBuf)
					fuActive = false
				}
			} else if fuActive {
				fuBuf = append(fuBuf, pay[dataOff:]...)
				if end {
					out = append(out, fuBuf)
					fuActive = false
				}
			}

		case t == H264NALSTAPA:
			pos := 3 // 1-byte indicator + 2-byte DON
			for pos+2 <= len(pay) {
				sz := int(binary.BigEndian.Uint16(pay[pos : pos+2]))
				pos += 2
				if sz == 0 || pos+sz > len(pay) {
					break
				}
				nal := make([]byte, sz)
				copy(nal, pay[pos:pos+sz])
				out = append(out, nal)
				pos += sz
			}

		case t >= 1 && t <= 23:
			if len(pay) < 2 {
				continue
			}
			nal := make([]byte, len(pay))
			copy(nal, pay)
			out = append(out, nal)
		}
	}
	return out
}

// RemoveEmulationPrevention strips 0x03 emulation prevention bytes from an RBSP.
func RemoveEmulationPrevention(in []byte) []byte {
	out := make([]byte, 0, len(in))
	zeros := 0
	for _, b := range in {
		if zeros == 2 && b == 0x03 {
			zeros = 0
			continue
		}
		out = append(out, b)
		if b == 0x00 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return out
}

// AddEmulationPrevention inserts 0x03 emulation prevention bytes per H.264 §7.4.1.
func AddEmulationPrevention(rbsp []byte) []byte {
	out := make([]byte, 0, len(rbsp)+8)
	zeros := 0
	for _, b := range rbsp {
		if zeros >= 2 && b <= 0x03 {
			out = append(out, 0x03)
			zeros = 0
		}
		out = append(out, b)
		if b == 0x00 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return out
}

// BitReader reads H.264 bitstream fields (unsigned bits and Exp-Golomb).
type BitReader struct {
	data []byte
	pos  int // bit offset
}

// NewBitReader creates a BitReader over RBSP bytes.
func NewBitReader(data []byte) *BitReader {
	return &BitReader{data: data}
}

// BitPos returns the current bit offset from the start of the buffer.
func (br *BitReader) BitPos() int { return br.pos }

// TotalBits returns the total number of bits in the buffer.
func (br *BitReader) TotalBits() int { return len(br.data) * 8 }

// ReadBits reads n (0..32) bits big-endian.
func (br *BitReader) ReadBits(n int) (uint32, error) {
	if n < 0 || n > 32 || br.pos+n > len(br.data)*8 {
		return 0, errors.New("applehp: bitreader out of bounds")
	}
	var v uint32
	for i := 0; i < n; i++ {
		bit := (br.data[br.pos>>3] >> uint(7-(br.pos&7))) & 1
		v = (v << 1) | uint32(bit)
		br.pos++
	}
	return v, nil
}

// ReadUE reads an unsigned Exp-Golomb value ue(v).
func (br *BitReader) ReadUE() (uint32, error) {
	zeros := 0
	for {
		b, err := br.ReadBits(1)
		if err != nil {
			return 0, err
		}
		if b != 0 {
			break
		}
		zeros++
		if zeros > 31 {
			return 0, errors.New("applehp: ue(v) overflow")
		}
	}
	if zeros == 0 {
		return 0, nil
	}
	rem, err := br.ReadBits(zeros)
	if err != nil {
		return 0, err
	}
	return ((1 << zeros) - 1) + rem, nil
}

// ReadSE reads a signed Exp-Golomb value se(v).
func (br *BitReader) ReadSE() (int32, error) {
	u, err := br.ReadUE()
	if err != nil {
		return 0, err
	}
	if u == 0 {
		return 0, nil
	}
	val := int32((u + 1) >> 1)
	if u&1 == 0 {
		return -val, nil
	}
	return val, nil
}

// AUIsKeyframe reports whether an access unit of raw NALUs is an independently
// decodable keyframe (IDR type 5, or Apple type-1 intra slice with slice_type 2 or 7).
func AUIsKeyframe(nalus [][]byte) bool {
	for _, nal := range nalus {
		if len(nal) < 2 {
			continue
		}
		t := nal[0] & 0x1f
		if t == H264NALSliceIDR {
			return true
		}
		if t == H264NALSliceNonIDR {
			rbsp := RemoveEmulationPrevention(nal[1:])
			br := NewBitReader(rbsp)
			if _, err := br.ReadUE(); err != nil { // first_mb_in_slice
				continue
			}
			sliceType, err := br.ReadUE()
			if err != nil {
				continue
			}
			if sliceType == 2 || sliceType == 7 {
				return true
			}
		}
	}
	return false
}

// SPSInfo summarizes parsed H.264 SPS header parameters.
type SPSInfo struct {
	ProfileIDC      uint8
	LevelIDC        uint8
	MaxNumRefFrames uint32
	RefStartBit     int
	RefEndBit       int
}

// ParseSPSInfo parses an H.264 SPS NAL unit through max_num_ref_frames.
func ParseSPSInfo(sps []byte) (SPSInfo, bool) {
	if len(sps) < 4 || (sps[0]&0x1f) != H264NALSPS {
		return SPSInfo{}, false
	}
	rbsp := RemoveEmulationPrevention(sps[1:])
	br := NewBitReader(rbsp)

	prof, err := br.ReadBits(8)
	if err != nil {
		return SPSInfo{}, false
	}
	if _, err := br.ReadBits(8); err != nil { // constraint flags
		return SPSInfo{}, false
	}
	lvl, err := br.ReadBits(8)
	if err != nil {
		return SPSInfo{}, false
	}
	if _, err := br.ReadUE(); err != nil { // seq_parameter_set_id
		return SPSInfo{}, false
	}

	switch prof {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		cfi, err := br.ReadUE()
		if err != nil {
			return SPSInfo{}, false
		}
		if cfi == 3 {
			if _, err := br.ReadBits(1); err != nil {
				return SPSInfo{}, false
			}
		}
		if _, err := br.ReadUE(); err != nil { // bit_depth_luma_minus8
			return SPSInfo{}, false
		}
		if _, err := br.ReadUE(); err != nil { // bit_depth_chroma_minus8
			return SPSInfo{}, false
		}
		if _, err := br.ReadBits(1); err != nil { // qpprime_y_zero_transform_bypass_flag
			return SPSInfo{}, false
		}
		scalingPresent, err := br.ReadBits(1)
		if err != nil {
			return SPSInfo{}, false
		}
		if scalingPresent == 1 {
			n := 8
			if cfi == 3 {
				n = 12
			}
			for i := 0; i < n; i++ {
				present, err := br.ReadBits(1)
				if err != nil {
					return SPSInfo{}, false
				}
				if present == 1 {
					sz := 16
					if i >= 6 {
						sz = 64
					}
					lastScale, nextScale := int32(8), int32(8)
					for j := 0; j < sz; j++ {
						if nextScale != 0 {
							delta, err := br.ReadSE()
							if err != nil {
								return SPSInfo{}, false
							}
							nextScale = (lastScale + delta + 256) % 256
						}
						if nextScale != 0 {
							lastScale = nextScale
						}
					}
				}
			}
		}
	}

	if _, err := br.ReadUE(); err != nil { // log2_max_frame_num_minus4
		return SPSInfo{}, false
	}
	pocType, err := br.ReadUE()
	if err != nil {
		return SPSInfo{}, false
	}
	switch pocType {
	case 0:
		if _, err := br.ReadUE(); err != nil { // log2_max_pic_order_cnt_lsb_minus4
			return SPSInfo{}, false
		}
	case 1:
		if _, err := br.ReadBits(1); err != nil {
			return SPSInfo{}, false
		}
		if _, err := br.ReadSE(); err != nil {
			return SPSInfo{}, false
		}
		if _, err := br.ReadSE(); err != nil {
			return SPSInfo{}, false
		}
		nCycle, err := br.ReadUE()
		if err != nil || nCycle > 256 {
			return SPSInfo{}, false
		}
		for i := uint32(0); i < nCycle; i++ {
			if _, err := br.ReadSE(); err != nil {
				return SPSInfo{}, false
			}
		}
	}

	refStart := br.BitPos()
	maxRef, err := br.ReadUE()
	if err != nil {
		return SPSInfo{}, false
	}
	refEnd := br.BitPos()

	return SPSInfo{
		ProfileIDC:      uint8(prof),
		LevelIDC:        uint8(lvl),
		MaxNumRefFrames: maxRef,
		RefStartBit:     refStart,
		RefEndBit:       refEnd,
	}, true
}

// PatchAVCSPSMaxRefFrames raises max_num_ref_frames inside an H.264 SPS NAL
// unit up to targetMaxRef when the advertised ceiling is lower (for example,
// Apple's 8 -> 10 so strict decoders hold Apple's full reference set without
// triggering VideoToolbox's >10 refusal). Returns (patched, true) if modified.
func PatchAVCSPSMaxRefFrames(sps []byte, targetMaxRef uint32) ([]byte, bool) {
	info, ok := ParseSPSInfo(sps)
	if !ok || info.MaxNumRefFrames >= targetMaxRef {
		return sps, false
	}
	rbsp := RemoveEmulationPrevention(sps[1:])
	totalBits := len(rbsp) * 8

	// Locate rbsp_stop_one_bit (the final 1 bit in rbsp) so trailing alignment zeros
	// are cleanly recomputed after replacing the Exp-Golomb field.
	stopBit := -1
	for b := totalBits - 1; b >= info.RefEndBit; b-- {
		bit := (rbsp[b>>3] >> uint(7-(b&7))) & 1
		if bit == 1 {
			stopBit = b
			break
		}
	}
	if stopBit < 0 {
		return sps, false
	}

	ueBits := encodeUEBits(targetMaxRef)
	tailPayloadBits := stopBit - info.RefEndBit // excludes rbsp_stop_one_bit
	newTotalPayload := info.RefStartBit + len(ueBits) + tailPayloadBits + 1
	newRBSPBytes := (newTotalPayload + 7) / 8
	newRBSP := make([]byte, newRBSPBytes)

	writeBit := func(pos int, val byte) {
		if val != 0 {
			newRBSP[pos>>3] |= 1 << uint(7-(pos&7))
		}
	}
	readBit := func(pos int) byte {
		return (rbsp[pos>>3] >> uint(7-(pos&7))) & 1
	}

	wp := 0
	for i := 0; i < info.RefStartBit; i++ {
		writeBit(wp, readBit(i))
		wp++
	}
	for _, b := range ueBits {
		writeBit(wp, b)
		wp++
	}
	for i := info.RefEndBit; i < stopBit; i++ {
		writeBit(wp, readBit(i))
		wp++
	}
	writeBit(wp, 1) // rbsp_stop_one_bit; remaining bits stay zero

	out := make([]byte, 1, 1+len(newRBSP)+4)
	out[0] = sps[0]
	out = append(out, AddEmulationPrevention(newRBSP)...)
	return out, true
}

func encodeUEBits(v uint32) []byte {
	code := v + 1
	bitLen := 0
	for x := code; x > 0; x >>= 1 {
		bitLen++
	}
	zeros := bitLen - 1
	bits := make([]byte, zeros+bitLen)
	for i := 0; i < bitLen; i++ {
		bits[zeros+bitLen-1-i] = byte((code >> uint(i)) & 1)
	}
	return bits
}
