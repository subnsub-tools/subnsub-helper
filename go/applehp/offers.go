package applehp

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	audioF4On  uint64 = 24191
	audioF4Off uint64 = 1000
)

// OfferOptions controls the AVConference MediaBlob offers sent in 0x1c.
type OfferOptions struct {
	Codec         string // "avc" (default), "hevc", or "both"
	TilesPerFrame int    // <=0 picks default (1 for avc, 4 for hevc)
	AudioEnabled  bool   // false offers the sound a rate too low for the host to send it
	LTRP          bool   // true advertises LTRP; always false for AVC
	// MaxBitrate, when above zero, lowers every bandwidth ceiling the offer
	// declares to at most this many bits a second. A ceiling, not a rate: the
	// host's encoder stays under it and spends less on a still screen.
	MaxBitrate int
}

type audioF9Tier struct {
	f1    uint64
	f2    uint64
	hasF3 bool
	f3    uint64
}

var canonicalAudioF9Tiers = []audioF9Tier{
	{0, 40_000_000, true, 12288},
	{0, 6_000_000, true, 131072},
	{4074, 0, true, 16384},
	{16, 4100, false, 0},
	{0, 75_000_000, true, 524288},
	{0, 20_000_000, true, 98304},
	{4, 6500, false, 0},
	{0, 60_000_000, true, 262144},
	{1, 299, false, 0},
	{0, 100_000_000, true, 1048576},
}

var (
	endpointOnce sync.Once
	endpointInfo []byte
)

func getRemoteEndpointInfo() []byte {
	endpointOnce.Do(func() {
		hwModel := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
		osBuild := "1.0"
		if runtime.GOOS == "darwin" {
			if out, err := exec.Command("sysctl", "-n", "hw.model").Output(); err == nil {
				if s := strings.TrimSpace(string(out)); s != "" {
					hwModel = s
				}
			}
			if out, err := exec.Command("sw_vers", "-buildVersion").Output(); err == nil {
				if s := strings.TrimSpace(string(out)); s != "" {
					osBuild = s
				}
			}
		}
		var b []byte
		b = append(b, 0x08, 0x00, 0x10, 0x01)
		b = appendLenPrefixedTag(b, 0x1a, hwModel)
		b = appendLenPrefixedTag(b, 0x22, "1.0.0")
		b = appendLenPrefixedTag(b, 0x2a, osBuild)
		endpointInfo = b
	})
	return endpointInfo
}

func appendLenPrefixedTag(dst []byte, tag byte, s string) []byte {
	b := []byte(s)
	if len(b) > 127 {
		b = b[:127]
	}
	dst = append(dst, tag, byte(len(b)))
	return append(dst, b...)
}

func appendVarint(dst []byte, v uint64) []byte {
	for v > 0x7f {
		dst = append(dst, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendFieldVarint(dst []byte, fieldNum uint64, v uint64) []byte {
	dst = appendVarint(dst, (fieldNum<<3)|0)
	return appendVarint(dst, v)
}

func appendFieldBytes(dst []byte, fieldNum uint64, val []byte) []byte {
	dst = appendVarint(dst, (fieldNum<<3)|2)
	dst = appendVarint(dst, uint64(len(val)))
	return append(dst, val...)
}

func readVarint(data []byte, pos int) (uint64, int, bool) {
	var val uint64
	shift := uint(0)
	for pos < len(data) {
		b := data[pos]
		pos++
		val |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, pos, true
		}
		shift += 7
		if shift >= 64 {
			return 0, pos, false
		}
	}
	return 0, pos, false
}

func buildAudioF9Bytes() []byte { return buildBandwidthBytes(0) }

// buildBandwidthBytes writes the offer's bandwidth table (the blob's
// repeated field 9; "audio" in the names above is historical). Entries that
// name a ceiling in bits a second are lowered to maxBitrate when it is set;
// the others (selectors without a ceiling, and the two small entries whose
// unit is not established) go out as they are.
func buildBandwidthBytes(maxBitrate int) []byte {
	var out []byte
	for _, t := range canonicalAudioF9Tiers {
		if maxBitrate > 0 && t.f2 >= 1_000_000 && t.f2 > uint64(maxBitrate) {
			t.f2 = uint64(maxBitrate)
		}
		var body []byte
		body = appendFieldVarint(body, 1, t.f1)
		body = appendFieldVarint(body, 2, t.f2)
		if t.hasF3 {
			body = appendFieldVarint(body, 3, t.f3)
		}
		out = appendFieldBytes(out, 9, body)
	}
	return out
}

var audioF9Bytes = buildAudioF9Bytes()

func buildMediaBlob(mode int, sessionID uint32, ts uint64, opts OfferOptions) ([]byte, error) {
	codec := strings.ToLower(opts.Codec)
	if codec == "" {
		codec = "avc"
	}
	tiles := opts.TilesPerFrame
	if tiles <= 0 {
		if codec == "avc" {
			tiles = 1
		} else {
			tiles = 4
		}
	}
	ltrpOn := codec != "avc" && opts.LTRP

	var descField []byte
	switch mode {
	case 7:
		hevcParams := []byte("FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;")
		if ltrpOn {
			hevcParams = []byte("FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;")
		}
		avcParams := []byte("FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;")

		var resEntry, resEntryAlt []byte
		resEntry = appendFieldVarint(resEntry, 1, 1)
		resEntry = appendFieldVarint(resEntry, 2, 1)
		resEntry = appendFieldVarint(resEntry, 3, 50115)
		resEntry = appendFieldVarint(resEntry, 4, 0)

		resEntryAlt = appendFieldVarint(resEntryAlt, 1, 1)
		resEntryAlt = appendFieldVarint(resEntryAlt, 2, 2)
		resEntryAlt = appendFieldVarint(resEntryAlt, 3, 50115)
		resEntryAlt = appendFieldVarint(resEntryAlt, 4, 0)

		// NOTE: macOS response mapping is inverted from the bank parameter names:
		// field1=123 yields H.264 4:2:0, while field1=100 yields HEVC 4:4:4.
		var bankYieldsH264 []byte
		bankYieldsH264 = appendFieldVarint(bankYieldsH264, 1, 123)
		bankYieldsH264 = appendFieldBytes(bankYieldsH264, 2, resEntry)
		bankYieldsH264 = appendFieldBytes(bankYieldsH264, 2, resEntryAlt)
		bankYieldsH264 = appendFieldBytes(bankYieldsH264, 2, resEntry)
		bankYieldsH264 = appendFieldBytes(bankYieldsH264, 2, resEntryAlt)
		bankYieldsH264 = appendFieldBytes(bankYieldsH264, 3, hevcParams)
		bankYieldsH264 = appendFieldVarint(bankYieldsH264, 4, 1)

		var bankYieldsHEVC []byte
		bankYieldsHEVC = appendFieldVarint(bankYieldsHEVC, 1, 100)
		bankYieldsHEVC = appendFieldBytes(bankYieldsHEVC, 2, resEntry)
		bankYieldsHEVC = appendFieldBytes(bankYieldsHEVC, 2, resEntryAlt)
		bankYieldsHEVC = appendFieldBytes(bankYieldsHEVC, 3, avcParams)
		bankYieldsHEVC = appendFieldVarint(bankYieldsHEVC, 4, 14)

		var banks []byte
		switch codec {
		case "avc":
			banks = appendFieldBytes(banks, 3, bankYieldsH264)
		case "hevc":
			banks = appendFieldBytes(banks, 3, bankYieldsHEVC)
		default:
			banks = appendFieldBytes(banks, 3, bankYieldsH264)
			banks = appendFieldBytes(banks, 3, bankYieldsHEVC)
		}

		ltrpBit := uint64(0)
		if ltrpOn {
			ltrpBit = 1
		}
		var desc []byte
		desc = appendFieldVarint(desc, 1, uint64(sessionID))
		desc = appendFieldVarint(desc, 2, ltrpBit)
		desc = append(desc, banks...)
		desc = appendFieldVarint(desc, 6, uint64(tiles))
		desc = appendFieldVarint(desc, 7, ltrpBit)
		desc = appendFieldVarint(desc, 8, 63)
		desc = appendFieldVarint(desc, 9, 1)
		desc = appendFieldVarint(desc, 12, 1)
		descField = appendFieldBytes(nil, 5, desc)

	case 8:
		f4 := audioF4Off
		if opts.AudioEnabled {
			f4 = audioF4On
		}
		var desc []byte
		desc = appendFieldVarint(desc, 1, uint64(sessionID))
		desc = appendFieldVarint(desc, 2, 0)
		desc = appendFieldVarint(desc, 3, 0)
		desc = appendFieldVarint(desc, 4, f4)
		desc = appendFieldVarint(desc, 5, 0)
		desc = appendFieldVarint(desc, 6, 0)
		descField = appendFieldBytes(nil, 3, desc)

	default:
		return nil, fmt.Errorf("applehp: unsupported negotiator mode %d", mode)
	}

	var blob []byte
	blob = appendFieldVarint(blob, 1, 1)
	blob = appendFieldVarint(blob, 2, 1)
	blob = append(blob, descField...)
	blob = appendFieldBytes(blob, 6, []byte("subnsub-hp 1.0"))
	blob = appendFieldVarint(blob, 8, 0)
	if opts.MaxBitrate > 0 {
		blob = append(blob, buildBandwidthBytes(opts.MaxBitrate)...)
	} else {
		blob = append(blob, audioF9Bytes...)
	}
	blob = appendFieldVarint(blob, 13, ts)
	blob = appendFieldVarint(blob, 14, 2)
	blob = appendFieldVarint(blob, 16, 0)
	blob = appendFieldVarint(blob, 18, 1)
	return blob, nil
}

func buildOfferPlist(mode int, opts OfferOptions) ([]byte, uint32, error) {
	var sidBuf [4]byte
	if _, err := io.ReadFull(rand.Reader, sidBuf[:]); err != nil {
		return nil, 0, err
	}
	sid := binary.BigEndian.Uint32(sidBuf[:])
	ts := uint64(time.Now().UnixNano())
	blob, err := buildMediaBlob(mode, sid, ts, opts)
	if err != nil {
		return nil, 0, err
	}
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(blob); err != nil {
		return nil, 0, err
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}

	var callID [16]byte
	if _, err := io.ReadFull(rand.Reader, callID[:]); err != nil {
		return nil, 0, err
	}
	callID[6] = (callID[6] & 0x0F) | 0x40
	callID[8] = (callID[8] & 0x3F) | 0x80
	callIDStr := fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		callID[0:4], callID[4:6], callID[6:8], callID[8:10], callID[10:16])

	plistBytes, err := EncodePlistDict(map[string]any{
		"avcMediaStreamOptionRemoteEndpointInfo": getRemoteEndpointInfo(),
		"avcMediaStreamNegotiatorMode":           mode,
		"avcMediaStreamNegotiatorMediaBlob":      zbuf.Bytes(),
		"avcMediaStreamOptionCallID":             callIDStr,
	})
	if err != nil {
		return nil, 0, err
	}
	return plistBytes, sid, nil
}

// CreateOffers generates matching (video, audio) binary-plist offers and returns
// the generated video and audio SSRCs alongside them.
func CreateOffers(opts OfferOptions) (videoOffer, audioOffer []byte, videoSSRC, audioSSRC uint32, err error) {
	videoOffer, videoSSRC, err = buildOfferPlist(7, opts)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	audioOffer, audioSSRC, err = buildOfferPlist(8, opts)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	return videoOffer, audioOffer, videoSSRC, audioSSRC, nil
}

// ExtractOfferSSRC parses an offer binary plist and extracts its advertised SSRC.
func ExtractOfferSSRC(offerPlist []byte, isVideo bool) (uint32, bool) {
	val, err := DecodePlist(offerPlist)
	if err != nil {
		return 0, false
	}
	m, ok := val.(map[string]any)
	if !ok {
		return 0, false
	}
	compressed, ok := m["avcMediaStreamNegotiatorMediaBlob"].([]byte)
	if !ok {
		return 0, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return 0, false
	}
	defer zr.Close()
	blob, err := io.ReadAll(zr)
	if err != nil {
		return 0, false
	}
	target := uint64(3)
	if isVideo {
		target = 5
	}
	pos := 0
	for pos < len(blob) {
		tag, next, ok := readVarint(blob, pos)
		if !ok {
			break
		}
		pos = next
		fn := tag >> 3
		wt := tag & 7
		switch wt {
		case 0:
			_, pos, ok = readVarint(blob, pos)
			if !ok {
				return 0, false
			}
		case 2:
			ln, next2, ok := readVarint(blob, pos)
			if !ok {
				return 0, false
			}
			pos = next2
			if pos+int(ln) > len(blob) {
				return 0, false
			}
			if fn == target {
				sub := blob[pos : pos+int(ln)]
				innerTag, sp, ok := readVarint(sub, 0)
				if ok && (innerTag&7) == 0 && (innerTag>>3) == 1 {
					ssrc, _, ok := readVarint(sub, sp)
					if ok {
						return uint32(ssrc), true
					}
				}
			}
			pos += int(ln)
		case 1:
			pos += 8
		case 5:
			pos += 4
		default:
			return 0, false
		}
	}
	return 0, false
}

// ExtractCanvasDims parses the server's 0x1c answer message and extracts
// (canvasWidth, canvasHeight, tileCount).
func ExtractCanvasDims(answerMsg []byte) (w, h, tiles int, ok bool) {
	if len(answerMsg) == 0 || answerMsg[0] != 0x00 {
		return 0, 0, 0, false
	}
	var blobs [][]byte
	if len(answerMsg) >= 18 && int32(binary.BigEndian.Uint32(answerMsg[12:16])) == EncAppleMediaInit {
		// A framebuffer update whose first rectangle is the 0x3f2 answer, as macOS 15 sends it.
		if end := 18 + int(binary.BigEndian.Uint16(answerMsg[16:18])); end <= len(answerMsg) {
			blobs = answerMediaBlobs(answerMsg[16:end])
		}
	} else {
		blobs = ExtractPlistMediaBlobs(answerMsg)
	}
	// One plist per stream, the audio one first: the size is in the video one.
	for _, compressed := range blobs {
		if w, h, tiles, ok := canvasFromBlob(compressed); ok {
			return w, h, tiles, true
		}
	}
	return 0, 0, 0, false
}

// canvasMax bounds a size read from an answer: anything larger is not a display.
const canvasMax = 16384

// canvasFromBlob reads the video settings (field 5) of a media blob: width (4), height (5) and
// tiles (6).
func canvasFromBlob(compressed []byte) (w, h, tiles int, ok bool) {
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return 0, 0, 0, false
	}
	defer zr.Close()
	dec, err := io.ReadAll(io.LimitReader(zr, 256*1024))
	if err != nil {
		return 0, 0, 0, false
	}
	walkFields(dec, func(field uint64, wire int, _ uint64, sub []byte) {
		if field != 5 || wire != 2 {
			return
		}
		walkFields(sub, func(f uint64, wt int, v uint64, _ []byte) {
			if wt != 0 || v > canvasMax {
				return
			}
			switch f {
			case 4:
				w = int(v)
			case 5:
				h = int(v)
			case 6:
				tiles = int(v)
			}
		})
	})
	if w > 0 && h > 0 {
		return w, h, tiles, true
	}
	return 0, 0, 0, false
}

// walkFields visits the fields of a protobuf message in order, a varint with its value and a
// length-delimited one with its bytes, and stops at the first field that does not fit in b.
func walkFields(b []byte, visit func(field uint64, wire int, v uint64, sub []byte)) {
	pos := 0
	for pos < len(b) {
		tag, next, ok := readVarint(b, pos)
		if !ok {
			return
		}
		pos = next
		field, wire := tag>>3, int(tag&7)
		var v uint64
		var sub []byte
		switch wire {
		case 0:
			if v, pos, ok = readVarint(b, pos); !ok {
				return
			}
		case 1:
			if len(b)-pos < 8 {
				return
			}
			pos += 8
		case 2:
			ln, next, ok := readVarint(b, pos)
			if !ok || ln > uint64(len(b)-next) {
				return
			}
			sub = b[next : next+int(ln)]
			pos = next + int(ln)
		case 5:
			if len(b)-pos < 4 {
				return
			}
			pos += 4
		default:
			return
		}
		visit(field, wire, v, sub)
	}
}
