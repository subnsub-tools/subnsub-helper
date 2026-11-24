package applehp

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
)

const (
	MsgClientSetPixelFormat     byte = 0x00
	MsgClientSetEncodings       byte = 0x02
	MsgClientFramebufferRequest byte = 0x03
	MsgClientKeyEvent           byte = 0x04
	MsgClientPointerEvent       byte = 0x05
	MsgClientSetMode            byte = 0x0a
	MsgClientEncryptedInput     byte = 0x10
	MsgClientSetEncryption      byte = 0x12
	MsgClientAutoPasteboard     byte = 0x15
	MsgClientMediaNegotiation   byte = 0x1c
	MsgClientVirtualDisplay     byte = 0x1d
	MsgClientClipboardSend      byte = 0x1f
	MsgClientViewerInfo         byte = 0x21

	MsgServerFramebufferUpdate byte = 0x00
	MsgServerSetColorMap       byte = 0x01
	MsgServerBell              byte = 0x02
	MsgServerCutText           byte = 0x03
	MsgServerMiscStatus        byte = 0x14
	MsgServerClipboardSend     byte = 0x1f

	EncRaw            int32 = 0
	EncZlib           int32 = 6
	EncDesktopSize    int32 = -223
	EncApplePointer   int32 = 1100 // 0x44c, no body
	EncAppleSelector  int32 = 1101 // 0x44d, no body
	EncAppleMediaInit int32 = 1010 // 0x3f2
	EncAppleMVS       int32 = 1011 // 0x3f3
	EncAppleHighQual  int32 = 1002 // 0x3ea
	EncAppleRekey     int32 = 1103 // 0x44f
	EncAppleCursor    int32 = 1104 // 0x450
	EncAppleLayout    int32 = 1105 // 0x451
	EncAppleKeysyms   int32 = 1107 // 0x453
	EncAppleInputSrc  int32 = 1109 // 0x455
	EncAppleDevice    int32 = 1110 // 0x456
)

var (
	// HPEncodings is the Apple High Performance SetEncodings list advertised both
	// before and after the enc1103 activation.
	HPEncodings = []int32{
		1010, 1011, 1002, 6, 16, 1104, 1100,
		-223, 1101, 1105, 1107, 1109, 1110,
	}

	// StandardEncodings is what a standard session takes: the picture as
	// pixels, raw or deflated, and the host's own rectangles a High
	// Performance session takes too (cursor, layout, keys). None of Apple's
	// picture codecs, which nothing here reads.
	StandardEncodings = []int32{
		EncZlib, 1104, 1100,
		-223, 1101, 1105, 1107, 1109, 1110,
	}

	// CodedEncodings is what a standard session names when its viewer reads
	// the Mac's own picture codec (Config.Coded): that codec first, which
	// makes it the one the Mac sends, then pixels deflated, for whatever the
	// Mac sends exact, and the rectangles StandardEncodings has.
	CodedEncodings = []int32{
		EncAppleMVS, EncZlib, 1104, 1100,
		-223, 1101, 1105, 1107, 1109, 1110,
	}

	sessionSelectMagic = []byte{0x00, 0x4a, 0x00, 0x01}

	// DefaultViewerOSVer matches a stable macOS Sequoia release so hosts of all
	// supported macOS versions take the standard HP code path.
	DefaultViewerOSVer = [3]uint32{15, 3, 0}
)

// DisplayRect describes one host monitor rectangle in backing pixels from 0x451.
type DisplayRect struct {
	DisplayID uint32
	X, Y      int
	W, H      int
}

// NegotiationKeys holds the four 46-byte SRTP master+salt blobs carried in 0x1c.
type NegotiationKeys struct {
	AudioKeyV [SRTPKeyBlobLen]byte
	AudioKeyS [SRTPKeyBlobLen]byte
	VideoKeyV [SRTPKeyBlobLen]byte
	VideoKeyS [SRTPKeyBlobLen]byte
}

// RandomNegotiationKeys generates fresh cryptographic SRTP master keys and salts.
func RandomNegotiationKeys() (NegotiationKeys, error) {
	var k NegotiationKeys
	for _, dst := range [][]byte{k.AudioKeyV[:], k.AudioKeyS[:], k.VideoKeyV[:], k.VideoKeyS[:]} {
		if _, err := io.ReadFull(rand.Reader, dst); err != nil {
			return k, err
		}
	}
	return k, nil
}

// ViewerCommandMask returns the 32-byte ViewerInfo capability bitmap matching
// native Screen Sharing.app.
func ViewerCommandMask() []byte {
	m := make([]byte, 32)
	m[0] = 0xb0
	m[2] = 0x0c
	m[3] = 0x03
	m[4] = 0x90
	m[10] = 0x40
	return m
}

// BuildViewerInfo constructs the 0x21 HandleViewerInfoMessage prelude packet.
func BuildViewerInfo(osVer [3]uint32) []byte {
	mask := ViewerCommandMask()
	buf := make([]byte, 34+len(mask))
	buf[0] = MsgClientViewerInfo
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], 0x3e)
	binary.BigEndian.PutUint16(buf[4:6], 1)  // msgVersion
	binary.BigEndian.PutUint32(buf[6:10], 2) // appID
	binary.BigEndian.PutUint32(buf[10:14], 6)
	binary.BigEndian.PutUint32(buf[14:18], 1)
	binary.BigEndian.PutUint32(buf[18:22], 0)
	binary.BigEndian.PutUint32(buf[22:26], osVer[0])
	binary.BigEndian.PutUint32(buf[26:30], osVer[1])
	binary.BigEndian.PutUint32(buf[30:34], osVer[2])
	copy(buf[34:], mask)
	return buf
}

// Apple0x12Followup returns the 12-byte plaintext SetEncryption(cmd=1) setup
// message emitted immediately after ViewerInfo.
func Apple0x12Followup() []byte {
	return []byte{0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}
}

// BuildPostEncryptionToggle returns the 8-byte 0x12 cmd=2 message emitted after
// the 0x44f rekey to activate media negotiation readiness.
func BuildPostEncryptionToggle() []byte {
	return []byte{0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00}
}

// BuildSetEncodings encodes an RFB SetEncodings (0x02) message.
func BuildSetEncodings(encs []int32) []byte {
	buf := make([]byte, 4+4*len(encs))
	buf[0] = MsgClientSetEncodings
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(encs)))
	for i, e := range encs {
		binary.BigEndian.PutUint32(buf[4+i*4:8+i*4], uint32(e))
	}
	return buf
}

// BuildFBURequest encodes a standard RFB FramebufferUpdateRequest (0x03).
func BuildFBURequest(incremental bool, x, y, w, h uint16) []byte {
	var buf [10]byte
	buf[0] = MsgClientFramebufferRequest
	if incremental {
		buf[1] = 1
	}
	binary.BigEndian.PutUint16(buf[2:4], x)
	binary.BigEndian.PutUint16(buf[4:6], y)
	binary.BigEndian.PutUint16(buf[6:8], w)
	binary.BigEndian.PutUint16(buf[8:10], h)
	return buf[:]
}

// BuildVirtualDisplay constructs the 0x1d SetDisplayConfiguration message that
// requests a SkyLight virtual display (curtain mode) and dynamic resolution.
func BuildVirtualDisplay(width, height int, hidpiScale float64, hdr bool, name string) []byte {
	if width <= 0 {
		width = 1920
	}
	if height <= 0 {
		height = 1080
	}
	if hidpiScale <= 0 {
		hidpiScale = 1.0
	}
	if name == "" {
		name = "subnsub Virtual Display"
	}

	const modeCount = 5
	diSize := 0x9c + 28*modeCount
	di := make([]byte, diSize)
	binary.BigEndian.PutUint16(di[0x00:0x02], uint16(diSize))

	nameBytes := []byte(name)
	if len(nameBytes) > 119 {
		nameBytes = nameBytes[:119]
	}
	copy(di[0x02:0x79], nameBytes)

	binary.BigEndian.PutUint32(di[0x7a:0x7e], 1) // DYNAMIC_RESOLUTION
	binary.BigEndian.PutUint32(di[0x7e:0x82], 4) // virtual display
	binary.BigEndian.PutUint32(di[0x82:0x86], math.Float32bits(369.45456))
	binary.BigEndian.PutUint32(di[0x86:0x8a], math.Float32bits(207.81818))
	binary.BigEndian.PutUint32(di[0x8a:0x8e], 3840)
	binary.BigEndian.PutUint32(di[0x8e:0x92], 2160)
	binary.BigEndian.PutUint16(di[0x92:0x94], 0)
	binary.BigEndian.PutUint16(di[0x94:0x96], 0)
	binary.BigEndian.PutUint32(di[0x96:0x9a], 7)
	binary.BigEndian.PutUint16(di[0x9a:0x9c], modeCount)

	nativeModes := [modeCount][2]int{
		{1920, 1080},
		{1440, 900},
		{1920, 1080},
		{1440, 810},
		{1312, 848},
	}
	sx := float64(width) / 1920.0
	sy := float64(height) / 1080.0
	var modeFlags uint32
	if hdr {
		modeFlags = 1
	}
	for i := 0; i < modeCount; i++ {
		msw := maxInt(1, int(float64(nativeModes[i][0])*sx+0.5))
		msh := maxInt(1, int(float64(nativeModes[i][1])*sy+0.5))
		// macOS reads a mode as its size in points, then that size divided
		// by the pixel scale: (w, w/2) is w points at twice as many pixels,
		// (w, w) a pixel a point. Seen on a Mac mini, macOS 15, 2026-11-22:
		// (2200, 1100) made a display of 2200x1400 points at 4400x2800
		// pixels, (1100, 550) one of 1100x700 points at 2200x1400.
		lw := maxInt(1, int(float64(msw)/hidpiScale+0.5))
		lh := maxInt(1, int(float64(msh)/hidpiScale+0.5))
		m := 0x9c + 28*i
		binary.BigEndian.PutUint32(di[m+0x00:m+0x04], uint32(msw))
		binary.BigEndian.PutUint32(di[m+0x04:m+0x08], uint32(msh))
		binary.BigEndian.PutUint32(di[m+0x08:m+0x0c], uint32(lw))
		binary.BigEndian.PutUint32(di[m+0x0c:m+0x10], uint32(lh))
		binary.BigEndian.PutUint64(di[m+0x10:m+0x18], math.Float64bits(60.0))
		binary.BigEndian.PutUint32(di[m+0x18:m+0x1c], modeFlags)
	}

	msgSize := 8 + diSize
	out := make([]byte, 4+msgSize)
	out[0] = MsgClientVirtualDisplay
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(msgSize))
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 1)
	binary.BigEndian.PutUint32(out[8:12], 0)
	copy(out[12:], di)
	return out
}

// Build0x1c constructs the 0x1c MediaStreamConfiguration offer message.
func Build0x1c(audioOffer, videoOffer []byte, keys NegotiationKeys, noCursor, altSession bool) []byte {
	as := len(audioOffer)
	vs := len(videoOffer)
	ms := as + vs + 0xd8

	buf := make([]byte, ms+4)
	buf[0] = MsgClientMediaNegotiation
	binary.BigEndian.PutUint16(buf[2:4], uint16(ms))
	binary.BigEndian.PutUint16(buf[4:6], 3)

	configFlags := uint32(3)
	if altSession {
		configFlags = (configFlags &^ 2) | 4
	} else if noCursor {
		configFlags |= 4
	}
	// Must be written big-endian on the wire so the host's IPC boundary delivers
	// the expected bitmask to ScreensharingAgent.
	binary.BigEndian.PutUint32(buf[6:10], configFlags)

	binary.BigEndian.PutUint16(buf[10:12], uint16(as))
	binary.BigEndian.PutUint16(buf[12:14], uint16(vs))

	var callID [16]byte
	_, _ = io.ReadFull(rand.Reader, callID[:])
	callID[6] = (callID[6] & 0x0F) | 0x40
	callID[8] = (callID[8] & 0x3F) | 0x80
	copy(buf[0x14:0x24], callID[:])

	copy(buf[0x24:0x52], keys.AudioKeyV[:])
	copy(buf[0x52:0x80], keys.AudioKeyS[:])
	copy(buf[0x80:0x80+as], audioOffer)

	vo := 0x80 + as
	copy(buf[vo:vo+0x2e], keys.VideoKeyV[:])
	copy(buf[vo+0x2e:vo+0x5c], keys.VideoKeyS[:])
	copy(buf[vo+0x5c:vo+0x5c+vs], videoOffer)
	return buf
}

// BuildSessionSelectCmd0 builds a cmd=0 (share console) SessionSelect response.
func BuildSessionSelectCmd0(consoleUser string) []byte {
	body := make([]byte, 72)
	binary.BigEndian.PutUint16(body[0:2], 2)
	body[6] = 0
	p := 8
	u := []byte(consoleUser)
	if len(u) > len(body)-p-2 {
		u = u[:len(body)-p-2]
	}
	copy(body[p:], u)
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

// BuildSessionSelectCmd2 builds a cmd=2 (alt-user virtual session) SessionSelect response.
func BuildSessionSelectCmd2(username, password string, ecbKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(ecbKey[:16])
	if err != nil {
		return nil, err
	}
	var userBuf, passBuf [64]byte
	copy(userBuf[:63], username)
	copy(passBuf[:63], password)

	body := make([]byte, 200)
	binary.BigEndian.PutUint16(body[0:2], 2)
	body[6] = 2
	for off := 0; off < 64; off += 16 {
		block.Encrypt(body[0x48+off:0x48+off+16], userBuf[off:off+16])
		block.Encrypt(body[0x88+off:0x88+off+16], passBuf[off:off+16])
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(body)))
	copy(out[2:], body)
	return out, nil
}

// How a display of w by h points at a pixel scale is written for the host.
// Macs read a mode's two pairs differently (seen 2026-11-22, both macOS 15):
// a Mac mini takes the first pair as the points and the first over the second
// as the pixel scale, which is what BuildVirtualDisplay writes; a Mac mini
// 2023 on 15.8.3 takes the first pair as the pixels and the second as the
// points, and asked the other way makes a display of 800x600 points, or of
// half the size, whatever was asked. Nothing in what a host says before the
// display is made tells which, so the session asks one way, reads the size
// the host made (0x451) and asks the other way when it is not the one asked
// for; a pixel a point, read the same by both, is what is left.
const (
	formPointsFirst = iota
	formPixelsFirst
	formPlain
)

func displayConfig(w, h int, scale float64, hdr bool, form int) []byte {
	const name = "subnsub Virtual Display"
	switch {
	case form == formPlain || scale <= 1:
		// An even number of pixels each way: asked for 933x412, the host made
		// that display and sent no picture of it (seen 2026-11-22, macOS
		// 15.8.3; 932x412 it sends).
		return BuildVirtualDisplay(w&^1, h&^1, 1, hdr, name)
	case form == formPixelsFirst:
		return BuildVirtualDisplay(int(float64(w)*scale+0.5), int(float64(h)*scale+0.5), scale, hdr, name)
	}
	return BuildVirtualDisplay(w, h, scale, hdr, name)
}

// ParseAppleDisplayLayout parses an AppleDisplayLayout (0x451) rectangle payload.
func ParseAppleDisplayLayout(payload []byte) (backingW, backingH int, rects []DisplayRect, ok bool) {
	if len(payload) < 20 {
		return 0, 0, nil, false
	}
	bw := int(binary.BigEndian.Uint16(payload[6:8]))
	bh := int(binary.BigEndian.Uint16(payload[8:10]))
	count := int(binary.BigEndian.Uint16(payload[18:20]))
	const entrySize = 56
	off := 20
	for i := 0; i < count && off+entrySize <= len(payload); i++ {
		did := binary.BigEndian.Uint32(payload[off+16 : off+20])
		py0 := int(binary.BigEndian.Uint16(payload[off+28 : off+30]))
		px0 := int(binary.BigEndian.Uint16(payload[off+30 : off+32]))
		py1 := int(binary.BigEndian.Uint16(payload[off+32 : off+34]))
		px1 := int(binary.BigEndian.Uint16(payload[off+34 : off+36]))
		if px1 > px0 && py1 > py0 {
			rects = append(rects, DisplayRect{
				DisplayID: did,
				X:         px0,
				Y:         py0,
				W:         px1 - px0,
				H:         py1 - py0,
			})
		}
		off += entrySize
	}
	if len(rects) == 0 {
		return bw, bh, nil, false
	}
	return bw, bh, rects, true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PixelFormat is how a pixel of a standard session's picture is written (RFB's
// PIXEL_FORMAT, as ServerInit gives it).
type PixelFormat struct {
	BitsPerPixel, Depth             uint8
	BigEndian, TrueColor            bool
	RedMax, GreenMax, BlueMax       uint16
	RedShift, GreenShift, BlueShift uint8
}

// pixelsBGRX is the format asked for when the host's own is not one read
// here: four bytes a pixel, blue first.
var pixelsBGRX = PixelFormat{BitsPerPixel: 32, Depth: 24, TrueColor: true, RedMax: 255, GreenMax: 255, BlueMax: 255, RedShift: 16, GreenShift: 8}

func parsePixelFormat(b []byte) PixelFormat {
	if len(b) < 13 {
		return PixelFormat{}
	}
	return PixelFormat{BitsPerPixel: b[0], Depth: b[1], BigEndian: b[2] != 0, TrueColor: b[3] != 0,
		RedMax: binary.BigEndian.Uint16(b[4:6]), GreenMax: binary.BigEndian.Uint16(b[6:8]), BlueMax: binary.BigEndian.Uint16(b[8:10]),
		RedShift: b[10], GreenShift: b[11], BlueShift: b[12]}
}

// usable says whether pixels of this format are read here: colors of their
// own, in one, two or four bytes.
func (f PixelFormat) usable() bool {
	if !f.TrueColor || f.RedMax == 0 || f.GreenMax == 0 || f.BlueMax == 0 {
		return false
	}
	if f.BitsPerPixel != 8 && f.BitsPerPixel != 16 && f.BitsPerPixel != 32 {
		return false
	}
	return f.RedShift < f.BitsPerPixel && f.GreenShift < f.BitsPerPixel && f.BlueShift < f.BitsPerPixel
}

func (f PixelFormat) bytes() int { return int(f.BitsPerPixel) / 8 }

// bgra turns n pixels of this format into BGRA with nothing transparent. raw
// is used for the answer where it already is that, but for its fourth byte.
func (f PixelFormat) bgra(raw []byte, n int) []byte {
	if f.BitsPerPixel == 32 && !f.BigEndian && f.RedShift == 16 && f.GreenShift == 8 && f.BlueShift == 0 &&
		f.RedMax == 255 && f.GreenMax == 255 && f.BlueMax == 255 {
		for i := 3; i < n*4; i += 4 {
			raw[i] = 0xff
		}
		return raw[:n*4]
	}
	out := make([]byte, n*4)
	size := f.bytes()
	rm, gm, bm := uint32(f.RedMax), uint32(f.GreenMax), uint32(f.BlueMax)
	for i := 0; i < n; i++ {
		var v uint32
		p := raw[i*size:]
		switch {
		case size == 1:
			v = uint32(p[0])
		case size == 2 && f.BigEndian:
			v = uint32(binary.BigEndian.Uint16(p))
		case size == 2:
			v = uint32(binary.LittleEndian.Uint16(p))
		case f.BigEndian:
			v = binary.BigEndian.Uint32(p)
		default:
			v = binary.LittleEndian.Uint32(p)
		}
		out[i*4] = byte((v >> f.BlueShift & bm) * 255 / bm)
		out[i*4+1] = byte((v >> f.GreenShift & gm) * 255 / gm)
		out[i*4+2] = byte((v >> f.RedShift & rm) * 255 / rm)
		out[i*4+3] = 0xff
	}
	return out
}

// BuildSetPixelFormat encodes RFB's SetPixelFormat (0x00).
func BuildSetPixelFormat(f PixelFormat) []byte {
	b := make([]byte, 20)
	b[0] = MsgClientSetPixelFormat
	b[4], b[5] = f.BitsPerPixel, f.Depth
	if f.BigEndian {
		b[6] = 1
	}
	if f.TrueColor {
		b[7] = 1
	}
	binary.BigEndian.PutUint16(b[8:10], f.RedMax)
	binary.BigEndian.PutUint16(b[10:12], f.GreenMax)
	binary.BigEndian.PutUint16(b[12:14], f.BlueMax)
	b[14], b[15], b[16] = f.RedShift, f.GreenShift, f.BlueShift
	return b
}
