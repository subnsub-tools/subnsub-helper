package applehp

// A running session: what the host sends, handed to a Handler, and what a
// viewer sends back.
//
// Connect (client.go) leaves a session negotiated and silent. Run reads its
// three flows until one of them ends: the encrypted control stream (cursor
// shapes, the display's layout, the clipboard, answers to a new offer), the
// video socket (H.264 access units) and the control socket's media side
// (audio, and the host's RTCP, which is read and dropped).

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	MsgClientCutText        byte = 0x06
	MsgClientAutoFBUpdate   byte = 0x09
	MsgServerMediaAnswerLow byte = 0x1c

	// How much of a message that spans records is kept before the stream is
	// taken to be out of step and picked up again at the next record.
	streamPendMax = 8 << 20
	// A cursor is small; a size beyond this is a parse gone wrong.
	cursorSideMax = 512
	// One clipboard, inflated.
	clipboardMax = 1 << 20
	// How often the host is told what arrived, and how long a picture that
	// cannot be decoded waits before another key frame is asked for.
	feedbackEvery = time.Second
	keyAskEvery   = 1500 * time.Millisecond
	// One picture, as packets: beyond either it is not a picture, and is
	// dropped whole.
	videoFrameMax   = 6 << 20
	videoPacketsMax = 8192
)

// Handler is what a session's output is handed to. A nil field is not
// called. Calls of one kind come one at a time, in the host's order; calls of
// different kinds may overlap. The slices handed over are the callee's.
type Handler struct {
	// The stream's parameter sets changed (the SPS as the host sent it, with
	// its reference count raised to what the host really uses): every frame
	// from the next key frame on is decoded with these.
	VideoConfig func(sps, pps []byte)
	// One access unit, complete, as NAL units without start codes.
	VideoFrame func(ts uint32, key bool, nalus [][]byte)
	// One audio packet's payload as the host sent it, and its payload type.
	Audio func(ts uint32, seq uint16, pt byte, payload []byte)
	// A cursor shape to keep under id (RGBA, w*h*4), and the one to show.
	CursorStore  func(id uint32, hotX, hotY, w, h int, rgba []byte)
	CursorSelect func(id uint32)
	// The display's size: scaled is what the pointer's coordinates are in,
	// backing what the picture is encoded at.
	Layout func(scaledW, scaledH, backingW, backingH int)
	// The host's clipboard, as text.
	Clipboard func(text string)
}

// Stats is what a running session has counted. VideoBad and AudioBad are
// packets that did not authenticate as this session's.
type Stats struct {
	VideoPackets, VideoBad int
	Frames, Keyframes      int
	FramesLost             int
	AudioPackets, AudioBad int
	Bytes                  int64
	KeyAsks                int
}

type runState struct {
	mu          sync.Mutex
	stats       Stats
	awaitKey    bool
	lastKeyAsk  time.Time
	primarySSRC uint32
	scaledW     int
	scaledH     int
	backingW    int
	backingH    int
	layouts     int
	// A new size was asked for and the host has not yet said what it made
	// of it: its next layout is the answer, whatever it says.
	resizeAsked bool
	cursorZ     *chunkInflater
	clipZ       *chunkInflater
}

// Stats returns the counters of the session's current or last Run.
func (s *Session) Stats() Stats {
	s.runMu.Lock()
	rs := s.run
	s.runMu.Unlock()
	if rs == nil {
		return Stats{}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.stats
}

// Run carries the session until ctx ends, the host closes the control
// stream, or a socket fails. It returns nil only for ctx.
func (s *Session) Run(ctx context.Context, h Handler) error {
	rs := &runState{awaitKey: true, scaledW: s.ServerW, scaledH: s.ServerH}
	s.runMu.Lock()
	if s.run != nil {
		s.runMu.Unlock()
		return errors.New("applehp: session already running")
	}
	s.run = rs
	s.runMu.Unlock()

	outer := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 3)
	var wg sync.WaitGroup
	// Closing the sockets is what wakes the three readers.
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	// The host frees its cursor and layout messages only while its
	// framebuffer sender is armed.
	_ = s.arm()
	_ = s.Cipher.EncryptAndSend(s.tcp, []byte{MsgClientAutoPasteboard, 0, 0, 1, 0, 0, 0, 0})

	wg.Add(3)
	go func() { defer wg.Done(); errc <- s.readControl(ctx, rs, h) }()
	go func() { defer wg.Done(); errc <- s.readVideo(ctx, rs, h) }()
	go func() { defer wg.Done(); errc <- s.readMedia(ctx, rs, h) }()

	tick := time.NewTicker(feedbackEvery)
	defer tick.Stop()
	var err error
loop:
	for {
		select {
		case err = <-errc:
			break loop
		case <-tick.C:
			var fir *uint32
			rs.mu.Lock()
			if rs.awaitKey && rs.primarySSRC != 0 && time.Since(rs.lastKeyAsk) >= keyAskEvery {
				ssrc := rs.primarySSRC
				fir = &ssrc
				rs.lastKeyAsk = time.Now()
				rs.stats.KeyAsks++
			}
			rs.mu.Unlock()
			s.SendRTCPFeedback(fir)
		}
	}
	cancel()
	wg.Wait()
	// Ended from this side (the caller's ctx): whatever the readers said as
	// their sockets closed under them is not a failure.
	if outer.Err() != nil {
		return nil
	}
	if err == nil {
		err = io.EOF
	}
	return err
}

// arm sends the pair that keeps the host's cursor and layout messages
// coming: server-driven updates, and one whole-screen request.
func (s *Session) arm() error {
	var m [16]byte
	m[0] = MsgClientAutoFBUpdate
	binary.BigEndian.PutUint16(m[2:4], 1)
	binary.BigEndian.PutUint32(m[4:8], 0xffffffff)
	binary.BigEndian.PutUint16(m[12:14], 0xffff)
	binary.BigEndian.PutUint16(m[14:16], 0xffff)
	if err := s.Cipher.EncryptAndSend(s.tcp, m[:]); err != nil {
		return err
	}
	return s.Cipher.EncryptAndSend(s.tcp, BuildFBURequest(false, 0, 0, 0xffff, 0xffff))
}

// RequestKeyframe asks the host for a picture that needs no other, at the
// next report.
func (s *Session) RequestKeyframe() {
	s.runMu.Lock()
	rs := s.run
	s.runMu.Unlock()
	if rs == nil {
		return
	}
	rs.mu.Lock()
	rs.awaitKey = true
	rs.lastKeyAsk = time.Time{}
	rs.mu.Unlock()
}

// A High Performance session takes the keys and the pointer's buttons only as
// Apple's encrypted input event (0x10): the plain RFB KeyEvent and
// PointerEvent move the pointer and do nothing else (seen 2026-11-22 against
// macOS 15, Intel and Apple silicon). The message is 0x10, a flags byte (0),
// and one 16-byte block encrypted with AES-128-ECB under the record layer's
// key, which Screen Sharing decrypts with a cryptor it makes with that key
// (screensharingd SetupAESKeys, and again on each rekey). In the block:
//
//	[0]      0xff: a key           [1] 1 down, 0 up   [2:6] keysym (BE)
//	[6:10]   unused here
//	[10]     0xff: the pointer     [11] buttons and wheel (bit 0 left,
//	         1 RIGHT, 2 middle, unlike RFB's; 3 up, 4 down, 5 left,
//	         6 right, a tick each)
//	[12:14]  x   [14:16] y, in the display's scaled coordinates (BE)
//
// Bytes 0 and 10 each have to be 0x00 or 0xff, or the block is taken for a
// decryption error and dropped. Read from screensharingd's
// HandleEncryptedEventMessage (macOS 15.8, arm64e) by static disassembly;
// the buttons' bits by holding each and reading the Mac's button state.
// Screen Sharing reads keysyms its own way: Super is Command, Alt is
// Command too, and Meta is Option (screenhp_keys.go).
const msgClientEncryptedEvent = 0x10

func (s *Session) sendEvent(block *[16]byte) error {
	s.eventMu.Lock()
	if s.eventKey == nil || !bytes.Equal(s.eventKeyOf, s.Cipher.CBCKey) {
		b, err := aes.NewCipher(s.Cipher.CBCKey)
		if err != nil {
			s.eventMu.Unlock()
			return err
		}
		s.eventKey, s.eventKeyOf = b, append([]byte(nil), s.Cipher.CBCKey...)
	}
	var m [18]byte
	m[0] = msgClientEncryptedEvent
	s.eventKey.Encrypt(m[2:], block[:])
	s.eventMu.Unlock()
	return s.Cipher.EncryptAndSend(s.tcp, m[:])
}

// SendPointer is a pointer event: the buttons held as Screen Sharing counts
// them (bit 0 left, 1 right, 2 middle; 3 and 4 one notch of the wheel up and
// down, 5 and 6 left and right) and where, in the display's scaled
// coordinates.
func (s *Session) SendPointer(mask byte, x, y int) error {
	x = min(max(x, 0), 0xffff)
	y = min(max(y, 0), 0xffff)
	var p [16]byte
	p[10] = 0xff
	p[11] = mask
	binary.BigEndian.PutUint16(p[12:14], uint16(x))
	binary.BigEndian.PutUint16(p[14:16], uint16(y))
	return s.sendEvent(&p)
}

// SendKey is a key going down or coming up, as an X11 keysym.
func (s *Session) SendKey(down bool, keysym uint32) error {
	var p [16]byte
	p[0] = 0xff
	if down {
		p[1] = 1
	}
	binary.BigEndian.PutUint32(p[2:6], keysym)
	return s.sendEvent(&p)
}

// SetMode tells the host whether the viewer controls the screen or only
// observes it (RFB SetMode, 0x0a: 1 control, 0 observe), as Screen Sharing's
// own viewer does; the host shows it. What the viewer sends is its own to
// hold back.
func (s *Session) SetMode(control bool) error {
	m := []byte{MsgClientSetMode, 0, 0, 0}
	if control {
		m[3] = 1
	}
	return s.Cipher.EncryptAndSend(s.tcp, m)
}

// SendCutText puts text on the host's clipboard. The message carries
// Latin-1 only; text with anything else is refused rather than mangled.
func (s *Session) SendCutText(text string) error {
	b := make([]byte, 0, len(text))
	for _, r := range text {
		if r > 0xff {
			return errors.New("applehp: clipboard text is not Latin-1")
		}
		b = append(b, byte(r))
	}
	if len(b) > clipboardMax {
		return errors.New("applehp: clipboard text too long")
	}
	// A record's body is at most 65535 bytes, and a message is one record.
	if len(b) > 60000 {
		return errors.New("applehp: clipboard text too long for one record")
	}
	m := make([]byte, 8+len(b))
	m[0] = MsgClientCutText
	binary.BigEndian.PutUint32(m[4:8], uint32(len(b)))
	copy(m[8:], b)
	return s.Cipher.EncryptAndSend(s.tcp, m)
}

// Resize asks the host to make its virtual display w by h points, at the
// given pixel scale. It is only a request: the size the host settles on
// comes back through Handler.Layout, and the picture follows it. A session
// that shares the Mac's own display (no virtual display) cannot be resized.
func (s *Session) Resize(w, h int, hidpi float64) error {
	if !s.cfg.Curtain {
		return errors.New("applehp: this session shares the physical display")
	}
	if w < 320 || h < 200 || w > 7680 || h > 4320 {
		return fmt.Errorf("applehp: display size %dx%d out of range", w, h)
	}
	s.runMu.Lock()
	s.cfg.Width, s.cfg.Height, s.cfg.HiDPIScale = w, h, hidpi
	rs := s.run
	s.runMu.Unlock()
	if rs != nil {
		rs.mu.Lock()
		rs.resizeAsked = true
		rs.mu.Unlock()
	}
	return s.Cipher.EncryptAndSend(s.tcp, BuildVirtualDisplay(w, h, hidpi, s.cfg.HDR, "subnsub Virtual Display"))
}

// SetMaxBitrate offers the media again with another bandwidth ceiling, in
// bits a second: the host starts its encoder anew under it, from a key frame,
// as after a resize.
func (s *Session) SetMaxBitrate(bps int) error {
	if bps < 0 {
		return fmt.Errorf("applehp: bitrate %d out of range", bps)
	}
	s.runMu.Lock()
	same := s.cfg.MaxBitrate == bps
	s.cfg.MaxBitrate = bps
	s.runMu.Unlock()
	if same {
		return nil
	}
	return s.reoffer()
}

// Canvas is the size the host last said its encoder draws at.
func (s *Session) Canvas() (w, h, tiles int) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.CanvasW, s.CanvasH, s.CanvasTiles
}

// reoffer sends the media offer again, with the session's keys: what makes
// the host start its encoder at a display's new size. An offer names the
// streams anew, and the reports that follow speak as the new ones.
func (s *Session) reoffer() error {
	s.runMu.Lock()
	opts := OfferOptions{
		Codec:         s.cfg.Codec,
		TilesPerFrame: s.cfg.TilesPerFrame,
		AudioEnabled:  s.cfg.AudioEnabled,
		MaxBitrate:    s.cfg.MaxBitrate,
	}
	s.runMu.Unlock()
	video, audio, vssrc, assrc, err := CreateOffers(opts)
	if err != nil {
		return err
	}
	s.runMu.Lock()
	s.VideoSSRC, s.AudioSSRC = vssrc, assrc
	s.runMu.Unlock()
	return s.Cipher.EncryptAndSend(s.tcp, Build0x1c(audio, video, s.Keys, true, s.altSession))
}

// ── the control stream ──

func (s *Session) readControl(ctx context.Context, rs *runState, h Handler) error {
	var pend []byte
	feed := func(body []byte) {
		if len(pend) == 0 {
			pend = body
		} else {
			pend = append(pend, body...)
		}
		for len(pend) > 0 {
			n, st := s.parseServer(pend, rs, h)
			if st == parseMore {
				if len(pend) > streamPendMax {
					pend = nil
				}
				return
			}
			if st == parseLost || n <= 0 || n > len(pend) {
				pend = nil
				return
			}
			pend = pend[n:]
		}
		pend = nil
	}
	for _, m := range s.LeftoverMsgs {
		feed(m)
	}
	s.LeftoverMsgs = nil
	enc := s.rxEncBuf
	s.rxEncBuf = nil
	tmp := make([]byte, 64<<10)
	for {
		msgs, used := s.Cipher.DecryptStream(enc)
		enc = enc[used:]
		for _, m := range msgs {
			feed(m)
		}
		if len(enc) >= 2 {
			if n := int(binary.BigEndian.Uint16(enc[0:2])); n == 0 || n%enc1103BlockSize != 0 {
				return errors.New("applehp: control stream out of step")
			}
		}
		_ = s.tcp.SetReadDeadline(time.Time{})
		n, err := s.br.Read(tmp)
		if n > 0 {
			enc = append(enc, tmp[:n]...)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("applehp: control stream: %w", err)
		}
	}
}

type parseStatus int

const (
	parseOK parseStatus = iota
	parseMore
	parseLost
)

// parseServer reads one server message from the head of b. It answers how
// much it took; parseMore when the message runs past b (the rest is in the
// records to come); parseLost when what is there cannot be followed, and the
// stream is picked up again at the next record.
func (s *Session) parseServer(b []byte, rs *runState, h Handler) (int, parseStatus) {
	switch b[0] {
	case MsgServerFramebufferUpdate:
		if len(b) < 4 {
			return 0, parseMore
		}
		if b[1] == MsgServerMediaAnswerLow {
			// The answer to a media offer, which is all of its record.
			n := len(b)
			if w, hh, t, ok := ExtractCanvasDims(b); ok {
				s.runMu.Lock()
				s.CanvasW, s.CanvasH, s.CanvasTiles = w, hh, t
				s.runMu.Unlock()
			}
			return n, parseOK
		}
		return s.parseUpdate(b, rs, h)
	case MsgServerBell:
		return 1, parseOK
	case MsgServerCutText:
		if len(b) < 8 {
			return 0, parseMore
		}
		n := int(binary.BigEndian.Uint32(b[4:8]))
		if n > clipboardMax {
			return 0, parseLost
		}
		if len(b) < 8+n {
			return 0, parseMore
		}
		if h.Clipboard != nil {
			r := make([]rune, n)
			for i, c := range b[8 : 8+n] {
				r[i] = rune(c)
			}
			h.Clipboard(string(r))
		}
		return 8 + n, parseOK
	case MsgServerMiscStatus:
		if len(b) < 8 {
			return 0, parseMore
		}
		return 8, parseOK
	case MsgServerClipboardSend:
		if len(b) < 16 {
			return 0, parseMore
		}
		raw := int(binary.BigEndian.Uint32(b[8:12]))
		zn := int(binary.BigEndian.Uint32(b[12:16]))
		if raw > clipboardMax || zn > clipboardMax {
			return 0, parseLost
		}
		if len(b) < 16+zn {
			return 0, parseMore
		}
		if h.Clipboard != nil && raw > 0 {
			if rs.clipZ == nil {
				rs.clipZ = &chunkInflater{}
			}
			if arc, err := rs.clipZ.inflate(b[16:16+zn], raw); err == nil {
				if text, ok := pasteboardText(arc); ok {
					h.Clipboard(text)
				}
			}
		}
		return 16 + zn, parseOK
	}
	return 0, parseLost
}

type pendingEvent func()

// parseUpdate reads a framebuffer update: here a list of the host's own
// rectangles (cursor, layout, and metadata this client has no use for).
// Nothing is handed over until the whole update is read, so an update that
// has to wait for its next record is not acted on twice.
func (s *Session) parseUpdate(b []byte, rs *runState, h Handler) (int, parseStatus) {
	rects := int(binary.BigEndian.Uint16(b[2:4]))
	pos := 4
	var evs []pendingEvent
	done := func(st parseStatus) (int, parseStatus) {
		if st != parseMore {
			for _, e := range evs {
				e()
			}
		}
		return pos, st
	}
	for i := 0; i < rects; i++ {
		if pos+12 > len(b) {
			return 0, parseMore
		}
		x := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		y := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		w := int(binary.BigEndian.Uint16(b[pos+4 : pos+6]))
		hh := int(binary.BigEndian.Uint16(b[pos+6 : pos+8]))
		enc := int32(binary.BigEndian.Uint32(b[pos+8 : pos+12]))
		p := pos + 12
		// What a rectangle's body takes when it begins with its own
		// 16-bit length.
		prefixed := func() (int, bool) {
			if p+2 > len(b) {
				return 0, false
			}
			n := 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
			return n, p+n <= len(b)
		}
		switch enc {
		case EncAppleCursor:
			if p+8 > len(b) {
				return 0, parseMore
			}
			id := binary.BigEndian.Uint32(b[p : p+4])
			zn := int(binary.BigEndian.Uint32(b[p+4 : p+8]))
			if zn > 4<<20 {
				return done(parseLost)
			}
			if p+8+zn > len(b) {
				return 0, parseMore
			}
			if zn == 0 {
				if h.CursorSelect != nil {
					evs = append(evs, func() { h.CursorSelect(id) })
				}
			} else if w > 0 && hh > 0 && w <= cursorSideMax && hh <= cursorSideMax {
				z := append([]byte(nil), b[p+8:p+8+zn]...)
				evs = append(evs, func() {
					if rs.cursorZ == nil {
						rs.cursorZ = &chunkInflater{}
					}
					// Read even with nobody to hand it to: the next shape may
					// ride the same zlib stream.
					raw, err := rs.cursorZ.inflate(z, w*hh*5)
					if err != nil {
						return
					}
					if h.CursorStore != nil {
						h.CursorStore(id, x, y, w, hh, cursorRGBA(raw, w, hh))
					}
					if h.CursorSelect != nil {
						h.CursorSelect(id)
					}
				})
			}
			pos = p + 8 + zn
		case EncAppleLayout:
			n, ok := prefixed()
			if !ok {
				if n == 0 || p+n > len(b) {
					return 0, parseMore
				}
			}
			body := b[p+2 : p+n]
			if len(body) >= 10 {
				sw := int(binary.BigEndian.Uint16(body[2:4]))
				sh := int(binary.BigEndian.Uint16(body[4:6]))
				bw := int(binary.BigEndian.Uint16(body[6:8]))
				bh := int(binary.BigEndian.Uint16(body[8:10]))
				evs = append(evs, func() { s.onLayout(rs, h, sw, sh, bw, bh) })
			}
			pos = p + n
		case EncAppleKeysyms:
			if p+22 > len(b) {
				return 0, parseMore
			}
			pos = p + 22
		case EncAppleMediaInit:
			n, ok := prefixed()
			if !ok {
				// Read, unlike the other metadata: the rest comes with the next records.
				return 0, parseMore
			}
			// The answer to a media offer, as macOS 15 sends it (mockAnswer): the new size is
			// in its video plist, and takes effect in the order of the update's rectangles.
			for _, blob := range answerMediaBlobs(b[p : p+n]) {
				if cw, ch, t, ok := canvasFromBlob(blob); ok {
					evs = append(evs, func() {
						s.runMu.Lock()
						s.CanvasW, s.CanvasH, s.CanvasTiles = cw, ch, t
						s.runMu.Unlock()
					})
					break
				}
			}
			pos = p + n
		case EncAppleInputSrc, EncAppleDevice:
			n, ok := prefixed()
			if !ok {
				if n == 0 {
					return 0, parseMore
				}
				// Metadata nothing here reads: a length that does not close
				// inside the record ends the update with the record.
				pos = len(b)
				return done(parseOK)
			}
			pos = p + n
		case EncAppleRekey:
			// A second key for the control stream. Nothing is known of how
			// the counters carry over; say so rather than read on wrongly.
			return done(parseLost)
		default:
			return done(parseLost)
		}
	}
	return done(parseOK)
}

func (s *Session) onLayout(rs *runState, h Handler, sw, sh, bw, bh int) {
	if sw <= 0 || sh <= 0 {
		return
	}
	rs.mu.Lock()
	// The size changed: the answer to a resize, or a layout unlike the one
	// before it.
	changed := rs.resizeAsked || (rs.layouts > 0 && (bw != rs.backingW || bh != rs.backingH))
	rs.resizeAsked = false
	rs.layouts++
	rs.scaledW, rs.scaledH, rs.backingW, rs.backingH = sw, sh, bw, bh
	if changed {
		rs.awaitKey = true
	}
	rs.mu.Unlock()
	// Every layout drops the host's arming; a changed size also needs the
	// offer again, or the host sends no more pictures.
	_ = s.arm()
	if changed {
		_ = s.reoffer()
	}
	if h.Layout != nil {
		h.Layout(sw, sh, bw, bh)
	}
}

// cursorRGBA turns the host's cursor (BGRA with nothing in its fourth
// byte, then the alpha as a plane of its own) into RGBA.
func cursorRGBA(raw []byte, w, h int) []byte {
	n := w * h
	out := make([]byte, n*4)
	for i := 0; i < n; i++ {
		out[i*4] = raw[i*4+2]
		out[i*4+1] = raw[i*4+1]
		out[i*4+2] = raw[i*4]
		out[i*4+3] = raw[n*4+i]
	}
	return out
}

// pasteboardText finds plain text in the host's clipboard archive: UTF-8
// where there is some, else UTF-16.
func pasteboardText(arc []byte) (string, bool) {
	u32 := func(p int) (int, bool) {
		if p+4 > len(arc) {
			return 0, false
		}
		v := binary.BigEndian.Uint32(arc[p : p+4])
		if v > uint32(len(arc)) {
			return 0, false
		}
		return int(v), true
	}
	take := func(p *int) ([]byte, bool) {
		n, ok := u32(*p)
		if !ok || *p+4+n > len(arc) {
			return nil, false
		}
		v := arc[*p+4 : *p+4+n]
		*p += 4 + n
		return v, true
	}
	items, ok := u32(0)
	if !ok {
		return "", false
	}
	p := 4
	var utf16 []byte
	for i := 0; i < items; i++ {
		uti, ok := take(&p)
		if !ok {
			break
		}
		p += 4 // reserved
		aliases, ok := u32(p)
		if !ok {
			break
		}
		p += 4
		bad := false
		for a := 0; a < aliases; a++ {
			if _, ok := take(&p); !ok {
				bad = true
				break
			}
			if _, ok := take(&p); !ok {
				bad = true
				break
			}
		}
		if bad {
			break
		}
		data, ok := take(&p)
		if !ok {
			break
		}
		switch string(uti) {
		case "public.utf8-plain-text":
			return string(data), true
		case "public.utf16-plain-text":
			utf16 = data
		}
	}
	if len(utf16) >= 2 {
		r := make([]rune, 0, len(utf16)/2)
		for i := 0; i+1 < len(utf16); i += 2 {
			r = append(r, rune(binary.BigEndian.Uint16(utf16[i:i+2])))
		}
		return string(r), true
	}
	return "", false
}

// chunkInflater inflates pieces of a zlib stream the host flushes after
// each message. Whether the host keeps one stream for the session or starts
// one per message is not established, so it follows whichever the bytes
// are: a piece that opens with a zlib header is tried as a stream of its
// own when the running one cannot take it.
type chunkInflater struct {
	in   bytes.Buffer
	zr   io.ReadCloser
	dead bool
}

func (c *chunkInflater) inflate(piece []byte, want int) ([]byte, error) {
	if want <= 0 || want > 16<<20 {
		return nil, errors.New("applehp: inflate size out of range")
	}
	fresh := func() ([]byte, error) {
		zr, err := zlib.NewReader(bytes.NewReader(piece))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		out := make([]byte, want)
		if _, err := io.ReadFull(zr, out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if !c.dead {
		c.in.Write(piece)
		var err error
		if c.zr == nil {
			c.zr, err = zlib.NewReader(&c.in)
		}
		if err == nil {
			out := make([]byte, want)
			if _, err = io.ReadFull(c.zr, out); err == nil {
				return out, nil
			}
		}
		// The running stream is lost with this piece; from here each piece
		// stands alone or is not read.
		c.dead = true
		c.in.Reset()
	}
	return fresh()
}

// ── video ──

type videoPacket struct {
	seq     uint16
	payload []byte
}

type videoGroup struct {
	ssrc    uint32
	ts      uint32
	marker  bool
	packets []videoPacket
	bytes   int
	over    bool // past a picture's bounds: counted as lost
}

type videoAssembler struct {
	cur      *videoGroup
	sps, pps []byte
	sent     bool // the parameter sets in force have been handed over
	nextSeq  map[uint32]uint16
	haveSeq  map[uint32]bool
}

func (s *Session) readVideo(ctx context.Context, rs *runState, h Handler) error {
	va := &videoAssembler{nextSeq: map[uint32]uint16{}, haveSeq: map[uint32]bool{}}
	buf := make([]byte, 65536)
	for {
		_ = s.videoConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := s.videoConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// A frame whose last packet carried no marker is not held
				// back for the next one.
				if va.cur != nil {
					s.flushVideo(va, rs, h)
				}
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("applehp: video socket: %w", err)
		}
		if n <= 1 {
			continue
		}
		_, payload, ssrc, seq, ts, marker, ok := s.VideoDec.Decrypt(buf[:n])
		rs.mu.Lock()
		rs.stats.VideoPackets++
		if !ok {
			rs.stats.VideoBad++
			rs.mu.Unlock()
			continue
		}
		rs.stats.Bytes += int64(len(payload))
		if rs.primarySSRC != ssrc {
			// A new stream (the first, or the encoder started again at a new
			// size): nothing of the old one is a reference any more.
			if rs.primarySSRC != 0 {
				rs.awaitKey = true
			}
			rs.primarySSRC = ssrc
		}
		rs.mu.Unlock()
		if va.cur != nil && (va.cur.ssrc != ssrc || va.cur.ts != ts) {
			s.flushVideo(va, rs, h)
		}
		if va.cur == nil {
			va.cur = &videoGroup{ssrc: ssrc, ts: ts}
		}
		if g := va.cur; g.over || g.bytes+len(payload) > videoFrameMax || len(g.packets) >= videoPacketsMax {
			// Kept as a group so that its end is still seen; its packets
			// are not.
			g.over = true
			g.packets = g.packets[:0]
			g.packets = append(g.packets, videoPacket{seq: seq})
		} else {
			g.bytes += len(payload)
			g.packets = append(g.packets, videoPacket{seq: seq, payload: append([]byte(nil), payload...)})
		}
		if marker {
			va.cur.marker = true
			s.flushVideo(va, rs, h)
		}
	}
}

func (s *Session) flushVideo(va *videoAssembler, rs *runState, h Handler) {
	g := va.cur
	va.cur = nil
	if g == nil || len(g.packets) == 0 {
		return
	}
	sort.Slice(g.packets, func(i, j int) bool { return int16(g.packets[i].seq-g.packets[j].seq) < 0 })
	// Whole means: it follows the last packet handed over, and has no hole.
	whole := true
	first := g.packets[0].seq
	if va.haveSeq[g.ssrc] && first != va.nextSeq[g.ssrc] {
		whole = false
	}
	for i := 1; i < len(g.packets); i++ {
		if g.packets[i].seq != g.packets[i-1].seq+1 {
			whole = false
		}
	}
	va.nextSeq[g.ssrc] = g.packets[len(g.packets)-1].seq + 1
	va.haveSeq[g.ssrc] = true
	if g.over {
		rs.mu.Lock()
		rs.stats.FramesLost++
		rs.awaitKey = true
		rs.mu.Unlock()
		return
	}

	payloads := make([][]byte, 0, len(g.packets))
	for _, p := range g.packets {
		if len(p.payload) > 0 && p.payload[0] == AppleAVCConfigMarker {
			if sps, pps, ok := ParseAVCConfig(p.payload); ok {
				if patched, did := PatchAVCSPSMaxRefFrames(sps, 10); did {
					sps = patched
				}
				if !bytes.Equal(sps, va.sps) || !bytes.Equal(pps, va.pps) {
					va.sps, va.pps, va.sent = sps, pps, false
				}
			}
		}
		payloads = append(payloads, p.payload)
	}
	nalus := ReassembleH264(payloads)
	if len(nalus) == 0 {
		return
	}
	key := AUIsKeyframe(nalus)
	rs.mu.Lock()
	if !whole {
		rs.stats.FramesLost++
		rs.awaitKey = true
		rs.mu.Unlock()
		return
	}
	if rs.awaitKey && !key {
		rs.mu.Unlock()
		return
	}
	if key && len(va.sps) == 0 {
		// A key frame before the parameter sets cannot be decoded by anyone.
		rs.mu.Unlock()
		return
	}
	rs.awaitKey = false
	rs.stats.Frames++
	if key {
		rs.stats.Keyframes++
	}
	rs.mu.Unlock()
	if key && !va.sent {
		va.sent = true
		if h.VideoConfig != nil {
			h.VideoConfig(append([]byte(nil), va.sps...), append([]byte(nil), va.pps...))
		}
	}
	if h.VideoFrame != nil {
		h.VideoFrame(g.ts, key, nalus)
	}
}

// ── the control socket's media: audio, and the host's reports ──

func (s *Session) readMedia(ctx context.Context, rs *runState, h Handler) error {
	buf := make([]byte, 8192)
	for {
		_ = s.ctrlConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := s.ctrlConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("applehp: media socket: %w", err)
		}
		if n < rtpHeaderMinLen+srtpAuthTagLen {
			continue
		}
		// RTCP shares the port: its packet types are 192 and 200 to 207.
		if pt := buf[1]; pt == 192 || (pt >= 200 && pt <= 207) {
			continue
		}
		pt := buf[1] & 0x7f
		_, payload, _, seq, ts, _, ok := s.AudioDec.Decrypt(buf[:n])
		rs.mu.Lock()
		rs.stats.AudioPackets++
		if !ok {
			rs.stats.AudioBad++
		}
		rs.mu.Unlock()
		if !ok || len(payload) == 0 || h.Audio == nil {
			continue
		}
		h.Audio(ts, seq, pt, append([]byte(nil), payload...))
	}
}
