package applehp

// A running session: what the host sends, handed to a Handler, and what a
// viewer sends back.
//
// Connect (client.go) leaves a session negotiated and silent. Run reads its
// three flows until one of them ends: the encrypted control stream (cursor
// shapes, the display's layout, the clipboard, answers to a new offer), the
// video socket (H.264 access units) and the control socket's media side
// (audio, and the host's RTCP, which is read and dropped).
//
// A standard session (Config.Standard) has the control stream alone, and its
// picture comes there: rectangles of the display's pixels, sent when they
// change, as RFB has always sent them (Handler.Picture).

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
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	MsgClientCutText        byte = 0x06
	MsgClientAutoFBUpdate   byte = 0x09
	MsgServerMediaAnswerLow byte = 0x1c

	// How much of a message that spans records is kept before the stream is
	// taken to be out of step and picked up again at the next record.
	streamPendMax = 8 << 20
	// The same for a standard session, whose pictures come on the stream: a
	// whole display of pixels that did not deflate.
	picturePendMax = 160 << 20
	// The most pixels a picture or one rectangle of it holds, and the
	// longest side: what the viewer has room for, and its frames can say.
	picturePixelsMax = 48 << 20
	pictureSideMax   = 16384
	// A cursor is small; a size beyond this is a parse gone wrong.
	cursorSideMax = 512
	// One clipboard, inflated.
	clipboardMax = 1 << 20
	// How often the host is told what arrived, and how long a picture that
	// cannot be decoded waits before another key frame is asked for.
	feedbackEvery = time.Second
	keyAskEvery   = 1500 * time.Millisecond
	// A standard session asks for what changes next at once while the
	// picture changes. While the host answers with what the viewer already
	// has, the asking waits, longer each time, between these two.
	askIdleMin = 30 * time.Millisecond
	askIdleMax = 250 * time.Millisecond
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
	// A standard session's picture. PictureSize: the whole picture's size in
	// pixels, before its first rectangle and whenever it changes. Picture:
	// the pixels of one rectangle (BGRA rows, none transparent).
	// PictureEnd: the rectangles of one update have all been handed over.
	PictureSize func(w, h int)
	Picture     func(x, y, w, h int, bgra []byte)
	PictureEnd  func()
}

// Stats is what a running session has counted. VideoBad and AudioBad are
// packets that did not authenticate as this session's.
type Stats struct {
	VideoPackets, VideoBad int
	Frames, Keyframes      int
	// Rectangles of a standard session's picture that came, and those of
	// them not handed over: the viewer had their pixels already.
	Pictures, Same         int
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
	// The display asked for, in points, the forms still to try for it, and
	// the wait for the host's layouts to come to rest before its answer is
	// read (askedDisplay).
	askW, askH int
	askLeft    []int
	askTimer   *time.Timer
	// Counts the sizes asked for: an answer is read for the size it was an
	// answer to, and not once another has been asked for.
	askGen  int
	cursorZ *chunkInflater
	clipZ   *chunkInflater
	// A standard session's picture: its size, the stream its rectangles are
	// deflated in, and what ended it (a rectangle that could not be read
	// leaves every one after it unreadable).
	picW, picH int
	picZ       *chunkInflater
	picErr     error
	ticks      int
	// What the viewer has of the picture (BGRA rows, seenW by seenH; a pixel
	// never sent has nothing in its fourth byte, which no pixel sent has), so
	// that a rectangle the host sends again as it was is not sent on.
	// Written by the control stream's reader alone, with seenMu held; read
	// by it, and by Seen with seenMu held. forget: the viewer asked for the
	// whole picture, and is to get it.
	seenMu       sync.Mutex
	seen         []byte
	seenW, seenH int
	forget       bool
	// Of the update being read, the rectangles handed over.
	passed int
	// Updates with pixels, those of them with nothing new, and the times the
	// host was asked for what changes next; how long the next asking waits,
	// and whether one is waiting.
	updates, stale, asks int
	idle                 time.Duration
	asking               bool
	asked                time.Time
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
	rs := &runState{awaitKey: !s.standard, scaledW: s.ServerW, scaledH: s.ServerH}
	s.runMu.Lock()
	if s.run != nil {
		s.runMu.Unlock()
		return errors.New("applehp: session already running")
	}
	s.run = rs
	if s.standard {
		rs.picW, rs.picH = s.ServerW, s.ServerH
	}
	if s.ownDisplay() {
		rs.askW, rs.askH, rs.askLeft = s.cfg.Width, s.cfg.Height, formsAfter(s.cfg.form, s.cfg.HiDPIScale)
	}
	s.runMu.Unlock()
	defer func() {
		rs.mu.Lock()
		if rs.askTimer != nil {
			rs.askTimer.Stop()
		}
		rs.askLeft = nil
		rs.mu.Unlock()
	}()

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

	if s.standard && h.PictureSize != nil && rs.picW > 0 && rs.picH > 0 {
		h.PictureSize(rs.picW, rs.picH)
	}
	// The host frees its cursor and layout messages only while its
	// framebuffer sender is armed; a standard session's picture comes the
	// same way, whole at first and then where it changed.
	_ = s.arm()
	_ = s.Cipher.EncryptAndSend(s.tcp, []byte{MsgClientAutoPasteboard, 0, 0, 1, 0, 0, 0, 0})

	wg.Add(1)
	go func() { defer wg.Done(); errc <- s.readControl(ctx, rs, h) }()
	if !s.standard {
		wg.Add(2)
		go func() { defer wg.Done(); errc <- s.readVideo(ctx, rs, h) }()
		go func() { defer wg.Done(); errc <- s.readMedia(ctx, rs, h) }()
	}

	tick := time.NewTicker(feedbackEvery)
	defer tick.Stop()
	var err error
loop:
	for {
		select {
		case err = <-errc:
			break loop
		case <-tick.C:
			if s.standard {
				// No picture yet: asked for again, every other second.
				rs.mu.Lock()
				waiting := rs.stats.Pictures == 0
				rs.ticks++
				again := waiting && rs.ticks%2 == 0
				secs, updates, stale, asks, st := rs.ticks, rs.updates, rs.stale, rs.asks, rs.stats
				rs.mu.Unlock()
				if again {
					_ = s.arm()
				}
				if secs == 10 || secs == 60 {
					s.cfg.logf("standard: %d s: %d updates, %d of them nothing new; %d rectangles, %d not passed on; asked %d times",
						secs, updates, stale, st.Pictures, st.Same, asks)
				}
				continue
			}
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
	// A High Performance session asks for everything there could be: its
	// picture comes another way. A standard session names the display's own
	// size, as Screen Sharing's viewer does: asked for 65535 by 65535, a Mac
	// answers with two pixels by two of black and nothing after (seen
	// 2026-11-24, macOS 15 on Intel and macOS 27 on Apple silicon).
	w, h := 0xffff, 0xffff
	if s.standard {
		if sw, sh, _, _ := s.Layout(); sw > 0 && sh > 0 {
			w, h = sw, sh
		}
	}
	var m [16]byte
	m[0] = MsgClientAutoFBUpdate
	binary.BigEndian.PutUint16(m[2:4], 1)
	binary.BigEndian.PutUint32(m[4:8], 0xffffffff)
	binary.BigEndian.PutUint16(m[12:14], uint16(w))
	binary.BigEndian.PutUint16(m[14:16], uint16(h))
	if err := s.Cipher.EncryptAndSend(s.tcp, m[:]); err != nil {
		return err
	}
	return s.Cipher.EncryptAndSend(s.tcp, BuildFBURequest(false, 0, 0, uint16(w), uint16(h)))
}

// RequestKeyframe asks the host for a picture that needs no other, at the
// next report.
func (s *Session) RequestKeyframe() {
	if s.standard {
		// The whole picture again, and all of it sent on.
		s.runMu.Lock()
		rs := s.run
		s.runMu.Unlock()
		if rs != nil {
			rs.mu.Lock()
			rs.forget = true
			rs.mu.Unlock()
		}
		_ = s.arm()
		return
	}
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
	err := s.Cipher.EncryptAndSend(s.tcp, m[:])
	if s.standard && err == nil {
		s.askSoon()
	}
	return err
}

// askSoon ends a standard session's wait between askings: the viewer did
// something, and what it changes on the display is wanted at once.
func (s *Session) askSoon() {
	s.runMu.Lock()
	rs := s.run
	s.runMu.Unlock()
	if rs == nil {
		return
	}
	rs.mu.Lock()
	// Not for every one of a moving pointer's events.
	waited := rs.idle > 0 && time.Since(rs.asked) >= askIdleMin
	if waited {
		rs.idle = 0
	}
	w, h := rs.picW, rs.picH
	rs.mu.Unlock()
	if waited {
		s.askNext(rs, 0, w, h)
	}
}

// askNext asks the host for what changes next in a standard session's
// picture, after wait. One asking waits at a time.
func (s *Session) askNext(rs *runState, wait time.Duration, w, h int) {
	if w <= 0 || h <= 0 {
		return
	}
	ask := func() {
		rs.mu.Lock()
		rs.asks++
		rs.asked = time.Now()
		rs.mu.Unlock()
		_ = s.Cipher.EncryptAndSend(s.tcp, BuildFBURequest(true, 0, 0, uint16(w), uint16(h)))
	}
	if wait <= 0 {
		ask()
		return
	}
	rs.mu.Lock()
	if rs.asking {
		rs.mu.Unlock()
		return
	}
	rs.asking = true
	rs.mu.Unlock()
	time.AfterFunc(wait, func() {
		rs.mu.Lock()
		rs.asking = false
		rs.mu.Unlock()
		ask()
	})
}

// SendPointer is a pointer event: the buttons held as Screen Sharing counts
// them (bit 0 left, 1 right, 2 middle; 3 and 4 one notch of the wheel up and
// down, 5 and 6 left and right) and where, in the display's points. On a
// display of the session's own the host takes it in the display's pixels: on
// one of 1024x578 points at 2048x1156 pixels, 400,300 sent as it is put the
// pointer at 200,150 points (seen 2026-11-22, macOS 15.8.3, read there with
// CGEventGetLocation). The Mac's own display at more than a pixel a point has
// not been measured, and is sent the points as before.
func (s *Session) SendPointer(mask byte, x, y int) error {
	if sw, sh, bw, bh := s.Layout(); s.ownDisplay() && sw > 0 && sh > 0 && bw > sw && bh > sh {
		// The middle of the point.
		x, y = (2*x+1)*bw/(2*sw), (2*y+1)*bh/(2*sh)
	}
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

// SendClipboard puts text on the host's clipboard. Text Latin-1 holds goes
// as RFB's ClientCutText, as it always has. Any other goes as Screen
// Sharing's own viewer sends a clipboard: message 0x1f, the mirror of the
// one the host sends (screensharingd's HandleViewerClipboardSend, which
// hands the bytes to the agent's SetPasteboard), with the text as one
// public.utf8-plain-text flavor.
func (s *Session) SendClipboard(text string) error {
	if latin1(text) {
		return s.SendCutText(text)
	}
	if !utf8.ValidString(text) {
		return errors.New("applehp: clipboard text is not UTF-8")
	}
	if len(text) > clipboardMax {
		return errors.New("applehp: clipboard text too long")
	}
	arc := pasteboardArchive(text)
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	// The agent inflates each clipboard as a stream of its own, and takes
	// one that ends where the message does and gives the size declared.
	if _, err := zw.Write(arc); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	// A record's body is at most 65535 bytes, and a message is one record.
	if zb.Len() > 60000 {
		return errors.New("applehp: clipboard text too long for one record")
	}
	m := make([]byte, 16, 16+zb.Len())
	m[0] = MsgClientClipboardSend
	binary.BigEndian.PutUint32(m[8:12], uint32(len(arc)))
	binary.BigEndian.PutUint32(m[12:16], uint32(zb.Len()))
	m = append(m, zb.Bytes()...)
	return s.Cipher.EncryptAndSend(s.tcp, m)
}

func latin1(text string) bool {
	for _, r := range text {
		if r > 0xff {
			return false
		}
	}
	return true
}

// pasteboardArchive is text as a clipboard of one flavor, in the form the
// host's own archive has (pasteboardText reads it): the number of flavors,
// then for each its type, a word of flags, its tags (none) and its data,
// every string and the data led by their length.
func pasteboardArchive(text string) []byte {
	const uti = "public.utf8-plain-text"
	arc := make([]byte, 0, 4+4+len(uti)+4+4+4+len(text))
	arc = binary.BigEndian.AppendUint32(arc, 1)
	arc = binary.BigEndian.AppendUint32(arc, uint32(len(uti)))
	arc = append(arc, uti...)
	arc = binary.BigEndian.AppendUint32(arc, 0)
	arc = binary.BigEndian.AppendUint32(arc, 0)
	arc = binary.BigEndian.AppendUint32(arc, uint32(len(text)))
	arc = append(arc, text...)
	return arc
}

// SendCutText puts text on the host's clipboard as RFB's ClientCutText. The
// message carries Latin-1 only; text with anything else is refused rather
// than mangled (SendClipboard sends it another way).
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
	if !s.ownDisplay() {
		return errors.New("applehp: this session shares the physical display")
	}
	if w < 320 || h < 200 || w > 7680 || h > 4320 {
		return fmt.Errorf("applehp: display size %dx%d out of range", w, h)
	}
	// One display is asked for at a time, so that a form tried again for the
	// size before (askedDisplay) cannot go out after this one.
	s.displayMu.Lock()
	defer s.displayMu.Unlock()
	s.runMu.Lock()
	s.cfg.Width, s.cfg.Height, s.cfg.HiDPIScale = w, h, hidpi
	// The form the host last took: a session that came down to a pixel a
	// point stays there.
	form, hdr := s.cfg.form, s.cfg.HDR
	rs := s.run
	s.runMu.Unlock()
	if rs != nil {
		rs.mu.Lock()
		rs.resizeAsked = true
		rs.askW, rs.askH, rs.askLeft = w, h, formsAfter(form, hidpi)
		rs.askGen++
		if rs.askTimer != nil {
			rs.askTimer.Stop()
		}
		rs.mu.Unlock()
	}
	return s.Cipher.EncryptAndSend(s.tcp, displayConfig(w, h, hidpi, hdr, form))
}

// ownDisplay says whether the session was given a display of its own: asked
// for, or one the Mac makes for a session apart from its console's.
func (s *Session) ownDisplay() bool { return s.cfg.Curtain || s.altSession }

// hostForm is the form the host last made the display asked for from
// (displayConfig): the helper's host is always this Mac.
var hostForm atomic.Int32

// displaySettle is how long after a layout the host is taken to have said
// all it has to say of a display: it says each size twice, a moment apart.
const displaySettle = 900 * time.Millisecond

// formsAfter is the forms left to try when a display asked for in `form` is
// not the one the host made. At a pixel a point every form is the same.
func formsAfter(form int, scale float64) []int {
	if scale <= 1 {
		return nil
	}
	switch form {
	case formPointsFirst:
		return []int{formPixelsFirst, formPlain}
	case formPixelsFirst:
		return []int{formPointsFirst, formPlain}
	}
	return nil
}

// askedDisplay reads the host's answer to the display asked for, once its
// layouts have come to rest: the size asked for, and the form is the host's;
// another, and the display is asked for again in the next form.
func (s *Session) askedDisplay(rs *runState, gen int) {
	s.displayMu.Lock()
	defer s.displayMu.Unlock()
	rs.mu.Lock()
	if gen != rs.askGen {
		// Another size was asked for since: this answer is to the one before.
		rs.mu.Unlock()
		return
	}
	w, h, sw, sh := rs.askW, rs.askH, rs.scaledW, rs.scaledH
	near := func(a, b int) bool { return a-b <= 2 && b-a <= 2 }
	if w <= 0 || h <= 0 || (near(sw, w) && near(sh, h)) || len(rs.askLeft) == 0 {
		done := w > 0 && h > 0 && near(sw, w) && near(sh, h)
		rs.askLeft = nil
		rs.mu.Unlock()
		if done {
			s.runMu.Lock()
			form := s.cfg.form
			s.runMu.Unlock()
			if form != formPlain {
				hostForm.Store(int32(form))
			}
		}
		return
	}
	form := rs.askLeft[0]
	rs.askLeft = rs.askLeft[1:]
	rs.resizeAsked = true
	rs.mu.Unlock()
	s.runMu.Lock()
	s.cfg.form = form
	scale, hdr := s.cfg.HiDPIScale, s.cfg.HDR
	s.runMu.Unlock()
	_ = s.Cipher.EncryptAndSend(s.tcp, displayConfig(w, h, scale, hdr, form))
}

// SetMaxBitrate offers the media again with another bandwidth ceiling, in
// bits a second: the host starts its encoder anew under it, from a key frame,
// as after a resize.
func (s *Session) SetMaxBitrate(bps int) error {
	if bps < 0 {
		return fmt.Errorf("applehp: bitrate %d out of range", bps)
	}
	if s.standard {
		return nil
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

// Layout is the display's size as the host last said it (0x451): in points,
// which is what pointer events are in, and in pixels. Before it has said, the
// size from the handshake, which for a display of the session's own is that
// of whatever the Mac showed before it (backingW and backingH are then 0).
func (s *Session) Layout() (scaledW, scaledH, backingW, backingH int) {
	s.runMu.Lock()
	rs := s.run
	s.runMu.Unlock()
	if rs == nil {
		return s.ServerW, s.ServerH, 0, 0
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.scaledW, rs.scaledH, rs.backingW, rs.backingH
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
	// A standard session that lost its place cannot find it again: its
	// pictures span records, so the next record may begin inside one, and
	// the stream its rectangles are deflated in goes on from what was lost.
	// The session ends, and the viewer opens another.
	pendMax, lostPlace := streamPendMax, false
	if s.standard {
		pendMax = picturePendMax
	}
	lost := func() {
		if s.standard {
			lostPlace = true
		}
	}
	feed := func(body []byte) {
		if len(pend) == 0 {
			pend = body
		} else {
			pend = append(pend, body...)
		}
		for len(pend) > 0 {
			n, st := s.parseServer(pend, rs, h)
			if st == parseMore {
				if len(pend) > pendMax {
					pend = nil
					lost()
				}
				return
			}
			if st == parseLost || n <= 0 || n > len(pend) {
				pend = nil
				lost()
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
		rs.mu.Lock()
		picErr := rs.picErr
		rs.mu.Unlock()
		if picErr != nil {
			return picErr
		}
		if lostPlace {
			return errors.New("applehp: the standard session's control stream cannot be followed")
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
	// The bytes of the update's pixels as they came, and whether it had any.
	pictures, wire := false, 0
	// The update's rectangles in a few words, for the first updates' log lines.
	said := ""
	done := func(st parseStatus) (int, parseStatus) {
		if st != parseMore {
			rs.passed = 0
			for _, e := range evs {
				e()
			}
			if pictures {
				// An update is the viewer's only where it changes what the
				// viewer has: a Mac asked for what changes next answers at
				// once with a rectangle it has sent, some fifty times a second
				// (seen 2026-11-24, macOS 27 on Apple silicon: 37 by 26 pixels
				// of its menu bar), and the viewer drew its window as often.
				fresh := rs.passed > 0
				rs.mu.Lock()
				rs.updates++
				if fresh {
					rs.stats.Frames++
					rs.stats.Bytes += int64(wire)
					rs.idle = 0
				} else {
					rs.stale++
					rs.idle = min(max(2*rs.idle, askIdleMin), askIdleMax)
				}
				n, wait, pw, ph := rs.updates, rs.idle, rs.picW, rs.picH
				rs.mu.Unlock()
				if fresh && h.PictureEnd != nil {
					h.PictureEnd()
				}
				if n <= 12 {
					was := ""
					if !fresh {
						was = ", nothing new in it"
					}
					s.cfg.logf("standard: update %d: %s (%d bytes of pixels as sent%s)", n, said, wire, was)
				}
				// What changes next, asked for as any RFB viewer asks. The
				// host's own sending (arm) may bring the same.
				s.askNext(rs, wait, pw, ph)
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
		if s.standard {
			if i < 6 {
				said += fmt.Sprintf("[enc %d %dx%d at %d,%d]", enc, w, hh, x, y)
			}
			// The picture, and the rectangles that say something of it.
			taken := true
			switch enc {
			case EncRaw:
				if w*hh > picturePixelsMax {
					return done(parseLost)
				}
				n := w * hh * s.pixels.bytes()
				if p+n > len(b) {
					return 0, parseMore
				}
				if n > 0 {
					raw := b[p : p+n]
					evs = append(evs, func() { s.onPixels(rs, h, x, y, w, hh, append([]byte(nil), raw...)) })
					pictures, wire = true, wire+n
				}
				pos = p + n
			case EncZlib:
				if p+4 > len(b) {
					return 0, parseMore
				}
				zn := int(binary.BigEndian.Uint32(b[p : p+4]))
				if zn > picturePendMax || w*hh > picturePixelsMax {
					return done(parseLost)
				}
				if p+4+zn > len(b) {
					return 0, parseMore
				}
				z := b[p+4 : p+4+zn]
				evs = append(evs, func() {
					if rs.picZ == nil {
						rs.picZ = &chunkInflater{most: picturePixelsMax * 4, strict: true}
					}
					if w == 0 || hh == 0 {
						// No pixels, but what it holds is part of the stream
						// the next rectangle is deflated in.
						rs.picZ.feed(z)
						return
					}
					raw, err := rs.picZ.inflate(z, w*hh*s.pixels.bytes())
					if err != nil {
						rs.mu.Lock()
						if rs.picErr == nil {
							rs.picErr = fmt.Errorf("applehp: picture rectangle %dx%d at %d,%d (%d bytes deflated): %w", w, hh, x, y, zn, err)
						}
						rs.mu.Unlock()
						return
					}
					s.onPixels(rs, h, x, y, w, hh, raw)
				})
				pictures, wire = true, wire+zn
				pos = p + 4 + zn
			case EncApplePointer, EncAppleSelector:
				pos = p
			case EncDesktopSize:
				evs = append(evs, func() { s.onPictureSize(rs, h, w, hh) })
				pos = p
			default:
				taken = false
			}
			if taken {
				continue
			}
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
			if s.standard {
				s.cfg.logf("standard: a rectangle of encoding %d (0x%x), %dx%d at %d,%d, is not read", enc, uint32(enc), w, hh, x, y)
			}
			return done(parseLost)
		}
	}
	return done(parseOK)
}

// onPictureSize is the size of a standard session's picture, said to the
// handler when it is not the size it knows.
func (s *Session) onPictureSize(rs *runState, h Handler, w, hh int) {
	if w <= 0 || hh <= 0 {
		return
	}
	rs.mu.Lock()
	if w > pictureSideMax || hh > pictureSideMax || w*hh > picturePixelsMax {
		if rs.picErr == nil {
			rs.picErr = fmt.Errorf("applehp: a picture of %dx%d is more than is shown", w, hh)
		}
		rs.mu.Unlock()
		return
	}
	same := rs.picW == w && rs.picH == hh
	rs.picW, rs.picH = w, hh
	rs.mu.Unlock()
	if !same && h.PictureSize != nil {
		h.PictureSize(w, hh)
	}
}

// onPixels hands over one rectangle of a standard session's picture, as the
// host wrote its pixels, or as much of it as is not what the viewer has. A rectangle past the picture's edge makes the
// picture that large: the host said its size in points and draws in pixels.
func (s *Session) onPixels(rs *runState, h Handler, x, y, w, hh int, raw []byte) {
	rs.mu.Lock()
	pw, ph := max(rs.picW, x+w), max(rs.picH, y+hh)
	if pw > rs.picW || ph > rs.picH {
		// Likely the display's pixels, which the layout said.
		pw, ph = max(pw, rs.backingW), max(ph, rs.backingH)
	}
	rs.mu.Unlock()
	s.onPictureSize(rs, h, pw, ph)
	rs.mu.Lock()
	fits := rs.picErr == nil && x+w <= rs.picW && y+hh <= rs.picH
	pw, ph = rs.picW, rs.picH
	forget := rs.forget
	rs.forget = false
	if fits {
		rs.stats.Pictures++
	}
	rs.mu.Unlock()
	if !fits {
		return
	}
	pix := s.pixels.bgra(raw, w*hh)
	rs.seenMu.Lock()
	if rs.seenW != pw || rs.seenH != ph {
		rs.seen, rs.seenW, rs.seenH = make([]byte, pw*ph*4), pw, ph
	} else if forget {
		clear(rs.seen)
	}
	// The rows between the first and the last that are not what the viewer has.
	had := func(r int) []byte { at := ((y+r)*pw + x) * 4; return rs.seen[at : at+w*4] }
	top, end := 0, hh
	for top < end && bytes.Equal(had(top), pix[top*w*4:(top+1)*w*4]) {
		top++
	}
	for end > top && bytes.Equal(had(end-1), pix[(end-1)*w*4:end*w*4]) {
		end--
	}
	if top == end {
		rs.seenMu.Unlock()
		rs.mu.Lock()
		rs.stats.Same++
		rs.mu.Unlock()
		return
	}
	for r := top; r < end; r++ {
		copy(had(r), pix[r*w*4:(r+1)*w*4])
	}
	rs.seenMu.Unlock()
	rs.passed++
	if h.Picture != nil {
		h.Picture(x, y+top, w, end-top, pix[top*w*4:end*w*4])
	}
}

// Seen is a rectangle of a standard session's picture as the viewer was last
// handed it by Handler.Picture: its BGRA rows, exact, the caller's own. Nil
// when the picture has no such rectangle. It is for a viewer handed some of
// the picture in a form that is not exact, and due the same pixels exact
// once the display rests.
func (s *Session) Seen(x, y, w, h int) []byte {
	s.runMu.Lock()
	rs := s.run
	s.runMu.Unlock()
	if rs == nil || x < 0 || y < 0 || w <= 0 || h <= 0 {
		return nil
	}
	rs.seenMu.Lock()
	defer rs.seenMu.Unlock()
	if x+w > rs.seenW || y+h > rs.seenH || len(rs.seen) < rs.seenW*rs.seenH*4 {
		return nil
	}
	rows := make([]byte, w*h*4)
	for r := 0; r < h; r++ {
		at := ((y+r)*rs.seenW + x) * 4
		copy(rows[r*w*4:(r+1)*w*4], rs.seen[at:at+w*4])
	}
	return rows
}

func (s *Session) onLayout(rs *runState, h Handler, sw, sh, bw, bh int) {
	if sw <= 0 || sh <= 0 {
		return
	}
	rs.mu.Lock()
	// The size changed: the answer to a resize, or a layout unlike the one
	// before it.
	changed := !s.standard && (rs.resizeAsked || (rs.layouts > 0 && (bw != rs.backingW || bh != rs.backingH)))
	rs.resizeAsked = false
	rs.layouts++
	rs.scaledW, rs.scaledH, rs.backingW, rs.backingH = sw, sh, bw, bh
	if changed {
		rs.awaitKey = true
	}
	if rs.askW > 0 && len(rs.askLeft) > 0 {
		if rs.askTimer != nil {
			rs.askTimer.Stop()
		}
		gen := rs.askGen
		rs.askTimer = time.AfterFunc(displaySettle, func() { s.askedDisplay(rs, gen) })
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
	// The most one piece inflates to; zero is 16 MB.
	most int
	// A piece has to be all of what it inflates to: one that holds more
	// than the size given is an error, not the start of the next.
	strict bool
}

// chunkSlack is what a piece may leave unread once its bytes are out: the
// empty block a flush ends with, or a stream's last block and checksum.
const chunkSlack = 16

// feed adds a piece nothing is read from now to the running stream.
func (c *chunkInflater) feed(piece []byte) {
	if !c.dead && len(piece) > 0 {
		c.in.Write(piece)
	}
}

func (c *chunkInflater) inflate(piece []byte, want int) ([]byte, error) {
	if want <= 0 || want > max(c.most, 16<<20) {
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
				if c.strict && c.in.Len() > chunkSlack {
					c.dead = true
					c.in.Reset()
					return nil, errors.New("applehp: a piece holds more than its size")
				}
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
