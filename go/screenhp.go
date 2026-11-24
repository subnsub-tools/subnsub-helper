package main

// Screen, High Performance — this Mac's own Screen Sharing as a video
// stream, for out.
//
// WHAT IT IS. out shows a Mac's screen in a window of its own on the
// owner's other Macs, and on the Monitor page through itself (put.go,
// {"op":"screen"}). It used to record the screen itself, which macOS lets
// an app do only with the Screen Recording permission, although the Mac's
// own Screen Sharing is on and does the same in its High Performance mode
// (user 2026-11-22: why should out need the Screen Recording permission when
// Screen Sharing is on; take the recording out). So out on the Mac being shown
// asks this helper for the session over put.sock ({"op":"screen-hp"});
// after the answer, the helper is the client of Screen Sharing on this Mac
// (applehp) and speaks out's frames on the connection (ScreenWire,
// input/Sources/QingyanCore/ScreenWire.swift), which out carries to the
// viewer without reading them.
//
// WHAT THE HELPER HOLDS. The account name and password arrive in the
// viewer's first word, are used to sign in, and are kept in memory for as
// long as the session lasts, never written. It dials this machine's own
// loopback address and nothing else: put.sock is the user's own, and the
// password is what Screen Sharing asks of anyone.
//
// FRAMES. ScreenWire's, each way [kind u8][length u24][body]:
//
//	to the viewer   1 status (JSON): hello {v 3, name, user, codecs,
//	                  signin}, connecting, live {w h: the display in
//	                  points, cw ch: the picture in pixels, own, audio,
//	                  input}, stats every two seconds {fps, kbps, lost,
//	                  keyframes, bad, audio, dropped, asks}, end {why: auth, no-vnc (Screen Sharing is
//	                  off), no-hp, no-media, busy, failed, closed}
//	                2 video configuration: codec (1, H.264), then avcC
//	                3 video frame: flags (1 = key), timestamp (90 kHz),
//	                  then [length u32][NAL unit] for each unit
//	                4 audio packet: codec (3, AAC-ELD: 48 kHz, two
//	                  channels, 480 samples a packet, configuration
//	                  f8e65000), timestamp (samples), sequence u16, the
//	                  access unit as the Mac sent it
//	                5 cursor shape: id u32, hot spot x y u16, size w h u16
//	                  (pixels), pixels per point u8, RGBA
//	                6 cursor shown: id u32       7 clipboard (UTF-8)
//	                8 layout: the display in points w h, the picture in
//	                  pixels w h, u16 each
//	                9 picture (a standard session): x y w h u16 (pixels),
//	                  flags, then the rectangle's BGRA rows, deflated (no
//	                  zlib header); with flag 2, the rectangle as a JPEG
//	                  instead (only to a viewer whose open said jpeg).
//	                  Flag 1 = the update is whole: show it. That one has
//	                  no rectangle, and to a viewer that said jpeg its x
//	                  and y are the update's number, high half and low
//	                  (never zero), which the viewer says back
//	from the viewer 1 control (JSON): open {codecs, audio, kbps, user,
//	                  password, own, standard, jpeg, w, h, scale}, size {w
//	                  h scale}, kbps, mode {observe} (told to the Mac, as
//	                  its own viewer does), key, clip {text} (any text;
//	                  status clip {ok: false} when it did not go: too long
//	                  for one message), text {text}, shown {n} (the update
//	                  of that number is on the viewer's screen)
//	                2 pointer: buttons u8 (1 left, 2 middle, 4 right),
//	                  x y u16 (points); Screen Sharing has middle and right
//	                  the other way round, and this turns them
//	                3 key: down u8, the Mac's virtual key code u16
//	                4 scroll: dx dy i16 (pixels, as a browser's wheel says
//	                  them), x y u16
//
// standard in open asks for no video: the Mac's display as it is, sent as
// Screen Sharing's standard mode sends it, the pixels of what changed and
// nothing while nothing does (user 2026-11-23: the Mac showing a High
// Performance stream runs hot, and the system's own standard mode does
// not). It has no sound. The hello says "standard" where the helper has it,
// and "own" where this Mac makes a display for a session.
//
// jpeg in open makes a standard session adaptive (user 2026-11-24: without
// it the picture lags too far behind to work with; it was every pixel exact,
// and up to twelve megabytes of them waiting for the viewer). The Mac's
// Screen Sharing is asked for exact pixels as before: it is on this machine,
// and what its own Adaptive Quality saves is saved on the way to a viewer,
// which here is the way from this helper. So the adapting is done here. A
// large rectangle goes as a JPEG, at a quality that follows how long the
// viewer takes to show an update; the Mac is asked for what changed next
// only once the viewer says it has shown the last, so the Mac sends what
// the display has become and not each state it went through; and where the
// display has rested a quarter of a second, the viewer is sent the same
// pixels exact. A small rectangle (a letter typed, the insertion point) is
// exact from the start.
//
// own asks for a display of the session's own, which takes the size asked
// for and follows the viewer's window (Dynamic resolution); the Mac's own
// displays are blanked while it lasts. Without it the session shows the
// Mac's main display as it is.

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"subnsubmonitor/applehp"
)

const (
	screenHPEnvVar = "MON_SCREEN_HP"

	swToStatus       = 1
	swToVideoConfig  = 2
	swToVideoFrame   = 3
	swToAudio        = 4
	swToCursorStore  = 5
	swToCursorSelect = 6
	swToClipboard    = 7
	swToLayout       = 8
	swToPicture      = 9

	swFromControl = 1
	swFromPointer = 2
	swFromKey     = 3
	swFromScroll  = 4

	swCodecAVC = 1
	swAudioELD = 3

	// What waits for the viewer: this many frames in all, of which video may
	// take this many before the newest are dropped instead.
	hpQueueLen   = 512
	hpVideoAhead = 24
	// One frame either way: a control message is small; a picture is not,
	// but it is less than the three bytes of a frame's length can say.
	hpFrameMax = 8 << 20
	// A standard session's picture goes in pieces of about this many bytes
	// of pixels, and no more than this much of it, deflated, waits for the
	// viewer: past that the Mac's own stream waits, and the Mac sends what
	// the display has become rather than every state it went through.
	hpPictureBand  = 1 << 20
	hpPictureAhead = 12 << 20
	hpControlMax   = 300 << 10
	hpClipboardMax = 256 << 10
	hpConnectWait  = 40 * time.Second
	hpFirstPicture = 5 * time.Second
	// The viewer's first word, which has to come.
	hpOpenWait = 60 * time.Second
	// A frame the viewer has not taken in this long ends the session.
	hpWriteWait = 15 * time.Second
	// Screen Sharing answers a second connection slowly when it follows the
	// first at once.
	hpRouteGap = 3 * time.Second
	// The bandwidth ceiling offered when the viewer names none, and the range
	// one may name, in kilobits a second.
	hpKbpsDefault = 12000
	hpKbpsMin     = 1000
	hpKbpsMax     = 60000
	// The pixels of the viewer's wheel to one tick of the Mac's, and the most
	// ticks one scroll message gives.
	hpScrollStep = 4
	hpScrollMax  = 64
)

// screenHPAvailable is whether this machine offers the stream: a Mac.
// MON_SCREEN_HP=off turns it off; MON_SCREEN_HP=on offers it elsewhere, for
// a test against a server that speaks the protocol.
func screenHPAvailable() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(screenHPEnvVar))) {
	case "off", "0", "false", "no":
		return false
	case "on", "1", "true", "yes":
		return true
	}
	return runtime.GOOS == "darwin"
}

// screenHPBusy: Screen Sharing gives one High Performance session at a time,
// and so does the helper.
var screenHPBusy atomic.Bool

type hpFrame struct {
	kind byte
	body []byte
}

type hpScreen struct {
	out  chan hpFrame
	ctx  context.Context
	stop context.CancelFunc
	// Closed when the session has said its last word.
	done chan struct{}

	mu      sync.Mutex
	in      []byte // what of a frame from the viewer has arrived
	opened  bool   // an open was taken; one session, one sign-in
	sess    *applehp.Session
	own     bool
	audio   bool
	hold    bool // video is being dropped until the next key frame
	ahead   int  // video frames waiting for the viewer
	dropped int
	// A standard session, the size of its picture in pixels, and how much
	// of it waits for the viewer.
	standard   bool
	picW, picH int
	picAhead   int
	deflate    *flate.Writer
	// An adaptive session (the viewer's open said jpeg). picMu: one piece
	// of the picture is made and queued at a time, the Mac's own and the
	// exact ones that follow a JPEG alike, and everything from here to
	// updSoftBytes is touched with it held. tiles: when each tile last went
	// as a JPEG (0: the viewer has it exact), tilesW across and tilesH down
	// a picture of tilesPicW by tilesPicH; soft counts those not 0.
	adaptive             bool
	picMu                sync.Mutex
	tiles                []int64
	tilesW, tilesH       int
	tilesPicW, tilesPicH int
	soft                 int
	quality              int
	// Of the update being sent: whether any of it went as a JPEG, and how
	// many bytes those were.
	updSoft      bool
	updSoftBytes int
	// The number of the last update sent whole and the last the viewer said
	// it has shown (both with mu), and a word each time it says so.
	serial, shown uint32
	shownCame     chan struct{}
	// Ends with the session on the route being tried: what a session that
	// is being let go still has to say is not waited for.
	route context.Context
	// The decoder configuration the viewer has not been sent yet: it goes
	// ahead of the key frame it is for, and waits for one that goes.
	conf []byte
	// The display's pixels to a point, for the cursor's shapes.
	scale int
	// The buttons held and where the pointer is, for the wheel's ticks; and
	// the wheel's pixels not yet a tick.
	buttons        byte
	px, py         int
	wheelX, wheelY int
	// The size the viewer last asked its own display to be: one asked for
	// while the session is still signing in is the one it is made at.
	want *hpSize
}

type hpSize struct {
	w, h  int
	scale float64
}

func newHPScreen() *hpScreen {
	ctx, cancel := context.WithCancel(context.Background())
	return &hpScreen{out: make(chan hpFrame, hpQueueLen), ctx: ctx, stop: cancel, done: make(chan struct{}), scale: 1,
		quality: hpQualityFirst, shownCame: make(chan struct{}, 1)}
}

// push queues a frame for the viewer; false when there was no room.
func (p *hpScreen) push(kind byte, body []byte) bool {
	select {
	case p.out <- hpFrame{kind, body}:
		return true
	default:
		return false
	}
}

func (p *hpScreen) status(v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	p.pushWaiting(swToStatus, b)
}

// pushWaiting is for a frame worth waiting for, which the viewer acts on: a
// status.
func (p *hpScreen) pushWaiting(kind byte, body []byte) {
	select {
	case p.out <- hpFrame{kind, body}:
	case <-p.ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

// pushLayout queues the display's size and waits for room however long: the
// viewer maps the pointer by it, so it goes or the session ends (a viewer
// that takes nothing for hpWriteWait is let go, which ends the wait).
func (p *hpScreen) pushLayout(body []byte) {
	select {
	case p.out <- hpFrame{swToLayout, body}:
	case <-p.ctx.Done():
	}
}

// hpAvcC is the decoder configuration for an H.264 stream.
func hpAvcC(sps, pps []byte) []byte {
	if len(sps) < 4 || len(pps) == 0 {
		return nil
	}
	b := []byte{1, sps[1], sps[2], sps[3], 0xff, 0xe1}
	b = binary.BigEndian.AppendUint16(b, uint16(len(sps)))
	b = append(b, sps...)
	b = append(b, 1)
	b = binary.BigEndian.AppendUint16(b, uint16(len(pps)))
	b = append(b, pps...)
	switch sps[1] {
	case 100, 110, 122, 144:
		// The high profiles name their chroma and depth: 4:2:0, 8 bits.
		b = append(b, 0xfd, 0xf8, 0xf8, 0)
	}
	return b
}

func (p *hpScreen) handler() applehp.Handler {
	return applehp.Handler{
		VideoConfig: func(sps, pps []byte) {
			if c := hpAvcC(sps, pps); c != nil {
				p.mu.Lock()
				p.conf = append([]byte{swCodecAVC}, c...)
				p.mu.Unlock()
			}
		},
		VideoFrame: func(ts uint32, key bool, nalus [][]byte) {
			p.mu.Lock()
			if p.hold && !key {
				p.dropped++
				p.mu.Unlock()
				return
			}
			if p.ahead >= hpVideoAhead {
				// The viewer is behind: nothing more until a picture that
				// stands alone, which the Mac is asked for.
				p.hold = true
				p.dropped++
				sess := p.sess
				p.mu.Unlock()
				if sess != nil {
					sess.RequestKeyframe()
				}
				return
			}
			p.mu.Unlock()
			n := 5
			for _, u := range nalus {
				n += 4 + len(u)
			}
			b := make([]byte, 5, n)
			if key {
				b[0] = 1
			}
			binary.BigEndian.PutUint32(b[1:5], ts)
			for _, u := range nalus {
				if len(u) == 0 {
					continue
				}
				// Parameter sets travel in the configuration; a delimiter is
				// nothing a decoder needs.
				if t := u[0] & 0x1f; t == 7 || t == 8 || t == 9 {
					continue
				}
				b = binary.BigEndian.AppendUint32(b, uint32(len(u)))
				b = append(b, u...)
			}
			if len(b) == 5 {
				return
			}
			p.mu.Lock()
			sent := len(b) <= hpFrameMax
			if sent && key && p.conf != nil {
				// The configuration first; kept if it did not go, for the
				// next key frame.
				if sent = p.push(swToVideoConfig, p.conf); sent {
					p.conf = nil
				}
			}
			if sent = sent && p.push(swToVideoFrame, b); sent {
				p.ahead++
				p.hold = false
			} else {
				p.hold = true
				p.dropped++
			}
			sess := p.sess
			p.mu.Unlock()
			if !sent && sess != nil {
				sess.RequestKeyframe()
			}
		},
		Audio: func(ts uint32, seq uint16, pt byte, payload []byte) {
			p.mu.Lock()
			wanted := p.audio
			p.mu.Unlock()
			if !wanted || len(payload) == 0 {
				return
			}
			b := make([]byte, 7, 7+len(payload))
			b[0] = swAudioELD
			binary.BigEndian.PutUint32(b[1:5], ts)
			binary.BigEndian.PutUint16(b[5:7], seq)
			p.push(swToAudio, append(b, payload...))
		},
		CursorStore: func(id uint32, hotX, hotY, w, h int, rgba []byte) {
			p.mu.Lock()
			scale := p.scale
			p.mu.Unlock()
			b := make([]byte, 13, 13+len(rgba))
			binary.BigEndian.PutUint32(b[0:4], id)
			binary.BigEndian.PutUint16(b[4:6], uint16(hotX))
			binary.BigEndian.PutUint16(b[6:8], uint16(hotY))
			binary.BigEndian.PutUint16(b[8:10], uint16(w))
			binary.BigEndian.PutUint16(b[10:12], uint16(h))
			b[12] = byte(scale)
			p.push(swToCursorStore, append(b, rgba...))
		},
		CursorSelect: func(id uint32) {
			p.push(swToCursorSelect, binary.BigEndian.AppendUint32(nil, id))
		},
		Layout: func(sw, sh, bw, bh int) {
			p.mu.Lock()
			if sw > 0 && bw > 0 {
				p.scale = min(max((bw+sw/2)/sw, 1), 4)
			}
			if p.standard && p.picW > 0 {
				// The picture is the size its rectangles are drawn in.
				bw, bh = p.picW, p.picH
			}
			p.mu.Unlock()
			b := make([]byte, 8)
			binary.BigEndian.PutUint16(b[0:2], uint16(sw))
			binary.BigEndian.PutUint16(b[2:4], uint16(sh))
			binary.BigEndian.PutUint16(b[4:6], uint16(bw))
			binary.BigEndian.PutUint16(b[6:8], uint16(bh))
			p.pushLayout(b)
		},
		Clipboard: func(text string) {
			if len(text) > hpClipboardMax {
				return
			}
			p.push(swToClipboard, []byte(text))
		},
		PictureSize: func(w, h int) {
			p.mu.Lock()
			p.picW, p.picH = w, h
			sess := p.sess
			p.mu.Unlock()
			if sess == nil {
				return
			}
			// The layout again, with the picture's new size.
			sw, sh, _, _ := sess.Layout()
			b := make([]byte, 8)
			binary.BigEndian.PutUint16(b[0:2], uint16(sw))
			binary.BigEndian.PutUint16(b[2:4], uint16(sh))
			binary.BigEndian.PutUint16(b[4:6], uint16(w))
			binary.BigEndian.PutUint16(b[6:8], uint16(h))
			p.pushLayout(b)
		},
		Picture: func(x, y, w, h int, bgra []byte) {
			if w <= 0 || h <= 0 || len(bgra) < w*h*4 {
				return
			}
			p.picMu.Lock()
			defer p.picMu.Unlock()
			rows := max(1, hpPictureBand/(w*4))
			if !p.adaptive || w*h < hpSoftMin {
				for top := 0; top < h; top += rows {
					n := min(rows, h-top)
					p.pushPicture(x, y+top, w, n, 0, bgra[top*w*4:(top+n)*w*4])
				}
				return
			}
			// As JPEGs, made side by side: a whole display is several.
			rows = max(hpSoftRows, rows/hpSoftRows*hpSoftRows)
			bands := (h + rows - 1) / rows
			made := make([][]byte, bands)
			quality := p.quality
			var wg sync.WaitGroup
			room := make(chan struct{}, hpEncoders())
			for i := 0; i < bands; i++ {
				top := i * rows
				n := min(rows, h-top)
				wg.Add(1)
				room <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-room }()
					made[i] = hpJPEG(bgra[top*w*4:(top+n)*w*4], w, n, quality)
				}()
			}
			wg.Wait()
			for i := 0; i < bands; i++ {
				top := i * rows
				n := min(rows, h-top)
				if made[i] == nil {
					p.pushPicture(x, y+top, w, n, 0, bgra[top*w*4:(top+n)*w*4])
					continue
				}
				p.pushPiece(x, y+top, w, n, hpPieceJPEG, made[i])
				p.wentSoft(x, y+top, w, n)
				p.updSoft = true
				p.updSoftBytes += len(made[i])
			}
		},
		PictureEnd: func() {
			p.picMu.Lock()
			serial := p.pushWhole()
			soft, sent := p.updSoft, p.updSoftBytes
			p.updSoft, p.updSoftBytes = false, 0
			p.picMu.Unlock()
			if serial != 0 {
				p.awaitShown(serial, soft, sent)
			}
		},
	}
}

const (
	// An adaptive session (jpeg in open). A rectangle of fewer pixels than
	// hpSoftMin goes exact; a larger one as JPEGs, of whole blocks of rows.
	// The quality starts at hpQualityFirst, goes down when the viewer took
	// longer than hpSoftSlow to show an update, and up when a sizable one
	// took less than hpSoftFast. An update the viewer has not said it has
	// shown after hpShownWait is no longer waited for.
	hpSoftMin      = 128 * 128
	hpSoftRows     = 16
	hpQualityFirst = 70
	hpQualityMin   = 30
	hpQualityMax   = 85
	hpSoftSlow     = 150 * time.Millisecond
	hpSoftFast     = 50 * time.Millisecond
	hpSoftSizable  = 32 << 10
	hpShownWait    = time.Second
	// What went as JPEG is remembered in tiles of hpSoftTile pixels a side.
	// A tile is sent exact once nothing of it changed for hpSoftSettle, a
	// few at a time (hpSoftEvery apart, and only while the viewer has shown
	// all it was sent): at most this many bytes of pixels a time, by the
	// quality the way allows.
	hpSoftTile    = 64
	hpSoftSettle  = 250 * time.Millisecond
	hpSoftEvery   = 50 * time.Millisecond
	hpSharpenFast = 4 << 20
	hpSharpenMid  = 1 << 20
	hpSharpenSlow = 256 << 10
	// A picture frame's flags.
	hpPieceWhole = 1
	hpPieceJPEG  = 2
)

// hpEncoders is how many JPEGs are made at once: this Mac has other work.
func hpEncoders() int { return min(max(runtime.NumCPU()/2, 1), 4) }

var hpJPEGRoom = sync.Pool{New: func() any { return new([]byte) }}

// hpJPEG is BGRA rows as a JPEG, or nil.
func hpJPEG(bgra []byte, w, h, quality int) []byte {
	n := w * h * 4
	if w <= 0 || h <= 0 || len(bgra) < n {
		return nil
	}
	room := hpJPEGRoom.Get().(*[]byte)
	defer hpJPEGRoom.Put(room)
	if cap(*room) < n {
		*room = make([]byte, n)
	}
	rgba := (*room)[:n]
	for i := 0; i < n; i += 4 {
		rgba[i], rgba[i+1], rgba[i+2], rgba[i+3] = bgra[i+2], bgra[i+1], bgra[i], 0xff
	}
	var b bytes.Buffer
	b.Grow(n / 16)
	img := &image.RGBA{Pix: rgba, Stride: w * 4, Rect: image.Rect(0, 0, w, h)}
	if jpeg.Encode(&b, img, &jpeg.Options{Quality: quality}) != nil {
		return nil
	}
	return b.Bytes()
}

// wentSoft remembers that the viewer has a rectangle as a JPEG, and since
// when. Called with picMu held.
func (p *hpScreen) wentSoft(x, y, w, h int) {
	p.mu.Lock()
	pw, ph := p.picW, p.picH
	p.mu.Unlock()
	if pw <= 0 || ph <= 0 {
		return
	}
	if pw != p.tilesPicW || ph != p.tilesPicH {
		p.tilesPicW, p.tilesPicH = pw, ph
		p.tilesW, p.tilesH = (pw+hpSoftTile-1)/hpSoftTile, (ph+hpSoftTile-1)/hpSoftTile
		p.tiles = make([]int64, p.tilesW*p.tilesH)
		p.soft = 0
	}
	now := time.Now().UnixNano()
	for ty := max(y/hpSoftTile, 0); ty <= (y+h-1)/hpSoftTile && ty < p.tilesH; ty++ {
		for tx := max(x/hpSoftTile, 0); tx <= (x+w-1)/hpSoftTile && tx < p.tilesW; tx++ {
			if p.tiles[ty*p.tilesW+tx] == 0 {
				p.soft++
			}
			p.tiles[ty*p.tilesW+tx] = now
		}
	}
}

// awaitShown waits for the viewer to say it has shown the update of this
// number, so that the Mac is asked for what changed next no sooner: what it
// then sends is the display as it is by then. How long the viewer took sets
// the quality of the JPEGs that follow.
func (p *hpScreen) awaitShown(serial uint32, soft bool, sent int) {
	p.mu.Lock()
	ctx := p.route
	p.mu.Unlock()
	if ctx == nil {
		ctx = p.ctx
	}
	from := time.Now()
	late := time.NewTimer(hpShownWait)
	defer late.Stop()
	shown := false
wait:
	for {
		p.mu.Lock()
		shown = p.shown >= serial
		p.mu.Unlock()
		if shown {
			break
		}
		select {
		case <-p.shownCame:
		case <-late.C:
			break wait
		case <-ctx.Done():
			return
		}
	}
	if !soft {
		return
	}
	took := time.Since(from)
	p.picMu.Lock()
	switch {
	case !shown || took > hpSoftSlow:
		p.quality = max(p.quality-10, hpQualityMin)
	case took < hpSoftFast && sent >= hpSoftSizable:
		p.quality = min(p.quality+5, hpQualityMax)
	}
	p.picMu.Unlock()
}

// sharpen sends the viewer exact what it has as JPEGs, where the display
// has rested, until done.
func (p *hpScreen) sharpen(sess *applehp.Session, done <-chan struct{}) {
	t := time.NewTicker(hpSoftEvery)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-p.ctx.Done():
			return
		case <-t.C:
		}
		p.picMu.Lock()
		p.sharpenSome(sess)
		p.picMu.Unlock()
	}
}

// sharpenSome is one round of sharpen. Called with picMu held, which keeps
// the Mac's own pieces from going between the reading of a tile's pixels
// and their queueing: the viewer never gets pixels older than those it has.
func (p *hpScreen) sharpenSome(sess *applehp.Session) {
	if p.soft == 0 {
		return
	}
	p.mu.Lock()
	caughtUp := p.picAhead == 0 && p.shown == p.serial
	p.mu.Unlock()
	if !caughtUp {
		return
	}
	room := hpSharpenSlow
	switch {
	case p.quality >= hpQualityFirst:
		room = hpSharpenFast
	case p.quality >= 50:
		room = hpSharpenMid
	}
	now := time.Now().UnixNano()
	due := func(tx, ty int) bool {
		t := p.tiles[ty*p.tilesW+tx]
		return t != 0 && now-t >= int64(hpSoftSettle)
	}
	sent := false
	for ty := 0; ty < p.tilesH && room > 0; ty++ {
		for tx := 0; tx < p.tilesW && room > 0; {
			if !due(tx, ty) {
				tx++
				continue
			}
			// The tiles due side by side, as one rectangle.
			first := tx
			for tx < p.tilesW && due(tx, ty) {
				p.tiles[ty*p.tilesW+tx] = 0
				p.soft--
				tx++
			}
			x, y := first*hpSoftTile, ty*hpSoftTile
			w, h := min(tx*hpSoftTile, p.tilesPicW)-x, min((ty+1)*hpSoftTile, p.tilesPicH)-y
			// Nil: the picture is no longer that size, and comes whole again.
			if pix := sess.Seen(x, y, w, h); pix != nil {
				p.pushPicture(x, y, w, h, 0, pix)
				room -= len(pix)
				sent = true
			}
		}
	}
	if sent {
		p.pushWhole()
	}
}

// pushWhole queues the word that an update is whole. To an adaptive
// session's viewer it carries the update's number, which is returned: the
// viewer says it back once the update is on its screen. Called with picMu
// held.
func (p *hpScreen) pushWhole() uint32 {
	if !p.adaptive {
		p.pushPicture(0, 0, 0, 0, hpPieceWhole, nil)
		return 0
	}
	p.mu.Lock()
	p.serial++
	if p.serial == 0 {
		p.serial = 1
	}
	serial := p.serial
	p.mu.Unlock()
	p.pushPiece(int(serial>>16), int(serial&0xffff), 0, 0, hpPieceWhole, nil)
	return serial
}

// pushPicture queues one piece of a standard session's picture, deflated, or
// the word that an update is whole. It waits for room: a piece left out
// would stay wrong on the viewer's screen until that place changed again.
// Called with picMu held.
func (p *hpScreen) pushPicture(x, y, w, h int, flags byte, bgra []byte) {
	if len(bgra) == 0 {
		p.pushPiece(x, y, w, h, flags, nil)
		return
	}
	var zb bytes.Buffer
	// One piece is made at a time (picMu).
	if p.deflate == nil {
		p.deflate, _ = flate.NewWriter(&zb, flate.BestSpeed)
	} else {
		p.deflate.Reset(&zb)
	}
	p.deflate.Write(bgra)
	p.deflate.Close()
	p.pushPiece(x, y, w, h, flags, zb.Bytes())
}

// pushPiece queues one piece of the picture as it goes: where it lies, its
// flags, and its pixels as the flags say they are. Called with picMu held.
func (p *hpScreen) pushPiece(x, y, w, h int, flags byte, pixels []byte) {
	body := make([]byte, 9, 9+len(pixels))
	binary.BigEndian.PutUint16(body[0:2], uint16(x))
	binary.BigEndian.PutUint16(body[2:4], uint16(y))
	binary.BigEndian.PutUint16(body[4:6], uint16(w))
	binary.BigEndian.PutUint16(body[6:8], uint16(h))
	body[8] = flags
	body = append(body, pixels...)
	p.mu.Lock()
	ctx := p.route
	p.mu.Unlock()
	if ctx == nil {
		ctx = p.ctx
	}
	if ctx.Err() != nil {
		return
	}
	for {
		p.mu.Lock()
		room := p.picAhead < hpPictureAhead
		if room {
			p.picAhead += len(body)
		}
		p.mu.Unlock()
		if room {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
	select {
	case p.out <- hpFrame{swToPicture, body}:
	case <-ctx.Done():
		p.mu.Lock()
		p.picAhead = max(p.picAhead-len(body), 0)
		p.mu.Unlock()
	}
}

// taken is the writer saying a frame went to the viewer.
func (p *hpScreen) taken(f hpFrame) {
	switch f.kind {
	case swToVideoFrame:
		p.mu.Lock()
		if p.ahead > 0 {
			p.ahead--
		}
		p.mu.Unlock()
	case swToPicture:
		p.mu.Lock()
		p.picAhead = max(p.picAhead-len(f.body), 0)
		p.mu.Unlock()
	}
}

// What the viewer sends as control.
type hpCommand struct {
	T        string   `json:"t"`
	Codecs   []string `json:"codecs"`
	Audio    *bool    `json:"audio"`
	Kbps     int      `json:"kbps"`
	User     string   `json:"user"`
	Password string   `json:"password"`
	Own      bool     `json:"own"`
	Standard bool     `json:"standard"`
	JPEG     bool     `json:"jpeg"`
	N        uint32   `json:"n"`
	W        int      `json:"w"`
	H        int      `json:"h"`
	Scale    float64  `json:"scale"`
	Text     string   `json:"text"`
	Observe  bool     `json:"observe"`
}

// hpRoute is one way of reaching the Screen Sharing on this machine: which
// of its addresses the connection leaves from, which it goes to, and where
// the media sockets are bound. The server sends its media to the address
// the connection came from, on its own two port numbers; which arrangement
// the system then delivers to this process is tried in order, and the one
// that worked is tried first after that.
type hpRoute struct {
	name      string
	local     string
	host      string
	udpBind   string
	reusePort bool
}

var (
	hpRouteMu   sync.Mutex
	hpRouteGood string
)

// hpRoutes: from a local network address to the loopback one first, which
// is what delivered the media on macOS 15 (2026-11-22, an M2 Pro and a 2018
// Intel Mac mini; from a tailnet address the connection is never answered,
// and from the loopback address the media goes elsewhere), then the
// loopback address itself.
func hpRoutes() []hpRoute {
	var routes []hpRoute
	if ifs, err := net.Interfaces(); err == nil {
		seen := map[string]bool{}
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				v4 := ipn.IP.To4()
				if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() || seen[v4.String()] {
					continue
				}
				// Tailscale's range.
				if v4[0] == 100 && v4[1]&0xc0 == 64 {
					continue
				}
				seen[v4.String()] = true
				routes = append(routes,
					hpRoute{name: "own-to-lo", local: v4.String(), host: "127.0.0.1", udpBind: v4.String()},
					hpRoute{name: "own-to-lo-reuse", local: v4.String(), host: "127.0.0.1", udpBind: v4.String(), reusePort: true})
			}
		}
	}
	routes = append(routes,
		hpRoute{name: "lo", local: "127.0.0.1", host: "127.0.0.1"},
		hpRoute{name: "lo-reuse", local: "127.0.0.1", host: "127.0.0.1", udpBind: "127.0.0.1", reusePort: true})
	for i := range routes {
		routes[i].name += ":" + routes[i].local + ">" + routes[i].host
	}
	hpRouteMu.Lock()
	good := hpRouteGood
	hpRouteMu.Unlock()
	if good != "" {
		for i, r := range routes {
			if r.name == good && i > 0 {
				routes = append([]hpRoute{r}, append(routes[:i:i], routes[i+1:]...)...)
				break
			}
		}
	}
	return routes
}

// hpStandardRoutes is the routes a standard session is tried on: it has no
// media to be delivered, so the loopback address first, and each way of
// reaching the Mac once.
func hpStandardRoutes(routes []hpRoute) []hpRoute {
	var lo, rest []hpRoute
	for _, r := range routes {
		switch {
		case r.reusePort:
		case r.local == "127.0.0.1":
			lo = append(lo, r)
		default:
			rest = append(rest, r)
		}
	}
	return append(lo, rest...)
}

// hpConnect is applehp.Connect, and hpRouteList the routes it is tried on;
// a test puts its own in.
var (
	hpConnect   = applehp.Connect
	hpRouteList = hpRoutes
	hpOwnHere   = hpOwnDisplayHere
)

// run is the session, from the viewer's open to its end: sign in, find the
// arrangement the media arrives on, and carry it.
func (p *hpScreen) run(o hpCommand, port int) {
	defer close(p.done)
	defer p.stop()
	if !screenHPBusy.CompareAndSwap(false, true) {
		p.status(map[string]any{"s": "end", "why": "busy"})
		return
	}
	defer screenHPBusy.Store(false)
	name := strings.TrimSpace(o.User)
	if name == "" || o.Password == "" {
		p.status(map[string]any{"s": "end", "why": "auth"})
		return
	}
	kbps := o.Kbps
	if kbps <= 0 {
		kbps = hpKbpsDefault
	}
	kbps = min(max(kbps, hpKbpsMin), hpKbpsMax)
	standard := o.Standard
	// A standard session has no sound.
	audio := (o.Audio == nil || *o.Audio) && !standard
	// A display of the session's own only where this Mac makes one
	// (hpOwnDisplayHere); elsewhere the session shows the Mac's display as
	// it is, and live says so. A standard session shows the Mac's display.
	own := o.Own && !standard && hpOwnHere()
	base := applehp.DefaultConfig()
	base.Port = port
	base.Username = name
	base.Password = o.Password
	base.AudioEnabled = audio
	base.Curtain = own
	base.MaxBitrate = kbps * 1000
	base.Standard = standard
	if standard {
		// What a standard session says of itself is worth a line in the log,
		// and the viewer is told the first of it: the log is on this Mac, and
		// the one who wants to know is at the other.
		var notes atomic.Int32
		base.Logf = func(format string, args ...any) {
			warnf("screen: "+format, args...)
			if notes.Add(1) <= 40 {
				if b, err := json.Marshal(map[string]any{"s": "note", "text": fmt.Sprintf(format, args...)}); err == nil {
					p.push(swToStatus, b)
				}
			}
		}
	}
	if own && o.W >= 320 && o.H >= 200 && o.W <= 7680 && o.H <= 4320 {
		base.Width, base.Height = o.W, o.H
		if o.Scale >= 1 && o.Scale <= 3 {
			base.HiDPIScale = o.Scale
		}
	}
	p.mu.Lock()
	p.own, p.audio, p.standard = own, audio, standard
	p.mu.Unlock()
	// Before any session's pictures: its reader finds it set.
	p.picMu.Lock()
	p.adaptive = standard && o.JPEG
	p.picMu.Unlock()
	p.status(map[string]any{"s": "connecting"})
	why := "failed"
	routes := hpRouteList()
	if standard {
		routes = hpStandardRoutes(routes)
	}
	for i, rt := range routes {
		if p.ctx.Err() != nil {
			return
		}
		if i > 0 {
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(hpRouteGap):
			}
		}
		cfg := base
		if own {
			p.mu.Lock()
			if w := p.want; w != nil {
				cfg.Width, cfg.Height, cfg.HiDPIScale = w.w, w.h, w.scale
			}
			p.mu.Unlock()
		}
		cfg.Host = rt.host
		cfg.LocalTCPAddr = rt.local
		cfg.UDPBindAddr = rt.udpBind
		cfg.ReusePort = rt.reusePort
		ctx, cancel := context.WithTimeout(p.ctx, hpConnectWait)
		sess, err := hpConnect(ctx, cfg)
		cancel()
		if err != nil {
			var be *applehp.UDPBindError
			switch {
			case errors.Is(err, applehp.ErrAuthRejected):
				p.status(map[string]any{"s": "end", "why": "auth"})
				return
			case errors.As(err, &be):
				warnf("screen: stream route %s: %v", rt.name, be.Err)
			case strings.Contains(err.Error(), "security type"):
				// A VNC server that is not a Mac's Screen Sharing.
				warnf("screen: stream route %s: %v", rt.name, err)
				why = "no-hp"
			case strings.Contains(err.Error(), "connection refused"):
				// Nothing listens: Screen Sharing is off. No other route
				// finds it on.
				p.status(map[string]any{"s": "end", "why": "no-vnc"})
				return
			default:
				warnf("screen: stream route %s: %v", rt.name, err)
			}
			continue
		}
		done := make(chan error, 1)
		rctx, rcancel := context.WithCancel(p.ctx)
		p.mu.Lock()
		p.sess = sess
		p.route = rctx
		p.hold, p.ahead = false, 0
		// A size asked for while this route was signing in: from here the
		// viewer's sizes go to the session themselves.
		late := p.want
		p.mu.Unlock()
		go func() { done <- sess.Run(rctx, p.handler()) }()
		if own && late != nil && (late.w != cfg.Width || late.h != cfg.Height || late.scale != cfg.HiDPIScale) {
			_ = sess.Resize(late.w, late.h, late.scale)
		}
		// Signed in and answered is not yet a picture: the media has to find
		// its way to this process.
		live, ended := false, false
		wait := time.NewTimer(hpFirstPicture)
		tick := time.NewTicker(100 * time.Millisecond)
	first:
		for {
			select {
			case err = <-done:
				ended = true
				break first
			case <-wait.C:
				break first
			case <-p.ctx.Done():
				break first
			case <-tick.C:
				// Packets that authenticate as this session's: its media
				// finds this process on this route. A standard session's
				// picture comes on the connection itself: its first pixels
				// (the update they are part of may take longer to go).
				if st := sess.Stats(); st.VideoPackets-st.VideoBad > 0 || (standard && st.Pictures > 0) {
					live = true
					break first
				}
			}
		}
		wait.Stop()
		tick.Stop()
		if !live {
			rcancel()
			_ = sess.Close()
			if !ended {
				// Nothing more of this session once the next is tried.
				<-done
			}
			p.mu.Lock()
			p.sess = nil
			p.mu.Unlock()
			if p.ctx.Err() != nil {
				return
			}
			if standard {
				warnf("screen: standard route %s: signed in, no picture arrived (%v)", rt.name, err)
				why = "no-picture"
				continue
			}
			warnf("screen: stream route %s: signed in, no media arrived", rt.name)
			why = "no-media"
			continue
		}
		codec := "avc"
		cw, ch, _ := sess.Canvas()
		if standard {
			codec = "pixels"
			p.mu.Lock()
			cw, ch = p.picW, p.picH
			p.mu.Unlock()
		} else {
			hpRouteMu.Lock()
			hpRouteGood = rt.name
			hpRouteMu.Unlock()
		}
		// The display as the host last said it, in the points the pointer
		// goes in: for a display of the session's own, the handshake's size
		// is that of whatever the Mac showed before it.
		sw, sh, _, _ := sess.Layout()
		warnf("screen: stream opened (%s, %dx%d)", rt.name, cw, ch)
		p.status(map[string]any{"s": "live", "w": sw, "h": sh, "cw": cw, "ch": ch,
			"own": own, "audio": audio, "input": true, "codec": codec, "standard": standard,
			"adaptive": standard && o.JPEG})
		stats := make(chan struct{})
		go p.stats(sess, stats)
		if standard && o.JPEG {
			go p.sharpen(sess, stats)
		}
		err = <-done
		close(stats)
		rcancel()
		_ = sess.Close()
		p.mu.Lock()
		p.sess = nil
		p.mu.Unlock()
		if err != nil && p.ctx.Err() == nil {
			warnf("screen: stream ended: %v", err)
		}
		p.status(map[string]any{"s": "end", "why": "closed"})
		return
	}
	p.status(map[string]any{"s": "end", "why": why})
}

// stats tells the viewer what the stream did, every two seconds, until done:
// pictures and kilobits a second, what was lost, key frames, packets that did
// not authenticate, sound packets a second, pictures not sent because the
// viewer was behind, and key frames asked for.
func (p *hpScreen) stats(sess *applehp.Session, done <-chan struct{}) {
	const every = 2 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()
	last := sess.Stats()
	for {
		select {
		case <-done:
			return
		case <-p.ctx.Done():
			return
		case <-t.C:
		}
		st := sess.Stats()
		p.mu.Lock()
		dropped := p.dropped
		p.mu.Unlock()
		secs := every.Seconds()
		b, err := json.Marshal(map[string]any{"s": "stats",
			"fps":   float64(st.Frames-last.Frames) / secs,
			"kbps":  float64(st.Bytes-last.Bytes) * 8 / 1000 / secs,
			"audio": float64(st.AudioPackets-last.AudioPackets) / secs,
			"lost":  st.FramesLost, "keyframes": st.Keyframes, "bad": st.VideoBad, "dropped": dropped, "asks": st.KeyAsks})
		last = st
		if err == nil {
			// Not waited for: the next one says the same, newer.
			p.push(swToStatus, b)
		}
	}
}

// input takes what the viewer sent: whole frames are acted on, the rest
// waits for its end. False ends the session: a frame nobody could send.
func (p *hpScreen) input(chunk []byte, port int) bool {
	p.mu.Lock()
	p.in = append(p.in, chunk...)
	var frames []hpFrame
	for len(p.in) >= 4 {
		n := int(p.in[1])<<16 | int(p.in[2])<<8 | int(p.in[3])
		if n > hpControlMax {
			p.mu.Unlock()
			return false
		}
		if len(p.in) < 4+n {
			break
		}
		frames = append(frames, hpFrame{p.in[0], append([]byte(nil), p.in[4:4+n]...)})
		p.in = p.in[4+n:]
	}
	if len(p.in) == 0 {
		p.in = nil
	}
	p.mu.Unlock()
	for _, f := range frames {
		if !p.take(f, port) {
			return false
		}
	}
	return true
}

func (p *hpScreen) take(f hpFrame, port int) bool {
	p.mu.Lock()
	sess := p.sess
	p.mu.Unlock()
	switch f.kind {
	case swFromPointer:
		if len(f.body) != 5 {
			return true
		}
		// ScreenWire's 1 left, 2 middle, 4 right; Screen Sharing's middle and
		// right the other way round.
		b := f.body[0]
		buttons := b&1 | (b&2)<<1 | (b&4)>>1
		x, y := int(binary.BigEndian.Uint16(f.body[1:3])), int(binary.BigEndian.Uint16(f.body[3:5]))
		p.mu.Lock()
		p.buttons, p.px, p.py = buttons, x, y
		p.mu.Unlock()
		if sess != nil {
			_ = sess.SendPointer(buttons, x, y)
		}
	case swFromKey:
		if len(f.body) != 3 || sess == nil {
			return true
		}
		if ks := macKeysym(binary.BigEndian.Uint16(f.body[1:3])); ks != 0 {
			_ = sess.SendKey(f.body[0] != 0, ks)
		}
	case swFromScroll:
		if len(f.body) != 8 || sess == nil {
			return true
		}
		dx, dy := int(int16(binary.BigEndian.Uint16(f.body[0:2]))), int(int16(binary.BigEndian.Uint16(f.body[2:4])))
		x, y := int(binary.BigEndian.Uint16(f.body[4:6])), int(binary.BigEndian.Uint16(f.body[6:8]))
		p.scroll(sess, dx, dy, x, y)
	case swFromControl:
		var o hpCommand
		if json.Unmarshal(f.body, &o) != nil {
			return false
		}
		switch o.T {
		case "open":
			p.mu.Lock()
			again := p.opened
			p.opened = true
			p.mu.Unlock()
			if again {
				return false
			}
			go p.run(o, port)
		case "size":
			p.mu.Lock()
			own := p.own
			p.mu.Unlock()
			// Only a display of the session's own takes another size; the
			// Mac's own is shown as it is.
			if o.W >= 320 && o.H >= 200 && o.W <= 7680 && o.H <= 4320 {
				sc := o.Scale
				if sc < 1 || sc > 3 {
					sc = 1
				}
				// Kept as well as asked for: the session may still be signing
				// in, or be made again on another route.
				p.mu.Lock()
				p.want = &hpSize{o.W, o.H, sc}
				sess = p.sess
				p.mu.Unlock()
				if sess != nil && own {
					_ = sess.Resize(o.W, o.H, sc)
				}
			}
		case "key":
			if sess != nil {
				sess.RequestKeyframe()
			}
		case "shown":
			p.mu.Lock()
			if o.N > p.shown {
				p.shown = o.N
			}
			p.mu.Unlock()
			select {
			case p.shownCame <- struct{}{}:
			default:
			}
		case "mode":
			if sess != nil {
				_ = sess.SetMode(!o.Observe)
			}
		case "kbps":
			// The viewer's quality, at once: the media is offered again under
			// the new ceiling.
			if sess != nil && o.Kbps > 0 {
				if err := sess.SetMaxBitrate(min(max(o.Kbps, hpKbpsMin), hpKbpsMax) * 1000); err != nil {
					warnf("screen: bitrate: %v", err)
				}
			}
		case "clip":
			if sess != nil && len(o.Text) <= hpClipboardMax {
				// Any text goes (applehp's SendClipboard) unless it is too long
				// for one message: the viewer is told when text did not go,
				// rather than the Mac keeping its old clipboard quietly.
				if err := sess.SendClipboard(o.Text); err != nil {
					p.status(map[string]any{"s": "clip", "ok": false})
				}
			}
		case "text":
			if sess != nil && len(o.Text) <= 16<<10 {
				for _, r := range o.Text {
					ks := runeKeysym(r)
					if ks == 0 {
						continue
					}
					_ = sess.SendKey(true, ks)
					_ = sess.SendKey(false, ks)
				}
			}
		}
	}
	return true
}

// scroll turns the viewer's wheel, in pixels, into the Mac's ticks: each a
// press of a wheel button and its release where the pointer is, an axis at a
// time (Screen Sharing takes one direction an event).
func (p *hpScreen) scroll(sess *applehp.Session, dx, dy, x, y int) {
	p.mu.Lock()
	p.px, p.py = x, y
	buttons := p.buttons
	p.wheelX += dx
	p.wheelY += dy
	var ticks []byte
	for len(ticks) < hpScrollMax && (p.wheelY >= hpScrollStep || p.wheelY <= -hpScrollStep) {
		if p.wheelY > 0 {
			// The content moves up: the wheel turns down.
			ticks = append(ticks, 0x10)
			p.wheelY -= hpScrollStep
		} else {
			ticks = append(ticks, 0x08)
			p.wheelY += hpScrollStep
		}
	}
	for len(ticks) < hpScrollMax && (p.wheelX >= hpScrollStep || p.wheelX <= -hpScrollStep) {
		if p.wheelX > 0 {
			ticks = append(ticks, 0x40)
			p.wheelX -= hpScrollStep
		} else {
			ticks = append(ticks, 0x20)
			p.wheelX += hpScrollStep
		}
	}
	if len(ticks) == hpScrollMax {
		p.wheelX, p.wheelY = 0, 0
	}
	p.mu.Unlock()
	for _, t := range ticks {
		_ = sess.SendPointer(buttons|t, x, y)
		_ = sess.SendPointer(buttons, x, y)
	}
}

// hpHello is the first thing the viewer is told: that this is the stream,
// that it signs in, and whose Mac it is, for the sign-in's account name.
func hpHello() []byte {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	b, _ := json.Marshal(map[string]any{"s": "hello", "v": 3, "name": hpComputerName(), "user": name,
		"codecs": []string{"avc"}, "signin": true, "standard": true, "own": hpOwnHere()})
	return b
}

// hpComputerName is the Mac's name as its Sharing settings give it.
func hpComputerName() string {
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--get", "ComputerName").Output(); err == nil {
			if n := strings.TrimSpace(string(out)); n != "" {
				return n
			}
		}
	}
	h, _ := os.Hostname()
	return h
}

func hpWire(kind byte, body []byte) []byte {
	b := make([]byte, 4, 4+len(body))
	b[0] = kind
	b[1], b[2], b[3] = byte(len(body)>>16), byte(len(body)>>8), byte(len(body))
	return append(b, body...)
}

// screenHPServe is put.sock's {"op":"screen-hp"}: one session on the
// connection, until either end goes.
func screenHPServe(c net.Conn) {
	defer c.Close()
	if !screenHPAvailable() {
		putAnswer(c, map[string]any{"ok": false, "error": "off"})
		return
	}
	if putAnswer(c, map[string]any{"ok": true}) != nil {
		return
	}
	p := newHPScreen()
	screenHPCarry(c, p, screenPort())
}

// screenHPCarry runs the session on c: what the viewer sends goes to p, and
// what p says goes to the viewer, its last word included.
func screenHPCarry(c net.Conn, p *hpScreen, port int) {
	defer p.stop()
	written := make(chan struct{})
	go func() {
		defer close(written)
		send := func(f hpFrame) bool {
			_ = c.SetWriteDeadline(time.Now().Add(hpWriteWait))
			if _, err := c.Write(hpWire(f.kind, f.body)); err != nil {
				return false
			}
			p.taken(f)
			return true
		}
		for {
			select {
			case f := <-p.out:
				if !send(f) {
					p.stop()
					return
				}
			case <-p.ctx.Done():
				// What was said before the end goes too: the end's reason
				// most of all.
				for {
					select {
					case f := <-p.out:
						if !send(f) {
							return
						}
					default:
						return
					}
				}
			}
		}
	}()
	// The hello, through the same queue so that it goes first.
	p.out <- hpFrame{swToStatus, hpHello()}
	go func() {
		// Once the session is over, the read waiting for the viewer ends too.
		<-p.ctx.Done()
		_ = c.SetReadDeadline(time.Now())
	}()
	go func() {
		// The viewer's first word has to come.
		t := time.NewTimer(hpOpenWait)
		defer t.Stop()
		select {
		case <-t.C:
			p.mu.Lock()
			opened := p.opened
			p.mu.Unlock()
			if !opened {
				p.stop()
			}
		case <-p.ctx.Done():
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, err := c.Read(buf)
		if n > 0 && !p.input(buf[:n], port) {
			break
		}
		if err != nil || p.ctx.Err() != nil {
			break
		}
	}
	p.stop()
	p.mu.Lock()
	opened := p.opened
	p.mu.Unlock()
	if opened {
		// The session ends with its Screen Sharing connection.
		select {
		case <-p.done:
		case <-time.After(hpConnectWait):
		}
	}
	<-written
}
