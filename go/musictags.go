package main

// musictags.go — a music file's own tags (title, artist, album, track, year,
// cover) and its running time, read on the machine that holds the file. The
// page shows a library it never has to read itself: music.go serves the
// index this builds.
//
// Formats: ID3v2.2–2.4 (ID3v1 as the fallback) for MP3, with the running time
// from the Xing / Info / VBRI header or, for a constant bit rate, the size;
// MP4 / M4A ilst atoms and mvhd; FLAC Vorbis comments, PICTURE blocks and
// STREAMINFO; Ogg Vorbis and Opus comments (METADATA_BLOCK_PICTURE too) and
// the last page's granule; WAV LIST/INFO and "id3 " chunks; AIFF COMM and
// "ID3 " chunks. Anything else is known by its file name alone.
//
// Reads only what it needs through ReadAt: the front of the file for ID3,
// FLAC and Ogg, the atom headers for MP4 (whose moov may sit after a gigabyte
// of mdat), the tail for ID3v1 and Ogg's last page. Never panics on what it
// reads: every index below is bounds-checked, and a file it cannot make sense
// of comes back with nothing but what it could.
//
// Chinese tags: many MP3s from Chinese software declare ISO-8859-1 and carry
// GBK bytes. Text that is not UTF-8 and whose every high byte pairs inside
// GB2312's 0xA1–0xFE range is read as GBK. Latin-1 accents almost never come
// in such pairs (an accent is followed by ASCII), so "Mötley" stays Mötley.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

const (
	tagHead = 1 << 20  // the first read
	tagCap  = 16 << 20 // never more than this for tags
	tagText = 300      // runes kept of any one tag
)

// musicSource is a file that can be read anywhere in it: a local file, or a
// WebDAV file read in ranges (musicdav.go).
type musicSource interface {
	ReadAt(p []byte, off int64) (int, error)
	Size() int64
}

type musicMeta struct {
	Title, Artist, AlbumArtist, Album string
	Track, Disc, Year                 int
	Duration                          float64 // seconds; 0 when it could not be told
	Pic                               *musicPicture
	HasPic                            bool
}

type musicPicture struct {
	Mime string
	Data []byte
	Type int // the ID3 picture type; 3 is the front cover
}

// readMusicMeta reads what the file says about itself. withPic keeps the
// cover's bytes (for the art route); without it only HasPic is set, so a scan
// of ten thousand files holds no images.
func readMusicMeta(src musicSource, withPic bool) (out musicMeta) {
	m := &metaWork{out: &out, keep: withPic}
	// The files are whatever is in the folder, so a slip in a parser below
	// must cost one track its tags, never the helper its life.
	defer func() {
		if recover() != nil {
			out = musicMeta{}
		}
	}()
	size := src.Size()
	if size <= 0 {
		return out
	}
	h := sliceAt(src, 0, 16)
	switch {
	case str(h, 0, 3) == "ID3":
		end := id3Read(src, h, m)
		if str(sliceAt(src, end, 4), 0, 4) == "fLaC" {
			flacRead(src, end, m)
		} else {
			if out.Title == "" || out.Artist == "" || out.Album == "" || out.Year == 0 || out.Track == 0 {
				id3v1Read(src, m)
			}
			if out.Duration == 0 {
				out.Duration = mp3Duration(src, end, m.tlen)
			}
		}
	case str(h, 0, 4) == "fLaC":
		flacRead(src, 0, m)
	case str(h, 0, 4) == "OggS":
		oggRead(src, m)
	case str(h, 4, 4) == "ftyp":
		mp4Read(src, m)
	case str(h, 0, 4) == "RIFF" && str(h, 8, 4) == "WAVE":
		wavRead(src, m)
	case str(h, 0, 4) == "FORM" && (str(h, 8, 4) == "AIFF" || str(h, 8, 4) == "AIFC"):
		aiffRead(src, m)
	default:
		id3v1Read(src, m)
		if mp3Sync(h) {
			out.Duration = mp3Duration(src, 0, 0)
		}
	}
	if out.Artist == "" {
		out.Artist = out.AlbumArtist
	}
	out.Title = cleanTag(out.Title)
	out.Artist = cleanTag(out.Artist)
	out.AlbumArtist = cleanTag(out.AlbumArtist)
	out.Album = cleanTag(out.Album)
	if out.Duration < 0 || math.IsNaN(out.Duration) || math.IsInf(out.Duration, 0) || out.Duration > 360000 {
		out.Duration = 0
	}
	if out.Year < 1000 || out.Year > 9999 {
		out.Year = 0
	}
	if out.Track < 0 || out.Track > 9999 {
		out.Track = 0
	}
	if out.Disc < 0 || out.Disc > 999 {
		out.Disc = 0
	}
	return out
}

type metaWork struct {
	out  *musicMeta
	keep bool
	tlen float64 // ID3 TLEN, seconds
}

// ── bytes ───────────────────────────────────────────────────────────────

// sliceAt is what could be read of [off, off+n): fewer bytes near the end of
// the file, none past it.
func sliceAt(src musicSource, off, n int64) []byte {
	size := src.Size()
	if off < 0 || off >= size || n <= 0 {
		return nil
	}
	if off+n > size {
		n = size - off
	}
	b := make([]byte, n)
	got, _ := src.ReadAt(b, off)
	if got < 0 {
		got = 0
	}
	return b[:got]
}

func str(b []byte, at, n int) string {
	if at < 0 || n <= 0 || at >= len(b) {
		return ""
	}
	end := len(b)
	if n < end-at {
		end = at + n
	}
	return string(b[at:end])
}

func sub(b []byte, from, to int) []byte {
	if from < 0 {
		from = 0
	}
	if to > len(b) {
		to = len(b)
	}
	if from >= to {
		return nil
	}
	return b[from:to]
}

func be16(b []byte, at int) int {
	if at < 0 || at > len(b)-2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[at:]))
}

func be32(b []byte, at int) int64 {
	if at < 0 || at > len(b)-4 {
		return 0
	}
	return int64(binary.BigEndian.Uint32(b[at:]))
}

func be64(b []byte, at int) int64 {
	if at < 0 || at > len(b)-8 {
		return 0
	}
	v := binary.BigEndian.Uint64(b[at:])
	if v > math.MaxInt64 {
		return 0
	}
	return int64(v)
}

func le16(b []byte, at int) int {
	if at < 0 || at > len(b)-2 {
		return 0
	}
	return int(binary.LittleEndian.Uint16(b[at:]))
}

func le32(b []byte, at int) int64 {
	if at < 0 || at > len(b)-4 {
		return 0
	}
	return int64(binary.LittleEndian.Uint32(b[at:]))
}

func le64(b []byte, at int) uint64 {
	if at < 0 || at > len(b)-8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b[at:])
}

func syncsafe(b []byte, at int) int64 {
	if at < 0 || at > len(b)-4 {
		return 0
	}
	return int64(b[at]&0x7f)<<21 | int64(b[at+1]&0x7f)<<14 | int64(b[at+2]&0x7f)<<7 | int64(b[at+3]&0x7f)
}

// ── text ────────────────────────────────────────────────────────────────

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func looksGBK(b []byte) bool {
	hi := 0
	for i := 0; i < len(b); i++ {
		if b[i] < 0x80 {
			continue
		}
		if b[i] < 0xA1 || b[i] > 0xFE || i+1 >= len(b) || b[i+1] < 0xA1 || b[i+1] > 0xFE {
			return false
		}
		hi++
		i++
	}
	return hi > 0
}

// narrowText reads a string declared ISO-8859-1: UTF-8 if it is valid UTF-8
// with something outside ASCII, GBK if it pairs up like GBK, Latin-1
// otherwise.
func narrowText(b []byte) string {
	high := false
	for _, c := range b {
		if c >= 0x80 {
			high = true
			break
		}
	}
	if !high {
		return string(b)
	}
	if utf8.Valid(b) {
		return string(b)
	}
	if looksGBK(b) {
		if s, err := simplifiedchinese.GBK.NewDecoder().Bytes(b); err == nil {
			return string(s)
		}
	}
	return latin1(b)
}

func utf16Text(b []byte, big bool) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		if big {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return string(utf16.Decode(u))
}

func utf8Text(b []byte) string { return strings.ToValidUTF8(string(b), "\uFFFD") }

// firstValue is the first of a NUL-separated list (ID3v2.4 multi-values).
func firstValue(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func id3Text(b []byte, enc byte) string {
	switch enc {
	case 0:
		return firstValue(narrowText(b))
	case 3:
		return firstValue(utf8Text(b))
	case 2:
		return firstValue(utf16Text(b, true))
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		return firstValue(utf16Text(b[2:], true))
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return firstValue(utf16Text(b[2:], false))
	}
	return firstValue(utf16Text(b, false))
}

// cleanTag drops control characters and keeps a tag to a sane length.
func cleanTag(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > tagText {
		r := []rune(s)
		s = string(r[:tagText])
	}
	return s
}

// leadingInt is the number a tag starts with: "3/12" is 3, "2019-05-01" is
// 2019.
func leadingInt(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for n < len(s) && n < 9 && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 {
		return 0
	}
	v, _ := strconv.Atoi(s[:n])
	return v
}

// ── pictures ────────────────────────────────────────────────────────────

func sniffImage(d []byte) string {
	switch {
	case len(d) >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF:
		return "image/jpeg"
	case len(d) >= 8 && bytes.Equal(d[:8], []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case len(d) >= 12 && str(d, 0, 4) == "RIFF" && str(d, 8, 4) == "WEBP":
		return "image/webp"
	case len(d) >= 6 && (str(d, 0, 6) == "GIF87a" || str(d, 0, 6) == "GIF89a"):
		return "image/gif"
	}
	return ""
}

// takePic keeps the front cover (type 3) over whatever came first. Without
// keep only the fact that there is one is kept.
func (m *metaWork) takePic(data []byte, typ int) {
	if len(data) < 16 || sniffImage(data) == "" {
		return
	}
	m.out.HasPic = true
	if !m.keep {
		return
	}
	if m.out.Pic == nil || (typ == 3 && m.out.Pic.Type != 3) {
		m.out.Pic = &musicPicture{Mime: sniffImage(data), Data: append([]byte(nil), data...), Type: typ}
	}
}

// ── ID3v2 ───────────────────────────────────────────────────────────────

// id3Read reads the tag at the front of the file and returns where it ends.
func id3Read(src musicSource, head []byte, m *metaWork) int64 {
	total := 10 + syncsafe(head, 6)
	if len(head) > 5 && head[5]&0x10 != 0 {
		total += 10 // a footer
	}
	n := total
	if n > tagCap {
		n = tagCap
	}
	parseID3(sliceAt(src, 0, n), m)
	return total
}

func unsync(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		out = append(out, b[i])
		if b[i] == 0xFF && i+1 < len(b) && b[i+1] == 0x00 {
			i++
		}
	}
	return out
}

// parseID3 reads one whole ID3v2 tag, header included.
func parseID3(b []byte, m *metaWork) {
	if len(b) < 10 || str(b, 0, 3) != "ID3" {
		return
	}
	ver, flags := b[3], b[5]
	if ver < 2 || ver > 4 {
		return
	}
	body := sub(b, 10, 10+int(syncsafe(b, 6)))
	if ver < 4 && flags&0x80 != 0 {
		body = unsync(body)
	}
	p := 0
	if flags&0x40 != 0 {
		switch ver {
		case 3:
			p = int(be32(body, 0)) + 4
		case 4:
			p = int(syncsafe(body, 0))
		}
	}
	idLen, hdr := 4, 10
	if ver == 2 {
		idLen, hdr = 3, 6
	}
	for p >= 0 && p+hdr <= len(body) {
		id := str(body, p, idLen)
		if !frameID(id) {
			break
		}
		var fs int
		switch ver {
		case 2:
			fs = int(body[p+3])<<16 | int(body[p+4])<<8 | int(body[p+5])
		case 4:
			fs = int(syncsafe(body, p+4))
		default:
			fs = int(be32(body, p+4))
		}
		ff := byte(0)
		if ver != 2 {
			ff = body[p+9]
		}
		if fs < 0 || fs > len(body) {
			break
		}
		d := sub(body, p+hdr, p+hdr+fs)
		p += hdr + fs
		if fs == 0 {
			continue
		}
		switch ver {
		case 4:
			if ff&0x0C != 0 { // compressed or encrypted
				continue
			}
			off := 0
			if ff&0x40 != 0 {
				off++
			}
			if ff&0x01 != 0 {
				off += 4
			}
			d = sub(d, off, len(d))
			if ff&0x02 != 0 {
				d = unsync(d)
			}
		case 3:
			if ff&0xC0 != 0 {
				continue
			}
			if ff&0x20 != 0 {
				d = sub(d, 1, len(d))
			}
		}
		id3Frame(id, d, m)
	}
}

func frameID(id string) bool {
	if len(id) < 3 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// pastTerm is the index just past a string's terminator: one zero byte, or an
// aligned pair for the UTF-16 encodings.
func pastTerm(b []byte, p int, enc byte) int {
	if p < 0 {
		return len(b)
	}
	if enc == 1 || enc == 2 {
		for i := p; i+1 < len(b); i += 2 {
			if b[i] == 0 && b[i+1] == 0 {
				return i + 2
			}
		}
		return len(b)
	}
	for j := p; j < len(b); j++ {
		if b[j] == 0 {
			return j + 1
		}
	}
	return len(b)
}

func id3Frame(id string, d []byte, m *metaWork) {
	if len(d) == 0 {
		return
	}
	enc := d[0]
	text := func() string { return id3Text(d[1:], enc) }
	o := m.out
	switch id {
	case "TIT2", "TT2":
		if o.Title == "" {
			o.Title = text()
		}
	case "TPE1", "TP1":
		if o.Artist == "" {
			o.Artist = text()
		}
	case "TPE2", "TP2":
		if o.AlbumArtist == "" {
			o.AlbumArtist = text()
		}
	case "TALB", "TAL":
		if o.Album == "" {
			o.Album = text()
		}
	case "TRCK", "TRK":
		if o.Track == 0 {
			o.Track = leadingInt(text())
		}
	case "TPOS", "TPA":
		if o.Disc == 0 {
			o.Disc = leadingInt(text())
		}
	case "TYER", "TYE", "TDRC", "TDRL", "TDOR", "TORY":
		if o.Year == 0 {
			o.Year = leadingInt(text())
		}
	case "TLEN", "TLE":
		if ms := leadingInt(text()); ms > 0 {
			m.tlen = float64(ms) / 1000
		}
	case "APIC":
		mt := pastTerm(d, 1, 0)
		if mt >= len(d) {
			return
		}
		typ := int(d[mt])
		start := pastTerm(d, mt+1, enc)
		m.takePic(sub(d, start, len(d)), typ)
	case "PIC":
		if len(d) < 6 {
			return
		}
		typ := int(d[4])
		start := pastTerm(d, 5, enc)
		m.takePic(sub(d, start, len(d)), typ)
	}
}

func id3v1Read(src musicSource, m *metaWork) {
	size := src.Size()
	if size < 128 {
		return
	}
	b := sliceAt(src, size-128, 128)
	if str(b, 0, 3) != "TAG" {
		return
	}
	field := func(at, n int) string {
		e := at
		for e < at+n && e < len(b) && b[e] != 0 {
			e++
		}
		return strings.TrimSpace(narrowText(sub(b, at, e)))
	}
	o := m.out
	if o.Title == "" {
		o.Title = field(3, 30)
	}
	if o.Artist == "" {
		o.Artist = field(33, 30)
	}
	if o.Album == "" {
		o.Album = field(63, 30)
	}
	if o.Year == 0 {
		o.Year = leadingInt(field(93, 4))
	}
	// ID3v1.1: a zero byte before the comment's last byte makes that byte the
	// track number.
	if o.Track == 0 && len(b) == 128 && b[125] == 0 && b[126] != 0 {
		o.Track = int(b[126])
	}
}

// ── MP3 running time ────────────────────────────────────────────────────

var (
	mp3Rates = [4][3]int{{11025, 12000, 8000}, {}, {22050, 24000, 16000}, {44100, 48000, 32000}}
	mp3Kbps  = map[[2]int][15]int{
		{3, 3}: {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448}, // MPEG-1 layer I
		{3, 2}: {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384},    // MPEG-1 layer II
		{3, 1}: {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320},     // MPEG-1 layer III
		{2, 3}: {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256},    // MPEG-2/2.5 layer I
		{2, 2}: {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},         // MPEG-2/2.5 layer II
		{2, 1}: {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},         // MPEG-2/2.5 layer III
	}
)

type mp3Header struct {
	version, layer, kbps, rate, length, samples int
	mono                                        bool
}

func mp3Parse(b []byte, at int) (mp3Header, bool) {
	var h mp3Header
	if at < 0 || at+4 > len(b) || b[at] != 0xFF || b[at+1]&0xE0 != 0xE0 {
		return h, false
	}
	h.version = int(b[at+1]>>3) & 3 // 0 = 2.5, 2 = 2, 3 = 1
	h.layer = int(b[at+1]>>1) & 3   // 1 = III, 2 = II, 3 = I
	bi, ri := int(b[at+2]>>4), int(b[at+2]>>2)&3
	if h.version == 1 || h.layer == 0 || bi == 0 || bi == 15 || ri == 3 {
		return h, false
	}
	table := 2
	if h.version == 3 {
		table = 3
	}
	h.kbps = mp3Kbps[[2]int{table, h.layer}][bi]
	h.rate = mp3Rates[h.version][ri]
	pad := int(b[at+2]>>1) & 1
	h.mono = b[at+3]>>6 == 3
	switch {
	case h.layer == 3:
		h.samples = 384
		h.length = (12*h.kbps*1000/h.rate + pad) * 4
	case h.layer == 2 || h.version == 3:
		h.samples = 1152
		h.length = 144*h.kbps*1000/h.rate + pad
	default:
		h.samples = 576
		h.length = 72*h.kbps*1000/h.rate + pad
	}
	return h, h.rate > 0 && h.length > 4
}

func mp3Sync(b []byte) bool {
	_, ok := mp3Parse(b, 0)
	return ok
}

// mp3Duration finds the first frame at or after audio and reads the running
// time from its Xing / Info / VBRI header, else from the constant bit rate.
// tlen, the tag's own figure, is the answer when there is no frame to read.
func mp3Duration(src musicSource, audio int64, tlen float64) float64 {
	b := sliceAt(src, audio, 64<<10)
	for i := 0; i+4 <= len(b); i++ {
		h, ok := mp3Parse(b, i)
		if !ok {
			continue
		}
		// Two frames in a row, or this is noise that looks like a header.
		if i+h.length+4 <= len(b) {
			if _, ok2 := mp3Parse(b, i+h.length); !ok2 {
				continue
			}
		}
		side := 17
		if h.version == 3 {
			side = 32
			if h.mono {
				side = 17
			}
		} else if h.mono {
			side = 9
		}
		x := i + 4 + side
		if tag := str(b, x, 4); tag == "Xing" || tag == "Info" {
			if flags := be32(b, x+4); flags&1 != 0 {
				if frames := be32(b, x+8); frames > 0 {
					return float64(frames) * float64(h.samples) / float64(h.rate)
				}
			}
		}
		if str(b, i+36, 4) == "VBRI" {
			if frames := be32(b, i+36+14); frames > 0 {
				return float64(frames) * float64(h.samples) / float64(h.rate)
			}
		}
		if tlen > 0 {
			return tlen
		}
		end := src.Size()
		if t := sliceAt(src, end-128, 3); string(t) == "TAG" {
			end -= 128
		}
		n := end - audio - int64(i)
		if n <= 0 || h.kbps <= 0 {
			return 0
		}
		return float64(n) * 8 / float64(h.kbps*1000)
	}
	return tlen
}

// ── Vorbis comments (FLAC block 4, Ogg Vorbis / Opus) ───────────────────

func flacPicture(b []byte, m *metaWork) {
	if len(b) < 32 {
		return
	}
	// Offsets in int64: each length is 32 bits, and on a 32-bit int their
	// sum wraps.
	L := int64(len(b))
	typ := be32(b, 0)
	p := 4 + 4 + be32(b, 4) // the type, the mime type
	if p > L-4 {
		return
	}
	p += 4 + be32(b, int(p)) + 16 // the description; width, height, depth, colours
	if p > L-4 {
		return
	}
	n := be32(b, int(p))
	p += 4
	if n > L-p {
		return
	}
	if typ > 255 {
		typ = 0
	}
	m.takePic(b[p:p+n], int(typ))
}

func vorbisComments(b []byte, p int, m *metaWork) {
	L := int64(len(b))
	q := int64(p)
	if q < 0 || q > L-8 {
		return
	}
	q += 4 + le32(b, int(q)) // the vendor string
	if q > L-4 {
		return
	}
	n := le32(b, int(q))
	q += 4
	o := m.out
	for i := int64(0); i < n && q <= L-4; i++ {
		l := le32(b, int(q))
		q += 4
		if l > L-q {
			return
		}
		s := utf8Text(b[q : q+l])
		q += l
		eq := strings.IndexByte(s, '=')
		if eq < 1 {
			continue
		}
		k, v := strings.ToUpper(s[:eq]), strings.TrimSpace(s[eq+1:])
		switch k {
		case "TITLE":
			if o.Title == "" {
				o.Title = v
			}
		case "ARTIST":
			if o.Artist == "" {
				o.Artist = v
			}
		case "ALBUMARTIST", "ALBUM ARTIST":
			if o.AlbumArtist == "" {
				o.AlbumArtist = v
			}
		case "ALBUM":
			if o.Album == "" {
				o.Album = v
			}
		case "TRACKNUMBER":
			if o.Track == 0 {
				o.Track = leadingInt(v)
			}
		case "DISCNUMBER":
			if o.Disc == 0 {
				o.Disc = leadingInt(v)
			}
		case "DATE", "YEAR", "ORIGINALDATE":
			if o.Year == 0 {
				o.Year = leadingInt(v)
			}
		case "METADATA_BLOCK_PICTURE":
			if raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), "")); err == nil {
				flacPicture(raw, m)
			}
		}
	}
}

// ── FLAC ── starting at `at` (after an ID3 prefix, if there was one) ─────

func flacRead(src musicSource, at int64, m *metaWork) {
	// The blocks' own lengths say how far the metadata runs: read the front,
	// and again as far as a block that ran past it (a big cover), never past
	// tagCap. Each pass meets the blocks already read again; first value wins,
	// so they change nothing.
	parse := func(b []byte) int64 {
		p := 4
		for {
			if p+4 > len(b) {
				// The read ended between blocks, after one that was not the
				// last: ask for the next header.
				return int64(p + 4)
			}
			last, typ := b[p]&0x80 != 0, b[p]&0x7f
			l := int(b[p+1])<<16 | int(b[p+2])<<8 | int(b[p+3])
			if p+4+l > len(b) {
				return int64(p + 4 + l)
			}
			blk := b[p+4 : p+4+l]
			switch typ {
			case 0:
				if len(blk) >= 18 && m.out.Duration == 0 {
					rate := int64(blk[10])<<12 | int64(blk[11])<<4 | int64(blk[12])>>4
					total := int64(blk[13]&0x0F)<<32 | int64(blk[14])<<24 | int64(blk[15])<<16 | int64(blk[16])<<8 | int64(blk[17])
					if rate > 0 && total > 0 {
						m.out.Duration = float64(total) / float64(rate)
					}
				}
			case 4:
				vorbisComments(blk, 0, m)
			case 6:
				flacPicture(blk, m)
			}
			p += 4 + l
			if last {
				return 0
			}
		}
	}
	n := int64(tagHead)
	for left := 8; left >= 0; left-- {
		b := sliceAt(src, at, n)
		need := parse(b)
		if need == 0 || need > tagCap || at+int64(len(b)) >= src.Size() {
			return
		}
		n = need + tagHead
		if n > tagCap {
			n = tagCap
		}
	}
}

// ── Ogg ── the first packet names the codec, the second is the comments ──

func oggRead(src musicSource, m *metaWork) {
	scan := func(b []byte) (serial int64, packets [][]byte) {
		p := 0
		serial = -1
		var cur []byte
		for p+27 <= len(b) && len(packets) < 2 {
			if str(b, p, 4) != "OggS" {
				return serial, nil
			}
			sn := le32(b, p+14)
			ns := int(b[p+26])
			segs := sub(b, p+27, p+27+ns)
			q := p + 27 + ns
			if serial < 0 {
				serial = sn
			}
			for i := 0; i < len(segs); i++ {
				l := int(segs[i])
				if sn == serial {
					cur = append(cur, sub(b, q, q+l)...)
				}
				q += l
				if sn == serial && l < 255 {
					packets = append(packets, cur)
					cur = nil
					if len(packets) == 2 {
						break
					}
				}
			}
			if q > len(b) {
				return serial, nil // the page runs past what was read
			}
			p = q
		}
		if len(packets) < 2 {
			return serial, nil
		}
		return serial, packets
	}
	serial, pk := scan(sliceAt(src, 0, tagHead))
	if pk == nil && src.Size() > tagHead {
		serial, pk = scan(sliceAt(src, 0, tagCap))
	}
	if pk == nil {
		return
	}
	id, com := pk[0], pk[1]
	rate, skip := 0.0, 0.0
	switch {
	case len(id) >= 16 && id[0] == 1 && str(id, 1, 6) == "vorbis":
		rate = float64(le32(id, 12))
	case str(id, 0, 8) == "OpusHead":
		rate, skip = 48000, float64(le16(id, 10))
	}
	switch {
	case len(com) > 7 && com[0] == 3 && str(com, 1, 6) == "vorbis":
		vorbisComments(com, 7, m)
	case str(com, 0, 8) == "OpusTags":
		vorbisComments(com, 8, m)
	}
	if rate <= 0 {
		return
	}
	// The running time is the last page's granule position.
	tail := int64(64 << 10)
	if tail > src.Size() {
		tail = src.Size()
	}
	b := sliceAt(src, src.Size()-tail, tail)
	for i := len(b) - 27; i >= 0; i-- {
		if b[i] != 'O' || str(b, i, 4) != "OggS" || le32(b, i+14) != serial {
			continue
		}
		g := le64(b, i+6)
		if g == 0 || g == math.MaxUint64 {
			continue
		}
		m.out.Duration = (float64(g) - skip) / rate
		return
	}
}

// ── MP4 / M4A ───────────────────────────────────────────────────────────

type atom struct {
	size, hdr int64
	typ       string
}

func atomAt(b []byte, p int, limit int64) atom {
	a := atom{size: be32(b, p), typ: str(b, p+4, 4), hdr: 8}
	if a.size == 1 {
		a.size, a.hdr = be64(b, p+8), 16
	} else if a.size == 0 {
		a.size = limit
	}
	return a
}

type span struct{ start, body, end int }

func child(b []byte, from, to int, typ string) (span, bool) {
	if to > len(b) {
		to = len(b)
	}
	for p := from; p >= 0 && p+8 <= to; {
		a := atomAt(b, p, int64(to-p))
		if a.size < 8 {
			return span{}, false
		}
		if a.size > int64(to-p) {
			a.size = int64(to - p)
		}
		if a.typ == typ {
			return span{start: p, body: p + int(a.hdr), end: p + int(a.size)}, true
		}
		p += int(a.size)
	}
	return span{}, false
}

func mp4Read(src musicSource, m *metaWork) {
	size := src.Size()
	var at, msize int64 = 0, 0
	for hops := 0; hops <= 64; hops++ {
		if at+8 > size {
			return
		}
		h := sliceAt(src, at, 16)
		a := atomAt(h, 0, size-at)
		if a.size < 8 {
			return
		}
		if a.typ == "moov" {
			msize = a.size
			break
		}
		at += a.size
	}
	if msize == 0 {
		return
	}
	n := msize
	if n > tagCap {
		n = tagCap
	}
	b := sliceAt(src, at, n)
	top := int(atomAt(b, 0, n).hdr)
	if mv, ok := child(b, top, len(b), "mvhd"); ok {
		v := 0
		if mv.body < len(b) {
			v = int(b[mv.body])
		}
		var scale, dur int64
		if v == 1 {
			scale, dur = be32(b, mv.body+20), be64(b, mv.body+24)
		} else {
			scale, dur = be32(b, mv.body+12), be32(b, mv.body+16)
		}
		if scale > 0 && dur > 0 {
			m.out.Duration = float64(dur) / float64(scale)
		}
	}
	udta, ok := child(b, top, len(b), "udta")
	if !ok {
		return
	}
	meta, ok := child(b, udta.body, udta.end, "meta")
	if !ok {
		return
	}
	// meta is a full box (four bytes of version and flags) in MP4, a plain
	// one in some QuickTime files: look for its hdlr.
	mb := meta.body
	if str(b, meta.body+8, 4) == "hdlr" {
		mb += 4
	}
	ilst, ok := child(b, mb, meta.end, "ilst")
	if !ok {
		return
	}
	o := m.out
	for q := ilst.body; q+8 <= ilst.end; {
		it := atomAt(b, q, int64(ilst.end-q))
		if it.size < 8 {
			break
		}
		next := ilst.end
		if it.size <= int64(ilst.end-q) {
			next = q + int(it.size)
		}
		if d, ok := child(b, q+int(it.hdr), next, "data"); ok {
			payload := sub(b, d.body+8, d.end)
			switch it.typ {
			case "\xa9nam":
				if o.Title == "" {
					o.Title = utf8Text(payload)
				}
			case "\xa9ART":
				if o.Artist == "" {
					o.Artist = utf8Text(payload)
				}
			case "aART":
				if o.AlbumArtist == "" {
					o.AlbumArtist = utf8Text(payload)
				}
			case "\xa9alb":
				if o.Album == "" {
					o.Album = utf8Text(payload)
				}
			case "\xa9day":
				if o.Year == 0 {
					o.Year = leadingInt(utf8Text(payload))
				}
			case "trkn":
				if o.Track == 0 {
					o.Track = be16(payload, 2)
				}
			case "disk":
				if o.Disc == 0 {
					o.Disc = be16(payload, 2)
				}
			case "covr":
				m.takePic(payload, 3)
			}
		}
		q = next
	}
}

// ── WAV / AIFF ──────────────────────────────────────────────────────────

func wavRead(src musicSource, m *metaWork) {
	size := src.Size()
	var byteRate, data int64
	p := int64(12)
	for hops := 0; hops < 64 && p+8 <= size; hops++ {
		h := sliceAt(src, p, 8)
		id, n := str(h, 0, 4), le32(h, 4)
		body := p + 8
		switch id {
		case "fmt ":
			byteRate = le32(sliceAt(src, body, 16), 8)
		case "data":
			data = n
		case "LIST":
			if n > 12 && n < 1<<20 {
				listInfo(sliceAt(src, body, n), m)
			}
		case "id3 ", "ID3 ":
			if n > 10 && n < tagCap {
				parseID3(sliceAt(src, body, n), m)
			}
		}
		p = body + n + n&1
	}
	if byteRate > 0 && data > 0 {
		m.out.Duration = float64(data) / float64(byteRate)
	}
}

func listInfo(b []byte, m *metaWork) {
	if str(b, 0, 4) != "INFO" {
		return
	}
	o := m.out
	for p := 4; p+8 <= len(b); {
		id, n64 := str(b, p, 4), le32(b, p+4)
		if n64 > int64(len(b)-p-8) {
			return
		}
		n := int(n64)
		v := sub(b, p+8, p+8+n)
		if i := bytes.IndexByte(v, 0); i >= 0 {
			v = v[:i]
		}
		s := strings.TrimSpace(narrowText(v))
		switch id {
		case "INAM":
			if o.Title == "" {
				o.Title = s
			}
		case "IART":
			if o.Artist == "" {
				o.Artist = s
			}
		case "IPRD":
			if o.Album == "" {
				o.Album = s
			}
		case "ICRD":
			if o.Year == 0 {
				o.Year = leadingInt(s)
			}
		case "ITRK", "IPRT":
			if o.Track == 0 {
				o.Track = leadingInt(s)
			}
		}
		p += 8 + n + n&1
	}
}

// ieeeExtended is AIFF's 80-bit sample rate.
func ieeeExtended(b []byte) float64 {
	if len(b) < 10 {
		return 0
	}
	exp := int(binary.BigEndian.Uint16(b[0:2]) & 0x7fff)
	mant := binary.BigEndian.Uint64(b[2:10])
	if exp == 0 && mant == 0 {
		return 0
	}
	return math.Ldexp(float64(mant), exp-16383-63)
}

func aiffRead(src musicSource, m *metaWork) {
	size := src.Size()
	p := int64(12)
	for hops := 0; hops < 64 && p+8 <= size; hops++ {
		h := sliceAt(src, p, 8)
		id, n := str(h, 0, 4), be32(h, 4)
		body := p + 8
		switch id {
		case "COMM":
			c := sliceAt(src, body, 18)
			frames, rate := be32(c, 2), ieeeExtended(sub(c, 8, 18))
			if frames > 0 && rate > 0 {
				m.out.Duration = float64(frames) / rate
			}
		case "ID3 ", "id3 ":
			if n > 10 && n < tagCap {
				parseID3(sliceAt(src, body, n), m)
			}
		case "NAME":
			if m.out.Title == "" && n < 4096 {
				m.out.Title = narrowText(sliceAt(src, body, n))
			}
		}
		p = body + n + n&1
	}
}
