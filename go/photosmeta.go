package main

// photosmeta.go — what a picture says about itself, read from its first
// bytes: how large it is, which way up, when and where it was taken, and
// with what. JPEG, HEIC/HEIF/AVIF, PNG, GIF, WebP and TIFF; anything this
// does not understand is a picture of unknown size taken when the file was
// last changed.
//
// Every offset read here is checked against what was read: the files are
// whatever is on the disk, and none of them is trusted to be what its name
// says.

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// photoMeta is a picture's own account of itself.
type photoMeta struct {
	W, H  int   // as stored
	O     int   // EXIF orientation, 1 to 8; 1 where the format turns it itself
	T     int64 // when taken, Unix seconds; 0 when it does not say
	Z     int   // the offset there, minutes (meaningful when T is set)
	La    float64
	Lo    float64
	GPS   bool
	Cam   string
	exif  bool
	thOff int64 // the EXIF thumbnail (JPEG), in the file; 0 when none
	thLen int64
}

const (
	photoHeadMax = 512 << 10 // where the metadata of a HEIF is looked for
	photoExifMax = 256 << 10
)

// readPhotoMeta reads what it can. ext is the file's extension, lower case,
// a hint only: the bytes decide. A file that trips the readers anyway is
// read as having nothing in it, never as a reason for the helper to stop.
func readPhotoMeta(r io.ReaderAt, size int64, ext string) (m photoMeta) {
	defer func() {
		if recover() != nil {
			m = photoMeta{O: 1}
		}
	}()
	return readPhotoMetaBare(r, size, ext)
}

// readPhotoMetaBare is readPhotoMeta without the catch: the tests read
// damaged files through it, for a panic to fail them.
func readPhotoMetaBare(r io.ReaderAt, size int64, ext string) photoMeta {
	var m photoMeta
	head := make([]byte, 32)
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	switch {
	case len(head) >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF:
		photoJPEG(r, size, &m)
	case len(head) >= 12 && string(head[4:8]) == "ftyp":
		photoHEIF(r, size, &m)
	case len(head) >= 24 && bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")) && string(head[12:16]) == "IHDR":
		m.W = int(binary.BigEndian.Uint32(head[16:20]))
		m.H = int(binary.BigEndian.Uint32(head[20:24]))
		photoPNGExif(r, size, &m)
	case len(head) >= 10 && (bytes.HasPrefix(head, []byte("GIF87a")) || bytes.HasPrefix(head, []byte("GIF89a"))):
		m.W = int(binary.LittleEndian.Uint16(head[6:8]))
		m.H = int(binary.LittleEndian.Uint16(head[8:10]))
	case len(head) >= 16 && string(head[0:4]) == "RIFF" && string(head[8:12]) == "WEBP":
		photoWebP(r, size, &m)
	case len(head) >= 8 && (string(head[0:4]) == "II*\x00" || string(head[0:4]) == "MM\x00*"):
		b := make([]byte, photoExifMax)
		n, _ := r.ReadAt(b, 0)
		parseExifTIFF(b[:n], 0, &m, true)
	}
	if m.O < 1 || m.O > 8 {
		m.O = 1
	}
	if m.W < 0 || m.H < 0 || m.W > 1<<20 || m.H > 1<<20 {
		m.W, m.H = 0, 0
	}
	return m
}

// ── JPEG ─────────────────────────────────────────────────────────────────

func photoJPEG(r io.ReaderAt, size int64, m *photoMeta) {
	pos := int64(2)
	hdr := make([]byte, 4)
	for i := 0; i < 512 && pos+4 <= size; i++ {
		if _, err := r.ReadAt(hdr, pos); err != nil {
			return
		}
		if hdr[0] != 0xFF {
			return
		}
		mk := hdr[1]
		if mk == 0xFF {
			// Fill byte.
			pos++
			continue
		}
		if mk == 0xD8 || mk == 0x01 || (mk >= 0xD0 && mk <= 0xD7) {
			pos += 2
			continue
		}
		if mk == 0xD9 || mk == 0xDA {
			return
		}
		ln := int64(binary.BigEndian.Uint16(hdr[2:4]))
		if ln < 2 {
			return
		}
		seg := pos + 4
		switch {
		case mk == 0xE1 && !m.exif && ln >= 8:
			want := ln - 2
			if want > 64<<10 {
				want = 64 << 10
			}
			b := make([]byte, want)
			if n, _ := r.ReadAt(b, seg); int64(n) == want && bytes.HasPrefix(b, []byte("Exif\x00\x00")) {
				parseExifTIFF(b[6:], seg+6, m, false)
			}
		case mk >= 0xC0 && mk <= 0xCF && mk != 0xC4 && mk != 0xC8 && mk != 0xCC:
			b := make([]byte, 5)
			if _, err := r.ReadAt(b, seg); err == nil {
				m.H = int(binary.BigEndian.Uint16(b[1:3]))
				m.W = int(binary.BigEndian.Uint16(b[3:5]))
			}
			return
		}
		pos = seg + ln - 2
	}
}

// ── TIFF / EXIF ──────────────────────────────────────────────────────────

type tiffReader struct {
	b  []byte
	bo binary.ByteOrder
}

func (t tiffReader) u16(o int) (int, bool) {
	if o < 0 || o > len(t.b)-2 {
		return 0, false
	}
	return int(t.bo.Uint16(t.b[o:])), true
}

func (t tiffReader) u32(o int) (int64, bool) {
	if o < 0 || o > len(t.b)-4 {
		return 0, false
	}
	return int64(t.bo.Uint32(t.b[o:])), true
}

type tiffEntry struct {
	typ   int
	count int64
	at    int // where the value is, in b
}

var tiffSizes = map[int]int{1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

// ifd reads one directory: its entries by tag, and the offset of the next.
func (t tiffReader) ifd(off int64) (map[int]tiffEntry, int64) {
	if off <= 0 || off > int64(len(t.b)) {
		return nil, 0
	}
	n, ok := t.u16(int(off))
	if !ok || n > 512 {
		return nil, 0
	}
	out := make(map[int]tiffEntry, n)
	for i := 0; i < n; i++ {
		e := int(off) + 2 + 12*i
		tag, ok1 := t.u16(e)
		typ, ok2 := t.u16(e + 2)
		cnt, ok3 := t.u32(e + 4)
		if !ok1 || !ok2 || !ok3 {
			break
		}
		sz, known := tiffSizes[typ]
		if !known || cnt < 0 || cnt > 1<<20 {
			continue
		}
		at := e + 8
		if int64(sz)*cnt > 4 {
			v, ok := t.u32(e + 8)
			if !ok {
				continue
			}
			if v > int64(len(t.b)) {
				continue
			}
			at = int(v)
		}
		if at < 0 || int64(at)+int64(sz)*cnt > int64(len(t.b)) {
			continue
		}
		out[tag] = tiffEntry{typ: typ, count: cnt, at: at}
	}
	next, _ := t.u32(int(off) + 2 + 12*n)
	return out, next
}

func (t tiffReader) num(e tiffEntry, i int) (float64, bool) {
	if int64(i) >= e.count {
		return 0, false
	}
	switch e.typ {
	case 1, 7:
		return float64(t.b[e.at+i]), true
	case 3:
		v, ok := t.u16(e.at + 2*i)
		return float64(v), ok
	case 4:
		v, ok := t.u32(e.at + 4*i)
		return float64(v), ok
	case 9:
		v, ok := t.u32(e.at + 4*i)
		return float64(int32(v)), ok
	case 5, 10:
		a, ok1 := t.u32(e.at + 8*i)
		b, ok2 := t.u32(e.at + 8*i + 4)
		if !ok1 || !ok2 || b == 0 {
			return 0, false
		}
		if e.typ == 10 {
			return float64(int32(a)) / float64(int32(b)), int32(b) != 0
		}
		return float64(a) / float64(b), true
	}
	return 0, false
}

func (t tiffReader) str(e tiffEntry) string {
	if e.typ != 2 && e.typ != 7 && e.typ != 1 {
		return ""
	}
	b := t.b[e.at : e.at+int(e.count)]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	s := strings.TrimSpace(string(b))
	if !utf8.ValidString(s) {
		return ""
	}
	return s
}

// parseExifTIFF reads a TIFF structure: an EXIF block (base is where it
// starts in the file, for the thumbnail's place), or a TIFF file itself
// (whole: its first directory's size is the picture's).
func parseExifTIFF(b []byte, base int64, m *photoMeta, whole bool) {
	if len(b) < 8 {
		return
	}
	var t tiffReader
	switch string(b[0:2]) {
	case "II":
		t = tiffReader{b, binary.LittleEndian}
	case "MM":
		t = tiffReader{b, binary.BigEndian}
	default:
		return
	}
	if v, _ := t.u16(2); v != 42 {
		return
	}
	off0, _ := t.u32(4)
	ifd0, next := t.ifd(off0)
	if ifd0 == nil {
		return
	}
	m.exif = true
	if e, ok := ifd0[0x0112]; ok {
		if v, ok := t.num(e, 0); ok {
			m.O = int(v)
		}
	}
	if whole {
		if e, ok := ifd0[0x0100]; ok {
			if v, ok := t.num(e, 0); ok {
				m.W = int(v)
			}
		}
		if e, ok := ifd0[0x0101]; ok {
			if v, ok := t.num(e, 0); ok {
				m.H = int(v)
			}
		}
	}
	mk, md := "", ""
	if e, ok := ifd0[0x010F]; ok {
		mk = t.str(e)
	}
	if e, ok := ifd0[0x0110]; ok {
		md = t.str(e)
	}
	m.Cam = photoCamera(mk, md)
	when, offs := "", ""
	if e, ok := ifd0[0x0132]; ok {
		when = t.str(e)
	}
	if e, ok := ifd0[0x8769]; ok {
		if v, ok := t.num(e, 0); ok {
			if sub, _ := t.ifd(int64(v)); sub != nil {
				for _, tag := range []int{0x9003, 0x9004} {
					if e, ok := sub[tag]; ok {
						if s := t.str(e); photoStampOK(s) {
							when = s
							break
						}
					}
				}
				for _, tag := range []int{0x9011, 0x9012, 0x9010} {
					if e, ok := sub[tag]; ok {
						if s := t.str(e); s != "" {
							offs = s
							break
						}
					}
				}
				if !whole {
					w, h := 0.0, 0.0
					if e, ok := sub[0xA002]; ok {
						w, _ = t.num(e, 0)
					}
					if e, ok := sub[0xA003]; ok {
						h, _ = t.num(e, 0)
					}
					if m.W == 0 && w > 0 && h > 0 {
						m.W, m.H = int(w), int(h)
					}
				}
			}
		}
	}
	m.T, m.Z = photoStamp(when, offs)
	if e, ok := ifd0[0x8825]; ok {
		if v, ok := t.num(e, 0); ok {
			if g, _ := t.ifd(int64(v)); g != nil {
				la, ok1 := photoDeg(t, g[2], g[1])
				lo, ok2 := photoDeg(t, g[4], g[3])
				if ok1 && ok2 && (la != 0 || lo != 0) && math.Abs(la) <= 90 && math.Abs(lo) <= 180 {
					m.La, m.Lo, m.GPS = math.Round(la*1e6)/1e6, math.Round(lo*1e6)/1e6, true
				}
			}
		}
	}
	// The thumbnail the camera wrote (IFD1), for a picture too large to
	// make one from here.
	if !whole && next > 0 {
		if ifd1, _ := t.ifd(next); ifd1 != nil {
			o, ok1 := ifd1[0x0201]
			l, ok2 := ifd1[0x0202]
			if ok1 && ok2 {
				ov, _ := t.num(o, 0)
				lv, _ := t.num(l, 0)
				if ov > 0 && lv > 0 && lv < 1<<20 {
					m.thOff, m.thLen = base+int64(ov), int64(lv)
				}
			}
		}
	}
}

func photoDeg(t tiffReader, v, ref tiffEntry) (float64, bool) {
	if v.count < 3 || ref.count < 1 {
		return 0, false
	}
	d, ok1 := t.num(v, 0)
	mi, ok2 := t.num(v, 1)
	s, ok3 := t.num(v, 2)
	if !ok1 || !ok2 || !ok3 {
		return 0, false
	}
	x := d + mi/60 + s/3600
	if r := t.str(ref); r == "S" || r == "W" {
		x = -x
	}
	return x, !math.IsNaN(x) && !math.IsInf(x, 0)
}

func photoStampOK(s string) bool {
	return len(s) >= 19 && !strings.HasPrefix(s, "0000") && s[4] == ':' && s[7] == ':' && s[13] == ':'
}

// photoStamp is the moment an EXIF date names, and the offset where it was
// taken: the one written beside it, else this machine's own at that date
// (the camera's clock is taken to have been set to the time here).
func photoStamp(when, offs string) (int64, int) {
	if !photoStampOK(when) {
		return 0, 0
	}
	num := func(s string) int {
		v, err := strconv.Atoi(s)
		if err != nil {
			return -1
		}
		return v
	}
	y, mo, d := num(when[0:4]), num(when[5:7]), num(when[8:10])
	h, mi, se := num(when[11:13]), num(when[14:16]), num(when[17:19])
	if y < 1900 || y > 2200 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60 {
		return 0, 0
	}
	if len(offs) >= 6 && (offs[0] == '+' || offs[0] == '-') && offs[3] == ':' {
		oh, om := num(offs[1:3]), num(offs[4:6])
		if oh >= 0 && oh <= 14 && om >= 0 && om < 60 {
			z := oh*60 + om
			if offs[0] == '-' {
				z = -z
			}
			at := time.Date(y, time.Month(mo), d, h, mi, se, 0, time.FixedZone("", z*60))
			return at.Unix(), z
		}
	}
	at := time.Date(y, time.Month(mo), d, h, mi, se, 0, time.Local)
	_, z := at.Zone()
	return at.Unix(), z / 60
}

// photoCamera names the camera as people do: the model, with the maker in
// front when the model does not already say it.
func photoCamera(mk, md string) string {
	mk, md = strings.TrimSpace(mk), strings.TrimSpace(md)
	if len(mk) > 40 {
		mk = mk[:40]
	}
	if len(md) > 60 {
		md = md[:60]
	}
	if md == "" {
		return mk
	}
	first := strings.ToLower(strings.Fields(mk + " x")[0])
	switch {
	case mk == "", strings.EqualFold(mk, "Apple"), strings.HasPrefix(strings.ToLower(md), first):
		return md
	}
	return mk + " " + md
}

// ── PNG, WebP ────────────────────────────────────────────────────────────

// photoPNGExif: an eXIf chunk before the pixels, where a program wrote one.
func photoPNGExif(r io.ReaderAt, size int64, m *photoMeta) {
	pos := int64(8)
	hdr := make([]byte, 8)
	for i := 0; i < 64 && pos+8 <= size; i++ {
		if _, err := r.ReadAt(hdr, pos); err != nil {
			return
		}
		ln := int64(binary.BigEndian.Uint32(hdr[0:4]))
		typ := string(hdr[4:8])
		if typ == "IDAT" || typ == "IEND" || ln > 1<<30 {
			return
		}
		if typ == "eXIf" && ln > 8 && ln <= photoExifMax {
			b := make([]byte, ln)
			if n, _ := r.ReadAt(b, pos+8); int64(n) == ln {
				w, h := m.W, m.H
				parseExifTIFF(b, pos+8, m, false)
				m.W, m.H = w, h
				m.thOff, m.thLen = 0, 0
			}
			return
		}
		pos += 12 + ln
	}
}

func photoWebP(r io.ReaderAt, size int64, m *photoMeta) {
	pos := int64(12)
	hdr := make([]byte, 8)
	for i := 0; i < 64 && pos+8 <= size; i++ {
		if _, err := r.ReadAt(hdr, pos); err != nil {
			return
		}
		typ := string(hdr[0:4])
		ln := int64(binary.LittleEndian.Uint32(hdr[4:8]))
		body := pos + 8
		switch typ {
		case "VP8 ":
			b := make([]byte, 10)
			if _, err := r.ReadAt(b, body); err == nil && b[3] == 0x9d && b[4] == 0x01 && b[5] == 0x2a {
				if m.W == 0 {
					m.W = int(binary.LittleEndian.Uint16(b[6:8]) & 0x3fff)
					m.H = int(binary.LittleEndian.Uint16(b[8:10]) & 0x3fff)
				}
			}
		case "VP8L":
			b := make([]byte, 5)
			if _, err := r.ReadAt(b, body); err == nil && b[0] == 0x2f {
				v := binary.LittleEndian.Uint32(b[1:5])
				if m.W == 0 {
					m.W = int(v&0x3fff) + 1
					m.H = int((v>>14)&0x3fff) + 1
				}
			}
		case "VP8X":
			b := make([]byte, 10)
			if _, err := r.ReadAt(b, body); err == nil {
				m.W = int(uint32(b[4])|uint32(b[5])<<8|uint32(b[6])<<16) + 1
				m.H = int(uint32(b[7])|uint32(b[8])<<8|uint32(b[9])<<16) + 1
			}
		case "EXIF":
			if ln > 8 && ln <= photoExifMax {
				b := make([]byte, ln)
				if n, _ := r.ReadAt(b, body); int64(n) == ln {
					start := int64(0)
					if bytes.HasPrefix(b, []byte("Exif\x00\x00")) {
						start = 6
					}
					w, h := m.W, m.H
					parseExifTIFF(b[start:], body+start, m, false)
					m.W, m.H = w, h
					m.thOff, m.thLen = 0, 0
				}
			}
		}
		pos = body + ln + ln%2
	}
}

// ── HEIF (HEIC, AVIF) ────────────────────────────────────────────────────

type bmffBox struct {
	typ        string
	start, end int // the payload, in b
}

// bmffBoxes lists the boxes in b[start:end].
func bmffBoxes(b []byte, start, end int) []bmffBox {
	var out []bmffBox
	for p := start; p >= 0 && p <= end-8 && len(out) < 4096; {
		sz32 := binary.BigEndian.Uint32(b[p:])
		if uint64(sz32) > uint64(end-p) {
			return out
		}
		sz := int(sz32)
		typ := string(b[p+4 : p+8])
		hdr := 8
		switch sz {
		case 1:
			if p+16 > end {
				return out
			}
			big := binary.BigEndian.Uint64(b[p+8:])
			if big > uint64(end-p) {
				return out
			}
			sz, hdr = int(big), 16
		case 0:
			sz = end - p
		}
		if sz < hdr || sz > end-p {
			return out
		}
		out = append(out, bmffBox{typ: typ, start: p + hdr, end: p + sz})
		p += sz
	}
	return out
}

func bmffFind(boxes []bmffBox, typ string) (bmffBox, bool) {
	for _, x := range boxes {
		if x.typ == typ {
			return x, true
		}
	}
	return bmffBox{}, false
}

// bmffUint reads an n-byte big-endian number (n 0, 2, 4 or 8) at p.
func bmffUint(b []byte, p, n int) (uint64, bool) {
	if p < 0 || n < 0 || p > len(b)-n {
		return 0, false
	}
	switch n {
	case 0:
		return 0, true
	case 1:
		return uint64(b[p]), true
	case 2:
		return uint64(binary.BigEndian.Uint16(b[p:])), true
	case 4:
		return uint64(binary.BigEndian.Uint32(b[p:])), true
	case 8:
		return binary.BigEndian.Uint64(b[p:]), true
	}
	return 0, false
}

func photoHEIF(r io.ReaderAt, size int64, m *photoMeta) {
	n := int64(photoHeadMax)
	if size < n {
		n = size
	}
	b := make([]byte, n)
	got, _ := r.ReadAt(b, 0)
	b = b[:got]
	top := bmffBoxes(b, 0, len(b))
	meta, ok := bmffFind(top, "meta")
	if !ok || meta.end-meta.start < 4 {
		return
	}
	kids := bmffBoxes(b, meta.start+4, meta.end) // a full box: version and flags first
	// The primary item.
	primary := uint64(1)
	if p, ok := bmffFind(kids, "pitm"); ok && p.end-p.start >= 6 {
		if b[p.start] == 0 {
			primary, _ = bmffUint(b, p.start+4, 2)
		} else {
			primary, _ = bmffUint(b, p.start+4, 4)
		}
	}
	// The items by type: the Exif one that describes the primary item is
	// wanted (iref, cdsc); in a file that does not say, the first.
	var exifIDs []uint64
	if inf, ok := bmffFind(kids, "iinf"); ok && inf.end-inf.start >= 6 {
		at := inf.start + 6
		if b[inf.start] != 0 {
			at = inf.start + 8
		}
		for _, e := range bmffBoxes(b, at, inf.end) {
			if e.typ != "infe" || e.end-e.start < 12 {
				continue
			}
			v := b[e.start]
			if v < 2 {
				continue
			}
			idLen := 2
			if v >= 3 {
				idLen = 4
			}
			id, ok := bmffUint(b, e.start+4, idLen)
			tp := e.start + 4 + idLen + 2
			if !ok || tp+4 > e.end {
				continue
			}
			if string(b[tp:tp+4]) == "Exif" && len(exifIDs) < 64 {
				exifIDs = append(exifIDs, id)
			}
		}
	}
	exifID := bmffExifFor(b, kids, exifIDs, primary)
	// The primary item's size and turn.
	var props []bmffBox
	if pr, ok := bmffFind(kids, "iprp"); ok {
		pk := bmffBoxes(b, pr.start, pr.end)
		if co, ok := bmffFind(pk, "ipco"); ok {
			props = bmffBoxes(b, co.start, co.end)
		}
		if ma, ok := bmffFind(pk, "ipma"); ok && ma.end-ma.start >= 8 {
			v, flags := b[ma.start], b[ma.start+3]
			cnt, _ := bmffUint(b, ma.start+4, 4)
			p := ma.start + 8
			rot := 0
			for i := uint64(0); i < cnt && i < 4096 && p < ma.end; i++ {
				idLen := 2
				if v >= 1 {
					idLen = 4
				}
				id, ok := bmffUint(b, p, idLen)
				if !ok || p+idLen >= ma.end {
					break
				}
				p += idLen
				na := int(b[p])
				p++
				for j := 0; j < na; j++ {
					idx := 0
					if flags&1 != 0 {
						x, ok := bmffUint(b, p, 2)
						if !ok {
							return
						}
						idx = int(x & 0x7fff)
						p += 2
					} else {
						if p >= len(b) {
							return
						}
						idx = int(b[p] & 0x7f)
						p++
					}
					if id != primary || idx < 1 || idx > len(props) {
						continue
					}
					x := props[idx-1]
					switch x.typ {
					case "ispe":
						if x.end-x.start >= 12 {
							m.W = int(binary.BigEndian.Uint32(b[x.start+4:]))
							m.H = int(binary.BigEndian.Uint32(b[x.start+8:]))
						}
					case "irot":
						if x.end-x.start >= 1 {
							rot = int(b[x.start] & 3)
						}
					}
				}
			}
			// The format turns the picture itself: the size given is the
			// picture as shown, and no orientation is left to apply.
			if rot == 1 || rot == 3 {
				m.W, m.H = m.H, m.W
			}
		}
	}
	if exifID != 0 {
		if off, ln, ok := bmffItemPlace(b, kids, exifID); ok && ln > 8 && ln <= photoExifMax && off+ln <= size {
			x := make([]byte, ln)
			if got, _ := r.ReadAt(x, off); int64(got) == ln {
				skip := int64(binary.BigEndian.Uint32(x[0:4])) + 4
				if skip < ln {
					w, h := m.W, m.H
					parseExifTIFF(x[skip:], off+skip, m, false)
					m.W, m.H = w, h
					m.thOff, m.thLen = 0, 0
				}
			}
		}
	}
	m.O = 1
}

// bmffExifFor picks, of the Exif items, the one iref says describes the
// primary item; else the first not said to describe another one.
func bmffExifFor(b []byte, kids []bmffBox, ids []uint64, primary uint64) uint64 {
	if len(ids) == 0 {
		return 0
	}
	about := map[uint64][]uint64{}
	if ir, ok := bmffFind(kids, "iref"); ok && ir.end-ir.start >= 4 {
		idLen := 2
		if b[ir.start] != 0 {
			idLen = 4
		}
		for _, r := range bmffBoxes(b, ir.start+4, ir.end) {
			if r.typ != "cdsc" {
				continue
			}
			from, ok1 := bmffUint(b, r.start, idLen)
			n, ok2 := bmffUint(b, r.start+idLen, 2)
			if !ok1 || !ok2 {
				continue
			}
			for j, p := uint64(0), r.start+idLen+2; j < n && j < 256; j, p = j+1, p+idLen {
				to, ok := bmffUint(b, p, idLen)
				if !ok || p+idLen > r.end {
					break
				}
				about[from] = append(about[from], to)
			}
		}
	}
	for _, id := range ids {
		for _, to := range about[id] {
			if to == primary {
				return id
			}
		}
	}
	for _, id := range ids {
		if len(about[id]) == 0 {
			return id
		}
	}
	return 0
}

// bmffItemPlace is where an item's one extent lies in the file (iloc).
func bmffItemPlace(b []byte, kids []bmffBox, want uint64) (int64, int64, bool) {
	lo, ok := bmffFind(kids, "iloc")
	if !ok || lo.end-lo.start < 8 {
		return 0, 0, false
	}
	v := b[lo.start]
	p := lo.start + 4
	offSize, lenSize := int(b[p]>>4), int(b[p]&15)
	baseSize, idxSize := int(b[p+1]>>4), int(b[p+1]&15)
	if v == 0 {
		idxSize = 0
	}
	p += 2
	var cnt uint64
	if v < 2 {
		cnt, _ = bmffUint(b, p, 2)
		p += 2
	} else {
		cnt, _ = bmffUint(b, p, 4)
		p += 4
	}
	for i := uint64(0); i < cnt && i < 4096; i++ {
		idLen := 2
		if v >= 2 {
			idLen = 4
		}
		id, ok := bmffUint(b, p, idLen)
		if !ok {
			return 0, 0, false
		}
		p += idLen
		method := uint64(0)
		if v == 1 || v == 2 {
			method, _ = bmffUint(b, p, 2)
			method &= 15
			p += 2
		}
		p += 2 // data reference index
		base, ok := bmffUint(b, p, baseSize)
		if !ok {
			return 0, 0, false
		}
		p += baseSize
		ext, ok := bmffUint(b, p, 2)
		if !ok {
			return 0, 0, false
		}
		p += 2
		// Only the first extent is read; the rest are stepped over in one
		// go, so a box of many empty extents costs nothing to pass.
		var first, firstLen uint64
		per := idxSize + offSize + lenSize
		if ext > 0 {
			if per > 0 && ext > uint64((len(b)-p)/per) {
				return 0, 0, false
			}
			o, ok1 := bmffUint(b, p+idxSize, offSize)
			l, ok2 := bmffUint(b, p+idxSize+offSize, lenSize)
			if !ok1 || !ok2 {
				return 0, 0, false
			}
			first, firstLen = o, l
			p += int(ext) * per
		}
		if id == want {
			if method != 0 || ext != 1 || base+first > math.MaxInt64/2 || firstLen > math.MaxInt64/2 {
				return 0, 0, false
			}
			return int64(base + first), int64(firstLen), true
		}
	}
	return 0, 0, false
}
