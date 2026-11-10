package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// ── pictures made up for the tests ─────────────────────────────────────

type tEnt struct {
	tag, typ uint16
	count    uint32
	val      []byte
	ptr      int // > 0: a LONG naming where IFD ptr begins
}

// tiffBlock lays IFDs out one after another, their values after them, big
// endian; next[i] > 0 chains IFD i to IFD next[i]. blobs are placed after
// the values and their offsets handed to fill, which may patch entries.
func tiffBlock(ifds [][]tEnt, next map[int]int) []byte {
	bo := binary.BigEndian
	offs := make([]int, len(ifds))
	pos := 8
	for i, d := range ifds {
		offs[i] = pos
		pos += 2 + 12*len(d) + 4
	}
	head := []byte("MM\x00\x2a\x00\x00\x00\x08")
	var dir, data []byte
	for i, d := range ifds {
		n := make([]byte, 2)
		bo.PutUint16(n, uint16(len(d)))
		dir = append(dir, n...)
		for _, e := range d {
			ent := make([]byte, 12)
			bo.PutUint16(ent[0:], e.tag)
			bo.PutUint16(ent[2:], e.typ)
			bo.PutUint32(ent[4:], e.count)
			switch {
			case e.ptr > 0:
				bo.PutUint32(ent[8:], uint32(offs[e.ptr]))
			case len(e.val) <= 4:
				copy(ent[8:], e.val)
			default:
				bo.PutUint32(ent[8:], uint32(pos+len(data)))
				data = append(data, e.val...)
				if len(data)%2 == 1 {
					data = append(data, 0)
				}
			}
			dir = append(dir, ent...)
		}
		nx := make([]byte, 4)
		if j, ok := next[i]; ok {
			bo.PutUint32(nx, uint32(offs[j]))
		}
		dir = append(dir, nx...)
	}
	return cat(head, dir, data)
}

func tAscii(tag uint16, s string) tEnt {
	return tEnt{tag: tag, typ: 2, count: uint32(len(s) + 1), val: append([]byte(s), 0)}
}

func tShort(tag uint16, v int) tEnt {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return tEnt{tag: tag, typ: 3, count: 1, val: b}
}

func tLong(tag uint16, v int) tEnt {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return tEnt{tag: tag, typ: 4, count: 1, val: b}
}

func tDeg(tag uint16, d float64) tEnt {
	d = math.Abs(d)
	deg := math.Floor(d)
	minutes := math.Floor((d - deg) * 60)
	sec := (d - deg - minutes/60) * 3600
	var b []byte
	for _, r := range [][2]uint32{{uint32(deg), 1}, {uint32(minutes), 1}, {uint32(math.Round(sec * 10000)), 10000}} {
		x := make([]byte, 8)
		binary.BigEndian.PutUint32(x, r[0])
		binary.BigEndian.PutUint32(x[4:], r[1])
		b = append(b, x...)
	}
	return tEnt{tag: tag, typ: 5, count: 3, val: b}
}

type exifSpec struct {
	make_, model string
	orient       int
	when, offs   string
	la, lo       float64
	gps          bool
	thumb        []byte
}

func exifTIFF(s exifSpec) []byte {
	ifd0 := []tEnt{}
	if s.make_ != "" {
		ifd0 = append(ifd0, tAscii(0x010F, s.make_))
	}
	if s.model != "" {
		ifd0 = append(ifd0, tAscii(0x0110, s.model))
	}
	if s.orient != 0 {
		ifd0 = append(ifd0, tShort(0x0112, s.orient))
	}
	ifds := [][]tEnt{nil}
	sub := []tEnt{}
	if s.when != "" {
		sub = append(sub, tAscii(0x9003, s.when))
	}
	if s.offs != "" {
		sub = append(sub, tAscii(0x9011, s.offs))
	}
	if len(sub) > 0 {
		ifds = append(ifds, sub)
		ifd0 = append(ifd0, tEnt{tag: 0x8769, typ: 4, count: 1, ptr: len(ifds) - 1})
	}
	if s.gps {
		ns, ew := "N", "E"
		if s.la < 0 {
			ns = "S"
		}
		if s.lo < 0 {
			ew = "W"
		}
		ifds = append(ifds, []tEnt{tAscii(1, ns), tDeg(2, s.la), tAscii(3, ew), tDeg(4, s.lo)})
		ifd0 = append(ifd0, tEnt{tag: 0x8825, typ: 4, count: 1, ptr: len(ifds) - 1})
	}
	ifds[0] = ifd0
	next := map[int]int{}
	if s.thumb != nil {
		// The offset is patched once the layout is known: the thumbnail is
		// the last thing in the block.
		ifds = append(ifds, []tEnt{tLong(0x0201, 0), tLong(0x0202, len(s.thumb))})
		next[0] = len(ifds) - 1
		b := tiffBlock(ifds, next)
		at := len(b)
		ifds[len(ifds)-1][0] = tLong(0x0201, at)
		b = tiffBlock(ifds, next)
		return append(b, s.thumb...)
	}
	return tiffBlock(ifds, next)
}

// withExif puts an APP1 EXIF segment right after a JPEG's SOI.
func withExif(t *testing.T, jpg, tiff []byte) []byte {
	t.Helper()
	seg := cat([]byte("Exif\x00\x00"), tiff)
	ln := make([]byte, 2)
	binary.BigEndian.PutUint16(ln, uint16(len(seg)+2))
	return cat(jpg[:2], []byte{0xFF, 0xE1}, ln, seg, jpg[2:])
}

// grain is a colour with a little noise in it: a picture the size a photo
// is on the disk, its colour still plain to see.
func grain(rng *rand.Rand, c color.RGBA) color.RGBA {
	j := func(v uint8) uint8 { return uint8(max(0, min(255, int(v)+rng.Intn(21)-10))) }
	return color.RGBA{j(c.R), j(c.G), j(c.B), 255}
}

// halves is a w × h JPEG, its left half red and its right half blue.
func halves(t *testing.T, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(int64(w*h + 1)))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{220, 20, 20, 255}
			if x >= w/2 {
				c = color.RGBA{20, 20, 220, 255}
			}
			img.Set(x, y, grain(rng, c))
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func plainJPEG(t *testing.T, w, h int, c color.RGBA) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(int64(w + h)))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, grain(rng, c))
		}
	}
	var b bytes.Buffer
	jpeg.Encode(&b, img, &jpeg.Options{Quality: 90})
	return b.Bytes()
}

func noisyPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(int64(w*7 + h)))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	rng.Read(img.Pix)
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// hugeJPEG says it is w × h and holds no pixels: only its EXIF thumbnail
// can be shown.
func hugeJPEG(t *testing.T, w, h int, thumb []byte) []byte {
	t.Helper()
	sof := []byte{0xFF, 0xC0, 0, 17, 8, byte(h >> 8), byte(h), byte(w >> 8), byte(w), 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1}
	base := cat([]byte{0xFF, 0xD8}, sof, []byte{0xFF, 0xD9})
	return withExif(t, base, exifTIFF(exifSpec{thumb: thumb}))
}

func hBox(typ string, body ...[]byte) []byte {
	b := cat(body...)
	n := make([]byte, 4)
	binary.BigEndian.PutUint32(n, uint32(8+len(b)))
	return cat(n, []byte(typ), b)
}

func hFull(typ string, v byte, body ...[]byte) []byte {
	return hBox(typ, cat([]byte{v, 0, 0, 0}, cat(body...)))
}

func pb16(v int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(v)); return b }
func pb32(v int) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, uint32(v)); return b }

// heifFile is the frame of an iPhone's HEIC: a primary picture w × h turned
// by irot, and an Exif item in the mdat.
func heifFile(w, h, rot int, tiff []byte) []byte {
	ftyp := hBox("ftyp", []byte("heic"), pb32(0), []byte("mif1heic"))
	payload := cat(pb32(0), tiff)
	meta := func(off int) []byte {
		pitm := hFull("pitm", 0, pb16(1))
		iinf := hFull("iinf", 0, pb16(2),
			hFull("infe", 2, pb16(1), pb16(0), []byte("hvc1"), []byte{0}),
			hFull("infe", 2, pb16(2), pb16(0), []byte("Exif"), []byte{0}))
		iloc := hFull("iloc", 0, []byte{0x44, 0x00}, pb16(1), pb16(2), pb16(0), pb16(1), pb32(off), pb32(len(payload)))
		ipco := hBox("ipco", hFull("ispe", 0, pb32(w), pb32(h)), hBox("irot", []byte{byte(rot)}))
		ipma := hFull("ipma", 0, pb32(1), pb16(1), []byte{2, 0x81, 0x02})
		return hFull("meta", 0, pitm, iinf, iloc, hBox("iprp", ipco, ipma))
	}
	m := meta(0)
	off := len(ftyp) + len(m) + 8
	return cat(ftyp, meta(off), hBox("mdat", payload))
}

// ── what a picture says ────────────────────────────────────────────────

func TestPhotoMetaJPEG(t *testing.T) {
	tiff := exifTIFF(exifSpec{make_: "Apple", model: "iPhone 15 Pro", orient: 6,
		when: "2024:05:01 10:00:00", offs: "+09:00", la: 35.6895, lo: 139.6917, gps: true})
	b := withExif(t, halves(t, 400, 300), tiff)
	m := readPhotoMeta(bytes.NewReader(b), int64(len(b)), ".jpg")
	want := time.Date(2024, 5, 1, 10, 0, 0, 0, time.FixedZone("", 9*3600)).Unix()
	if m.W != 400 || m.H != 300 || m.O != 6 || m.T != want || m.Z != 540 || m.Cam != "iPhone 15 Pro" {
		t.Fatalf("%+v", m)
	}
	if !m.GPS || math.Abs(m.La-35.6895) > 1e-4 || math.Abs(m.Lo-139.6917) > 1e-4 {
		t.Fatalf("where: %+v", m)
	}
	// South and west are negative; a maker the model does not name goes in
	// front of it; a date with no offset is this machine's.
	tiff = exifTIFF(exifSpec{make_: "FUJIFILM", model: "X-T5", when: "2023:12:24 18:30:05", la: -33.86, lo: -70.65, gps: true})
	b = withExif(t, halves(t, 64, 48), tiff)
	m = readPhotoMeta(bytes.NewReader(b), int64(len(b)), ".jpg")
	local := time.Date(2023, 12, 24, 18, 30, 5, 0, time.Local)
	_, z := local.Zone()
	if m.T != local.Unix() || m.Z != z/60 || m.Cam != "FUJIFILM X-T5" || m.La > -33 || m.Lo > -70 || m.O != 1 {
		t.Fatalf("%+v", m)
	}
	if got := photoCamera("NIKON CORPORATION", "NIKON Z 6"); got != "NIKON Z 6" {
		t.Fatalf("the model names its maker: %q", got)
	}
	// No EXIF at all: the size, and nothing else.
	b = halves(t, 50, 70)
	m = readPhotoMeta(bytes.NewReader(b), int64(len(b)), ".jpg")
	if m.W != 50 || m.H != 70 || m.T != 0 || m.O != 1 || m.GPS {
		t.Fatalf("%+v", m)
	}
}

func TestPhotoMetaOtherKinds(t *testing.T) {
	p := tinyPNG(t, 33, 21)
	if m := readPhotoMeta(bytes.NewReader(p), int64(len(p)), ".png"); m.W != 33 || m.H != 21 {
		t.Fatalf("png %+v", m)
	}
	var g bytes.Buffer
	pal := image.NewPaletted(image.Rect(0, 0, 17, 9), color.Palette{color.Black, color.White})
	gif.Encode(&g, pal, nil)
	if m := readPhotoMeta(bytes.NewReader(g.Bytes()), int64(g.Len()), ".gif"); m.W != 17 || m.H != 9 {
		t.Fatalf("gif %+v", m)
	}
	vp8x := cat([]byte("RIFF"), le32b(30), []byte("WEBP"), []byte("VP8X"), le32b(10), []byte{0, 0, 0, 0}, []byte{0x1f, 0x03, 0}, []byte{0x57, 0x02, 0})
	if m := readPhotoMeta(bytes.NewReader(vp8x), int64(len(vp8x)), ".webp"); m.W != 800 || m.H != 600 {
		t.Fatalf("webp %+v", m)
	}
	tif := tiffBlock([][]tEnt{{tShort(0x0100, 1200), tShort(0x0101, 900), tShort(0x0112, 8)}}, nil)
	if m := readPhotoMeta(bytes.NewReader(tif), int64(len(tif)), ".tif"); m.W != 1200 || m.H != 900 || m.O != 8 {
		t.Fatalf("tiff %+v", m)
	}
	// A HEIC turned a quarter: the size as shown, the turn already the
	// format's own, and the EXIF orientation beside it ignored.
	h := heifFile(4032, 3024, 1, exifTIFF(exifSpec{model: "iPhone 14", orient: 6, when: "2025:01:02 03:04:05", offs: "-05:00"}))
	m := readPhotoMeta(bytes.NewReader(h), int64(len(h)), ".heic")
	want := time.Date(2025, 1, 2, 3, 4, 5, 0, time.FixedZone("", -5*3600)).Unix()
	if m.W != 3024 || m.H != 4032 || m.O != 1 || m.T != want || m.Z != -300 || m.Cam != "iPhone 14" {
		t.Fatalf("heic %+v", m)
	}
}

// Whatever is on the disk: cut short or scrambled, a picture is read without
// a panic and without anything out of range.
func TestPhotoMetaSurvivesDamage(t *testing.T) {
	good := [][]byte{
		withExif(t, halves(t, 40, 30), exifTIFF(exifSpec{make_: "Apple", model: "iPhone", orient: 3, when: "2024:01:01 00:00:00", offs: "+01:00", la: 1, lo: 2, gps: true, thumb: plainJPEG(t, 8, 8, color.RGBA{0, 200, 0, 255})})),
		heifFile(100, 80, 3, exifTIFF(exifSpec{when: "2024:01:01 00:00:00"})),
		tinyPNG(t, 9, 9),
		tiffBlock([][]tEnt{{tShort(0x0100, 5), tShort(0x0101, 5)}}, nil),
	}
	rng := rand.New(rand.NewSource(7))
	for _, g := range good {
		for n := 0; n <= len(g); n += 1 + len(g)/300 {
			b := g[:n]
			readPhotoMetaBare(bytes.NewReader(b), int64(len(b)), "")
		}
		for i := 0; i < 1500; i++ {
			b := append([]byte(nil), g...)
			for k := 0; k < 1+rng.Intn(6); k++ {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			m := readPhotoMetaBare(bytes.NewReader(b), int64(len(b)), "")
			if m.O < 1 || m.O > 8 || m.W < 0 || m.H < 0 {
				t.Fatalf("out of range: %+v", m)
			}
		}
	}
}

// A HEIF with an Exif item for each of two pictures: the one iref ties to
// the primary picture is read, wherever it is in the list.
func TestPhotoMetaHEIFExifOfPrimary(t *testing.T) {
	ftyp := hBox("ftyp", []byte("heic"), pb32(0), []byte("mif1heic"))
	mine := cat(pb32(0), exifTIFF(exifSpec{model: "Mine", when: "2025:03:04 05:06:07", offs: "+00:00"}))
	other := cat(pb32(0), exifTIFF(exifSpec{model: "Other", when: "2001:01:01 00:00:00", offs: "+00:00"}))
	meta := func(off int) []byte {
		pitm := hFull("pitm", 0, pb16(1))
		iinf := hFull("iinf", 0, pb16(4),
			hFull("infe", 2, pb16(1), pb16(0), []byte("hvc1"), []byte{0}),
			hFull("infe", 2, pb16(2), pb16(0), []byte("Exif"), []byte{0}),
			hFull("infe", 2, pb16(3), pb16(0), []byte("Exif"), []byte{0}),
			hFull("infe", 2, pb16(4), pb16(0), []byte("hvc1"), []byte{0}))
		iloc := hFull("iloc", 0, []byte{0x44, 0x00}, pb16(2),
			pb16(2), pb16(0), pb16(1), pb32(off), pb32(len(mine)),
			pb16(3), pb16(0), pb16(1), pb32(off+len(mine)), pb32(len(other)))
		iref := hFull("iref", 0, hBox("cdsc", pb16(2), pb16(1), pb16(1)), hBox("cdsc", pb16(3), pb16(1), pb16(4)))
		ipco := hBox("ipco", hFull("ispe", 0, pb32(640), pb32(480)))
		ipma := hFull("ipma", 0, pb32(1), pb16(1), []byte{1, 0x81})
		return hFull("meta", 0, pitm, iinf, iloc, iref, hBox("iprp", ipco, ipma))
	}
	off := len(ftyp) + len(meta(0)) + 8
	h := cat(ftyp, meta(off), hBox("mdat", mine, other))
	m := readPhotoMetaBare(bytes.NewReader(h), int64(len(h)), ".heic")
	if m.Cam != "Mine" || m.W != 640 || m.H != 480 || m.T != time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC).Unix() {
		t.Fatalf("%+v", m)
	}
}

// An iloc of thousands of items with tens of thousands of empty extents
// each is passed over at once, not stepped through.
func TestPhotoMetaHEIFManyEmptyExtents(t *testing.T) {
	ftyp := hBox("ftyp", []byte("heic"), pb32(0), []byte("mif1heic"))
	var items [][]byte
	for i := 0; i < 4096; i++ {
		items = append(items, pb16(100+i), pb16(0), pb16(65535))
	}
	iloc := hFull("iloc", 0, []byte{0x00, 0x00}, pb16(4096), cat(items...))
	iinf := hFull("iinf", 0, pb16(1), hFull("infe", 2, pb16(2), pb16(0), []byte("Exif"), []byte{0}))
	h := cat(ftyp, hFull("meta", 0, hFull("pitm", 0, pb16(1)), iinf, iloc))
	start := time.Now()
	readPhotoMetaBare(bytes.NewReader(h), int64(len(h)), ".heic")
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

func TestPhotosOrient(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 3, 2))
	for i := range src.Pix {
		src.Pix[i] = byte(i * 7)
	}
	same := func(a, b *image.RGBA) bool { return a.Rect.Eq(b.Rect) && bytes.Equal(a.Pix, b.Pix) }
	for _, o := range []int{2, 3, 4, 5, 7} {
		if !same(photosOrient(photosOrient(src, o), o), src) {
			t.Fatalf("orientation %d twice is where it began", o)
		}
	}
	if !same(photosOrient(photosOrient(src, 6), 8), src) {
		t.Fatal("a quarter each way is where it began")
	}
	r := photosOrient(src, 6)
	if r.Rect.Dx() != 2 || r.Rect.Dy() != 3 {
		t.Fatalf("turned: %v", r.Rect)
	}
	// Turned a quarter clockwise, the top left corner is at the top right.
	if !bytes.Equal(r.Pix[r.PixOffset(1, 0):r.PixOffset(1, 0)+4], src.Pix[0:4]) {
		t.Fatal("orientation 6 turns clockwise")
	}
}

// ── the folders, the index and the small copies ────────────────────────

func photosReset(t *testing.T) {
	t.Helper()
	photoLib.Lock()
	for _, rs := range photoLib.roots {
		if rs.cancel != nil {
			rs.cancel()
		}
	}
	photoLib.roots = map[string]*photosRootState{}
	photoLib.order = nil
	photoLib.rescan, photoLib.rescanSeen = 0, false
	photoLib.saved, photoLib.loaded = nil, false
	photoLib.Unlock()
	photosConfCache.Lock()
	photosConfCache.ok = false
	photosConfCache.Unlock()
	photosThumbLRU.Lock()
	photosThumbLRU.items, photosThumbLRU.order, photosThumbLRU.bytes = map[string][]byte{}, nil, 0
	photosThumbLRU.Unlock()
	for _, v := range []string{photosEnvVar, consoleEnvVar, musicEnvVar, "XDG_CACHE_HOME"} {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
	photosIndexBudget = 0
	t.Cleanup(func() { photosIndexBudget = 0 })
}

func photosSettle(t *testing.T) {
	t.Helper()
	photosReconcile()
	for i := 0; i < 40; i++ {
		rs := photosNextDue(time.Now())
		if rs == nil {
			return
		}
		photosWalk(rs)
		photosReconcile()
	}
	t.Fatal("the walker never settled")
}

type photosFixture struct {
	home, pics string
	peer       key.NodePublic
	h          *directHandler
	pngAt      time.Time
}

func newPhotosFixture(t *testing.T) photosFixture {
	t.Helper()
	home := scratchHome(t)
	photosReset(t)
	musicReset(t)
	photosReset(t)
	f := photosFixture{home: home, pics: filepath.Join(home, "Pictures"), h: newDirectHandler()}
	f.peer = key.NewNode().Public()
	if err := allowClient(f.peer.String()); err != nil {
		t.Fatal(err)
	}
	trip := withExif(t, halves(t, 400, 300), exifTIFF(exifSpec{make_: "Apple", model: "iPhone 15 Pro", orient: 6,
		when: "2024:05:01 10:00:00", offs: "+09:00", la: 35.6895, lo: 139.6917, gps: true}))
	writeFile(t, filepath.Join(f.pics, "2024", "trip", "a.jpg"), trip)
	writeFile(t, filepath.Join(f.pics, "2024", "b.png"), noisyPNG(t, 320, 200))
	f.pngAt = time.Date(2022, 3, 4, 5, 6, 7, 0, time.UTC)
	os.Chtimes(filepath.Join(f.pics, "2024", "b.png"), f.pngAt, f.pngAt)
	writeFile(t, filepath.Join(f.pics, "icon.png"), noisyPNG(t, 64, 64))
	writeFile(t, filepath.Join(f.pics, "big.jpg"), hugeJPEG(t, 9000, 7000, plainJPEG(t, 160, 120, color.RGBA{0, 200, 0, 255})))
	writeFile(t, filepath.Join(f.pics, ".hidden", "c.jpg"), halves(t, 300, 300))
	writeFile(t, filepath.Join(f.pics, "notes.txt"), bytes.Repeat([]byte("x"), 5000))
	writeFile(t, filepath.Join(home, "Private", "d.jpg"), halves(t, 300, 300))
	if err := os.Symlink(filepath.Join(home, "Private", "d.jpg"), filepath.Join(f.pics, "escape.jpg")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f photosFixture) get(t *testing.T, target string, peer *key.NodePublic) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if peer != nil {
		req = req.WithContext(transport.WithPeer(req.Context(), *peer))
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func photosBody(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	fr, err := transport.Decode(rec.Body.Bytes())
	if err != nil || fr.Type != transport.TypePhotos {
		t.Fatalf("frame: %v %q", err, rec.Body.String())
	}
	if err := json.Unmarshal(fr.Body, into); err != nil {
		t.Fatal(err)
	}
}

func photosCmd(op string, arg any) consoleResult {
	b, _ := json.Marshal(arg)
	return runPhotosCommand(consoleCmd{ID: "p" + op, Kind: "photos", Target: op, Cmd: string(b)})
}

func (f photosFixture) console(t *testing.T) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	t.Setenv(consoleEnvVar, "1")
}

func (f photosFixture) index(t *testing.T, id string) []photoLine {
	t.Helper()
	var all []photoLine
	from := 0
	for i := 0; i < 100; i++ {
		var ix photosIndexBody
		photosBody(t, f.get(t, "/v1/photos/index?r="+id+"&from="+strconv.Itoa(from), &f.peer), &ix)
		all = append(all, ix.Photos...)
		if !ix.More {
			return all
		}
		from += len(ix.Photos)
	}
	t.Fatal("the pages never ended")
	return nil
}

func (f photosFixture) thumb(t *testing.T, id, p string, px int) (*httptest.ResponseRecorder, image.Image) {
	t.Helper()
	rec := f.get(t, "/v1/photos/thumb?r="+id+"&p="+url.QueryEscape(p)+"&s="+strconv.Itoa(px), &f.peer)
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("type %q", ct)
	}
	img, err := jpeg.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return rec, img
}

func nearRGB(c color.Color, r, g, b int) bool {
	cr, cg, cb, _ := c.RGBA()
	d := func(a uint32, w int) bool { return math.Abs(float64(int(a>>8)-w)) < 60 }
	return d(cr, r) && d(cg, g) && d(cb, b)
}

func TestPhotosChosenFolderIsWalkedAndServed(t *testing.T) {
	f := newPhotosFixture(t)
	if photosOn() {
		t.Fatal("nothing switched on, no console: off")
	}
	f.console(t)
	if !photosOn() {
		t.Fatal("the console and a pinned key: on")
	}
	photosSettle(t)
	var st photosStatusBody
	photosBody(t, f.get(t, "/v1/photos", &f.peer), &st)
	if len(st.Roots) != 0 || !st.CanAdd {
		t.Fatalf("on, nothing chosen, a folder may be: %+v", st)
	}
	for _, p := range []string{photosConfPath(), photosIndexPath()} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("nothing is written down until something is chosen: %s", p)
		}
	}
	var hello transport.Hello
	fr, _ := transport.Decode(f.get(t, "/v1/hello", &f.peer).Body.Bytes())
	json.Unmarshal(fr.Body, &hello)
	if !containsStr(hello.Caps, transport.CapPhotos) {
		t.Fatalf("the hello names photos: %v", hello.Caps)
	}

	r := photosCmd("add", map[string]string{"path": f.pics})
	if r.Code != 0 || r.Out == "" {
		t.Fatalf("add: %+v", r)
	}
	id := r.Out
	photosSettle(t)
	photosBody(t, f.get(t, "/v1/photos", &f.peer), &st)
	if len(st.Roots) != 1 || st.Roots[0].ID != id || st.Roots[0].Path != f.pics || st.Roots[0].N != 3 || st.Roots[0].Sep != string(filepath.Separator) {
		t.Fatalf("status: %+v", st.Roots)
	}
	lines := f.index(t, id)
	by := map[string]photoLine{}
	for _, l := range lines {
		by[l.P] = l
	}
	if len(lines) != 3 {
		t.Fatalf("the photos, not the icon, the hidden folder, the text or the link out: %+v", lines)
	}
	a := by["2024/trip/a.jpg"]
	if a.W != 400 || a.H != 300 || a.O != 6 || a.Z != 540 || a.C != "iPhone 15 Pro" || math.Abs(a.La-35.6895) > 1e-4 ||
		a.T != time.Date(2024, 5, 1, 1, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("a.jpg: %+v", a)
	}
	b := by["2024/b.png"]
	_, z := f.pngAt.In(time.Local).Zone()
	if b.T != f.pngAt.Unix() || b.Z != z/60 || b.W != 320 || b.O != 0 || b.La != 0 {
		t.Fatalf("b.png, by its file's time: %+v", b)
	}
	if by["big.jpg"].W != 9000 {
		t.Fatalf("big.jpg: %+v", by["big.jpg"])
	}

	// The small copies: upright, at the size asked for, never larger than
	// the picture.
	_, img := f.thumb(t, id, "2024/trip/a.jpg", 640)
	if img == nil || img.Bounds().Dx() != 300 || img.Bounds().Dy() != 400 {
		t.Fatalf("a.jpg upright: %v", img)
	}
	if !nearRGB(img.At(150, 20), 220, 20, 20) || !nearRGB(img.At(150, 380), 20, 20, 220) {
		t.Fatalf("turned clockwise: the left half is on top: %v %v", img.At(150, 20), img.At(150, 380))
	}
	_, img = f.thumb(t, id, "2024/trip/a.jpg", 320)
	if img == nil || img.Bounds().Dx() != 240 || img.Bounds().Dy() != 320 {
		t.Fatalf("a.jpg small: %v", img)
	}
	_, img = f.thumb(t, id, "big.jpg", 640)
	if img == nil || img.Bounds().Dx() != 160 || !nearRGB(img.At(80, 60), 0, 200, 0) {
		t.Fatalf("big.jpg by its camera's copy: %v", img)
	}
	base := photosThumbBase(f.pics)
	if ents, err := os.ReadDir(base); err != nil || len(ents) < 3 {
		t.Fatalf("kept on disk: %v %d", err, len(ents))
	}
	for p, want := range map[string]string{"notes.txt": "no-photo", "escape.jpg": "no-photo", "../Private/d.jpg": "bad-path", ".hidden/c.jpg": "no-photo"} {
		if rec, _ := f.thumb(t, id, p, 640); rec.Code == 200 || errCode(t, rec) != want {
			t.Fatalf("%s: %d %s", p, rec.Code, errCode(t, rec))
		}
	}
	// Who may look: a key on the allowlist, while photos are on.
	if rec := f.get(t, "/v1/photos", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("no peer: %d", rec.Code)
	}
	stranger := key.NewNode().Public()
	if rec := f.get(t, "/v1/photos/index?r="+id, &stranger); rec.Code != http.StatusForbidden {
		t.Fatalf("a stranger: %d", rec.Code)
	}
	runPhotosCLI([]string{"off"})
	if rec := f.get(t, "/v1/photos", &f.peer); rec.Code != http.StatusNotFound || errCode(t, rec) != "photos-off" {
		t.Fatalf("off at the keyboard beats the console: %d", rec.Code)
	}
	fr, _ = transport.Decode(f.get(t, "/v1/hello", &f.peer).Body.Bytes())
	json.Unmarshal(fr.Body, &hello)
	if containsStr(hello.Caps, transport.CapPhotos) {
		t.Fatal("off: the hello does not name photos")
	}
	runPhotosCLI([]string{"on"})

	// Taken away: the small copies go with it.
	if r := photosCmd("remove", map[string]string{"id": id}); r.Code != 0 {
		t.Fatalf("remove: %+v", r)
	}
	if _, err := os.Stat(base); err == nil {
		t.Fatal("the small copies are taken away with the folder")
	}
	photosBody(t, f.get(t, "/v1/photos", &f.peer), &st)
	if len(st.Roots) != 0 {
		t.Fatalf("removed: %+v", st.Roots)
	}
	if got := mailboxRefusal(consoleCmd{ID: "x", Kind: "photos", Target: "browse"}); got != "tunnel-only" {
		t.Fatalf("the mailbox carries no photos command: %q", got)
	}
}

func TestPhotosBrowseAndAdd(t *testing.T) {
	f := newPhotosFixture(t)
	runPhotosCLI([]string{"on"})
	for _, op := range []string{"browse", "add"} {
		if r := photosCmd(op, map[string]string{"path": f.pics}); r.Error != "unpinned" {
			t.Fatalf("%s with nothing pinned: %+v", op, r)
		}
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	trustKey(base64.StdEncoding.EncodeToString(pub))
	for _, op := range []string{"browse", "add"} {
		if r := photosCmd(op, map[string]string{"path": f.pics}); r.Error != "console-off" {
			t.Fatalf("%s without the console: %+v", op, r)
		}
	}
	t.Setenv(consoleEnvVar, "1")
	browse := func(p string) photosBrowseBody {
		t.Helper()
		r := photosCmd("browse", map[string]string{"path": p})
		if r.Code != 0 {
			t.Fatalf("browse %q: %+v", p, r)
		}
		var b photosBrowseBody
		if err := json.Unmarshal([]byte(r.Out), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	kinds := map[string]string{}
	for _, pl := range browse("").Places {
		kinds[pl.K] = pl.P
	}
	if kinds["pictures"] != f.pics || kinds["home"] != f.home {
		t.Fatalf("places: %+v", kinds)
	}
	if _, ok := kinds["desktop"]; ok && musicLookAhead {
		t.Fatal("a Desktop that is not there is not a place")
	}
	home := browse(f.home)
	counts := map[string]photosDirView{}
	for _, d := range home.Dirs {
		counts[d.N] = d
	}
	// Counted as files with a picture's name, small or not, hidden folders
	// and links left out.
	if counts["Pictures"].Pics != 4 || counts["Private"].Pics != 1 || counts["Pictures"].U || home.Pics != 5 || home.Pm || home.Here != 0 {
		t.Fatalf("home: %+v", home)
	}
	pics := browse(f.pics)
	if pics.Here != 2 || pics.Pics != 4 || pics.Shown != "" || len(pics.Names) != 2 {
		t.Fatalf("Pictures: %+v", pics)
	}
	if r := photosCmd("add", map[string]string{"path": f.home}); r.Error != "too-broad" {
		t.Fatalf("home itself: %+v", r)
	}
	if r := photosCmd("add", map[string]string{"path": "/"}); r.Error != "too-broad" {
		t.Fatalf("the whole disk: %+v", r)
	}
	if r := photosCmd("add", map[string]string{"path": filepath.Join(f.home, "nope")}); r.Error != "missing" {
		t.Fatalf("not there: %+v", r)
	}
	in := photosCmd("add", map[string]string{"path": filepath.Join(f.pics, "2024")})
	if in.Code != 0 {
		t.Fatalf("add 2024: %+v", in)
	}
	around := photosCmd("add", map[string]string{"path": f.pics, "name": "Photos"})
	if around.Code != 0 {
		t.Fatalf("add around: %+v", around)
	}
	if c := loadPhotosConf(); len(c.Roots) != 1 || c.Roots[0].ID != around.Out || c.Roots[0].Name != "Photos" {
		t.Fatalf("the folder around takes the place of the one inside: %+v", c.Roots)
	}
	if r := photosCmd("add", map[string]string{"path": filepath.Join(f.pics, "2024")}); r.Error != "already-shared" || r.Out != around.Out {
		t.Fatalf("inside one shown: %+v", r)
	}
	if b := browse(filepath.Join(f.pics, "2024")); b.Shown != around.Out {
		t.Fatalf("shown, by the folder around: %+v", b)
	}
	if r := photosCmd("rescan", map[string]string{"id": "nope"}); r.Error != "no-root" {
		t.Fatalf("rescan nothing: %+v", r)
	}
	if r := photosCmd("rescan", map[string]string{}); r.Code != 0 {
		t.Fatalf("rescan all: %+v", r)
	}
}

func TestPhotosIndexPagesAndSurvivesARestart(t *testing.T) {
	f := newPhotosFixture(t)
	for i := 0; i < 30; i++ {
		writeFile(t, filepath.Join(f.pics, "many", "p"+strconv.Itoa(i)+".png"), noisyPNG(t, 200, 200))
	}
	runPhotosCLI([]string{"on", f.pics})
	photosSettle(t)
	id := photoLib.order[0]
	photosIndexBudget = 400
	lines := f.index(t, id)
	if len(lines) != 33 {
		t.Fatalf("every page: %d", len(lines))
	}
	photoLib.Lock()
	rev := photoLib.roots[id].rev
	photoLib.Unlock()
	photosReset(t)
	photosReconcile()
	photoLib.Lock()
	n := len(photoLib.roots[id].photos)
	photoLib.Unlock()
	if n != 33 {
		t.Fatalf("restored %d", n)
	}
	photosSettle(t)
	if photoLib.roots[id].rev != rev {
		t.Fatal("nothing changed, nor did the revision")
	}
	os.Remove(filepath.Join(f.pics, "2024", "b.png"))
	photoLib.Lock()
	photoLib.roots[id].due = true
	photoLib.Unlock()
	photosSettle(t)
	if len(photoLib.roots[id].photos) != 32 || photoLib.roots[id].rev == rev {
		t.Fatal("a picture gone is a new revision")
	}
}
