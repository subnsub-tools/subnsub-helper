package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// memSource is a file held in memory.
type memSource []byte

func (m memSource) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m)) {
		return 0, os.ErrClosed
	}
	n := copy(p, m[off:])
	if n < len(p) {
		return n, os.ErrClosed
	}
	return n, nil
}
func (m memSource) Size() int64 { return int64(len(m)) }

func be32b(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func le32b(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le16b(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }

func syncsafeB(n int) []byte {
	return []byte{byte(n >> 21 & 0x7f), byte(n >> 14 & 0x7f), byte(n >> 7 & 0x7f), byte(n & 0x7f)}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func frame23(id string, data []byte) []byte {
	return cat([]byte(id), be32b(uint32(len(data))), []byte{0, 0}, data)
}

func frame24(id string, data []byte) []byte {
	return cat([]byte(id), syncsafeB(len(data)), []byte{0, 0}, data)
}

func id3(ver byte, frames ...[]byte) []byte {
	body := cat(frames...)
	return cat([]byte("ID3"), []byte{ver, 0, 0}, syncsafeB(len(body)), body)
}

func tinyPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 40), uint8(y * 40), 200, 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// mp3Frames is n MPEG-1 layer III frames at 128 kbps / 44.1 kHz, the first a
// Xing header naming xing frames when xing > 0.
func mp3Frames(n, xing int) []byte {
	const flen = 417 // 144 * 128000 / 44100
	var out []byte
	for i := 0; i < n; i++ {
		f := make([]byte, flen)
		copy(f, []byte{0xFF, 0xFB, 0x90, 0x00})
		if i == 0 && xing > 0 {
			copy(f[36:], "Xing")
			copy(f[40:], be32b(1))
			copy(f[44:], be32b(uint32(xing)))
		}
		out = append(out, f...)
	}
	return out
}

func near(a, b float64) bool { return math.Abs(a-b) < 0.06 }

func TestMusicTagsID3v23WithXingAndCover(t *testing.T) {
	pic := tinyPNG(t, 4, 4)
	apic := cat([]byte{0}, []byte("image/png\x00"), []byte{3}, []byte("front\x00"), pic)
	tag := id3(3,
		frame23("TIT2", cat([]byte{0}, []byte("Night Drive"))),
		frame23("TPE1", cat([]byte{1, 0xFF, 0xFE}, []byte("B\x00a\x00n\x00d\x00"))),
		frame23("TALB", cat([]byte{0}, []byte("First\x00Second"))),
		frame23("TRCK", cat([]byte{0}, []byte("3/12"))),
		frame23("TYER", cat([]byte{0}, []byte("2019"))),
		frame23("APIC", apic),
	)
	file := cat(tag, mp3Frames(8, 1000))
	m := readMusicMeta(memSource(file), true)
	if m.Title != "Night Drive" || m.Artist != "Band" || m.Album != "First" || m.Track != 3 || m.Year != 2019 {
		t.Fatalf("tags: %+v", m)
	}
	if !near(m.Duration, 1000*1152/44100.0) {
		t.Fatalf("duration from the Xing header: %v", m.Duration)
	}
	if !m.HasPic || m.Pic == nil || m.Pic.Mime != "image/png" || !bytes.Equal(m.Pic.Data, pic) {
		t.Fatalf("cover: %+v", m.Pic)
	}
	// Without asking for the picture, only the fact of one.
	m2 := readMusicMeta(memSource(file), false)
	if !m2.HasPic || m2.Pic != nil {
		t.Fatalf("a scan keeps no image bytes: %+v", m2.Pic)
	}
}

func TestMusicTagsID3v24AndConstantBitRate(t *testing.T) {
	tag := id3(4,
		frame24("TIT2", cat([]byte{3}, []byte("Caf\xc3\xa9"))),
		frame24("TPE2", cat([]byte{3}, []byte("Album Artist"))),
		frame24("TPOS", cat([]byte{3}, []byte("2"))),
	)
	audio := mp3Frames(100, 0)
	file := cat(tag, audio)
	m := readMusicMeta(memSource(file), false)
	if m.Title != "Café" || m.Artist != "Album Artist" || m.AlbumArtist != "Album Artist" || m.Disc != 2 {
		t.Fatalf("tags: %+v", m)
	}
	want := float64(len(audio)) * 8 / 128000
	if !near(m.Duration, want) {
		t.Fatalf("constant bit rate duration %v, want %v", m.Duration, want)
	}
}

func TestMusicTagsLatin1ThatIsReallyGBK(t *testing.T) {
	// Three Chinese characters in GBK, declared ISO-8859-1, as Chinese
	// software writes them; and a real Latin-1 accent beside ASCII.
	tag := id3(3,
		frame23("TIT2", cat([]byte{0}, []byte("\xd6\xdc\xbd\xdc\xc2\xd7"))),
		frame23("TPE1", cat([]byte{0}, []byte("M\xf6tley"))),
	)
	m := readMusicMeta(memSource(cat(tag, mp3Frames(4, 0))), false)
	if m.Title != "\u5468\u6770\u4f26" {
		t.Fatalf("GBK title: %q", m.Title)
	}
	if m.Artist != "Mötley" {
		t.Fatalf("Latin-1 artist: %q", m.Artist)
	}
}

func TestMusicTagsID3v1Only(t *testing.T) {
	v1 := make([]byte, 128)
	copy(v1, "TAG")
	copy(v1[3:], "Old Song")
	copy(v1[33:], "Old Band")
	copy(v1[63:], "Old Album")
	copy(v1[93:], "1999")
	v1[126] = 7
	file := cat(mp3Frames(20, 0), v1)
	m := readMusicMeta(memSource(file), false)
	if m.Title != "Old Song" || m.Artist != "Old Band" || m.Album != "Old Album" || m.Year != 1999 || m.Track != 7 {
		t.Fatalf("ID3v1: %+v", m)
	}
	if !near(m.Duration, float64(20*417)*8/128000) {
		t.Fatalf("duration %v", m.Duration)
	}
}

func vorbisBlock(vendor string, kv ...string) []byte {
	out := cat(le32b(uint32(len(vendor))), []byte(vendor), le32b(uint32(len(kv))))
	for _, c := range kv {
		out = cat(out, le32b(uint32(len(c))), []byte(c))
	}
	return out
}

func flacFile(t *testing.T, pic []byte) []byte {
	si := make([]byte, 34)
	si[10], si[11], si[12], si[13] = 0x0A, 0xC4, 0x42, 0xF0
	copy(si[14:], be32b(441000)) // 10 s at 44.1 kHz
	vc := vorbisBlock("test", "TITLE=Lake", "ARTIST=Quartet", "ALBUM=Waters", "TRACKNUMBER=4/9", "DATE=2021-03-04", "DISCNUMBER=1")
	pb := cat(be32b(3), be32b(9), []byte("image/png"), be32b(0), make([]byte, 16), be32b(uint32(len(pic))), pic)
	blk := func(typ byte, last bool, b []byte) []byte {
		if last {
			typ |= 0x80
		}
		return cat([]byte{typ, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b)
	}
	return cat([]byte("fLaC"), blk(0, false, si), blk(4, false, vc), blk(6, true, pb), make([]byte, 64))
}

func TestMusicTagsFLAC(t *testing.T) {
	pic := tinyPNG(t, 3, 3)
	file := flacFile(t, pic)
	m := readMusicMeta(memSource(file), true)
	if m.Title != "Lake" || m.Artist != "Quartet" || m.Album != "Waters" || m.Track != 4 || m.Year != 2021 || m.Disc != 1 {
		t.Fatalf("FLAC tags: %+v", m)
	}
	if !near(m.Duration, 10) {
		t.Fatalf("FLAC duration %v", m.Duration)
	}
	if m.Pic == nil || !bytes.Equal(m.Pic.Data, pic) {
		t.Fatal("FLAC picture")
	}
	// The same FLAC behind an ID3 prefix keeps its own comments.
	tag := id3(3, frame23("TPE1", cat([]byte{0}, []byte("Prefix"))))
	m2 := readMusicMeta(memSource(cat(tag, file)), false)
	if m2.Title != "Lake" || m2.Artist != "Prefix" || !near(m2.Duration, 10) {
		t.Fatalf("FLAC behind ID3: %+v", m2)
	}
}

// oggPage is one page holding the given packets whole.
func oggPage(serial uint32, granule uint64, packets ...[]byte) []byte {
	var segs, body []byte
	for _, p := range packets {
		n := len(p)
		for n >= 255 {
			segs = append(segs, 255)
			n -= 255
		}
		segs = append(segs, byte(n))
		body = append(body, p...)
	}
	g := make([]byte, 8)
	binary.LittleEndian.PutUint64(g, granule)
	return cat([]byte("OggS"), []byte{0, 0}, g, le32b(serial), le32b(0), le32b(0), []byte{byte(len(segs))}, segs, body)
}

func TestMusicTagsOggVorbisAndOpus(t *testing.T) {
	id := cat([]byte{1}, []byte("vorbis"), le32b(0), []byte{2}, le32b(44100), make([]byte, 13))
	com := cat([]byte{3}, []byte("vorbis"), vorbisBlock("v", "TITLE=Rain", "ARTIST=Choir", "ALBUM=Weather"), []byte{1})
	file := cat(oggPage(7, 0, id), oggPage(7, 0, com), oggPage(7, 441000, make([]byte, 300)))
	m := readMusicMeta(memSource(file), false)
	if m.Title != "Rain" || m.Artist != "Choir" || m.Album != "Weather" || !near(m.Duration, 10) {
		t.Fatalf("Vorbis: %+v", m)
	}
	oid := cat([]byte("OpusHead"), []byte{1, 2}, le16b(312), le32b(48000), []byte{0, 0, 0})
	ocom := cat([]byte("OpusTags"), vorbisBlock("v", "TITLE=Wind"))
	ofile := cat(oggPage(9, 0, oid), oggPage(9, 0, ocom), oggPage(9, 480312, make([]byte, 100)))
	om := readMusicMeta(memSource(ofile), false)
	if om.Title != "Wind" || !near(om.Duration, 10) {
		t.Fatalf("Opus: %+v", om)
	}
}

func atomB(typ string, parts ...[]byte) []byte {
	body := cat(parts...)
	return cat(be32b(uint32(8+len(body))), []byte(typ), body)
}

func TestMusicTagsMP4(t *testing.T) {
	pic := tinyPNG(t, 5, 5)
	data := func(kind uint32, payload []byte) []byte { return atomB("data", be32b(kind), be32b(0), payload) }
	mvhd := atomB("mvhd", []byte{0, 0, 0, 0}, be32b(0), be32b(0), be32b(1000), be32b(12345), make([]byte, 80))
	ilst := atomB("ilst",
		atomB("\xa9nam", data(1, []byte("Harbour"))),
		atomB("\xa9ART", data(1, []byte("Trio"))),
		atomB("\xa9alb", data(1, []byte("Coast"))),
		atomB("\xa9day", data(1, []byte("2008-06-01"))),
		atomB("trkn", data(0, []byte{0, 0, 0, 5, 0, 11, 0, 0})),
		atomB("covr", data(14, pic)),
	)
	meta := atomB("meta", []byte{0, 0, 0, 0}, atomB("hdlr", make([]byte, 25)), ilst)
	moov := atomB("moov", mvhd, atomB("udta", meta))
	// moov after a large mdat, as some encoders write it.
	file := cat(atomB("ftyp", []byte("M4A "), be32b(0)), atomB("mdat", make([]byte, 5000)), moov)
	m := readMusicMeta(memSource(file), true)
	if m.Title != "Harbour" || m.Artist != "Trio" || m.Album != "Coast" || m.Year != 2008 || m.Track != 5 {
		t.Fatalf("MP4 tags: %+v", m)
	}
	if !near(m.Duration, 12.345) {
		t.Fatalf("MP4 duration %v", m.Duration)
	}
	if m.Pic == nil || !bytes.Equal(m.Pic.Data, pic) {
		t.Fatal("MP4 cover")
	}
}

func TestMusicTagsWAVAndAIFF(t *testing.T) {
	fmtc := cat([]byte("fmt "), le32b(16), le16b(1), le16b(2), le32b(44100), le32b(176400), le16b(4), le16b(16))
	info := cat([]byte("INFO"), []byte("INAM"), le32b(5), []byte("Tone\x00"), []byte{0}, []byte("IART"), le32b(4), []byte("Lab\x00"))
	list := cat([]byte("LIST"), le32b(uint32(len(info))), info)
	wav := cat([]byte("RIFF"), le32b(0), []byte("WAVE"), fmtc, list, []byte("data"), le32b(1764000), make([]byte, 64))
	m := readMusicMeta(memSource(wav), false)
	if m.Title != "Tone" || m.Artist != "Lab" || !near(m.Duration, 10) {
		t.Fatalf("WAV: %+v", m)
	}
	comm := cat([]byte("COMM"), be32b(18), []byte{0, 2}, be32b(441000), []byte{0, 16}, []byte{0x40, 0x0E, 0xAC, 0x44, 0, 0, 0, 0, 0, 0})
	aiff := cat([]byte("FORM"), be32b(0), []byte("AIFF"), comm, []byte("NAME"), be32b(4), []byte("Hum!"))
	am := readMusicMeta(memSource(aiff), false)
	if am.Title != "Hum!" || !near(am.Duration, 10) {
		t.Fatalf("AIFF: %+v", am)
	}
}

// Whatever a file holds, reading it never panics: random bytes, random bytes
// behind every magic number, and every valid sample cut short.
func TestMusicTagsNeverPanics(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	magics := [][]byte{[]byte("ID3\x03\x00\x00"), []byte("ID3\x04\x00\x40"), []byte("fLaC"), []byte("OggS"),
		[]byte("\x00\x00\x00\x18ftypM4A "), []byte("RIFF\x00\x00\x00\x00WAVE"), []byte("FORM\x00\x00\x00\x00AIFF"), {0xFF, 0xFB, 0x90, 0}}
	for i := 0; i < 3000; i++ {
		b := make([]byte, r.Intn(3000))
		r.Read(b)
		if i%2 == 0 {
			m := magics[i%len(magics)]
			b = cat(m, b)
		}
		readMusicMeta(memSource(b), true)
	}
	samples := [][]byte{flacFile(t, tinyPNG(t, 2, 2)), cat(id3(3, frame23("TIT2", cat([]byte{1}, []byte{0xFF, 0xFE, 'a'}))), mp3Frames(3, 9))}
	for _, s := range samples {
		for n := 0; n < len(s); n += 7 {
			readMusicMeta(memSource(s[:n]), true)
		}
	}
}

// Real encoders, where this machine has them: ffmpeg writes the tags and the
// running time is the length of the tone it was asked for.
func TestMusicTagsFromFFmpeg(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("no ffmpeg here")
	}
	dir := t.TempDir()
	cases := []struct{ name, codec string }{
		{"a.mp3", "libmp3lame"}, {"a.flac", "flac"}, {"a.ogg", "libvorbis"}, {"a.opus", "libopus"}, {"a.m4a", "aac"}, {"a.wav", "pcm_s16le"},
	}
	ran := 0
	for _, c := range cases {
		out := filepath.Join(dir, c.name)
		cmd := exec.Command("ffmpeg", "-loglevel", "error", "-f", "lavfi", "-i", "sine=frequency=440:duration=7",
			"-c:a", c.codec, "-metadata", "title=Tone Title", "-metadata", "artist=Tone Artist", "-metadata", "album=Tone Album", "-y", out)
		if err := cmd.Run(); err != nil {
			continue // this build has no such encoder
		}
		ran++
		f, err := os.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := f.Stat()
		m := readMusicMeta(fileSource{f, fi.Size()}, false)
		f.Close()
		if c.name != "a.wav" && (m.Title != "Tone Title" || m.Artist != "Tone Artist" || m.Album != "Tone Album") {
			t.Errorf("%s tags: %+v", c.name, m)
		}
		if math.Abs(m.Duration-7) > 0.2 {
			t.Errorf("%s duration %v, want about 7", c.name, m.Duration)
		}
	}
	if ran == 0 {
		t.Skip("ffmpeg here has none of the encoders")
	}
}

func TestMusicCleanTagAndNumbers(t *testing.T) {
	if got := cleanTag("  a\x01b\tc  "); got != "abc" {
		t.Fatalf("clean %q", got)
	}
	if got := cleanTag(strings.Repeat("x", 500)); len(got) != tagText {
		t.Fatalf("length %d", len(got))
	}
	for in, want := range map[string]int{"3/12": 3, "2019-05-01": 2019, "": 0, "x": 0, " 07 ": 7} {
		if got := leadingInt(in); got != want {
			t.Fatalf("leadingInt(%q) = %d", in, got)
		}
	}
}
