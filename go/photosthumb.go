package main

// photosthumb.go — the small copies the Photos tab shows: a JPEG 640 (or
// 320) pixels on its long side, upright, the alpha laid over white. Made
// when first asked for, kept in memory a while and on this machine's cache
// disk after that, under a folder per chosen folder that is taken away with
// it (photosThumbForget).
//
// JPEG, PNG and GIF are decoded here; HEIC, AVIF, WebP and TIFF by the
// system's own decoder where there is one (photosthumb_darwin.go), else not
// at all. A picture too large to decode here is shown by the small copy its
// camera wrote into it, where there is one.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	_ "image/gif"
	_ "image/png"
)

const (
	photosThumbBig    = 640
	photosThumbSmall  = 320
	photosThumbRead   = 96 << 20
	photosThumbPixels = 52 << 20
	photosThumbMem    = 32 << 20
	photosThumbDisk   = 512 << 20
)

var photosThumbGate = make(chan struct{}, photosGates())

func photosThumbKinds() []string {
	return append([]string{"jpeg", "png", "gif"}, photosNativeKinds...)
}

func (h *directHandler) photosThumb(w http.ResponseWriter, r *http.Request) {
	if !h.photosPeer(w, r) {
		return
	}
	conf, t, ok := h.photosFind(w, r)
	if !ok {
		return
	}
	px := photosThumbBig
	if s := queryInt(r, "s"); s > 0 && s <= photosThumbSmall {
		px = photosThumbSmall
	}
	key := photosThumbKey(t, px)
	if b := photosThumbGet(conf.Path, key); b != nil {
		photosThumbSend(w, b)
		return
	}
	select {
	case photosThumbGate <- struct{}{}:
		defer func() { <-photosThumbGate }()
	case <-r.Context().Done():
		return
	}
	// Made by another request while this one waited.
	if b := photosThumbGet(conf.Path, key); b != nil {
		photosThumbSend(w, b)
		return
	}
	var out []byte
	if px == photosThumbSmall {
		bkey := photosThumbKey(t, photosThumbBig)
		big := photosThumbGet(conf.Path, bkey)
		if big == nil {
			if big = photosThumbMake(conf, t, photosThumbBig); big != nil {
				photosThumbPut(conf.Path, bkey, big)
			}
		}
		if big != nil {
			if img, err := jpeg.Decode(bytes.NewReader(big)); err == nil {
				out = photosJPEG(photosShrink(img, photosThumbSmall))
			}
		}
	} else {
		out = photosThumbMake(conf, t, px)
	}
	if out == nil {
		h.refuse(w, http.StatusUnsupportedMediaType, "no-thumb")
		return
	}
	photosThumbPut(conf.Path, key, out)
	photosThumbSend(w, out)
}

func photosThumbSend(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func photosJPEG(img image.Image) []byte {
	if img == nil {
		return nil
	}
	var buf bytes.Buffer
	if jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}) != nil {
		return nil
	}
	return buf.Bytes()
}

// photosThumbMake reads the picture and makes its small copy.
func photosThumbMake(conf photosRootConf, t photoLine, px int) []byte {
	root, err := os.OpenRoot(conf.Path)
	if err != nil {
		return nil
	}
	defer root.Close()
	f, err := root.Open(t.P)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	size := fi.Size()
	ext := strings.ToLower(path.Ext(t.P))
	m := readPhotoMeta(f, size, ext)
	var img image.Image
	if size <= photosThumbRead {
		sr := io.NewSectionReader(f, 0, size)
		if cfg, _, err := image.DecodeConfig(sr); err == nil && cfg.Width > 0 && cfg.Height > 0 && int64(cfg.Width)*int64(cfg.Height) <= photosThumbPixels {
			if _, err := sr.Seek(0, io.SeekStart); err == nil {
				img, _, _ = image.Decode(sr)
			}
		}
	}
	if img != nil {
		return photosJPEG(photosOrient(photosShrink(img, px), m.O))
	}
	// The system's decoder, for what this one does not read.
	if n, o2 := photosNative(f, size, ext, px); n != nil {
		s := photosShrink(n, px)
		// Upright as the picture says it is shown: the system's copy may
		// have been turned already or may still carry the turn.
		if o2 > 1 {
			turned := photosOrient(s, o2)
			dw, dh := t.W, t.H
			if t.O >= 5 {
				dw, dh = dh, dw
			}
			if dw <= 0 || dh <= 0 || (dw >= dh) == (turned.Rect.Dx() >= turned.Rect.Dy()) {
				s = turned
			}
		}
		return photosJPEG(s)
	}
	// The camera's own small copy, for a picture too large to decode here.
	if m.thOff > 0 && m.thLen > 0 && m.thOff+m.thLen <= size {
		b := make([]byte, m.thLen)
		if n, _ := f.ReadAt(b, m.thOff); int64(n) == m.thLen {
			if cfg, err := jpeg.DecodeConfig(bytes.NewReader(b)); err != nil || cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > photosThumbPixels {
				return nil
			}
			if th, err := jpeg.Decode(bytes.NewReader(b)); err == nil {
				return photosJPEG(photosOrient(photosShrink(th, px), m.O))
			}
		}
	}
	return nil
}

// photosShrink averages the picture over each pixel of a copy that fits in
// px × px, laid over white. The decoders' own pixel layouts are read
// directly; anything else through image.Image, which is slower.
func photosShrink(src image.Image, px int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 0 || sh <= 0 {
		return image.NewRGBA(image.Rect(0, 0, 1, 1))
	}
	dw, dh := sw, sh
	if sw > px || sh > px {
		if sw >= sh {
			dw, dh = px, sh*px/sw
		} else {
			dw, dh = sw*px/sh, px
		}
	}
	dw, dh = max(dw, 1), max(dh, 1)
	xs, ys := make([]int, dw+1), make([]int, dh+1)
	for x := 0; x <= dw; x++ {
		xs[x] = x * sw / dw
	}
	for y := 0; y <= dh; y++ {
		ys[y] = y * sh / dh
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	put := func(x, y int, r, g, bl uint8) {
		i := dst.PixOffset(x, y)
		dst.Pix[i], dst.Pix[i+1], dst.Pix[i+2], dst.Pix[i+3] = r, g, bl, 255
	}
	for y := 0; y < dh; y++ {
		y0, y1 := ys[y], max(ys[y+1], ys[y]+1)
		for x := 0; x < dw; x++ {
			x0, x1 := xs[x], max(xs[x+1], xs[x]+1)
			var sr, sg, sb, n uint64
			switch s := src.(type) {
			case *image.YCbCr:
				for yy := y0; yy < y1; yy++ {
					row := s.YOffset(b.Min.X+x0, b.Min.Y+yy)
					for xx := x0; xx < x1; xx++ {
						sr += uint64(s.Y[row+xx-x0])
						ci := s.COffset(b.Min.X+xx, b.Min.Y+yy)
						sg += uint64(s.Cb[ci])
						sb += uint64(s.Cr[ci])
					}
				}
				n = uint64((y1 - y0) * (x1 - x0))
				r, g, bl := color.YCbCrToRGB(uint8(sr/n), uint8(sg/n), uint8(sb/n))
				put(x, y, r, g, bl)
				continue
			case *image.NRGBA:
				for yy := y0; yy < y1; yy++ {
					i := s.PixOffset(b.Min.X+x0, b.Min.Y+yy)
					for xx := x0; xx < x1; xx, i = xx+1, i+4 {
						a := uint64(s.Pix[i+3])
						sr += uint64(s.Pix[i])*a + 255*(255-a)
						sg += uint64(s.Pix[i+1])*a + 255*(255-a)
						sb += uint64(s.Pix[i+2])*a + 255*(255-a)
					}
				}
				n = uint64((y1-y0)*(x1-x0)) * 255
			case *image.RGBA:
				for yy := y0; yy < y1; yy++ {
					i := s.PixOffset(b.Min.X+x0, b.Min.Y+yy)
					for xx := x0; xx < x1; xx, i = xx+1, i+4 {
						a := uint64(s.Pix[i+3])
						sr += uint64(s.Pix[i]) + 255 - a
						sg += uint64(s.Pix[i+1]) + 255 - a
						sb += uint64(s.Pix[i+2]) + 255 - a
					}
				}
				n = uint64((y1 - y0) * (x1 - x0))
			case *image.Gray:
				for yy := y0; yy < y1; yy++ {
					i := s.PixOffset(b.Min.X+x0, b.Min.Y+yy)
					for xx := x0; xx < x1; xx, i = xx+1, i+1 {
						sr += uint64(s.Pix[i])
					}
				}
				n = uint64((y1 - y0) * (x1 - x0))
				sg, sb = sr, sr
			default:
				for yy := y0; yy < y1; yy++ {
					for xx := x0; xx < x1; xx++ {
						cr, cg, cb, ca := src.At(b.Min.X+xx, b.Min.Y+yy).RGBA()
						sr += uint64(cr>>8) + 255 - uint64(ca>>8)
						sg += uint64(cg>>8) + 255 - uint64(ca>>8)
						sb += uint64(cb>>8) + 255 - uint64(ca>>8)
					}
				}
				n = uint64((y1 - y0) * (x1 - x0))
			}
			put(x, y, uint8(min(sr/n, 255)), uint8(min(sg/n, 255)), uint8(min(sb/n, 255)))
		}
	}
	return dst
}

// photosOrient turns a copy the way EXIF orientation o says it is shown.
func photosOrient(src *image.RGBA, o int) *image.RGBA {
	if o <= 1 || o > 8 {
		return src
	}
	w, h := src.Rect.Dx(), src.Rect.Dy()
	dw, dh := w, h
	if o >= 5 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var dx, dy int
			switch o {
			case 2:
				dx, dy = w-1-x, y
			case 3:
				dx, dy = w-1-x, h-1-y
			case 4:
				dx, dy = x, h-1-y
			case 5:
				dx, dy = y, x
			case 6:
				dx, dy = h-1-y, x
			case 7:
				dx, dy = h-1-y, w-1-x
			case 8:
				dx, dy = y, w-1-x
			}
			si, di := src.PixOffset(src.Rect.Min.X+x, src.Rect.Min.Y+y), dst.PixOffset(dx, dy)
			copy(dst.Pix[di:di+4], src.Pix[si:si+4])
		}
	}
	return dst
}

// ── kept ─────────────────────────────────────────────────────────────────

func photosThumbKey(t photoLine, px int) string {
	h := sha256.Sum256([]byte(t.P + "\n" + strconv.FormatInt(t.S, 10) + "\n" + strconv.FormatInt(t.M, 10) + "\n" + strconv.Itoa(px)))
	return hex.EncodeToString(h[:16])
}

// photosThumbBase is where the small copies of one chosen folder's pictures
// are kept on disk; "" when this account has nowhere to keep them.
func photosThumbBase(rootPath string) string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		if dir = configDir(); dir == "" {
			return ""
		}
	}
	h := sha256.Sum256([]byte("photos\n" + rootPath))
	return filepath.Join(dir, "subnsub-helper", "photos", hex.EncodeToString(h[:8]))
}

var photosThumbLRU = struct {
	sync.Mutex
	order []string
	items map[string][]byte
	bytes int
}{items: map[string][]byte{}}

func photosThumbGet(rootPath, key string) []byte {
	mk := rootPath + "\n" + key
	photosThumbLRU.Lock()
	b, ok := photosThumbLRU.items[mk]
	photosThumbLRU.Unlock()
	if ok {
		return b
	}
	base := photosThumbBase(rootPath)
	if base == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(base, key+".jpg"))
	if err != nil || len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return nil
	}
	photosThumbMemPut(mk, b)
	return b
}

func photosThumbMemPut(mk string, b []byte) {
	photosThumbLRU.Lock()
	defer photosThumbLRU.Unlock()
	if _, ok := photosThumbLRU.items[mk]; ok || len(b) > photosThumbMem/8 {
		return
	}
	photosThumbLRU.items[mk] = b
	photosThumbLRU.order = append(photosThumbLRU.order, mk)
	photosThumbLRU.bytes += len(b)
	for photosThumbLRU.bytes > photosThumbMem && len(photosThumbLRU.order) > 0 {
		old := photosThumbLRU.order[0]
		photosThumbLRU.order = photosThumbLRU.order[1:]
		photosThumbLRU.bytes -= len(photosThumbLRU.items[old])
		delete(photosThumbLRU.items, old)
	}
}

// photosThumbDiskUsed is what the cache holds on disk, as far as this
// process knows: counted once, then kept up as copies are added.
var (
	photosThumbDiskUsed   atomic.Int64
	photosThumbDiskCount  sync.Once
	photosThumbDiskPruneM sync.Mutex
)

func photosThumbPut(rootPath, key string, b []byte) {
	photosThumbMemPut(rootPath+"\n"+key, b)
	base := photosThumbBase(rootPath)
	if base == "" || os.MkdirAll(base, 0o700) != nil {
		return
	}
	if writeFileAtomic(filepath.Join(base, key+".jpg"), b) != nil {
		return
	}
	photosThumbDiskCount.Do(func() { photosThumbDiskUsed.Store(photosThumbDiskSize()) })
	if photosThumbDiskUsed.Add(int64(len(b))) > photosThumbDisk {
		go photosThumbPrune()
	}
}

func photosThumbTop() string {
	base := photosThumbBase("")
	if base == "" {
		return ""
	}
	return filepath.Dir(base)
}

func photosThumbDiskSize() int64 {
	top := photosThumbTop()
	var n int64
	if top == "" {
		return 0
	}
	filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// photosThumbPrune takes the oldest copies away until the cache is down to
// three quarters of what it may hold.
func photosThumbPrune() {
	if !photosThumbDiskPruneM.TryLock() {
		return
	}
	defer photosThumbDiskPruneM.Unlock()
	top := photosThumbTop()
	if top == "" {
		return
	}
	type ent struct {
		p    string
		mod  int64
		size int64
	}
	var all []ent
	var total int64
	filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				all = append(all, ent{p, fi.ModTime().UnixNano(), fi.Size()})
				total += fi.Size()
			}
		}
		return nil
	})
	sort.Slice(all, func(i, j int) bool { return all[i].mod < all[j].mod })
	for _, e := range all {
		if total <= photosThumbDisk*3/4 {
			break
		}
		if os.Remove(e.p) == nil {
			total -= e.size
		}
	}
	photosThumbDiskUsed.Store(total)
}

// photosThumbForget takes away what was kept for a folder no longer shown.
func photosThumbForget(rootPath string) {
	photosThumbLRU.Lock()
	kept := photosThumbLRU.order[:0]
	for _, mk := range photosThumbLRU.order {
		if strings.HasPrefix(mk, rootPath+"\n") {
			photosThumbLRU.bytes -= len(photosThumbLRU.items[mk])
			delete(photosThumbLRU.items, mk)
			continue
		}
		kept = append(kept, mk)
	}
	photosThumbLRU.order = kept
	photosThumbLRU.Unlock()
	if base := photosThumbBase(rootPath); base != "" {
		os.RemoveAll(base)
		photosThumbDiskUsed.Store(photosThumbDiskSize())
	}
}
