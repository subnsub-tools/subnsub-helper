package main

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// What the system's image tools read that Go's do not: sips, which every Mac
// has, is the same decoder Preview and Photos use.
var photosNativeKinds = []string{"heic", "heif", "avif", "webp", "tiff"}

var photosNativeExt = map[string]bool{
	".heic": true, ".heif": true, ".hif": true, ".avif": true, ".webp": true, ".tif": true, ".tiff": true,
}

// photosNative is the picture as sips makes it into a JPEG px on its long
// side, and the orientation that JPEG says it is shown at. The picture is
// copied out of the chosen folder first, through the os.Root it was opened
// by, so the tool reads nothing a link in the folder could point it at.
func photosNative(f *os.File, size int64, ext string, px int) (image.Image, int) {
	if !photosNativeExt[ext] || size <= 0 || size > photosThumbRead*2 {
		return nil, 0
	}
	dir, err := os.MkdirTemp("", "subnsub-photo-")
	if err != nil {
		return nil, 0
	}
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "in"+ext), filepath.Join(dir, "out.jpg")
	w, err := os.OpenFile(in, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, 0
	}
	_, err = io.Copy(w, io.NewSectionReader(f, 0, size))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sips", "-s", "format", "jpeg", "-s", "formatOptions", "85",
		"-Z", strconv.Itoa(px), in, "--out", out)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Run() != nil {
		return nil, 0
	}
	b, err := os.ReadFile(out)
	if err != nil || len(b) == 0 || len(b) > 32<<20 {
		return nil, 0
	}
	img, err := jpeg.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, 0
	}
	return img, readPhotoMeta(bytes.NewReader(b), int64(len(b)), ".jpg").O
}
