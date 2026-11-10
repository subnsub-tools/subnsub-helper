//go:build !darwin

package main

import (
	"image"
	"os"
)

// No system decoder is called on here: HEIC, AVIF, WebP and TIFF pictures
// are listed, without a small copy.
var photosNativeKinds = []string{}

func photosNative(*os.File, int64, string, int) (image.Image, int) { return nil, 0 }
