//go:build darwin

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// musicVolumes: the whole tree, then every other disk under /Volumes. The
// startup disk is there too, as a link to /, and is left out.
func musicVolumes() []musicPlace {
	out := []musicPlace{{K: "root", P: "/"}}
	ents, _ := os.ReadDir("/Volumes")
	for _, e := range ents {
		if e.Type()&fs.ModeSymlink != 0 || !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, musicPlace{K: "volume", P: filepath.Join("/Volumes", e.Name()), N: e.Name()})
	}
	return out
}
