//go:build linux

package main

import (
	"path/filepath"
	"strings"
)

// musicVolumes: the whole tree, then each disk mounted somewhere other than
// the system's own places — a data disk, a USB stick, a NAS share.
func musicVolumes() []musicPlace {
	out := []musicPlace{{K: "root", P: "/"}}
	list, _ := scanLinuxMounts()
	for _, m := range list {
		if musicVolumeSkip(m.Path) {
			continue
		}
		out = append(out, musicPlace{K: "volume", P: m.Path, N: filepath.Base(m.Path)})
	}
	return out
}

func musicVolumeSkip(p string) bool {
	if strings.HasPrefix(p, "/run/media/") {
		// Where a desktop mounts a removable disk.
		return false
	}
	for _, pre := range []string{"/boot", "/efi", "/snap", "/var", "/usr", "/opt", "/tmp", "/proc", "/sys", "/dev", "/run", "/etc"} {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}
