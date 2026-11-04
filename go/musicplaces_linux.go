//go:build linux

package main

import (
	"path/filepath"
	"strings"
)

// A place is shown only if it is a folder here now, and a link in a
// listing is looked through to see whether it leads to one: nothing here
// asks the person first, as macOS does (musicplaces_darwin.go).
const musicLookAhead = true

// Nothing here waits on a person's answer to read a folder: a folder this
// account may not read says so at once.
const musicSystemAsks = false

func musicGuardedLinks(string) bool { return false }

func musicHomeMusic(string) string { return musicDefaultDir() }

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
