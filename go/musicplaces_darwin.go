//go:build darwin

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// On macOS the folders a person keeps things in (Downloads, Documents, the
// Music library) and the other disks are guarded: the system asks before
// anything reads them. So nothing is touched before it is opened on a page
// (user, 2026-11-04: macOS above all): the places are named, not looked at,
// and a link in a listing is not followed to see where it leads.
const musicLookAhead = false

// The system asks the person at the machine before a guarded folder is read,
// and the read waits for the answer (musicWithin, musicAskWatch).
const musicSystemAsks = true

// musicGuarded: the folders macOS asks about — Desktop, Documents, Downloads,
// iCloud Drive, the media folders, other apps' data — and the other disks,
// removable or on the network, under /Volumes. By name alone: nothing is
// looked at.
func musicGuarded(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	p = filepath.Clean(p)
	// The startup disk's data, by the name it also has.
	if rest, ok := strings.CutPrefix(p, "/System/Volumes/Data/"); ok {
		p = "/" + rest
	}
	if strings.HasPrefix(p, "/Volumes/") {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	for _, d := range []string{"Desktop", "Documents", "Downloads", "Music", "Movies", "Pictures",
		"Library/Mobile Documents", "Library/Containers", "Library/Group Containers"} {
		g := filepath.Join(home, d)
		if p == g || strings.HasPrefix(p, g+"/") {
			return true
		}
	}
	return false
}

// musicGuardedLinks: guarded by its name, or by where a link on the way
// leads — a folder elsewhere linked to Documents is Documents to the system.
func musicGuardedLinks(p string) bool { return musicLinksInto(p, musicGuarded) }

func musicHomeMusic(home string) string { return filepath.Join(home, "Music") }

// musicVolumes: the whole tree, then every other disk under /Volumes, by the
// names /Volumes lists. The startup disk is there too, as a link to /, and
// is left out.
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
