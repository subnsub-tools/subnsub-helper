//go:build windows

package main

import "golang.org/x/sys/windows"

// A place is shown only if it is a folder here now, and a link in a
// listing is looked through to see whether it leads to one: nothing here
// asks the person first, as macOS does (musicplaces_darwin.go).
const musicLookAhead = true

// Nothing here waits on a person's answer to read a folder: a folder this
// account may not read says so at once.
const musicSystemAsks = false

func musicGuardedLinks(string) bool { return false }

func musicHomeMusic(string) string { return musicDefaultDir() }

// musicVolumes: every drive letter in use, from C: on — A: and B: are the
// floppy drives' letters, and asking one that has no disk in it can take a
// while.
func musicVolumes() []musicPlace {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []musicPlace
	for i := 2; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		l := string(rune('A' + i))
		out = append(out, musicPlace{K: "drive", P: l + `:\`, N: l + ":"})
	}
	return out
}
