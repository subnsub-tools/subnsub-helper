//go:build windows

package main

import "golang.org/x/sys/windows"

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
