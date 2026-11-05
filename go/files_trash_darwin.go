//go:build darwin

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// filesTrash puts p in the user's own trash, ~/.Trash, where the Finder
// shows it and it can be dragged back out (the Finder's Put Back, which reads
// a record only the Finder writes, is not offered for what arrives this way).
// A name already in the trash takes the next free one, looked at first:
// rename(2) would replace what is there, and the trash is the one place a
// thing must never be lost from. A thing on another disk is not moved across
// (that disk's own .Trashes is the Finder's to keep): trash-unavailable.
func filesTrash(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "trash-unavailable"
	}
	bin := filepath.Join(home, ".Trash")
	if musicPathWithin(bin, p) {
		return "too-broad"
	}
	if fi, err := os.Lstat(bin); err != nil {
		if !errors.Is(err, fs.ErrNotExist) || os.Mkdir(bin, 0o700) != nil {
			return "trash-unavailable"
		}
	} else if !fi.IsDir() {
		return "trash-unavailable"
	}
	name := filepath.Base(p)
	for i := 1; i <= filesKeepMax; i++ {
		cand := name
		if i > 1 {
			cand = filesNumbered(name, i, filesNameMax)
		}
		dst := filepath.Join(bin, cand)
		if _, err := os.Lstat(dst); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			// The trash may not be looked into (the system guards it): no
			// way to be sure nothing of that name is there.
			return "trash-unavailable"
		}
		if err := os.Rename(p, dst); err != nil {
			code := filesWriteErr(err)
			if code == "cross-device" {
				return "trash-unavailable"
			}
			return code
		}
		return ""
	}
	return "trash-unavailable"
}
