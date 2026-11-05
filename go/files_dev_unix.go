//go:build unix

package main

import (
	"os"
	"syscall"
)

// filesDev is the filesystem a file is on, as the kernel numbers it: a
// search stays on the disk it began on (files.go).
func filesDev(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}
