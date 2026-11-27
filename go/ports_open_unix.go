//go:build unix

package main

import (
	"os"
	"syscall"
)

// portsOpenRegular opens a file only when it is a regular one: without
// waiting (a FIFO named like a .desktop entry or an icon would hold the
// command gate) and checked on what was opened, not on the name.
func portsOpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}
