//go:build windows

package main

import (
	"errors"
	"syscall"
)

// filesErrno is what a change's failure means in the page's words, for the
// Win32 errors that have one; "" for the rest (filesWriteErr).
func filesErrno(err error) string {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return ""
	}
	switch e {
	case 39, 112: // ERROR_HANDLE_DISK_FULL, ERROR_DISK_FULL
		return "no-space"
	case 17: // ERROR_NOT_SAME_DEVICE
		return "cross-device"
	case 19: // ERROR_WRITE_PROTECT
		return "read-only"
	case 206: // ERROR_FILENAME_EXCED_RANGE
		return "bad-name"
	case 145, 183: // ERROR_DIR_NOT_EMPTY, ERROR_ALREADY_EXISTS
		return "exists"
	}
	return ""
}
