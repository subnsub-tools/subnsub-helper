//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"syscall"
)

// filesErrno is what a change's failure means in the page's words, for the
// failures the system names by number; "" for the rest (filesWriteErr).
func filesErrno(err error) string {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return ""
	}
	switch e {
	case syscall.ENOSPC, syscall.EDQUOT:
		return "no-space"
	case syscall.EXDEV:
		return "cross-device"
	case syscall.EROFS:
		return "read-only"
	case syscall.ENAMETOOLONG:
		return "bad-name"
	case syscall.ENOTEMPTY, syscall.EEXIST:
		return "exists"
	}
	return ""
}
