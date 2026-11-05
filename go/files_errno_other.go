//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package main

// filesErrno: nothing system-specific here; filesWriteErr's words serve.
func filesErrno(error) string { return "" }
