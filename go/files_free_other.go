//go:build !linux && !darwin && !windows

package main

// filesFree: unknown here (system_other.go says why this build measures no
// filesystem), so a put is not refused for room; the disk says so itself
// when it is full (no-space).
func filesFree(string) (uint64, bool) { return 0, false }
