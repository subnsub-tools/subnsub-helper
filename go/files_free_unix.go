//go:build linux || darwin

package main

import "syscall"

// filesFree is the room a put may use in dir's filesystem: what this user
// may still write there (f_bavail, the reserve for root left out, as
// statfsUsage counts it). ok is false where the system does not say.
func filesFree(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	bs := fsBlockSize(&st)
	if bs <= 0 {
		return 0, false
	}
	return uint64(float64(st.Bavail) * bs), true
}
