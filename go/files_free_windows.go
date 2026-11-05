//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// filesFree is the room a put may use on dir's volume: the free space this
// user may take, which a quota makes smaller than the volume's
// (GetDiskFreeSpaceExW's first answer; system_windows.go loads it).
func filesFree(dir string) (uint64, bool) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil || !winReady(procGetDiskFreeSpaceExW) {
		return 0, false
	}
	var availToCaller, total, totalFree uint64
	r, _, _ := syscall.SyscallN(procGetDiskFreeSpaceExW.Addr(),
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&availToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return 0, false
	}
	return availToCaller, true
}
