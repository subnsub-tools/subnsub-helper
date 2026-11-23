package main

import "syscall"

// hpOwnDisplayHere is whether this Mac is asked for a display of the
// session's own: a Mac with Apple silicon. Screen Sharing's own window offers
// one to no other Mac, and an Intel Mac asked all the same does not make a
// display: it adds the size asked for to the modes of the display it has and
// stays in it after the session (seen 2026-11-23, a 2018 Mac mini with no
// monitor, macOS 15.7.9: its screen was left at 1100x700, the size of a
// window of the day before, and was 1280x1024 before that). The name is one
// Intel Macs do not have.
func hpOwnDisplayHere() bool {
	v, err := syscall.SysctlUint32("hw.optional.arm64")
	return err == nil && v == 1
}
