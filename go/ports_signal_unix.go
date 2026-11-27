//go:build unix && !linux

package main

import (
	"errors"
	"syscall"
)

// portsPin on a system without pidfds: the pid, checked again just before
// the signal (ports.go portsEnd). On macOS the check is the start time to
// the microsecond (ports_darwin.go macStart), and pids are handed out in
// turn, so the one checked is the one signalled.
type portsPin struct{ pid int }

func portsPinOpen(pid int) (*portsPin, error) { return &portsPin{pid: pid}, nil }

func (k *portsPin) exact() bool { return false }

func (k *portsPin) signal(force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	err := syscall.Kill(k.pid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return errPortsGone
	}
	return err
}

func (k *portsPin) close() {}
