//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// portsPin holds the program ports-end checked until it is signalled: a
// pidfd, which keeps naming that one program even once its pid is reused.
// Kernels before 5.3 (some Androids) have none; there the pid is checked
// again just before the signal (exact false).
type portsPin struct{ pid, fd int }

func portsPinOpen(pid int) (*portsPin, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		return &portsPin{pid: pid, fd: fd}, nil
	}
	if errors.Is(err, unix.ESRCH) {
		return nil, errPortsGone
	}
	return &portsPin{pid: pid, fd: -1}, nil
}

func (k *portsPin) exact() bool { return k.fd >= 0 }

// signal: SIGTERM, or SIGKILL when forced. errPortsGone when it has ended
// meanwhile; EPERM comes back as os.ErrPermission (errors.Is).
func (k *portsPin) signal(force bool) error {
	sig := unix.SIGTERM
	if force {
		sig = unix.SIGKILL
	}
	var err error
	if k.fd >= 0 {
		err = unix.PidfdSendSignal(k.fd, sig, nil, 0)
	} else {
		err = unix.Kill(k.pid, sig)
	}
	if errors.Is(err, unix.ESRCH) {
		return errPortsGone
	}
	return err
}

func (k *portsPin) close() {
	if k.fd >= 0 {
		unix.Close(k.fd)
	}
}
