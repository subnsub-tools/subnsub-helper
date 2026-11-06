package main

// Handing this process's place to the binary that just replaced it.
//
// This used to be a bare os.Exit(0) with a comment naming the three service
// managers that would start the successor: systemd's Restart=always, launchd's
// KeepAlive, the Windows task's repetition trigger. That comment described an
// assumption rather than a guarantee, and the assumption fails in a whole
// class of environment this helper is meant for — a machine you cannot reach,
// which is exactly where nobody notices it did not come back.
//
// The environment that proved it: a container whose PID 1 is `tini --
// /pod-daemon`, no /run/systemd/system, no /run/user/$UID, and
// docker-systemctl-replacement (a Python script whose own docstring says "run
// 'systemctl start' ... without a systemd daemon running in the system")
// installed at /usr/bin/systemctl. install.sh asked `command -v systemctl`,
// got yes, wrote a unit with Restart=always and reported success. The shim
// forked the helper and wrote a PID file. Nothing was watching it. The helper
// updated itself, exited as designed, and the machine went quiet for seven
// hours holding a relay seat.
//
// So on Unix the restart stops being someone else's job. See restart_unix.go
// for how, and restart_windows.go for why Windows deliberately keeps the old
// arrangement.

import (
	"errors"
	"os"
	"sync"
)

// The handover is not this platform's to make — the supervisor that starts
// this program is a real one and owns the restart. Not a failure: a platform
// answering that its own arrangement already works.
var errSupervisorOwnsRestart = errors.New("the service manager restarts this helper")

// Where the updater put the new binary, remembered from BEFORE the swap.
//
// os.Executable() cannot be asked afterwards. On Linux it reads
// /proc/self/exe, and the rename that installs the new binary unhashes the
// dentry this process was executed from, so the answer comes back as
// "/path/to/subnsub-helper (deleted)" — a path that cannot be executed. The
// updater holds the right answer at the moment it still means something, and
// says so here rather than leaving the restart to guess.
var (
	installedMu   sync.Mutex
	installedPath string
)

func noteInstalledAt(path string) {
	installedMu.Lock()
	installedPath = path
	installedMu.Unlock()
}

func installedAt() string {
	installedMu.Lock()
	defer installedMu.Unlock()
	return installedPath
}

// Hand this process's place to the version that is already on disk.
//
// Returns only when the handover did NOT happen and this process should carry
// on running the old image. That is the important half of the contract, and it
// is the opposite of what this code used to do: exiting on a machine where
// nothing restarts us is how the original seven hours of silence happened, and
// an exec that failed is a machine in exactly that position. The old image is
// still perfectly good — it is running — so the honest failure is a helper
// that keeps working and updates at the next restart, not one that stops.
//
// Where a real supervisor owns the restart (Windows), it exits instead, which
// is what that supervisor is waiting for.
func restartSelf() {
	self := installedAt()
	if self == "" {
		// Nothing recorded: an exit that is not the tail of a successful
		// update. Whatever this process was executed from is the best answer
		// left, and on this path the dentry is still intact.
		if s, err := os.Executable(); err == nil {
			self = s
		}
	}
	if self == "" {
		warnf("update: cannot work out this program's own path — staying on the running version")
		return
	}
	err := restartInto(self)
	if errors.Is(err, errSupervisorOwnsRestart) {
		os.Exit(0)
	}
	// Said out loud rather than swallowed. On a machine with a real service
	// manager this only costs the update a restart; on a machine without one
	// it is the difference between "quiet because it is updating" and "quiet
	// because it is gone", and the operator reading this log is the only one
	// who can tell them apart.
	warnf("update: could not hand over to the new binary (%v) — "+
		"staying on %s, which is still running; the new one takes over at the next restart",
		err, helperVersion)
}
