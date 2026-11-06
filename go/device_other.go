//go:build !linux && !darwin

package main

import (
	"os"
	"runtime"
)

// Nothing here reads the hardware: the BSDs keep it behind kenv and a sysctl
// this build cannot parse (system_other.go says why), and Windows is not a
// published target. The one thing worth saying is TrueNAS CORE, which is
// FreeBSD with its middleware's client on disk.
func readDevice() Device {
	if runtime.GOOS == "freebsd" {
		if _, err := os.Stat("/usr/local/bin/midclt"); err == nil {
			return Device{Form: formNAS, OS: "TrueNAS"}
		}
	}
	return Device{}
}
