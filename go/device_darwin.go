package main

import (
	"strings"
	"syscall"
	"time"
)

const macSystemProfiler = "/usr/sbin/system_profiler"

// A Mac names itself: system_profiler prints the model ("Mac mini", "MacBook
// Pro") beside the identifier. -detailLevel mini leaves the serial number and
// the hardware UUID out of what it prints, and parseSPHardware would not keep
// them if it did. hw.model is the identifier alone, read without a process,
// and is what the model is worked out from when system_profiler is missing
// or slow.
func readDevice() Device {
	id, _ := syscall.Sysctl("hw.model")
	id = strings.TrimSpace(id)
	name, spID := parseSPHardware(runMacTool(macSystemProfiler,
		[]string{"-json", "-detailLevel", "mini", "SPHardwareDataType"}, 8*time.Second, false))
	if id == "" {
		id = spID
	}
	return macDevice(name, id)
}
