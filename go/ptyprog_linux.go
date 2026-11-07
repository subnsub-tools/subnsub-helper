package main

import (
	"os"
	"strconv"
	"strings"
)

// ptyProgName is the name the kernel holds for a process (the executable's
// basename, cut to sixteen bytes), or "" — for the program in a terminal's
// foreground (ptyhold_unix.go).
func ptyProgName(pid int) string {
	if pid <= 1 {
		return ""
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return ptyProgClean(strings.TrimSpace(string(b)))
}
