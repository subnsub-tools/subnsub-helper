package main

// ptyProgName is the name the kernel holds for a process, or "" — for the
// program in a terminal's foreground (ptyhold_unix.go). procComm is the fork
// reaper's (reaper_darwin.go).
func ptyProgName(pid int) string {
	if pid <= 1 {
		return ""
	}
	return ptyProgClean(procComm(pid))
}
