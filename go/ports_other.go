//go:build !linux && !darwin

package main

// No Ports view here yet: Windows names a port's program (GetExtendedTcpTable)
// but this helper does not ask it, and the BSDs are not looked at.

import "context"

func portsSupported() bool { return false }

func portsScan(context.Context) ([]portProc, string) { return nil, "unsupported" }

func portsProcNow(pid int) (portProc, bool) { return portProc{PID: pid}, false }

func portsPPID(int) int { return 0 }

func portsIconData(path string) (string, []byte, bool) { return portsIconFile(path) }
