//go:build !linux && !darwin

package main

// No way to name a process here that is worth its cost: the session is
// listed without its program.
func ptyProgName(pid int) string { return "" }
