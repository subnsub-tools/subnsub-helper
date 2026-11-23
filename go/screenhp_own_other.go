//go:build !darwin

package main

// hpOwnDisplayHere: elsewhere the stream is only offered for a test against
// a server that speaks the protocol (MON_SCREEN_HP=on), which makes the
// display.
func hpOwnDisplayHere() bool { return true }
