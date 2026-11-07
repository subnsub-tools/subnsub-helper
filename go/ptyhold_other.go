//go:build !linux && !darwin && !freebsd

package main

// No pseudo-terminal here (pty_other.go), so no holder either: these keep
// the package compiling.

import (
	"crypto/ed25519"
	"errors"
	"time"
)

func ptyHoldDir() string { return "" }

func runPtyHold(args []string) int { return 2 }

func ptyHoldSpawn(dir, id string, cols, rows int, keep, ceil time.Duration, signer ed25519.PublicKey) error {
	return errors.New("no pseudo-terminal on this platform")
}

func ptyIsShell(name string) bool { return true }
