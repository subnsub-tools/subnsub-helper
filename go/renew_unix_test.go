//go:build unix

// The FIFO case lives here rather than in renew_test.go because making one is a
// Unix syscall — and because the failure it guards against is a Unix failure:
// open(2) on a FIFO blocks until a writer shows up. Windows has no equivalent
// hang for this path.

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The one that would hang rather than misbehave: os.Open on a FIFO blocks until
// somebody writes, and this runs during startup — before the push loop, before
// the console, with nothing on stderr to explain it.
func TestInstalledEnvDoesNotBlockOnAFifo(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "subnsub-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "token"), 0o600); err != nil {
		t.Skipf("no fifo here: %v", err)
	}
	done := make(chan map[string]string, 1)
	go func() { done <- installedEnv() }()
	select {
	case env := <-done:
		if len(env) != 0 {
			t.Fatalf("read settings out of a fifo: %v", env)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("★ installedEnv blocked on a fifo — a machine would hang at startup")
	}
}
