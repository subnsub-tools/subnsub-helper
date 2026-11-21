//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A pipe named index.html is not opened: its open would wait for a writer,
// and the list with it.
func TestServeLookSkipsPipes(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "index.html"), 0o644); err != nil {
		t.Skip("no pipes here:", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cover.png"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan serveItem, 1)
	go func() {
		var s serveItem
		serveLook(dir, &s)
		done <- s
	}()
	select {
	case s := <-done:
		if s.Index || s.Thumb != filepath.Join(dir, "cover.png") {
			t.Errorf("look: %+v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the look waited on the pipe")
	}
}
