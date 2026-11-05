//go:build unix && !darwin && !android

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The trash is the freedesktop one the desktops' file managers restore
// from: the thing under files/, a .trashinfo beside it under info/, and a
// name already there never replaced.
func TestFilesTrashIsTheFreedesktopTrash(t *testing.T) {
	f := newWriteFixture(t)
	data := filepath.Join(f.home, "share")
	t.Setenv("XDG_DATA_HOME", data)
	trash := filepath.Join(data, "Trash")
	notes := filepath.Join(f.home, "Documents", "notes.txt")
	if r := f.command(t, f.peer, "trash", map[string]any{"path": notes}); r.Code != 0 {
		t.Fatalf("trash: %+v", r)
	}
	if _, err := os.Lstat(notes); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("still there: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(trash, "files", "notes.txt")); err != nil || string(got) != "content of Documents/notes.txt" {
		t.Fatalf("in the trash: %q %v", got, err)
	}
	info, err := os.ReadFile(filepath.Join(trash, "info", "notes.txt.trashinfo"))
	if err != nil || !strings.HasPrefix(string(info), "[Trash Info]\nPath="+filesTrashPath(notes)+"\nDeletionDate=") {
		t.Fatalf("the info: %q %v", info, err)
	}
	writeFile(t, notes, []byte("again"))
	if r := f.command(t, f.peer, "trash", map[string]any{"path": notes}); r.Code != 0 {
		t.Fatalf("trash again: %+v", r)
	}
	if got, _ := os.ReadFile(filepath.Join(trash, "files", "notes (2).txt")); string(got) != "again" {
		t.Fatalf("the second: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(trash, "files", "notes.txt")); string(got) != "content of Documents/notes.txt" {
		t.Fatalf("the first was replaced: %q", got)
	}
	if _, err := os.Stat(filepath.Join(trash, "info", "notes (2).txt.trashinfo")); err != nil {
		t.Fatalf("the second's info: %v", err)
	}
	if r := f.command(t, f.peer, "trash", map[string]any{"path": filepath.Join(f.home, "Work")}); r.Code != 0 {
		t.Fatalf("a folder: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(trash, "files", "Work", "b", "c", "other.txt")); err != nil {
		t.Fatalf("the folder whole: %v", err)
	}
	for _, c := range []struct{ p, code string }{
		{f.home, "too-broad"},
		{trash, "too-broad"},
		{data, "too-broad"},
		{filepath.Join(f.home, "gone.txt"), "missing"},
		{"relative", "bad-path"},
	} {
		if r := f.command(t, f.peer, "trash", map[string]any{"path": c.p}); r.Error != c.code {
			t.Errorf("trash %s: %+v, want %s", c.p, r, c.code)
		}
	}
	if p := filesTrashPath("/a b/café%.txt"); p != "/a%20b/caf%C3%A9%25.txt" {
		t.Fatalf("a path as the info writes it: %s", p)
	}
}

// What a copy cannot carry — a pipe, a name JSON cannot hold whole — is
// counted for the page, which then knows the tree is not all there.
func TestFilesWalkCountsWhatItCannotCopy(t *testing.T) {
	f := newWriteFixture(t)
	dir := filepath.Join(f.home, "Odd")
	writeFile(t, filepath.Join(dir, "plain.txt"), []byte("x"))
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Skipf("no fifo here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "two\nlines"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	names, _, p := f.walk(t, dir)
	if strings.Join(names, ",") != "Odd/plain.txt" || p.Odd != 2 || p.Why != "" {
		t.Fatalf("the walk: %v %+v", names, p)
	}
}
