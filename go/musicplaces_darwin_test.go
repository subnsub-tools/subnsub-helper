//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// What macOS asks about, by name and through links: a folder elsewhere
// linked to Documents is Documents.
func TestMusicGuardedOnMac(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, d := range []string{"Documents", "Songs"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "Documents"), filepath.Join(home, "Docs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Documents", filepath.Join(home, "DocsRel")); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		filepath.Join(home, "Documents", "x"):                   true,
		filepath.Join(home, "Library", "Containers", "com.x"):   true,
		"/System/Volumes/Data" + filepath.Join(home, "Desktop"): true,
		"/Volumes/USB/Music":                                    true,
		filepath.Join(home, "Docs", "x"):                        false,
		filepath.Join(home, "Songs"):                            false,
		"/Volumes":                                              false,
	} {
		if got := musicGuarded(p); got != want {
			t.Errorf("musicGuarded(%q): %v, want %v", p, got, want)
		}
	}
	for p, want := range map[string]bool{
		filepath.Join(home, "Docs", "x"):    true,
		filepath.Join(home, "DocsRel", "x"): true,
		filepath.Join(home, "Songs"):        false,
	} {
		if got := musicGuardedLinks(p); got != want {
			t.Errorf("musicGuardedLinks(%q): %v, want %v", p, got, want)
		}
	}
}
