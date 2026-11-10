package main

import "path/filepath"

// The account's Pictures and Desktop, named and not looked at: on macOS a
// look is what the system asks about (musicLookAhead).
func photosPicturesDir(home string) string { return filepath.Join(home, "Pictures") }
func photosDesktopDir(home string) string  { return filepath.Join(home, "Desktop") }
