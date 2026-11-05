//go:build darwin

package main

// filesGuarded: a folder macOS asks the person about before it is read
// (musicGuarded), by its name alone.
func filesGuarded(p string) bool { return musicGuarded(p) }
