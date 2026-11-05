//go:build !darwin

package main

// filesGuarded: nothing here waits on a person's answer to read a folder.
func filesGuarded(string) bool { return false }
