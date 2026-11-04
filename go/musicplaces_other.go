//go:build !linux && !darwin && !windows

package main

// A place is shown only if it is a folder here now, and a link in a
// listing is looked through to see whether it leads to one: nothing here
// asks the person first, as macOS does (musicplaces_darwin.go).
const musicLookAhead = true

// Nothing here waits on a person's answer to read a folder: a folder this
// account may not read says so at once.
const musicSystemAsks = false

func musicGuardedLinks(string) bool { return false }

func musicHomeMusic(string) string { return musicDefaultDir() }

// musicVolumes: the whole tree, from which every disk is reached.
func musicVolumes() []musicPlace {
	return []musicPlace{{K: "root", P: "/"}}
}
