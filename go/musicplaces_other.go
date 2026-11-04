//go:build !linux && !darwin && !windows

package main

// musicVolumes: the whole tree, from which every disk is reached.
func musicVolumes() []musicPlace {
	return []musicPlace{{K: "root", P: "/"}}
}
