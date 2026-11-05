//go:build !unix

package main

import "os"

// filesDev: not known here, so a search does not judge disks by it.
func filesDev(os.FileInfo) (uint64, bool) { return 0, false }
