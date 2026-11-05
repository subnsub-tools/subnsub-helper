//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

import (
	"io/fs"
	"os"
	"time"
)

// The systems no helper is built for (the other Unixes, Plan 9): a part is
// opened as named, the look before (os.SameFile, filesPartAgain) and the look
// at the part's name before it is given away (fileswrite.go settle) are the
// guard, and the file keeps its part's 0600.
const filesNoFollow = 0

const filesReopen = os.O_RDONLY

func filesNewPerm() fs.FileMode { return 0o600 }

func filesSetMode(*os.File, fs.FileMode) error { return nil }

// filesSetTime sets the modified time by the path: nothing here takes the
// descriptor.
func filesSetTime(_ *os.File, path string, t time.Time) { os.Chtimes(path, time.Now(), t) }

func filesLinks(os.FileInfo) (uint64, bool) { return 0, false }
