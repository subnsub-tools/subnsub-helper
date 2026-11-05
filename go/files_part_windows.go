//go:build windows

package main

import (
	"io/fs"
	"os"
	"syscall"
	"time"
)

// No O_NOFOLLOW on Windows, where a link is made only by those allowed to:
// a part is opened as named, and what is opened is checked against the look
// before it (os.SameFile, filesPartAgain) and against the part's name before
// that name is given away (fileswrite.go settle).
const filesNoFollow = 0

// filesReopen is how settle opens a part again to give it its time: a handle
// that may write the file, which SetFileTime takes.
const filesReopen = os.O_WRONLY

// The mode bits are not who may read a file on Windows: a part and the file
// it becomes take what the folder hands down, and no umask applies.
func filesNewPerm() fs.FileMode { return 0o666 }

func filesSetMode(*os.File, fs.FileMode) error { return nil }

// filesSetTime sets the modified time on the open file's handle
// (SetFileTime, what os.Chtimes does once it has opened the path), not on
// whatever the path names by then. Every part is open for writing when this
// runs, which is what changing a file's times takes; where it fails the
// file keeps the time it was written at.
func filesSetTime(f *os.File, _ string, t time.Time) {
	w := syscall.NsecToFiletime(t.UnixNano())
	syscall.SetFileTime(syscall.Handle(f.Fd()), nil, nil, &w)
}

// filesLinks: a second name is not looked for here.
func filesLinks(os.FileInfo) (uint64, bool) { return 0, false }
