//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"io/fs"
	"os"
	"syscall"
	"time"
)

// A part file is reached by its path only to open it, and then without
// following a link somebody else writing in the same folder may have put in
// its place; its final mode and time are set through the descriptor, on the
// file that was written, never on whatever the path names by then
// (fileswrite.go settle).

// filesNoFollow opens a part only if it is not a link.
const filesNoFollow = syscall.O_NOFOLLOW

// filesReopen is how settle opens a part again to give it its mode and time:
// fchmod and futimes take any descriptor of a file one owns, so for reading,
// which a mode without the owner's write bit does not stop.
const filesReopen = os.O_RDONLY

// filesUmask is this process's umask, read once as the package starts,
// before anything of the helper's runs: reading it means setting it, so it
// is set back at once, while nothing here can be making a file.
var filesUmask = func() int {
	m := syscall.Umask(0)
	syscall.Umask(m)
	return m
}()

// filesNewPerm is the mode a new file gets, as creating it under this
// process's umask would give it. A part is made 0600 whatever the umask, so
// that nobody else reads a file before it has its name, and is given this
// (or the mode of the file it replaces) once it has every byte.
func filesNewPerm() fs.FileMode { return 0o666 &^ fs.FileMode(filesUmask) }

// filesSetMode gives the file written its mode through its descriptor. A
// disk that keeps no modes (FAT, exFAT, some network shares) refuses any
// change it cannot show and keeps its own, and the caller lets it.
func filesSetMode(f *os.File, perm fs.FileMode) error { return f.Chmod(perm) }

// filesSetTime gives the file written its modified time through its
// descriptor: futimes(2), which Linux does by the descriptor's own entry in
// /proc, as glibc does. Where that fails the file keeps the time it was
// written at; the path is not used instead, since by then it may lead
// somewhere else.
func filesSetTime(f *os.File, _ string, t time.Time) {
	tv := []syscall.Timeval{syscall.NsecToTimeval(time.Now().UnixNano()), syscall.NsecToTimeval(t.UnixNano())}
	syscall.Futimes(int(f.Fd()), tv)
}

// filesLinks is how many names a file has: a part with more than one is
// not one this helper is writing alone (a link to another file put in its
// place, or a part that was given its name by a helper stopped before it
// let the part's name go).
func filesLinks(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
