//go:build unix && !darwin && !android

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// filesTrash puts p in the user's trash as the freedesktop.org Trash
// specification lays it out, the one the desktops' file managers show and
// restore from: $XDG_DATA_HOME/Trash (~/.local/share/Trash when unset), the
// thing itself under files/, and beside it under info/ a .trashinfo naming
// where it came from and when. The info file is made first and exclusively,
// which is the specification's way of claiming a name in the trash, and the
// name is also looked at under files/: rename(2) would replace what is
// there. A thing on another disk is not copied across (that disk's own
// .Trash-$uid is not looked for): trash-unavailable, and nothing changes.
func filesTrash(p string) string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "trash-unavailable"
		}
		base = filepath.Join(home, ".local", "share")
	}
	trash := filepath.Join(base, "Trash")
	if musicPathWithin(trash, p) {
		return "too-broad"
	}
	files, info := filepath.Join(trash, "files"), filepath.Join(trash, "info")
	for _, d := range []string{files, info} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "trash-unavailable"
		}
	}
	name := filepath.Base(p)
	const ext = ".trashinfo"
	for i := 1; i <= filesKeepMax; i++ {
		cand := name
		if i > 1 || len(cand)+len(ext) > filesNameMax {
			cand = filesNumbered(name, i, filesNameMax-len(ext))
		}
		if _, err := os.Lstat(filepath.Join(files, cand)); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "trash-unavailable"
		}
		ip := filepath.Join(info, cand+ext)
		f, err := os.OpenFile(ip, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "trash-unavailable"
		}
		_, werr := f.WriteString("[Trash Info]\nPath=" + filesTrashPath(p) + "\nDeletionDate=" + time.Now().Format("2006-01-02T15:04:05") + "\n")
		cerr := f.Close()
		if werr != nil || cerr != nil {
			os.Remove(ip)
			return "trash-unavailable"
		}
		if err := os.Rename(p, filepath.Join(files, cand)); err != nil {
			os.Remove(ip)
			code := filesWriteErr(err)
			if code == "cross-device" {
				return "trash-unavailable"
			}
			return code
		}
		return ""
	}
	return "trash-unavailable"
}

// filesTrashPath is an absolute path as a .trashinfo writes it: URL-escaped
// as RFC 2396 escapes, the slashes left as they are.
func filesTrashPath(p string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("-_.!~*'()/", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		}
	}
	return b.String()
}
