//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func permOf(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// A part is 0600 until it has its name, whatever the umask; then it has the
// mode a new file gets under the helper's umask, or the mode of the file it
// replaces. A done that gave it that mode and could not name it gives it its
// 0600 back while the person chooses.
func TestFilesPartIsPrivateUntilNamed(t *testing.T) {
	f := newWriteFixture(t)
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		// The umask read as the helper started is the process's own.
		seen := false
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "Umask:"); ok {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 8, 32)
				if err != nil || int(n) != filesUmask {
					t.Fatalf("umask %q, read as %o", v, filesUmask)
				}
				seen = true
			}
		}
		if !seen {
			t.Log("no Umask line in /proc/self/status")
		}
	}
	saved := filesUmask
	t.Cleanup(func() { filesUmask = saved })
	dir := filepath.Join(f.home, "Documents")

	filesUmask = 0o027
	b := f.put(t, map[string]any{"dir": dir, "name": "new.txt", "size": 8})
	pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD")))
	if got := permOf(t, filepath.Join(dir, b.Part)); got != 0o600 {
		t.Fatalf("a part: %o", got)
	}
	pieceHave(f.piece(&f.peer, b.T, 4, []byte("EFGH")))
	if d, code := f.done(t, b.T, nil); code != "" {
		t.Fatalf("done: %q", code)
	} else if got := permOf(t, d.Path); got != 0o640 {
		t.Fatalf("a new file under umask 027: %o", got)
	}

	// Only its owner may read the file replaced, and the one replacing it,
	// all the way: paused half way, and once it has the name.
	filesUmask = 0
	private := filepath.Join(dir, "private.txt")
	writeFile(t, private, []byte("secret"))
	if err := os.Chmod(private, 0o600); err != nil {
		t.Fatal(err)
	}
	r := f.put(t, map[string]any{"dir": dir, "name": "private.txt", "size": 6, "mode": "replace", "k": "private-key-01"})
	pieceHave(f.piece(&f.peer, r.T, 0, []byte("SEC")))
	if got := permOf(t, filepath.Join(dir, r.Part)); got != 0o600 {
		t.Fatalf("a part replacing a 0600 file: %o", got)
	}
	pieceHave(f.piece(&f.peer, r.T, 3, []byte("RET")))
	if d, code := f.done(t, r.T, nil); code != "" || d.Path != private {
		t.Fatalf("done: %+v %q", d, code)
	}
	if got := permOf(t, private); got != 0o600 {
		t.Fatalf("the file replaced: %o", got)
	}
	if c, _ := os.ReadFile(private); string(c) != "SECRET" {
		t.Fatalf("the file replaced: %q", c)
	}

	// The name taken in the instant between done's look and the link: the
	// part is 0600 again, and the next done opens it again to name it.
	savedLink := filesLink
	t.Cleanup(func() { filesLink = savedLink })
	filesLink = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: fs.ErrExist}
	}
	c := f.put(t, map[string]any{"dir": dir, "name": "raced.txt", "size": 4, "mode": "fail"})
	pieceHave(f.piece(&f.peer, c.T, 0, []byte("RACE")))
	if _, code := f.done(t, c.T, nil); code != "exists" {
		t.Fatalf("a name taken at the link: %q", code)
	}
	if got := permOf(t, filepath.Join(dir, c.Part)); got != 0o600 {
		t.Fatalf("the part after a done that could not name it: %o", got)
	}
	filesLink = savedLink
	const m = 1700000000
	d, code := f.done(t, c.T, map[string]any{"mode": "keep", "m": m})
	if code != "" || d.N != "raced.txt" || d.M != m {
		t.Fatalf("done again: %+v %q", d, code)
	}
	if got := permOf(t, d.Path); got != 0o666 {
		t.Fatalf("a new file under umask 0: %o", got)
	}
	if fi, err := os.Stat(d.Path); err != nil || fi.ModTime().Unix() != m {
		t.Fatalf("its time: %v %v", fi, err)
	}
}

// victim is a file a link may lead to, which nothing here may touch.
func victim(t *testing.T, f *filesFixture) (string, func()) {
	t.Helper()
	p := filepath.Join(f.home, "victim.txt")
	writeFile(t, p, []byte("not yours"))
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(1600000000, 0)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p, func() {
		t.Helper()
		fi, err := os.Lstat(p)
		c, _ := os.ReadFile(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || !fi.ModTime().Equal(old) || string(c) != "not yours" {
			t.Fatalf("the file a link led to was touched: %v %v %q", fi, err, c)
		}
		if n, ok := filesLinks(fi); ok && n != 1 {
			t.Fatalf("the file a link led to has %d names", n)
		}
	}
}

// A part swapped for a link by somebody else writing in the same folder is
// never written through and never given the name: done refuses it as often
// as it is asked, and cancel takes the link away, not what it leads to.
func TestFilesPartSwappedForALink(t *testing.T) {
	f := newWriteFixture(t)
	dir := filepath.Join(f.home, "Documents")
	target, untouched := victim(t, f)
	b := f.put(t, map[string]any{"dir": dir, "name": "swapped.txt", "size": 4, "k": "swap-key-0001"})
	pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD")))
	part := filepath.Join(dir, b.Part)
	if err := os.Rename(part, filepath.Join(dir, "aside.part")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, part); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, code := f.done(t, b.T, map[string]any{"m": 1700000000, "mode": "replace"}); code != "unavailable" {
			t.Fatalf("done %d of a part swapped for a link: %q", i, code)
		}
		untouched()
	}
	if _, err := os.Lstat(filepath.Join(dir, "swapped.txt")); err == nil {
		t.Fatal("named")
	}
	if r := f.command(t, f.peer, "cancel", map[string]any{"t": b.T}); r.Code != 0 {
		t.Fatalf("cancel: %+v", r)
	}
	if _, err := os.Lstat(part); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the link: %v", err)
	}
	untouched()
}

// A part found again under its key is gone on with only if it is still a
// file of its own: a link or a second name in its place is let go (the name
// alone) and the part begun again, and one that is not what the look before
// the open saw (swapped between the two) is refused.
func TestFilesPartFoundAgainIsItsOwn(t *testing.T) {
	f := newWriteFixture(t)
	target, untouched := victim(t, f)
	for i, plant := range []func(part string) error{
		func(part string) error { return os.Symlink(target, part) },
		func(part string) error { return os.Link(target, part) },
	} {
		k := fmt.Sprintf("plant-key-%04d", i)
		part := filepath.Join(f.home, filesPartPrefix+k+filesPartSuffix)
		if err := plant(part); err != nil {
			t.Fatal(err)
		}
		b := f.put(t, map[string]any{"dir": f.home, "name": fmt.Sprintf("planted-%d.txt", i), "size": 4, "k": k})
		if b.Have != 0 {
			t.Fatalf("%d: went on with what was planted: %+v", i, b)
		}
		fi, err := os.Lstat(part)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%d: the part begun again: %v %v", i, fi, err)
		}
		pieceHave(f.piece(&f.peer, b.T, 0, []byte("MINE")))
		if d, code := f.done(t, b.T, nil); code != "" {
			t.Fatalf("%d: done: %q", i, code)
		} else if c, _ := os.ReadFile(d.Path); string(c) != "MINE" {
			t.Fatalf("%d: the file: %q", i, c)
		}
		untouched()
	}

	saved := filesPartLstat
	t.Cleanup(func() { filesPartLstat = saved })
	decoy := filepath.Join(f.home, "decoy.part")
	writeFile(t, decoy, nil)
	filesPartLstat = func(string) (os.FileInfo, error) { return os.Lstat(decoy) }
	for i, plant := range []func(part string) error{
		// The open, which follows no link, refuses it.
		func(part string) error { return os.Symlink(target, part) },
		// Another file than the one looked at.
		func(part string) error { return os.WriteFile(part, nil, 0o600) },
	} {
		k := fmt.Sprintf("raced-key-%04d", i)
		if err := plant(filepath.Join(f.home, filesPartPrefix+k+filesPartSuffix)); err != nil {
			t.Fatal(err)
		}
		if r := f.command(t, f.peer, "put", map[string]any{"dir": f.home, "name": "raced.txt", "size": 4, "k": k}); r.Error != "unavailable" {
			t.Fatalf("%d: a part swapped between the look and the open: %+v", i, r)
		}
		untouched()
	}
}

// cancel by key never takes a link away, nor what it leads to.
func TestFilesCancelByKeyLeavesALink(t *testing.T) {
	f := newWriteFixture(t)
	target, untouched := victim(t, f)
	const k = "discard-key-03"
	part := filepath.Join(f.home, filesPartPrefix+k+filesPartSuffix)
	if err := os.Symlink(target, part); err != nil {
		t.Fatal(err)
	}
	if r := f.command(t, f.peer, "cancel", map[string]any{"dir": f.home, "k": k}); r.Error != "unavailable" {
		t.Fatalf("a link under a part's name: %+v", r)
	}
	if fi, err := os.Lstat(part); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("the link: %v %v", fi, err)
	}
	untouched()
}
