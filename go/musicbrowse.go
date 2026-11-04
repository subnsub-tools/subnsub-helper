package main

// musicbrowse.go — a page looking through this machine's folders for the one
// with the music in it, where the console is on (music.go: browse, add-dir).
//
// A listing is the folder's own entries and nothing below them: its folders
// by name, how many audio files sit in it, and the first of their names. It is
// read once per question, on a clock — a network mount whose server has gone
// away blocks a directory read for as long as the kernel cares to wait, and
// the command gate (direct.go) is held while a command runs.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	musicBrowseWait = 15 * time.Second
	// What one listing carries at most: a result crosses the tunnel in one
	// frame (transport.Limits), and a folder with a hundred thousand others
	// in it is not browsed by reading every name.
	musicBrowseDirs  = 1500
	musicBrowseBytes = 96 << 10
	musicBrowseNames = 40
	// Links are looked through to see whether they lead to a folder, a stat
	// each, up to this many in one listing.
	musicBrowseLinks = 256
	// Entries read from one folder at most, in batches: a folder with a
	// million files in it is not held in memory to show a page of names.
	musicBrowseEntries = 20000
	musicBrowseBatch   = 512
)

// musicPlace is somewhere to begin: the account's own folders, then the
// disks.
type musicPlace struct {
	K string `json:"k"`           // music | home | downloads | root | volume | drive
	P string `json:"p"`           // the folder
	N string `json:"n,omitempty"` // a disk's own name
}

type musicBrowseBody struct {
	Path   string       `json:"path"`             // "" for the places
	Parent string       `json:"parent,omitempty"` // "" at the top of a disk: up is the places
	Sep    string       `json:"sep"`
	Places []musicPlace `json:"places,omitempty"`
	Dirs   []string     `json:"dirs"`
	More   bool         `json:"more,omitempty"` // more folders than are listed
	Audio  int          `json:"audio"`          // audio files right in it
	Names  []string     `json:"names,omitempty"`
	// The root this folder is, or is inside: sharing it again would list
	// its tracks twice.
	Shared string `json:"shared,omitempty"`
}

// musicWithin is a look at the disks on a clock: a listing, or the checks
// on a folder a page asks to share. The look goes on in the background if the
// clock runs out: there is no taking back a blocked read. A few of those may
// be left waiting on a disk that went away, and no more: past that, a
// question is answered at once rather than with one more thread stuck in the
// kernel.
var musicBrowsing atomic.Int32

func musicWithin[T any](wait time.Duration, look func() (T, string)) (T, string) {
	var zero T
	if musicBrowsing.Add(1) > 4 {
		musicBrowsing.Add(-1)
		return zero, "timeout"
	}
	type answer struct {
		v    T
		code string
	}
	ch := make(chan answer, 1)
	go func() {
		defer musicBrowsing.Add(-1)
		v, code := look()
		ch <- answer{v, code}
	}()
	select {
	case a := <-ch:
		return a.v, a.code
	case <-time.After(wait):
		return zero, "timeout"
	}
}

func musicBrowseWithin(p string, wait time.Duration) (musicBrowseBody, string) {
	return musicWithin(wait, func() (musicBrowseBody, string) { return musicBrowse(p) })
}

func musicBrowse(raw string) (musicBrowseBody, string) {
	b := musicBrowseBody{Sep: string(filepath.Separator), Dirs: []string{}}
	if raw == "" {
		b.Places = musicPlaces()
		return b, ""
	}
	p, code := musicPathArg(raw)
	if code != "" {
		return b, code
	}
	f, err := os.Open(p)
	if err != nil {
		return b, musicFolderErr(p, err)
	}
	defer f.Close()
	used, links, seen := 0, 0, 0
	for {
		ents, err := f.ReadDir(musicBrowseBatch)
		if err != nil && seen == 0 && len(ents) == 0 && err != io.EOF {
			return b, musicFolderErr(p, err)
		}
		for _, e := range ents {
			seen++
			name := e.Name()
			if !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\n\r") {
				continue
			}
			dir := e.IsDir()
			if !dir && e.Type()&fs.ModeSymlink != 0 && links < musicBrowseLinks {
				links++
				if fi, err := os.Stat(filepath.Join(p, name)); err == nil && fi.IsDir() {
					dir = true
				}
			}
			if dir {
				if musicSkipDir(name) {
					continue
				}
				if len(b.Dirs) >= musicBrowseDirs || used+len(name) > musicBrowseBytes {
					b.More = true
					continue
				}
				used += len(name) + 3
				b.Dirs = append(b.Dirs, name)
				continue
			}
			if e.Type().IsRegular() && musicMime(name) != "" {
				b.Audio++
				if len(b.Names) < musicBrowseNames {
					b.Names = append(b.Names, name)
				}
			}
		}
		if err != nil {
			break
		}
		if seen >= musicBrowseEntries {
			b.More = true
			break
		}
	}
	b.Path = p
	if up := filepath.Dir(p); up != p {
		b.Parent = up
	}
	sort.SliceStable(b.Dirs, func(i, j int) bool { return strings.ToLower(b.Dirs[i]) < strings.ToLower(b.Dirs[j]) })
	sort.SliceStable(b.Names, func(i, j int) bool { return strings.ToLower(b.Names[i]) < strings.ToLower(b.Names[j]) })
	// Shared as the walk sees it: a folder reached through a link inside a
	// shared one is not walked from there (musicWalkDir), so it is not
	// shared by it; a shared folder that is itself a link is walked where
	// it leads.
	real := musicReal(p)
	for _, r := range musicRoots(loadMusicConf()) {
		if r.Kind == "dir" && musicPathWithin(real, musicReal(r.Path)) {
			b.Shared = r.ID
			break
		}
	}
	return b, ""
}

// musicReal is a folder as the walk reaches it: its links resolved. One that
// cannot be resolved now is taken as named.
func musicReal(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// musicPathArg is a folder named by a page: absolute, clean, valid text.
func musicPathArg(raw string) (string, string) {
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\n\r") || !filepath.IsAbs(raw) {
		return "", "bad-path"
	}
	return filepath.Clean(raw), ""
}

// musicDirArg is a folder a page asks to share: one that is there, and not
// the whole system, by its name or by where a link leads. It is the folder
// as named, and as the walk reaches it.
func musicDirArg(raw string) (string, string, string) {
	p, code := musicPathArg(raw)
	if code != "" {
		return "", "", code
	}
	if musicDirTooBroad(p) {
		return "", "", "too-broad"
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", "", musicFolderErr(p, err)
	}
	if !fi.IsDir() {
		return "", "", "not-a-folder"
	}
	real := musicReal(p)
	if musicDirTooBroad(real) {
		return "", "", "too-broad"
	}
	return p, real, ""
}

// musicDirTooBroad: the root of a Unix system, and the trees the kernel makes
// up as they are read. A walk of those would never be about music. A drive
// on Windows is a disk somebody may well keep nothing but music on.
func musicDirTooBroad(p string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if p == "/" {
		return true
	}
	for _, pre := range []string{"/proc", "/sys", "/dev"} {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// musicPathWithin says whether p is dir or inside it.
func musicPathWithin(p, dir string) bool {
	if p == dir {
		return true
	}
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func musicFolderErr(p string, err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "missing"
	case errors.Is(err, fs.ErrPermission):
		return "no-access"
	}
	if fi, e := os.Stat(p); e == nil && !fi.IsDir() {
		return "not-a-folder"
	}
	return "unavailable"
}

// musicPlaces: the Music folder, home and Downloads, then the disks, each
// only if it is a folder here now.
func musicPlaces() []musicPlace {
	var out []musicPlace
	seen := map[string]bool{}
	add := func(pl musicPlace) {
		if pl.P == "" || seen[pl.P] {
			return
		}
		if fi, err := os.Stat(pl.P); err != nil || !fi.IsDir() {
			return
		}
		seen[pl.P] = true
		out = append(out, pl)
	}
	add(musicPlace{K: "music", P: musicDefaultCached()})
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		add(musicPlace{K: "home", P: home})
		add(musicPlace{K: "downloads", P: filepath.Join(home, "Downloads")})
	}
	for _, v := range musicVolumes() {
		add(v)
	}
	return out
}
