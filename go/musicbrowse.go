package main

// musicbrowse.go — a page looking through this machine's folders for the one
// with the music in it, where the console is on (music.go: browse, add-dir).
//
// A listing is the folder's own entries and nothing below them: its folders
// by name, how many audio files sit in it, and the first of their names. It is
// read once per question, on a clock — a network mount whose server has gone
// away blocks a directory read for as long as the kernel cares to wait, and
// the command gate (direct.go) is held while a command runs. Nothing is
// listed until somebody opens it on the page, and on macOS nothing beyond
// what was opened is touched (musicLookAhead).

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
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
// kernel. The same question asked again while its look is still under way
// waits on that look rather than starting another, and one asked again soon
// after a look nobody waited out is answered by that look (musicLookKeep).
//
// A look at a folder the system guards (asks; on macOS musicGuardedLinks,
// found out in the look, since a link may lead there) is answered sooner:
// held up for musicAskWait, it is waiting on the person at the machine, whom
// the system is asking whether it may be read, and the page is told so
// ("permission-wait") and asks again; the look itself goes on, and the answer
// it brings is the next one given.
var musicBrowsing atomic.Int32

// musicAskWait: how long a look at a guarded folder may take before it is
// taken to be waiting on the system's question.
const musicAskWait = 1500 * time.Millisecond

// musicLookKeep: how long the answer of a look nobody waited out is kept
// for the question asked again — the page asks again every second or so.
const musicLookKeep = 10 * time.Second

type musicLook struct {
	done   chan struct{}
	asks   atomic.Bool // it reads a guarded folder: a hold-up is the system asking
	v      any
	code   string
	doneAt time.Time // when it finished (under musicLooks); zero while it runs
}

var musicLooks = struct {
	sync.Mutex
	m map[string]*musicLook
}{m: map[string]*musicLook{}}

func musicWithin[T any](wait time.Duration, key string, asks func() bool, look func() (T, string)) (T, string) {
	var zero T
	now := time.Now()
	musicLooks.Lock()
	for k, o := range musicLooks.m {
		if !o.doneAt.IsZero() && now.Sub(o.doneAt) > musicLookKeep {
			delete(musicLooks.m, k)
		}
	}
	l := musicLooks.m[key]
	if l != nil && !l.doneAt.IsZero() {
		// Finished after the last question about it stopped waiting: its
		// answer is this one, once.
		delete(musicLooks.m, key)
		musicLooks.Unlock()
		v, _ := l.v.(T)
		return v, l.code
	}
	if l == nil {
		if musicBrowsing.Add(1) > 4 {
			musicBrowsing.Add(-1)
			musicLooks.Unlock()
			return zero, "timeout"
		}
		l = &musicLook{done: make(chan struct{})}
		musicLooks.m[key] = l
		go func() {
			defer musicBrowsing.Add(-1)
			if asks != nil && asks() {
				l.asks.Store(true)
			}
			v, code := look()
			musicLooks.Lock()
			l.v, l.code, l.doneAt = v, code, time.Now()
			musicLooks.Unlock()
			close(l.done)
		}()
	}
	musicLooks.Unlock()
	clock := time.NewTimer(wait)
	defer clock.Stop()
	var ask <-chan time.Time
	if asks != nil && musicAskWait < wait {
		ask = time.After(musicAskWait)
	}
	for {
		select {
		case <-l.done:
			musicLooks.Lock()
			if musicLooks.m[key] == l {
				delete(musicLooks.m, key)
			}
			musicLooks.Unlock()
			v, _ := l.v.(T)
			return v, l.code
		case <-ask:
			if l.asks.Load() {
				return zero, "permission-wait"
			}
			// Not known yet to be guarded (finding out where a link leads
			// may itself be slow): looked at again shortly.
			ask = time.After(musicAskWait / 6)
		case <-clock.C:
			return zero, "timeout"
		}
	}
}

func musicBrowseWithin(p string, wait time.Duration) (musicBrowseBody, string) {
	return musicWithin(wait, "browse\n"+p, func() bool { return musicGuardedLinks(p) }, func() (musicBrowseBody, string) { return musicBrowse(p) })
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
			if !dir && e.Type()&fs.ModeSymlink != 0 {
				if !musicLookAhead {
					// Where it leads is looked at when it is opened.
					dir = true
				} else if links < musicBrowseLinks {
					links++
					if fi, err := os.Stat(filepath.Join(p, name)); err == nil && fi.IsDir() {
						dir = true
					}
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
	for _, r := range loadMusicConf().Roots {
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

// musicLinksInto says whether p is, or leads through links into, a folder
// named says yes to. Each folder on the way is looked at from the top, a link
// followed by what it says, and nothing inside such a folder is looked at: on
// macOS that look would be what the system asks about. Links lead on eight
// deep at most.
func musicLinksInto(p string, named func(string) bool) bool {
	return musicLinksDepth(p, named, 0)
}

func musicLinksDepth(p string, named func(string) bool, depth int) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	p = filepath.Clean(p)
	if named(p) {
		return true
	}
	if depth >= 8 {
		return false
	}
	sep := string(filepath.Separator)
	vol := filepath.VolumeName(p)
	parts := strings.Split(strings.TrimPrefix(p[len(vol):], sep), sep)
	cur := vol + sep
	for i, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		if named(cur) {
			return true
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return false
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			continue
		}
		to, err := os.Readlink(cur)
		if err != nil {
			return false
		}
		if !filepath.IsAbs(to) {
			to = filepath.Join(filepath.Dir(cur), to)
		}
		return musicLinksDepth(filepath.Join(append([]string{to}, parts[i+1:]...)...), named, depth+1)
	}
	return false
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

// musicPlaces: the Music folder, home and Downloads, then the disks — each
// only if it is a folder here now, except on macOS, where they are named
// without being looked at (musicLookAhead).
func musicPlaces() []musicPlace {
	var out []musicPlace
	seen := map[string]bool{}
	add := func(pl musicPlace) {
		if pl.P == "" || seen[pl.P] {
			return
		}
		if musicLookAhead {
			if fi, err := os.Stat(pl.P); err != nil || !fi.IsDir() {
				return
			}
		}
		seen[pl.P] = true
		out = append(out, pl)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		add(musicPlace{K: "music", P: musicHomeMusic(home)})
		add(musicPlace{K: "home", P: home})
		add(musicPlace{K: "downloads", P: filepath.Join(home, "Downloads")})
	}
	for _, v := range musicVolumes() {
		add(v)
	}
	return out
}
