package main

// photosbrowse.go — a page looking through this machine's folders for the
// ones with the photos in, where the console is on (photos.go: browse, add).
//
// As musicBrowse, with one thing more: each folder listed says how many
// pictures are in it and in the folders inside it, counted on a budget — a
// few seconds and some tens of thousands of entries for the whole listing,
// on the disk the folder is on (a mount inside is not counted into). What
// the budget did not reach is said to be not counted, never to be empty. The
// places are named and not counted: on macOS a count would be a read of a
// guarded folder nobody opened.

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	photosCountTime    = 3 * time.Second
	photosCountEntries = 60000
)

type photosDirView struct {
	N    string `json:"n"`
	Pics int    `json:"pics"`
	// Pm: there are more than Pics, the count stopped there. U: not
	// counted at all.
	Pm bool `json:"pm,omitempty"`
	U  bool `json:"u,omitempty"`
}

type photosBrowseBody struct {
	Path   string          `json:"path"`
	Parent string          `json:"parent,omitempty"`
	Sep    string          `json:"sep"`
	Places []musicPlace    `json:"places,omitempty"`
	Dirs   []photosDirView `json:"dirs"`
	More   bool            `json:"more,omitempty"`
	// The pictures in it and in the folders inside it, as counted; Pm:
	// at least that many, some of it was not counted.
	Pics int  `json:"pics"`
	Pm   bool `json:"pm,omitempty"`
	// Right in it, and the first of their names.
	Here  int      `json:"here"`
	Names []string `json:"names,omitempty"`
	// The folder shown that this one is, or is inside.
	Shown string `json:"shown,omitempty"`
}

func photosBrowseWithin(p string, wait time.Duration) (photosBrowseBody, string) {
	return musicWithin(wait, "photos-browse\n"+p, func() bool { return musicGuardedLinks(p) }, func() (photosBrowseBody, string) { return photosBrowse(p) })
}

func photosBrowse(raw string) (photosBrowseBody, string) {
	b := photosBrowseBody{Sep: string(filepath.Separator), Dirs: []photosDirView{}}
	if raw == "" {
		b.Places = photosPlaces()
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
	var top os.FileInfo
	if fi, err := f.Stat(); err == nil {
		top = fi
	}
	used, links, seen := 0, 0, 0
	type sub struct {
		name string
		link bool
	}
	var subs []sub
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
			dir, link := e.IsDir(), false
			if !dir && e.Type()&fs.ModeSymlink != 0 {
				link = true
				if !musicLookAhead {
					dir = true
				} else if links < musicBrowseLinks {
					links++
					if fi, err := os.Stat(filepath.Join(p, name)); err == nil && fi.IsDir() {
						dir = true
					}
				}
			}
			if dir {
				if photosSkipDir(name, filepath.Join(p, name)) {
					continue
				}
				if len(subs) >= musicBrowseDirs || used+len(name) > musicBrowseBytes {
					b.More = true
					continue
				}
				used += len(name) + 24
				subs = append(subs, sub{name, link})
				continue
			}
			if e.Type().IsRegular() && photosIsPic(name) {
				b.Here++
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
	sort.SliceStable(subs, func(i, j int) bool { return strings.ToLower(subs[i].name) < strings.ToLower(subs[j].name) })
	sort.SliceStable(b.Names, func(i, j int) bool { return strings.ToLower(b.Names[i]) < strings.ToLower(b.Names[j]) })
	cnt := &photosCounter{until: time.Now().Add(photosCountTime), left: photosCountEntries}
	if top != nil {
		cnt.dev, cnt.devOK = filesDev(top)
	}
	b.Pics = b.Here
	broad := musicDirTooBroad(p)
	for _, s := range subs {
		v := photosDirView{N: s.name, U: true}
		if !s.link && !broad {
			v.Pics, v.Pm, v.U = cnt.count(filepath.Join(p, s.name))
		}
		b.Dirs = append(b.Dirs, v)
		b.Pics += v.Pics
		b.Pm = b.Pm || v.Pm || v.U
	}
	b.Pm = b.Pm || b.More
	real := musicReal(p)
	for _, r := range loadPhotosConf().Roots {
		if musicPathWithin(real, musicReal(r.Path)) {
			b.Shown = r.ID
			break
		}
	}
	return b, ""
}

// photosCounter counts the pictures under folders, on one budget.
type photosCounter struct {
	until time.Time
	left  int
	dev   uint64
	devOK bool
}

// count is how many pictures are in dir and the folders inside it; more
// when it stopped before the end, none when it could not begin.
func (c *photosCounter) count(dir string) (n int, more, none bool) {
	if c.left <= 0 || time.Now().After(c.until) {
		return 0, false, true
	}
	if c.devOK {
		if fi, err := os.Stat(dir); err != nil {
			return 0, false, true
		} else if d, ok := filesDev(fi); ok && d != c.dev {
			return 0, false, true
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, false, true
	}
	defer root.Close()
	stopped := false
	fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		c.left--
		if c.left <= 0 || (c.left%256 == 0 && time.Now().After(c.until)) {
			stopped = true
			return fs.SkipAll
		}
		if err != nil {
			if d != nil && d.IsDir() && p != "." {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != "." && (photosSkipDir(d.Name(), filepath.Join(dir, filepath.FromSlash(p))) || strings.Count(p, "/") >= photosDepthMax) {
				return fs.SkipDir
			}
			if c.devOK && p != "." {
				if fi, err := d.Info(); err == nil {
					if dv, ok := filesDev(fi); ok && dv != c.dev {
						return fs.SkipDir
					}
				}
			}
			return nil
		}
		if d.Type().IsRegular() && photosIsPic(d.Name()) {
			n++
		}
		return nil
	})
	return n, stopped, false
}

// photosPlaces: Pictures, Desktop, home and Downloads, then the disks —
// named, and on macOS not looked at (musicLookAhead).
func photosPlaces() []musicPlace {
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
		add(musicPlace{K: "pictures", P: photosPicturesDir(home)})
		add(musicPlace{K: "desktop", P: photosDesktopDir(home)})
		add(musicPlace{K: "home", P: home})
		add(musicPlace{K: "downloads", P: filepath.Join(home, "Downloads")})
	}
	for _, v := range musicVolumes() {
		add(v)
	}
	return out
}
