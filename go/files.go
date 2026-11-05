package main

// files.go — the Files tab looking through this machine's disks: a folder's
// listing, a search by name across the places, and a file read a piece at a
// time (index.html's Files panel, through monitor.js MonitorFiles).
//
// WHO MAY. A machine whose console is on has already granted arbitrary
// /bin/sh as this user, so reading its files is no new power (user
// 2026-11-04: every machine whose helper allows remote commands should be
// able to look at the files on its disks). The gate is the console's: a
// pinned dashboard key, the console switch, and the tunnel alone — the
// relay's mailbox refuses the kind
// (mailboxRefusal), as it refuses a shell line. A portable copy is refused:
// its certificate grants what it names, and it names nothing of this.
//
// WHAT THE SIGNATURE BUYS. Each look is a signed command, as the music
// player's browse is. A search and a file are long things — a walk that runs
// for a minute, a file read four megabytes at a time — so their commands
// answer with a token instead: 128 random bits, good only on the tunnel of
// the peer that asked, and only while the console stays on, that peer's key
// stays on the allowlist and the dashboard key that signed the command stays
// pinned here. The reads that follow (/v1/files/search,
// /v1/files/file) carry the token and are not signed one by one, as a
// terminal's keystrokes are not (pty.go).
//
// THE SEARCH is a walk done when it is asked for, nothing kept between (user
// 2026-11-05: walked when asked, the results shown as they are found).
// Breadth first, home before the rest, so what a person keeps comes before
// what the system does; a name matches
// when it holds every word of the question, or, with * or ?, when it fits
// the pattern — case aside either way. It stays on the disk it began on
// where the system can say which that is (Linux: the other disks are walked
// as their own places, and the kernel's made-up trees and network mounts are
// not disks), does not follow links, and does not go into hidden folders or
// a package's insides. It stops at filesSearchHits hits, after
// filesSearchTime, or once nobody has asked for its results for
// filesSearchIdle; one per peer, a new question ending the old one.
//
// THE WALK is the search's twin for a copy: the whole tree under one
// folder, every entry, so a folder brought to another computer arrives as
// it was — hidden files and folders and a package's insides included (a
// project without its .git would be a loss nobody sees). It still never
// follows a link (a link is named, as one, for the page to make again),
// stays on the folder's own disk, and leaves the kernel's made-up trees
// alone. It is told apart from a search so that typing a question never
// ends a copy under way: its own limits (filesWalkHits, filesWalkTime), its
// own count per browser, and a search does not end it.
//
// What the page writes (a file coming in, a folder, a name, a move, the
// trash) is fileswrite.go.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	filesListWait = 15 * time.Second
	// What one listing carries at most: the result crosses the tunnel in one
	// frame (transport.Limits), its JSON quoted once more inside the result.
	filesListShown   = 2000
	filesListBytes   = 96 << 10
	filesListEntries = 20000
	filesListBatch   = 512

	filesSearchTime  = 90 * time.Second
	filesSearchHits  = 1000
	filesSearchIdle  = 30 * time.Second
	filesSearchKeep  = 2 * time.Minute
	filesSearchPage  = 400
	filesSearchWait  = 2 * time.Second
	filesSearchQueue = 200000
	filesSearchDir   = 200000
	filesSearchJobs  = 4
	// A question: a few words, or one pattern.
	filesQueryMax = 200
	filesTermsMax = 8
	// Folders the system holds up asking the person at the machine (macOS):
	// how long the walk waits on one before it goes on without it, and how
	// many such reads may be left waiting at once.
	filesAskWait  = 2 * time.Second
	filesAskStuck = 8

	filesReadMax  = 4 << 20
	filesOpenKeep = 10 * time.Minute
	filesOpenMax  = 64

	// A walk (a whole tree, for a copy): every entry, at most this many — a
	// tree cut short is one the page will not copy — and for this long. Two
	// at once per browser, four on the helper.
	filesWalkHits    = 100000
	filesWalkTime    = 5 * time.Minute
	filesWalkPerPeer = 2
	filesWalkJobs    = 4
	filesWalkPage    = 2000
	// A page of hits as it crosses the tunnel: under the module's ceiling for
	// one answer (tailcat-web maxBytesBody), with room to spare, and room in
	// that for the page's own fields (the folders the system held up).
	filesPageBytes = 1 << 20
	filesPageSlack = 64 << 10
)

// filesWalkLimit is filesWalkHits, a variable so a test can see a walk cut
// at its limit without making a hundred thousand files.
var filesWalkLimit = filesWalkHits

// filesOn: what makes this machine's files the Files tab's to read.
func filesOn() bool { return consoleEnabled() && loadTrust().sealed }

func filesToken() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

// ── the listing ─────────────────────────────────────────────────────────

type filesDirEntry struct {
	N string `json:"n"`
	M int64  `json:"m,omitempty"` // modified, Unix seconds
	L bool   `json:"l,omitempty"` // a link, not looked through
}

type filesFileEntry struct {
	N string `json:"n"`
	S int64  `json:"s"`
	M int64  `json:"m,omitempty"`
}

type filesListBody struct {
	Path   string           `json:"path"`             // "" for the places
	Parent string           `json:"parent,omitempty"` // "" at the top of a disk: up is the places
	Sep    string           `json:"sep"`
	Places []musicPlace     `json:"places,omitempty"`
	Dirs   []filesDirEntry  `json:"dirs"`
	Files  []filesFileEntry `json:"files"`
	More   bool             `json:"more,omitempty"` // more entries than are listed
	Hidden int              `json:"hidden,omitempty"`
}

func filesListWithin(p string, wait time.Duration) (filesListBody, string) {
	return musicWithin(wait, "files\n"+p, func() bool { return musicGuardedLinks(p) }, func() (filesListBody, string) { return filesList(p) })
}

func filesList(raw string) (filesListBody, string) {
	b := filesListBody{Sep: string(filepath.Separator), Dirs: []filesDirEntry{}, Files: []filesFileEntry{}}
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
	if fi, err := f.Stat(); err == nil && !fi.IsDir() {
		return b, "not-a-folder"
	}
	used, seen := 0, 0
	full := func(name string) bool {
		if len(b.Dirs)+len(b.Files) >= filesListShown || used+len(name)+40 > filesListBytes {
			b.More = true
			return true
		}
		used += len(name) + 40
		return false
	}
	for {
		ents, err := f.ReadDir(filesListBatch)
		if err != nil && seen == 0 && len(ents) == 0 && err != io.EOF {
			return b, musicFolderErr(p, err)
		}
		for _, e := range ents {
			seen++
			name := e.Name()
			if !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\n\r") {
				continue
			}
			// Hidden entries are counted, not listed: a home folder's
			// dot-files would bury what is in it. The page says how many.
			if strings.HasPrefix(name, ".") {
				b.Hidden++
				continue
			}
			t := e.Type()
			if t&fs.ModeSymlink != 0 {
				if !musicLookAhead {
					// Where it leads is looked at when it is opened (macOS:
					// the look may be what the system asks about).
					if !full(name) {
						b.Dirs = append(b.Dirs, filesDirEntry{N: name, L: true})
					}
					continue
				}
				fi, err := os.Stat(filepath.Join(p, name))
				if err != nil {
					continue
				}
				if full(name) {
					continue
				}
				if fi.IsDir() {
					b.Dirs = append(b.Dirs, filesDirEntry{N: name, M: fi.ModTime().Unix()})
				} else if fi.Mode().IsRegular() {
					b.Files = append(b.Files, filesFileEntry{N: name, S: fi.Size(), M: fi.ModTime().Unix()})
				}
				continue
			}
			if !e.IsDir() && !t.IsRegular() {
				continue
			}
			if full(name) {
				continue
			}
			var m, s int64
			if fi, err := e.Info(); err == nil {
				m, s = fi.ModTime().Unix(), fi.Size()
			}
			if e.IsDir() {
				b.Dirs = append(b.Dirs, filesDirEntry{N: name, M: m})
			} else {
				b.Files = append(b.Files, filesFileEntry{N: name, S: s, M: m})
			}
		}
		if err != nil {
			break
		}
		if seen >= filesListEntries {
			b.More = true
			break
		}
	}
	b.Path = p
	if up := filepath.Dir(p); up != p {
		b.Parent = up
	}
	sort.SliceStable(b.Dirs, func(i, j int) bool { return strings.ToLower(b.Dirs[i].N) < strings.ToLower(b.Dirs[j].N) })
	sort.SliceStable(b.Files, func(i, j int) bool { return strings.ToLower(b.Files[i].N) < strings.ToLower(b.Files[j].N) })
	return b, ""
}

// ── the search ──────────────────────────────────────────────────────────

type filesHit struct {
	P string `json:"p"`
	D bool   `json:"d,omitempty"`
	S int64  `json:"s,omitempty"`
	M int64  `json:"m,omitempty"`
	// A link, named and never followed: a walk's, for the page to make the
	// same link again where it copies the tree.
	L bool `json:"l,omitempty"`
}

type filesJob struct {
	tok    string
	peer   key.NodePublic
	signer ed25519.PublicKey // the key that signed the question: unpinned, the search is over
	match  func(string) bool
	// A walk (filesStartWalk): every entry, hidden ones and packages'
	// insides too, links named as links; its own limits.
	every  bool
	limit  int
	page   int
	roots  []string
	skip   map[string]bool // the other roots, walked as their own
	cancel context.CancelFunc
	start  time.Time

	mu      sync.Mutex
	hits    []filesHit
	scanned int64
	folders int64
	unread  int      // folders that could not be read
	odd     int      // a walk's entries no page could copy: names JSON cannot carry, devices, sockets
	asks    []string // folders held up by the system's question
	done    bool
	why     string // limit | time | stopped | idle | busy | ""
	ms      int64
	seen    time.Time
	wake    chan struct{}
}

var filesJobs = struct {
	sync.Mutex
	m map[string]*filesJob
}{m: map[string]*filesJob{}}

var filesWalking atomic.Int32
var filesWalks atomic.Int32
var filesAsking atomic.Int32

// filesMatcher is the question turned into a test on a name: every word,
// or the one pattern, case aside.
func filesMatcher(q string) (func(string) bool, string) {
	q = strings.TrimSpace(q)
	if q == "" || len(q) > filesQueryMax || !utf8.ValidString(q) || strings.ContainsAny(q, "\x00\n\r/\\") {
		return nil, "bad-args"
	}
	lq := strings.ToLower(q)
	if strings.ContainsAny(lq, "*?") {
		if _, err := path.Match(lq, ""); err != nil {
			return nil, "bad-pattern"
		}
		return func(name string) bool {
			ok, _ := path.Match(lq, strings.ToLower(name))
			return ok
		}, ""
	}
	terms := strings.Fields(lq)
	if len(terms) > filesTermsMax {
		return nil, "bad-args"
	}
	return func(name string) bool {
		ln := strings.ToLower(name)
		for _, t := range terms {
			if !strings.Contains(ln, t) {
				return false
			}
		}
		return true
	}, ""
}

// filesNoDescend: folders whose name matches but whose insides are not a
// person's files — hidden ones, dependencies, a package's contents.
func filesNoDescend(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "$") {
		return true
	}
	switch strings.ToLower(name) {
	case "node_modules", "system volume information", "lost+found", "__pycache__":
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".app", ".bundle", ".framework", ".photoslibrary", ".musiclibrary", ".tvlibrary",
		".imovielibrary", ".band", ".logicx", ".xcarchive", ".kext", ".plugin":
		return true
	}
	return false
}

// filesSkipPath: the system's own trees that are not files at all, or are
// other places seen twice.
func filesSkipPath(p string) bool {
	var pre []string
	switch runtime.GOOS {
	case "linux", "android":
		pre = []string{"/proc", "/sys", "/dev", "/run"}
	case "darwin":
		// /System/Volumes holds the data volume again under its own name
		// (the firmlinks show it at /Users, /Applications …), /Volumes the
		// other disks, walked as their own places.
		pre = []string{"/System/Volumes", "/Volumes", "/dev", "/private/var/vm", "/net", "/home", "/cores"}
	}
	for _, x := range pre {
		if p == x || strings.HasPrefix(p, x+"/") {
			return true
		}
	}
	return false
}

// filesRoots is where a search with no folder given starts; tests point it
// at their scratch home so a test never walks the real disk.
var filesRoots = filesSearchRoots

// filesSearchRoots: where a search with no folder looks — home, then the
// disks (musicVolumes), each once.
func filesSearchRoots() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		add(filepath.Clean(home))
	}
	for _, v := range musicVolumes() {
		add(filepath.Clean(v.P))
	}
	return out
}

// filesRootsFor is where a search starts: the folder asked for, or
// everywhere.
func filesRootsFor(in string) ([]string, string) {
	if in == "" {
		return filesRoots(), ""
	}
	p, code := musicPathArg(in)
	if code != "" {
		return nil, code
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil, musicFolderErr(p, err)
	}
	if !fi.IsDir() {
		return nil, "not-a-folder"
	}
	return []string{p}, ""
}

func filesStartSearch(peer key.NodePublic, signer ed25519.PublicKey, q, in string) (string, string) {
	match, code := filesMatcher(q)
	if code != "" {
		return "", code
	}
	// Under the command gate: a disk that does not answer (a mount gone
	// away) is waited on as long as a folder's listing is, no longer.
	roots, code := musicWithin(filesListWait, "files-roots\n"+in, nil, func() ([]string, string) { return filesRootsFor(in) })
	if code != "" {
		return "", code
	}
	if len(roots) == 0 {
		return "", "unavailable"
	}
	tok := filesToken()
	if tok == "" {
		return "", "unavailable"
	}
	filesSweep(time.Now())
	filesJobs.Lock()
	// One search per peer: a new question ends the one before — never a
	// walk, which is a copy under way.
	for _, j := range filesJobs.m {
		if j.peer == peer && !j.every {
			j.cancel()
			j.finish("stopped")
		}
	}
	if filesWalking.Load() >= filesSearchJobs {
		filesJobs.Unlock()
		return "", "busy"
	}
	ctx, cancel := context.WithTimeout(context.Background(), filesSearchTime)
	now := time.Now()
	j := &filesJob{tok: tok, peer: peer, signer: signer, match: match, limit: filesSearchHits, page: filesSearchPage,
		roots: roots, cancel: cancel, start: now, seen: now, wake: make(chan struct{})}
	if len(roots) > 1 {
		j.skip = map[string]bool{}
		for _, r := range roots {
			j.skip[r] = true
		}
	}
	filesJobs.m[tok] = j
	filesWalking.Add(1)
	filesJobs.Unlock()
	filesSweeping()
	go func() {
		defer filesWalking.Add(-1)
		defer cancel()
		why := j.walk(ctx)
		if why == "" && ctx.Err() == context.DeadlineExceeded {
			why = "time"
		}
		j.finish(why)
	}()
	return tok, ""
}

// filesStartWalk is a walk of the tree under in, for a copy: every entry,
// as it is found, by the same token and pages as a search's.
func filesStartWalk(peer key.NodePublic, signer ed25519.PublicKey, in string) (string, string) {
	if in == "" {
		return "", "bad-args"
	}
	roots, code := musicWithin(filesListWait, "files-roots\n"+in, nil, func() ([]string, string) { return filesRootsFor(in) })
	if code != "" {
		return "", code
	}
	tok := filesToken()
	if tok == "" {
		return "", "unavailable"
	}
	filesSweep(time.Now())
	filesJobs.Lock()
	mine := 0
	for _, j := range filesJobs.m {
		if j.every && j.peer == peer {
			j.mu.Lock()
			if !j.done {
				mine++
			}
			j.mu.Unlock()
		}
	}
	if mine >= filesWalkPerPeer || filesWalks.Load() >= filesWalkJobs {
		filesJobs.Unlock()
		return "", "busy"
	}
	ctx, cancel := context.WithTimeout(context.Background(), filesWalkTime)
	now := time.Now()
	j := &filesJob{tok: tok, peer: peer, signer: signer, every: true, limit: filesWalkLimit, page: filesWalkPage,
		roots: roots, cancel: cancel, start: now, seen: now, wake: make(chan struct{})}
	filesJobs.m[tok] = j
	filesWalks.Add(1)
	filesJobs.Unlock()
	filesSweeping()
	go func() {
		defer filesWalks.Add(-1)
		defer cancel()
		why := j.walk(ctx)
		if why == "" && ctx.Err() == context.DeadlineExceeded {
			why = "time"
		}
		j.finish(why)
	}()
	return tok, ""
}

// finish marks the search over, once; the first reason given stands.
func (j *filesJob) finish(why string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return
	}
	j.done, j.why = true, why
	j.ms = time.Since(j.start).Milliseconds()
	close(j.wake)
}

func (j *filesJob) note() {
	// Under j.mu: wakes the poll waiting on more. finish has closed the last
	// one for good.
	if j.done {
		return
	}
	close(j.wake)
	j.wake = make(chan struct{})
}

func (j *filesJob) walk(ctx context.Context) string {
	for _, root := range j.roots {
		dev, devOK := uint64(0), false
		// A search stays on its root's disk on Linux, where /proc and the
		// like are disks of their own; a walk stays on its folder's disk
		// wherever the system can say which that is, as a copy of a folder
		// must not take in a disk mounted inside it.
		if runtime.GOOS == "linux" || runtime.GOOS == "android" || j.every {
			// A walk's folder is where a link to it leads, as its listing is.
			look := os.Lstat
			if j.every {
				look = os.Stat
			}
			if fi, err := look(root); err == nil {
				dev, devOK = filesDev(fi)
			}
		}
		// The system's own trees are left alone — unless the root is in one
		// already: a disk under /Volumes, looked at as its own place, is not
		// to be cut off below its top.
		skipTrees := !filesSkipPath(root)
		queue := []string{root}
		for len(queue) > 0 {
			if ctx.Err() != nil {
				if ctx.Err() == context.DeadlineExceeded {
					return "time"
				}
				return "stopped"
			}
			dir := queue[0]
			queue[0] = ""
			queue = queue[1:]
			if len(queue) == 0 {
				queue = nil // let the backing array go
			}
			ents, ok := j.read(dir)
			if !ok {
				continue
			}
			j.mu.Lock()
			room, over := j.limit-len(j.hits), j.done
			j.mu.Unlock()
			if over {
				// Stopped while this folder was read.
				return "stopped"
			}
			var hits []filesHit
			odd := 0
			// A walk with an entry it had no room for: the tree is cut.
			cut := false
			for i, e := range ents {
				// A folder of many thousands is looked through a batch at a
				// time, the clock read between.
				if i&511 == 511 && ctx.Err() != nil {
					break
				}
				name := e.Name()
				if !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\n\r") {
					if j.every {
						odd++
					}
					continue
				}
				full := filepath.Join(dir, name)
				// A link is a name, never a way in.
				isDir := e.IsDir()
				if j.every {
					t := e.Type()
					link := t&fs.ModeSymlink != 0
					if !isDir && !link && !t.IsRegular() {
						// A device, a socket, a pipe: nothing a copy can carry.
						odd++
						continue
					}
					if len(hits) < room {
						h := filesHit{P: full, D: isDir, L: link}
						if fi, err := e.Info(); err == nil {
							h.M = fi.ModTime().Unix()
							if t.IsRegular() {
								h.S = fi.Size()
							}
						}
						hits = append(hits, h)
					} else {
						// Over the limit: the tree is cut, and said to be.
						cut = true
						break
					}
					if !isDir || (skipTrees && filesSkipPath(full)) {
						continue
					}
					if devOK {
						fi, err := e.Info()
						if err != nil {
							odd++
							continue
						}
						if d, ok := filesDev(fi); ok && d != dev {
							continue
						}
					}
					if len(queue) < filesSearchQueue {
						queue = append(queue, full)
					}
					continue
				}
				if len(hits) < room && j.match(name) {
					h := filesHit{P: full, D: isDir}
					if fi, err := e.Info(); err == nil {
						h.M = fi.ModTime().Unix()
						if !isDir {
							h.S = fi.Size()
						}
					}
					hits = append(hits, h)
				}
				if !isDir || filesNoDescend(name) || (skipTrees && filesSkipPath(full)) {
					continue
				}
				if j.skip[full] {
					continue
				}
				if devOK {
					fi, err := e.Info()
					if err != nil {
						continue
					}
					if d, ok := filesDev(fi); ok && d != dev {
						continue
					}
				}
				if len(queue) < filesSearchQueue {
					queue = append(queue, full)
				}
			}
			j.mu.Lock()
			if j.done {
				j.mu.Unlock()
				return "stopped"
			}
			j.scanned += int64(len(ents))
			j.folders++
			j.odd += odd
			room = j.limit - len(j.hits)
			if len(hits) > room {
				hits = hits[:room]
				cut = true
			}
			if len(hits) > 0 {
				j.hits = append(j.hits, hits...)
				j.note()
			}
			// A search that filled up stops there. A walk stops when an
			// entry had no room — a tree of exactly the limit is whole, and
			// the folders still queued are read to know it (with no room
			// left, the first entry in any of them is the cut).
			enough := len(j.hits) >= j.limit
			if j.every {
				enough = cut
			}
			j.mu.Unlock()
			if enough {
				return "limit"
			}
		}
	}
	return ""
}

// read is one folder's entries, as many as are worth looking at. A folder
// the system holds up asking the person at the machine is not waited on
// past filesAskWait: the walk goes on without it and the page is told.
func (j *filesJob) read(dir string) ([]os.DirEntry, bool) {
	look := func() ([]os.DirEntry, error) {
		f, err := os.Open(dir)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var out []os.DirEntry
		for len(out) < filesSearchDir {
			ents, err := f.ReadDir(filesListBatch)
			out = append(out, ents...)
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				if len(out) > 0 {
					err = nil
				}
				return out, err
			}
		}
		return out, nil
	}
	if !musicSystemAsks || !filesGuarded(dir) || filesGuarded(filepath.Dir(dir)) {
		ents, err := look()
		if err != nil {
			j.mu.Lock()
			j.unread++
			j.mu.Unlock()
			return nil, false
		}
		return ents, true
	}
	// The top of a guarded folder: the read may be the system's question.
	if filesAsking.Load() >= filesAskStuck {
		j.mu.Lock()
		j.asks = append(j.asks, dir)
		j.mu.Unlock()
		return nil, false
	}
	type got struct {
		ents []os.DirEntry
		err  error
	}
	ch := make(chan got, 1)
	filesAsking.Add(1)
	go func() {
		defer filesAsking.Add(-1)
		ents, err := look()
		ch <- got{ents, err}
	}()
	select {
	case g := <-ch:
		if g.err != nil {
			j.mu.Lock()
			if errors.Is(g.err, fs.ErrPermission) {
				j.asks = append(j.asks, dir)
			} else {
				j.unread++
			}
			j.mu.Unlock()
			return nil, false
		}
		return g.ents, true
	case <-time.After(filesAskWait):
		j.mu.Lock()
		j.asks = append(j.asks, dir)
		j.mu.Unlock()
		return nil, false
	}
}

var filesSweeper sync.Once

// filesSweeping keeps filesSweep running on its own clock from the first
// search or file on: a token nobody uses runs out whether or not anyone
// asks for another.
func filesSweeping() {
	filesSweeper.Do(func() {
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for now := range t.C {
				filesSweep(now)
			}
		}()
	})
}

// filesSweep ends the searches nobody is reading and forgets the finished
// ones nobody came back for, and the files nobody has read lately.
func filesSweep(now time.Time) {
	filesJobs.Lock()
	for tok, j := range filesJobs.m {
		j.mu.Lock()
		seen, done := j.seen, j.done
		j.mu.Unlock()
		if !done && (now.Sub(seen) > filesSearchIdle || !filesSignerOK(j.signer)) {
			j.cancel()
			j.finish("idle")
		}
		if now.Sub(seen) > filesSearchKeep {
			j.cancel()
			delete(filesJobs.m, tok)
		}
	}
	filesJobs.Unlock()
	filesOpened.Lock()
	for tok, o := range filesOpened.m {
		if now.Sub(o.seen) > filesOpenKeep || !filesSignerOK(o.signer) {
			delete(filesOpened.m, tok)
		}
	}
	filesOpened.Unlock()
	filesPutSweep(now)
}

type filesPage struct {
	Hits    []filesHit `json:"hits"`
	Next    int        `json:"next"`
	Done    bool       `json:"done"`
	Why     string     `json:"why,omitempty"`
	Scanned int64      `json:"scanned"`
	Folders int64      `json:"folders"`
	Unread  int        `json:"unread,omitempty"`
	Odd     int        `json:"odd,omitempty"`
	Asks    []string   `json:"asks,omitempty"`
	Ms      int64      `json:"ms"`
}

// ── the files ───────────────────────────────────────────────────────────

type filesOpen struct {
	peer   key.NodePublic
	signer ed25519.PublicKey
	p      string
	size   int64
	mod    time.Time
	seen   time.Time
}

var filesOpened = struct {
	sync.Mutex
	m map[string]*filesOpen
}{m: map[string]*filesOpen{}}

var filesReads = make(chan struct{}, 4)

type filesOpenBody struct {
	T    string `json:"t"`
	N    string `json:"n"`
	S    int64  `json:"s"`
	M    int64  `json:"m"`
	Max  int    `json:"max"`
	Path string `json:"path"`
}

// filesSignerOK: the key that asked is pinned here still. Unpinning it ends
// what it opened, as it ends its terminals (pty.go).
func filesSignerOK(k ed25519.PublicKey) bool {
	return trustsKey(k)
}

type filesLooked struct {
	p    string
	size int64
	mod  time.Time
}

func filesOpenFile(peer key.NodePublic, signer ed25519.PublicKey, raw string) (filesOpenBody, string) {
	var b filesOpenBody
	p, code := musicPathArg(raw)
	if code != "" {
		return b, code
	}
	// Under the command gate, as long as a listing is waited on and no longer.
	got, code := musicWithin(filesListWait, "files-open\n"+p, nil, func() (filesLooked, string) { return filesLookAt(p) })
	if code != "" {
		return b, code
	}
	tok := filesToken()
	if tok == "" {
		return b, "unavailable"
	}
	filesSweep(time.Now())
	filesSweeping()
	filesOpened.Lock()
	if len(filesOpened.m) >= filesOpenMax {
		// The one read longest ago makes room.
		var old string
		var at time.Time
		for t, o := range filesOpened.m {
			if old == "" || o.seen.Before(at) {
				old, at = t, o.seen
			}
		}
		delete(filesOpened.m, old)
	}
	filesOpened.m[tok] = &filesOpen{peer: peer, signer: signer, p: got.p, size: got.size, mod: got.mod, seen: time.Now()}
	filesOpened.Unlock()
	return filesOpenBody{T: tok, N: filepath.Base(got.p), S: got.size, M: got.mod.Unix(), Max: filesReadMax, Path: got.p}, ""
}

// filesLookAt: a regular file this account can open, as it is now.
func filesLookAt(p string) (filesLooked, string) {
	var b filesLooked
	fi, err := os.Stat(p)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return b, "missing"
		case errors.Is(err, fs.ErrPermission):
			return b, "no-access"
		}
		return b, "unavailable"
	}
	if fi.IsDir() {
		return b, "not-a-file"
	}
	if !fi.Mode().IsRegular() {
		return b, "not-a-file"
	}
	// Readable now, or the page is told so before it asks for a piece.
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return b, "no-access"
		}
		return b, "unavailable"
	}
	f.Close()
	return filesLooked{p: p, size: fi.Size(), mod: fi.ModTime()}, ""
}

// ── the doors ───────────────────────────────────────────────────────────

// filesArgs is every files command's argument, each op reading its own:
// the reads here, the changes in fileswrite.go.
type filesArgs struct {
	Path string `json:"path"`
	Q    string `json:"q"`
	In   string `json:"in"`
	T    string `json:"t"`
	// A file coming in (put), a folder made (mkdir): the folder and the name.
	Dir  string `json:"dir"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	K    string `json:"k"`
	Mode string `json:"mode"`
	// done: the modified time to give the file, Unix seconds.
	M int64 `json:"m"`
	// move: the folder it goes to.
	To string `json:"to"`
	// put with mode replace: the size and modified time the page saw of
	// the file it replaces (fileswrite.go filesWasArg).
	Was json.RawMessage `json:"was"`
}

// runFilesCommand is a signed files command, from the tunnel's command door
// (direct.go), with the peer that sent it.
func runFilesCommand(c consoleCmd, peer key.NodePublic, hasPeer bool, signer ed25519.PublicKey) consoleResult {
	res := consoleResult{ID: c.ID, Kind: "files", Target: c.Target, Code: -1}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	if !consoleEnabled() {
		res.Error = "console-off"
		return res
	}
	if !hasPeer || len(signer) == 0 {
		res.Error = "not-allowed"
		return res
	}
	var arg filesArgs
	if c.Cmd != "" && json.Unmarshal([]byte(c.Cmd), &arg) != nil {
		res.Error = "bad-args"
		return res
	}
	var out any
	switch c.Target {
	case "list":
		body, code := filesListWithin(arg.Path, filesListWait)
		if code != "" {
			res.Error = code
			return res
		}
		out = body
	case "search":
		tok, code := filesStartSearch(peer, signer, arg.Q, arg.In)
		if code != "" {
			res.Error = code
			return res
		}
		out = map[string]any{"t": tok, "page": filesSearchPage, "hits": filesSearchHits, "secs": int(filesSearchTime / time.Second)}
	case "walk":
		tok, code := filesStartWalk(peer, signer, arg.In)
		if code != "" {
			res.Error = code
			return res
		}
		out = map[string]any{"t": tok, "page": filesWalkPage, "hits": filesWalkLimit, "secs": int(filesWalkTime / time.Second)}
	case "stop":
		filesJobs.Lock()
		if j := filesJobs.m[arg.T]; j != nil && j.peer == peer {
			j.cancel()
			j.finish("stopped")
		}
		filesJobs.Unlock()
		out = map[string]any{}
	case "open":
		body, code := filesOpenFile(peer, signer, arg.Path)
		if code != "" {
			res.Error = code
			return res
		}
		out = body
	default:
		body, code, known := filesWriteCommand(c.Target, peer, signer, arg)
		if !known {
			res.Error = "unknown-op"
			return res
		}
		if code != "" {
			res.Error = code
			return res
		}
		out = body
	}
	b, err := json.Marshal(out)
	if err != nil {
		res.Error = "unavailable"
		return res
	}
	res.Code, res.Out = 0, string(b)
	return res
}

// filesPeer: an allowlisted key, on a machine whose files are the tab's.
func (h *directHandler) filesPeer(w http.ResponseWriter, r *http.Request) (key.NodePublic, bool) {
	k, ok := transport.PeerFromContext(r.Context())
	if !ok {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return k, false
	}
	listed := false
	for _, a := range loadAllowedClients() {
		if a == k {
			listed = true
			break
		}
	}
	if !listed {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return k, false
	}
	if !filesOn() {
		h.refuse(w, http.StatusNotFound, "console-off")
		return k, false
	}
	return k, true
}

// filesSearch is GET /v1/files/search?s=…&from=N: the hits from N on, as
// they come — held up to filesSearchWait for the next ones while the walk
// goes on.
func (h *directHandler) filesSearch(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.filesPeer(w, r)
	if !ok {
		return
	}
	tok := r.URL.Query().Get("s")
	filesJobs.Lock()
	j := filesJobs.m[tok]
	filesJobs.Unlock()
	if j == nil || tok == "" || j.peer != peer || !filesSignerOK(j.signer) {
		h.refuse(w, http.StatusNotFound, "no-search")
		return
	}
	// Clamped before it is an int: on a 32-bit build a large one wraps.
	from64 := queryInt(r, "from")
	if from64 > int64(j.limit) {
		from64 = int64(j.limit)
	}
	from := int(from64)
	clock := time.NewTimer(filesSearchWait)
	defer clock.Stop()
	// Leaves the loop holding j.mu.
	for {
		j.mu.Lock()
		j.seen = time.Now()
		if from > len(j.hits) {
			from = len(j.hits)
		}
		if from < len(j.hits) || j.done {
			break
		}
		wake := j.wake
		j.mu.Unlock()
		late := false
		select {
		case <-wake:
		case <-clock.C:
			late = true
		case <-r.Context().Done():
			return
		}
		if late {
			j.mu.Lock()
			j.seen = time.Now()
			break
		}
	}
	// So many hits as the job's page holds, and no more than fit in one
	// answer: a walk's paths may be long, and two thousand of them could
	// outgrow what the page reads in one piece.
	end, size := from, 0
	for end < len(j.hits) && end-from < j.page {
		n := filesHitBytes(j.hits[end])
		if end > from && size+n > filesPageBytes-filesPageSlack {
			break
		}
		size += n
		end++
	}
	page := filesPage{
		// An empty page is [], never null: the page reads hits as a list.
		Hits: append(make([]filesHit, 0, end-from), j.hits[from:end]...), Next: end,
		Done: j.done && end == len(j.hits), Why: j.why,
		Scanned: j.scanned, Folders: j.folders, Unread: j.unread, Odd: j.odd,
		Asks: append([]string(nil), j.asks...), Ms: time.Since(j.start).Milliseconds(),
	}
	if j.done {
		page.Ms = j.ms
	}
	if !page.Done {
		page.Why = ""
	}
	j.mu.Unlock()
	b, err := json.Marshal(page)
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// filesHitBytes is what one hit takes in a page's JSON, at most: the path as
// encoding/json writes it (a control byte and <, >, & as \u00XX, a quote
// and a backslash with a backslash before, U+2028 and U+2029 as \u2028),
// its names, flags and numbers at their longest.
func filesHitBytes(h filesHit) int {
	n := 96
	for i := 0; i < len(h.P); i++ {
		switch c := h.P[i]; {
		case c < 0x20, c == '<', c == '>', c == '&':
			n += 6
		case c == '"', c == '\\':
			n += 2
		default:
			n++
		}
	}
	return n + 3*(strings.Count(h.P, "\u2028")+strings.Count(h.P, "\u2029"))
}

// filesFile is GET /v1/files/file?s=…&o=…&n=…: a piece of an opened file,
// filesReadMax at most, read whole before anything is sent.
func (h *directHandler) filesFile(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.filesPeer(w, r)
	if !ok {
		return
	}
	tok := r.URL.Query().Get("s")
	filesOpened.Lock()
	o := filesOpened.m[tok]
	var p string
	var size int64
	var mod time.Time
	now := time.Now()
	if o != nil && (now.Sub(o.seen) > filesOpenKeep || !filesSignerOK(o.signer)) {
		// Run out, or its key unpinned since: gone, whatever the sweep's clock says.
		delete(filesOpened.m, tok)
		o = nil
	}
	if o != nil && tok != "" && o.peer == peer {
		o.seen = now
		p, size, mod = o.p, o.size, o.mod
	}
	filesOpened.Unlock()
	if p == "" {
		h.refuse(w, http.StatusNotFound, "no-file")
		return
	}
	off, n := queryInt(r, "o"), queryInt(r, "n")
	if off >= size && !(off == 0 && size == 0) {
		h.refuse(w, http.StatusRequestedRangeNotSatisfiable, "out-of-range")
		return
	}
	if n <= 0 || n > filesReadMax {
		n = filesReadMax
	}
	if off+n > size {
		n = size - off
	}
	select {
	case filesReads <- struct{}{}:
		defer func() { <-filesReads }()
	case <-r.Context().Done():
		return
	case <-time.After(20 * time.Second):
		h.refuse(w, http.StatusServiceUnavailable, "busy")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			h.refuse(w, http.StatusConflict, "changed")
			return
		}
		h.refuse(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	defer f.Close()
	// The file as it was opened, or the page is told it changed: pieces of
	// two different files make neither.
	if fi, err := f.Stat(); err != nil || fi.Size() != size || !fi.ModTime().Equal(mod) {
		h.refuse(w, http.StatusConflict, "changed")
		return
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := f.ReadAt(buf, off); err != nil {
			if errors.Is(err, io.EOF) {
				h.refuse(w, http.StatusConflict, "changed")
			} else {
				h.refuse(w, http.StatusServiceUnavailable, "unavailable")
			}
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf)
}
