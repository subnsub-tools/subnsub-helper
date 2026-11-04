package main

// music.go — this machine's music, shared with the browsers on its allowlist.
//
// What is shared, and who decides:
//
//   - Nothing is read until a person chooses a folder (user, 2026-11-04: the
//     music library is not touched unless the web client asks, macOS above
//     all, and files are not scanned until somebody picks the path). There
//     is no default folder, here or from a page: music switched on with
//     nothing chosen shares nothing, and the disk is not looked at.
//   - A machine whose console is on (console.go) and which has pinned a
//     dashboard key has music on without being asked. That dashboard may
//     already run any line here as this account, so a second switch would
//     guard nothing — update.go makes the same argument for updates (user,
//     2026-11-04: every machine whose helper takes remote commands should
//     reach its disk's files). Its page may look through the machine's
//     folders when somebody opens them there, and share the one chosen
//     (browse, add-dir); only then is that folder walked.
//   - Elsewhere the folders are chosen here: `subnsub-monitor music add
//     <dir>` (or --music-dir on the install line), after `music on` (or
//     --music). A dashboard whose key this machine has pinned may add WebDAV
//     folders (musicdav.go) and take any root away, but it cannot look
//     through or name a local folder.
//   - `music off` at the keyboard, or MON_MUSIC=off, wins over both.
//
// The roads are the direct ones alone — the tailnet road and the tailcat
// tunnel (direct.go, tailnet.go). The relay never carries a byte of it: no
// route here is reachable from the mailbox, and the `music` command kind is
// refused there (mailboxRefusal). The page reads:
//
//	GET /v1/music                       which roots, how many tracks, scanning or not
//	GET /v1/music/index?r=ID&from=N     one page of a root's tracks, with their tags
//	GET /v1/music/file?r=ID&p=PATH&o=OFF&n=LEN   that many of a track's bytes
//	GET /v1/music/art?r=ID&p=PATH&w=PX  the track's cover, scaled to fit PX
//
// A path is answered only when it is a track in the root's own index — the
// walk below put it there — so no request names a file the walk did not find,
// and the local reads go through os.Root besides, which refuses a path that
// would leave the folder. Only audio files are indexed; the cover route also
// reads the folder images the walk noted beside them, and nothing else. The
// folder listing a page looks through comes only in answer to a signed
// command (browse), never to a GET: a key on the allowlist may watch and
// listen, and only a pinned key on a machine with the console on may look.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "image/gif"
	_ "image/png"

	"golang.org/x/term"

	"subnsubmonitor/transport"
)

const (
	musicConfFile   = "music.json"
	musicIndexFile  = "music-index.json"
	musicEnvVar     = "MON_MUSIC"
	musicRootsMax   = 16
	musicTracksMax  = 100000
	musicDepthMax   = 24
	musicReadMax    = 4 << 20
	musicLocalEvery = 30 * time.Minute
	musicDavEvery   = 3 * time.Hour
	musicArtMax     = 8 << 20
	musicArtPixels  = 40 << 20
	musicArtCache   = 24 << 20
	musicReadsMax   = 6
)

// The audio a browser plays, by extension, and the type it is served as.
var musicAudio = map[string]string{
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".m4b": "audio/mp4", ".aac": "audio/aac",
	".flac": "audio/flac", ".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg",
	".wav": "audio/wav", ".aif": "audio/aiff", ".aiff": "audio/aiff", ".aifc": "audio/aiff",
	".webm": "audio/webm", ".weba": "audio/webm", ".caf": "audio/x-caf",
}

// A folder's own cover, by its usual names, best first.
var musicCoverNames = []string{"cover", "folder", "front", "album", "albumartlarge", "albumart"}

var musicImageExt = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".webp": true}

// ── configuration ──────────────────────────────────────────────────────

type musicRootConf struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // "dir" or "webdav"
	Path string `json:"path,omitempty"`
	URL  string `json:"url,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
	Pin  string `json:"pin,omitempty"`
	Name string `json:"name,omitempty"`
}

type musicConf struct {
	V  int  `json:"v"`
	On bool `json:"on"`
	// Off is `music off`, typed at the keyboard: it wins over the console's
	// grant, which otherwise switches music on (musicOnConf).
	Off bool `json:"off,omitempty"`
	// A rescan asked for at the keyboard: the running helper is another
	// process, and a newer stamp here is how it hears.
	Rescan int64           `json:"rescan,omitempty"`
	Roots  []musicRootConf `json:"roots"`
}

func musicConfPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, musicConfFile)
}

var musicConfCache struct {
	sync.Mutex
	mod  time.Time
	size int64
	conf musicConf
	ok   bool
}

// loadMusicConf is the file as it is now, read again only when it changed.
func loadMusicConf() musicConf {
	p := musicConfPath()
	if p == "" {
		return musicConf{}
	}
	fi, err := os.Stat(p)
	musicConfCache.Lock()
	defer musicConfCache.Unlock()
	if err != nil {
		musicConfCache.ok = false
		return musicConf{}
	}
	if musicConfCache.ok && fi.ModTime().Equal(musicConfCache.mod) && fi.Size() == musicConfCache.size {
		return musicConfCache.conf
	}
	b, err := os.ReadFile(p)
	var c musicConf
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, &c) != nil {
		// Unreadable is off: sharing nobody can see the list of is not a
		// default worth having.
		c = musicConf{}
	}
	if c.V == 1 {
		// Written before the console's grant, when off was all that "on":
		// false could say. It may have been 'music off' at the keyboard,
		// which nothing from a page undoes, so it is kept as that.
		c.Off = c.Off || !c.On
	}
	c.Roots = cleanMusicRoots(c.Roots)
	kept := c.Roots[:0]
	for _, r := range c.Roots {
		if !musicWasDefault(r.ID, r.Kind, r.Path) {
			kept = append(kept, r)
		}
	}
	c.Roots = kept
	musicConfCache.mod, musicConfCache.size, musicConfCache.conf, musicConfCache.ok = fi.ModTime(), fi.Size(), c, true
	return c
}

// musicWasDefault: the Music folder 2026.11.04.2 shared by itself where the
// console was on, under an id worked out from its path, and wrote down beside
// a folder added from a page. Nobody chose it, and nothing is read that
// nobody chose (user, 2026-11-04: only a path the person chose is scanned),
// so it is no longer shared, and what was found in it is forgotten
// (musicLoadSaved).
func musicWasDefault(id, kind, p string) bool {
	if kind != "dir" || len(id) != 12 {
		return false
	}
	h := sha256.Sum256([]byte("music-folder\n" + p))
	return id == hex.EncodeToString(h[:6])
}

func cleanMusicRoots(in []musicRootConf) []musicRootConf {
	var out []musicRootConf
	seen := map[string]bool{}
	for _, r := range in {
		if r.ID == "" || len(r.ID) > 32 || seen[r.ID] || len(out) >= musicRootsMax {
			continue
		}
		switch r.Kind {
		case "dir":
			if r.Path == "" || !filepath.IsAbs(r.Path) {
				continue
			}
		case "webdav":
			if _, err := cleanDavURL(r.URL); err != nil {
				continue
			}
		default:
			continue
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out
}

func saveMusicConf(c musicConf) error {
	p := musicConfPath()
	if p == "" {
		return errString("no config directory")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	c.V = 2
	if c.Roots == nil {
		c.Roots = []musicRootConf{}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// writeFileAtomic's temporary file is 0600 from its first byte: the file
	// can hold a WebDAV password.
	if err := writeFileAtomic(p, append(b, '\n')); err != nil {
		return err
	}
	os.Chmod(p, 0o600)
	return nil
}

func musicEnvOff() bool {
	v, ok := os.LookupEnv(musicEnvVar)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "false", "no":
		return true
	}
	return false
}

// musicByConsole is the console's grant: commands from a pinned dashboard
// key, which may already read whatever this account can (see the top of this
// file). The console is not taken without a pinned key on the tunnel either
// (direct.go), so a machine with nothing pinned has no such grant.
func musicByConsole() bool {
	return consoleEnabled() && loadTrust().sealed
}

// musicOnConf says whether this configuration shares music right now.
func musicOnConf(c musicConf) bool {
	if musicEnvOff() || c.Off {
		return false
	}
	return c.On || musicByConsole()
}

// musicOn says whether this machine shares music right now.
func musicOn() bool {
	return musicOnConf(loadMusicConf())
}

func musicNewID() string {
	var b [6]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// musicRelOK is the shape of a path under a root: relative, slash-separated,
// no empty, "." or ".." segment, no NUL or backslash, valid UTF-8.
func musicRelOK(p string) bool {
	if p == "" || len(p) > 1024 || !utf8.ValidString(p) || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// musicSkipDir is a folder no music walk goes into: hidden ones, NAS
// thumbnail and recycle folders, and the bundles applications keep their
// projects and databases in.
func musicSkipDir(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "#") || strings.HasPrefix(name, "$") {
		return true
	}
	switch strings.ToLower(name) {
	case "system volume information", "node_modules", "lost+found":
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".musiclibrary", ".photoslibrary", ".band", ".logicx", ".app", ".tvlibrary", ".imovielibrary":
		return true
	}
	return false
}

func musicMime(p string) string {
	return musicAudio[strings.ToLower(path.Ext(p))]
}

func musicCoverRank(name string) int {
	ext := strings.ToLower(path.Ext(name))
	if !musicImageExt[ext] {
		return -1
	}
	base := strings.ToLower(strings.TrimSuffix(name, path.Ext(name)))
	for i, c := range musicCoverNames {
		if base == c {
			return len(musicCoverNames) - i
		}
	}
	return -1
}

// homeTilde names a local path as the page shows it: the home directory as ~.
func homeTilde(p string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		if p == h {
			return "~"
		}
		if strings.HasPrefix(p, h+string(filepath.Separator)) {
			return "~" + filepath.ToSlash(p[len(h):])
		}
	}
	return filepath.ToSlash(p)
}

func (r musicRootConf) label() string {
	if r.Name != "" {
		return r.Name
	}
	if r.Kind == "dir" {
		return filepath.Base(r.Path)
	}
	if u, err := cleanDavURL(r.URL); err == nil {
		if b := path.Base(strings.TrimSuffix(u.Path, "/")); b != "" && b != "/" && b != "." {
			return b
		}
		return u.Hostname()
	}
	return r.ID
}

func (r musicRootConf) where() string {
	if r.Kind == "dir" {
		return homeTilde(r.Path)
	}
	if u, err := cleanDavURL(r.URL); err == nil {
		return strings.TrimSuffix(u.Host+u.Path, "/")
	}
	return ""
}

// ── the library ────────────────────────────────────────────────────────

// musicTrack is one indexed file. Short keys: an index of ten thousand of
// these crosses the tunnel.
type musicTrack struct {
	P  string  `json:"p"`            // path under the root
	S  int64   `json:"s"`            // size in bytes
	M  int64   `json:"m"`            // modified, unix seconds
	E  string  `json:"e,omitempty"`  // the WebDAV ETag
	T  string  `json:"t,omitempty"`  // title
	A  string  `json:"a,omitempty"`  // artist
	AA string  `json:"aa,omitempty"` // album artist
	B  string  `json:"b,omitempty"`  // album
	N  int     `json:"n,omitempty"`  // track number
	K  int     `json:"k,omitempty"`  // disc number
	Y  int     `json:"y,omitempty"`  // year
	D  float64 `json:"d,omitempty"`  // running time, seconds
	C  int     `json:"c,omitempty"`  // cover: 1 in the file, 2 a picture in its folder
}

type musicRootState struct {
	conf     musicRootConf
	dav      *davRoot
	tracks   []musicTrack
	byPath   map[string]int
	covers   map[string]string // folder → its cover's path
	rev      uint64
	at       int64 // when the last walk finished
	scanning bool
	seen     int
	err      string
	due      bool
	cancel   context.CancelFunc
	// ask is the folder this walk is held on while the system asks the
	// person at the machine whether it may be read (musicAskWatch).
	ask string
}

type musicSavedRoot struct {
	Rev    uint64            `json:"rev"`
	At     int64             `json:"at"`
	Sig    string            `json:"sig"` // what the root was when walked: path or URL
	Tracks []musicTrack      `json:"tracks"`
	Covers map[string]string `json:"covers,omitempty"`
}

type musicSaved struct {
	V     int                        `json:"v"`
	Roots map[string]*musicSavedRoot `json:"roots"`
}

var musicLib = struct {
	sync.Mutex
	roots  map[string]*musicRootState
	order  []string
	rescan int64
	// rescanSeen: the configuration's rescan stamp has been read once. The
	// first read only records it (every root is walked at start anyway); a
	// later, newer stamp marks them all due.
	rescanSeen bool
	// The index on disk, read on the first look and handed to each root as
	// it is set up: a restart does not read ten thousand files' tags again.
	saved  map[string]*musicSavedRoot
	loaded bool
	wake   chan struct{}
}{roots: map[string]*musicRootState{}, wake: make(chan struct{}, 1)}

var musicOnce sync.Once

// musicStart runs the walker for this process's life, from the first time
// the direct roads come up (runDirect): music is served on them alone.
func musicStart() {
	musicOnce.Do(func() { go musicLoop() })
}

func musicWake() {
	select {
	case musicLib.wake <- struct{}{}:
	default:
	}
}

func (r musicRootConf) sig() string {
	if r.Kind == "dir" {
		return "dir:" + r.Path
	}
	return "webdav:" + r.URL + "\n" + r.User
}

func musicIndexPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, musicIndexFile)
}

func musicLoadSaved() map[string]*musicSavedRoot {
	p := musicIndexPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 256<<20 {
		return nil
	}
	var s musicSaved
	if json.Unmarshal(b, &s) != nil || s.V != 1 {
		return nil
	}
	gone := false
	for id, r := range s.Roots {
		if r != nil && strings.HasPrefix(r.Sig, "dir:") && musicWasDefault(id, "dir", strings.TrimPrefix(r.Sig, "dir:")) {
			delete(s.Roots, id)
			gone = true
		}
	}
	if gone {
		if nb, err := json.Marshal(s); err == nil {
			if err := writeFileAtomic(p, nb); err != nil {
				warnf("music: could not save the index: %v", err)
			}
		}
	}
	return s.Roots
}

func musicSave() {
	p := musicIndexPath()
	if p == "" {
		return
	}
	musicLib.Lock()
	s := musicSaved{V: 1, Roots: map[string]*musicSavedRoot{}}
	for id, rs := range musicLib.roots {
		if rs.at == 0 {
			continue
		}
		s.Roots[id] = &musicSavedRoot{Rev: rs.rev, At: rs.at, Sig: rs.conf.sig(), Tracks: rs.tracks, Covers: rs.covers}
	}
	b, err := json.Marshal(s)
	musicLib.Unlock()
	if err != nil {
		return
	}
	if err := writeFileAtomic(p, b); err != nil {
		warnf("music: could not save the index: %v", err)
	}
}

// musicReconcile brings the library in line with the configuration: roots
// added, removed or changed since the last look.
func musicReconcile() {
	c := loadMusicConf()
	on := musicOnConf(c)
	musicLib.Lock()
	defer musicLib.Unlock()
	if !musicLib.loaded {
		musicLib.saved, musicLib.loaded = musicLoadSaved(), true
	}
	saved := musicLib.saved
	want := map[string]musicRootConf{}
	order := []string{}
	if on {
		for _, r := range c.Roots {
			want[r.ID] = r
			order = append(order, r.ID)
		}
	}
	for id, rs := range musicLib.roots {
		if w, ok := want[id]; !ok || w.sig() != rs.conf.sig() || w.Pass != rs.conf.Pass || w.Pin != rs.conf.Pin {
			if rs.cancel != nil {
				rs.cancel()
			}
			delete(musicLib.roots, id)
		}
	}
	for _, id := range order {
		r := want[id]
		if rs, ok := musicLib.roots[id]; ok {
			rs.conf.Name = r.Name
			continue
		}
		// Revisions from the clock, not from one: a root set up again without
		// its saved index (music switched off and on, its settings changed)
		// must not hand out a revision a browser already holds a library for.
		rs := &musicRootState{conf: r, byPath: map[string]int{}, covers: map[string]string{}, due: true,
			rev: uint64(time.Now().UnixNano())}
		if r.Kind == "webdav" {
			if d, err := newDav(r.URL, r.User, r.Pass, r.Pin); err == nil {
				rs.dav = d
			} else {
				rs.err = "bad-url"
			}
		}
		if s := saved[id]; s != nil && s.Sig == r.sig() {
			rs.tracks, rs.rev, rs.at = s.Tracks, s.Rev, s.At
			if s.Covers != nil {
				rs.covers = s.Covers
			}
			rs.reindex()
			// Walked again at once all the same — the folder may have changed
			// while this helper was not running — but the tags of files that
			// did not change are not read again.
		}
		delete(saved, id)
		musicLib.roots[id] = rs
	}
	musicLib.order = order
	if !musicLib.rescanSeen {
		musicLib.rescan, musicLib.rescanSeen = c.Rescan, true
	} else if c.Rescan > musicLib.rescan {
		for _, rs := range musicLib.roots {
			rs.due = true
		}
		musicLib.rescan = c.Rescan
	}
}

func (rs *musicRootState) reindex() {
	rs.byPath = make(map[string]int, len(rs.tracks))
	for i, t := range rs.tracks {
		rs.byPath[t.P] = i
	}
}

// musicNextDue is the root to walk next: one never walked or asked for again,
// then one whose interval has passed.
func musicNextDue(now time.Time) *musicRootState {
	musicLib.Lock()
	defer musicLib.Unlock()
	for _, id := range musicLib.order {
		rs := musicLib.roots[id]
		if rs == nil || rs.scanning {
			continue
		}
		every := musicLocalEvery
		if rs.conf.Kind == "webdav" {
			every = musicDavEvery
		}
		if rs.due || now.Unix()-rs.at >= int64(every/time.Second) {
			rs.due = false
			rs.scanning = true
			rs.seen = 0
			return rs
		}
	}
	return nil
}

func musicLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		musicReconcile()
		if rs := musicNextDue(time.Now()); rs != nil {
			musicWalk(rs)
			continue
		}
		select {
		case <-musicLib.wake:
		case <-t.C:
		}
	}
}

// musicWalk walks one root and puts what it found in place of what it had.
func musicWalk(rs *musicRootState) {
	ctx, cancel := context.WithCancel(context.Background())
	musicLib.Lock()
	rs.cancel = cancel
	old := rs.byPath
	oldTracks := rs.tracks
	musicLib.Unlock()
	defer cancel()

	prev := func(p string) *musicTrack {
		if i, ok := old[p]; ok && i < len(oldTracks) {
			t := oldTracks[i]
			return &t
		}
		return nil
	}
	var tracks []musicTrack
	var covers map[string]string
	var err error
	if rs.conf.Kind == "dir" {
		tracks, covers, err = musicWalkDir(ctx, rs, prev)
	} else if rs.dav != nil {
		tracks, covers, err = musicWalkDav(ctx, rs, prev)
	} else {
		err = davFail("bad-url")
	}
	sort.Slice(tracks, func(i, j int) bool { return tracks[i].P < tracks[j].P })

	musicLib.Lock()
	rs.scanning = false
	rs.cancel = nil
	if musicLib.roots[rs.conf.ID] != rs {
		// Taken away, or changed, while it was being walked.
		musicLib.Unlock()
		return
	}
	if ctx.Err() != nil {
		musicLib.Unlock()
		return
	}
	if err != nil {
		// A folder that is not there right now (a disk not mounted, a server
		// not answering) keeps the tracks it had: they come back with it.
		rs.err = musicErrCode(err)
		rs.at = time.Now().Unix()
		musicLib.Unlock()
		return
	}
	rs.err = ""
	changed := len(tracks) != len(oldTracks) || len(covers) != len(rs.covers)
	if !changed {
		for i := range tracks {
			if tracks[i] != oldTracks[i] {
				changed = true
				break
			}
		}
	}
	if !changed {
		for k, v := range covers {
			if rs.covers[k] != v {
				changed = true
				break
			}
		}
	}
	rs.at = time.Now().Unix()
	if changed {
		rs.tracks, rs.covers = tracks, covers
		rs.rev++
		rs.reindex()
	}
	musicLib.Unlock()
	musicSave()
}

func musicErrCode(err error) string {
	var de *davError
	if errors.As(err, &de) {
		return de.Code
	}
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "no-access"
	}
	return "unavailable"
}

func musicNote(rs *musicRootState, seen int) {
	musicLib.Lock()
	rs.seen = seen
	musicLib.Unlock()
}

// musicProgress is where a walk is and when it last moved on.
type musicProgress struct {
	mu    sync.Mutex
	dir   string
	since time.Time
}

func (p *musicProgress) at(dir string) {
	p.mu.Lock()
	if dir != "" {
		p.dir = dir
	}
	p.since = time.Now()
	p.mu.Unlock()
}

// musicAskWatch notes, while a walk has not moved on for musicAskWait in a
// folder the system guards (musicGuardedLinks), that it is waiting on the person
// at the machine to allow the read — for the page to say so, on whatever
// machine it is (user, 2026-11-04: whenever a machine waits on an access prompt, the page says so).
// The function it returns stops the watch.
func musicAskWatch(rs *musicRootState, prog *musicProgress) func() {
	if !musicSystemAsks {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(musicAskWait / 3)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			prog.mu.Lock()
			dir, idle := prog.dir, time.Since(prog.since)
			prog.mu.Unlock()
			ask := ""
			if idle >= musicAskWait && musicGuardedLinks(dir) {
				ask = homeTilde(dir)
			}
			musicLib.Lock()
			select {
			case <-done:
				// Stopped while this looked: the walk is over, and so is
				// what it waited on.
			default:
				rs.ask = ask
			}
			musicLib.Unlock()
		}
	}()
	return func() {
		close(done)
		musicLib.Lock()
		rs.ask = ""
		musicLib.Unlock()
	}
}

type fileSource struct {
	f    *os.File
	size int64
}

func (s fileSource) ReadAt(p []byte, off int64) (int, error) { return s.f.ReadAt(p, off) }
func (s fileSource) Size() int64                             { return s.size }

func trackFromMeta(t *musicTrack, m musicMeta) {
	t.T, t.A, t.AA, t.B = m.Title, m.Artist, m.AlbumArtist, m.Album
	t.N, t.K, t.Y = m.Track, m.Disc, m.Year
	t.D = float64(int(m.Duration*10+0.5)) / 10
	t.C = 0
	if m.HasPic {
		t.C = 1
	}
}

func musicWalkDir(ctx context.Context, rs *musicRootState, prev func(string) *musicTrack) ([]musicTrack, map[string]string, error) {
	prog := &musicProgress{}
	prog.at(rs.conf.Path)
	defer musicAskWatch(rs, prog)()
	fi, err := os.Stat(rs.conf.Path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.IsDir() {
		return nil, nil, fs.ErrNotExist
	}
	root, err := os.OpenRoot(rs.conf.Path)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	fsys := root.FS()
	var tracks []musicTrack
	covers := map[string]string{}
	coverRank := map[string]int{}
	parsed := 0
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if p == "." {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if p != "." && (musicSkipDir(name) || strings.Count(p, "/") >= musicDepthMax) {
				return fs.SkipDir
			}
			// Read next, and where the system may stop to ask.
			prog.at(filepath.Join(rs.conf.Path, filepath.FromSlash(p)))
			return nil
		}
		prog.at("")
		dir := path.Dir(p)
		if rank := musicCoverRank(name); rank > 0 {
			if rank > coverRank[dir] {
				coverRank[dir] = rank
				covers[dir] = p
			}
			return nil
		}
		if musicMime(name) == "" || !musicRelOK(p) {
			return nil
		}
		info, err := fs.Stat(fsys, p) // follows a link that stays inside the root
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return nil
		}
		if len(tracks) >= musicTracksMax {
			return fs.SkipAll
		}
		t := musicTrack{P: p, S: info.Size(), M: info.ModTime().Unix()}
		if o := prev(p); o != nil && o.S == t.S && o.M == t.M {
			t = *o
		} else if f, err := root.Open(p); err == nil {
			trackFromMeta(&t, readMusicMeta(fileSource{f, t.S}, false))
			f.Close()
			parsed++
			// Gentle on a spinning disk and a small machine: a breath every
			// hundred files read.
			if parsed%100 == 0 {
				time.Sleep(20 * time.Millisecond)
			}
		}
		tracks = append(tracks, t)
		if len(tracks)%200 == 0 {
			musicNote(rs, len(tracks))
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, nil, err
	}
	musicCoverFill(tracks, covers)
	return tracks, covers, nil
}

// musicCoverFill marks the tracks with no picture of their own whose folder
// has one.
func musicCoverFill(tracks []musicTrack, covers map[string]string) {
	for i := range tracks {
		if tracks[i].C == 0 {
			if _, ok := covers[path.Dir(tracks[i].P)]; ok {
				tracks[i].C = 2
			}
		}
	}
}

func musicWalkDav(ctx context.Context, rs *musicRootState, prev func(string) *musicTrack) ([]musicTrack, map[string]string, error) {
	var tracks []musicTrack
	covers := map[string]string{}
	coverRank := map[string]int{}
	type job struct {
		i int
		t musicTrack
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				src := rs.dav.source(ctx, j.t.P, j.t.S)
				trackFromMeta(&j.t, readMusicMeta(src, false))
				mu.Lock()
				tracks[j.i] = j.t
				mu.Unlock()
			}
		}()
	}
	err := rs.dav.walk(ctx, func(e davEntry) error {
		name := path.Base(e.Rel)
		dir := path.Dir(e.Rel)
		if rank := musicCoverRank(name); rank > 0 {
			if rank > coverRank[dir] {
				coverRank[dir] = rank
				covers[dir] = e.Rel
			}
			return nil
		}
		if musicMime(name) == "" || e.Size <= 0 {
			return nil
		}
		mu.Lock()
		n := len(tracks)
		mu.Unlock()
		if n >= musicTracksMax {
			return fs.SkipAll
		}
		t := musicTrack{P: e.Rel, S: e.Size, M: e.Mod, E: e.ETag}
		if o := prev(e.Rel); o != nil && o.S == t.S && (o.E == t.E && t.E != "" || o.M == t.M && t.M != 0) {
			mu.Lock()
			tracks = append(tracks, *o)
			mu.Unlock()
			return nil
		}
		mu.Lock()
		tracks = append(tracks, t)
		i := len(tracks) - 1
		mu.Unlock()
		select {
		case jobs <- job{i: i, t: t}:
		case <-ctx.Done():
			return ctx.Err()
		}
		if i%100 == 0 {
			musicNote(rs, i)
		}
		return nil
	})
	close(jobs)
	wg.Wait()
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, nil, err
	}
	musicCoverFill(tracks, covers)
	return tracks, covers, nil
}

// ── what the tunnel serves ─────────────────────────────────────────────

type musicRootView struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Where    string `json:"where"`
	Tracks   int    `json:"tracks"`
	Rev      string `json:"rev"`
	Scanning bool   `json:"scanning,omitempty"`
	Seen     int    `json:"seen,omitempty"`
	Err      string `json:"err,omitempty"`
	At       int64  `json:"at,omitempty"`
	// The folder the walk waits on the system's question for, while it does.
	Ask string `json:"ask,omitempty"`
}

type musicStatusBody struct {
	On      bool            `json:"on"`
	Roots   []musicRootView `json:"roots"`
	ReadMax int             `json:"read_max"`
	// What a dashboard may add here: WebDAV folders, with a pinned key, and
	// this machine's own folders where the console is on as well ("dir").
	CanAdd []string `json:"can_add"`
}

type musicIndexBody struct {
	Root   string       `json:"root"`
	Rev    string       `json:"rev"`
	From   int          `json:"from"`
	Total  int          `json:"total"`
	Tracks []musicTrack `json:"tracks"`
	More   bool         `json:"more"`
}

// musicPeer is the gate every music route shares: a key on the allowlist —
// not a transfer guest, not a portable copy — on a machine that shares.
func (h *directHandler) musicPeer(w http.ResponseWriter, r *http.Request) bool {
	k, ok := transport.PeerFromContext(r.Context())
	if !ok {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return false
	}
	listed := false
	for _, a := range loadAllowedClients() {
		if a == k {
			listed = true
			break
		}
	}
	if !listed {
		h.refuseFor(w, r, http.StatusForbidden, "not-allowed")
		return false
	}
	if !musicOn() {
		h.refuse(w, http.StatusNotFound, "music-off")
		return false
	}
	// A config written at the keyboard a moment ago is acted on now, not at
	// the walker's next tick.
	musicReconcile()
	return true
}

func (h *directHandler) musicFrame(w http.ResponseWriter, r *http.Request, body any) {
	f, err := transport.New(transport.TypeMusic, agentID(), r.Header.Get("X-Request-Id"), body)
	var b []byte
	if err == nil {
		b, err = transport.Encode(f)
	}
	if err != nil {
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (h *directHandler) musicStatus(w http.ResponseWriter, r *http.Request) {
	if !h.musicPeer(w, r) {
		return
	}
	body := musicStatusBody{On: true, Roots: []musicRootView{}, ReadMax: musicReadMax, CanAdd: []string{}}
	if loadTrust().sealed {
		body.CanAdd = append(body.CanAdd, "webdav")
		if musicByConsole() {
			body.CanAdd = append(body.CanAdd, "dir")
		}
	}
	musicLib.Lock()
	for _, id := range musicLib.order {
		rs := musicLib.roots[id]
		if rs == nil {
			continue
		}
		body.Roots = append(body.Roots, musicRootView{
			ID: id, Kind: rs.conf.Kind, Name: rs.conf.label(), Where: rs.conf.where(),
			Tracks: len(rs.tracks), Rev: strconv.FormatUint(rs.rev, 10), Scanning: rs.scanning,
			Seen: rs.seen, Err: rs.err, At: rs.at, Ask: rs.ask,
		})
	}
	musicLib.Unlock()
	h.musicFrame(w, r, body)
}

func queryInt(r *http.Request, k string) int64 {
	s := strings.TrimSpace(r.URL.Query().Get(k))
	if s == "" || len(s) > 15 {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func (h *directHandler) musicIndex(w http.ResponseWriter, r *http.Request) {
	if !h.musicPeer(w, r) {
		return
	}
	id := r.URL.Query().Get("r")
	from64 := queryInt(r, "from")
	musicLib.Lock()
	rs := musicLib.roots[id]
	if rs == nil {
		musicLib.Unlock()
		h.refuse(w, http.StatusNotFound, "no-root")
		return
	}
	total := len(rs.tracks)
	// Compared before it is made an int: on a 32-bit int a large one wraps
	// negative, and the lock would be held through the panic.
	from := total
	if from64 < int64(total) {
		from = int(from64)
	}
	rev := strconv.FormatUint(rs.rev, 10)
	// The page's share of the frame: the envelope and the body's other
	// fields are well under the slack left here.
	budget := transport.Limits[transport.TypeMusic] - 8<<10
	if musicIndexBudget > 0 {
		budget = musicIndexBudget
	}
	var page []musicTrack
	used := 0
	i := from
	for ; i < total; i++ {
		t := rs.tracks[i]
		t.E = ""
		b, _ := json.Marshal(t)
		if used+len(b)+1 > budget && len(page) > 0 {
			break
		}
		used += len(b) + 1
		page = append(page, t)
	}
	musicLib.Unlock()
	if page == nil {
		page = []musicTrack{}
	}
	h.musicFrame(w, r, musicIndexBody{Root: id, Rev: rev, From: from, Total: total, Tracks: page, More: i < total})
}

// musicFind is the track a request names, and the root it is in, read under
// the lock and handed back as copies.
func (h *directHandler) musicFind(w http.ResponseWriter, r *http.Request) (musicRootConf, *davRoot, musicTrack, map[string]string, bool) {
	q := r.URL.Query()
	id, p := q.Get("r"), q.Get("p")
	if !musicRelOK(p) {
		h.refuse(w, http.StatusBadRequest, "bad-path")
		return musicRootConf{}, nil, musicTrack{}, nil, false
	}
	musicLib.Lock()
	defer musicLib.Unlock()
	rs := musicLib.roots[id]
	if rs == nil {
		h.refuse(w, http.StatusNotFound, "no-root")
		return musicRootConf{}, nil, musicTrack{}, nil, false
	}
	i, ok := rs.byPath[p]
	if !ok || i >= len(rs.tracks) {
		h.refuse(w, http.StatusNotFound, "no-track")
		return musicRootConf{}, nil, musicTrack{}, nil, false
	}
	cover := map[string]string{}
	if c, ok := rs.covers[path.Dir(p)]; ok {
		cover[path.Dir(p)] = c
	}
	return rs.conf, rs.dav, rs.tracks[i], cover, true
}

// musicIndexBudget, when set, replaces the frame's share for a page of
// tracks: the tests' way to see more than one page without ten thousand files.
var musicIndexBudget = 0

var musicReads = make(chan struct{}, musicReadsMax)

func (h *directHandler) musicFile(w http.ResponseWriter, r *http.Request) {
	if !h.musicPeer(w, r) {
		return
	}
	conf, dav, t, _, ok := h.musicFind(w, r)
	if !ok {
		return
	}
	off, n := queryInt(r, "o"), queryInt(r, "n")
	if off >= t.S {
		h.refuse(w, http.StatusRequestedRangeNotSatisfiable, "out-of-range")
		return
	}
	if n <= 0 || n > musicReadMax {
		n = musicReadMax
	}
	if off+n > t.S {
		n = t.S - off
	}
	select {
	case musicReads <- struct{}{}:
		defer func() { <-musicReads }()
	case <-r.Context().Done():
		return
	case <-time.After(20 * time.Second):
		h.refuse(w, http.StatusServiceUnavailable, "busy")
		return
	}
	var src io.Reader
	switch conf.Kind {
	case "dir":
		root, err := os.OpenRoot(conf.Path)
		if err != nil {
			h.refuse(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		defer root.Close()
		f, err := root.Open(t.P)
		if err != nil {
			h.refuse(w, http.StatusNotFound, "no-track")
			return
		}
		defer f.Close()
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			h.refuse(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		src = f
	case "webdav":
		if dav == nil {
			h.refuse(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		// The body on a clock of its own: a server that sends its headers and
		// then stalls would hold one of the reads above with it.
		dctx, cancel := context.WithTimeout(r.Context(), 2*davTimeout)
		defer cancel()
		rc, _, err := dav.get(dctx, t.P, off, n)
		if err != nil {
			h.refuse(w, http.StatusBadGateway, musicErrCode(err))
			return
		}
		defer rc.Close()
		src = rc
	default:
		h.refuse(w, http.StatusNotFound, "no-root")
		return
	}
	// Read whole before anything is sent (n is at most musicReadMax): a file
	// that changed since its walk comes up short, and a short answer under a
	// 200 would be taken for the track.
	buf := make([]byte, n)
	if _, err := io.ReadFull(src, buf); err != nil {
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			if conf.Kind == "webdav" {
				h.refuse(w, http.StatusBadGateway, musicErrCode(err))
			} else {
				h.refuse(w, http.StatusServiceUnavailable, "unavailable")
			}
			return
		}
		musicLib.Lock()
		if rs := musicLib.roots[conf.ID]; rs != nil {
			rs.due = true
		}
		musicLib.Unlock()
		musicWake()
		h.refuse(w, http.StatusConflict, "changed")
		return
	}
	w.Header().Set("Content-Type", musicMime(t.P))
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}

// ── covers ─────────────────────────────────────────────────────────────

var musicArtLRU = struct {
	sync.Mutex
	order []string
	items map[string]musicArtItem
	bytes int
}{items: map[string]musicArtItem{}}

type musicArtItem struct {
	mime string
	data []byte
}

func musicArtGet(k string) (musicArtItem, bool) {
	musicArtLRU.Lock()
	defer musicArtLRU.Unlock()
	it, ok := musicArtLRU.items[k]
	return it, ok
}

func musicArtPut(k string, it musicArtItem) {
	musicArtLRU.Lock()
	defer musicArtLRU.Unlock()
	if _, ok := musicArtLRU.items[k]; ok || len(it.data) > musicArtCache/4 {
		return
	}
	musicArtLRU.items[k] = it
	musicArtLRU.order = append(musicArtLRU.order, k)
	musicArtLRU.bytes += len(it.data)
	for musicArtLRU.bytes > musicArtCache && len(musicArtLRU.order) > 0 {
		old := musicArtLRU.order[0]
		musicArtLRU.order = musicArtLRU.order[1:]
		musicArtLRU.bytes -= len(musicArtLRU.items[old].data)
		delete(musicArtLRU.items, old)
	}
}

var musicArtGate = make(chan struct{}, 2)

func (h *directHandler) musicArt(w http.ResponseWriter, r *http.Request) {
	if !h.musicPeer(w, r) {
		return
	}
	conf, dav, t, cover, ok := h.musicFind(w, r)
	if !ok {
		return
	}
	px := int(queryInt(r, "w"))
	switch {
	case px <= 0:
		px = 512
	case px <= 128:
		px = 128
	case px <= 256:
		px = 256
	case px <= 512:
		px = 512
	default:
		px = 1024
	}
	key := conf.ID + "\n" + t.P + "\n" + strconv.FormatInt(t.M, 10) + "\n" + strconv.Itoa(px)
	if it, ok := musicArtGet(key); ok {
		musicArtSend(w, it)
		return
	}
	select {
	case musicArtGate <- struct{}{}:
		defer func() { <-musicArtGate }()
	case <-r.Context().Done():
		return
	}
	raw, mime := musicArtRaw(r.Context(), conf, dav, t, cover)
	if raw == nil {
		h.refuse(w, http.StatusNotFound, "no-art")
		return
	}
	it := musicArtScale(raw, mime, px)
	if it.data == nil {
		h.refuse(w, http.StatusNotFound, "no-art")
		return
	}
	musicArtPut(key, it)
	musicArtSend(w, it)
}

func musicArtSend(w http.ResponseWriter, it musicArtItem) {
	w.Header().Set("Content-Type", it.mime)
	w.Header().Set("Content-Length", strconv.Itoa(len(it.data)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(it.data)
}

// musicArtRaw is the picture in the file, else the one in its folder.
func musicArtRaw(ctx context.Context, conf musicRootConf, dav *davRoot, t musicTrack, cover map[string]string) ([]byte, string) {
	var root *os.Root
	if conf.Kind == "dir" {
		var err error
		if root, err = os.OpenRoot(conf.Path); err != nil {
			return nil, ""
		}
		defer root.Close()
	}
	if t.C == 1 {
		var m musicMeta
		switch {
		case root != nil:
			if f, err := root.Open(t.P); err == nil {
				m = readMusicMeta(fileSource{f, t.S}, true)
				f.Close()
			}
		case dav != nil:
			m = readMusicMeta(dav.source(ctx, t.P, t.S), true)
		}
		if m.Pic != nil {
			return m.Pic.Data, m.Pic.Mime
		}
	}
	c, ok := cover[path.Dir(t.P)]
	if !ok {
		return nil, ""
	}
	var b []byte
	switch {
	case root != nil:
		f, err := root.Open(c)
		if err != nil {
			return nil, ""
		}
		b, _ = io.ReadAll(io.LimitReader(f, musicArtMax+1))
		f.Close()
	case dav != nil:
		dctx, cancel := context.WithTimeout(ctx, 2*davTimeout)
		defer cancel()
		rc, _, err := dav.get(dctx, c, 0, 0)
		if err != nil {
			return nil, ""
		}
		b, _ = io.ReadAll(io.LimitReader(rc, musicArtMax+1))
		rc.Close()
	}
	if len(b) == 0 || len(b) > musicArtMax {
		return nil, ""
	}
	m := sniffImage(b)
	if m == "" {
		return nil, ""
	}
	return b, m
}

// musicArtScale fits a cover into px × px as a JPEG. A picture already that
// small, or one this build cannot decode (WebP), is passed on as it is when
// it is not too large to send.
func musicArtScale(raw []byte, mime string, px int) musicArtItem {
	pass := musicArtItem{mime: mime, data: raw}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		if len(raw) <= 2<<20 {
			return pass
		}
		return musicArtItem{}
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > musicArtPixels {
		if len(raw) <= 2<<20 {
			return pass
		}
		return musicArtItem{}
	}
	if cfg.Width <= px && cfg.Height <= px && len(raw) <= 1<<20 {
		return pass
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return musicArtItem{}
	}
	out := musicDownscale(img, px)
	var buf bytes.Buffer
	if jpeg.Encode(&buf, out, &jpeg.Options{Quality: 84}) != nil {
		return musicArtItem{}
	}
	return musicArtItem{mime: "image/jpeg", data: buf.Bytes()}
}

// musicDownscale averages the source over each destination pixel's box.
func musicDownscale(src image.Image, px int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	dw, dh := sw, sh
	if sw > px || sh > px {
		if sw >= sh {
			dw, dh = px, sh*px/sw
		} else {
			dw, dh = sw*px/sh, px
		}
	}
	if dw < 1 {
		dw = 1
	}
	if dh < 1 {
		dh = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		y0, y1 := b.Min.Y+y*sh/dh, b.Min.Y+(y+1)*sh/dh
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < dw; x++ {
			x0, x1 := b.Min.X+x*sw/dw, b.Min.X+(x+1)*sw/dw
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var rr, gg, bb, aa, n uint64
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					cr, cg, cb, ca := src.At(xx, yy).RGBA()
					rr, gg, bb, aa = rr+uint64(cr), gg+uint64(cg), bb+uint64(cb), aa+uint64(ca)
					n++
				}
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(rr / n >> 8), uint8(gg / n >> 8), uint8(bb / n >> 8), uint8(aa / n >> 8)})
		}
	}
	return dst
}

// ── the command ────────────────────────────────────────────────────────

// runMusicCommand changes what is shared, for a dashboard whose key this
// machine pinned, over the tunnel alone (mailboxRefusal). The op is the
// command's target and its arguments are the line, both under the signature:
//
//	add-webdav  {"url","user","pass","name","pin"}  → out: the new root's id
//	remove      {"id"}
//	rescan      {"id"} (or {} for every root)
//	browse      {"path"} ("" for the places)  → out: a folder's listing (musicBrowseBody)
//	add-dir     {"path","name"}               → out: the new root's id
//
// The last two only where the console is on: see the top of this file.
//
// musicConfMu serialises this process's changes to music.json: the WebDAV
// probe takes seconds, and the configuration is read again after it.
var musicConfMu sync.Mutex

func runMusicCommand(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: "music", Target: c.Target, Code: -1}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	if !musicOn() {
		res.Error = "music-off"
		return res
	}
	var arg struct {
		ID   string `json:"id"`
		Path string `json:"path"`
		URL  string `json:"url"`
		User string `json:"user"`
		Pass string `json:"pass"`
		Name string `json:"name"`
		Pin  string `json:"pin"`
	}
	if c.Cmd != "" && json.Unmarshal([]byte(c.Cmd), &arg) != nil {
		res.Error = "bad-args"
		return res
	}
	conf := loadMusicConf()
	switch c.Target {
	case "add-webdav":
		if len(conf.Roots) >= musicRootsMax {
			res.Error = "too-many"
			return res
		}
		if len(arg.User) > 256 || len(arg.Pass) > 1024 || len(arg.Name) > 120 {
			res.Error = "bad-args"
			return res
		}
		d, err := newDav(arg.URL, arg.User, arg.Pass, arg.Pin)
		if err != nil {
			res.Error = musicErrCode(err)
			return res
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		err = d.probe(ctx)
		cancel()
		if err != nil {
			res.Error = musicErrCode(err)
			var de *davError
			if errors.As(err, &de) && de.Code == "cert-untrusted" {
				res.Out = de.Detail
			}
			return res
		}
		// The probe took its time: music may have been switched off, or a
		// folder taken away, at the keyboard meanwhile. The change goes into
		// the configuration as it is now, not as it was read before.
		musicConfMu.Lock()
		defer musicConfMu.Unlock()
		conf = loadMusicConf()
		if !musicOnConf(conf) {
			res.Error = "music-off"
			return res
		}
		if len(conf.Roots) >= musicRootsMax {
			res.Error = "too-many"
			return res
		}
		for _, r := range conf.Roots {
			if r.Kind == "webdav" && r.URL == d.base.String() && r.User == arg.User {
				res.Error = "already-shared"
				res.Out = r.ID
				return res
			}
		}
		r := musicRootConf{ID: musicNewID(), Kind: "webdav", URL: d.base.String(), User: arg.User, Pass: arg.Pass,
			Pin: d.pin, Name: cleanTag(arg.Name)}
		conf.Roots = append(conf.Roots, r)
		if err := saveMusicConf(conf); err != nil {
			res.Error = "save-failed"
			return res
		}
		res.Code, res.Out = 0, r.ID
	case "remove":
		musicConfMu.Lock()
		defer musicConfMu.Unlock()
		conf = loadMusicConf()
		kept := conf.Roots[:0:0]
		found := false
		for _, r := range conf.Roots {
			if r.ID == arg.ID {
				found = true
				continue
			}
			kept = append(kept, r)
		}
		if !found {
			res.Error = "no-root"
			return res
		}
		conf.Roots = kept
		if err := saveMusicConf(conf); err != nil {
			res.Error = "save-failed"
			return res
		}
		res.Code = 0
	case "browse":
		if !musicByConsole() {
			res.Error = "console-off"
			return res
		}
		body, code := musicBrowseWithin(arg.Path, musicBrowseWait)
		if code != "" {
			res.Error = code
			return res
		}
		b, err := json.Marshal(body)
		if err != nil {
			res.Error = "unavailable"
			return res
		}
		res.Code, res.Out = 0, string(b)
		// Nothing changed: no reconcile, no wake.
		return res
	case "add-dir":
		if !musicByConsole() {
			res.Error = "console-off"
			return res
		}
		if len(arg.Name) > 120 {
			res.Error = "bad-args"
			return res
		}
		// The folder is looked at on the clock browse runs on, and so are
		// the folders shared now, for where their links lead: the command
		// gate is held while this runs, and any of them may sit on a disk
		// that went away.
		type dirPlan struct {
			p, real string
			reals   map[string]string
		}
		plan, code := musicWithin(musicBrowseWait, "add-dir\n"+arg.Path, func() bool { return musicGuardedLinks(arg.Path) }, func() (dirPlan, string) {
			p, real, code := musicDirArg(arg.Path)
			if code != "" {
				return dirPlan{}, code
			}
			pl := dirPlan{p: p, real: real, reals: map[string]string{}}
			for _, r := range loadMusicConf().Roots {
				if r.Kind == "dir" {
					pl.reals[r.Path] = musicReal(r.Path)
				}
			}
			return pl, ""
		})
		if code != "" {
			res.Error = code
			return res
		}
		realOf := func(p string) string {
			if r, ok := plan.reals[p]; ok {
				return r
			}
			return p
		}
		musicConfMu.Lock()
		defer musicConfMu.Unlock()
		conf = loadMusicConf()
		if !musicOnConf(conf) {
			res.Error = "music-off"
			return res
		}
		// A folder inside one already shared would list its tracks twice;
		// one around folders already shared takes their place. Both as the
		// walk sees them: it does not follow a link to a folder inside a
		// shared one, and it follows a shared folder that is a link.
		kept := conf.Roots[:0:0]
		for _, r := range conf.Roots {
			if r.Kind == "dir" && (r.Path == plan.p || musicPathWithin(plan.real, realOf(r.Path))) {
				res.Error, res.Out = "already-shared", r.ID
				return res
			}
			if r.Kind == "dir" && musicPathWithin(realOf(r.Path), plan.real) {
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) >= musicRootsMax {
			res.Error = "too-many"
			return res
		}
		r := musicRootConf{ID: musicNewID(), Kind: "dir", Path: plan.p, Name: cleanTag(arg.Name)}
		conf.Roots = append(kept, r)
		if err := saveMusicConf(conf); err != nil {
			res.Error = "save-failed"
			return res
		}
		res.Code, res.Out = 0, r.ID
	case "rescan":
		musicReconcile()
		musicLib.Lock()
		hit := false
		for id, rs := range musicLib.roots {
			if arg.ID == "" || arg.ID == id {
				rs.due, hit = true, true
			}
		}
		musicLib.Unlock()
		if !hit {
			res.Error = "no-root"
			return res
		}
		res.Code = 0
	default:
		res.Error = "unknown-op"
		return res
	}
	musicReconcile()
	musicWake()
	return res
}

// ── at the keyboard ────────────────────────────────────────────────────

func runMusicCLI(args []string) int {
	conf := loadMusicConf()
	verb := ""
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}
	save := func() int {
		if err := saveMusicConf(conf); err != nil {
			warnf("could not save the music settings: %v", err)
			return 1
		}
		return -1
	}
	addDir := func(p string) bool {
		abs, err := filepath.Abs(p)
		if err != nil {
			warnf("%s: %v", p, err)
			return false
		}
		fi, err := os.Stat(abs)
		if err != nil || !fi.IsDir() {
			warnf("%s is not a folder on this machine", abs)
			return false
		}
		for _, r := range conf.Roots {
			if r.Kind == "dir" && r.Path == abs {
				fmt.Printf("already shared: %s\n", homeTilde(abs))
				return true
			}
		}
		if len(conf.Roots) >= musicRootsMax {
			warnf("at most %d folders can be shared", musicRootsMax)
			return false
		}
		conf.Roots = append(conf.Roots, musicRootConf{ID: musicNewID(), Kind: "dir", Path: abs})
		fmt.Printf("sharing %s\n", homeTilde(abs))
		return true
	}
	switch verb {
	case "", "status":
	case "on":
		// On, and nothing more: no folder is shared, or read, until one is
		// named — here, or chosen on a page where the console is on.
		conf.On, conf.Off = true, false
		for _, a := range args {
			if !addDir(a) {
				return 1
			}
		}
		if rc := save(); rc >= 0 {
			return rc
		}
	case "off":
		conf.On, conf.Off = false, true
		if rc := save(); rc >= 0 {
			return rc
		}
		if musicByConsole() {
			fmt.Println("note: the console is on, so a dashboard could switch it back on through a line; 'console off' is what takes that away")
		}
	case "add":
		if len(args) == 0 {
			warnf("say 'music add <folder>'")
			return 2
		}
		for _, a := range args {
			if !addDir(a) {
				return 1
			}
		}
		if !musicOnConf(conf) {
			fmt.Println("note: music is off; 'subnsub-monitor music on' shares what is listed")
		}
		if rc := save(); rc >= 0 {
			return rc
		}
	case "add-webdav":
		return runMusicDavCLI(&conf, args)
	case "remove":
		if len(args) != 1 {
			warnf("say 'music remove <id, folder or URL>' — 'music' lists them")
			return 2
		}
		want := args[0]
		abs, _ := filepath.Abs(want)
		kept := conf.Roots[:0:0]
		for _, r := range conf.Roots {
			if r.ID == want || r.Kind == "dir" && r.Path == abs || r.Kind == "webdav" && strings.TrimSuffix(r.URL, "/") == strings.TrimSuffix(want, "/") {
				fmt.Printf("no longer sharing %s\n", r.where())
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == len(conf.Roots) {
			warnf("nothing shared matches %s", want)
			return 1
		}
		conf.Roots = kept
		if rc := save(); rc >= 0 {
			return rc
		}
	case "rescan":
		conf.Rescan = time.Now().UnixNano()
		if rc := save(); rc >= 0 {
			return rc
		}
		fmt.Println("the running helper reads every shared folder again within a few seconds")
	default:
		warnf("usage: subnsub-monitor music [on [FOLDER...] | off | add FOLDER... | add-webdav URL [--user NAME] [--name LABEL] [--pin sha256:HEX] | remove ID | rescan]")
		return 2
	}
	on := musicOnConf(conf)
	switch {
	case on && !conf.On:
		fmt.Printf("on   (%s) by the console: a dashboard that may run lines here may read these files anyway\n", agentID())
	case on:
		fmt.Printf("on   (%s)\n", agentID())
	default:
		fmt.Printf("off  (%s)\n", agentID())
	}
	if on {
		fmt.Println("browsers on this machine's direct allowlist can play what is listed, over the tailnet or the tailcat tunnel only")
		if musicByConsole() {
			fmt.Println("with the console on, a dashboard whose key is pinned here may also look through this machine's folders and share one")
		}
	}
	saved := musicLoadSaved()
	for _, r := range conf.Roots {
		n := "not read yet"
		if s := saved[r.ID]; s != nil && s.Sig == r.sig() {
			n = fmt.Sprintf("%d tracks", len(s.Tracks))
		}
		fmt.Printf("  %s  %-6s  %s  (%s)\n", r.ID, r.Kind, r.where(), n)
	}
	if len(conf.Roots) == 0 {
		switch {
		case musicByConsole():
			fmt.Println("nothing shared, and nothing read: choose a folder on the Monitor page, or 'subnsub-monitor music add <folder>' here")
		default:
			fmt.Println("nothing shared, and nothing read: 'subnsub-monitor music add <folder>' names one")
		}
	}
	return 0
}

func runMusicDavCLI(conf *musicConf, args []string) int {
	var raw, user, name, pin string
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--user":
			user = next()
		case "--name":
			name = next()
		case "--pin":
			pin = next()
		default:
			if raw != "" || strings.HasPrefix(args[i], "--") {
				warnf("unexpected argument: %s", args[i])
				return 2
			}
			raw = args[i]
		}
	}
	if raw == "" {
		warnf("say 'music add-webdav <URL> [--user NAME]'; the password comes from MON_WEBDAV_PASSWORD or is asked for")
		return 2
	}
	pass, hasPass := os.LookupEnv("MON_WEBDAV_PASSWORD")
	if !hasPass && user != "" && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			warnf("could not read the password: %v", err)
			return 1
		}
		pass = string(b)
	}
	d, err := newDav(raw, user, pass, pin)
	if err != nil {
		warnf("%s", musicErrCode(err))
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	err = d.probe(ctx)
	cancel()
	if err != nil {
		var de *davError
		if errors.As(err, &de) && de.Code == "cert-untrusted" && de.Detail != "" {
			warnf("this server's certificate is not one the system trusts. Its fingerprint is\n  %s\nIf that is the server you meant, run the same line again with --pin %s", de.Detail, de.Detail)
			return 1
		}
		warnf("could not list that folder: %s", musicErrCode(err))
		return 1
	}
	if len(conf.Roots) >= musicRootsMax {
		warnf("at most %d folders can be shared", musicRootsMax)
		return 1
	}
	conf.Roots = append(conf.Roots, musicRootConf{ID: musicNewID(), Kind: "webdav", URL: d.base.String(), User: user, Pass: pass, Pin: d.pin, Name: name})
	if !musicOnConf(*conf) {
		fmt.Println("note: music is off; 'subnsub-monitor music on' shares what is listed")
	}
	if err := saveMusicConf(*conf); err != nil {
		warnf("could not save the music settings: %v", err)
		return 1
	}
	fmt.Printf("sharing %s\n", d.where())
	return 0
}
