package main

// photos.go — the pictures in the folders chosen on this machine, for the
// Photos tab: which folders, every picture in them with when and where it
// was taken (photosmeta.go), and small copies to show (photosthumb.go).
//
// Who decides what is read is as for music (music.go), and for the same
// reasons:
//
//   - Nothing is read until a person chooses a folder. There is no default:
//     photos switched on with nothing chosen shares nothing.
//   - A machine whose console is on and which has pinned a dashboard key has
//     photos on without being asked: that dashboard may already run any line
//     here as this account. Its page may look through the folders when
//     somebody opens them there, and share the one chosen (browse, add).
//   - Elsewhere the folders are chosen here: `subnsub-helper photos add
//     <dir>`, after `photos on`. A pinned dashboard may take one away or
//     have it read again, and nothing more.
//   - `photos off` at the keyboard, or MON_PHOTOS=off, wins over both.
//
// The roads are the direct ones alone, as for music: no route here is
// reachable from the mailbox, and the `photos` command kind is refused there
// (mailboxRefusal). The page reads:
//
//	GET /v1/photos                    which folders, how many pictures, reading or not
//	GET /v1/photos/index?r=ID&from=N  one page of a folder's pictures
//	GET /v1/photos/thumb?r=ID&p=PATH&s=PX  a small copy, PX on its long side, upright
//
// A path is answered only when it is a picture in the folder's own index,
// and the reads go through os.Root besides. Moving, renaming and deleting
// pictures are the Files tab's own commands (fileswrite.go), under the
// console's grant; nothing here writes to a folder that was chosen.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"
)

const (
	photosConfFile  = "photos.json"
	photosIndexFile = "photos-index.json"
	photosEnvVar    = "MON_PHOTOS"
	photosRootsMax  = 16
	photosPerRoot   = 200000
	photosDepthMax  = 24
	photosEvery     = 30 * time.Minute
	// Smaller than this, by bytes or on its long side, is an icon or a
	// button, not a photo.
	photosMinBytes = 2 << 10
	photosMinSide  = 160
)

// The pictures shown, by extension.
var photosExt = map[string]bool{
	".jpg": true, ".jpeg": true, ".jpe": true, ".png": true, ".gif": true, ".webp": true,
	".heic": true, ".heif": true, ".hif": true, ".avif": true, ".tif": true, ".tiff": true,
}

func photosIsPic(name string) bool {
	return photosExt[strings.ToLower(path.Ext(name))]
}

// ── configuration ──────────────────────────────────────────────────────

type photosRootConf struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
}

type photosConf struct {
	V      int              `json:"v"`
	On     bool             `json:"on"`
	Off    bool             `json:"off,omitempty"`
	Rescan int64            `json:"rescan,omitempty"`
	Roots  []photosRootConf `json:"roots"`
}

func photosConfPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, photosConfFile)
}

var photosConfCache struct {
	sync.Mutex
	mod  time.Time
	size int64
	conf photosConf
	ok   bool
}

func loadPhotosConf() photosConf {
	p := photosConfPath()
	if p == "" {
		return photosConf{}
	}
	fi, err := os.Stat(p)
	photosConfCache.Lock()
	defer photosConfCache.Unlock()
	if err != nil {
		photosConfCache.ok = false
		return photosConf{}
	}
	if photosConfCache.ok && fi.ModTime().Equal(photosConfCache.mod) && fi.Size() == photosConfCache.size {
		return photosConfCache.conf
	}
	b, err := os.ReadFile(p)
	var c photosConf
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, &c) != nil {
		// Unreadable is off: see loadMusicConf.
		c = photosConf{Off: true}
	}
	var kept []photosRootConf
	seen := map[string]bool{}
	for _, r := range c.Roots {
		if r.ID == "" || len(r.ID) > 32 || seen[r.ID] || len(kept) >= photosRootsMax || r.Path == "" || !filepath.IsAbs(r.Path) {
			continue
		}
		seen[r.ID] = true
		kept = append(kept, r)
	}
	c.Roots = kept
	photosConfCache.mod, photosConfCache.size, photosConfCache.conf, photosConfCache.ok = fi.ModTime(), fi.Size(), c, true
	return c
}

func savePhotosConf(c photosConf) error {
	p := photosConfPath()
	if p == "" {
		return errString("no config directory")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	c.V = 1
	if c.Roots == nil {
		c.Roots = []photosRootConf{}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(p, append(b, '\n')); err != nil {
		return err
	}
	os.Chmod(p, 0o600)
	return nil
}

func photosEnvOff() bool {
	v, ok := os.LookupEnv(photosEnvVar)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "false", "no":
		return true
	}
	return false
}

func photosOnConf(c photosConf) bool {
	if photosEnvOff() || c.Off {
		return false
	}
	return c.On || musicByConsole()
}

func photosOn() bool { return photosOnConf(loadPhotosConf()) }

func (r photosRootConf) label() string {
	if r.Name != "" {
		return r.Name
	}
	return filepath.Base(r.Path)
}

// photosSkipDir: what music's walk leaves out, and the trees where an
// account's programs keep their own pictures.
func photosSkipDir(name, abs string) bool {
	if musicSkipDir(name) {
		return true
	}
	switch strings.ToLower(name) {
	case "appdata", "$recycle.bin", "@eadir", ".thumbnails", "thumbs.db":
		return true
	case "library":
		if home, err := os.UserHomeDir(); err == nil && filepath.Dir(abs) == home {
			return true
		}
	}
	return false
}

// photosDirTooBroad: music's, and the home folder itself — a walk of every
// program's pictures, and on macOS of every guarded folder at once, is not
// a choice of where the photos are.
func photosDirTooBroad(p string) bool {
	if musicDirTooBroad(p) {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" && filepath.Clean(home) == p {
		return true
	}
	return false
}

// ── the index ──────────────────────────────────────────────────────────

// photoLine is one picture. Short keys: a page of thousands crosses the
// tunnel. Comparable, for telling whether a walk changed anything.
type photoLine struct {
	P  string  `json:"p"`            // path under the folder, '/' between
	S  int64   `json:"s"`            // size in bytes
	M  int64   `json:"m"`            // modified, Unix seconds
	T  int64   `json:"t"`            // taken, Unix seconds (modified, where it does not say)
	Z  int     `json:"z"`            // the offset where it was taken, minutes
	W  int     `json:"w,omitempty"`  // as stored
	H  int     `json:"h,omitempty"`  //
	O  int     `json:"o,omitempty"`  // EXIF orientation, where not 1
	La float64 `json:"la,omitempty"` // where
	Lo float64 `json:"lo,omitempty"` //
	C  string  `json:"c,omitempty"`  // the camera
}

type photosRootState struct {
	conf     photosRootConf
	photos   []photoLine
	byPath   map[string]int
	rev      uint64
	at       int64
	scanning bool
	seen     int
	err      string
	due      bool
	cancel   context.CancelFunc
	ask      string
}

type photosSavedRoot struct {
	Rev    uint64      `json:"rev"`
	At     int64       `json:"at"`
	Sig    string      `json:"sig"`
	Photos []photoLine `json:"photos"`
}

type photosSaved struct {
	V     int                         `json:"v"`
	Roots map[string]*photosSavedRoot `json:"roots"`
}

var photoLib = struct {
	sync.Mutex
	roots      map[string]*photosRootState
	order      []string
	rescan     int64
	rescanSeen bool
	saved      map[string]*photosSavedRoot
	loaded     bool
	wake       chan struct{}
}{roots: map[string]*photosRootState{}, wake: make(chan struct{}, 1)}

var photosOnce sync.Once

// photosStart runs the walker for this process's life, from the first time
// the direct roads come up (runDirect).
func photosStart() {
	photosOnce.Do(func() { go photosLoop() })
}

func photosWake() {
	select {
	case photoLib.wake <- struct{}{}:
	default:
	}
}

func (r photosRootConf) sig() string { return "dir:" + r.Path }

func photosIndexPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, photosIndexFile)
}

func photosLoadSaved() map[string]*photosSavedRoot {
	p := photosIndexPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 512<<20 {
		return nil
	}
	var s photosSaved
	if json.Unmarshal(b, &s) != nil || s.V != 1 {
		return nil
	}
	return s.Roots
}

func photosSave() {
	p := photosIndexPath()
	if p == "" {
		return
	}
	photoLib.Lock()
	s := photosSaved{V: 1, Roots: map[string]*photosSavedRoot{}}
	for id, rs := range photoLib.roots {
		if rs.at == 0 {
			continue
		}
		s.Roots[id] = &photosSavedRoot{Rev: rs.rev, At: rs.at, Sig: rs.conf.sig(), Photos: rs.photos}
	}
	b, err := json.Marshal(s)
	photoLib.Unlock()
	if err != nil {
		return
	}
	if err := writeFileAtomic(p, b); err != nil {
		warnf("photos: could not save the index: %v", err)
	}
}

// photosReconcile brings the library in line with the configuration.
func photosReconcile() {
	c := loadPhotosConf()
	on := photosOnConf(c)
	photoLib.Lock()
	defer photoLib.Unlock()
	if !photoLib.loaded {
		photoLib.saved, photoLib.loaded = photosLoadSaved(), true
	}
	want := map[string]photosRootConf{}
	order := []string{}
	if on {
		for _, r := range c.Roots {
			want[r.ID] = r
			order = append(order, r.ID)
		}
	}
	for id, rs := range photoLib.roots {
		if w, ok := want[id]; !ok || w.sig() != rs.conf.sig() {
			if rs.cancel != nil {
				rs.cancel()
			}
			delete(photoLib.roots, id)
		}
	}
	for _, id := range order {
		r := want[id]
		if rs, ok := photoLib.roots[id]; ok {
			rs.conf.Name = r.Name
			continue
		}
		rs := &photosRootState{conf: r, byPath: map[string]int{}, due: true, rev: uint64(time.Now().UnixNano())}
		if s := photoLib.saved[id]; s != nil && s.Sig == r.sig() {
			rs.photos, rs.rev, rs.at = s.Photos, s.Rev, s.At
			rs.reindex()
		}
		delete(photoLib.saved, id)
		photoLib.roots[id] = rs
	}
	photoLib.order = order
	if !photoLib.rescanSeen {
		photoLib.rescan, photoLib.rescanSeen = c.Rescan, true
	} else if c.Rescan > photoLib.rescan {
		for _, rs := range photoLib.roots {
			rs.due = true
		}
		photoLib.rescan = c.Rescan
	}
}

func (rs *photosRootState) reindex() {
	rs.byPath = make(map[string]int, len(rs.photos))
	for i, t := range rs.photos {
		rs.byPath[t.P] = i
	}
}

func photosNextDue(now time.Time) *photosRootState {
	photoLib.Lock()
	defer photoLib.Unlock()
	for _, id := range photoLib.order {
		rs := photoLib.roots[id]
		if rs == nil || rs.scanning {
			continue
		}
		if rs.due || now.Unix()-rs.at >= int64(photosEvery/time.Second) {
			rs.due, rs.scanning, rs.seen = false, true, 0
			return rs
		}
	}
	return nil
}

func photosLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		photosReconcile()
		if rs := photosNextDue(time.Now()); rs != nil {
			photosWalk(rs)
			continue
		}
		select {
		case <-photoLib.wake:
		case <-t.C:
		}
	}
}

func photosWalk(rs *photosRootState) {
	ctx, cancel := context.WithCancel(context.Background())
	photoLib.Lock()
	rs.cancel = cancel
	old, oldPhotos := rs.byPath, rs.photos
	photoLib.Unlock()
	defer cancel()
	prev := func(p string) *photoLine {
		if i, ok := old[p]; ok && i < len(oldPhotos) {
			t := oldPhotos[i]
			return &t
		}
		return nil
	}
	photos, err := photosWalkDir(ctx, rs, prev)
	sort.Slice(photos, func(i, j int) bool { return photos[i].P < photos[j].P })

	photoLib.Lock()
	rs.scanning, rs.cancel = false, nil
	if photoLib.roots[rs.conf.ID] != rs || ctx.Err() != nil {
		photoLib.Unlock()
		return
	}
	rs.at = time.Now().Unix()
	if err != nil {
		// A folder not there right now keeps what it had.
		rs.err = musicErrCode(err)
		photoLib.Unlock()
		return
	}
	rs.err = ""
	changed := len(photos) != len(oldPhotos)
	for i := 0; !changed && i < len(photos); i++ {
		changed = photos[i] != oldPhotos[i]
	}
	if changed {
		rs.photos = photos
		rs.rev++
		rs.reindex()
	}
	photoLib.Unlock()
	photosSave()
}

func photosNote(rs *photosRootState, seen int) {
	photoLib.Lock()
	rs.seen = seen
	photoLib.Unlock()
}

// photosAskWatch is musicAskWatch for a folder of pictures.
func photosAskWatch(rs *photosRootState, prog *musicProgress) func() {
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
			photoLib.Lock()
			select {
			case <-done:
			default:
				rs.ask = ask
			}
			photoLib.Unlock()
		}
	}()
	return func() {
		close(done)
		photoLib.Lock()
		rs.ask = ""
		photoLib.Unlock()
	}
}

// photoFromMeta fills a line from what the picture says, and its time from
// the file where the picture does not say.
func photoFromMeta(t *photoLine, m photoMeta) {
	t.W, t.H, t.O = m.W, m.H, m.O
	if t.O == 1 {
		t.O = 0
	}
	t.La, t.Lo, t.C = 0, 0, m.Cam
	if m.GPS {
		t.La, t.Lo = m.La, m.Lo
	}
	if m.T != 0 {
		t.T, t.Z = m.T, m.Z
		return
	}
	t.T = t.M
	_, z := time.Unix(t.M, 0).Zone()
	t.Z = z / 60
}

func photosWalkDir(ctx context.Context, rs *photosRootState, prev func(string) *photoLine) ([]photoLine, error) {
	prog := &musicProgress{}
	prog.at(rs.conf.Path)
	defer photosAskWatch(rs, prog)()
	fi, err := os.Stat(rs.conf.Path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fs.ErrNotExist
	}
	root, err := os.OpenRoot(rs.conf.Path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fsys := root.FS()
	var out []photoLine
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
			abs := filepath.Join(rs.conf.Path, filepath.FromSlash(p))
			if p != "." && (photosSkipDir(name, abs) || strings.Count(p, "/") >= photosDepthMax) {
				return fs.SkipDir
			}
			prog.at(abs)
			return nil
		}
		prog.at("")
		if !photosIsPic(name) || !musicRelOK(p) {
			return nil
		}
		info, err := fs.Stat(fsys, p)
		if err != nil || !info.Mode().IsRegular() || info.Size() < photosMinBytes {
			return nil
		}
		if len(out) >= photosPerRoot {
			return fs.SkipAll
		}
		t := photoLine{P: p, S: info.Size(), M: info.ModTime().Unix()}
		if o := prev(p); o != nil && o.S == t.S && o.M == t.M {
			t = *o
		} else if f, err := root.Open(p); err == nil {
			photoFromMeta(&t, readPhotoMeta(f, t.S, strings.ToLower(path.Ext(name))))
			f.Close()
			parsed++
			if parsed%100 == 0 {
				time.Sleep(20 * time.Millisecond)
			}
		} else {
			return nil
		}
		if t.W > 0 && t.H > 0 && t.W < photosMinSide && t.H < photosMinSide {
			return nil
		}
		out = append(out, t)
		if len(out)%200 == 0 {
			photosNote(rs, len(out))
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, err
	}
	return out, nil
}

// ── what the tunnel serves ─────────────────────────────────────────────

type photosRootView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Sep      string `json:"sep"`
	N        int    `json:"n"`
	Rev      string `json:"rev"`
	Scanning bool   `json:"scanning,omitempty"`
	Seen     int    `json:"seen,omitempty"`
	Err      string `json:"err,omitempty"`
	At       int64  `json:"at,omitempty"`
	Ask      string `json:"ask,omitempty"`
}

type photosStatusBody struct {
	On    bool             `json:"on"`
	Roots []photosRootView `json:"roots"`
	// A dashboard may choose folders here: the console is on.
	CanAdd bool `json:"can_add"`
	// The pictures this machine makes small copies of: jpeg, png and gif
	// everywhere, and on macOS the system's own decoder's (photosthumb.go).
	Thumbs []string `json:"thumbs"`
}

type photosIndexBody struct {
	Root   string      `json:"root"`
	Rev    string      `json:"rev"`
	From   int         `json:"from"`
	Total  int         `json:"total"`
	Photos []photoLine `json:"photos"`
	More   bool        `json:"more"`
}

// photosPeer is musicPeer for pictures: a key on the allowlist, on a machine
// that shares them.
func (h *directHandler) photosPeer(w http.ResponseWriter, r *http.Request) bool {
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
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return false
	}
	if !photosOn() {
		h.refuse(w, http.StatusNotFound, "photos-off")
		return false
	}
	photosReconcile()
	return true
}

func (h *directHandler) photosFrame(w http.ResponseWriter, r *http.Request, body any) {
	f, err := transport.New(transport.TypePhotos, agentID(), r.Header.Get("X-Request-Id"), body)
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

func (h *directHandler) photosStatus(w http.ResponseWriter, r *http.Request) {
	if !h.photosPeer(w, r) {
		return
	}
	body := photosStatusBody{On: true, Roots: []photosRootView{}, CanAdd: musicByConsole(), Thumbs: photosThumbKinds()}
	sep := string(filepath.Separator)
	photoLib.Lock()
	for _, id := range photoLib.order {
		rs := photoLib.roots[id]
		if rs == nil {
			continue
		}
		body.Roots = append(body.Roots, photosRootView{
			ID: id, Name: rs.conf.label(), Path: rs.conf.Path, Sep: sep, N: len(rs.photos),
			Rev: strconv.FormatUint(rs.rev, 10), Scanning: rs.scanning || rs.due, Seen: rs.seen, Err: rs.err, At: rs.at, Ask: rs.ask,
		})
	}
	photoLib.Unlock()
	h.photosFrame(w, r, body)
}

// photosIndexBudget, when set, replaces the frame's share for a page: the
// tests' way to see more than one page.
var photosIndexBudget = 0

func (h *directHandler) photosIndex(w http.ResponseWriter, r *http.Request) {
	if !h.photosPeer(w, r) {
		return
	}
	id := r.URL.Query().Get("r")
	from64 := queryInt(r, "from")
	photoLib.Lock()
	rs := photoLib.roots[id]
	if rs == nil {
		photoLib.Unlock()
		h.refuse(w, http.StatusNotFound, "no-root")
		return
	}
	total := len(rs.photos)
	from := total
	if from64 < int64(total) {
		from = int(from64)
	}
	rev := strconv.FormatUint(rs.rev, 10)
	budget := transport.Limits[transport.TypePhotos] - 8<<10
	if photosIndexBudget > 0 {
		budget = photosIndexBudget
	}
	var page []photoLine
	used, i := 0, from
	for ; i < total; i++ {
		b, _ := json.Marshal(rs.photos[i])
		if used+len(b)+1 > budget && len(page) > 0 {
			break
		}
		used += len(b) + 1
		page = append(page, rs.photos[i])
	}
	photoLib.Unlock()
	if page == nil {
		page = []photoLine{}
	}
	h.photosFrame(w, r, photosIndexBody{Root: id, Rev: rev, From: from, Total: total, Photos: page, More: i < total})
}

// photosFind is the picture a request names, and its folder, as copies.
func (h *directHandler) photosFind(w http.ResponseWriter, r *http.Request) (photosRootConf, photoLine, bool) {
	q := r.URL.Query()
	id, p := q.Get("r"), q.Get("p")
	if !musicRelOK(p) {
		h.refuse(w, http.StatusBadRequest, "bad-path")
		return photosRootConf{}, photoLine{}, false
	}
	photoLib.Lock()
	defer photoLib.Unlock()
	rs := photoLib.roots[id]
	if rs == nil {
		h.refuse(w, http.StatusNotFound, "no-root")
		return photosRootConf{}, photoLine{}, false
	}
	i, ok := rs.byPath[p]
	if !ok || i >= len(rs.photos) {
		h.refuse(w, http.StatusNotFound, "no-photo")
		return photosRootConf{}, photoLine{}, false
	}
	return rs.conf, rs.photos[i], true
}

// ── the command ────────────────────────────────────────────────────────

// runPhotosCommand changes which folders are shown, for a dashboard whose key
// this machine pinned, over the tunnel alone (mailboxRefusal):
//
//	browse  {"path"} ("" for the places)  → out: a folder's listing (photosBrowseBody)
//	add     {"path","name"}               → out: the new folder's id
//	remove  {"id"}
//	rescan  {"id"} (or {} for every folder)
//
// browse and add only where the console is on: see the top of this file.
var photosConfMu sync.Mutex

func runPhotosCommand(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: "photos", Target: c.Target, Code: -1}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	if !photosOn() {
		res.Error = "photos-off"
		return res
	}
	var arg struct {
		ID   string `json:"id"`
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if c.Cmd != "" && json.Unmarshal([]byte(c.Cmd), &arg) != nil {
		res.Error = "bad-args"
		return res
	}
	switch c.Target {
	case "browse":
		if !musicByConsole() {
			res.Error = "console-off"
			return res
		}
		body, code := photosBrowseWithin(arg.Path, musicBrowseWait)
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
		return res
	case "add":
		if !musicByConsole() {
			res.Error = "console-off"
			return res
		}
		if len(arg.Name) > 120 {
			res.Error = "bad-args"
			return res
		}
		type dirPlan struct {
			p, real string
			reals   map[string]string
		}
		plan, code := musicWithin(musicBrowseWait, "photos-add\n"+arg.Path, func() bool { return musicGuardedLinks(arg.Path) }, func() (dirPlan, string) {
			p, real, code := photosDirArg(arg.Path)
			if code != "" {
				return dirPlan{}, code
			}
			pl := dirPlan{p: p, real: real, reals: map[string]string{}}
			for _, r := range loadPhotosConf().Roots {
				pl.reals[r.Path] = musicReal(r.Path)
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
		photosConfMu.Lock()
		defer photosConfMu.Unlock()
		conf := loadPhotosConf()
		if !photosOnConf(conf) {
			res.Error = "photos-off"
			return res
		}
		// One inside a folder already shown would show its pictures twice;
		// one around folders already shown takes their place.
		kept := conf.Roots[:0:0]
		for _, r := range conf.Roots {
			if r.Path == plan.p || musicPathWithin(plan.real, realOf(r.Path)) {
				res.Error, res.Out = "already-shared", r.ID
				return res
			}
			if musicPathWithin(realOf(r.Path), plan.real) {
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) >= photosRootsMax {
			res.Error = "too-many"
			return res
		}
		r := photosRootConf{ID: musicNewID(), Path: plan.p, Name: cleanTag(arg.Name)}
		conf.Roots = append(kept, r)
		if err := savePhotosConf(conf); err != nil {
			res.Error = "save-failed"
			return res
		}
		res.Code, res.Out = 0, r.ID
	case "remove":
		photosConfMu.Lock()
		defer photosConfMu.Unlock()
		conf := loadPhotosConf()
		kept := conf.Roots[:0:0]
		var gone *photosRootConf
		for _, r := range conf.Roots {
			if r.ID == arg.ID {
				g := r
				gone = &g
				continue
			}
			kept = append(kept, r)
		}
		if gone == nil {
			res.Error = "no-root"
			return res
		}
		conf.Roots = kept
		if err := savePhotosConf(conf); err != nil {
			res.Error = "save-failed"
			return res
		}
		photosThumbForget(gone.Path)
		res.Code = 0
	case "rescan":
		photosReconcile()
		photoLib.Lock()
		hit := false
		for id, rs := range photoLib.roots {
			if arg.ID == "" || arg.ID == id {
				rs.due, hit = true, true
			}
		}
		photoLib.Unlock()
		if !hit {
			res.Error = "no-root"
			return res
		}
		res.Code = 0
	default:
		res.Error = "unknown-op"
		return res
	}
	photosReconcile()
	photosWake()
	return res
}

// photosDirArg is musicDirArg with the home folder refused too.
func photosDirArg(raw string) (string, string, string) {
	p, real, code := musicDirArg(raw)
	if code != "" {
		return "", "", code
	}
	if photosDirTooBroad(p) || photosDirTooBroad(real) {
		return "", "", "too-broad"
	}
	return p, real, ""
}

// ── at the keyboard ────────────────────────────────────────────────────

func runPhotosCLI(args []string) int {
	conf := loadPhotosConf()
	verb := ""
	if len(args) > 0 {
		verb, args = args[0], args[1:]
	}
	save := func() int {
		if err := savePhotosConf(conf); err != nil {
			warnf("could not save the photos settings: %v", err)
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
		if photosDirTooBroad(abs) {
			warnf("%s is too broad: choose the folder the photos are in", homeTilde(abs))
			return false
		}
		for _, r := range conf.Roots {
			if r.Path == abs {
				fmt.Printf("already shown: %s\n", homeTilde(abs))
				return true
			}
		}
		if len(conf.Roots) >= photosRootsMax {
			warnf("at most %d folders can be shown", photosRootsMax)
			return false
		}
		conf.Roots = append(conf.Roots, photosRootConf{ID: musicNewID(), Path: abs})
		fmt.Printf("showing %s\n", homeTilde(abs))
		return true
	}
	switch verb {
	case "", "status":
	case "on":
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
			warnf("say 'photos add <folder>'")
			return 2
		}
		for _, a := range args {
			if !addDir(a) {
				return 1
			}
		}
		if !photosOnConf(conf) {
			fmt.Println("note: photos are off; 'subnsub-helper photos on' shows what is listed")
		}
		if rc := save(); rc >= 0 {
			return rc
		}
	case "remove":
		if len(args) != 1 {
			warnf("say 'photos remove <id or folder>' — 'photos' lists them")
			return 2
		}
		abs, _ := filepath.Abs(args[0])
		kept := conf.Roots[:0:0]
		for _, r := range conf.Roots {
			if r.ID == args[0] || r.Path == abs {
				fmt.Printf("no longer showing %s\n", homeTilde(r.Path))
				photosThumbForget(r.Path)
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == len(conf.Roots) {
			warnf("nothing shown matches %s", args[0])
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
		fmt.Println("the running helper reads every folder shown again within a few seconds")
	default:
		warnf("usage: subnsub-helper photos [on [FOLDER...] | off | add FOLDER... | remove ID | rescan]")
		return 2
	}
	on := photosOnConf(conf)
	switch {
	case on && !conf.On:
		fmt.Printf("on   (%s) by the console: a dashboard that may run lines here may read these files anyway\n", agentID())
	case on:
		fmt.Printf("on   (%s)\n", agentID())
	default:
		fmt.Printf("off  (%s)\n", agentID())
	}
	if on {
		fmt.Println("browsers on this machine's direct allowlist can see the photos in what is listed, over the tailnet or the tailcat tunnel only")
	}
	saved := photosLoadSaved()
	for _, r := range conf.Roots {
		n := "not read yet"
		if s := saved[r.ID]; s != nil && s.Sig == r.sig() {
			n = fmt.Sprintf("%d photos", len(s.Photos))
		}
		fmt.Printf("  %s  %s  (%s)\n", r.ID, homeTilde(r.Path), n)
	}
	if len(conf.Roots) == 0 {
		if musicByConsole() {
			fmt.Println("nothing shown, and nothing read: choose a folder on the Photos page, or 'subnsub-helper photos add <folder>' here")
		} else {
			fmt.Println("nothing shown, and nothing read: 'subnsub-helper photos add <folder>' names one")
		}
	}
	return 0
}

// photosGates is how many small copies are made at once: two, or a quarter
// of the cores on a larger machine.
func photosGates() int {
	n := runtime.NumCPU() / 4
	if n < 2 {
		n = 2
	}
	if n > 4 {
		n = 4
	}
	return n
}
