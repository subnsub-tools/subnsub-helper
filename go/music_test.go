package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// musicReset puts the process-wide library back to nothing, as a new helper
// would start.
func musicReset(t *testing.T) {
	t.Helper()
	musicLib.Lock()
	for _, rs := range musicLib.roots {
		if rs.cancel != nil {
			rs.cancel()
		}
	}
	musicLib.roots = map[string]*musicRootState{}
	musicLib.order = nil
	musicLib.rescan = 0
	musicLib.saved = nil
	musicLib.loaded = false
	musicLib.Unlock()
	musicConfCache.Lock()
	musicConfCache.ok = false
	musicConfCache.Unlock()
	musicArtLRU.Lock()
	musicArtLRU.items = map[string]musicArtItem{}
	musicArtLRU.order = nil
	musicArtLRU.bytes = 0
	musicArtLRU.Unlock()
	t.Setenv(musicEnvVar, "")
	os.Unsetenv(musicEnvVar)
	musicIndexBudget = 0
	t.Cleanup(func() { musicIndexBudget = 0 })
}

// musicSettle walks every root that is due, as the loop would.
func musicSettle(t *testing.T) {
	t.Helper()
	musicReconcile()
	for i := 0; i < 20; i++ {
		rs := musicNextDue(time.Now())
		if rs == nil {
			return
		}
		musicWalk(rs)
		musicReconcile()
	}
	t.Fatal("the walker never settled")
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type musicFixture struct {
	home, music string
	peer        key.NodePublic
	h           *directHandler
}

func newMusicFixture(t *testing.T) musicFixture {
	t.Helper()
	home := scratchHome(t)
	musicReset(t)
	f := musicFixture{home: home, music: filepath.Join(home, "Music"), h: newDirectHandler()}
	f.peer = key.NewNode().Public()
	if err := allowClient(f.peer.String()); err != nil {
		t.Fatal(err)
	}
	pic := tinyPNG(t, 600, 400)
	tagged := func(title, artist, album string, n int, withPic bool) []byte {
		frames := [][]byte{
			frame23("TIT2", cat([]byte{0}, []byte(title))),
			frame23("TPE1", cat([]byte{0}, []byte(artist))),
			frame23("TALB", cat([]byte{0}, []byte(album))),
			frame23("TRCK", cat([]byte{0}, []byte(fmt.Sprint(n)))),
		}
		if withPic {
			frames = append(frames, frame23("APIC", cat([]byte{0}, []byte("image/png\x00"), []byte{3, 0}, pic)))
		}
		return cat(id3(3, frames...), mp3Frames(40, 0))
	}
	writeFile(t, filepath.Join(f.music, "Band", "Album", "01 First.mp3"), tagged("First", "Band", "Album", 1, true))
	writeFile(t, filepath.Join(f.music, "Band", "Album", "02 Second.mp3"), tagged("Second", "Band", "Album", 2, false))
	writeFile(t, filepath.Join(f.music, "Band", "Album", "cover.jpg"), tinyPNG(t, 30, 30)) // a PNG named .jpg: sniffed, not trusted by name
	writeFile(t, filepath.Join(f.music, "Other", "song.flac"), flacFile(t, tinyPNG(t, 2, 2)))
	writeFile(t, filepath.Join(f.music, "Other", "notes.txt"), []byte("not music"))
	writeFile(t, filepath.Join(f.music, ".hidden", "secret.mp3"), tagged("Hidden", "X", "Y", 1, false))
	writeFile(t, filepath.Join(f.music, "@eaDir", "thumb.mp3"), tagged("Thumb", "X", "Y", 1, false))
	// A file outside the folder, and a link inside it pointing there: the
	// walk does not follow a link out of the root.
	writeFile(t, filepath.Join(home, "Private", "diary.mp3"), tagged("Diary", "Me", "Mine", 1, false))
	if err := os.Symlink(filepath.Join(home, "Private", "diary.mp3"), filepath.Join(f.music, "escape.mp3")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f musicFixture) get(t *testing.T, target string, peer *key.NodePublic) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if peer != nil {
		req = req.WithContext(transport.WithPeer(req.Context(), *peer))
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func musicBody(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	fr, err := transport.Decode(rec.Body.Bytes())
	if err != nil || fr.Type != transport.TypeMusic {
		t.Fatalf("frame: %v %q", err, rec.Body.String())
	}
	if err := json.Unmarshal(fr.Body, into); err != nil {
		t.Fatal(err)
	}
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	fr, err := transport.Decode(rec.Body.Bytes())
	if err != nil || fr.Type != transport.TypeError {
		return ""
	}
	var e transport.Error
	json.Unmarshal(fr.Body, &e)
	return e.Code
}

func TestMusicOnSharesTheMusicFolderAndWalksIt(t *testing.T) {
	f := newMusicFixture(t)
	if musicOn() {
		t.Fatal("music is off until somebody at the machine turns it on")
	}
	if rc := runMusicCLI([]string{"on"}); rc != 0 {
		t.Fatalf("music on: %d", rc)
	}
	fi, err := os.Stat(musicConfPath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the settings file is the owner's alone: %v %v", fi.Mode(), err)
	}
	musicSettle(t)

	var st musicStatusBody
	musicBody(t, f.get(t, "/v1/music", &f.peer), &st)
	if !st.On || len(st.Roots) != 1 || st.Roots[0].Kind != "dir" || st.Roots[0].Where != "~/Music" || st.Roots[0].Tracks != 3 {
		t.Fatalf("status: %+v", st)
	}
	if len(st.CanAdd) != 0 {
		t.Fatal("nothing pinned, so a dashboard may change nothing here")
	}
	var ix musicIndexBody
	musicBody(t, f.get(t, "/v1/music/index?r="+st.Roots[0].ID, &f.peer), &ix)
	var paths []string
	for _, tr := range ix.Tracks {
		paths = append(paths, tr.P)
	}
	want := []string{"Band/Album/01 First.mp3", "Band/Album/02 Second.mp3", "Other/song.flac"}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("indexed %v, want %v (hidden, NAS, non-audio and escaping links left out)", paths, want)
	}
	if ix.Tracks[0].T != "First" || ix.Tracks[0].N != 1 || ix.Tracks[0].C != 1 {
		t.Fatalf("first track: %+v", ix.Tracks[0])
	}
	if ix.Tracks[1].C != 2 {
		t.Fatalf("a track with no picture of its own takes its folder's: %+v", ix.Tracks[1])
	}
	if ix.Tracks[2].T != "Lake" || ix.Tracks[2].D != 10 {
		t.Fatalf("FLAC track: %+v", ix.Tracks[2])
	}
	if ix.Total != 3 || ix.More {
		t.Fatalf("one page: %+v", ix)
	}
}

func TestMusicIndexPages(t *testing.T) {
	f := newMusicFixture(t)
	runMusicCLI([]string{"on"})
	musicSettle(t)
	musicIndexBudget = 200 // about one track a page
	id := musicLib.order[0]
	var all []string
	from := 0
	for pages := 0; pages < 10; pages++ {
		var ix musicIndexBody
		musicBody(t, f.get(t, fmt.Sprintf("/v1/music/index?r=%s&from=%d", id, from), &f.peer), &ix)
		for _, tr := range ix.Tracks {
			all = append(all, tr.P)
		}
		from += len(ix.Tracks)
		if !ix.More {
			break
		}
	}
	if len(all) != 3 {
		t.Fatalf("paged %v", all)
	}
}

func TestMusicFileReadsOnlyIndexedTracks(t *testing.T) {
	f := newMusicFixture(t)
	runMusicCLI([]string{"on"})
	musicSettle(t)
	id := musicLib.order[0]
	disk, _ := os.ReadFile(filepath.Join(f.music, "Band", "Album", "01 First.mp3"))
	q := func(p string, o, n int) string {
		return "/v1/music/file?r=" + id + "&p=" + url.QueryEscape(p) + fmt.Sprintf("&o=%d&n=%d", o, n)
	}
	rec := f.get(t, q("Band/Album/01 First.mp3", 100, 500), &f.peer)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), disk[100:600]) || rec.Header().Get("Content-Type") != "audio/mpeg" {
		t.Fatalf("a piece: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = f.get(t, q("Band/Album/01 First.mp3", len(disk)-10, 500), &f.peer)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), disk[len(disk)-10:]) {
		t.Fatalf("the end of the file: %d %d bytes", rec.Code, rec.Body.Len())
	}
	if rec := f.get(t, q("Band/Album/01 First.mp3", len(disk), 1), &f.peer); rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("past the end: %d", rec.Code)
	}
	for _, p := range []string{"../Private/diary.mp3", "escape.mp3", "Band/Album/cover.jpg", "Other/notes.txt", ".hidden/secret.mp3", "/etc/passwd", "Band//Album/01 First.mp3"} {
		rec := f.get(t, q(p, 0, 10), &f.peer)
		if rec.Code == 200 {
			t.Fatalf("%s was served", p)
		}
	}
	// n beyond the ceiling is the ceiling.
	if rec := f.get(t, q("Other/song.flac", 0, 1<<30), &f.peer); rec.Code != 200 {
		t.Fatalf("a large n: %d", rec.Code)
	}
}

func TestMusicGate(t *testing.T) {
	f := newMusicFixture(t)
	runMusicCLI([]string{"on"})
	musicSettle(t)
	// No peer, a stranger: refused.
	if rec := f.get(t, "/v1/music", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("no peer: %d", rec.Code)
	}
	stranger := key.NewNode().Public()
	if rec := f.get(t, "/v1/music", &stranger); rec.Code != http.StatusForbidden {
		t.Fatalf("a stranger: %d", rec.Code)
	}
	// The hello names music to the allowlisted key, and not once it is off.
	var hello transport.Hello
	rec := f.get(t, "/v1/hello", &f.peer)
	fr, _ := transport.Decode(rec.Body.Bytes())
	json.Unmarshal(fr.Body, &hello)
	if !containsStr(hello.Caps, transport.CapMusic) {
		t.Fatalf("caps %v", hello.Caps)
	}
	runMusicCLI([]string{"off"})
	if rec := f.get(t, "/v1/music", &f.peer); rec.Code != http.StatusNotFound || errCode(t, rec) != "music-off" {
		t.Fatalf("off: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.get(t, "/v1/hello", &f.peer)
	fr, _ = transport.Decode(rec.Body.Bytes())
	hello = transport.Hello{}
	json.Unmarshal(fr.Body, &hello)
	if containsStr(hello.Caps, transport.CapMusic) {
		t.Fatalf("caps when off %v", hello.Caps)
	}
	// The environment overrides the file.
	runMusicCLI([]string{"on"})
	t.Setenv(musicEnvVar, "off")
	if musicOn() {
		t.Fatal("MON_MUSIC=off")
	}
	// The relay's mailbox never carries the kind, and the tailnet road
	// serves the routes.
	if mailboxRefusal(consoleCmd{Kind: "music"}) != "tunnel-only" {
		t.Fatal("music commands are tunnel-only")
	}
	for _, p := range []string{"/v1/music", "/v1/music/index", "/v1/music/file", "/v1/music/art"} {
		if !tailnetInnerOK(p) {
			t.Fatalf("%s on the tailnet road", p)
		}
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestMusicArt(t *testing.T) {
	f := newMusicFixture(t)
	runMusicCLI([]string{"on"})
	musicSettle(t)
	id := musicLib.order[0]
	rec := f.get(t, "/v1/music/art?r="+id+"&p="+url.QueryEscape("Band/Album/01 First.mp3")+"&w=256", &f.peer)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("embedded cover: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(rec.Body.Bytes()))
	if err != nil || cfg.Width != 256 || cfg.Height != 170 {
		t.Fatalf("scaled to fit 256: %+v %v", cfg, err)
	}
	rec = f.get(t, "/v1/music/art?r="+id+"&p="+url.QueryEscape("Band/Album/02 Second.mp3"), &f.peer)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("the folder's cover, small enough to pass as it is: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestMusicIndexSurvivesARestartWithoutReadingAgain(t *testing.T) {
	f := newMusicFixture(t)
	runMusicCLI([]string{"on"})
	musicSettle(t)
	id := musicLib.order[0]
	rev := musicLib.roots[id].rev
	// A new process: the saved index comes back, and a walk over files that
	// did not change finds nothing new.
	musicReset(t)
	musicReconcile()
	musicLib.Lock()
	rs := musicLib.roots[id]
	n := len(rs.tracks)
	musicLib.Unlock()
	if n != 3 {
		t.Fatalf("restored %d tracks", n)
	}
	musicSettle(t)
	if musicLib.roots[id].rev != rev {
		t.Fatal("nothing changed, so the revision did not either")
	}
	// A new file is found by the next walk.
	writeFile(t, filepath.Join(f.music, "New", "n.flac"), flacFile(t, tinyPNG(t, 2, 2)))
	musicLib.Lock()
	musicLib.roots[id].due = true
	musicLib.Unlock()
	musicSettle(t)
	if len(musicLib.roots[id].tracks) != 4 || musicLib.roots[id].rev == rev {
		t.Fatal("a new file is a new revision")
	}
}

// ── WebDAV ─────────────────────────────────────────────────────────────

type davServer struct {
	mu      sync.Mutex
	prefix  string
	files   map[string][]byte // path under prefix → bytes
	user    string
	pass    string
	noRange bool
	gets    int
}

func (d *davServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != d.user || p != d.pass {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !strings.HasPrefix(r.URL.Path, d.prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, d.prefix)
	d.mu.Lock()
	defer d.mu.Unlock()
	switch r.Method {
	case "PROPFIND":
		dir := strings.TrimSuffix(rel, "/")
		type ent struct {
			href string
			dir  bool
			size int
		}
		var ents []ent
		ents = append(ents, ent{href: d.prefix + (&url.URL{Path: rel}).EscapedPath(), dir: true})
		seen := map[string]bool{}
		for p, b := range d.files {
			if dir != "" && !strings.HasPrefix(p, dir+"/") {
				continue
			}
			rest := strings.TrimPrefix(p, dir+"/")
			if dir == "" {
				rest = p
			}
			if i := strings.Index(rest, "/"); i >= 0 {
				sub := rest[:i]
				if !seen[sub] {
					seen[sub] = true
					full := sub
					if dir != "" {
						full = dir + "/" + sub
					}
					ents = append(ents, ent{href: d.prefix + (&url.URL{Path: full}).EscapedPath() + "/", dir: true})
				}
				continue
			}
			ents = append(ents, ent{href: d.prefix + (&url.URL{Path: p}).EscapedPath(), size: len(b)})
		}
		if dir != "" && len(ents) == 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].href < ents[j].href })
		var b strings.Builder
		b.WriteString(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">`)
		for _, e := range ents {
			rt := "<d:resourcetype/>"
			if e.dir {
				rt = "<d:resourcetype><d:collection/></d:resourcetype>"
			}
			fmt.Fprintf(&b, `<d:response><d:href>%s</d:href><d:propstat><d:prop>%s<d:getcontentlength>%d</d:getcontentlength>`+
				`<d:getlastmodified>Mon, 02 Nov 2026 10:00:00 GMT</d:getlastmodified><d:getetag>"e%d"</d:getetag></d:prop>`+
				`<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`, e.href, rt, e.size, e.size)
		}
		b.WriteString(`</d:multistatus>`)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		io.WriteString(w, b.String())
	case http.MethodGet:
		body, ok := d.files[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		d.gets++
		if d.noRange {
			w.Write(body)
			return
		}
		http.ServeContent(w, r, path.Base(rel), time.Time{}, bytes.NewReader(body))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newDavServer(t *testing.T) *davServer {
	return &davServer{
		prefix: "/dav/music/", user: "listener", pass: "s3cret",
		files: map[string][]byte{
			"Artist One/Live/01 Opening.flac": flacFile(t, tinyPNG(t, 2, 2)),
			"Artist One/Live/cover.png":       tinyPNG(t, 40, 40),
			"Loose.mp3":                       cat(id3(3, frame23("TIT2", cat([]byte{0}, []byte("Loose")))), mp3Frames(30, 0)),
			"readme.txt":                      []byte("x"),
		},
	}
}

func TestMusicWebDAVWalkAndRead(t *testing.T) {
	scratchHome(t)
	musicReset(t)
	ds := newDavServer(t)
	srv := httptest.NewServer(ds)
	defer srv.Close()
	d, err := newDav(srv.URL+"/dav/music", "listener", "s3cret", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	bad, _ := newDav(srv.URL+"/dav/music", "listener", "wrong", "")
	if err := bad.probe(t.Context()); musicErrCode(err) != "dav-auth" {
		t.Fatalf("a wrong password: %v", err)
	}
	none, _ := newDav(srv.URL+"/nothing/here", "listener", "s3cret", "")
	if err := none.probe(t.Context()); musicErrCode(err) != "dav-not-found" {
		t.Fatalf("no such folder: %v", err)
	}
	rs := &musicRootState{conf: musicRootConf{ID: "w1", Kind: "webdav", URL: d.base.String()}, dav: d}
	tracks, covers, err := musicWalkDav(t.Context(), rs, func(string) *musicTrack { return nil })
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(tracks, func(i, j int) bool { return tracks[i].P < tracks[j].P })
	if len(tracks) != 2 || tracks[0].P != "Artist One/Live/01 Opening.flac" || tracks[0].T != "Lake" || tracks[0].D != 10 || tracks[1].T != "Loose" {
		t.Fatalf("walked %+v", tracks)
	}
	if covers["Artist One/Live"] != "Artist One/Live/cover.png" || tracks[0].C != 1 {
		t.Fatalf("covers %v / %+v", covers, tracks[0])
	}
	rc, _, err := d.get(t.Context(), "Loose.mp3", 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, ds.files["Loose.mp3"][10:30]) {
		t.Fatal("a ranged read")
	}
	// A server that ignores Range still gives the bytes asked for.
	ds.noRange = true
	rc, _, err = d.get(t.Context(), "Loose.mp3", 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, ds.files["Loose.mp3"][10:30]) {
		t.Fatal("a read from a server without ranges")
	}
}

func TestMusicWebDAVCommandAndPin(t *testing.T) {
	f := newMusicFixture(t)
	runMusicCLI([]string{"on"})
	pub, _, _ := ed25519.GenerateKey(nil)
	cmd := func(op string, arg any) consoleResult {
		b, _ := json.Marshal(arg)
		return runMusicCommand(consoleCmd{ID: "m" + op, Kind: "music", Target: op, Cmd: string(b)})
	}
	ds := newDavServer(t)
	srv := httptest.NewTLSServer(ds)
	defer srv.Close()
	if r := cmd("add-webdav", map[string]string{"url": srv.URL + "/dav/music/"}); r.Error != "unpinned" {
		t.Fatalf("without a pinned key: %+v", r)
	}
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	r := cmd("add-webdav", map[string]string{"url": srv.URL + "/dav/music/", "user": "listener", "pass": "s3cret", "name": "NAS"})
	if r.Error != "cert-untrusted" || r.Out != certPin(srv.Certificate()) {
		t.Fatalf("an unknown certificate is answered with its fingerprint: %+v", r)
	}
	if r := cmd("add-webdav", map[string]string{"url": srv.URL + "/dav/music/", "user": "listener", "pass": "s3cret", "pin": "sha256:" + strings.Repeat("0", 64)}); r.Error != "dav-unreachable" && r.Error != "cert-changed" {
		t.Fatalf("a pin for another certificate: %+v", r)
	}
	r = cmd("add-webdav", map[string]string{"url": srv.URL + "/dav/music/", "user": "listener", "pass": "s3cret", "name": "NAS", "pin": certPin(srv.Certificate())})
	if r.Code != 0 || r.Out == "" {
		t.Fatalf("added: %+v", r)
	}
	if r2 := cmd("add-webdav", map[string]string{"url": srv.URL + "/dav/music/", "user": "listener", "pass": "s3cret", "pin": certPin(srv.Certificate())}); r2.Error != "already-shared" {
		t.Fatalf("twice: %+v", r2)
	}
	musicSettle(t)
	var st musicStatusBody
	musicBody(t, f.get(t, "/v1/music", &f.peer), &st)
	if len(st.Roots) != 2 || st.Roots[1].Name != "NAS" || st.Roots[1].Tracks != 2 || !containsStr(st.CanAdd, "webdav") {
		t.Fatalf("status: %+v", st)
	}
	if strings.Contains(fmt.Sprint(st), "s3cret") || strings.Contains(fmt.Sprint(st), "listener") {
		t.Fatal("the account never leaves the machine")
	}
	// The bytes come through the helper.
	rec := f.get(t, "/v1/music/file?r="+r.Out+"&p=Loose.mp3&o=0&n=16", &f.peer)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), ds.files["Loose.mp3"][:16]) {
		t.Fatalf("read through the helper: %d", rec.Code)
	}
	if r := cmd("rescan", map[string]string{"id": r.Out}); r.Code != 0 {
		t.Fatalf("rescan: %+v", r)
	}
	if r := cmd("remove", map[string]string{"id": r.Out}); r.Code != 0 {
		t.Fatalf("remove: %+v", r)
	}
	if r := cmd("remove", map[string]string{"id": "nope"}); r.Error != "no-root" {
		t.Fatalf("remove twice: %+v", r)
	}
	if r := cmd("format-disk", map[string]string{}); r.Error != "unknown-op" {
		t.Fatalf("unknown op: %+v", r)
	}
	musicReconcile()
	if len(musicLib.order) != 1 {
		t.Fatalf("removed: %v", musicLib.order)
	}
}

func TestMusicDavURLs(t *testing.T) {
	for in, want := range map[string]string{
		"nas.local/dav":                                        "https://nas.local/dav/",
		"http://192.168.1.10:5005/music":                       "http://192.168.1.10:5005/music/",
		"https://cloud.example/remote.php/dav/files/me/Music/": "https://cloud.example/remote.php/dav/files/me/Music/",
	} {
		u, err := cleanDavURL(in)
		if err != nil || u.String() != want {
			t.Fatalf("%s → %v %v", in, u, err)
		}
	}
	for _, in := range []string{"", "ftp://x/y", "https://user:pw@x/", "javascript:alert(1)", "https://"} {
		if _, err := cleanDavURL(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
	d, _ := newDav("https://x.example/a%20b/", "", "", "")
	for href, want := range map[string]string{
		"/a%20b/c/d.mp3":                   "c/d.mp3",
		"https://x.example/a%20b/e.flac":   "e.flac",
		"https://evil.example/a%20b/e.mp3": "",
		"/other/f.mp3":                     "",
	} {
		got, ok := d.relOf(href)
		if !ok {
			got = ""
		}
		if got != want {
			t.Fatalf("relOf(%s) = %q, want %q", href, got, want)
		}
	}
}
