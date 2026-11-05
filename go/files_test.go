package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

type filesFixture struct {
	home string
	h    *directHandler
	peer key.NodePublic
	priv ed25519.PrivateKey
	n    int
}

func newFilesFixture(t *testing.T) *filesFixture {
	t.Helper()
	home := scratchHome(t)
	t.Setenv("MON_CONSOLE", "1")
	t.Setenv("MON_UPDATE", "0")
	t.Setenv(musicEnvVar, "off")
	// A search left walking would go on after the test, into the next ones.
	stop := func() {
		filesJobs.Lock()
		for tok, j := range filesJobs.m {
			j.cancel()
			delete(filesJobs.m, tok)
		}
		filesJobs.Unlock()
		filesOpened.Lock()
		filesOpened.m = map[string]*filesOpen{}
		filesOpened.Unlock()
	}
	stop()
	// "Everywhere" is the scratch home alone: the real roots are the whole
	// disk, which a test must never walk.
	filesRoots = func() []string { return []string{home} }
	t.Cleanup(func() {
		stop()
		filesRoots = filesSearchRoots
	})
	f := &filesFixture{home: home, h: newDirectHandler(), peer: key.NewNode().Public()}
	if err := allowClient(f.peer.String()); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.priv = priv
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"Documents/report-2024.pdf",
		"Documents/notes.txt",
		"Work/b/c/Report final.txt",
		"Work/b/c/other.txt",
		".hidden/report.txt",
		"node_modules/x/report.js",
		"Pictures/REPORT.png",
	} {
		writeFile(t, filepath.Join(home, p), []byte("content of "+p))
	}
	if err := os.MkdirAll(filepath.Join(home, "Reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

// command sends a signed files command through the tunnel's command door,
// as peer.
func (f *filesFixture) command(t *testing.T, peer key.NodePublic, op string, arg any) consoleResult {
	t.Helper()
	b, _ := json.Marshal(arg)
	f.n++
	c := signedCmd(t, f.priv, agentID(), consoleCmd{ID: fmt.Sprintf("f%x-%d", time.Now().UnixNano(), f.n), Kind: "files", Target: op, Cmd: string(b)})
	fr, _ := transport.New(transport.TypeCommand, "", c.ID, transport.Command{Kind: c.Kind, Cmd: c.Cmd, Target: c.Target, Sig: c.Sig, At: c.IssuedAt})
	body, _ := transport.Encode(fr)
	req := httptest.NewRequest(http.MethodPost, "/v1/command", strings.NewReader(string(body)))
	req = req.WithContext(transport.WithPeer(req.Context(), peer))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", op, rec.Code, rec.Body.String())
	}
	out, err := transport.Decode(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var res consoleResult
	if err := json.Unmarshal(out.Body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func (f *filesFixture) get(t *testing.T, target string, peer *key.NodePublic) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if peer != nil {
		req = req.WithContext(transport.WithPeer(req.Context(), *peer))
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// search runs a question to its end and gives back the paths it found,
// relative to home and sorted, with the last page.
func (f *filesFixture) search(t *testing.T, q, in string) ([]string, filesPage) {
	t.Helper()
	res := f.command(t, f.peer, "search", map[string]string{"q": q, "in": in})
	if res.Code != 0 {
		t.Fatalf("search %q: %+v", q, res)
	}
	var started struct {
		T string `json:"t"`
	}
	json.Unmarshal([]byte(res.Out), &started)
	var got []string
	from := 0
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rec := f.get(t, "/v1/files/search?s="+started.T+fmt.Sprintf("&from=%d", from), &f.peer)
		if rec.Code != 200 {
			t.Fatalf("poll: %d %s", rec.Code, rec.Body.String())
		}
		var p filesPage
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		for _, h := range p.Hits {
			rel, _ := filepath.Rel(f.home, h.P)
			if h.D {
				rel += "/"
			}
			got = append(got, filepath.ToSlash(rel))
		}
		from = p.Next
		if p.Done {
			sort.Strings(got)
			return got, p
		}
	}
	t.Fatal("the search never finished")
	return nil, filesPage{}
}

func TestFilesCapsFollowTheConsole(t *testing.T) {
	f := newFilesFixture(t)
	caps := func(peer key.NodePublic) []string {
		rec := f.get(t, "/v1/hello", &peer)
		fr, _ := transport.Decode(rec.Body.Bytes())
		var hello transport.Hello
		json.Unmarshal(fr.Body, &hello)
		return hello.Caps
	}
	if !containsStr(caps(f.peer), transport.CapFiles) {
		t.Fatalf("console on, key pinned: caps %v", caps(f.peer))
	}
	if containsStr(caps(key.NewNode().Public()), transport.CapFiles) {
		t.Fatal("named to a key that is not on the allowlist")
	}
	t.Setenv("MON_CONSOLE", "0")
	if containsStr(caps(f.peer), transport.CapFiles) {
		t.Fatal("named with the console off")
	}
	if r := f.command(t, f.peer, "list", map[string]string{"path": f.home}); r.Error != "console-off" {
		t.Fatalf("a listing with the console off: %+v", r)
	}
	if mailboxRefusal(consoleCmd{Kind: "files"}) != "tunnel-only" {
		t.Fatal("files commands are tunnel-only")
	}
	if r, _ := runCommand(consoleCmd{ID: "x", Kind: "files", Target: "list"}); r.Error != "tunnel-only" {
		t.Fatalf("runCommand took a files command: %+v", r)
	}
}

func TestFilesListing(t *testing.T) {
	f := newFilesFixture(t)
	r := f.command(t, f.peer, "list", map[string]string{"path": f.home})
	if r.Code != 0 {
		t.Fatalf("list: %+v", r)
	}
	var b filesListBody
	json.Unmarshal([]byte(r.Out), &b)
	var dirs []string
	for _, d := range b.Dirs {
		dirs = append(dirs, d.N)
	}
	if strings.Join(dirs, ",") != "Documents,node_modules,Pictures,Reports,Work" || b.Hidden < 1 || b.Path != f.home {
		t.Fatalf("home: %+v", b)
	}
	r = f.command(t, f.peer, "list", map[string]string{"path": filepath.Join(f.home, "Documents")})
	b = filesListBody{}
	json.Unmarshal([]byte(r.Out), &b)
	if len(b.Files) != 2 || b.Files[0].N != "notes.txt" || b.Files[0].S != int64(len("content of Documents/notes.txt")) || b.Files[0].M == 0 || b.Parent != f.home {
		t.Fatalf("Documents: %+v", b)
	}
	r = f.command(t, f.peer, "list", map[string]string{})
	b = filesListBody{}
	json.Unmarshal([]byte(r.Out), &b)
	if len(b.Places) == 0 {
		t.Fatalf("the places: %+v", r)
	}
	for _, bad := range []string{"relative/path", filepath.Join(f.home, "Documents", "notes.txt"), filepath.Join(f.home, "missing")} {
		if r := f.command(t, f.peer, "list", map[string]string{"path": bad}); r.Code == 0 {
			t.Fatalf("%s listed", bad)
		}
	}
}

func TestFilesSearchByWordsAndPattern(t *testing.T) {
	f := newFilesFixture(t)
	got, p := f.search(t, "report", f.home)
	want := "Documents/report-2024.pdf,Pictures/REPORT.png,Reports/,Work/b/c/Report final.txt"
	if strings.Join(got, ",") != want {
		t.Fatalf("report: %v, want %s (hidden folders and node_modules are not gone into)", got, want)
	}
	if p.Why != "" || p.Scanned == 0 || p.Folders == 0 {
		t.Fatalf("the last page: %+v", p)
	}
	if got, _ := f.search(t, "REPORT final", f.home); strings.Join(got, ",") != "Work/b/c/Report final.txt" {
		t.Fatalf("every word: %v", got)
	}
	if got, _ := f.search(t, "*.txt", f.home); strings.Join(got, ",") != "Documents/notes.txt,Work/b/c/Report final.txt,Work/b/c/other.txt" {
		t.Fatalf("a pattern: %v", got)
	}
	for _, q := range []string{"", "a/b", "*[", strings.Repeat("x", filesQueryMax+1)} {
		if r := f.command(t, f.peer, "search", map[string]string{"q": q, "in": f.home}); r.Code == 0 {
			t.Fatalf("question %q was taken", q)
		}
	}
}

func TestFilesSearchBelongsToItsPeer(t *testing.T) {
	f := newFilesFixture(t)
	other := key.NewNode().Public()
	if err := allowClient(other.String()); err != nil {
		t.Fatal(err)
	}
	r := f.command(t, f.peer, "search", map[string]string{"q": "report", "in": f.home})
	var started struct {
		T string `json:"t"`
	}
	json.Unmarshal([]byte(r.Out), &started)
	if rec := f.get(t, "/v1/files/search?s="+started.T, &other); rec.Code != http.StatusNotFound || errCode(t, rec) != "no-search" {
		t.Fatalf("another peer read it: %d", rec.Code)
	}
	if rec := f.get(t, "/v1/files/search?s="+started.T, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("no peer: %d", rec.Code)
	}
	stranger := key.NewNode().Public()
	if rec := f.get(t, "/v1/files/search?s="+started.T, &stranger); rec.Code != http.StatusForbidden {
		t.Fatalf("a stranger: %d", rec.Code)
	}
	// A new question from the same peer ends the one before.
	f.command(t, f.peer, "search", map[string]string{"q": "notes", "in": f.home})
	filesJobs.Lock()
	j := filesJobs.m[started.T]
	filesJobs.Unlock()
	if j == nil {
		t.Fatal("the first search was forgotten at once")
	}
	j.mu.Lock()
	done := j.done
	j.mu.Unlock()
	if !done {
		t.Fatal("a new question did not end the old one")
	}
	if rec := f.get(t, "/v1/files/search?s="+started.T, &f.peer); rec.Code != 200 {
		t.Fatalf("the ended search's last page: %d", rec.Code)
	}
}

func TestFilesReadAPiece(t *testing.T) {
	f := newFilesFixture(t)
	p := filepath.Join(f.home, "Documents", "notes.txt")
	disk, _ := os.ReadFile(p)
	r := f.command(t, f.peer, "open", map[string]string{"path": p})
	if r.Code != 0 {
		t.Fatalf("open: %+v", r)
	}
	var o filesOpenBody
	json.Unmarshal([]byte(r.Out), &o)
	if o.S != int64(len(disk)) || o.N != "notes.txt" || o.Max != filesReadMax || o.T == "" {
		t.Fatalf("opened: %+v", o)
	}
	piece := func(peer *key.NodePublic, off, n int) *httptest.ResponseRecorder {
		return f.get(t, "/v1/files/file?s="+url.QueryEscape(o.T)+fmt.Sprintf("&o=%d&n=%d", off, n), peer)
	}
	if rec := piece(&f.peer, 3, 5); rec.Code != 200 || rec.Body.String() != string(disk[3:8]) {
		t.Fatalf("a piece: %d %q", rec.Code, rec.Body.String())
	}
	if rec := piece(&f.peer, len(disk)-2, 100); rec.Code != 200 || rec.Body.String() != string(disk[len(disk)-2:]) {
		t.Fatalf("the end: %d %q", rec.Code, rec.Body.String())
	}
	if rec := piece(&f.peer, len(disk), 1); rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("past the end: %d", rec.Code)
	}
	other := key.NewNode().Public()
	allowClient(other.String())
	if rec := piece(&other, 0, 5); rec.Code != http.StatusNotFound {
		t.Fatalf("another peer's read: %d", rec.Code)
	}
	// Changed under the page: refused, not spliced.
	writeFile(t, p, []byte("something else entirely, and longer"))
	if rec := piece(&f.peer, 0, 5); rec.Code != http.StatusConflict || errCode(t, rec) != "changed" {
		t.Fatalf("a changed file: %d", rec.Code)
	}
	// The console switched off: no more pieces.
	r = f.command(t, f.peer, "open", map[string]string{"path": p})
	json.Unmarshal([]byte(r.Out), &o)
	t.Setenv("MON_CONSOLE", "0")
	if rec := piece(&f.peer, 0, 5); rec.Code != http.StatusNotFound || errCode(t, rec) != "console-off" {
		t.Fatalf("console off: %d", rec.Code)
	}
	t.Setenv("MON_CONSOLE", "1")
	for _, bad := range []string{filepath.Join(f.home, "Documents"), filepath.Join(f.home, "nope.txt"), "notes.txt"} {
		if r := f.command(t, f.peer, "open", map[string]string{"path": bad}); r.Code == 0 {
			t.Fatalf("%s opened", bad)
		}
	}
}

func TestFilesRefusedToAPortableCopy(t *testing.T) {
	// The kind is the tunnel's alone, and only an allowlisted browser's: a
	// command without a peer is not one a token can be bound to.
	f := newFilesFixture(t)
	signer := f.priv.Public().(ed25519.PublicKey)
	if r := runFilesCommand(consoleCmd{ID: "p", Kind: "files", Target: "list", Cmd: "{}"}, key.NodePublic{}, false, signer); r.Error != "not-allowed" {
		t.Fatalf("no peer: %+v", r)
	}
	// Nor without the key that signed it: a token is pinned to that too.
	if r := runFilesCommand(consoleCmd{ID: "p", Kind: "files", Target: "list", Cmd: "{}"}, f.peer, true, nil); r.Error != "not-allowed" {
		t.Fatalf("no signer: %+v", r)
	}
	if r := f.command(t, f.peer, "nonsense", map[string]string{}); r.Error != "unknown-op" {
		t.Fatalf("an unknown op: %+v", r)
	}
}

// A page with nothing new on it is an empty list, never null: the tab reads
// hits as a list and stops at anything else.
func TestFilesEmptyPageIsAList(t *testing.T) {
	f := newFilesFixture(t)
	res := f.command(t, f.peer, "search", map[string]string{"q": "nothing-is-called-this"})
	if res.Code != 0 {
		t.Fatalf("search: %+v", res)
	}
	var started struct {
		T string `json:"t"`
	}
	json.Unmarshal([]byte(res.Out), &started)
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := f.get(t, "/v1/files/search?s="+started.T, &f.peer)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hits":[]`) {
			t.Fatalf("an empty page: %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `"done":true`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the search never finished")
		}
	}
	// A page asked for far past the end (on a 32-bit build, past an int)
	// is the end, not a panic.
	if rec := f.get(t, "/v1/files/search?s="+started.T+"&from=999999999999999", &f.peer); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hits":[]`) {
		t.Fatalf("far past the end: %d %s", rec.Code, rec.Body.String())
	}
}

// The tailnet road serves the two reads as the tailcat one does: a token it
// handed out is good for the search and the file behind it.
func TestFilesReadsAreOnTheTailnetRoad(t *testing.T) {
	for _, p := range []string{"/v1/files/search", "/v1/files/file"} {
		if !tailnetInnerOK(p) {
			t.Errorf("%s is not served over the tailnet road", p)
		}
	}
}

// A search stopped, or replaced, while its walk is reading a folder: the
// walk finds it over and publishes nothing more (once it closed the poll's
// wake a second time and took the helper down).
func TestFilesStoppedWhileWalking(t *testing.T) {
	f := newFilesFixture(t)
	for i := 0; i < 300; i++ {
		writeFile(t, filepath.Join(f.home, "Many", fmt.Sprintf("d%03d", i), "report.txt"), []byte("x"))
	}
	var last string
	for round := 0; round < 20; round++ {
		res := f.command(t, f.peer, "search", map[string]string{"q": "report"})
		if res.Error == "busy" {
			// The walks replaced a moment ago have not seen it yet.
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if res.Code != 0 {
			t.Fatalf("search: %+v", res)
		}
		var started struct {
			T string `json:"t"`
		}
		json.Unmarshal([]byte(res.Out), &started)
		last = started.T
		if round%2 == 0 {
			if r := f.command(t, f.peer, "stop", map[string]string{"t": started.T}); r.Code != 0 {
				t.Fatalf("stop: %+v", r)
			}
		}
	}
	f.command(t, f.peer, "stop", map[string]string{"t": last})
	deadline := time.Now().Add(5 * time.Second)
	for filesWalking.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d walks still going after every search was stopped", filesWalking.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Unpinning the key that asked ends what it opened and searched, as it ends
// its terminals; another pinned key keeps the machine sealed meanwhile.
func TestFilesUnpinnedSignerEndsItsTokens(t *testing.T) {
	f := newFilesFixture(t)
	other, _, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(other)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.home, "Documents", "notes.txt")
	r := f.command(t, f.peer, "open", map[string]string{"path": p})
	if r.Code != 0 {
		t.Fatalf("open: %+v", r)
	}
	var o filesOpenBody
	json.Unmarshal([]byte(r.Out), &o)
	s := f.command(t, f.peer, "search", map[string]string{"q": "report"})
	var started struct {
		T string `json:"t"`
	}
	json.Unmarshal([]byte(s.Out), &started)
	if rec := f.get(t, "/v1/files/file?s="+url.QueryEscape(o.T)+"&o=0&n=4", &f.peer); rec.Code != 200 {
		t.Fatalf("a piece before: %d", rec.Code)
	}
	if err := untrustKey(base64.StdEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	if !loadTrust().sealed {
		t.Fatal("the other key should keep the machine sealed")
	}
	if rec := f.get(t, "/v1/files/file?s="+url.QueryEscape(o.T)+"&o=0&n=4", &f.peer); rec.Code != http.StatusNotFound {
		t.Fatalf("a piece after its key was unpinned: %d", rec.Code)
	}
	if rec := f.get(t, "/v1/files/search?s="+started.T, &f.peer); rec.Code != http.StatusNotFound {
		t.Fatalf("a page after its key was unpinned: %d", rec.Code)
	}
}

// A file token nobody has read for longer than it keeps is gone at the next
// read, sweep or no sweep.
func TestFilesTokenRunsOut(t *testing.T) {
	f := newFilesFixture(t)
	p := filepath.Join(f.home, "Documents", "notes.txt")
	r := f.command(t, f.peer, "open", map[string]string{"path": p})
	var o filesOpenBody
	json.Unmarshal([]byte(r.Out), &o)
	filesOpened.Lock()
	filesOpened.m[o.T].seen = time.Now().Add(-filesOpenKeep - time.Second)
	filesOpened.Unlock()
	if rec := f.get(t, "/v1/files/file?s="+url.QueryEscape(o.T)+"&o=0&n=4", &f.peer); rec.Code != http.StatusNotFound {
		t.Fatalf("a token past its time: %d", rec.Code)
	}
}
