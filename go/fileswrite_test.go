package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// endAllPuts ends every upload, so none is left open, or counted against the
// limits, for the next test.
func endAllPuts() {
	filesPuts.Lock()
	var all []*filesPut
	for tok, p := range filesPuts.m {
		all = append(all, p)
		delete(filesPuts.m, tok)
	}
	filesPuts.Unlock()
	for _, p := range all {
		p.end("test", false)
	}
}

// newWriteFixture is the files fixture with every upload ended when the test
// is.
func newWriteFixture(t *testing.T) *filesFixture {
	t.Helper()
	f := newFilesFixture(t)
	endAllPuts()
	t.Cleanup(endAllPuts)
	return f
}

// put opens an upload; a refusal stops the test.
func (f *filesFixture) put(t *testing.T, arg map[string]any) filesPutBody {
	t.Helper()
	r := f.command(t, f.peer, "put", arg)
	if r.Code != 0 {
		t.Fatalf("put %v: %+v", arg, r)
	}
	var b filesPutBody
	if err := json.Unmarshal([]byte(r.Out), &b); err != nil || b.T == "" {
		t.Fatalf("put answered %q", r.Out)
	}
	return b
}

// piece sends one piece of an upload as peer. Safe from another goroutine.
func (f *filesFixture) piece(peer *key.NodePublic, tok string, off int64, b []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/files/put?s="+url.QueryEscape(tok)+"&o="+strconv.FormatInt(off, 10), bytes.NewReader(b))
	if peer != nil {
		req = req.WithContext(transport.WithPeer(req.Context(), *peer))
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// done names a finished upload; the error's code when it is refused.
func (f *filesFixture) done(t *testing.T, tok string, more map[string]any) (filesDoneBody, string) {
	t.Helper()
	arg := map[string]any{"t": tok}
	for k, v := range more {
		arg[k] = v
	}
	r := f.command(t, f.peer, "done", arg)
	if r.Code != 0 {
		return filesDoneBody{}, r.Error
	}
	var b filesDoneBody
	if err := json.Unmarshal([]byte(r.Out), &b); err != nil {
		t.Fatalf("done answered %q", r.Out)
	}
	return b, ""
}

// pieceHave reads a piece's answer: the bytes the part holds (200, or 409
// with them) and the error's code, "" for a piece taken.
func pieceHave(rec *httptest.ResponseRecorder) (int64, string) {
	if rec.Code == http.StatusOK {
		var b struct {
			Have int64 `json:"have"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &b) != nil {
			return -1, "bad-answer"
		}
		return b.Have, ""
	}
	fr, err := transport.Decode(rec.Body.Bytes())
	if err != nil || fr.Type != transport.TypeError {
		return -1, fmt.Sprintf("status %d", rec.Code)
	}
	var e struct {
		Code string `json:"code"`
		Have int64  `json:"have"`
	}
	json.Unmarshal(fr.Body, &e)
	return e.Have, e.Code
}

func putOf(tok string) *filesPut {
	filesPuts.Lock()
	defer filesPuts.Unlock()
	return filesPuts.m[tok]
}

func (p *filesPut) waitingNow() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waiting
}

func filesWaitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// partsIn is the part files in dir.
func partsIn(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), filesPartPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func resultPath(r consoleResult) string {
	var b struct {
		Path string `json:"path"`
	}
	json.Unmarshal([]byte(r.Out), &b)
	return b.Path
}

// walk runs a walk of in to its end: the hits relative to home (a folder
// with a slash after it, a link with an @), sorted, the hits as they came,
// and the last page.
func (f *filesFixture) walk(t *testing.T, in string) ([]string, []filesHit, filesPage) {
	t.Helper()
	r := f.command(t, f.peer, "walk", map[string]string{"in": in})
	if r.Code != 0 {
		t.Fatalf("walk %s: %+v", in, r)
	}
	var started struct {
		T    string `json:"t"`
		Page int    `json:"page"`
		Hits int    `json:"hits"`
	}
	json.Unmarshal([]byte(r.Out), &started)
	if started.T == "" || started.Page != filesWalkPage || started.Hits != filesWalkLimit {
		t.Fatalf("walk answered %q", r.Out)
	}
	var names []string
	var all []filesHit
	from := 0
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rec := f.get(t, "/v1/files/search?s="+started.T+fmt.Sprintf("&from=%d", from), &f.peer)
		if rec.Code != 200 {
			t.Fatalf("walk page: %d %s", rec.Code, rec.Body.String())
		}
		var p filesPage
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		for _, h := range p.Hits {
			rel, _ := filepath.Rel(f.home, h.P)
			rel = filepath.ToSlash(rel)
			if h.D {
				rel += "/"
			}
			if h.L {
				rel += "@"
			}
			names = append(names, rel)
			all = append(all, h)
		}
		from = p.Next
		if p.Done {
			sort.Strings(names)
			return names, all, p
		}
	}
	t.Fatal("the walk never finished")
	return nil, nil, filesPage{}
}

// A file comes in a piece at a time under a name no listing shows, and only
// done gives it its own, with the time the page named.
func TestFilesPutInPieces(t *testing.T) {
	f := newWriteFixture(t)
	dir := filepath.Join(f.home, "Documents")
	data := []byte("the first piece|the second|and the last")
	b := f.put(t, map[string]any{"dir": dir, "name": "carried.txt", "size": len(data)})
	if b.Have != 0 || b.Max != filesPutMax || b.Taken || !strings.HasPrefix(b.Part, filesPartPrefix) || !strings.HasSuffix(b.Part, filesPartSuffix) {
		t.Fatalf("put: %+v", b)
	}
	r := f.command(t, f.peer, "list", map[string]string{"path": dir})
	var l filesListBody
	json.Unmarshal([]byte(r.Out), &l)
	for _, e := range l.Files {
		if strings.HasPrefix(e.N, filesPartPrefix) {
			t.Fatalf("the part is listed: %+v", l)
		}
	}
	for _, cut := range [][2]int{{0, 16}, {16, 27}} {
		if have, code := pieceHave(f.piece(&f.peer, b.T, int64(cut[0]), data[cut[0]:cut[1]])); code != "" || have != int64(cut[1]) {
			t.Fatalf("piece %v: %d %s", cut, have, code)
		}
	}
	if _, code := f.done(t, b.T, nil); code != "short" {
		t.Fatalf("done before the last piece: %q", code)
	}
	if have, code := pieceHave(f.piece(&f.peer, b.T, 27, data[27:])); code != "" || have != int64(len(data)) {
		t.Fatalf("the last piece: %d %s", have, code)
	}
	want := filepath.Join(dir, "carried.txt")
	if _, err := os.Lstat(want); err == nil {
		t.Fatal("named before done")
	}
	const m = 1700000000
	d, code := f.done(t, b.T, map[string]any{"m": m})
	if code != "" || d.Path != want || d.N != "carried.txt" || d.S != int64(len(data)) {
		t.Fatalf("done: %+v %q", d, code)
	}
	if got, err := os.ReadFile(want); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the file: %q %v", got, err)
	}
	if fi, err := os.Stat(want); err != nil || fi.ModTime().Unix() != m {
		t.Fatalf("its time: %v %v", fi, err)
	}
	if ps := partsIn(dir); len(ps) != 0 {
		t.Fatalf("parts left: %v", ps)
	}
	if _, code := pieceHave(f.piece(&f.peer, b.T, 0, data[:1])); code != "no-put" {
		t.Fatalf("a piece after done: %q", code)
	}
	if _, code := f.done(t, b.T, nil); code != "no-put" {
		t.Fatalf("done twice: %q", code)
	}
	// Nothing to send: done at once makes the empty file.
	e := f.put(t, map[string]any{"dir": f.home, "name": "empty.txt", "size": 0})
	if d, code := f.done(t, e.T, nil); code != "" || d.S != 0 {
		t.Fatalf("an empty file: %+v %q", d, code)
	} else if fi, err := os.Stat(d.Path); err != nil || fi.Size() != 0 {
		t.Fatalf("an empty file: %v %v", fi, err)
	}
}

// A piece that comes before its turn waits for the one before it, and the
// file is written in order whatever order the pieces came in.
func TestFilesPutEarlyPieceWaitsItsTurn(t *testing.T) {
	f := newWriteFixture(t)
	b := f.put(t, map[string]any{"dir": f.home, "name": "ordered.bin", "size": 8})
	p := putOf(b.T)
	type answer struct {
		have int64
		code string
	}
	early := make(chan answer, 1)
	go func() {
		have, code := pieceHave(f.piece(&f.peer, b.T, 4, []byte("EFGH")))
		early <- answer{have, code}
	}()
	filesWaitFor(t, "the early piece to wait", func() bool { return p.waitingNow() == 1 })
	select {
	case a := <-early:
		t.Fatalf("the early piece did not wait: %+v", a)
	default:
	}
	if have, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD"))); code != "" || have != 4 {
		t.Fatalf("the first piece: %d %q", have, code)
	}
	select {
	case a := <-early:
		if a.code != "" || a.have != 8 {
			t.Fatalf("the early piece: %+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the early piece was never written")
	}
	d, code := f.done(t, b.T, nil)
	if code != "" {
		t.Fatalf("done: %q", code)
	}
	if got, _ := os.ReadFile(d.Path); string(got) != "ABCDEFGH" {
		t.Fatalf("out of order: %q", got)
	}
}

// A piece sent again (its answer lost) is taken as done; one that overlaps
// what is written is refused with where the part stands; one past the end,
// or bigger than a piece may be, is refused outright.
func TestFilesPutRetriedAndOverlappingPieces(t *testing.T) {
	f := newWriteFixture(t)
	b := f.put(t, map[string]any{"dir": f.home, "name": "retried.bin", "size": 10})
	if have, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("01234"))); code != "" || have != 5 {
		t.Fatalf("a piece: %d %q", have, code)
	}
	if have, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("01234"))); code != "" || have != 5 {
		t.Fatalf("the same piece again: %d %q", have, code)
	}
	rec := f.piece(&f.peer, b.T, 3, []byte("34567"))
	if have, code := pieceHave(rec); rec.Code != http.StatusConflict || code != "offset" || have != 5 {
		t.Fatalf("an overlap: %d %d %q", rec.Code, have, code)
	}
	if rec := f.piece(&f.peer, b.T, 8, []byte("89X")); rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("past the end: %d", rec.Code)
	}
	if rec := f.piece(&f.peer, b.T, 11, nil); rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("an offset past the end: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/files/put?s="+b.T+"&o=5", strings.NewReader("56789"))
	req.ContentLength = filesPutMax + 1
	req = req.WithContext(transport.WithPeer(req.Context(), f.peer))
	big := httptest.NewRecorder()
	f.h.ServeHTTP(big, req)
	if big.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a piece bigger than a piece: %d", big.Code)
	}
	if rec := f.get(t, "/v1/files/put?s="+b.T+"&o=5", &f.peer); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a GET: %d", rec.Code)
	}
	if have, code := pieceHave(f.piece(&f.peer, b.T, 5, []byte("56789"))); code != "" || have != 10 {
		t.Fatalf("the rest: %d %q", have, code)
	}
	if d, code := f.done(t, b.T, nil); code != "" {
		t.Fatalf("done: %q", code)
	} else if got, _ := os.ReadFile(d.Path); string(got) != "0123456789" {
		t.Fatalf("the file: %q", got)
	}
}

// An early piece is held so long and no longer, and only so many at once;
// the ones held go in as their turns come.
func TestFilesPutHoldAndWaiters(t *testing.T) {
	f := newWriteFixture(t)
	saved := filesPutHold
	t.Cleanup(func() { filesPutHold = saved })
	filesPutHold = 150 * time.Millisecond
	b := f.put(t, map[string]any{"dir": f.home, "name": "held.bin", "size": 5})
	start := time.Now()
	rec := f.piece(&f.peer, b.T, 4, []byte("e"))
	if have, code := pieceHave(rec); rec.Code != http.StatusConflict || code != "offset" || have != 0 || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("a piece whose turn never came: %d %d %q after %v", rec.Code, have, code, time.Since(start))
	}

	filesPutHold = 5 * time.Second
	p := putOf(b.T)
	got := make(chan string, filesPutWaiters)
	for off := 1; off <= filesPutWaiters; off++ {
		go func(off int) {
			have, code := pieceHave(f.piece(&f.peer, b.T, int64(off), []byte{"abcde"[off]}))
			if code == "" && have < int64(off+1) {
				code = fmt.Sprintf("have %d", have)
			}
			got <- code
		}(off)
	}
	filesWaitFor(t, "four pieces to wait", func() bool { return p.waitingNow() == filesPutWaiters })
	rec = f.piece(&f.peer, b.T, 2, []byte("c"))
	if have, code := pieceHave(rec); code != "offset" || have != 0 {
		t.Fatalf("a fifth early piece: %d %d %q", rec.Code, have, code)
	}
	if _, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("a"))); code != "" {
		t.Fatalf("the first piece: %q", code)
	}
	for i := 0; i < filesPutWaiters; i++ {
		select {
		case code := <-got:
			if code != "" {
				t.Fatalf("a held piece: %q", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a held piece never went in")
		}
	}
	if d, code := f.done(t, b.T, nil); code != "" {
		t.Fatalf("done: %q", code)
	} else if c, _ := os.ReadFile(d.Path); string(c) != "abcde" {
		t.Fatalf("the file: %q", c)
	}
}

// A page that names a key comes back to its part: the same peer and signer
// asking again ends the upload it had (a piece of it still waiting is told
// so) and goes on from what the part holds; anybody else is told busy.
func TestFilesPutComesBackWithItsKey(t *testing.T) {
	f := newWriteFixture(t)
	const k = "resume-key-0001"
	arg := map[string]any{"dir": f.home, "name": "resumed.bin", "size": 8, "k": k}
	b := f.put(t, arg)
	if b.Part != filesPartPrefix+k+filesPartSuffix || b.Have != 0 {
		t.Fatalf("put: %+v", b)
	}
	if _, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD"))); code != "" {
		t.Fatalf("a piece: %q", code)
	}
	other := key.NewNode().Public()
	if err := allowClient(other.String()); err != nil {
		t.Fatal(err)
	}
	if r := f.command(t, other, "put", arg); r.Error != "busy" {
		t.Fatalf("another browser's put of the same part: %+v", r)
	}
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub2)); err != nil {
		t.Fatal(err)
	}
	mine := f.priv
	f.priv = priv2
	r := f.command(t, f.peer, "put", arg)
	f.priv = mine
	if r.Error != "busy" {
		t.Fatalf("another key's put of the same part: %+v", r)
	}

	p := putOf(b.T)
	waiting := make(chan string, 1)
	go func() {
		_, code := pieceHave(f.piece(&f.peer, b.T, 6, []byte("GH")))
		waiting <- code
	}()
	filesWaitFor(t, "the early piece to wait", func() bool { return p.waitingNow() == 1 })
	again := f.put(t, arg)
	if again.T == b.T || again.Have != 4 || again.Part != b.Part {
		t.Fatalf("put again: %+v", again)
	}
	select {
	case code := <-waiting:
		if code != "no-put" {
			t.Fatalf("the old upload's waiting piece: %q", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the old upload's waiting piece was never told")
	}
	if _, code := pieceHave(f.piece(&f.peer, b.T, 4, []byte("EF"))); code != "no-put" {
		t.Fatalf("the old token: %q", code)
	}
	if have, code := pieceHave(f.piece(&f.peer, again.T, 4, []byte("EFGH"))); code != "" || have != 8 {
		t.Fatalf("the rest: %d %q", have, code)
	}
	if d, code := f.done(t, again.T, nil); code != "" {
		t.Fatalf("done: %q", code)
	} else if got, _ := os.ReadFile(d.Path); string(got) != "ABCDEFGH" {
		t.Fatalf("the file: %q", got)
	}
	if ps := partsIn(f.home); len(ps) != 0 {
		t.Fatalf("parts left: %v", ps)
	}
	// A part longer than the file now announced starts over.
	long := map[string]any{"dir": f.home, "name": "shorter.bin", "size": 8, "k": "resume-key-0002"}
	l := f.put(t, long)
	if _, code := pieceHave(f.piece(&f.peer, l.T, 0, []byte("12345678"))); code != "" {
		t.Fatalf("a piece: %q", code)
	}
	long["size"] = 4
	if s := f.put(t, long); s.Have != 0 {
		t.Fatalf("a part longer than the file: %+v", s)
	}
	if fi, err := os.Stat(filepath.Join(f.home, l.Part)); err != nil || fi.Size() != 0 {
		t.Fatalf("the part: %v %v", fi, err)
	}
}

// An upload nobody sends to is closed; its part stays for a page that named
// a key, and goes for one that did not.
func TestFilesPutIdle(t *testing.T) {
	f := newWriteFixture(t)
	keyed := f.put(t, map[string]any{"dir": f.home, "name": "keyed.bin", "size": 8, "k": "idle-key-0001"})
	plain := f.put(t, map[string]any{"dir": f.home, "name": "plain.bin", "size": 8})
	for _, tok := range []string{keyed.T, plain.T} {
		if _, code := pieceHave(f.piece(&f.peer, tok, 0, []byte("ABCD"))); code != "" {
			t.Fatalf("a piece: %q", code)
		}
		p := putOf(tok)
		p.mu.Lock()
		p.seen = time.Now().Add(-filesPutIdle - time.Second)
		p.mu.Unlock()
	}
	filesPutSweep(time.Now())
	for _, tok := range []string{keyed.T, plain.T} {
		if _, code := pieceHave(f.piece(&f.peer, tok, 4, []byte("EFGH"))); code != "no-put" {
			t.Fatalf("a piece after the sweep: %q", code)
		}
	}
	if ps := partsIn(f.home); strings.Join(ps, ",") != keyed.Part {
		t.Fatalf("the parts kept: %v", ps)
	}
	if again := f.put(t, map[string]any{"dir": f.home, "name": "keyed.bin", "size": 8, "k": "idle-key-0001"}); again.Have != 4 {
		t.Fatalf("back after the sweep: %+v", again)
	}
}

// Keep both (the default), replace (a file, keeping who may read it, never
// a folder) or fail, told at put when the name is taken already and at done
// when it was taken meanwhile; a failed done leaves the upload to be done
// again as the person chose.
func TestFilesPutKeepsBothOrReplaces(t *testing.T) {
	f := newWriteFixture(t)
	dir := filepath.Join(f.home, "Documents")
	orig := filepath.Join(dir, "notes.txt")
	before, _ := os.ReadFile(orig)
	carry := func(name, mode, data string) (filesDoneBody, string, bool) {
		t.Helper()
		b := f.put(t, map[string]any{"dir": dir, "name": name, "size": len(data), "mode": mode})
		if _, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte(data))); code != "" {
			t.Fatalf("a piece: %q", code)
		}
		d, code := f.done(t, b.T, nil)
		return d, code, b.Taken
	}
	if d, code, taken := carry("notes.txt", "", "second"); code != "" || !taken || d.N != "notes (2).txt" {
		t.Fatalf("keep both: %+v %q %v", d, code, taken)
	}
	if d, _, _ := carry("notes.txt", "keep", "third"); d.N != "notes (3).txt" {
		t.Fatalf("keep both again: %+v", d)
	}
	if got, _ := os.ReadFile(orig); !bytes.Equal(got, before) {
		t.Fatalf("the first was touched: %q", got)
	}
	if err := os.Chmod(orig, 0o640); err != nil {
		t.Fatal(err)
	}
	if d, code, _ := carry("notes.txt", "replace", "replaced"); code != "" || d.Path != orig {
		t.Fatalf("replace: %+v %q", d, code)
	}
	if got, _ := os.ReadFile(orig); string(got) != "replaced" {
		t.Fatalf("replaced: %q", got)
	}
	if fi, err := os.Stat(orig); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("who may read it: %v %v", fi, err)
	}
	if r := f.command(t, f.peer, "put", map[string]any{"dir": f.home, "name": "Reports", "size": 1, "mode": "replace"}); r.Error != "exists" {
		t.Fatalf("a folder replaced: %+v", r)
	}
	if r := f.command(t, f.peer, "put", map[string]any{"dir": dir, "name": "notes.txt", "size": 1, "mode": "fail"}); r.Error != "exists" {
		t.Fatalf("fail on a taken name: %+v", r)
	}
	if ps := partsIn(dir); len(ps) != 0 {
		t.Fatalf("parts left by refused puts: %v", ps)
	}

	b := f.put(t, map[string]any{"dir": dir, "name": "late.txt", "size": 4, "mode": "fail"})
	pieceHave(f.piece(&f.peer, b.T, 0, []byte("late")))
	writeFile(t, filepath.Join(dir, "late.txt"), []byte("first"))
	if _, code := f.done(t, b.T, nil); code != "exists" {
		t.Fatalf("a name taken meanwhile: %q", code)
	}
	if d, code := f.done(t, b.T, map[string]any{"mode": "keep"}); code != "" || d.N != "late (2).txt" {
		t.Fatalf("done again, keeping both: %+v %q", d, code)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "late.txt")); string(got) != "first" {
		t.Fatalf("the one there first: %q", got)
	}

	b = f.put(t, map[string]any{"dir": dir, "name": "box", "size": 3, "mode": "replace"})
	pieceHave(f.piece(&f.peer, b.T, 0, []byte("box")))
	if err := os.Mkdir(filepath.Join(dir, "box"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, code := f.done(t, b.T, nil); code != "exists" {
		t.Fatalf("a folder in the way of a replace: %q", code)
	}
	if d, code := f.done(t, b.T, map[string]any{"mode": "keep"}); code != "" || d.N != "box (2)" {
		t.Fatalf("done again: %+v %q", d, code)
	}
	if fi, err := os.Stat(filepath.Join(dir, "box")); err != nil || !fi.IsDir() {
		t.Fatalf("the folder: %v %v", fi, err)
	}
}

// A disk without hard links still gets the file, under a free name.
func TestFilesPutWithoutHardLinks(t *testing.T) {
	f := newWriteFixture(t)
	saved := filesLink
	t.Cleanup(func() { filesLink = saved })
	filesLink = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errors.New("no hard links here")}
	}
	dir := filepath.Join(f.home, "Documents")
	for _, c := range []struct{ name, want string }{{"notes.txt", "notes (2).txt"}, {"fresh.txt", "fresh.txt"}} {
		b := f.put(t, map[string]any{"dir": dir, "name": c.name, "size": 3})
		pieceHave(f.piece(&f.peer, b.T, 0, []byte("abc")))
		d, code := f.done(t, b.T, nil)
		if code != "" || d.N != c.want {
			t.Fatalf("%s: %+v %q", c.name, d, code)
		}
		if got, _ := os.ReadFile(d.Path); string(got) != "abc" {
			t.Fatalf("%s: %q", c.name, got)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "notes.txt")); string(got) != "content of Documents/notes.txt" {
		t.Fatalf("the one there: %q", got)
	}
	if ps := partsIn(dir); len(ps) != 0 {
		t.Fatalf("parts left: %v", ps)
	}
}

// cancel ends the upload and takes its part away, key or no key.
func TestFilesPutCancel(t *testing.T) {
	f := newWriteFixture(t)
	b := f.put(t, map[string]any{"dir": f.home, "name": "dropped.bin", "size": 8, "k": "cancel-key-01"})
	pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD")))
	if r := f.command(t, f.peer, "cancel", map[string]any{"t": b.T}); r.Code != 0 {
		t.Fatalf("cancel: %+v", r)
	}
	if ps := partsIn(f.home); len(ps) != 0 {
		t.Fatalf("parts left: %v", ps)
	}
	if _, code := pieceHave(f.piece(&f.peer, b.T, 4, []byte("EFGH"))); code != "no-put" {
		t.Fatalf("a piece after cancel: %q", code)
	}
	if r := f.command(t, f.peer, "cancel", map[string]any{"t": "not-a-token"}); r.Code != 0 {
		t.Fatalf("cancel of nothing: %+v", r)
	}
}

// An upload is its peer's alone, while the console is on and the key that
// signed its put stays pinned.
func TestFilesPutBelongsToItsPeerAndKey(t *testing.T) {
	f := newWriteFixture(t)
	b := f.put(t, map[string]any{"dir": f.home, "name": "mine.bin", "size": 8})
	other := key.NewNode().Public()
	if err := allowClient(other.String()); err != nil {
		t.Fatal(err)
	}
	if _, code := pieceHave(f.piece(&other, b.T, 0, []byte("ABCD"))); code != "no-put" {
		t.Fatalf("another browser's piece: %q", code)
	}
	if rec := f.piece(nil, b.T, 0, []byte("ABCD")); rec.Code != http.StatusForbidden {
		t.Fatalf("no peer: %d", rec.Code)
	}
	stranger := key.NewNode().Public()
	if rec := f.piece(&stranger, b.T, 0, []byte("ABCD")); rec.Code != http.StatusForbidden {
		t.Fatalf("a stranger: %d", rec.Code)
	}
	if r := f.command(t, other, "done", map[string]any{"t": b.T}); r.Error != "no-put" {
		t.Fatalf("another browser's done: %+v", r)
	}
	f.command(t, other, "cancel", map[string]any{"t": b.T})
	if have, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD"))); code != "" || have != 4 {
		t.Fatalf("after another browser's cancel: %d %q", have, code)
	}
	t.Setenv("MON_CONSOLE", "0")
	if _, code := pieceHave(f.piece(&f.peer, b.T, 4, []byte("EFGH"))); code != "console-off" {
		t.Fatalf("console off: %q", code)
	}
	if r := f.command(t, f.peer, "mkdir", map[string]any{"dir": f.home, "name": "x"}); r.Error != "console-off" {
		t.Fatalf("a folder with the console off: %+v", r)
	}
	t.Setenv("MON_CONSOLE", "1")
	pub2, _, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub2)); err != nil {
		t.Fatal(err)
	}
	if err := untrustKey(base64.StdEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	if _, code := pieceHave(f.piece(&f.peer, b.T, 4, []byte("EFGH"))); code != "no-put" {
		t.Fatalf("a piece after its key was unpinned: %q", code)
	}
	filesPutSweep(time.Now())
	if ps := partsIn(f.home); len(ps) != 0 {
		t.Fatalf("the part of an upload whose key went: %v", ps)
	}
}

func TestFilesPutRefusesWhatItCannotTake(t *testing.T) {
	f := newWriteFixture(t)
	good := func(m map[string]any) map[string]any {
		a := map[string]any{"dir": f.home, "name": "a.bin", "size": 1}
		for k, v := range m {
			a[k] = v
		}
		return a
	}
	cases := []struct {
		arg  map[string]any
		code string
	}{
		{good(map[string]any{"dir": "relative/dir"}), "bad-path"},
		{good(map[string]any{"dir": filepath.Join(f.home, "missing")}), "missing"},
		{good(map[string]any{"dir": filepath.Join(f.home, "Documents", "notes.txt")}), "not-a-folder"},
		{good(map[string]any{"size": -1}), "bad-args"},
		{good(map[string]any{"size": filesPutSize + 1}), "bad-args"},
		{good(map[string]any{"k": "short"}), "bad-args"},
		{good(map[string]any{"k": "has spaces in it"}), "bad-args"},
		{good(map[string]any{"mode": "overwrite"}), "bad-args"},
	}
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, filesPartPrefix + "x" + filesPartSuffix, "a\x01b", "tab\there", strings.Repeat("n", filesNameMax+1)} {
		cases = append(cases, struct {
			arg  map[string]any
			code string
		}{good(map[string]any{"name": n}), "bad-name"})
	}
	for _, c := range cases {
		if r := f.command(t, f.peer, "put", c.arg); r.Error != c.code {
			t.Errorf("put %v: %+v, want %s", c.arg, r, c.code)
		}
	}
	if ps := partsIn(f.home); len(ps) != 0 {
		t.Fatalf("parts left by refused puts: %v", ps)
	}
	b := f.put(t, good(nil))
	if r := f.command(t, f.peer, "done", map[string]any{"t": b.T, "mode": "sideways"}); r.Error != "bad-args" {
		t.Fatalf("done in a mode that is none: %+v", r)
	}
	if r := f.command(t, f.peer, "done", map[string]any{"t": "nope"}); r.Error != "no-put" {
		t.Fatalf("done of nothing: %+v", r)
	}
}

func TestFilesNamesWindowsWouldRefuse(t *testing.T) {
	for _, n := range []string{"CON", "con.txt", "Aux.tar.gz", "nul", "COM1", "lpt9.log", "COM0", "COM¹", "lpt³.txt",
		"CONIN$", "a:b", "a<b", "what?", "star*", `quo"te`, "pipe|", "trailing.", "trailing "} {
		if filesNameOK(n, "windows") {
			t.Errorf("%q taken on Windows", n)
		}
	}
	for _, n := range []string{"COM10", "console.txt", "LPT", "com", "a.b.c", "résumé.pdf", "x y", ".env"} {
		if !filesNameOK(n, "windows") {
			t.Errorf("%q refused on Windows", n)
		}
	}
	for _, n := range []string{"con.txt", "a:b", "what?", "trailing.", "résumé.pdf"} {
		if !filesNameOK(n, "linux") {
			t.Errorf("%q refused on Linux", n)
		}
	}
	if filesNameOK("bad\xffutf8", "linux") {
		t.Error("a name that is not UTF-8 was taken")
	}
}

func TestFilesNumberedNames(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int
		want string
	}{
		{"report.pdf", 2, "report (2).pdf"},
		{"archive.tar.gz", 3, "archive.tar (3).gz"},
		{".env", 2, ".env (2)"},
		{"Makefile", 12, "Makefile (12)"},
	} {
		if got := filesNumbered(c.name, c.n, filesNameMax); got != c.want {
			t.Errorf("%s %d: %q, want %q", c.name, c.n, got, c.want)
		}
	}
	long := strings.Repeat("é", 125) + ".txt"
	got := filesNumbered(long, 2, filesNameMax)
	if len(got) > filesNameMax || !utf8.ValidString(got) || !strings.HasSuffix(got, " (2).txt") || !filesNameOK(got, "linux") {
		t.Fatalf("a long name numbered: %d bytes, %q", len(got), got)
	}
}

// Too many at once: sixteen a browser, thirty-two on the helper.
func TestFilesPutLimits(t *testing.T) {
	f := newWriteFixture(t)
	var first string
	for i := 0; i < filesPutPerPeer; i++ {
		b := f.put(t, map[string]any{"dir": f.home, "name": fmt.Sprintf("n%02d", i), "size": 1})
		if i == 0 {
			first = b.T
		}
	}
	if r := f.command(t, f.peer, "put", map[string]any{"dir": f.home, "name": "one-more", "size": 1}); r.Error != "busy" {
		t.Fatalf("a browser's seventeenth: %+v", r)
	}
	second := key.NewNode().Public()
	allowClient(second.String())
	for i := 0; i < filesPutOpen-filesPutPerPeer; i++ {
		if r := f.command(t, second, "put", map[string]any{"dir": f.home, "name": fmt.Sprintf("m%02d", i), "size": 1}); r.Code != 0 {
			t.Fatalf("another browser's: %+v", r)
		}
	}
	third := key.NewNode().Public()
	allowClient(third.String())
	if r := f.command(t, third, "put", map[string]any{"dir": f.home, "name": "third", "size": 1}); r.Error != "busy" {
		t.Fatalf("the helper's thirty-third: %+v", r)
	}
	f.command(t, f.peer, "cancel", map[string]any{"t": first})
	if r := f.command(t, third, "put", map[string]any{"dir": f.home, "name": "third", "size": 1}); r.Code != 0 {
		t.Fatalf("after one ended: %+v", r)
	}
}

func TestFilesFoldersNamesAndMoves(t *testing.T) {
	f := newWriteFixture(t)
	r := f.command(t, f.peer, "mkdir", map[string]any{"dir": f.home, "name": "New folder"})
	if r.Code != 0 || resultPath(r) != filepath.Join(f.home, "New folder") {
		t.Fatalf("mkdir: %+v", r)
	}
	if fi, err := os.Stat(filepath.Join(f.home, "New folder")); err != nil || !fi.IsDir() {
		t.Fatalf("the folder: %v %v", fi, err)
	}
	for _, c := range []struct {
		arg  map[string]any
		code string
	}{
		{map[string]any{"dir": f.home, "name": "New folder"}, "exists"},
		{map[string]any{"dir": filepath.Join(f.home, "nowhere"), "name": "x"}, "missing"},
		{map[string]any{"dir": f.home, "name": "a/b"}, "bad-name"},
	} {
		if r := f.command(t, f.peer, "mkdir", c.arg); r.Error != c.code {
			t.Errorf("mkdir %v: %+v, want %s", c.arg, r, c.code)
		}
	}

	notes := filepath.Join(f.home, "Documents", "notes.txt")
	renamed := filepath.Join(f.home, "Documents", "renamed.txt")
	if r := f.command(t, f.peer, "rename", map[string]any{"path": notes, "name": "renamed.txt"}); r.Code != 0 || resultPath(r) != renamed {
		t.Fatalf("rename: %+v", r)
	}
	if _, err := os.Lstat(notes); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the old name: %v", err)
	}
	for _, c := range []struct {
		arg  map[string]any
		code string
	}{
		{map[string]any{"path": renamed, "name": "report-2024.pdf"}, "exists"},
		{map[string]any{"path": f.home, "name": "elsewhere"}, "too-broad"},
		{map[string]any{"path": "/", "name": "elsewhere"}, "too-broad"},
		{map[string]any{"path": filepath.Join(f.home, "gone.txt"), "name": "x"}, "missing"},
		{map[string]any{"path": renamed, "name": "../out.txt"}, "bad-name"},
	} {
		if r := f.command(t, f.peer, "rename", c.arg); r.Error != c.code {
			t.Errorf("rename %v: %+v, want %s", c.arg, r, c.code)
		}
	}
	if r := f.command(t, f.peer, "rename", map[string]any{"path": renamed, "name": "renamed.txt"}); r.Code != 0 || resultPath(r) != renamed {
		t.Fatalf("a rename to its own name: %+v", r)
	}

	pdf := filepath.Join(f.home, "Documents", "report-2024.pdf")
	reports := filepath.Join(f.home, "Reports")
	if r := f.command(t, f.peer, "move", map[string]any{"path": pdf, "to": reports}); r.Code != 0 || resultPath(r) != filepath.Join(reports, "report-2024.pdf") {
		t.Fatalf("move: %+v", r)
	}
	writeFile(t, pdf, []byte("another"))
	if r := f.command(t, f.peer, "move", map[string]any{"path": pdf, "to": reports}); r.Code != 0 || resultPath(r) != filepath.Join(reports, "report-2024 (2).pdf") {
		t.Fatalf("move, keeping both: %+v", r)
	}
	writeFile(t, pdf, []byte("a third"))
	if r := f.command(t, f.peer, "move", map[string]any{"path": pdf, "to": reports, "mode": "fail"}); r.Error != "exists" {
		t.Fatalf("move, failing on a taken name: %+v", r)
	}
	if r := f.command(t, f.peer, "move", map[string]any{"path": pdf, "to": reports, "mode": "replace"}); r.Code != 0 || resultPath(r) != filepath.Join(reports, "report-2024.pdf") {
		t.Fatalf("move, replacing: %+v", r)
	}
	if got, _ := os.ReadFile(filepath.Join(reports, "report-2024.pdf")); string(got) != "a third" {
		t.Fatalf("replaced: %q", got)
	}
	work := filepath.Join(f.home, "Work")
	if err := os.Symlink(filepath.Join(work, "b"), filepath.Join(f.home, "to-b")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		arg  map[string]any
		code string
	}{
		{map[string]any{"path": work, "to": filepath.Join(work, "b", "c")}, "into-itself"},
		{map[string]any{"path": work, "to": work}, "into-itself"},
		{map[string]any{"path": work, "to": filepath.Join(f.home, "to-b")}, "into-itself"},
		{map[string]any{"path": f.home, "to": reports}, "too-broad"},
		{map[string]any{"path": renamed, "to": filepath.Join(reports, "report-2024.pdf")}, "not-a-folder"},
		{map[string]any{"path": renamed, "to": reports, "mode": "sideways"}, "bad-args"},
		{map[string]any{"path": filepath.Join(f.home, "gone.txt"), "to": reports}, "missing"},
	} {
		if r := f.command(t, f.peer, "move", c.arg); r.Error != c.code {
			t.Errorf("move %v: %+v, want %s", c.arg, r, c.code)
		}
	}
	if r := f.command(t, f.peer, "move", map[string]any{"path": filepath.Join(work, "b"), "to": work}); r.Code != 0 || resultPath(r) != filepath.Join(work, "b") {
		t.Fatalf("a move to the folder it is in: %+v", r)
	}
	// A link is moved as the link, not what it leads to.
	if r := f.command(t, f.peer, "move", map[string]any{"path": filepath.Join(f.home, "to-b"), "to": reports}); r.Code != 0 {
		t.Fatalf("a link moved: %+v", r)
	}
	if fi, err := os.Lstat(filepath.Join(reports, "to-b")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("the link: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(work, "b", "c", "other.txt")); err != nil || fi.IsDir() {
		t.Fatalf("what it led to: %v %v", fi, err)
	}
}

// The helper names the changes in its hello, under the grant the reads have,
// and both roads carry the pieces.
func TestFilesWritesOnBothRoads(t *testing.T) {
	f := newWriteFixture(t)
	if !tailnetInnerOK("/v1/files/put") {
		t.Fatal("the tailnet road does not carry a piece")
	}
	caps := func() []string {
		rec := f.get(t, "/v1/hello", &f.peer)
		fr, _ := transport.Decode(rec.Body.Bytes())
		var hello transport.Hello
		json.Unmarshal(fr.Body, &hello)
		return hello.Caps
	}
	if c := caps(); !containsStr(c, transport.CapFiles) || !containsStr(c, transport.CapFilesWrite) {
		t.Fatalf("console on: %v", c)
	}
	t.Setenv("MON_CONSOLE", "0")
	if c := caps(); containsStr(c, transport.CapFilesWrite) {
		t.Fatalf("console off: %v", c)
	}
}

// A walk is the whole tree: hidden files and folders and a package's
// insides too, a link named as one and never gone through.
func TestFilesWalkTakesTheWholeTree(t *testing.T) {
	f := newWriteFixture(t)
	proj := filepath.Join(f.home, "Proj")
	writeFile(t, filepath.Join(proj, ".git", "config"), []byte("[core]"))
	writeFile(t, filepath.Join(proj, ".env"), []byte("A=1"))
	writeFile(t, filepath.Join(proj, "node_modules", "m", "index.js"), []byte("x"))
	writeFile(t, filepath.Join(proj, "Tool.app", "Contents", "Info.plist"), []byte("<plist/>"))
	writeFile(t, filepath.Join(proj, "src", "main.go"), []byte("package main"))
	if err := os.Symlink(filepath.Join(f.home, "Documents"), filepath.Join(proj, "docs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("src/main.go", filepath.Join(proj, "main-link")); err != nil {
		t.Fatal(err)
	}
	names, hits, p := f.walk(t, proj)
	want := "Proj/.env,Proj/.git/,Proj/.git/config,Proj/Tool.app/,Proj/Tool.app/Contents/,Proj/Tool.app/Contents/Info.plist," +
		"Proj/docs@,Proj/main-link@,Proj/node_modules/,Proj/node_modules/m/,Proj/node_modules/m/index.js,Proj/src/,Proj/src/main.go"
	if strings.Join(names, ",") != want {
		t.Fatalf("the walk:\n%s\nwant\n%s", strings.Join(names, ","), want)
	}
	if p.Why != "" || p.Odd != 0 {
		t.Fatalf("the last page: %+v", p)
	}
	for _, h := range hits {
		switch filepath.Base(h.P) {
		case "config":
			if h.S != int64(len("[core]")) || h.M == 0 || h.D || h.L {
				t.Fatalf("a file: %+v", h)
			}
		case "docs", "main-link":
			if !h.L || h.D || h.S != 0 {
				t.Fatalf("a link: %+v", h)
			}
		}
	}
	for _, c := range []struct {
		arg  map[string]string
		code string
	}{
		{map[string]string{}, "bad-args"},
		{map[string]string{"in": filepath.Join(f.home, "Documents", "notes.txt")}, "not-a-folder"},
		{map[string]string{"in": "relative"}, "bad-path"},
	} {
		if r := f.command(t, f.peer, "walk", c.arg); r.Error != c.code {
			t.Errorf("walk %v: %+v, want %s", c.arg, r, c.code)
		}
	}
}

// A tree with more entries than a walk takes is said to be cut; one of
// exactly as many is whole.
func TestFilesWalkStopsAtItsLimit(t *testing.T) {
	f := newWriteFixture(t)
	saved := filesWalkLimit
	t.Cleanup(func() { filesWalkLimit = saved })
	three := filepath.Join(f.home, "Three")
	for _, n := range []string{"a", "b", "c"} {
		writeFile(t, filepath.Join(three, n), []byte(n))
	}
	filesWalkLimit = 3
	if names, _, p := f.walk(t, three); len(names) != 3 || p.Why != "" {
		t.Fatalf("exactly the limit: %v %+v", names, p)
	}
	filesWalkLimit = 2
	if names, _, p := f.walk(t, three); len(names) != 2 || p.Why != "limit" {
		t.Fatalf("over the limit: %v %+v", names, p)
	}
	writeFile(t, filepath.Join(three, "sub", "x"), []byte("x"))
	writeFile(t, filepath.Join(three, "sub", "y"), []byte("y"))
	filesWalkLimit = 5
	if names, _, p := f.walk(t, three); len(names) != 5 || p.Why != "limit" {
		t.Fatalf("cut in a folder below: %v %+v", names, p)
	}
	filesWalkLimit = 6
	if names, _, p := f.walk(t, three); len(names) != 6 || p.Why != "" {
		t.Fatalf("the whole of it: %v %+v", names, p)
	}
}

// fakeJob is a search or walk under way that never moves, for the rules
// about which ends which.
func fakeJob(f *filesFixture, peer key.NodePublic, every bool) *filesJob {
	now := time.Now()
	j := &filesJob{tok: filesToken(), peer: peer, signer: f.priv.Public().(ed25519.PublicKey), every: every,
		limit: 10, page: 10, cancel: func() {}, start: now, seen: now, wake: make(chan struct{})}
	filesJobs.Lock()
	filesJobs.m[j.tok] = j
	filesJobs.Unlock()
	return j
}

func (j *filesJob) over() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done
}

// Typing a question never ends a copy under way, nor a copy a search; two
// walks a browser at once.
func TestFilesSearchAndWalkLeaveEachOtherBe(t *testing.T) {
	f := newWriteFixture(t)
	walking := fakeJob(f, f.peer, true)
	searching := fakeJob(f, f.peer, false)
	if r := f.command(t, f.peer, "search", map[string]string{"q": "report", "in": f.home}); r.Code != 0 {
		t.Fatalf("search: %+v", r)
	}
	if !searching.over() {
		t.Fatal("a new question did not end the search before it")
	}
	if walking.over() {
		t.Fatal("a question ended a walk")
	}
	searching = fakeJob(f, f.peer, false)
	if r := f.command(t, f.peer, "walk", map[string]string{"in": f.home}); r.Code != 0 {
		t.Fatalf("walk: %+v", r)
	}
	if searching.over() || walking.over() {
		t.Fatal("a walk ended a search or another walk")
	}
	fakeJob(f, f.peer, true)
	if r := f.command(t, f.peer, "walk", map[string]string{"in": f.home}); r.Error != "busy" {
		t.Fatalf("a third walk at once: %+v", r)
	}
	other := key.NewNode().Public()
	allowClient(other.String())
	if r := f.command(t, other, "walk", map[string]string{"in": f.home}); r.Code != 0 {
		t.Fatalf("another browser's walk: %+v", r)
	}
	if r := f.command(t, f.peer, "stop", map[string]string{"t": walking.tok}); r.Code != 0 || !walking.over() {
		t.Fatalf("stop ends a walk: %+v", r)
	}
}

// A page is cut to fit one answer however long its paths are, and every hit
// still comes, page after page.
func TestFilesPageFitsInOneAnswer(t *testing.T) {
	f := newWriteFixture(t)
	now := time.Now()
	j := &filesJob{tok: filesToken(), peer: f.peer, signer: f.priv.Public().(ed25519.PublicKey), every: true,
		limit: filesWalkHits, page: filesWalkPage, cancel: func() {}, start: now, seen: now, wake: make(chan struct{}), done: true}
	long := "/" + strings.Repeat("<&>", 1300)
	for i := 0; i < 400; i++ {
		j.hits = append(j.hits, filesHit{P: long + strconv.Itoa(i), S: 1 << 40, M: now.Unix()})
	}
	filesJobs.Lock()
	filesJobs.m[j.tok] = j
	filesJobs.Unlock()
	from, pages, total := 0, 0, 0
	for {
		rec := f.get(t, "/v1/files/search?s="+j.tok+fmt.Sprintf("&from=%d", from), &f.peer)
		if rec.Code != 200 {
			t.Fatalf("a page: %d", rec.Code)
		}
		if rec.Body.Len() > filesPageBytes {
			t.Fatalf("a page of %d bytes", rec.Body.Len())
		}
		var p filesPage
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		total += len(p.Hits)
		pages++
		from = p.Next
		if p.Done {
			break
		}
		if len(p.Hits) == 0 || pages > 400 {
			t.Fatalf("page %d: %d hits before the end", pages, len(p.Hits))
		}
	}
	if total != 400 || pages < 9 {
		t.Fatalf("%d hits in %d pages", total, pages)
	}
	for _, h := range []filesHit{{P: long}, {P: "/a\"b\\c\td e ", D: true, L: true, S: 1 << 62, M: -1 << 62}, {P: "/plain"}} {
		b, _ := json.Marshal(h)
		if filesHitBytes(h) < len(b)+1 {
			t.Errorf("%q: counted %d, takes %d", h.P, filesHitBytes(h), len(b)+1)
		}
	}
}

// The tailnet road carries a piece of a file a megabyte at a time once the
// session has proven its key; before that, no more than a command needs.
func TestFilesPutOnTheTailnetRoad(t *testing.T) {
	url, static, pub, _ := tnBench(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MON_CONSOLE", "1")
	t.Setenv("MON_UPDATE", "0")
	t.Setenv(musicEnvVar, "off")
	signPub, signPriv, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(signPub)); err != nil {
		t.Fatal(err)
	}
	endAllPuts()
	t.Cleanup(endAllPuts)
	c, st := tnOpenAs(t, url, static, pub)
	if st != 200 {
		t.Fatalf("open: %d", st)
	}
	c.seq++
	if st, _ := tnPost(t, url+"/tn/rpc?s="+c.sid, c.seal(c.seq, "POST", "/v1/files/put?s=x&o=0", make([]byte, 300<<10))); st != http.StatusBadRequest {
		t.Fatalf("a big first request on a session not proven: %d", st)
	}
	if inner, _ := c.call("GET", "/v1/hello", nil); inner != 200 {
		t.Fatalf("hello: %d", inner)
	}
	n := 0
	cmd := func(op string, arg any) consoleResult {
		t.Helper()
		a, _ := json.Marshal(arg)
		n++
		cc := signedCmd(t, signPriv, agentID(), consoleCmd{ID: fmt.Sprintf("tn%x-%d", time.Now().UnixNano(), n), Kind: "files", Target: op, Cmd: string(a)})
		fr, _ := transport.New(transport.TypeCommand, "", cc.ID, transport.Command{Kind: cc.Kind, Cmd: cc.Cmd, Target: cc.Target, Sig: cc.Sig, At: cc.IssuedAt})
		body, _ := transport.Encode(fr)
		inner, b := c.call("POST", "/v1/command", body)
		if inner != 200 {
			t.Fatalf("%s: inner status %d", op, inner)
		}
		out, err := transport.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		var res consoleResult
		json.Unmarshal(out.Body, &res)
		return res
	}
	r := cmd("put", map[string]any{"dir": home, "name": "big.bin", "size": 1 << 20})
	if r.Code != 0 {
		t.Fatalf("put: %+v", r)
	}
	var b filesPutBody
	json.Unmarshal([]byte(r.Out), &b)
	piece := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	inner, got := c.call("POST", "/v1/files/put?s="+b.T+"&o=0", piece)
	var h struct {
		Have int64 `json:"have"`
	}
	if json.Unmarshal(got, &h); inner != 200 || h.Have != 1<<20 {
		t.Fatalf("a megabyte in one piece: %d %s", inner, got)
	}
	if r := cmd("done", map[string]any{"t": b.T}); r.Code != 0 {
		t.Fatalf("done: %+v", r)
	}
	if disk, err := os.ReadFile(filepath.Join(home, "big.bin")); err != nil || !bytes.Equal(disk, piece) {
		t.Fatalf("the file: %d bytes, %v", len(disk), err)
	}
}

// A replace may name what the page saw of the file it replaces (was: its
// size and modified time as the listing gave them), read strictly: it is
// refused at put when the file is not that any more, and at done when it
// changed meanwhile, which leaves the upload to be done another way; a file
// gone since is no change to lose, and keep never looks. done's m is what to
// name the next time.
func TestFilesPutWasGuardsASaveBack(t *testing.T) {
	f := newWriteFixture(t)
	dir := filepath.Join(f.home, "Documents")
	target := filepath.Join(dir, "notes.txt")
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	s, m := fi.Size(), fi.ModTime().Unix()
	arg := func(name string, size int, mode string, was any) map[string]any {
		return map[string]any{"dir": dir, "name": name, "size": size, "mode": mode, "was": was}
	}
	for _, bad := range []any{
		-1, "x", []any{s, m}, map[string]any{},
		map[string]any{"s": s},
		map[string]any{"m": m},
		map[string]any{"s": s, "m": m, "x": 1},
		map[string]any{"S": s, "M": m},
		map[string]any{"s": -1, "m": m},
		map[string]any{"s": s, "m": -m},
		map[string]any{"s": s, "m": 1.5},
		map[string]any{"s": strconv.FormatInt(s, 10), "m": m},
		map[string]any{"s": s, "m": nil},
		json.RawMessage(`{"s":1e3,"m":5}`),
		json.RawMessage(`{"s":30.0,"m":5}`),
		json.RawMessage(`{"s":99999999999999999999,"m":5}`),
	} {
		if r := f.command(t, f.peer, "put", arg("notes.txt", 5, "replace", bad)); r.Error != "bad-args" {
			t.Fatalf("was %s: %+v", fmt.Sprint(bad), r)
		}
	}
	for _, was := range []map[string]any{{"s": s + 1, "m": m}, {"s": s, "m": m - 1}} {
		if r := f.command(t, f.peer, "put", arg("notes.txt", 5, "replace", was)); r.Error != "changed-since" {
			t.Fatalf("was %v of a file that is not that now: %+v", was, r)
		}
	}
	if ps := partsIn(dir); len(ps) != 0 {
		t.Fatalf("parts left by refused puts: %v", ps)
	}
	// No was (null is none), or keep: nothing looked at.
	for _, a := range []map[string]any{arg("notes.txt", 5, "replace", nil), arg("notes.txt", 5, "keep", map[string]any{"s": s + 1, "m": m})} {
		b := f.put(t, a)
		f.command(t, f.peer, "cancel", map[string]any{"t": b.T})
	}

	// Changed between the put and the done.
	b := f.put(t, arg("notes.txt", 5, "replace", map[string]any{"s": s, "m": m}))
	if _, code := pieceHave(f.piece(&f.peer, b.T, 0, []byte("saved"))); code != "" {
		t.Fatalf("a piece: %q", code)
	}
	writeFile(t, target, []byte("changed meanwhile"))
	later := time.Unix(m+60, 0)
	os.Chtimes(target, later, later)
	if _, code := f.done(t, b.T, nil); code != "changed-since" {
		t.Fatalf("done over a file changed meanwhile: %q", code)
	}
	if got, _ := os.ReadFile(target); string(got) != "changed meanwhile" {
		t.Fatalf("the change was lost: %q", got)
	}
	if ps := partsIn(dir); len(ps) != 1 {
		t.Fatalf("the upload's part: %v", ps)
	}
	d, code := f.done(t, b.T, map[string]any{"mode": "keep"})
	if code != "" || d.N != "notes (2).txt" {
		t.Fatalf("done again, keeping both: %+v %q", d, code)
	}
	if got, _ := os.ReadFile(d.Path); string(got) != "saved" {
		t.Fatalf("the copy kept: %q", got)
	}

	// Saved again over what done answered: its own save is no change.
	again := f.put(t, arg("notes (2).txt", 6, "replace", map[string]any{"s": d.S, "m": d.M}))
	pieceHave(f.piece(&f.peer, again.T, 0, []byte("saved2")))
	if d2, code := f.done(t, again.T, nil); code != "" || d2.Path != d.Path || d2.S != 6 {
		t.Fatalf("saved again: %+v %q", d2, code)
	} else if got, _ := os.ReadFile(d.Path); string(got) != "saved2" {
		t.Fatalf("saved again: %q", got)
	}

	// Gone since the page saw it: the file is put back under its name.
	report := filepath.Join(dir, "report-2024.pdf")
	rfi, _ := os.Stat(report)
	g := f.put(t, arg("report-2024.pdf", 3, "replace", map[string]any{"s": rfi.Size(), "m": rfi.ModTime().Unix()}))
	pieceHave(f.piece(&f.peer, g.T, 0, []byte("new")))
	if err := os.Remove(report); err != nil {
		t.Fatal(err)
	}
	if d, code := f.done(t, g.T, nil); code != "" || d.Path != report {
		t.Fatalf("a file gone since: %+v %q", d, code)
	} else if got, _ := os.ReadFile(report); string(got) != "new" {
		t.Fatalf("a file gone since: %q", got)
	}
}

// done answers the file's modified time as the listing gives it: the one the
// page named, or (none named, or milliseconds) the time it was written.
func TestFilesDoneAnswersItsTime(t *testing.T) {
	f := newWriteFixture(t)
	listed := func(name string) int64 {
		t.Helper()
		r := f.command(t, f.peer, "list", map[string]string{"path": f.home})
		var l filesListBody
		json.Unmarshal([]byte(r.Out), &l)
		for _, e := range l.Files {
			if e.N == name {
				return e.M
			}
		}
		t.Fatalf("%s is not listed: %s", name, r.Out)
		return 0
	}
	const m = 1650000000
	for _, c := range []struct {
		name string
		m    any
	}{{"timed.txt", m}, {"untimed.txt", nil}, {"millis.txt", int64(m) * 1000}} {
		before := time.Now().Unix()
		b := f.put(t, map[string]any{"dir": f.home, "name": c.name, "size": 2})
		pieceHave(f.piece(&f.peer, b.T, 0, []byte("ok")))
		more := map[string]any{}
		if c.m != nil {
			more["m"] = c.m
		}
		d, code := f.done(t, b.T, more)
		if code != "" || d.M != listed(c.name) {
			t.Fatalf("%s: %+v %q, listed %d", c.name, d, code, listed(c.name))
		}
		if c.name == "timed.txt" {
			if d.M != m {
				t.Fatalf("%s: %d", c.name, d.M)
			}
		} else if d.M < before-1 || d.M > time.Now().Unix()+1 {
			// A second either way: a disk's clock is the kernel's coarse one.
			t.Fatalf("%s: %d, not between %d and now", c.name, d.M, before)
		}
	}
}

// cancel with a folder and a key and no token lets go of a part no upload
// holds any more (the page's discard once the upload is gone: the helper
// restarted, or the part sat idle past its time). Not while an upload holds
// it, and nothing that is not a file.
func TestFilesCancelByKey(t *testing.T) {
	f := newWriteFixture(t)
	const k = "discard-key-01"
	b := f.put(t, map[string]any{"dir": f.home, "name": "discarded.bin", "size": 8, "k": k})
	pieceHave(f.piece(&f.peer, b.T, 0, []byte("ABCD")))
	byKey := map[string]any{"dir": f.home, "k": k}
	if r := f.command(t, f.peer, "cancel", byKey); r.Error != "busy" {
		t.Fatalf("by its key while its upload is open: %+v", r)
	}
	if ps := partsIn(f.home); len(ps) != 1 {
		t.Fatalf("the part: %v", ps)
	}
	endAllPuts()
	if ps := partsIn(f.home); len(ps) != 1 {
		t.Fatalf("the part kept for its key: %v", ps)
	}
	for i := 0; i < 2; i++ {
		// The second time there is nothing to let go of: done already.
		if r := f.command(t, f.peer, "cancel", byKey); r.Code != 0 {
			t.Fatalf("by its key, %d: %+v", i+1, r)
		}
		if ps := partsIn(f.home); len(ps) != 0 {
			t.Fatalf("parts left: %v", ps)
		}
	}
	odd := filepath.Join(f.home, filesPartPrefix+"discard-key-02"+filesPartSuffix)
	if err := os.Mkdir(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := f.command(t, f.peer, "cancel", map[string]any{"dir": f.home, "k": "discard-key-02"}); r.Error != "unavailable" {
		t.Fatalf("a folder under a part's name: %+v", r)
	}
	if fi, err := os.Stat(odd); err != nil || !fi.IsDir() {
		t.Fatalf("the folder: %v %v", fi, err)
	}
	for _, c := range []struct {
		arg  map[string]any
		want string
	}{
		{map[string]any{}, "bad-args"},
		{map[string]any{"dir": f.home}, "bad-args"},
		{map[string]any{"dir": f.home, "k": "short"}, "bad-args"},
		{map[string]any{"dir": f.home, "k": "../escape-key"}, "bad-args"},
		{map[string]any{"dir": "relative/dir", "k": k}, "bad-path"},
	} {
		if r := f.command(t, f.peer, "cancel", c.arg); r.Error != c.want {
			t.Fatalf("cancel %v: %+v, want %q", c.arg, r, c.want)
		}
	}
}
