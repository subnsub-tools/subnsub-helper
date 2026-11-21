package main

// host_test.go — the files a primary hosts: the store, the link on the
// tailnet listener, the members' keys and their door, a member's host-key,
// out's side of put.sock, and the real-DERP end to end.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	hostIDA = "11111111-aaaa-4bbb-8ccc-000000000001"
	hostIDB = "11111111-aaaa-4bbb-8ccc-000000000002"
)

func hostReset(t *testing.T) {
	t.Helper()
	wasMax := hostMaxDefault
	clear := func() {
		hostState.Lock()
		hostState.pending, hostState.pendingN, hostState.swept = 0, 0, false
		hostState.arriving = nil
		hostState.Unlock()
		tailnetRoad.Store(nil)
		tailnetSure.Store(false)
		hostShared.Lock()
		if t := hostShared.cur; t != nil {
			t.refs = 0
			t.retireLocked()
		}
		hostShared.Unlock()
	}
	clear()
	t.Cleanup(func() { hostMaxDefault = wasMax; clear() })
}

func hostOnTailnet(t *testing.T) {
	t.Helper()
	tailnetRoad.Store(&transport.TailnetRoad{Host: "primary.tail0.ts.net", IP: "100.64.0.9", Port: 8126})
	tailnetSure.Store(true)
}

func hostParts(t *testing.T) []string {
	t.Helper()
	var out []string
	entries, _ := os.ReadDir(hostDir())
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".part-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// The store: only a primary keeps anything; an item is kept once, whoever
// puts it again; what does not match its announced size is not kept; room is
// refused rather than made; a drop removes the bytes.
func TestHostStore(t *testing.T) {
	f := newPrimaryFixture(t)
	hostReset(t)
	if _, code := hostAccept(hostIDA, "a.png", 5, "me", strings.NewReader("hello"), nil); code != "not-primary" {
		t.Fatalf("before primary-on: %q", code)
	}
	f.primaryOn(t)
	ticks := 0
	it, code := hostAccept(hostIDA, "dir/My pic (1).png", 5, "macA", strings.NewReader("hello"), func() { ticks++ })
	if code != "" || it.Name != "My pic (1).png" || it.Size != 5 || it.From != "macA" || !hostTokenRE.MatchString(it.Token) {
		t.Fatalf("accept: %+v %q", it, code)
	}
	if ticks == 0 {
		t.Fatal("the read's deadline was never pushed on")
	}
	fi, err := os.Stat(filepath.Join(hostDir(), it.Token))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 5 {
		t.Fatalf("the kept file: %v %v", fi, err)
	}
	if di, err := os.Stat(hostDir()); err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("the folder: %v %v", di, err)
	}
	// Again, from another Mac: the same item, and the new bytes are not read.
	body := strings.NewReader("other")
	again, code := hostAccept(hostIDA, "x.png", 5, "macB", body, nil)
	if code != "" || again.Token != it.Token || body.Len() != 5 {
		t.Fatalf("second accept: %+v %q (unread %d)", again, code, body.Len())
	}
	if got, ok := hostFind(hostIDA); !ok || got.Token != it.Token {
		t.Fatalf("find: %+v %v", got, ok)
	}
	// Fewer bytes than announced, then more.
	if _, code := hostAccept(hostIDB, "b.bin", 10, "macA", strings.NewReader("short"), nil); code != "bad-size" {
		t.Fatalf("short body: %q", code)
	}
	if _, code := hostAccept(hostIDB, "b.bin", 3, "macA", strings.NewReader("longer"), nil); code != "bad-size" {
		t.Fatalf("long body: %q", code)
	}
	if _, ok := hostFind(hostIDB); ok {
		t.Fatal("a refused item is hosted")
	}
	if left := hostParts(t); len(left) != 0 {
		t.Fatalf("partial files left: %v", left)
	}
	// Room: 5 bytes are here, 8 is the most.
	hostMaxDefault = 8
	if _, code := hostAccept(hostIDB, "b.bin", 4, "macA", strings.NewReader("four"), nil); code != "full" {
		t.Fatalf("past the room: %q", code)
	}
	if _, ok := hostFind(hostIDA); !ok {
		t.Fatal("making room took an item down")
	}
	if b, code := hostAccept(hostIDB, "b.bin", 3, "macA", strings.NewReader("abc"), nil); code != "" || b.Size != 3 {
		t.Fatalf("within the room: %+v %q", b, code)
	}
	// A size no disk holds is refused before it is added to anything.
	if _, code := hostAccept("11111111-aaaa-4bbb-8ccc-00000000000f", "huge", math.MaxInt64, "macA", strings.NewReader("x"), nil); code != "full" {
		t.Fatalf("a size past every limit: %q", code)
	}
	hostState.Lock()
	if hostState.pending != 0 || hostState.pendingN != 0 || len(hostState.arriving) != 0 {
		t.Fatalf("left counted: %d bytes, %d puts, %d arriving", hostState.pending, hostState.pendingN, len(hostState.arriving))
	}
	hostState.Unlock()
	for _, bad := range []string{"", "short", "UPPER-CASE-0000", "../../../etc/passwd"} {
		if _, code := hostAccept(bad, "x", 1, "macA", strings.NewReader("x"), nil); code != "bad-args" {
			t.Fatalf("id %q: %q", bad, code)
		}
	}
	// A drop that cannot be written down says so, and the item still opens.
	blocked := filepath.Join(hostDir(), hostIndexName+".new")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if hostDrop(hostIDA) {
		t.Fatal("a drop that was not saved was acknowledged")
	}
	if _, ok := hostFind(hostIDA); !ok {
		t.Fatal("a failed drop took the item down halfway")
	}
	os.Remove(blocked)
	if !hostDrop(hostIDA) {
		t.Fatal("drop")
	}
	if _, ok := hostFind(hostIDA); ok {
		t.Fatal("still hosted after the drop")
	}
	if _, err := os.Stat(filepath.Join(hostDir(), it.Token)); !os.IsNotExist(err) {
		t.Fatalf("the bytes outlived the drop: %v", err)
	}
	if !hostDrop(hostIDA) {
		t.Fatal("dropping what is not here")
	}
	// Dropped while its bytes were still arriving: it does not appear after.
	feed, gate := io.Pipe()
	landed := make(chan string, 1)
	go func() {
		_, code := hostAccept(hostIDA, "late.png", 4, "macA", feed, nil)
		landed <- code
	}()
	gate.Write([]byte("la"))
	if !hostDrop(hostIDA) {
		t.Fatal("drop during a put")
	}
	gate.Write([]byte("te"))
	gate.Close()
	if code := <-landed; code != "dropped" {
		t.Fatalf("a put that outlived its drop: %q", code)
	}
	if _, ok := hostFind(hostIDA); ok || len(hostParts(t)) != 0 {
		t.Fatalf("a dropped put left something: %v", hostParts(t))
	}
	// An item whose bytes went missing is not hosted, and can be put again.
	b, _ := hostFind(hostIDB)
	os.Remove(filepath.Join(hostDir(), b.Token))
	if _, ok := hostFind(hostIDB); ok {
		t.Fatal("an item without bytes reads as hosted")
	}
	if nb, code := hostAccept(hostIDB, "b.bin", 3, "macA", strings.NewReader("xyz"), nil); code != "" || nb.Token == b.Token {
		t.Fatalf("put again: %+v %q", nb, code)
	}
	// The role ends, and what was hosted with it.
	if res := f.command(t, "primary-off", "", ""); res.Code != 0 {
		t.Fatalf("primary-off: %+v", res)
	}
	if _, err := os.Stat(hostDir()); !os.IsNotExist(err) {
		t.Fatalf("hosted files outlived the role: %v", err)
	}
}

func TestHostNames(t *testing.T) {
	for in, want := range map[string]string{
		"a.png":               "a.png",
		"/tmp/x/photo.jpg":    "photo.jpg",
		"..":                  "file",
		".hidden":             "file",
		"":                    "file",
		"line\nbreak\x00.txt": "linebreak.txt",
		"  spaced.txt  ":      "spaced.txt",
		"C:\\Users\\a\\b.doc": "b.doc",
	} {
		if got := hostName(in); got != want {
			t.Errorf("hostName(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("\u56fe", 100) + ".png"
	if got := hostName(long); len(got) > hostNameMax || !strings.HasPrefix(got, "\u56fe") {
		t.Errorf("a long name: %d bytes", len(got))
	}
	if got := hostEscape("My pic (1) \u56fe.png"); got != "My%20pic%20%281%29%20%E5%9B%BE.png" {
		t.Errorf("hostEscape: %q", got)
	}
}

// The link: on the tailnet listener, by token alone, shown in place for what
// a browser can show safely and handed over as a download otherwise.
func TestHostedServe(t *testing.T) {
	f := newPrimaryFixture(t)
	hostReset(t)
	f.primaryOn(t)
	png, _ := hostAccept(hostIDA, "shot one.png", 10, "macA", strings.NewReader("0123456789"), nil)
	page, _ := hostAccept(hostIDB, "page.html", 6, "macA", strings.NewReader("<html>"), nil)
	svg, _ := hostAccept("11111111-aaaa-4bbb-8ccc-000000000003", "draw.svg", 5, "macA", strings.NewReader("<svg>"), nil)
	if _, ok := hostURL(png); ok {
		t.Fatal("a link without a tailnet road")
	}
	hostOnTailnet(t)
	link, ok := hostURL(png)
	if !ok || link != "http://primary.tail0.ts.net:8126/s/"+png.Token+"/shot%20one.png" {
		t.Fatalf("link: %q", link)
	}
	tailnetRoad.Store(&transport.TailnetRoad{IP: "100.64.0.9", Port: 40123})
	if link, _ := hostURL(png); !strings.HasPrefix(link, "http://100.64.0.9:40123/s/") {
		t.Fatalf("link without a name: %q", link)
	}
	// An address that only looks like a tailnet's: no link, and none answered.
	tailnetSure.Store(false)
	if _, ok := hostURL(png); ok {
		t.Fatal("a link on an address not known to be Tailscale's")
	}
	unsure := httptest.NewRecorder()
	tailnetServe.ServeHTTP(unsure, httptest.NewRequest(http.MethodGet, "/s/"+png.Token+"/x", nil))
	if unsure.Code != 404 {
		t.Fatalf("answered on an unsure address: %d", unsure.Code)
	}
	tailnetSure.Store(true)
	get := func(method, path, rng string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if rng != "" {
			req.Header.Set("Range", rng)
		}
		rec := httptest.NewRecorder()
		tailnetServe.ServeHTTP(rec, req)
		return rec
	}
	rec := get(http.MethodGet, "/s/"+png.Token+"/shot%20one.png", "")
	if rec.Code != 200 || rec.Body.String() != "0123456789" {
		t.Fatalf("get: %d %q", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if h.Get("Content-Type") != "image/png" || !strings.HasPrefix(h.Get("Content-Disposition"), "inline; filename*=UTF-8''shot%20one.png") ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: %v", h)
	}
	// Whatever name the link carries, the token finds the file.
	if rec := get(http.MethodGet, "/s/"+png.Token+"/renamed", ""); rec.Code != 200 {
		t.Fatalf("another name: %d", rec.Code)
	}
	if rec := get(http.MethodGet, "/s/"+png.Token+"/shot%20one.png", "bytes=2-4"); rec.Code != 206 || rec.Body.String() != "234" {
		t.Fatalf("range: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get(http.MethodHead, "/s/"+png.Token+"/x", ""); rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "10" {
		t.Fatalf("head: %d %d %v", rec.Code, rec.Body.Len(), rec.Header())
	}
	for _, path := range []string{"/s/", "/s/" + strings.Repeat("0", 32) + "/x", "/s/../hosted/index.json", "/s/" + png.Token[:31] + "/x", "/s/index.json"} {
		if rec := get(http.MethodGet, path, ""); rec.Code != 404 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
	if rec := get(http.MethodPost, "/s/"+png.Token+"/x", ""); rec.Code != 404 {
		t.Fatalf("post: %d", rec.Code)
	}
	rec = get(http.MethodGet, "/s/"+page.Token+"/page.html", "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("a page is handed over, not shown: %d %v", rec.Code, rec.Header())
	}
	rec = get(http.MethodGet, "/s/"+svg.Token+"/draw.svg", "")
	if rec.Header().Get("Content-Type") != "image/svg+xml" || !strings.HasPrefix(rec.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("svg: %v", rec.Header())
	}
	// The road's own doors are as they were.
	if rec := get(http.MethodGet, "/tn/open", ""); rec.Code != 404 {
		t.Fatalf("GET /tn/open: %d", rec.Code)
	}
	t.Setenv("MON_HOST", "off")
	if rec := get(http.MethodGet, "/s/"+png.Token+"/x", ""); rec.Code != 404 {
		t.Fatalf("with hosting off: %d", rec.Code)
	}
	t.Setenv("MON_HOST", "")
	hostDrop(hostIDA)
	if rec := get(http.MethodGet, "/s/"+png.Token+"/x", ""); rec.Code != 404 {
		t.Fatalf("after the drop: %d", rec.Code)
	}
}

// A member's host-key: only verified, the primary's address is kept and the
// same key is given every time; a delegated signature may run it and may
// not run anything outside the coordination set.
func TestHostKey(t *testing.T) {
	f := newPrimaryFixture(t)
	hostReset(t)
	if !delegatedKind("host-key") || mailboxRefusal(consoleCmd{Kind: "host-key"}) != "tunnel-only" {
		t.Fatal("host-key is a delegated kind and travels the tunnel alone")
	}
	if hostAvailable() {
		t.Fatal("links offered with no primary known")
	}
	addr := testPutAddr(t)
	cmd, _ := json.Marshal(map[string]string{"a": addr})
	res := f.command(t, "host-key", "", string(cmd))
	if res.Code != 0 {
		t.Fatalf("host-key: %+v", res)
	}
	var out struct {
		Key string `json:"key"`
	}
	if json.Unmarshal([]byte(res.Out), &out) != nil {
		t.Fatalf("out: %q", res.Out)
	}
	priv, err := hostClientKey()
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := transport.ParseNodeKey(out.Key); !ok || k != priv.Public() {
		t.Fatalf("the key given is not the key dialed from: %q", out.Key)
	}
	if hostAtRead() != addr || !hostAvailable() {
		t.Fatalf("host-at: %q", hostAtRead())
	}
	if fi, err := os.Stat(primaryPath(hostAtFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("host-at's mode: %v %v", fi, err)
	}
	again := f.command(t, "host-key", "", string(cmd))
	if again.Out != res.Out {
		t.Fatalf("a second answer differs: %q", again.Out)
	}
	// The key is not one of the keys this Mac dials other Macs from.
	if other, _ := putKeyFor("macOther01"); other.Public() == priv.Public() {
		t.Fatal("the host key is a put key")
	}
	for _, bad := range []string{"", "{}", `{"a":"not an address"}`, `{"a":""}`} {
		if r := f.command(t, "host-key", "", bad); r.Error != "bad-args" {
			t.Fatalf("%q: %+v", bad, r)
		}
	}
	if hostAtRead() != addr {
		t.Fatal("a refused host-key changed the address")
	}
	t.Setenv("MON_HOST", "off")
	if r := f.command(t, "host-key", "", string(cmd)); r.Error != "off" {
		t.Fatalf("with hosting off: %+v", r)
	}
	t.Setenv("MON_HOST", "")
	// Another primary's delegation, or none, forgets where the old one was.
	pubA := f.primaryOn(t)
	node := key.NewNode().Public()
	dg, _ := json.Marshal(map[string]string{"key": pubA, "node": node.String()})
	if r := f.command(t, "primary-off", "", ""); r.Code != 0 {
		t.Fatalf("primary-off: %+v", r)
	}
	if r := f.command(t, "delegate", "", string(dg)); r.Code != 0 {
		t.Fatalf("delegate: %+v", r)
	}
	if hostAtRead() != "" {
		t.Fatal("a new primary kept the old one's address")
	}
	f.command(t, "host-key", "", string(cmd))
	if r := f.command(t, "delegate", "", string(dg)); r.Code != 0 || hostAtRead() != addr {
		t.Fatalf("the same primary delegating again: %+v, host-at %q", r, hostAtRead())
	}
	if r := f.command(t, "undelegate", "", ""); r.Code != 0 || hostAtRead() != "" {
		t.Fatalf("undelegate: %+v, host-at %q", r, hostAtRead())
	}
	was := putSupported
	putSupported = false
	if r := f.command(t, "host-key", "", string(cmd)); r.Error != "unsupported" {
		t.Fatalf("where out does not run: %+v", r)
	}
	putSupported = was
}

// hostDoor asks the primary's tunnel door as the peer with this key.
func hostDoor(f *primaryFixture, peer key.NodePublic, method, target string, body []byte) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	req = req.WithContext(transport.WithPeer(req.Context(), peer))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func hostDoorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	fr, err := transport.Decode(rec.Body.Bytes())
	if err != nil || fr.Type != transport.TypeError {
		return ""
	}
	var e transport.Error
	json.Unmarshal(fr.Body, &e)
	return e.Code
}

// The round asks each member that can host for its key and tells it where
// the primary is; the key then opens the host door and nothing else, for as
// long as the member is on the roster as it was.
func TestHostRoundAndDoor(t *testing.T) {
	f := newPrimaryFixture(t)
	hostReset(t)
	f.primaryOn(t)
	self := agentID()
	selfAddr, addrA, addrB := testPutAddr(t), testPutAddr(t), testPutAddr(t)
	setDirectAddress(selfAddr)
	t.Cleanup(func() { setDirectAddress("") })
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember(self, "This Mac", selfAddr),
		rosterMember("memberAA", "Member A", addrA),
		rosterMember("memberBB", "Member B", addrB),
	))
	keyA := key.NewNode().Public()
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut, transport.CapHost}, hostKey: keyA.String()}
	// B is an older helper: it does not say host, and is not asked.
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}}
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa, "memberBB": fb})
	primaryRound(context.Background())
	var asked string
	for _, c := range fa.recorded() {
		if c.kind == "host-key" {
			asked = c.cmd
		}
	}
	var a struct {
		Addr string `json:"a"`
	}
	if json.Unmarshal([]byte(asked), &a) != nil || a.Addr != selfAddr {
		t.Fatalf("host-key to A: %q", asked)
	}
	for _, c := range fb.recorded() {
		if c.kind == "host-key" {
			t.Fatal("a member that does not say host was asked host-key")
		}
	}
	if agent, ok := hostMemberForNode(keyA); !ok || agent != "memberAA" {
		t.Fatalf("A's key: %q %v", agent, ok)
	}
	if nodes := activeHostNodes(); len(nodes) != 1 || nodes[0] != keyA {
		t.Fatalf("admitted: %v", nodes)
	}
	if fi, err := os.Stat(primaryPath(hostKeysFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("primary-hosts: %v %v", fi, err)
	}
	// A round that began under another role's key leaves nothing behind.
	_, other, _ := ed25519.GenerateKey(nil)
	if err := os.Remove(primaryPath(hostKeysFile)); err != nil {
		t.Fatal(err)
	}
	primaryHostRound(context.Background(), other, readPrimaryRoster(), []*sweepLink{{agent: "memberAA", addr: addrA, kid: "a:memberAA", conn: fa, host: true}})
	if list := hostMembersLoad(); len(list) != 0 {
		t.Fatalf("a round under another key kept %+v", list)
	}
	primaryRound(context.Background())
	if _, ok := hostMemberForNode(keyA); !ok {
		t.Fatal("the next round did not bring A's key back")
	}
	// A round A does not answer keeps its key.
	fa.failOn = map[string]bool{"host-key": true}
	primaryRound(context.Background())
	if _, ok := hostMemberForNode(keyA); !ok {
		t.Fatal("a missed round took A's key away")
	}
	fa.failOn = nil

	put := hostPutPath + "?id=" + hostIDA + "&name=clip%20one.mov&size=6"
	// No tailnet road: no link could be given, so nothing is taken.
	if rec := hostDoor(f, keyA, http.MethodPost, put, []byte("abcdef")); rec.Code != http.StatusConflict || hostDoorCode(t, rec) != "no-tailnet" {
		t.Fatalf("put without a road: %d %s", rec.Code, rec.Body.String())
	}
	hostOnTailnet(t)
	if rec := hostDoor(f, keyA, http.MethodGet, hostHavePath+"?id="+hostIDA, nil); rec.Code != http.StatusNotFound || hostDoorCode(t, rec) != "not-hosted" {
		t.Fatalf("have before put: %d %s", rec.Code, rec.Body.String())
	}
	rec := hostDoor(f, keyA, http.MethodPost, put, []byte("abcdef"))
	var got struct {
		URL string `json:"url"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !strings.HasSuffix(got.URL, "/clip%20one.mov") {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	it, ok := hostFind(hostIDA)
	if !ok || it.From != "memberAA" || it.Name != "clip one.mov" {
		t.Fatalf("kept: %+v %v", it, ok)
	}
	rec = hostDoor(f, keyA, http.MethodGet, hostHavePath+"?id="+strings.ToUpper(hostIDA), nil)
	var have struct {
		URL string `json:"url"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &have) != nil || have.URL != got.URL {
		t.Fatalf("have: %d %s", rec.Code, rec.Body.String())
	}
	// What the announced size and the body disagree on is refused.
	for _, target := range []string{
		hostPutPath + "?id=" + hostIDB + "&name=x&size=9",
		hostPutPath + "?id=" + hostIDB + "&name=x&size=0",
		hostPutPath + "?id=" + hostIDB + "&name=x",
		hostPutPath + "?id=bad&name=x&size=6",
	} {
		if rec := hostDoor(f, keyA, http.MethodPost, target, []byte("abcdef")); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
		}
	}
	// The key opens this door alone.
	for _, try := range [][2]string{
		{http.MethodGet, "/v1/hello"}, {http.MethodGet, "/v1/snapshot"}, {http.MethodPost, "/v1/command"},
		{http.MethodGet, "/v1/files/list?id=" + hostIDA}, {http.MethodGet, hostPutPath + "?id=" + hostIDA},
		{http.MethodPost, "/v1/primary/join"},
	} {
		rec := hostDoor(f, keyA, try[0], try[1], []byte("{}"))
		if rec.Code == 200 {
			t.Fatalf("%s %s answered a host key: %s", try[0], try[1], rec.Body.String())
		}
	}
	// A key nobody gave is not let in.
	if rec := hostDoor(f, key.NewNode().Public(), http.MethodGet, hostHavePath+"?id="+hostIDA, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a stranger's key: %d", rec.Code)
	}
	if rec := hostDoor(f, keyA, http.MethodPost, hostDropPath+"?id="+hostIDA, nil); rec.Code != 200 {
		t.Fatalf("drop: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := hostFind(hostIDA); ok {
		t.Fatal("hosted after the drop")
	}
	// Off the roster: the key is refused at its next request.
	rm, _ := json.Marshal(map[string]any{"remove": []string{"memberAA"}})
	if res := f.command(t, "primary-roster", "", string(rm)); res.Code != 0 {
		t.Fatalf("roster remove: %+v", res)
	}
	if rec := hostDoor(f, keyA, http.MethodGet, hostHavePath+"?id="+hostIDA, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("after leaving the roster: %d", rec.Code)
	}
	primaryRound(context.Background())
	if list := hostMembersLoad(); len(list) != 0 {
		t.Fatalf("primary-hosts after the round: %+v", list)
	}
}

// One tunnel to the primary serves everything asked at once, is kept after
// its last use, and is not used again once a request on it went unanswered.
func TestHostSharedTunnel(t *testing.T) {
	newPrimaryFixture(t)
	hostReset(t)
	addr := testPutAddr(t)
	a, err := hostRoadFor(addr)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := hostRoadFor(addr)
	if a != b {
		t.Fatal("two uses at once got two tunnels")
	}
	a.Close()
	b.Close()
	c, _ := hostRoadFor(addr)
	if c != a {
		t.Fatal("the tunnel was not kept after its last use")
	}
	ct := c.(*hostTunnel)
	if ct.refs != 1 || ct.idle != nil {
		t.Fatalf("refs %d, idle %v", ct.refs, ct.idle)
	}
	ct.silent()
	d, _ := hostRoadFor(addr)
	if d == c {
		t.Fatal("a tunnel that went silent was used again")
	}
	c.Close()
	if !ct.shut {
		t.Fatal("the silent tunnel was not closed after its last use")
	}
	e, _ := hostRoadFor(testPutAddr(t))
	if e == d {
		t.Fatal("another primary got the old primary's tunnel")
	}
	d.Close()
	e.Close()
	if !d.(*hostTunnel).shut {
		t.Fatal("the old primary's tunnel was kept")
	}
}

// fakeHostRoad is a primary that keeps what it is put, in memory.
type fakeHostRoad struct {
	mu      sync.Mutex
	items   map[string][]byte
	names   map[string]string
	drops   []string
	down    bool
	refuse  string
	closedN int
}

func (r *fakeHostRoad) link(id string) string {
	return "http://primary.test:8126/s/" + id + "/" + r.names[id]
}

func (r *fakeHostRoad) have(ctx context.Context, id string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return "", "", io.ErrUnexpectedEOF
	}
	if _, ok := r.items[id]; !ok {
		return "", "not-hosted", nil
	}
	return r.link(id), "", nil
}

func (r *fakeHostRoad) put(ctx context.Context, id, name string, size int64, body io.Reader) (string, string, error) {
	b, err := io.ReadAll(body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || int64(len(b)) != size {
		return "", "bad-size", nil
	}
	if r.refuse != "" {
		return "", r.refuse, nil
	}
	r.items[id], r.names[id] = b, name
	return r.link(id), "", nil
}

func (r *fakeHostRoad) drop(ctx context.Context, id string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return "", io.ErrUnexpectedEOF
	}
	delete(r.items, id)
	r.drops = append(r.drops, id)
	return "", nil
}

func (r *fakeHostRoad) Close() { r.mu.Lock(); r.closedN++; r.mu.Unlock() }

// hostAsk is out on put.sock: one line asked, what the helper answers, the
// bytes when it says send, and the last answer.
func hostAsk(t *testing.T, ask map[string]any, body []byte) []map[string]any {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { servePutLocal(server); close(done) }()
	defer func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the helper kept the socket")
		}
	}()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	line, _ := json.Marshal(ask)
	if _, err := client.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(client)
	var answers []map[string]any
	for {
		raw, err := r.ReadBytes('\n')
		if err != nil {
			return answers
		}
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil {
			t.Fatalf("answer: %q", raw)
		}
		answers = append(answers, v)
		if v["send"] != true {
			return answers
		}
		if _, err := client.Write(body); err != nil {
			t.Fatal(err)
		}
	}
}

// out's side, on a member: the primary is asked first, the bytes go only
// when it has none, and each refusal reaches out as its code.
func TestHostSocketMember(t *testing.T) {
	f := newPrimaryFixture(t)
	hostReset(t)
	road := &fakeHostRoad{items: map[string][]byte{}, names: map[string]string{}}
	was := hostRoadFor
	var dialed []string
	hostRoadFor = func(addr string) (hostRoad, error) { dialed = append(dialed, addr); return road, nil }
	t.Cleanup(func() { hostRoadFor = was })
	body := bytes.Repeat([]byte("0123456789abcdef"), 40<<10) // 640 KiB
	ask := map[string]any{"op": "host", "id": strings.ToUpper(hostIDA), "name": "Screen Shot.png", "size": len(body), "have": true}
	if got := hostAsk(t, ask, body); len(got) != 1 || got[0]["error"] != "no-primary" {
		t.Fatalf("with no primary known: %v", got)
	}
	addr := testPutAddr(t)
	cmd, _ := json.Marshal(map[string]string{"a": addr})
	if res := f.command(t, "host-key", "", string(cmd)); res.Code != 0 {
		t.Fatalf("host-key: %+v", res)
	}
	got := hostAsk(t, ask, body)
	if len(got) != 2 || got[0]["send"] != true || got[1]["ok"] != true || got[1]["url"] != road.link(hostIDA) {
		t.Fatalf("host: %v", got)
	}
	if !bytes.Equal(road.items[hostIDA], body) || road.names[hostIDA] != "Screen Shot.png" {
		t.Fatalf("what the primary was put: %d bytes, %q", len(road.items[hostIDA]), road.names[hostIDA])
	}
	if len(dialed) != 1 || dialed[0] != addr || road.closedN != 1 {
		t.Fatalf("dialed %v, closed %d", dialed, road.closedN)
	}
	// Hosted already: the link, and no bytes asked for — from a Mac that
	// holds only the card, too.
	for _, have := range []bool{true, false} {
		ask["have"] = have
		if got := hostAsk(t, ask, body); len(got) != 1 || got[0]["url"] != road.link(hostIDA) {
			t.Fatalf("hosted already (have %v): %v", have, got)
		}
	}
	other := map[string]any{"op": "host", "id": hostIDB, "name": "b.bin", "have": false}
	if got := hostAsk(t, other, nil); len(got) != 1 || got[0]["error"] != "not-hosted" {
		t.Fatalf("a card with no bytes anywhere: %v", got)
	}
	other["have"], other["size"] = true, 4
	road.refuse = "full"
	if got := hostAsk(t, other, []byte("four")); len(got) != 2 || got[1]["error"] != "full" {
		t.Fatalf("a full primary: %v", got)
	}
	road.refuse = ""
	if got := hostAsk(t, map[string]any{"op": "host", "id": "nope", "name": "x", "size": 1, "have": true}, nil); got[0]["error"] != "bad-args" {
		t.Fatalf("a bad id: %v", got)
	}
	if got := hostAsk(t, map[string]any{"op": "host", "id": hostIDB, "name": "x", "size": 0, "have": true}, nil); got[0]["error"] != "bad-args" {
		t.Fatalf("no size: %v", got)
	}
	if got := hostAsk(t, map[string]any{"op": "unhost", "id": hostIDA}, nil); len(got) != 1 || got[0]["ok"] != true || len(road.drops) != 1 || road.drops[0] != hostIDA {
		t.Fatalf("unhost: %v %v", got, road.drops)
	}
	road.down = true
	if got := hostAsk(t, ask, body); len(got) != 1 || got[0]["error"] != "unreachable" {
		t.Fatalf("a primary that does not answer: %v", got)
	}
	if got := hostAsk(t, map[string]any{"op": "unhost", "id": hostIDA}, nil); got[0]["error"] != "unreachable" {
		t.Fatalf("unhost with the primary away: %v", got)
	}
	// The socket says whether links can be had at all.
	peers := hostAsk(t, map[string]any{"op": "peers"}, nil)
	if len(peers) != 1 || peers[0]["host"] != true {
		t.Fatalf("peers: %v", peers)
	}
	t.Setenv("MON_HOST", "off")
	if got := hostAsk(t, ask, body); got[0]["error"] != "off" {
		t.Fatalf("with hosting off: %v", got)
	}
	if peers := hostAsk(t, map[string]any{"op": "peers"}, nil); peers[0]["host"] != false {
		t.Fatalf("peers with hosting off: %v", peers)
	}
}

// out's side, on the primary itself: kept here, nothing dialed.
func TestHostSocketPrimary(t *testing.T) {
	f := newPrimaryFixture(t)
	hostReset(t)
	f.primaryOn(t)
	was := hostRoadFor
	hostRoadFor = func(addr string) (hostRoad, error) {
		t.Error("the primary dialed for its own item")
		return nil, io.EOF
	}
	t.Cleanup(func() { hostRoadFor = was })
	body := []byte("the bytes of a picture")
	ask := map[string]any{"op": "host", "id": hostIDA, "name": "pic.jpg", "size": len(body), "have": true}
	if got := hostAsk(t, ask, body); len(got) != 1 || got[0]["error"] != "no-tailnet" {
		t.Fatalf("with no tailnet road: %v", got)
	}
	hostOnTailnet(t)
	got := hostAsk(t, ask, body)
	if len(got) != 2 || got[0]["send"] != true || got[1]["ok"] != true {
		t.Fatalf("host: %v", got)
	}
	it, ok := hostFind(hostIDA)
	link, _ := hostURL(it)
	if !ok || got[1]["url"] != link || it.From != agentID() {
		t.Fatalf("kept %+v, answered %v", it, got[1])
	}
	kept, _ := os.ReadFile(filepath.Join(hostDir(), it.Token))
	if !bytes.Equal(kept, body) {
		t.Fatalf("kept %q", kept)
	}
	if got := hostAsk(t, ask, body); len(got) != 1 || got[0]["url"] != link {
		t.Fatalf("hosted already: %v", got)
	}
	// out went away mid-file: nothing is kept of it.
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { servePutLocal(server); close(done) }()
	line, _ := json.Marshal(map[string]any{"op": "host", "id": hostIDB, "name": "half.bin", "size": 1000, "have": true})
	client.Write(append(line, '\n'))
	bufio.NewReader(client).ReadBytes('\n')
	client.Write([]byte("only a part"))
	client.Close()
	<-done
	if _, ok := hostFind(hostIDB); ok || len(hostParts(t)) != 0 {
		t.Fatalf("a cut transfer left something: %v", hostParts(t))
	}
	if got := hostAsk(t, map[string]any{"op": "unhost", "id": hostIDA}, nil); got[0]["ok"] != true {
		t.Fatalf("unhost: %v", got)
	}
	if _, ok := hostFind(hostIDA); ok {
		t.Fatal("hosted after unhost")
	}
}

// A member's helper puts a file to its primary over a real tunnel, with the
// key the round learned, and the link then serves the same bytes.
func TestE2EHostOverTailcat(t *testing.T) {
	if os.Getenv("MON_E2E") == "" {
		t.Skip("set MON_E2E=1 to run against a real DERP")
	}
	f := newPrimaryFixture(t)
	hostReset(t)
	f.primaryOn(t)
	hostOnTailnet(t)
	// The member shares this config dir, so its host key is this one.
	priv, err := hostClientKey()
	if err != nil {
		t.Fatal(err)
	}
	memberAddr := testPutAddr(t)
	f.command(t, "primary-roster", "", rosterJSON(t, rosterMember("e2eHostMem1", "Member", memberAddr)))
	var kid string
	for _, m := range readPrimaryRoster() {
		if m.Agent == "e2eHostMem1" {
			kid = m.Kid
		}
	}
	if err := writeJSONFile(primaryPath(hostKeysFile), []hostMember{{Agent: "e2eHostMem1", Addr: memberAddr, Kid: kid, Key: priv.Public().String()}}); err != nil {
		t.Fatal(err)
	}
	tc, err := transport.StartTailcat(transport.TailcatConfig{
		StateDir: filepath.Join(t.TempDir(), "primary-state"),
		Port:     directPort,
		Allowed:  func() []key.NodePublic { return append(loadAllowedClients(), activeHostNodes()...) },
		Handler:  f.h,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	road, err := hostRoadFor(tc.ConnBlob())
	if err != nil {
		t.Fatal(err)
	}
	defer road.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, code, err := road.have(ctx, hostIDA); err != nil || code != "not-hosted" {
		t.Fatalf("have before put: %q %v", code, err)
	}
	body := make([]byte, 3<<20)
	rand.Read(body)
	began := time.Now()
	link, code, err := road.put(ctx, hostIDA, "big picture.png", int64(len(body)), bytes.NewReader(body))
	if err != nil || code != "" || link == "" {
		t.Fatalf("put: %q %q %v", link, code, err)
	}
	t.Logf("3 MiB over the tunnel in %s", time.Since(began).Round(time.Millisecond))
	again, code, err := road.have(ctx, hostIDA)
	if err != nil || code != "" || again != link {
		t.Fatalf("have: %q %q %v", again, code, err)
	}
	it, _ := hostFind(hostIDA)
	rec := httptest.NewRecorder()
	tailnetServe.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s/"+it.Token+"/big%20picture.png", nil))
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), body) || rec.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("the link: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if !strings.HasSuffix(link, "/s/"+it.Token+"/big%20picture.png") || it.From != "e2eHostMem1" {
		t.Fatalf("link %q, item %+v", link, it)
	}
	if code, err := road.drop(ctx, hostIDA); err != nil || code != "" {
		t.Fatalf("drop: %q %v", code, err)
	}
	if _, code, _ := road.have(ctx, hostIDA); code != "not-hosted" {
		t.Fatalf("have after drop: %q", code)
	}
}
