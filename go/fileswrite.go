package main

// fileswrite.go — the Files tab putting things on this machine's disks: a
// file brought from another computer or from the browser, a piece at a
// time; a new folder; a name changed; a thing moved to another folder here;
// a thing put in the system's own trash (index.html's Files panel, through
// monitor.js MonitorFiles; the reads are files.go).
//
// WHO MAY. The gate is the one files.go reads behind, unchanged: a pinned
// dashboard key, the console switch, the tunnel alone, never a portable
// copy (runFilesCommand, filesPeer). A console already runs /bin/sh as this
// user, which can write anything this user can; these are that power in a
// shape a page can drive without composing a shell line, and nothing more.
//
// WHAT IS NOT HERE: a way to destroy. There is no delete and no overwrite
// nobody asked for. A thing taken away goes to the trash the system keeps
// for its user (the Finder's ~/.Trash, the freedesktop trash), where it can
// be taken back; where there is no such trash the page is told so and
// nothing happens. A file put where one of that name already is takes the
// next free name ("name (2).ext") unless the page said, for that file, to
// replace it — and a folder is never replaced.
//
// A FILE COMES IN as a part file beside where it will live, under a name no
// listing shows (".subnsub-<key>.part": hidden, so files.go counts it and
// does not list it), written strictly in order: a piece that arrives before
// its turn is held until the one before it is written, so a page may keep a
// few pieces in flight without the helper keeping a map of holes. Only when
// every byte is there does `done` move it to its name, by a hard link that
// fails rather than clobber, so a half-written file never stands under the
// real name and an interrupted copy leaves nothing a person would mistake
// for the file. A page that names a key (k) can come back to the same part
// after a dropped tunnel or a restart and go on from where it stopped.
//
// THE TOKEN a put answers with is good only on the tunnel of the peer that
// asked, and only while the console stays on, that peer stays on the
// allowlist and the key that signed the put stays pinned — the same binding
// as a read's (files.go). The pieces that follow carry the token and are
// not signed one by one, as a terminal's keystrokes are not (pty.go).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	// One piece: what the browser module carries in one request
	// (tailcat-web maxPutBody). The tailnet road's sealed requests take
	// less (tailnetMaxRPC); the page sends that road smaller pieces.
	filesPutMax = 4 << 20
	// The largest file a put may announce.
	filesPutSize = int64(1) << 40
	// Uploads open on this helper at once, and per browser.
	filesPutOpen    = 32
	filesPutPerPeer = 16
	// An upload nobody has sent a piece to for this long is closed; its part
	// stays only when the page named a key it can come back with.
	filesPutIdle = 15 * time.Minute
	// Early pieces held per upload while the one before is written.
	filesPutWaiters = 4
	// Piece bodies held in memory at once across the helper, and how long
	// one waits for room before it is told "busy".
	filesPutBodies   = 8
	filesPutBodyWait = 20 * time.Second
	// A piece's own time to come in: the tunnel's server gives a request ten
	// seconds (transport/tailcat.go), which four megabytes through a busy
	// DERP relay can outlast.
	filesPutRead = 2 * time.Minute

	filesNameMax = 255
	// done's m at most: 9999-12-31T23:59:59Z in Unix seconds.
	filesTimeMax = 253402300799
	// "name (2)" … "name (999)", then the page is told the name is taken.
	filesKeepMax    = 999
	filesPartPrefix = ".subnsub-"
	filesPartSuffix = ".part"

	// A change to a disk under the command gate, and how many may be left
	// running past it (a network mount that stopped answering).
	filesDoWait  = filesListWait
	filesDoStuck = 4
)

// filesPutHold is how long an early piece waits for its turn; a variable so
// a test need not wait half a minute to see one given up on.
var filesPutHold = 30 * time.Second

// filesLink is os.Link; a test swaps it for one that fails the way a disk
// without hard links (FAT, exFAT, many network shares) does.
var filesLink = os.Link

var filesPutKRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// ── names ───────────────────────────────────────────────────────────────

// filesNameArg is a name a page asks to give something in a folder: one
// entry's own name, nothing that leads anywhere else, and nothing this
// helper keeps for its parts.
func filesNameArg(raw string) (string, string) {
	if !filesNameOK(raw, runtime.GOOS) {
		return "", "bad-name"
	}
	return raw, ""
}

// filesNameOK is filesNameArg's rule for the system named, so Windows' rules
// can be tested on any machine.
func filesNameOK(n, goos string) bool {
	if n == "" || len(n) > filesNameMax || !utf8.ValidString(n) || n == "." || n == ".." {
		return false
	}
	if strings.ContainsAny(n, "/\\") || strings.HasPrefix(n, filesPartPrefix) {
		return false
	}
	// No control characters anywhere: a name with a newline or an escape in
	// it is a name a listing (files.go) does not show and a terminal shows
	// wrongly.
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if goos == "windows" {
		if strings.ContainsAny(n, `<>:"|?*`) || strings.HasSuffix(n, ".") || strings.HasSuffix(n, " ") {
			return false
		}
		// The device names, which Windows takes for the device whatever
		// follows the first dot.
		stem := n
		if i := strings.IndexByte(stem, '.'); i >= 0 {
			stem = stem[:i]
		}
		stem = strings.ToUpper(strings.TrimRight(stem, " "))
		switch stem {
		case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
			return false
		}
		// COM0 to COM9 and LPT0 to LPT9, and the superscript one, two and
		// three after either, which Windows takes for the same ports.
		if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
			switch stem[3:] {
			case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
				return false
			}
		}
	}
	return true
}

// filesNumbered is the n-th name a thing called name takes when name is
// taken: "report (2).pdf". A name whose only dot leads it (".env") has no
// extension. Cut so the result still fits max bytes, on a character's edge.
func filesNumbered(name string, n, max int) string {
	ext := filepath.Ext(name)
	if ext == name {
		ext = ""
	}
	base := strings.TrimSuffix(name, ext)
	tag := " (" + strconv.Itoa(n) + ")"
	for len(base)+len(tag)+len(ext) > max && len(base) > 0 {
		_, size := utf8.DecodeLastRuneInString(base)
		base = base[:len(base)-size]
	}
	if len(base)+len(tag)+len(ext) > max {
		// Nothing left of the name to cut: the extension goes too.
		ext = ""
	}
	return base + tag + ext
}

// filesTooBroad: what a page may not rename, move or put in the trash —
// a disk's root, the system's own top-level trees, the home folder itself,
// a mounted disk's own folder. Not a fence against the person (the console
// is a shell), a fence against a drag that let go in the wrong place.
func filesTooBroad(p string) bool {
	if musicDirTooBroad(p) || filepath.Dir(p) == p {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" && filepath.Clean(home) == p {
		return true
	}
	switch runtime.GOOS {
	case "windows":
		vol := filepath.VolumeName(p)
		for _, x := range []string{`\Windows`, `\Program Files`, `\Program Files (x86)`, `\ProgramData`, `\Users`} {
			if strings.EqualFold(p, vol+x) {
				return true
			}
		}
		return false
	case "darwin", "ios":
		// A disk under /Volumes is its own folder there; what is in it is not.
		if rest, ok := strings.CutPrefix(p, "/Volumes/"); ok && rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	case "linux", "android":
		// Every mounted disk's own folder (musicVolumes reads the kernel's
		// list, which does not wait on any disk).
		for _, v := range musicVolumes() {
			if filepath.Clean(v.P) == p {
				return true
			}
		}
	}
	for _, x := range []string{"/bin", "/boot", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/root",
		"/run", "/sbin", "/snap", "/srv", "/tmp", "/usr", "/var", "/home", "/mnt", "/media", "/nix",
		"/Users", "/System", "/Library", "/Applications", "/Volumes", "/private", "/cores", "/Network",
		"/data", "/system", "/sdcard", "/storage"} {
		if p == x {
			return true
		}
	}
	return false
}

// ── errors ──────────────────────────────────────────────────────────────

// filesWriteErr is a change that failed, in the words the page knows.
func filesWriteErr(err error) string {
	if err == nil {
		return ""
	}
	if code := filesErrno(err); code != "" {
		return code
	}
	switch {
	case errors.Is(err, fs.ErrExist):
		return "exists"
	case errors.Is(err, fs.ErrNotExist):
		return "missing"
	case errors.Is(err, fs.ErrPermission):
		return "no-access"
	}
	return "unavailable"
}

// ── bounded changes ─────────────────────────────────────────────────────

// filesDoing counts the changes still running after their caller stopped
// waiting.
var filesDoing atomic.Int32

// filesDo runs one change to a disk for at most wait, under the command
// gate. A disk that does not answer (a network mount gone away) holds the
// goroutine, never the gate: the page is told "timeout", and late, if
// given, is handed what the change did once it finishes, so a file it
// opened is closed by somebody. Unlike musicWithin's looks, changes are
// never shared between callers: two asks to make a folder are two asks.
func filesDo[T any](wait time.Duration, do func() (T, string), late func(T, string)) (T, string) {
	var zero T
	if filesDoing.Load() >= filesDoStuck {
		return zero, "busy"
	}
	type got struct {
		v    T
		code string
	}
	ch := make(chan got, 1)
	var mu sync.Mutex
	abandoned := false
	go func() {
		v, code := do()
		mu.Lock()
		if abandoned {
			mu.Unlock()
			filesDoing.Add(-1)
			if late != nil {
				late(v, code)
			}
			return
		}
		ch <- got{v, code}
		mu.Unlock()
	}()
	clock := time.NewTimer(wait)
	defer clock.Stop()
	select {
	case g := <-ch:
		return g.v, g.code
	case <-clock.C:
		mu.Lock()
		defer mu.Unlock()
		select {
		case g := <-ch:
			return g.v, g.code
		default:
		}
		abandoned = true
		filesDoing.Add(1)
		return zero, "timeout"
	}
}

// filesStat is one thing on a disk as a look found it.
type filesStat struct {
	dir  bool
	reg  bool
	link bool
	size int64
	mode fs.FileMode
	mod  time.Time
}

// filesLook looks at a path the way a listing looks at a folder: shared with
// whoever asks the same thing meanwhile, waited on as long as a listing is,
// and on a Mac answered "permission-wait" while the system asks its user
// about a guarded folder (musicWithin). follow: where a link leads (a folder
// to put things in) or the link itself (a thing to rename, move or trash).
func filesLook(p string, follow bool) (filesStat, string) {
	op := "files-lstat\n"
	if follow {
		op = "files-stat\n"
	}
	return musicWithin(filesListWait, op+p, func() bool { return musicGuardedLinks(p) }, func() (filesStat, string) {
		var fi os.FileInfo
		var err error
		if follow {
			fi, err = os.Stat(p)
		} else {
			fi, err = os.Lstat(p)
		}
		if err != nil {
			return filesStat{}, filesWriteErr(err)
		}
		return filesStat{dir: fi.IsDir(), reg: fi.Mode().IsRegular(), link: fi.Mode()&fs.ModeSymlink != 0,
			size: fi.Size(), mode: fi.Mode(), mod: fi.ModTime()}, ""
	})
}

// filesLookDir: a folder that is there, to put things in.
func filesLookDir(p string) string {
	st, code := filesLook(p, true)
	if code != "" {
		return code
	}
	if !st.dir {
		return "not-a-folder"
	}
	return ""
}

// ── uploads ─────────────────────────────────────────────────────────────

type filesPut struct {
	tok    string
	peer   key.NodePublic
	signer ed25519.PublicKey
	dir    string
	name   string
	part   string
	k      string // the page's key for this part, "" when it named none
	size   int64
	mode   string
	was    filesWas    // what the page saw of the file a replace replaces
	id     os.FileInfo // the part as opened: what every later look must find

	// Held for the one write in progress, so closing the file waits for it.
	wmu sync.Mutex

	mu        sync.Mutex
	f         *os.File
	have      int64
	writing   bool
	waiting   int
	moved     chan struct{} // closed when have moves or the upload ends
	ended     string        // why it ended; "" while it is open
	full      bool          // done has synced and closed the file
	finishing bool
	seen      time.Time
}

var filesPuts = struct {
	sync.Mutex
	m map[string]*filesPut
}{m: map[string]*filesPut{}}

// The piece bodies in hand: so many, waiting ones counted, at once.
var filesPutHand = make(chan struct{}, filesPutBodies)

// bump wakes everyone waiting on this upload. Under p.mu.
func (p *filesPut) bump() {
	close(p.moved)
	p.moved = make(chan struct{})
}

// end closes the upload once; the first reason stands. drop removes the part.
func (p *filesPut) end(why string, drop bool) {
	p.mu.Lock()
	if p.ended != "" {
		p.mu.Unlock()
		return
	}
	p.ended = why
	f := p.f
	p.f = nil
	p.bump()
	p.mu.Unlock()
	// The piece being written, if one is, lands before the file is closed.
	p.wmu.Lock()
	if f != nil {
		f.Close()
	}
	p.wmu.Unlock()
	if drop {
		os.Remove(p.part)
	}
}

// filesPutFind is an upload by its token, for the peer that holds it and
// while the key that signed its put is pinned; nil otherwise.
func filesPutFind(tok string, peer key.NodePublic) *filesPut {
	if tok == "" {
		return nil
	}
	filesPuts.Lock()
	p := filesPuts.m[tok]
	filesPuts.Unlock()
	if p == nil || p.peer != peer || !filesSignerOK(p.signer) {
		return nil
	}
	p.mu.Lock()
	ended := p.ended != ""
	p.mu.Unlock()
	if ended {
		return nil
	}
	return p
}

func filesPutForget(p *filesPut) {
	filesPuts.Lock()
	if filesPuts.m[p.tok] == p {
		delete(filesPuts.m, p.tok)
	}
	filesPuts.Unlock()
}

// filesPutSweep ends the uploads nobody has sent a piece to lately and the
// ones whose signing key was unpinned since; called with filesSweep's clock.
func filesPutSweep(now time.Time) {
	filesPuts.Lock()
	var gone []*filesPut
	for tok, p := range filesPuts.m {
		p.mu.Lock()
		idle := !p.writing && p.waiting == 0 && !p.finishing && now.Sub(p.seen) > filesPutIdle
		p.mu.Unlock()
		if idle || !filesSignerOK(p.signer) {
			delete(filesPuts.m, tok)
			gone = append(gone, p)
		}
	}
	filesPuts.Unlock()
	for _, p := range gone {
		// A part the page named a key for waits for it to come back.
		p.end("idle", p.k == "")
	}
}

type filesPutBody struct {
	T     string `json:"t"`
	Have  int64  `json:"have"`
	Max   int    `json:"max"`
	Part  string `json:"part"`
	Taken bool   `json:"taken,omitempty"` // a thing of that name is there now
}

// filesPutStart is `put`: the part file opened, or found again, and its
// token.
func filesPutStart(peer key.NodePublic, signer ed25519.PublicKey, rawDir, rawName string, size int64, k, mode string, rawWas json.RawMessage) (filesPutBody, string) {
	var b filesPutBody
	dir, code := musicPathArg(rawDir)
	if code != "" {
		return b, code
	}
	name, code := filesNameArg(rawName)
	if code != "" {
		return b, code
	}
	if size < 0 || size > filesPutSize {
		return b, "bad-args"
	}
	if k != "" && !filesPutKRe.MatchString(k) {
		return b, "bad-args"
	}
	switch mode {
	case "":
		mode = "keep"
	case "keep", "replace", "fail":
	default:
		return b, "bad-args"
	}
	was, code := filesWasArg(rawWas)
	if code != "" {
		return b, code
	}
	if code := filesLookDir(dir); code != "" {
		return b, code
	}
	partName := filesPartPrefix + k + filesPartSuffix
	if k == "" {
		partName = filesPartPrefix + filesToken()[:16] + filesPartSuffix
	}
	part := filepath.Join(dir, partName)

	filesSweep(time.Now())
	filesSweeping()
	filesPuts.Lock()
	var old *filesPut
	open, mine := 0, 0
	for _, p := range filesPuts.m {
		if k != "" && p.part == part {
			// The same part, asked for again: the page that paused, or
			// lost its tunnel, coming back. Another browser's, or another
			// key's, is left alone.
			if p.peer != peer || !p.signer.Equal(signer) {
				filesPuts.Unlock()
				return b, "busy"
			}
			old = p
			continue
		}
		open++
		if p.peer == peer {
			mine++
		}
	}
	if open >= filesPutOpen || mine >= filesPutPerPeer {
		filesPuts.Unlock()
		return b, "busy"
	}
	if old != nil {
		delete(filesPuts.m, old.tok)
	}
	filesPuts.Unlock()
	if old != nil {
		// Its waiting pieces are told no-put; the part stays as it is.
		old.end("replaced", false)
	}

	type opened struct {
		f     *os.File
		id    os.FileInfo
		have  int64
		taken bool
	}
	got, code := filesDo(filesDoWait, func() (opened, string) {
		var o opened
		target := filepath.Join(dir, name)
		if fi, err := os.Lstat(target); err == nil {
			o.taken = true
			// Told now rather than after every byte has crossed: a page
			// that asks first, and a folder that is never replaced.
			if mode == "fail" || (mode == "replace" && fi.IsDir()) {
				return o, "exists"
			}
		}
		if mode == "replace" {
			// A file saved back over the one the page read: not over one
			// somebody has changed since.
			if code := filesWasHolds(target, was); code != "" {
				return o, code
			}
		}
		if k != "" {
			f, id, code := filesPartAgain(part, size)
			if code != "" {
				return o, code
			}
			if f != nil {
				o.f, o.id, o.have = f, id, id.Size()
				return o, ""
			}
		}
		// A part of its own, made by this call or not at all, and 0600
		// until it has its name whatever the umask: a file replacing one
		// only its owner may read is not readable by others meanwhile.
		f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL|filesNoFollow, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				// Made under its name since the look: somebody else's.
				return o, "unavailable"
			}
			return o, filesWriteErr(err)
		}
		id, err := f.Stat()
		if err != nil {
			f.Close()
			os.Remove(part)
			return o, "unavailable"
		}
		o.f, o.id = f, id
		return o, ""
	}, func(o opened, _ string) {
		// Opened after the page was told "timeout": nobody will write it.
		if o.f != nil {
			o.f.Close()
			if k == "" {
				os.Remove(part)
			}
		}
	})
	if code != "" {
		return b, code
	}
	if free, ok := filesFree(dir); ok && free < uint64(size-got.have) {
		got.f.Close()
		if k == "" {
			os.Remove(part)
		}
		return b, "no-space"
	}
	tok := filesToken()
	if tok == "" {
		got.f.Close()
		return b, "unavailable"
	}
	p := &filesPut{tok: tok, peer: peer, signer: signer, dir: dir, name: name, part: part, k: k, size: size,
		mode: mode, was: was, id: got.id, f: got.f, have: got.have, moved: make(chan struct{}), seen: time.Now()}
	filesPuts.Lock()
	filesPuts.m[tok] = p
	filesPuts.Unlock()
	return filesPutBody{T: tok, Have: got.have, Max: filesPutMax, Part: partName, Taken: got.taken}, ""
}

// filesPartLstat is os.Lstat, for filesPartAgain's first look: a test puts
// in its place a look that sees another file, as one would if a writer in
// the same folder swapped the part between the look and the open.
var filesPartLstat = os.Lstat

// filesPartAgain is a keyed part found again, to go on with: opened only if
// it is still one this helper would have written (a regular file with one
// name, no longer than the file now announced), without following a link,
// and only if what was opened is what was looked at; and 0600 again, as a
// done that could not name it may have left it otherwise. Anything else
// under the part's name is let go (os.Remove takes the name, never what a
// link leads to, and a second name leaves the file under its first) and the
// part is begun again. nil and "" when there is none to go on with.
func filesPartAgain(part string, size int64) (*os.File, os.FileInfo, string) {
	fi, err := filesPartLstat(part)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ""
	}
	if err != nil {
		return nil, nil, filesWriteErr(err)
	}
	links, known := filesLinks(fi)
	if !fi.Mode().IsRegular() || (known && links != 1) || fi.Size() > size {
		if err := os.Remove(part); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, "unavailable"
		}
		return nil, nil, ""
	}
	f, err := os.OpenFile(part, os.O_WRONLY|filesNoFollow, 0)
	if err != nil {
		// A link swapped in since the look is refused by the open itself.
		return nil, nil, "unavailable"
	}
	id, err := f.Stat()
	if err != nil || !id.Mode().IsRegular() || !os.SameFile(id, fi) || id.Size() > size {
		f.Close()
		return nil, nil, "unavailable"
	}
	filesSetMode(f, 0o600)
	return f, id, ""
}

// filesWas is what the page saw of the file a replace is to replace: its
// size and modified time, in Unix seconds as the listings give it. A file
// saved back over the one it was read from is not saved over a change
// somebody made since.
type filesWas struct {
	set  bool
	s, m int64
}

// filesWasArg reads put's was, {"s": size, "m": modified}: those two keys
// as written (json's own matching would take "S" as "s"), both whole
// numbers not below zero, nothing else; or no was, or null.
func filesWasArg(raw json.RawMessage) (filesWas, string) {
	var w filesWas
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return w, ""
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(t, &v) != nil || len(v) != 2 {
		return w, "bad-args"
	}
	size, ok := filesWhole(v["s"])
	mod, ok2 := filesWhole(v["m"])
	if !ok || !ok2 {
		return w, "bad-args"
	}
	return filesWas{set: true, s: size, m: mod}, ""
}

// filesWhole is a JSON number written as digits alone (no sign, fraction,
// exponent or quotes) that fits an int64.
func filesWhole(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || len(raw) > 19 {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil
}

// filesWasHolds: the file at target is still what the page saw, or there is
// nothing there now (a file gone is not a change to lose). Looked at as the
// listing looks, through a link, since that is where the page's s and m came
// from; only looked at, nothing is done through it. "" when it holds or no
// was was given, "changed-since" when it does not.
func filesWasHolds(target string, w filesWas) string {
	if !w.set {
		return ""
	}
	fi, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		return filesWriteErr(err)
	}
	if !fi.Mode().IsRegular() || fi.Size() != w.s || fi.ModTime().Unix() != w.m {
		return "changed-since"
	}
	return ""
}

// await holds a piece that came before its turn until the one before it is
// written: until the part reaches off, the upload ends, the hold runs out
// ("offset", with where the part stands) or the request goes ("gone"). It
// comes before the piece's body is read, so a piece waiting holds neither
// its bytes nor a seat among the bodies in hand (filesPutHand): pieces
// waiting on a turn could otherwise fill every seat while the piece whose
// turn it is waits for one.
func (p *filesPut) await(ctx context.Context, off int64) (int64, string) {
	p.mu.Lock()
	if off <= p.have || p.ended != "" {
		// Its turn, or a piece already written, or an upload over:
		// write says which.
		p.mu.Unlock()
		return 0, ""
	}
	if p.waiting >= filesPutWaiters {
		have := p.have
		p.mu.Unlock()
		return have, "offset"
	}
	p.waiting++
	clock := time.NewTimer(filesPutHold)
	defer clock.Stop()
	for off > p.have && p.ended == "" {
		p.seen = time.Now()
		ch := p.moved
		p.mu.Unlock()
		select {
		case <-ch:
			p.mu.Lock()
		case <-clock.C:
			p.mu.Lock()
			p.waiting--
			have := p.have
			p.mu.Unlock()
			return have, "offset"
		case <-ctx.Done():
			p.mu.Lock()
			p.waiting--
			p.mu.Unlock()
			return 0, "gone"
		}
	}
	p.waiting--
	p.seen = time.Now()
	p.mu.Unlock()
	return 0, ""
}

// write is one piece at off, in its turn: a piece already written answers as
// written (a retry whose answer was lost), one that arrives early waits for
// the one before it, one that overlaps what is written is refused with where
// the part stands. Answers the bytes the part now holds.
func (p *filesPut) write(ctx context.Context, off int64, b []byte) (int64, string) {
	n := int64(len(b))
	counted := false
	clock := time.NewTimer(filesPutHold)
	defer clock.Stop()
	p.mu.Lock()
	leave := func() {
		if counted {
			p.waiting--
			counted = false
		}
	}
	for {
		if p.ended != "" {
			leave()
			p.mu.Unlock()
			return 0, "no-put"
		}
		p.seen = time.Now()
		switch {
		case off+n <= p.have:
			have := p.have
			leave()
			p.mu.Unlock()
			return have, ""
		case off < p.have:
			have := p.have
			leave()
			p.mu.Unlock()
			return have, "offset"
		case off == p.have && !p.writing && !p.full:
			leave()
			p.writing = true
			f := p.f
			p.mu.Unlock()
			p.wmu.Lock()
			var err error
			if f == nil {
				err = os.ErrClosed
			} else {
				_, err = f.WriteAt(b, off)
			}
			p.wmu.Unlock()
			p.mu.Lock()
			p.writing = false
			if err != nil {
				p.bump()
				ended := p.ended != ""
				p.mu.Unlock()
				if ended {
					return 0, "no-put"
				}
				if code := filesWriteErr(err); code == "no-space" {
					return 0, code
				}
				return 0, "unavailable"
			}
			p.have += n
			p.seen = time.Now()
			p.bump()
			have := p.have
			p.mu.Unlock()
			return have, ""
		}
		// Early, or its turn while another piece is being written.
		if !counted {
			if p.waiting >= filesPutWaiters {
				have := p.have
				p.mu.Unlock()
				return have, "offset"
			}
			p.waiting++
			counted = true
		}
		ch := p.moved
		p.mu.Unlock()
		select {
		case <-ch:
			p.mu.Lock()
		case <-clock.C:
			p.mu.Lock()
			have := p.have
			leave()
			p.mu.Unlock()
			return have, "offset"
		case <-ctx.Done():
			p.mu.Lock()
			leave()
			p.mu.Unlock()
			return 0, "gone"
		}
	}
}

// filesPutPiece is POST /v1/files/put?s=…&o=…: one piece of an upload, the
// body its bytes. 200 {"have":N}; 409 with have when the offset is not the
// part's to take.
func (h *directHandler) filesPutPiece(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.filesPeer(w, r)
	if !ok {
		return
	}
	if r.ContentLength > filesPutMax {
		h.refuse(w, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	p := filesPutFind(r.URL.Query().Get("s"), peer)
	if p == nil {
		filesPutDrain(w, r)
		h.refuse(w, http.StatusNotFound, "no-put")
		return
	}
	// Past the end is refused at once when the length is known, not held
	// for a turn that would only end in the same answer.
	off := queryInt(r, "o")
	if off < 0 || off > p.size || (r.ContentLength >= 0 && off+r.ContentLength > p.size) {
		filesPutDrain(w, r)
		h.refuse(w, http.StatusRequestedRangeNotSatisfiable, "out-of-range")
		return
	}
	if have, code := p.await(r.Context(), off); code == "gone" {
		return
	} else if code == "offset" {
		filesPutDrain(w, r)
		filesPutOffset(w, have)
		return
	}
	select {
	case filesPutHand <- struct{}{}:
		defer func() { <-filesPutHand }()
	case <-r.Context().Done():
		return
	case <-time.After(filesPutBodyWait):
		filesPutDrain(w, r)
		h.refuse(w, http.StatusServiceUnavailable, "busy")
		return
	}
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(filesPutRead))
	body, err := io.ReadAll(io.LimitReader(r.Body, filesPutMax+1))
	if err != nil {
		h.refuse(w, http.StatusBadRequest, "cut-off")
		return
	}
	if len(body) > filesPutMax {
		h.refuse(w, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	if off+int64(len(body)) > p.size {
		h.refuse(w, http.StatusRequestedRangeNotSatisfiable, "out-of-range")
		return
	}
	have, code := p.write(r.Context(), off, body)
	switch code {
	case "":
	case "gone":
		return
	case "offset":
		filesPutOffset(w, have)
		return
	case "no-put":
		h.refuse(w, http.StatusNotFound, code)
		return
	case "no-space":
		h.refuse(w, http.StatusInsufficientStorage, code)
		return
	default:
		h.refuse(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]int64{"have": have})
}

// filesPutDrain reads what is left of a piece the helper is not taking, to
// nowhere and no further than a piece may be, before the answer goes. Left
// unread, the server would close the connection under a browser still
// sending, which then may hear a broken connection rather than the answer
// (offset, busy) that tells it what to do next.
func filesPutDrain(w http.ResponseWriter, r *http.Request) {
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(filesPutRead))
	io.Copy(io.Discard, io.LimitReader(r.Body, filesPutMax))
}

// filesPutOffset is 409: the piece is not the part's to take at its offset
// (it overlaps what is written, or waited too long for its turn), with how
// many bytes the part holds, so the page goes on from there.
func filesPutOffset(w http.ResponseWriter, have int64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusConflict)
	if f, err := transport.New(transport.TypeError, agentID(), "", struct {
		Code string `json:"code"`
		Have int64  `json:"have"`
	}{"offset", have}); err == nil {
		if b, err := transport.Encode(f); err == nil {
			w.Write(b)
		}
	}
}

type filesDoneBody struct {
	Path string `json:"path"`
	N    string `json:"n"`
	S    int64  `json:"s"`
	// The file's modified time as it now stands, in Unix seconds as the
	// listings give it: what the page names as was to save it again.
	M int64 `json:"m"`
}

// filesPutDone is `done`: every byte is there, the part goes to its name.
// A name that is taken where the page said to ask ("fail"), or a folder in
// the way of a replace, answers "exists" and leaves the upload open, so the
// page can say done again with what the person chose.
func filesPutDone(peer key.NodePublic, tok string, m int64, mode string) (filesDoneBody, string) {
	var b filesDoneBody
	switch mode {
	case "", "keep", "replace", "fail":
	default:
		return b, "bad-args"
	}
	p := filesPutFind(tok, peer)
	if p == nil {
		return b, "no-put"
	}
	p.mu.Lock()
	if p.ended != "" {
		// Ended between the look and now (the sweep, a put that took its
		// part over): its file is closed and nobody is to name it.
		p.mu.Unlock()
		return b, "no-put"
	}
	if p.finishing {
		p.mu.Unlock()
		return b, "busy"
	}
	if p.writing || p.have != p.size {
		p.mu.Unlock()
		return b, "short"
	}
	if mode == "" {
		mode = p.mode
	}
	p.finishing = true
	p.seen = time.Now()
	f, full := p.f, p.full
	p.mu.Unlock()
	finished := func() {
		p.mu.Lock()
		p.finishing = false
		p.seen = time.Now()
		p.mu.Unlock()
	}
	type settled struct {
		path string
		m    int64
	}
	settle := func() (settled, string) {
		target := filepath.Join(p.dir, p.name)
		// Looked at before the part is touched: a done that cannot name it
		// as asked (the name taken where the page said to ask, a folder in
		// the way, a file changed since the page read it) leaves the upload
		// just as it was, its file open and 0600.
		if code := filesSettleLook(target, mode, p.was); code != "" {
			return settled{}, code
		}
		// Through the descriptor of the file written: synced before it has
		// a name (a crash after the rename must not leave a file of that
		// name with its last pieces lost), its mode and time set on it and
		// not on whatever the path names by then, and its identity taken
		// for the look before it is named.
		fd := f
		if full {
			// Closed by a done that could not finish: opened again without
			// following a link, and only if it is still the file written.
			g, err := os.OpenFile(p.part, filesReopen|filesNoFollow, 0)
			if err != nil {
				return settled{}, "unavailable"
			}
			if fi, err := g.Stat(); err != nil || !os.SameFile(fi, p.id) {
				g.Close()
				return settled{}, "unavailable"
			}
			fd = g
		}
		perm := filesNewPerm()
		if mode == "replace" {
			if fi, err := os.Lstat(target); err == nil && fi.Mode().IsRegular() {
				// The file replaced keeps who may read it.
				perm = fi.Mode().Perm()
			}
		}
		p.wmu.Lock()
		var serr error
		if !full {
			serr = fd.Sync()
		}
		// Refused only by a disk that keeps no modes, whose files have the
		// one it gives them.
		filesSetMode(fd, perm)
		// Seconds, up to the last of the year 9999; anything else (a page
		// that sent milliseconds) leaves the time the copy was made.
		if m > 0 && m <= filesTimeMax {
			filesSetTime(fd, p.part, time.Unix(m, 0))
		}
		st, sterr := fd.Stat()
		cerr := fd.Close()
		p.wmu.Unlock()
		if !full {
			p.mu.Lock()
			p.f, p.full = nil, true
			p.mu.Unlock()
		}
		if serr != nil || sterr != nil || cerr != nil {
			filesPartPrivate(p.part, p.id)
			return settled{}, "unavailable"
		}
		// The part's name still names the file written: a link, or another
		// file, put in its place by somebody else writing in this folder is
		// never given the name.
		if fi, err := os.Lstat(p.part); err != nil || !os.SameFile(fi, st) {
			return settled{}, "unavailable"
		}
		// And the file replaced, once more, just before it is: the look
		// above came before the sync, which on a slow disk takes a while.
		code := ""
		if mode == "replace" {
			code = filesWasHolds(target, p.was)
		}
		path := ""
		if code == "" {
			path, code = filesSettle(p.part, p.dir, p.name, mode)
		}
		if code != "" {
			filesPartPrivate(p.part, st)
			return settled{}, code
		}
		mod := st.ModTime()
		if fi, err := os.Lstat(path); err == nil && os.SameFile(fi, st) {
			// As a listing will show it, now it has its name: a network
			// disk may keep the time the last bytes reached it.
			mod = fi.ModTime()
		}
		return settled{path, mod.Unix()}, ""
	}
	got, code := filesDo(filesDoWait, settle, func(s settled, code string) {
		// Settled after the page was told "timeout": the upload stays
		// finishing until then, so a second done cannot run beside it.
		if code == "" {
			filesPutForget(p)
			p.end("done", false)
		}
		finished()
	})
	if code == "timeout" {
		return b, code
	}
	finished()
	if code != "" {
		return b, code
	}
	filesPutForget(p)
	p.end("done", false)
	return filesDoneBody{Path: got.path, N: filepath.Base(got.path), S: p.size, M: got.m}, ""
}

// filesSettleLook is done's look before it touches the part, for what would
// stop it in filesSettle anyway: in "fail" a name that is taken, in
// "replace" a folder in the way or a file changed since the page saw it.
// filesSettle and filesPlace look again as they name it; this one only keeps
// a done that will not get there from changing the part on its way.
func filesSettleLook(target, mode string, was filesWas) string {
	switch mode {
	case "fail":
		if _, err := os.Lstat(target); err == nil {
			return "exists"
		}
	case "replace":
		if fi, err := os.Lstat(target); err == nil && fi.IsDir() {
			return "exists"
		}
		return filesWasHolds(target, was)
	}
	return ""
}

// filesPartPrivate gives a part its 0600 again after a done that gave it its
// final mode could not name it: a part that waits for the person's choice is
// read by nobody else meanwhile. Only the file written, opened again without
// following a link.
func filesPartPrivate(part string, id os.FileInfo) {
	g, err := os.OpenFile(part, os.O_RDONLY|filesNoFollow, 0)
	if err != nil {
		return
	}
	if fi, err := g.Stat(); err == nil && os.SameFile(fi, id) {
		filesSetMode(g, 0o600)
	}
	g.Close()
}

// filesSettle moves a finished part to its name in dir, by the mode.
func filesSettle(part, dir, name, mode string) (string, string) {
	target := filepath.Join(dir, name)
	switch mode {
	case "replace":
		// Its mode is the replaced file's already (done's settle, on the
		// descriptor).
		if fi, err := os.Lstat(target); err == nil && fi.IsDir() {
			return "", "exists"
		}
		if err := os.Rename(part, target); err != nil {
			return "", filesWriteErr(err)
		}
		return target, ""
	case "fail":
		return filesPlace(part, target)
	}
	for i := 1; i <= filesKeepMax; i++ {
		t := target
		if i > 1 {
			t = filepath.Join(dir, filesNumbered(name, i, filesNameMax))
		}
		got, code := filesPlace(part, t)
		if code == "exists" {
			continue
		}
		return got, code
	}
	return "", "exists"
}

// filesPlace gives from the name to, if to is free: by a hard link, which
// fails rather than replace what is there, then the old name let go. A disk
// with no hard links (FAT, exFAT, many network shares) gets a look and a
// rename, whose window is a writer making the same name in the same instant.
func filesPlace(from, to string) (string, string) {
	err := filesLink(from, to)
	if err == nil {
		os.Remove(from)
		return to, ""
	}
	if errors.Is(err, fs.ErrExist) {
		return "", "exists"
	}
	if _, err := os.Lstat(to); err == nil {
		return "", "exists"
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", filesWriteErr(err)
	}
	if err := os.Rename(from, to); err != nil {
		return "", filesWriteErr(err)
	}
	return to, ""
}

// filesPutCancel is `cancel`: the upload ended and its part removed.
func filesPutCancel(peer key.NodePublic, tok string) string {
	p := filesPutFind(tok, peer)
	if p == nil {
		return ""
	}
	p.mu.Lock()
	busy := p.finishing
	p.mu.Unlock()
	if busy {
		return "busy"
	}
	filesPutForget(p)
	p.end("cancel", true)
	return ""
}

// filesPutDiscard is `cancel` by {dir, k} with no token: the page letting go
// of a part it named a key for, once the upload that held it is gone (the
// helper restarted, or the part sat idle past its time). Only when no upload
// open now holds it ("busy" if one does), only a regular file (a link or
// anything else under that name is not this helper's to remove), and only
// the name: os.Remove never reaches what a link leads to. Nothing there is
// done already.
func filesPutDiscard(rawDir, k string) string {
	// First: a cancel with neither a token nor a key is a page's mistake,
	// not a folder to look at.
	if !filesPutKRe.MatchString(k) {
		return "bad-args"
	}
	dir, code := musicPathArg(rawDir)
	if code != "" {
		return code
	}
	part := filepath.Join(dir, filesPartPrefix+k+filesPartSuffix)
	filesPuts.Lock()
	for _, p := range filesPuts.m {
		if p.part == part {
			filesPuts.Unlock()
			return "busy"
		}
	}
	filesPuts.Unlock()
	// A put of the same key that opens the part after the look above (the
	// page's own two asks crossing) writes to a file whose name is gone: its
	// done answers "unavailable", nothing of it is given a name.
	if code := filesLookDir(dir); code != "" {
		return code
	}
	_, code = filesDo(filesDoWait, func() (struct{}, string) {
		fi, err := os.Lstat(part)
		if errors.Is(err, fs.ErrNotExist) {
			return struct{}{}, ""
		}
		if err != nil {
			return struct{}{}, filesWriteErr(err)
		}
		if !fi.Mode().IsRegular() {
			return struct{}{}, "unavailable"
		}
		if err := os.Remove(part); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return struct{}{}, filesWriteErr(err)
		}
		return struct{}{}, ""
	}, nil)
	return code
}

// ── folders, names, moves, the trash ────────────────────────────────────

func filesMkdir(rawDir, rawName string) (string, string) {
	dir, code := musicPathArg(rawDir)
	if code != "" {
		return "", code
	}
	name, code := filesNameArg(rawName)
	if code != "" {
		return "", code
	}
	if code := filesLookDir(dir); code != "" {
		return "", code
	}
	target := filepath.Join(dir, name)
	return filesDo(filesDoWait, func() (string, string) {
		if err := os.Mkdir(target, 0o777); err != nil {
			return "", filesWriteErr(err)
		}
		return target, ""
	}, nil)
}

func filesRename(rawPath, rawName string) (string, string) {
	p, code := musicPathArg(rawPath)
	if code != "" {
		return "", code
	}
	name, code := filesNameArg(rawName)
	if code != "" {
		return "", code
	}
	if filesTooBroad(p) {
		return "", "too-broad"
	}
	if _, code := filesLook(p, false); code != "" {
		return "", code
	}
	target := filepath.Join(filepath.Dir(p), name)
	if target == p {
		return p, ""
	}
	return filesDo(filesDoWait, func() (string, string) {
		if fi, err := os.Lstat(target); err == nil {
			// The same entry under another case of its name, on a disk that
			// does not tell the two apart: a rename, not a clash.
			if was, err := os.Lstat(p); err != nil || !os.SameFile(fi, was) {
				return "", "exists"
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", filesWriteErr(err)
		}
		if err := os.Rename(p, target); err != nil {
			return "", filesWriteErr(err)
		}
		return target, ""
	}, nil)
}

func filesMove(rawPath, rawTo, mode string) (string, string) {
	p, code := musicPathArg(rawPath)
	if code != "" {
		return "", code
	}
	to, code := musicPathArg(rawTo)
	if code != "" {
		return "", code
	}
	switch mode {
	case "":
		mode = "keep"
	case "keep", "replace", "fail":
	default:
		return "", "bad-args"
	}
	if filesTooBroad(p) {
		return "", "too-broad"
	}
	st, code := filesLook(p, false)
	if code != "" {
		return "", code
	}
	if code := filesLookDir(to); code != "" {
		return "", code
	}
	if filepath.Dir(p) == to {
		return p, ""
	}
	if st.dir && musicPathWithin(to, p) {
		return "", "into-itself"
	}
	name := filepath.Base(p)
	return filesDo(filesDoWait, func() (string, string) {
		// Where links lead, too: a folder moved into a link to its own
		// insides is the same mistake by another road.
		if st.dir {
			if rp, rt := musicReal(p), musicReal(to); rp != "" && rt != "" && musicPathWithin(rt, rp) {
				return "", "into-itself"
			}
		}
		for i := 1; i <= filesKeepMax; i++ {
			t := filepath.Join(to, name)
			if i > 1 {
				t = filepath.Join(to, filesNumbered(name, i, filesNameMax))
			}
			fi, err := os.Lstat(t)
			if err == nil {
				if mode == "replace" && !fi.IsDir() && !st.dir {
					if err := os.Rename(p, t); err != nil {
						return "", filesWriteErr(err)
					}
					return t, ""
				}
				if mode != "keep" {
					return "", "exists"
				}
				continue
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return "", filesWriteErr(err)
			}
			if err := os.Rename(p, t); err != nil {
				return "", filesWriteErr(err)
			}
			return t, ""
		}
		return "", "exists"
	}, nil)
}

func filesToTrash(rawPath string) string {
	p, code := musicPathArg(rawPath)
	if code != "" {
		return code
	}
	if filesTooBroad(p) {
		return "too-broad"
	}
	if _, code := filesLook(p, false); code != "" {
		return code
	}
	_, code = filesDo(filesDoWait, func() (struct{}, string) { return struct{}{}, filesTrash(p) }, nil)
	return code
}

// filesWriteCommand is the changes' half of runFilesCommand: ok false for an
// op that is not one of them.
func filesWriteCommand(op string, peer key.NodePublic, signer ed25519.PublicKey, a filesArgs) (any, string, bool) {
	switch op {
	case "put":
		b, code := filesPutStart(peer, signer, a.Dir, a.Name, a.Size, a.K, a.Mode, a.Was)
		return b, code, true
	case "done":
		b, code := filesPutDone(peer, a.T, a.M, a.Mode)
		return b, code, true
	case "cancel":
		// By its token; or, with none, by the folder and key of a part no
		// upload holds any more.
		if a.T == "" {
			return map[string]any{}, filesPutDiscard(a.Dir, a.K), true
		}
		return map[string]any{}, filesPutCancel(peer, a.T), true
	case "mkdir":
		p, code := filesMkdir(a.Dir, a.Name)
		return map[string]string{"path": p}, code, true
	case "rename":
		p, code := filesRename(a.Path, a.Name)
		return map[string]string{"path": p}, code, true
	case "move":
		p, code := filesMove(a.Path, a.To, a.Mode)
		return map[string]string{"path": p}, code, true
	case "trash":
		return map[string]bool{"ok": true}, filesToTrash(a.Path), true
	}
	return nil, "", false
}
