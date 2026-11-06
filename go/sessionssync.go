package main

// Pushing this machine's coding-agent sessions to the account's archive —
// `subnsub-helper sessions sync`.
//
// sessions.go and sessionsread.go answer QUESTIONS: the dashboard asks over the
// console channel, this machine reads its own transcripts, and an answer comes
// back. That shape has one thing it cannot do — a machine that is asleep,
// decommissioned or on a plane answers nothing, and a fleet search is only ever
// a search of whatever happens to be awake. The archive is the other half: the
// same transcripts, parsed and redacted here, sent up the connection this
// helper already holds, and kept centrally so the account can search and read
// them whether or not the machine that made them still exists.
//
// OFF UNLESS THE OPERATOR TURNED IT ON, AT THE MACHINE — the same rule and the
// same shape as the console's switch, and for a stronger reason. The console
// grant is "this box will run what you type"; this one is "this box's
// conversations leave it and are stored". Those are different decisions and
// they get different switches: neither implies the other, `sessions sync on`
// is the only thing that sets this one, and a helper with the file absent
// never reads a transcript for this purpose at all.
//
// WHAT LEAVES, EXACTLY. Not the transcript files. Each line is parsed the way
// the reader parses it — message text only, no tool plumbing, no ids, no
// base64 payloads — run through the same redaction every other sessions verb
// applies, capped per message, and emitted as one compact JSON object per
// message. What the archive holds is therefore a redacted transcript of the
// conversation and nothing else about the machine. It is still the
// conversation: anyone who can read the account's dashboard can read it, which
// is exactly what turning this on grants.
//
// INCREMENTAL, BY BYTES. Transcripts are append-only JSONL, so the state file
// remembers how far into each one this machine has read and every pass sends
// only what was appended since. A file whose head changed, or that shrank, is
// a different file wearing the same name (a rotation, a restore) and is read
// again from the start. The cursor advances only for lines that arrived
// COMPLETE — a transcript being written to right now ends in half a line, and
// consuming that half would lose the other one forever.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// Turning it on for one run without touching the filesystem — a container,
	// a test. Same precedence as the console's switch: the environment wins.
	syncEnvVar = "MON_SYNC"
	// The file whose EXISTENCE is the switch, and the file that remembers how
	// far each transcript has been read. Both live beside the console's switch,
	// in the directory --uninstall removes.
	syncFileName  = "sessions-sync"
	syncStateName = "sessions-sync.json"

	// How long between passes when there is nothing left to send, and the much
	// shorter wait when a pass stopped only because it hit its own batch cap.
	// The second is what makes a first-run backfill finish in minutes instead
	// of days without ever letting one pass run unbounded.
	syncIdleWait = 2 * time.Minute
	syncBusyWait = 15 * time.Second
	// Backoff when the relay refuses or cannot be reached. The push loop is
	// what reports this machine's health; this loop going quiet must never be
	// the reason that stops, so its failures are slept off, never escalated.
	syncErrorWait = 5 * time.Minute
	// A room that is full has nothing to say for a while. Asking every two
	// minutes would be a request per machine per two minutes, forever, for an
	// answer that cannot change quickly.
	syncQuotaWait = time.Hour

	// One pass's wall clock, and the most uploads it may make. Together they
	// bound both the time this loop can spend and the bandwidth it can take
	// while the operator is doing something else with the machine.
	syncPassBudget = 90 * time.Second
	syncMaxBatches = 24

	// One upload's payload. The relay stores the message lines verbatim as one
	// object, so this is also the archive's chunk size — big enough that a
	// backfill is not a request per page, small enough that a failed upload
	// re-sends little and that the relay's own body cap has room over it.
	syncBatchBytes = 160 << 10

	// Text kept per message, in runes. The console reader's 320 exists to fit
	// thirty messages in a 16 KiB frame; nothing here is squeezed into a frame,
	// so the archive keeps the message rather than a preview of it. A cap is
	// still needed — a pasted file is one "message" — and this one holds the
	// paragraph-scale exchanges the archive exists to search.
	syncMsgRunes = 4000

	// The longest single transcript line that will be parsed. Past it the line
	// is consumed (the cursor must move) and its text dropped: a megabyte of
	// base64 on one line is real, and is not a message anyone will search for.
	syncMaxLineBytes = 1 << 20

	// Files remembered in the state file, and how long an entry outlives the
	// file it describes. A machine that has been running for a year should not
	// carry cursors for transcripts deleted in March.
	syncStateMax = 6000
	syncStateTTL = 30 * 24 * time.Hour

	// Bytes fingerprinted on each side of a resume: the file's opening (which
	// says WHICH file this is) and the stretch ending at the cursor (which says
	// the content up to it is still the content that was read).
	syncTailBytes = 256
)

// How far one transcript has been archived, and what the archive already knows
// about it. Kept per file rather than per session id: the id is what the
// dashboard shows, the FILE is what has a byte cursor.
type syncFileState struct {
	UID   string `json:"uid"`             // this file's stable archive key
	Off   int64  `json:"off"`             // bytes consumed, all of them complete lines
	Line  int    `json:"line"`            // transcript lines consumed
	Seq   int    `json:"seq"`             // next chunk number
	Msgs  int    `json:"msgs"`            // messages sent so far
	Sig   string `json:"sig"`             // head fingerprint; a change means a new file
	Tail  string `json:"tail,omitempty"`  // fingerprint of the bytes ending AT the cursor
	Seen  int64  `json:"seen"`            // when this entry was last confirmed, unix seconds
	Title string `json:"title,omitempty"` // sent with every chunk so late-arriving
	Proj  string `json:"proj,omitempty"`  // metadata reaches the index too
	First string `json:"first,omitempty"` // first message timestamp seen
}

type syncState struct {
	V     int                       `json:"v"`
	Files map[string]*syncFileState `json:"files"`
}

func syncSwitchFile() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, syncFileName)
}

func syncStatePath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, syncStateName)
}

// May this machine send its transcripts to the account's archive?
//
// Read every time rather than cached, so `sessions sync off` stops a helper
// that is already running within one pass and without a restart. Every error
// is a no: there is no failure here that means "probably fine".
func syncEnabled() bool {
	if v := strings.TrimSpace(os.Getenv(syncEnvVar)); v != "" {
		return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
	}
	path := syncSwitchFile()
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// Turn it on or off, from the command line on the machine itself.
//
// Turning it OFF leaves the state file alone. The cursors describe what the
// ARCHIVE already holds, and the archive does not forget because this machine
// stopped talking to it; discarding them would mean a later `on` re-uploading
// every transcript from line one.
func setSync(on bool) error {
	dir := configDir()
	if dir == "" {
		return os.ErrNotExist
	}
	path := filepath.Join(dir, syncFileName)
	if !on {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// 0600, like the console's: the file's presence is a decision about where
	// this machine's conversations go, and not one another local user gets to
	// make on this operator's behalf.
	return os.WriteFile(path, []byte("on\n"), 0o600)
}

func loadSyncState() *syncState {
	st := &syncState{V: 1, Files: map[string]*syncFileState{}}
	path := syncStatePath()
	if path == "" {
		return st
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	var got syncState
	if json.Unmarshal(b, &got) != nil || got.Files == nil {
		// A corrupt state file re-archives everything, which the relay absorbs
		// as repeated chunk writes over the same keys. That is wasteful and
		// correct; refusing to run until somebody deletes a file is neither.
		return st
	}
	got.V = 1
	return &got
}

// Written whole, through a temporary file in the same directory, because a
// cursor file torn in half by a power cut is worse than one that is slightly
// behind: the second re-sends a chunk, the first is unparseable and re-sends
// everything.
func saveSyncState(st *syncState) error {
	path := syncStatePath()
	if path == "" {
		return os.ErrNotExist
	}
	syncPruneState(st)
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, syncStateName+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// Entries for transcripts this machine no longer has, and the ceiling that
// keeps the file bounded on a box that generates sessions faster than it
// deletes them. Oldest-seen goes first, because the newest cursors are the
// ones whose loss would re-send the most.
func syncPruneState(st *syncState) {
	if st.Files == nil {
		st.Files = map[string]*syncFileState{}
		return
	}
	cut := time.Now().Add(-syncStateTTL).Unix()
	for k, v := range st.Files {
		if v == nil || v.Seen < cut {
			delete(st.Files, k)
		}
	}
	if len(st.Files) <= syncStateMax {
		return
	}
	keys := make([]string, 0, len(st.Files))
	for k := range st.Files {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := st.Files[keys[i]], st.Files[keys[j]]
		if a.Seen != b.Seen {
			return a.Seen < b.Seen
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[:len(keys)-syncStateMax] {
		delete(st.Files, k)
	}
}

// The archive's key for one transcript file.
//
// The session id alone is what the dashboard shows and is NOT enough to key
// by: two tools can produce the same stem, and a hand-copied transcript can
// duplicate one within a tool. The path decides identity, the id decides what
// is displayed, and the eight hex digits are what keeps two files that agree
// on the second from overwriting each other's chunks.
func syncUID(src sessSource, rel string) string {
	sum := sha256.Sum256([]byte(src.agent + "\x00" + rel))
	return syncSID(src, rel) + "-" + hex.EncodeToString(sum[:4])
}

// The displayed session id, in a shape the relay will accept. A transcript can
// be named anything a person can type — `notes 1.jsonl` is a real file — and
// sending the raw stem would have the relay refuse the batch as malformed,
// which the helper reads as "unstorable" and skips past forever. Both the key
// and the label go through here, so they can never disagree about which file
// this is.
func syncSID(src sessSource, rel string) string {
	id := sessIDFromName(src, rel)
	if !sessValidID(id) {
		return "session"
	}
	return id
}

// The head fingerprint that tells "this file grew" from "this is a different
// file at the same path". Cheap enough to take on every pass, and the only
// thing standing between a rotated transcript and a cursor that silently
// points into the middle of somebody else's conversation.
//
// The FIRST LINE, not the first 512 bytes, and the difference is the whole
// correctness of the resume: a transcript five appends old is shorter than 512
// bytes, so a fixed-width prefix hash changes every time the file grows and
// every pass would re-send the file from line one. A transcript's opening line
// is written once and never rewritten — it is the session's own header — so it
// is both stable under appending and specific enough that a different
// conversation at the same path fails the comparison. (A first line longer than
// the window hashes the window instead, which is stable for the same reason.)
func syncSig(f *os.File) (string, error) {
	head := make([]byte, 512)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return "", err
	}
	head = head[:n]
	if nl := bytes.IndexByte(head, '\n'); nl >= 0 {
		head = head[:nl+1]
	}
	sum := sha256.Sum256(head)
	return hex.EncodeToString(sum[:8]), nil
}

// And the fingerprint of the bytes ending exactly AT the cursor, which is what
// catches the case the head cannot: a transcript truncated and written past its
// old length again, under the same first line. The head still matches, the size
// is no longer smaller, and without this the cursor would resume in the middle
// of a conversation it never read the beginning of.
//
// Read through ReadAt so it does not disturb the sequential read that follows.
func syncTailSig(f *os.File, off int64) (string, error) {
	if off <= 0 {
		return "", nil
	}
	n := int64(syncTailBytes)
	if off < n {
		n = off
	}
	buf := make([]byte, n)
	// A SHORT read is a failure here, not an EOF to shrug at: the window ends at
	// a byte the cursor says was already consumed, so anything less than all of
	// it means the file shrank underneath us — and hashing the zero bytes that
	// were never filled would answer a question nobody asked.
	got, err := f.ReadAt(buf, off-n)
	if err != nil && err != io.EOF {
		return "", err
	}
	if int64(got) != n {
		return "", io.ErrUnexpectedEOF
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8]), nil
}

// One line of a transcript, read without ever holding more than max bytes of
// it. complete is false for a trailing fragment — a file being appended to
// right now — and the caller must neither parse nor consume it.
//
// Written against bufio.Reader's ReadSlice rather than a Scanner because both
// of the Scanner's answers to an over-long line are wrong here: growing without
// bound lets one pasted binary decide this process's memory, and erroring out
// abandons the file forever at a line the cursor can never get past.
func syncReadLine(br *bufio.Reader, max int) (line []byte, n int64, complete bool, err error) {
	var buf []byte
	for {
		part, e := br.ReadSlice('\n')
		n += int64(len(part))
		if len(buf) < max {
			room := max - len(buf)
			if room > len(part) {
				room = len(part)
			}
			buf = append(buf, part[:room]...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			// EOF with bytes in hand is the fragment case: real data, not yet
			// terminated, and not this pass's business.
			return nil, n, false, syncEOF(e)
		}
		return bytes.TrimRight(buf, "\r\n"), n, true, nil
	}
}

// io.EOF is the ordinary end of a pass, not a failure.
func syncEOF(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

// One upload's worth of one transcript: the metadata line the relay indexes by,
// followed by one compact JSON object per message.
type syncBatch struct {
	key   string
	state *syncFileState
	body  []byte
	// What the cursor becomes if — and only if — the relay stores this.
	off  int64
	line int
	msgs int
	// The document's own edges, for the index row.
	firstLine int
	lastLine  int
	firstTS   string
	lastTS    string
	final     bool   // nothing left in this file after this batch
	tail      string // the file's fingerprint AT off, for the next resume
}

// The compact per-message record. Short keys because the archive stores
// millions of these and every byte is a byte somebody's account pays for; the
// meanings are exactly the reader's sessMsg, so a page served from the archive
// and a page read live are the same shape by the time either reaches a screen.
type syncMsgRec struct {
	N int    `json:"n"`
	R string `json:"r,omitempty"`
	T string `json:"t,omitempty"`
	X string `json:"x"`
	C bool   `json:"c,omitempty"`
}

// The same job for a transcript that is ONE json document rather than one
// message per line — Amp's threads, and anything else that grows by rewriting
// a whole file.
//
// Everything the archive needs is here; only how the cursor works differs, and
// it differs because a document HAS no byte offsets to resume from. Its
// messages are a list that gets longer, so the cursor is an INDEX into that
// list, and three fields change meaning for these files and these only:
//
//	Sig   the document's own identity, not a fingerprint of its opening bytes.
//	      Amp writes a revision counter into its second line, so the head
//	      changes on every single write and a head fingerprint would report a
//	      different conversation every time.
//	Off   the file's SIZE at the last complete read, which is what makes the
//	      cheap "nothing new" test still work — and deliberately 0 while
//	      messages remain, because a size that already matches would short out
//	      the very pass that was going to send them.
//	Tail  unused. There is no stretch of bytes ending at the cursor to sign.
//
// The document is read whole, which is what makes a size cap load-bearing
// rather than tidy — see sessMaxDocBytes.
func syncScanDoc(file *os.File, st os.FileInfo, src sessSource, f sessFile, fs *syncFileState, deadline time.Time) (b *syncBatch, more bool, trouble bool) {
	if st.Size() == fs.Off && fs.Off > 0 {
		return nil, false, false
	}
	raw, err := io.ReadAll(io.LimitReader(file, sessMaxDocBytes+1))
	if err != nil || len(raw) > sessMaxDocBytes {
		return nil, false, true
	}
	doc, ok := src.doc(raw)
	if !ok {
		return nil, false, true
	}
	sig := "doc:" + doc.Ident
	// A different conversation at the same path, or one that lost messages: in
	// both cases what was uploaded describes something this file no longer is,
	// and the archive starts a fresh series rather than appending to it.
	if fs.Sig != sig || len(doc.Msgs) < fs.Line {
		fs.Off, fs.Line, fs.Seq, fs.Msgs = 0, 0, 0, 0
		fs.First, fs.Tail, fs.Title, fs.Proj = "", "", "", ""
		fs.Sig = sig
	}
	if fs.Proj == "" && doc.Cwd != "" {
		fs.Proj = sessProjectLabel(doc.Cwd)
	}
	if fs.Line >= len(doc.Msgs) {
		// Nothing new, but the size moved — record it so the cheap test can
		// short-circuit next time.
		fs.Off = st.Size()
		return nil, false, false
	}

	var out bytes.Buffer
	batch := &syncBatch{key: syncKey(src.agent, f.rel), state: fs, line: fs.Line, msgs: 0}
	for i := fs.Line; i < len(doc.Msgs); i++ {
		if out.Len() >= syncBatchBytes || time.Now().After(deadline) {
			more = true
			break
		}
		batch.line++
		// The 1-based position in the document, which is the coordinate search
		// hits and `open` already use for these files.
		m, _, okMsg := sessParseMsgCap(doc.Msgs[i], i+1, syncMsgRunes)
		if !okMsg {
			continue
		}
		syncAddMsg(&out, batch, fs, m)
	}
	// Only a finished read may record the size. Left set while messages remain,
	// the test at the top would refuse to come back for them.
	if !more {
		batch.off = st.Size()
	}
	if fs.First == "" && batch.firstTS != "" {
		fs.First = batch.firstTS
	}
	if out.Len() == 0 {
		// Messages were consumed and none of them carried text. The cursor still
		// has to move or the next pass reads them again forever.
		fs.Off = batch.off
		fs.Line = batch.line
		return nil, more, trouble
	}
	batch.final = !more
	batch.body = syncEnvelope(src, f, fs, batch, st, out.Bytes())
	return batch, more, trouble
}

// One parsed message onto a batch: the record itself, the edges the index row
// needs, and the title decided once per file. Shared by the two scanners below
// so a document-shaped transcript and a line-shaped one produce byte-identical
// records for the same message.
func syncAddMsg(out *bytes.Buffer, batch *syncBatch, fs *syncFileState, m sessMsg) {
	rec := syncMsgRec{N: m.Line, R: m.Role, T: m.Time, X: m.Text, C: m.Cut}
	enc, err := json.Marshal(rec)
	if err != nil {
		return
	}
	out.Write(enc)
	out.WriteByte('\n')
	batch.msgs++
	if batch.firstLine == 0 {
		batch.firstLine = m.Line
	}
	batch.lastLine = m.Line
	if m.Time != "" {
		if batch.firstTS == "" {
			batch.firstTS = m.Time
		}
		batch.lastTS = m.Time
	}
	// The title is the first thing the user typed, decided once per file and
	// then carried on every chunk so the index row can be written by whichever
	// chunk arrives — including a chunk that holds none of the transcript's
	// opening.
	if fs.Title == "" && m.Role == "user" {
		// Unwrapped exactly as the live listing unwraps it, or the archive
		// would show a column of `<timestamp>` where the machine itself
		// shows what somebody typed.
		t := sessTitleUnwrap(strings.TrimSpace(m.Text))
		if t != "" && !sessTitlePrelude(t) {
			fs.Title = sessTitleClip(t)
		}
	}
}

// Read one file forward from its cursor and build at most one batch.
//
// Returns nil when the file has nothing new to send. `more` says the file still
// holds data past this batch, which is what turns a backfill into a series of
// short passes instead of one long one.
func syncScanFile(root *os.Root, src sessSource, f sessFile, fs *syncFileState, deadline time.Time) (b *syncBatch, more bool, trouble bool) {
	if root == nil {
		return nil, false, true
	}
	file, err := root.Open(f.rel)
	if err != nil {
		return nil, false, true
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, false, true
	}
	// The same hard-link refusal every other sessions verb makes: a transcript
	// with a second name is one somebody else can point at something of their
	// choosing, and this path uploads what it reads.
	if n, known := openLinkCount(file, st); !known || n != 1 {
		return nil, false, true
	}
	if src.doc != nil {
		return syncScanDoc(file, st, src, f, fs, deadline)
	}
	sig, err := syncSig(file)
	if err != nil {
		return nil, false, true
	}
	// Three ways to learn that the file under the cursor is not the file the
	// cursor describes: it shrank, its opening line changed, or the bytes
	// ending AT the cursor are no longer the bytes that were read. The third is
	// the one that catches a truncate-and-regrow past the old length under an
	// unchanged first line, which the other two both miss. A state written before this field existed has no tail to
	// compare and is trusted once, which is the same trust it already had.
	// Ordered so the cheap, certain answers come first: a file that SHRANK is
	// already known to be a different file, and asking for a fingerprint of
	// bytes that are no longer there would only report an unreadable file. Past those two, a short read really does
	// mean the file is being truncated underneath this pass, and the honest
	// answer is to come back rather than to guess.
	replaced := fs.Sig != sig || st.Size() < fs.Off
	if !replaced && fs.Off > 0 && fs.Tail != "" {
		tail, terr := syncTailSig(file, fs.Off)
		if terr != nil {
			return nil, false, true
		}
		replaced = tail != fs.Tail
	}
	if replaced {
		fs.Sig = sig
		fs.Off = 0
		fs.Line = 0
		fs.Seq = 0
		fs.Msgs = 0
		fs.First = ""
		fs.Tail = ""
		// The metadata belongs to the conversation that WAS here. Carried over,
		// the new series would wear the old one's title and project for as long
		// as it lived, because both are only ever filled when empty.
		fs.Title = ""
		fs.Proj = ""
	}
	// Where this session ran, for the tools that record it beside the transcript
	// rather than on a line inside it. Asked BEFORE the nothing-new exit, so a
	// file that is already fully read still learns its project — otherwise a
	// transcript archived once and never appended to again would carry no
	// project forever, and the archive's `project:` filter would disagree with
	// the live search about sessions it can see and the machine cannot (review
	// 2026-08-19). The tools that stamp it on a line are picked up in the loop.
	if src.cwd != nil && fs.Proj == "" {
		if c := src.cwd(root, f.rel); c != "" {
			fs.Proj = sessProjectLabel(c)
		}
	}
	if st.Size() == fs.Off {
		return nil, false, false
	}
	if _, err := file.Seek(fs.Off, io.SeekStart); err != nil {
		return nil, false, true
	}

	var out bytes.Buffer
	br := bufio.NewReaderSize(file, 64<<10)
	batch := &syncBatch{
		key:   syncKey(src.agent, f.rel),
		state: fs,
		off:   fs.Off,
		line:  fs.Line,
		// Zero, not the running total: this counts what THIS chunk carries, and
		// the relay sums the chunk table. Seeded from the state it would count
		// every earlier chunk again in every later one.
		msgs: 0,
	}
	cwd := ""
	for {
		if out.Len() >= syncBatchBytes {
			more = true
			break
		}
		if time.Now().After(deadline) {
			more = true
			break
		}
		line, n, complete, err := syncReadLine(br, syncMaxLineBytes)
		if err != nil {
			trouble = true
			break
		}
		if !complete {
			// Either the end of the file or a half-written tail. Both mean
			// "come back later", and neither may move the cursor.
			break
		}
		batch.off += n
		batch.line++
		m, lineCwd, ok := sessParseMsgCap(line, batch.line, syncMsgRunes)
		if lineCwd != "" && cwd == "" {
			cwd = lineCwd
		}
		if !ok {
			continue
		}
		syncAddMsg(&out, batch, fs, m)
	}
	if cwd != "" && fs.Proj == "" {
		fs.Proj = sessProjectLabel(cwd)
	}
	if fs.First == "" && batch.firstTS != "" {
		fs.First = batch.firstTS
	}
	// The fingerprint of the file as it will stand at the NEW cursor, which is
	// what the next pass compares against before trusting it.
	tailAt, tailErr := syncTailSig(file, batch.off)
	if tailErr != nil {
		trouble = true
	}
	batch.tail = tailAt
	if out.Len() == 0 {
		// Lines were consumed but none of them were messages — a chunk of pure
		// plumbing. The cursor still has to move or the next pass reads them
		// again forever, so a batch with no body is reported as a cursor
		// advance and nothing else.
		if batch.off != fs.Off {
			fs.Off = batch.off
			fs.Line = batch.line
			fs.Tail = tailAt
		}
		return nil, more, trouble
	}
	batch.final = !more
	batch.body = syncEnvelope(src, f, fs, batch, st, out.Bytes())
	return batch, more, trouble
}

// The state-file key for one transcript. The tool's name is part of it because
// two tools' trees are walked separately and a relative path is only unique
// inside one of them.
func syncKey(agent, rel string) string {
	return agent + "/" + filepath.ToSlash(rel)
}

// The uploaded document: one metadata line, then the message lines already
// built. The relay parses only the first line and stores the rest verbatim, so
// nothing here is escaped twice and the archive holds exactly the NDJSON this
// machine produced.
func syncEnvelope(src sessSource, f sessFile, fs *syncFileState, b *syncBatch, st os.FileInfo, msgs []byte) []byte {
	meta := map[string]any{
		"v":          1,
		"agent":      agentID(),
		"tool":       src.agent,
		"uid":        fs.UID,
		"sid":        syncSID(src, f.rel),
		"seq":        fs.Seq,
		"first_line": b.firstLine,
		"last_line":  b.lastLine,
		"msgs":       b.msgs,
		"total_msgs": b.msgs + fs.Msgs,
		"lines":      b.line,
		"final":      b.final,
		"mtime":      st.ModTime().UTC().Format(time.RFC3339),
	}
	if fs.Title != "" {
		meta["title"] = fs.Title
	}
	if fs.Proj != "" {
		meta["project"] = fs.Proj
	}
	if fs.First != "" {
		meta["first_ts"] = fs.First
	}
	if b.lastTS != "" {
		meta["last_ts"] = b.lastTS
	}
	head, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, len(head)+1+len(msgs))
	out = append(out, head...)
	out = append(out, '\n')
	out = append(out, msgs...)
	return out
}

// What the relay said about one batch.
type syncVerdict int

const (
	syncStored syncVerdict = iota
	syncRetry              // transient: the same batch is worth sending again
	syncSkip               // the relay will never take this batch; move past it
	syncFull               // the account's archive is full
	syncDenied             // this room may not archive at all
)

func syncPost(client *http.Client, base, token string, body []byte) syncVerdict {
	url := strings.TrimRight(base, "/") + "/sync"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return syncSkip
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "subnsub-helper")
	resp, err := client.Do(req)
	if err != nil {
		return syncRetry
	}
	defer func() {
		io.CopyN(io.Discard, resp.Body, 4<<10)
		resp.Body.Close()
	}()
	switch {
	case resp.StatusCode == 200:
		return syncStored
	case resp.StatusCode == 507:
		return syncFull
	case resp.StatusCode == 403 || resp.StatusCode == 402:
		return syncDenied
	case resp.StatusCode == 404 || resp.StatusCode == 501:
		// A relay too old to have an archive. Not an error on this machine,
		// and not something a retry fixes.
		return syncDenied
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		return syncRetry
	case resp.StatusCode >= 400:
		// The relay has looked at this batch and will not take it. Sending it
		// again forever would wedge the file behind one unstorable chunk, so
		// the cursor moves past it and the loss is stated in this machine's own
		// log rather than hidden.
		return syncSkip
	}
	return syncRetry
}

// One pass over every transcript this machine has: newest first, so a fleet
// that has just been switched on has its most useful sessions archived first
// rather than its oldest.
//
// Returns how long to wait before the next one.
func syncPass(client *http.Client, base string, tok *tokenBox) time.Duration {
	token := tok.get()
	if token == "" {
		return syncErrorWait
	}
	deadline := time.Now().Add(syncPassBudget)
	state := loadSyncState()
	sources := sessSources()
	roots, files, _ := sessAllCandidates(sources, deadline)
	defer sessCloseRoots(roots)

	now := time.Now().Unix()
	sent := 0
	pending := false
	dirty := false
	wait := syncIdleWait
	for _, f := range files {
		if sent >= syncMaxBatches {
			pending = true
			break
		}
		if time.Now().After(deadline) {
			pending = true
			break
		}
		key := syncKey(sources[f.src].agent, f.rel)
		fs := state.Files[key]
		if fs == nil {
			fs = &syncFileState{UID: syncUID(sources[f.src], f.rel)}
			state.Files[key] = fs
		}
		if fs.UID == "" {
			fs.UID = syncUID(sources[f.src], f.rel)
		}
		fs.Seen = now
		dirty = true
		// NO STAT-ONLY SHORTCUT. Skipping a file whose mtime and
		// size still matched what it had consumed is fast and is not a
		// proof: a restore, an in-place rewrite, or a copy that preserves
		// metadata can leave both unchanged over different content, before
		// any of the identity checks that would catch it. syncScanFile opens the file,
		// verifies its opening line and the bytes at the cursor, and returns
		// immediately when there is nothing new — an open and two small reads
		// per transcript per pass, which is not the expensive part of anything.
		batch, more, _ := syncScanFile(roots[f.src], sources[f.src], f, fs, deadline)
		if more {
			pending = true
		}
		if batch == nil {
			continue
		}
		// The switch is re-read here as well as at the top of the pass. It is
		// the one switch on this machine that decides whether a conversation
		// leaves it, so `sessions sync off` stops uploading within the batch.
		if !syncEnabled() {
			saveSyncState(state)
			return syncIdleWait
		}
		sent++
		switch syncPost(client, base, token, batch.body) {
		case syncStored:
			fs.Off = batch.off
			fs.Line = batch.line
			fs.Msgs += batch.msgs
			fs.Seq++
			// ALWAYS, including the empty string. Tail describes the file at
			// Off, so carrying an older one forward past a cursor that moved
			// would fail its own comparison next pass and re-send the whole
			// transcript; empty means "unknown, trust once", which is the
			// right thing to record when it could not be taken.
			fs.Tail = batch.tail
		case syncSkip:
			warnf("archive refused a chunk of %s; skipping it", batch.state.UID)
			fs.Off = batch.off
			fs.Line = batch.line
			fs.Seq++
			fs.Tail = batch.tail
		case syncFull:
			saveSyncState(state)
			warnf("archive is full for this account; pausing")
			return syncQuotaWait
		case syncDenied:
			saveSyncState(state)
			return syncQuotaWait
		default: // syncRetry — leave the cursor where it was
			saveSyncState(state)
			return syncErrorWait
		}
	}
	if dirty {
		saveSyncState(state)
	}
	if pending {
		wait = syncBusyWait
	}
	return wait
}

// Push transcripts to the archive, forever, beside the push and console loops.
//
// Checked on every pass rather than at startup: `sessions sync off` has to
// reach a helper that is already running, and it is the OFF direction that
// must be the fast one.
func syncLoop(base string, tok *tokenBox) {
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: relayTransport(),
		// Same refusal the push and update paths make: the relay token is a
		// bearer secret, and Go's client keeps Authorization across a redirect
		// to the same host without checking that the scheme survived it.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for {
		wait := syncIdleWait
		if syncEnabled() {
			wait = syncPass(client, base, tok)
		}
		time.Sleep(wait)
	}
}

// ── CLI ──────────────────────────────────────────────────────────────

// `sessions sync [on|off] [--dry-run] [--json]`.
//
// With no argument it reports the switch and what the cursors say has been
// archived — the question an operator actually has ("is this thing on, and is
// it done yet?"). --dry-run walks the transcripts and reports what the next
// pass WOULD send without opening a connection to anything, which is how to
// see the size of a backfill before turning it on.
func runSessionsSyncCLI(rest []string) int {
	dry := false
	asJSON := false
	set := ""
	for _, a := range rest {
		switch a {
		case "--dry-run":
			dry = true
		case "--json":
			asJSON = true
		case "on", "1", "true", "yes":
			set = "on"
		case "off", "0", "false", "no":
			set = "off"
		default:
			warnf("usage: subnsub-helper sessions sync [on|off] [--dry-run] [--json]")
			return 2
		}
	}
	if set != "" {
		if err := setSync(set == "on"); err != nil {
			warnf("could not change the archive setting")
			return 1
		}
	}
	on := syncEnabled()
	state := loadSyncState()
	files, msgs, bytesDone := 0, 0, int64(0)
	for _, v := range state.Files {
		if v == nil {
			continue
		}
		files++
		msgs += v.Msgs
		bytesDone += v.Off
	}
	pendingFiles, pendingBytes := 0, int64(0)
	if dry {
		pendingFiles, pendingBytes = syncPendingEstimate(state)
	}
	if asJSON {
		out := map[string]any{
			"on":         on,
			"files":      files,
			"messages":   msgs,
			"bytes_read": bytesDone,
			"agent":      agentID(),
		}
		if dry {
			out["pending_files"] = pendingFiles
			out["pending_bytes"] = pendingBytes
		}
		b, err := json.Marshal(out)
		if err != nil {
			warnf("could not encode the answer")
			return 1
		}
		fmt.Println(string(b))
		return 0
	}
	if on {
		fmt.Printf("on   (%s)\n", agentID())
	} else {
		fmt.Printf("off  (%s)\n", agentID())
	}
	fmt.Printf("archived: %d transcripts, %d messages, %s read\n", files, msgs, syncHuman(bytesDone))
	if dry {
		fmt.Printf("pending:  %d transcripts, %s to send\n", pendingFiles, syncHuman(pendingBytes))
	}
	if !on {
		fmt.Println("\nturn it on with:  subnsub-helper sessions sync on")
		fmt.Println("with it on, this machine's agent conversations are parsed, redacted and")
		fmt.Println("sent to your account's archive, where the dashboard can search and read")
		fmt.Println("them even when this machine is offline. off is the default and off stays off.")
	}
	return 0
}

// What a pass would have to send, without sending any of it. Reads no
// transcript body — the walk's own stat is enough to know how much of each file
// is past its cursor.
func syncPendingEstimate(state *syncState) (files int, bytes int64) {
	sources := sessSources()
	roots, cands, _ := sessAllCandidates(sources, time.Now().Add(sessBudget))
	defer sessCloseRoots(roots)
	for _, f := range cands {
		key := syncKey(sources[f.src].agent, f.rel)
		off := int64(0)
		if fs := state.Files[key]; fs != nil {
			off = fs.Off
		}
		root := roots[f.src]
		if root == nil {
			continue
		}
		fh, err := root.Open(f.rel)
		if err != nil {
			continue
		}
		st, err := fh.Stat()
		fh.Close()
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if st.Size() > off {
			files++
			bytes += st.Size() - off
		}
	}
	return files, bytes
}

func syncHuman(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
