package main

// Searching THIS machine's coding-agent sessions, when the dashboard's fleet
// search asks over the console channel — `subnsub-helper sessions search`.
//
// A machine that granted the console has already granted arbitrary /bin/sh as
// this user, so the fleet search rides that one channel and nothing more
// sensitive is exposed by it. What leaves the machine is the snippets this
// prints — never a transcript.
//
// This file answers the question by READING THE TRANSCRIPTS WHERE THEY
// ALREADY ARE. No index is built, no daemon starts, nothing is downloaded,
// no file is written, and the only network anywhere near this path is the
// console channel that carried the question in.
//
// The shape of the answer is a JSON
// object with a `matches` list of {project, agent, timestamp, session_id,
// snippet}.
//
// Reading discipline is codex.go's, because the trees are the same kind of
// place: every open goes through os.Root so a symlinked component cannot walk
// the read out of the agent's own directory, and a file with more than one
// hard link is refused rather than read — a genuine second name inside the
// tree can point at somebody else's inode. Secrets that appear in matched
// text are best-effort redacted from the snippet before it is printed; the
// transcript itself is not touched.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// How many hits a search returns when the caller does not say. The
	// dashboard asks for 12 — about 3 KB of a 16 KB console pipe — and the cap
	// exists so a caller cannot ask this process to serialise its whole
	// history into one console frame.
	sessDefaultLimit = 12
	sessMaxLimit     = 50

	// Hits kept per session, newest last. One chatty session must not spend
	// the whole limit before the file after it is even opened.
	sessPerSession = 3

	// The whole search runs inside this. The console gives a command 30
	// seconds; stopping well short of that turns "the channel killed it and
	// reported nothing" into "an answer came back marked partial", which is
	// the difference between a timeout and a result.
	sessBudget = 15 * time.Second

	// The longest transcript line the scanner will hold. Lines beyond it are
	// real — a pasted image becomes megabytes of base64 on one line — but a
	// line this large is not something a snippet can usefully quote, and the
	// file it aborts is reported as partial rather than silently complete.
	sessMaxLineBytes = 8 << 20

	// Snippet length, in runes — what one hit contributes to the 16 KB pipe.
	sessSnippetRunes = 200

	// The answer's ceiling, measured as sessFrameCost measures it: the size
	// of the document AFTER console.go has escaped it into the result
	// frame's one JSON string. Runes are not bytes, and marshalled bytes are
	// not frame bytes either — every quote and backslash in the document
	// doubles again inside the frame, and consoleReport halves anything
	// whose frame runs past 20 KiB, mid-JSON and unreadable (review
	// 2026-08-18). 15 KiB of frame cost leaves the envelope its room. A
	// document over this sheds until it fits, marked, rather than letting
	// the channel cut it into something the dashboard cannot read at all.
	sessMaxJSONBytes = 15 << 10

	// How deep sessCollectText follows nested structure before deciding the
	// line is not a transcript message. Real messages sit three or four
	// levels down; forty levels is a crafted file, not a conversation.
	sessMaxDepth = 12
)

// The sources themselves — which tools are read, and the per-tool hooks the
// readers below take as given — live in sessionsources.go.

// One hit, in exactly the field names the dashboard renders. `agent` is the
// tool, `project` the working directory's base name when the transcript
// recorded one, `session_id` something short enough to show and stable enough
// to look up by hand. `line` is the 1-based transcript line the hit lives on
// — the anchor `sessions open --around` accepts, which is what turns a
// snippet into a place the dashboard can go back to.
type sessHit struct {
	Project   string `json:"project"`
	Agent     string `json:"agent"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id"`
	Snippet   string `json:"snippet"`
	Line      int    `json:"line,omitempty"`
}

// The whole answer. Matches is initialised, never nil: the far end asks
// Array.isArray, and `"matches":null` would read as the tool having failed
// rather than having found nothing.
type sessReport struct {
	Matches []sessHit `json:"matches"`
	Files   int       `json:"files"`
	Scanned int       `json:"scanned"`
	Ms      int64     `json:"ms"`
	Partial bool      `json:"partial,omitempty"`
}

// What a search was asked to do. A hit is a single transcript message whose
// extracted text holds every one of `terms` and matches every one of `res`,
// and holds none of `nots` and matches none of `nres`. Terms arrive lowercased
// and non-empty — a term may contain spaces, which is what a quoted phrase
// becomes, and is the whole difference between searching for two words and
// searching for two words in that order.
//
// The negative halves are why matching lives on this type rather than in the
// scan loop: `recent` narrows the same way, the archive answers the same
// query, and three copies of "…and none of these" would be three chances to
// disagree about what a query means.
//
// The deadline is absolute so tests can put it in the past.
type sessQuery struct {
	terms []string
	nots  []string
	res   []*regexp.Regexp
	nres  []*regexp.Regexp
	// What the answer is narrowed to. The zero value means "everything", so a
	// caller that does not filter says nothing about it.
	filter   sessFilter
	limit    int
	deadline time.Time
}

// Whether one message's text answers the whole query.
func (q sessQuery) match(text string) bool {
	for _, t := range q.terms {
		if sessIndexFold(text, t) < 0 {
			return false
		}
	}
	for _, t := range q.nots {
		if sessIndexFold(text, t) >= 0 {
			return false
		}
	}
	for _, re := range q.res {
		if !re.MatchString(text) {
			return false
		}
	}
	for _, re := range q.nres {
		if re.MatchString(text) {
			return false
		}
	}
	return true
}

// Whether this query can match anything at all. A query of nothing but
// exclusions would match every message ever written, which is not a search
// anybody meant to run.
func (q sessQuery) empty() bool {
	return len(q.terms) == 0 && len(q.res) == 0
}

// The text a snippet should be cut around: the first term, or — for a query
// made only of patterns — whatever the first pattern actually matched here, so
// a regex hit is shown at the place it hit rather than from the top of a long
// message.
func (q sessQuery) anchor(text string) string {
	if len(q.terms) > 0 {
		return q.terms[0]
	}
	for _, re := range q.res {
		if m := re.FindString(text); m != "" {
			return sessLowerASCII(m)
		}
	}
	return ""
}

// The first positive term, for the callers that want one without a message in
// hand. Empty for a pattern-only query.
func (q sessQuery) first() string {
	if len(q.terms) > 0 {
		return q.terms[0]
	}
	return ""
}

// The longest a search pattern may be, in CODE POINTS. A pattern is
// caller-shaped and runs against every message of every candidate transcript;
// RE2 makes that linear rather than catastrophic, but there is still no
// question a longer pattern could ask that a shorter one could not.
//
// Counted in code points rather than bytes because the panel and the relay
// count that way too, and a limit that means three different lengths would
// accept a hundred Chinese characters in the browser and report this helper as
// too old to run it.
const sessMaxPattern = 200

// One search pattern, compiled the way both ends of this feature agree to read
// one: case-insensitive, because every other kind of term here is, and RE2's
// dialect, which has no backreferences and no lookaround — the panel refuses
// those up front so that a query means the same thing whichever source answers
// it.
func sessCompile(pat string) (*regexp.Regexp, error) {
	if pat == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	if utf8.RuneCountInString(pat) > sessMaxPattern {
		return nil, fmt.Errorf("pattern longer than %d characters", sessMaxPattern)
	}
	return regexp.Compile("(?i)" + pat)
}

// When one message was written, in RFC3339, or "" when the transcript does
// not say. Three spellings, because the tools genuinely disagree: a top-level
// `timestamp` string (claude, codex), unix MILLISECONDS under the message's
// own meta (amp), unix SECONDS under a nested one (kiro).
//
// Without this every hit in a session shares the FILE's mtime, which for a
// thread spanning months puts every message in it at the same minute — the one
// the conversation last moved (2026-08-19). The tools that record nothing at
// all still fall back to mtime, which is the honest answer there.
func sessMsgTime(raw map[string]any) string {
	if ts, ok := raw["timestamp"].(string); ok {
		if _, err := time.Parse(time.RFC3339, ts); err == nil {
			return ts
		}
	}
	if meta, ok := raw["meta"].(map[string]any); ok {
		if ms, ok := meta["sentAt"].(float64); ok {
			return sessEpoch(ms / 1000)
		}
	}
	if data, ok := raw["data"].(map[string]any); ok {
		if meta, ok := data["meta"].(map[string]any); ok {
			if s, ok := meta["timestamp"].(float64); ok {
				return sessEpoch(s)
			}
		}
	}
	return ""
}

// Unix seconds as an RFC3339 stamp, or "" for a number no clock produced.
// The window is deliberately wide and the point of it is narrow: a field that
// happens to be called `timestamp` and holds a sequence number must not become
// a date in 1970 that a listing then sorts by.
func sessEpoch(sec float64) string {
	if sec < 946684800 || sec > 4102444800 { // 2000-01-01 … 2100-01-01
		return ""
	}
	return time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
}

// Whether a parsed line is a tool's own system prompt rather than anything
// somebody said. Some tools keep theirs in the transcript, as one message of
// many kilobytes that mentions nearly every word a person might search for; a
// search that counted it would return every session that tool ever opened, for
// almost any query.
// The {kind, data} kinds that hold a tool's plumbing rather than anything
// said. Named rather than inferred: the format's whole point is that `kind`
// says what `data` is, so the honest reading is to believe it.
func sessPlumbingKind(kind string) bool {
	switch kind {
	case "toolUse", "toolResult":
		return true
	}
	return false
}

func sessIsSystem(m map[string]any) bool {
	if t, _ := m["type"].(string); t == "system" {
		return true
	}
	if k, _ := m["kind"].(string); k == "system" {
		return true
	}
	return false
}

// The CLI entry: `sessions search [--limit N] [--json] [--] TEXT...`.
// Exit code discipline is load-bearing for the dashboard: a search that RAN
// exits 0 whatever it found, including nothing, so the far end can read any
// non-zero exit as "this helper does not know how to search" (an older build
// prints its usage and exits 2) and say "update the helper" instead of
// guessing. Only a caller error — no query, an unknown flag — exits non-zero
// here, and the dashboard never sends one.
func runSessionsSearchCLI(rest []string) int {
	limit := sessDefaultLimit
	asJSON := false
	var filter sessFilter
	var q sessQuery
	now := time.Now()
	var parts []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		// Before the switch, so a filter flag is never mistaken for a term and
		// never reaches the unknown-flag refusal below.
		if handled, err := sessFilterFlag(&filter, rest, &i, now); handled {
			if err != nil {
				warnf("%v", err)
				return 2
			}
			continue
		}
		if handled, err := sessQueryFlag(&q, rest, &i); handled {
			if err != nil {
				warnf("%v", err)
				return 2
			}
			continue
		}
		switch {
		case a == "--":
			parts = append(parts, rest[i+1:]...)
			i = len(rest)
		case a == "--json":
			asJSON = true
		case a == "--limit":
			if i+1 >= len(rest) {
				warnf("--limit needs a number")
				return 2
			}
			i++
			n, err := parsePositive(rest[i])
			if err != nil {
				warnf("--limit needs a number, not %q", rest[i])
				return 2
			}
			limit = n
		case strings.HasPrefix(a, "--limit="):
			n, err := parsePositive(a[len("--limit="):])
			if err != nil {
				warnf("--limit needs a number, not %q", a[len("--limit="):])
				return 2
			}
			limit = n
		case strings.HasPrefix(a, "-") && a != "-":
			warnf("unknown flag %q", a)
			return 2
		default:
			parts = append(parts, a)
		}
	}
	// Words written plainly are terms, and they come after any --term so that a
	// query built from both keeps the flags' phrases first — which is what
	// decides the term a snippet is cut around.
	q.terms = append(q.terms, sessTerms(strings.Join(parts, " "))...)
	if q.empty() {
		warnf("usage: subnsub-helper sessions search [--limit N] [--project NAME] [--since WHEN] [--until WHEN]")
		warnf("       [--term TEXT] [--not TEXT] [--re PATTERN] [--not-re PATTERN] [--json] [--] TEXT...")
		warnf("a search needs something to look FOR: exclusions alone would match every message ever written")
		return 2
	}
	if limit < 1 {
		limit = 1
	}
	if limit > sessMaxLimit {
		limit = sessMaxLimit
	}
	q.filter = filter
	q.limit = limit
	q.deadline = now.Add(sessBudget)

	rep := sessionsSearch(sessSources(), q)

	if asJSON {
		out, err := sessEncodeCapped(&rep)
		if err != nil {
			// Nothing in the report can fail to marshal; saying so beats
			// printing half a document.
			warnf("could not encode the result: %v", err)
			return 2
		}
		fmt.Println(string(out))
		return 0
	}
	for _, h := range rep.Matches {
		when := h.Timestamp
		if len(when) >= 16 {
			when = strings.Replace(when[:16], "T", " ", 1)
		}
		id := h.SessionID
		if len(id) > 8 {
			id = id[:8]
		}
		line := []string{when, h.Agent}
		if h.Project != "" {
			line = append(line, h.Project)
		}
		line = append(line, id, h.Snippet)
		fmt.Println(strings.Join(line, "  "))
	}
	fmt.Printf("%d match(es) across %d file(s), %d scanned, %d ms%s", len(rep.Matches), rep.Files, rep.Scanned, rep.Ms, filter.describe())
	if rep.Partial {
		fmt.Print(" (partial — some files could not be fully searched)")
	}
	fmt.Println()
	return 0
}

// What this document will cost inside the console result frame, where it
// travels as ONE escaped JSON string. This — not len(doc) — is the number the
// far end's 20 KiB body cap judges: a
// transcript full of code doubles its quotes and backslashes again at that
// second encoding, and a document sized only by its own bytes would sail through
// here and come back halved.
func sessFrameCost(doc []byte) int {
	esc, err := json.Marshal(string(doc))
	if err != nil {
		return len(doc) * 2 // unreachable for valid UTF-8; fail conservative
	}
	return len(esc)
}

// The report as JSON, guaranteed to fit the channel. Hits leave from the end
// — the end is the oldest-file tail of the list, so what survives is what the
// ordering already ranked first — and any drop is declared in `partial`.
func sessEncodeCapped(rep *sessReport) ([]byte, error) {
	out, err := json.Marshal(rep)
	for err == nil && sessFrameCost(out) > sessMaxJSONBytes && len(rep.Matches) > 0 {
		rep.Matches = rep.Matches[:len(rep.Matches)-1]
		rep.Partial = true
		out, err = json.Marshal(rep)
	}
	return out, err
}

// A small positive integer out of a flag value. strconv.Atoi accepts "+12"
// and "-3"; a limit does not.
func parsePositive(s string) (int, error) {
	if s == "" || len(s) > 4 {
		return 0, fmt.Errorf("not a small number")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, nil
}

// Query text into search terms: split on whitespace, lowercased ASCII-only —
// the SAME folding sessContainsFold applies, which is the point. A Unicode
// lower here would turn a query's Ärger into ärger and then match neither
// spelling, because the comparison below folds nothing outside A–Z (review
// 2026-08-18).
func sessTerms(q string) []string {
	fields := strings.Fields(q)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, sessLowerASCII(f))
	}
	return out
}

func sessLowerASCII(s string) string {
	b := []byte(s)
	changed := false
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

// The terms the RAW-BYTE gate may use. A term holding a quote or a backslash
// can appear JSON-escaped in the file (`"foo"` as \"foo\", C:\tmp as
// C:\\tmp), so testing the raw line for it would throw away real hits before
// they were ever parsed. Those terms are still enforced —
// on the extracted text, where escapes are gone — they just cannot serve as
// the cheap gate.
func sessGateTerms(terms []string) []string {
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		if !strings.ContainsAny(t, "\"\\") {
			out = append(out, t)
		}
	}
	return out
}

// The query flags, in the same shape sessFilterFlag has and parsed in the same
// place, so `--since` and `--not` are one code path with one set of rules.
//
// Why these exist at all when a query can just be words: a word written
// plainly cannot say "these two words, in this order" or "everything except
// this", and the shell has already finished splitting by the time this program
// sees its arguments. So the panel — which IS allowed to see the whole query
// string — does the splitting, and hands the pieces down as flags. A person at
// a terminal gets the same three powers by writing them out, with their own
// shell doing the quoting.
func sessQueryFlag(q *sessQuery, rest []string, i *int) (bool, error) {
	a := rest[*i]
	name, val := a, ""
	inline := false
	if eq := strings.IndexByte(a, '='); eq > 0 {
		name, val, inline = a[:eq], a[eq+1:], true
	}
	switch name {
	case "--term", "--not", "--re", "--not-re":
	default:
		return false, nil
	}
	if !inline {
		if *i+1 >= len(rest) {
			return true, fmt.Errorf("%s needs a value", name)
		}
		*i++
		val = rest[*i]
	}
	switch name {
	case "--term", "--not":
		// Inner whitespace is kept — that is exactly what makes this a phrase
		// rather than a word — but the ends are trimmed, because a trailing
		// space is a typo in every query anybody has ever meant to write.
		t := sessLowerASCII(strings.TrimSpace(val))
		if t == "" {
			return true, fmt.Errorf("%s needs some text", name)
		}
		if name == "--term" {
			q.terms = append(q.terms, t)
		} else {
			q.nots = append(q.nots, t)
		}
	default:
		re, err := sessCompile(strings.TrimSpace(val))
		if err != nil {
			return true, fmt.Errorf("%s needs a pattern: %v", name, err)
		}
		if name == "--re" {
			q.res = append(q.res, re)
		} else {
			q.nres = append(q.nres, re)
		}
	}
	return true, nil
}

// A transcript file waiting to be searched: which source it belongs to, where
// it lives under that source's root, and when it last changed — the sort key
// that decides what "the most recent matches" means.
type sessFile struct {
	src   int
	rel   string
	mtime time.Time
}

// Every transcript under one source, unordered. The walk pattern (and the
// reason `partial` exists) is codexCandidates': an unreadable directory means
// the list is incomplete, and an incomplete list must not become a confident
// "nothing here". The deadline covers the walk itself, because the budget is
// over the whole search and a tree pathological enough to take seconds to
// LIST would otherwise spend the scan's time before a single file was read.
func sessCandidates(src sessSource, srcIdx int, deadline time.Time) (out []sessFile, partial bool) {
	filepath.WalkDir(src.root, func(p string, d fs.DirEntry, err error) error {
		if time.Now().After(deadline) {
			partial = true
			return fs.SkipAll
		}
		if err != nil {
			partial = true
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// The relative path first, because that is what a matcher is given:
		// several of these tools say what a file is by the directory above it,
		// not by its own name.
		rel, err := filepath.Rel(src.root, p)
		if err != nil {
			partial = true
			return nil
		}
		if !src.match(rel) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			partial = true
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		out = append(out, sessFile{srcIdx, rel, info.ModTime()})
		return nil
	})
	return out, partial
}

// Newest first, with a stable tie-break so equal mtimes cannot reorder
// between runs — every sessions verb promises the same "recent" and this is
// the one definition of it.
func sessSortFiles(files []sessFile) {
	sort.Slice(files, func(i, j int) bool {
		if !files[i].mtime.Equal(files[j].mtime) {
			return files[i].mtime.After(files[j].mtime)
		}
		if files[i].src != files[j].src {
			return files[i].src < files[j].src
		}
		return files[i].rel < files[j].rel
	})
}

// The search: newest transcripts first, across every source at once, stopping
// at the limit or the deadline, whichever comes first. Partial means exactly
// "some transcript was not fully searched" — a directory that would not list,
// a file that would not read, a line too long to hold, or time running out —
// and never "the limit filled", which is the search working as designed.
func sessionsSearch(sources []sessSource, q sessQuery) sessReport {
	started := time.Now()
	rep := sessReport{Matches: []sessHit{}}

	roots, files, partial := sessAllCandidates(sources, q.deadline)
	defer sessCloseRoots(roots)
	if partial {
		rep.Partial = true
	}
	rep.Files = len(files)

	gate := sessGateTerms(q.terms)
	for _, f := range files {
		if len(rep.Matches) >= q.limit {
			break
		}
		if time.Now().After(q.deadline) {
			rep.Partial = true
			break
		}
		// The cheap half of the filter, before anything is opened. A file ruled
		// out by its mtime is not scanned and does not count as scanned — which
		// is what makes `--since` a budget saved rather than a result thrown
		// away after the reading was already paid for.
		if !q.filter.wantsTime(f.mtime) {
			continue
		}
		// And the other half of it, for the tools that record where a session
		// ran somewhere OTHER than inside the transcript. Those can be ruled
		// out by project before the file is opened too; the tools that write
		// their cwd into the transcript cannot, and pay one head read.
		if !q.filter.wantsSession(sessIDFromName(sources[f.src], f.rel)) {
			continue
		}
		pathCwd, ok := sessPathCwd(roots[f.src], sources[f.src], f, q.filter)
		if !ok {
			continue
		}
		hits, trouble := sessScanFile(roots[f.src], sources[f.src], f, pathCwd, q, gate)
		if trouble {
			rep.Partial = true
		}
		rep.Scanned++
		// When the limit has room for only part of this file's hits, keep the
		// TAIL: hits are chronological, so the tail is the newest, and newest
		// is the promise the whole ordering makes.
		if remaining := q.limit - len(rep.Matches); len(hits) > remaining {
			hits = hits[len(hits)-remaining:]
		}
		rep.Matches = append(rep.Matches, hits...)
	}
	rep.Ms = time.Since(started).Milliseconds()
	return rep
}

// ── the shared read ──────────────────────────────────────────────────

// A file inside a source's tree, opened under the discipline every verb here
// shares: through the source's own os.Root, so a symlinked component cannot
// walk the read out of the agent's directory, and refused outright when the
// file answers to more than one name — a genuine second link inside the tree
// can point at somebody else's inode. ok=false is always "trouble", never
// "empty": a file that could not be opened must not become a confident
// absence.
func sessOpenIn(root *os.Root, rel string) (*os.File, bool) {
	if root == nil {
		return nil, false
	}
	file, err := root.Open(rel)
	if err != nil {
		return nil, false
	}
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() {
		file.Close()
		return nil, false
	}
	if n, known := openLinkCount(file, st); !known || n != 1 {
		file.Close()
		return nil, false
	}
	return file, true
}

// A whole small file out of a source's tree, under the same discipline, or
// ok=false. For the sidecars a couple of these tools keep beside a transcript
// — never for a transcript itself, which is streamed.
func sessReadCapped(root *os.Root, rel string, max int64) ([]byte, bool) {
	file, ok := sessOpenIn(root, rel)
	if !ok {
		return nil, false
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, false
	}
	return b, true
}

// Every message of one transcript, in order, whatever shape the file stores
// them in — one JSON object per line for most tools, one JSON document holding
// a list of them for Amp. fn is handed the message's raw bytes and its 1-based
// position, and returns false to stop the walk early; stopping is not trouble.
//
// This is the seam that keeps a document-shaped tool from being a second
// implementation of everything: search, listing and reading all walk a
// transcript through here, so a new format costs a `doc` hook rather than
// three new loops that will drift apart.
//
// docCwd is whatever working directory a DOCUMENT named — line-shaped
// transcripts return "" and let the caller read cwd off the lines as before.
func sessEachMessage(file *os.File, src sessSource, fn func(no int, raw []byte) bool) (docCwd string, trouble bool) {
	if src.doc != nil {
		b, err := io.ReadAll(io.LimitReader(file, sessMaxDocBytes+1))
		if err != nil || len(b) > sessMaxDocBytes {
			return "", true
		}
		doc, ok := src.doc(b)
		if !ok {
			return "", true
		}
		for i, m := range doc.Msgs {
			if !fn(i+1, m) {
				return doc.Cwd, false
			}
		}
		return doc.Cwd, false
	}
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), sessMaxLineBytes)
	for no := 1; sc.Scan(); no++ {
		if !fn(no, sc.Bytes()) {
			return "", false
		}
	}
	return "", sc.Err() != nil
}

// Where a source says a transcript ran WITHOUT reading the transcript — from
// the path it sits on, or a sidecar beside it. ok=false means the filter has
// already ruled this file out and it need never be opened.
//
// Only asked of sources that have such a place. For a tool that writes its
// working directory into the transcript, the file itself is the authority and
// answering from anywhere else could rule out a session that does match: the
// slug these paths carry is the cwd with its separators flattened, and
// `a/b` and a directory genuinely named `a-b` flatten to the same thing.
func sessPathCwd(root *os.Root, src sessSource, f sessFile, filter sessFilter) (string, bool) {
	if src.cwd == nil {
		return "", true
	}
	cwd := src.cwd(root, f.rel)
	if cwd == "" {
		return "", true
	}
	return cwd, filter.wantsProject(sessProjectLabel(cwd))
}

// One transcript, message by message. Returns the last few matching messages
// in the order they happened, and whether anything kept the scan from being
// complete. pathCwd is what the source already worked out about this file
// without opening it, "" when it had nothing to say.
func sessScanFile(root *os.Root, src sessSource, f sessFile, pathCwd string, q sessQuery, gate []string) (hits []sessHit, trouble bool) {
	file, ok := sessOpenIn(root, f.rel)
	if !ok {
		return nil, true
	}
	defer file.Close()

	// The working directory this transcript records, once one is seen. Claude
	// stamps it on every line; codex only on the head of the file — so the
	// head lines are given a cheap look even when they match nothing. Some
	// tools do not write it into the transcript at all, and for those the
	// caller has already asked the source.
	fileCwd := pathCwd
	// Whether the project filter has already been put to fileCwd. The check is
	// worth exactly one run per file: the label cannot change once the file has
	// said what it is, and sessProjectLabel redacts and caps on every call.
	cwdChecked := false
	// The project filter ruled this transcript out mid-walk. A separate flag
	// because the walk is a callback now and cannot return the verdict itself.
	ruledOut := false

	docCwd, readTrouble := sessEachMessage(file, src, func(lineNo int, line []byte) bool {
		// Every few messages rather than every few hundred: lines here can be
		// megabytes each, and a check that comes around only after 256 of
		// them can overshoot the budget so far the console's own timeout
		// kills the command — which returns NOTHING, where this returns a
		// partial answer. Stop, not abandon: the hits
		// already found still deserve their timestamps and project below.
		if lineNo%16 == 0 && time.Now().After(q.deadline) {
			trouble = true
			return false
		}
		if fileCwd == "" && lineNo <= 4 && len(line) < 512*1024 && bytes.Contains(line, []byte(`"cwd"`)) {
			var head struct {
				Cwd     string `json:"cwd"`
				Payload struct {
					Cwd string `json:"cwd"`
				} `json:"payload"`
			}
			if json.Unmarshal(line, &head) == nil {
				if head.Cwd != "" {
					fileCwd = head.Cwd
				} else if head.Payload.Cwd != "" {
					fileCwd = head.Payload.Cwd
				}
			}
		}
		// The moment this transcript admits where it ran, a project filter can
		// rule it out for good — nothing later in the file can put it back in
		// the asked-for project. Purely an early exit: the authoritative test is
		// after the loop, for the transcripts that only reveal their cwd late or
		// never — which includes every document-shaped one, whose cwd is not
		// known until its walk has finished.
		if fileCwd != "" && !cwdChecked {
			cwdChecked = true
			if !q.filter.wantsProject(sessProjectLabel(fileCwd)) {
				ruledOut = true
				return false
			}
		}

		// Cheap gate first: a line whose raw bytes do not hold every GATE
		// term cannot produce a message text that does, and almost every
		// line of almost every file stops here without being parsed. Terms
		// that JSON escaping could disguise are not in the gate (see
		// sessGateTerms) — a query made only of those parses every line,
		// which is slower and correct.
		for _, t := range gate {
			if !sessContainsFold(line, t) {
				return true
			}
		}

		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			return true
		}
		if sessIsSystem(m) {
			// A tool that keeps its system prompt in the transcript keeps it as
			// one enormous message, and it mentions nearly every word anybody
			// searches for. Skipping it is the difference between a query for
			// `git push` finding what somebody said and finding every session
			// that tool ever opened.
			return true
		}
		// Who said it, before the text is even joined: a message the role
		// filter rules out cannot be a hit whatever it holds.
		if !q.filter.wantsRole(sessRole(m)) {
			return true
		}
		var texts []string
		sessCollectText(m, 0, &texts)
		if len(texts) == 0 {
			return true
		}
		joined := strings.Join(texts, "\n")
		if !q.match(joined) {
			// The terms lived in the line's plumbing — keys, ids, paths — not
			// in anything a person said, or something the query excluded was in
			// it. Not a hit.
			return true
		}

		hit := sessHit{
			Agent:     src.agent,
			SessionID: sessIDFromName(src, f.rel),
			Snippet:   sessRedact(sessSnippet(joined, q.anchor(joined))),
			Line:      lineNo,
		}
		hit.Timestamp = sessMsgTime(m)
		if cwd, ok := m["cwd"].(string); ok && cwd != "" {
			fileCwd = cwd
		}
		// Project is filled in after the loop, once the file has had every
		// chance to reveal its cwd.
		hits = append(hits, hit)
		if len(hits) > sessPerSession {
			hits = hits[1:]
		}
		return true
	})
	if readTrouble {
		trouble = true
	}
	if ruledOut {
		return nil, false
	}
	if fileCwd == "" {
		fileCwd = docCwd
	}
	project := sessProjectLabel(fileCwd)
	// The authoritative project test. A transcript that never said where it ran
	// has no project, and no project is not a match for a named one — the other
	// reading would file every unlabelled session under every project.
	if !q.filter.wantsProject(project) {
		return nil, trouble
	}
	for i := range hits {
		if hits[i].Timestamp == "" {
			hits[i].Timestamp = f.mtime.UTC().Format(time.RFC3339)
		}
		hits[i].Project = project
	}
	return hits, trouble
}

// A working directory's base name, fit to ride the pipe: redacted FIRST —
// a directory really can be named DB_PASSWORD=..., and a label that skips
// the mask the message text wears would be the one unredacted string in the
// answer — then capped, because a directory can
// also be NAMED five kilobytes and one row must not spend the frame on its
// label.
func sessProjectLabel(cwd string) string {
	if cwd == "" {
		return ""
	}
	return sessCapRunes(sessRedact(filepath.Base(cwd)), 64)
}

// The first n runes of s, whole runes only.
func sessCapRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// The human-readable text out of one parsed transcript line. Collection is by
// key, not by position: `text` and `thinking` hold what somebody typed or the
// model said, in every format this searches (Claude's content items, codex's
// input_text/output_text items), and `content` is the older claude shape
// where a user message is one plain string. Everything else — ids, paths,
// base64 payloads under other names — is structure to walk through, not text
// to quote. Keys are visited in sorted order so the same line always yields
// the same joined text, which is what keeps snippets stable between runs.
//
// `data` is the awkward one and is why this looks at a sibling: Kiro writes
// every piece of a message as {kind, data}, where data is the text when kind
// says "text" and a nest of tool plumbing when it says anything else. Reading
// it by key alone would either miss every Kiro message or quote every tool
// argument as if somebody had said it.
func sessCollectText(v any, depth int, out *[]string) {
	if depth > sessMaxDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		kind, _ := t["kind"].(string)
		for _, k := range keys {
			val := t[k]
			switch k {
			case "data":
				if s, ok := val.(string); ok {
					if kind == "text" && s != "" {
						*out = append(*out, s)
					}
				} else if !sessPlumbingKind(kind) {
					// Walked only when the kind does not already say this is
					// machinery. A tool call's arguments really do contain keys
					// called `text` and `content` — an editor's replacement
					// string, a fetch's prompt — and quoting those would answer
					// searches with things nobody said.
					sessCollectText(val, depth+1, out)
				}
			case "text", "thinking":
				if s, ok := val.(string); ok && s != "" {
					*out = append(*out, s)
				}
			case "content":
				if s, ok := val.(string); ok {
					if s != "" {
						*out = append(*out, s)
					}
				} else {
					sessCollectText(val, depth+1, out)
				}
			default:
				switch val.(type) {
				case map[string]any, []any:
					sessCollectText(val, depth+1, out)
				}
			}
		}
	case []any:
		for _, e := range t {
			sessCollectText(e, depth+1, out)
		}
	}
}

// Case-insensitive substring, ASCII fold only, no allocation. The needle
// arrives already lowercased. Folding stops at ASCII deliberately: transcript
// search here is for code and command fragments and English/CJK prose, and a
// full Unicode fold would buy Å≈å at the price of lowercasing megabytes of
// line into fresh allocations. CJK has no case and is unaffected.
func sessContainsFold(hay []byte, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	if n > len(hay) {
		return false
	}
	c := needle[0]
	C := c
	if c >= 'a' && c <= 'z' {
		C = c - ('a' - 'A')
	}
	for i := 0; i+n <= len(hay); i++ {
		if b := hay[i]; b != c && b != C {
			continue
		}
		j := 1
		for ; j < n; j++ {
			h := hay[i+j]
			if h >= 'A' && h <= 'Z' {
				h += 'a' - 'A'
			}
			if h != needle[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

// The byte index of the needle in a string, same folding rules, -1 when
// absent. Kept separate from sessContainsFold so the hot path above never
// pays for an index it does not want.
func sessIndexFold(hay string, needle string) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	if n > len(hay) {
		return -1
	}
	c := needle[0]
	C := c
	if c >= 'a' && c <= 'z' {
		C = c - ('a' - 'A')
	}
	for i := 0; i+n <= len(hay); i++ {
		if b := hay[i]; b != c && b != C {
			continue
		}
		j := 1
		for ; j < n; j++ {
			h := hay[i+j]
			if h >= 'A' && h <= 'Z' {
				h += 'a' - 'A'
			}
			if h != needle[j] {
				break
			}
		}
		if j == n {
			return i
		}
	}
	return -1
}

// A window of the matched text around the first term, whitespace collapsed,
// capped in runes, with ellipses marking where it was cut. The window is
// taken from the raw text FIRST and collapsed after, so a multi-megabyte
// message costs a few hundred bytes of work, not a full rewrite.
func sessSnippet(text, firstTerm string) string {
	idx := sessIndexFold(text, firstTerm)
	if idx < 0 {
		idx = 0
	}
	start := idx - 300
	if start < 0 {
		start = 0
	}
	end := idx + len(firstTerm) + 300
	if end > len(text) {
		end = len(text)
	}
	for start > 0 && start < len(text) && !utf8.RuneStart(text[start]) {
		start--
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	window := strings.Join(strings.Fields(text[start:end]), " ")
	cutHead := start > 0
	cutTail := end < len(text)

	// Cap in runes, centred on the term, so whatever else the cut takes it
	// never takes the one word the reader searched for.
	runes := []rune(window)
	if len(runes) > sessSnippetRunes {
		termAt := sessIndexFold(window, firstTerm)
		if termAt < 0 {
			termAt = 0
		}
		tr := utf8.RuneCountInString(window[:termAt])
		lo := tr - sessSnippetRunes/2
		if lo < 0 {
			lo = 0
		}
		hi := lo + sessSnippetRunes
		if hi > len(runes) {
			hi = len(runes)
			lo = hi - sessSnippetRunes
		}
		if lo > 0 {
			cutHead = true
		}
		if hi < len(runes) {
			cutTail = true
		}
		window = string(runes[lo:hi])
	}
	if cutHead {
		window = "…" + window
	}
	if cutTail {
		window = window + "…"
	}
	return window
}

// Best-effort masking of credentials that appear in a snippet — the one part
// of a transcript that leaves the machine. Patterns over cleverness: the
// well-known prefixes vendors stamp on their tokens, JWTs by their shape, key
// material by its armour, and `key=value` assignments whose key says secret.
// This is defence in depth for a channel the operator already holds both ends
// of, not data-loss prevention; the transcript on disk is untouched.
var sessRedactRes = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}`),
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}[A-Za-z0-9_.-]*`),
	regexp.MustCompile(`-----BEGIN[A-Z ]{0,32}PRIVATE KEY-----[^-]*(?:-----END[A-Z ]{0,32}PRIVATE KEY-----)?`),
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}`),
}

// Assignments keep their key and lose their value, so the snippet still shows
// WHAT was set — which is usually why the line matched — without showing what
// it was set to. The key may carry prefixes and suffixes around the sensitive
// word (AWS_SECRET_ACCESS_KEY, DB_PASSWORD, CLIENT_SECRET) — a plain \b
// before the word would miss all of those, because an underscore IS a word
// character. RE2 has no lookaround, so the shape is
// spelled out: optional `..._`-style prefix, the word, optional `_...`-style
// suffix. `tokens:` stays untouched — a bare `s` fits neither the suffix nor
// the separator. Values may be quoted (spaces and all) or bare.
var sessRedactAssign = regexp.MustCompile(
	`(?i)((?:[A-Za-z0-9_-]*[_-])?(?:api[_-]?key|apikey|access[_-]?key|secret|token|passw(?:or)?d|credentials?|authorization)(?:[_-][A-Za-z0-9_-]*)?["']?\s*[:=]\s*)("[^"]{4,}"|'[^']{4,}'|[^\s"']{6,})`)

func sessRedact(s string) string {
	for _, re := range sessRedactRes {
		s = re.ReplaceAllString(s, "[redacted]")
	}
	return sessRedactAssign.ReplaceAllString(s, "${1}[redacted]")
}

// The id worth showing for a transcript file. Claude names files by the
// session's uuid; codex wraps the uuid in a rollout-<stamp>- prefix; amp uses
// a T- prefixed one. When a trailing uuid is there, it IS the id; otherwise
// the stem is the honest answer — except for a tool that gives every one of
// its transcripts the SAME file name, where the stem would be an id shared by
// every session on the machine and the source says where the id really lives.
func sessIDFromName(src sessSource, rel string) string {
	name := filepath.Base(rel)
	if src.id != nil {
		if v := src.id(rel); v != "" {
			name = v
		}
	}
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if len(stem) >= 36 && sessLooksUUID(stem[len(stem)-36:]) {
		return stem[len(stem)-36:]
	}
	return stem
}

func sessLooksUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			hex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !hex {
				return false
			}
		}
	}
	return true
}
