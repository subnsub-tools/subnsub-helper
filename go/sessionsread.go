package main

// Reading THIS machine's coding-agent sessions, one page at a time, when the
// dashboard asks over the console channel — `subnsub-helper sessions recent`
// and `subnsub-helper sessions open`.
//
// sessions.go finds places; this file goes to them. A search hit is a snippet
// with a session id and a line number, and the two verbs here are the rest of
// that story: `recent` lists the newest transcripts so there is something to
// open before anyone has thought of a query, and `open` prints a bounded
// window of one transcript's messages — around a hit, before or after a line
// already shown, or the tail when nothing is anchored — so the dashboard reads
// a conversation by asking for one page at a time rather than by pulling a
// document.
//
// That is a description of THIS verb's shape, not a rule about the feature:
// sessionssync.go deliberately sends whole transcripts to the account's archive
// when an operator turns that switch on. What the console owes is a bounded
// ANSWER; whether a conversation leaves this machine at all is a different
// switch in a different file.
//
// The same ruling that allowed search allows this: a machine that granted the
// console has already granted arbitrary /bin/sh as this user, so nothing here
// exposes anything that grant did not. The same discipline applies too: every
// open goes through os.Root, multi-linked files are refused, secrets are
// redacted from every string printed, and the answer is capped under the
// console's 16 KiB frame.
//
// Paging is by transcript line number, because the line number is the one
// coordinate both sides already share: search hits carry it, and every page
// names the lines it covered, so "earlier" and "later" are just the same verb
// anchored at an edge the dashboard has already seen.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// Sessions a `recent` listing returns when the caller does not say, and
	// the most it will say ever. Recent is per-machine UI, not an export.
	sessRecentDefault = 10
	sessRecentMax     = 20

	// How far into a transcript the title hunt reads. The first thing the
	// user typed is normally within the first few lines; forty is generous,
	// and a transcript that opens with forty lines of machinery simply lists
	// without a title rather than spending the budget on one.
	sessHeadLines = 40

	// Title length, in runes — one line of a list row.
	sessTitleRunes = 90

	// Messages per `open` page before the byte cap has its say, and the text
	// each message may contribute, in runes. Both exist for the same 16 KiB
	// frame the search snippets respect; a page of dense CJK will shed
	// messages at the byte cap below and still hold these shapes.
	sessPageMsgs = 30
	sessMsgRunes = 320

	// The longest id `open` will even look for. Real ids are uuids or
	// rollout stems; anything longer is not a file this machine wrote.
	sessIDMaxLen = 120
)

// One message of an opened transcript. Line is the 1-based transcript line it
// came from — the paging coordinate. Role is "user", "assistant", "tool", or
// absent when the line is real but unowned (system notes, reasoning without a
// speaker). Cut says the text was truncated to fit the frame, so the
// dashboard can show that honestly instead of presenting a stump as a whole.
type sessMsg struct {
	Line int    `json:"line"`
	Role string `json:"role,omitempty"`
	Time string `json:"time,omitempty"`
	Text string `json:"text"`
	Cut  bool   `json:"cut,omitempty"`
}

// What `open` says about the transcript itself, once, above the messages.
type sessMeta struct {
	ID      string `json:"id"`
	Agent   string `json:"agent"`
	Project string `json:"project,omitempty"`
}

// One `open` answer. Messages is initialised, never nil, for the same
// Array.isArray reason the search report's matches is. MoreBefore/MoreAfter
// are the paging affordances: they say whether the transcript continues past
// the window's edges, whatever trimmed the window to its final shape. Error
// is "not-found" when no transcript on this machine answers to the id — a
// ran-and-answered outcome, not a caller mistake, so it exits 0.
type sessOpenReport struct {
	Error      string    `json:"error,omitempty"`
	Session    *sessMeta `json:"session,omitempty"`
	Messages   []sessMsg `json:"messages"`
	MoreBefore bool      `json:"more_before,omitempty"`
	MoreAfter  bool      `json:"more_after,omitempty"`
	Ms         int64     `json:"ms"`
	Partial    bool      `json:"partial,omitempty"`
}

// One row of a `recent` listing. Timestamp is the file's mtime — when the
// session last MOVED, which is what "recent" means — not any line's own
// clock. Title is the first thing the user typed, redacted and capped, or
// empty when the head of the transcript never says.
type sessRecentEntry struct {
	Project   string `json:"project"`
	Agent     string `json:"agent"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id"`
	Title     string `json:"title"`
}

// The whole `recent` answer, matches' sibling in shape and discipline.
type sessRecentReport struct {
	Sessions []sessRecentEntry `json:"sessions"`
	Files    int               `json:"files"`
	Ms       int64             `json:"ms"`
	Partial  bool              `json:"partial,omitempty"`
}

// The CLI entry for `sessions recent [--limit N] [--json]`. Exit discipline
// is sessions.go's: a listing that RAN exits 0 whatever it found, and only a
// caller error exits non-zero — which an older helper also does by printing
// its usage, and that is exactly how the dashboard tells "too old" from
// "empty machine".
func runSessionsRecentCLI(rest []string) int {
	limit := sessRecentDefault
	asJSON := false
	var filter sessFilter
	now := time.Now()
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if handled, err := sessFilterFlag(&filter, rest, &i, now); handled {
			if err != nil {
				warnf("%v", err)
				return 2
			}
			continue
		}
		switch {
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
		default:
			warnf("usage: subnsub-helper sessions recent [--limit N] [--project NAME] [--since WHEN] [--until WHEN] [--json]")
			return 2
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > sessRecentMax {
		limit = sessRecentMax
	}
	rep := sessionsRecent(sessSources(), limit, filter, now.Add(sessBudget))
	if asJSON {
		out, err := sessEncodeRecentCapped(&rep)
		if err != nil {
			warnf("could not encode the result: %v", err)
			return 2
		}
		fmt.Println(string(out))
		return 0
	}
	for _, s := range rep.Sessions {
		when := s.Timestamp
		if len(when) >= 16 {
			when = strings.Replace(when[:16], "T", " ", 1)
		}
		id := s.SessionID
		if len(id) > 8 {
			id = id[:8]
		}
		line := []string{when, s.Agent}
		if s.Project != "" {
			line = append(line, s.Project)
		}
		line = append(line, id)
		if s.Title != "" {
			line = append(line, s.Title)
		}
		fmt.Println(strings.Join(line, "  "))
	}
	fmt.Printf("%d session(s) of %d file(s), %d ms%s", len(rep.Sessions), rep.Files, rep.Ms, filter.describe())
	if rep.Partial {
		fmt.Print(" (partial — some files could not be read)")
	}
	fmt.Println()
	return 0
}

// The CLI entry for `sessions open --id ID [--around N | --before N |
// --after N] [--json]`. At most one anchor; none means the tail, which is
// what "open this session" should show first — the latest exchange.
func runSessionsOpenCLI(rest []string) int {
	id := ""
	mode := "tail"
	anchor := 0
	asJSON := false
	setAnchor := func(m, v string) bool {
		if mode != "tail" {
			warnf("only one of --around, --before, --after")
			return false
		}
		n, err := sessParseLine(v)
		if err != nil {
			warnf("--%s needs a line number, not %q", m, v)
			return false
		}
		mode, anchor = m, n
		return true
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		eat := func() (string, bool) {
			if i+1 >= len(rest) {
				warnf("%s needs a value", a)
				return "", false
			}
			i++
			return rest[i], true
		}
		switch {
		case a == "--json":
			asJSON = true
		case a == "--id":
			v, ok := eat()
			if !ok {
				return 2
			}
			id = v
		case strings.HasPrefix(a, "--id="):
			id = a[len("--id="):]
		case a == "--around" || a == "--before" || a == "--after":
			v, ok := eat()
			if !ok || !setAnchor(a[2:], v) {
				return 2
			}
		case strings.HasPrefix(a, "--around="):
			if !setAnchor("around", a[len("--around="):]) {
				return 2
			}
		case strings.HasPrefix(a, "--before="):
			if !setAnchor("before", a[len("--before="):]) {
				return 2
			}
		case strings.HasPrefix(a, "--after="):
			if !setAnchor("after", a[len("--after="):]) {
				return 2
			}
		default:
			warnf("usage: subnsub-helper sessions open --id ID [--around N | --before N | --after N] [--json]")
			return 2
		}
	}
	if !sessValidID(id) {
		warnf("--id must name a session id from `sessions search` or `sessions recent`")
		return 2
	}
	rep := sessionsOpen(sessSources(), id, mode, anchor, time.Now().Add(sessBudget))
	if asJSON {
		out, err := sessEncodeOpenCapped(&rep, mode, anchor)
		if err != nil {
			warnf("could not encode the result: %v", err)
			return 2
		}
		fmt.Println(string(out))
		return 0
	}
	if rep.Error != "" {
		fmt.Println(rep.Error)
		return 0
	}
	if rep.Session != nil {
		head := []string{rep.Session.Agent}
		if rep.Session.Project != "" {
			head = append(head, rep.Session.Project)
		}
		head = append(head, rep.Session.ID)
		fmt.Println(strings.Join(head, "  "))
	}
	if rep.MoreBefore {
		fmt.Println("  …")
	}
	for _, m := range rep.Messages {
		role := m.Role
		if role == "" {
			role = "·"
		}
		text := m.Text
		if m.Cut {
			text += "…"
		}
		fmt.Printf("  %6d  %-9s %s\n", m.Line, role, strings.Join(strings.Fields(text), " "))
	}
	if rep.MoreAfter {
		fmt.Println("  …")
	}
	if rep.Partial {
		fmt.Println("(partial — some of this session could not be read)")
	}
	return 0
}

// A transcript line number out of a flag. parsePositive stops at four digits
// because limits are small; a line number is not — a long session runs past
// 9999 lines without being unusual.
func sessParseLine(s string) (int, error) {
	if s == "" || len(s) > 9 {
		return 0, fmt.Errorf("not a line number")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < 1 {
		return 0, fmt.Errorf("lines start at 1")
	}
	return n, nil
}

// Whether a string is shaped like an id sessions.go would have printed —
// uuids, rollout stems, plain file stems. Nothing else is looked for, which
// keeps the argument from being a probe: an id here is only ever COMPARED
// against names the walk found inside the roots, never joined into a path.
func sessValidID(id string) bool {
	if id == "" || len(id) > sessIDMaxLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// ── shared line parsing ──────────────────────────────────────────────

// One transcript line, parsed as far as a reader cares: the message text (via
// the same collector search quotes from), who said it, when, and any working
// directory the line reveals. ok is false for lines that are structure only —
// metadata, tool plumbing without text — which are real lines but not
// messages, and never spend a slot of a page.
func sessParseMsg(line []byte, lineNo int) (m sessMsg, cwd string, ok bool) {
	return sessParseMsgCap(line, lineNo, sessMsgRunes)
}

// The same parse with the text ceiling as a parameter. The reader's 320 runes
// exist to fit a page inside the console's 16 KiB frame; the archive is not
// inside a frame and keeps whole messages, so the one thing the two callers
// disagree about is passed in rather than duplicated (see sessionssync.go).
func sessParseMsgCap(line []byte, lineNo int, capRunes int) (m sessMsg, cwd string, ok bool) {
	var raw map[string]any
	if json.Unmarshal(line, &raw) != nil {
		return m, "", false
	}
	// A tool's own system prompt is a real line and not a message: it is
	// machinery, it is enormous, and nobody reading a conversation back wants
	// a page of it between two things they said. Search skips it for the same
	// reason — see sessIsSystem.
	if sessIsSystem(raw) {
		return m, "", false
	}
	if c, _ := raw["cwd"].(string); c != "" {
		cwd = c
	} else if p, okP := raw["payload"].(map[string]any); okP {
		if c, _ := p["cwd"].(string); c != "" {
			cwd = c
		}
	}
	var texts []string
	sessCollectText(raw, 0, &texts)
	// Codex writes a tool's reply under `payload.output`, a key the shared
	// collector deliberately ignores for search — here it IS conversation,
	// and without it every `function_call_output` line would be structure
	// only and the tool's side of the exchange unreadable (review
	// 2026-08-18).
	if p, okP := raw["payload"].(map[string]any); okP {
		if t, _ := p["type"].(string); t == "function_call_output" {
			if o, okO := p["output"].(string); okO && o != "" {
				texts = append(texts, o)
			}
		}
	}
	if len(texts) == 0 {
		return m, cwd, false
	}
	joined := strings.TrimSpace(strings.Join(texts, "\n"))
	if joined == "" {
		return m, cwd, false
	}
	m.Line = lineNo
	m.Role = sessRole(raw)
	m.Time = sessMsgTime(raw)
	// Redaction BEFORE the cut, and the order is load-bearing: a credential
	// straddling the cut would leave a prefix too short for any pattern to
	// recognise and long enough to matter, so the mask has to see the whole
	// message and the cut may only ever shorten masked text (review
	// 2026-08-18).
	joined = sessRedact(joined)
	runes := []rune(joined)
	if capRunes > 0 && len(runes) > capRunes {
		joined = string(runes[:capRunes])
		m.Cut = true
	}
	m.Text = joined
	return m, cwd, true
}

// Who a parsed line speaks for. The shapes are the two formats this machine
// stores: claude's {type, message:{role, content}} lines — where a content
// list opening with a tool_result is the tool talking back, whatever the
// envelope's role says — and codex's {payload:{role|type}} lines, where
// reasoning is the assistant thinking. A line that fits none of that is real
// but unowned, and "" is the honest label.
func sessRole(raw map[string]any) string {
	if msg, ok := raw["message"].(map[string]any); ok {
		if items, ok := msg["content"].([]any); ok && len(items) > 0 {
			if it, ok := items[0].(map[string]any); ok {
				if t, _ := it["type"].(string); t == "tool_result" {
					return "tool"
				}
			}
		}
		if r, _ := msg["role"].(string); r == "user" || r == "assistant" {
			return r
		}
	}
	if p, ok := raw["payload"].(map[string]any); ok {
		if r, _ := p["role"].(string); r == "user" || r == "assistant" {
			return r
		}
		if t, _ := p["type"].(string); t == "reasoning" {
			return "assistant"
		}
		if t, _ := p["type"].(string); t == "function_call_output" {
			return "tool"
		}
	}
	if t, _ := raw["type"].(string); t == "user" || t == "assistant" {
		return t
	}
	// Cursor and Amp put the speaker at the top level, beside the message
	// rather than inside it.
	if r, _ := raw["role"].(string); r == "user" || r == "assistant" {
		return r
	}
	// Kiro names the KIND of message instead of who sent it.
	switch k, _ := raw["kind"].(string); k {
	case "Prompt":
		return "user"
	case "AssistantMessage":
		return "assistant"
	case "ToolResults":
		return "tool"
	}
	return ""
}

// ── recent ───────────────────────────────────────────────────────────

func sessionsRecent(sources []sessSource, limit int, filter sessFilter, deadline time.Time) sessRecentReport {
	started := time.Now()
	rep := sessRecentReport{Sessions: []sessRecentEntry{}}
	roots, files, partial := sessAllCandidates(sources, deadline)
	defer sessCloseRoots(roots)
	if partial {
		rep.Partial = true
	}
	rep.Files = len(files)
	for _, f := range files {
		if len(rep.Sessions) >= limit {
			break
		}
		if time.Now().After(deadline) {
			rep.Partial = true
			break
		}
		// Time first, so a filtered listing does not open the transcripts it is
		// about to discard; project after, because the label only exists once
		// the head has been read.
		if !filter.wantsTime(f.mtime) {
			continue
		}
		if !filter.wantsSession(sessIDFromName(sources[f.src], f.rel)) {
			continue
		}
		pathCwd, want := sessPathCwd(roots[f.src], sources[f.src], f, filter)
		if !want {
			continue
		}
		entry, trouble := sessRecentFor(roots[f.src], sources[f.src], f, pathCwd, deadline)
		if trouble {
			rep.Partial = true
		}
		if entry != nil && filter.wantsProject(entry.Project) {
			rep.Sessions = append(rep.Sessions, *entry)
		}
	}
	rep.Ms = time.Since(started).Milliseconds()
	return rep
}

// Every source's candidates, walked, merged and sorted newest-first — the
// prologue every sessions verb shares. A missing root is a tool that is not
// installed, which is a normal empty answer; any other refusal is partial.
// The returned roots are open; sessCloseRoots is the caller's duty.
func sessAllCandidates(sources []sessSource, deadline time.Time) (roots []*os.Root, files []sessFile, partial bool) {
	roots = make([]*os.Root, len(sources))
	for i, src := range sources {
		if src.root == "" {
			continue
		}
		r, err := os.OpenRoot(src.root)
		if err != nil {
			if !os.IsNotExist(err) {
				partial = true
			}
			continue
		}
		roots[i] = r
		cs, p := sessCandidates(src, i, deadline)
		if p {
			partial = true
		}
		files = append(files, cs...)
	}
	sessSortFiles(files)
	return roots, files, partial
}

func sessCloseRoots(roots []*os.Root) {
	for _, r := range roots {
		if r != nil {
			r.Close()
		}
	}
}

// One listing row out of one transcript's head. The scan reads until it has
// both a working directory and a title, or sessHeadLines lines have said
// neither is coming. A file that cannot be opened under the read discipline
// yields no row and marks the answer partial — same as search, an unreadable
// file must not become a confident absence.
func sessRecentFor(root *os.Root, src sessSource, f sessFile, pathCwd string, deadline time.Time) (*sessRecentEntry, bool) {
	file, ok := sessOpenIn(root, f.rel)
	if !ok {
		return nil, true
	}
	defer file.Close()
	entry := sessRecentEntry{
		Agent:     src.agent,
		SessionID: sessIDFromName(src, f.rel),
		Timestamp: f.mtime.UTC().Format(time.RFC3339),
	}
	cwd := pathCwd
	trouble := false
	docCwd, readTrouble := sessEachMessage(file, src, func(lineNo int, line []byte) bool {
		if lineNo > sessHeadLines {
			return false
		}
		if lineNo%8 == 0 && time.Now().After(deadline) {
			trouble = true
			return false
		}
		m, lineCwd, ok := sessParseMsg(line, lineNo)
		if lineCwd != "" && cwd == "" {
			cwd = lineCwd
		}
		if !ok || entry.Title != "" {
			return !(entry.Title != "" && cwd != "")
		}
		// The title is the first thing the USER typed — not tool chatter, and
		// not the machinery agents inject as the nominal first user message
		// of a transcript.
		if m.Role != "user" {
			return true
		}
		t := sessTitleUnwrap(strings.TrimSpace(m.Text))
		if t == "" || sessTitlePrelude(t) {
			return true
		}
		entry.Title = sessTitleClip(t)
		return cwd == ""
	})
	if readTrouble {
		trouble = true
	}
	if cwd == "" {
		cwd = docCwd
	}
	entry.Project = sessProjectLabel(cwd)
	return &entry, trouble
}

// The machinery that poses as the first user message of a transcript, by its
// EXACT openings — claude's slash-command wrappers and local-command caveat,
// codex's tag-wrapped context blocks. Matching precisely is the point:
// skipping anything starting with `<` or `Caveat:` would drop a user
// whose genuine first words were "<div> is overflowing…".
// The list will trail new wrappers slightly;
// a machinery title for a while beats stealing titles from real prompts.
// Compared ASCII-lowercased, the same folding everything here searches by.
var sessTitlePreludes = []string{
	"<command-name",
	"<command-message",
	"<local-command",
	"<user-memory-input",
	"<system-reminder",
	"<task-notification",
	"<user_instructions",
	"<environment_context",
	"<turn_context",
	"<permissions",
	"caveat: the messages below",
}

func sessTitlePrelude(t string) bool {
	low := sessLowerASCII(t)
	for _, p := range sessTitlePreludes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// What somebody actually typed, out of the envelope one tool wraps it in.
// Cursor prefixes every prompt with the local time and then encloses the words
// in <user_query>, so a listing built from the raw text would show a column of
// identical timestamps where the titles should be. Only unwrapped when the
// message OPENS with that machinery — a message that merely mentions the tag
// is a message that mentions the tag, and keeps its own words.
func sessTitleUnwrap(t string) string {
	if !strings.HasPrefix(t, "<timestamp>") && !strings.HasPrefix(t, "<user_query>") {
		return t
	}
	const open, close = "<user_query>", "</user_query>"
	i := strings.Index(t, open)
	if i < 0 {
		return t
	}
	rest := t[i+len(open):]
	if j := strings.Index(rest, close); j >= 0 {
		rest = rest[:j]
	}
	if inner := strings.TrimSpace(rest); inner != "" {
		return inner
	}
	return t
}

// A one-line title out of message text: whitespace collapsed, capped in
// runes, an ellipsis owning up to any cut. Redaction already happened in
// sessParseMsg; this only shapes.
func sessTitleClip(t string) string {
	flat := strings.Join(strings.Fields(t), " ")
	runes := []rune(flat)
	if len(runes) <= sessTitleRunes {
		return flat
	}
	return string(runes[:sessTitleRunes]) + "…"
}

func sessEncodeRecentCapped(rep *sessRecentReport) ([]byte, error) {
	out, err := json.Marshal(rep)
	for err == nil && sessFrameCost(out) > sessMaxJSONBytes && len(rep.Sessions) > 0 {
		rep.Sessions = rep.Sessions[:len(rep.Sessions)-1]
		rep.Partial = true
		out, err = json.Marshal(rep)
	}
	return out, err
}

// ── open ─────────────────────────────────────────────────────────────

func sessionsOpen(sources []sessSource, id, mode string, anchor int, deadline time.Time) sessOpenReport {
	started := time.Now()
	rep := sessOpenReport{Messages: []sessMsg{}}
	// The walk's own troubles are NOT this answer's `partial`: partial here
	// means "this session's page may be missing lines", and an unlistable
	// directory in some other agent's tree says nothing about the file that
	// WAS found and read whole. The walk's
	// incompleteness matters only below, where it forbids the not-found
	// verdict.
	roots, files, walkPartial := sessAllCandidates(sources, deadline)
	defer sessCloseRoots(roots)
	// The newest file answering to the id. Ids are filenames' stems, so a
	// collision is unlikely but representable — a plain-named file in two
	// trees — and newest-first is the same promise every other verb makes.
	var found *sessFile
	for i := range files {
		if sessIDFromName(sources[files[i].src], files[i].rel) == id {
			found = &files[i]
			break
		}
	}
	if found == nil {
		// "Not found" is a verdict, and a verdict needs the whole candidate
		// list to have been seen. Off an incomplete walk the honest answer
		// is an empty partial page, which the dashboard shows as a failed
		// read — not as this session having ceased to exist.
		if walkPartial {
			rep.Partial = true
		} else {
			rep.Error = "not-found"
		}
		rep.Ms = time.Since(started).Milliseconds()
		return rep
	}
	src := sources[found.src]
	msgs, cwd, trouble, sawEnd := sessScanMessages(roots[found.src], src, *found, mode, anchor, deadline)
	if trouble {
		rep.Partial = true
	}
	rep.Session = &sessMeta{ID: id, Agent: src.agent, Project: sessProjectLabel(cwd)}
	rep.Messages, rep.MoreBefore, rep.MoreAfter = msgs.page(sessPageMsgs)
	// A scan that never reached the end of the file cannot testify that
	// nothing follows: without this, a timed-out tail passes its prefix off
	// as the real end and the rest of the transcript becomes unreachable
	// from the UI. The deliberate early stop sets its
	// own more_after through the window's counts; this covers the
	// involuntary ones.
	if !sawEnd {
		rep.MoreAfter = true
	}
	// An anchored scan that was cut BEFORE it ever reached its anchor has a
	// window from somewhere far short of the page it was asked for; handing
	// that over would let the dashboard stitch a distant prefix onto the
	// transcript and orphan everything between.
	// The page comes back empty and partial instead — the edges on screen
	// stay where they were, and the same button asks again.
	if (mode == "before" || mode == "around") && !sawEnd && !msgs.anchorSeen {
		rep.Messages = []sessMsg{}
		rep.Partial = true
		if mode == "before" {
			rep.MoreBefore = true
		}
	}
	rep.Ms = time.Since(started).Milliseconds()
	return rep
}

// A window collector: the scan feeds it every message in order, and it keeps
// just enough on each side of the anchor to build one page, so a hundred-
// thousand-line transcript costs a page of memory, not a transcript of it.
// done tells the scan it may stop — everything a later line could add is
// already known to be "more after".
type sessWindow struct {
	mode    string // tail | around | before | after
	anchor  int
	keep    int
	before  []sessMsg // the last `keep` messages on the near side
	after   []sessMsg // the first `keep` messages on the far side
	nBefore int
	nAfter  int
	done    bool
	// Whether the scan ever arrived at the anchor's side of the file. An
	// anchored window that was cut short of this holds messages from the
	// wrong neighbourhood entirely, and sessionsOpen refuses to serve it.
	anchorSeen bool
}

func (w *sessWindow) add(m sessMsg) {
	nearSide := false
	switch w.mode {
	case "tail":
		nearSide = true // everything is before the end
	case "around":
		nearSide = m.Line < w.anchor
		if !nearSide {
			w.anchorSeen = true
		}
	case "before":
		if m.Line >= w.anchor {
			// The first far-side message proves the transcript continues,
			// and nothing after it can change this page.
			w.nAfter++
			w.done = true
			w.anchorSeen = true
			return
		}
		nearSide = true
	case "after":
		if m.Line <= w.anchor {
			w.nBefore++
			return
		}
	}
	if nearSide {
		w.nBefore++
		w.before = append(w.before, m)
		if len(w.before) > w.keep {
			w.before = w.before[1:]
		}
		return
	}
	w.nAfter++
	if len(w.after) < w.keep {
		w.after = append(w.after, m)
		return
	}
	// One past the window: more exists, and the scan may stop reading.
	w.done = true
}

// The page, and whether the transcript continues past each edge. For around,
// the anchor sits as close to the middle as the transcript allows, each side
// donating its slack to the other.
func (w *sessWindow) page(size int) ([]sessMsg, bool, bool) {
	takeB, takeA := 0, 0
	switch w.mode {
	case "tail", "before":
		takeB = size
	case "after":
		takeA = size
	case "around":
		takeB = size / 2
		takeA = size - takeB
		if len(w.before) < takeB {
			takeA += takeB - len(w.before)
			takeB = len(w.before)
		}
		if len(w.after) < takeA {
			takeB += takeA - len(w.after)
			takeA = len(w.after)
		}
	}
	if takeB > len(w.before) {
		takeB = len(w.before)
	}
	if takeA > len(w.after) {
		takeA = len(w.after)
	}
	msgs := make([]sessMsg, 0, takeB+takeA)
	msgs = append(msgs, w.before[len(w.before)-takeB:]...)
	msgs = append(msgs, w.after[:takeA]...)
	return msgs, w.nBefore > takeB, w.nAfter > takeA
}

// Every message of one transcript, driven through a window. Same read guards
// and budget checks as the search scan; trouble means the window may be
// missing lines it should have seen, reported as partial. sawEnd says the
// scan genuinely ran out of file — the one condition under which "nothing
// more after this" is a fact rather than a guess; a deliberate early stop
// (w.done) and every involuntary one leave it false.
func sessScanMessages(root *os.Root, src sessSource, f sessFile, mode string, anchor int, deadline time.Time) (w *sessWindow, cwd string, trouble, sawEnd bool) {
	w = &sessWindow{mode: mode, anchor: anchor, keep: sessPageMsgs}
	file, ok := sessOpenIn(root, f.rel)
	if !ok {
		return w, "", true, false
	}
	defer file.Close()
	if src.cwd != nil {
		cwd = src.cwd(root, f.rel)
	}
	stopped := false
	docCwd, readTrouble := sessEachMessage(file, src, func(lineNo int, line []byte) bool {
		if lineNo%16 == 0 && time.Now().After(deadline) {
			trouble = true
			stopped = true
			return false
		}
		m, lineCwd, ok := sessParseMsg(line, lineNo)
		if lineCwd != "" && cwd == "" {
			cwd = lineCwd
		}
		if !ok {
			return true
		}
		w.add(m)
		if w.done {
			stopped = true
			return false
		}
		return true
	})
	if readTrouble {
		trouble = true
	}
	if cwd == "" {
		cwd = docCwd
	}
	sawEnd = !stopped && !readTrouble
	return w, cwd, trouble, sawEnd
}

// The open report as JSON, under the frame like every other answer. What a
// byte overflow sheds is the edge FARTHER from the anchor, and each shed edge
// admits to itself through the more_* flag — the dashboard's next page will
// simply start from the new edge, so a drop here costs one extra click, never
// a message.
func sessEncodeOpenCapped(rep *sessOpenReport, mode string, anchor int) ([]byte, error) {
	out, err := json.Marshal(rep)
	for err == nil && sessFrameCost(out) > sessMaxJSONBytes && len(rep.Messages) > 1 {
		dropHead := false
		switch mode {
		case "tail", "before":
			dropHead = true
		case "after":
			dropHead = false
		case "around":
			// Whichever edge sits farther from the anchor line gives way, so
			// the hit being read stays on the page.
			first := rep.Messages[0].Line
			last := rep.Messages[len(rep.Messages)-1].Line
			dropHead = anchor-first >= last-anchor
		}
		if dropHead {
			rep.Messages = rep.Messages[1:]
			rep.MoreBefore = true
		} else {
			rep.Messages = rep.Messages[:len(rep.Messages)-1]
			rep.MoreAfter = true
		}
		out, err = json.Marshal(rep)
	}
	// A single message so large it still overflows loses its text's tail
	// rather than the whole answer.
	for err == nil && sessFrameCost(out) > sessMaxJSONBytes && len(rep.Messages) == 1 {
		m := &rep.Messages[0]
		runes := []rune(m.Text)
		if len(runes) < 8 {
			break
		}
		m.Text = string(runes[:len(runes)/2])
		m.Cut = true
		out, err = json.Marshal(rep)
	}
	return out, err
}
