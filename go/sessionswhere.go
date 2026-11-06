package main

// Where a session ran — `subnsub-helper sessions where --id ID` — so the
// dashboard can open a terminal on this machine, stand in that directory and
// hand the conversation back to the agent that had it.
//
// The answer is a place, not a command. Which CLI resumes which agent, and
// with which flags, is knowledge the dashboard keeps: it changes when the
// agents change, and a helper that baked it in would need a release every time
// one of them renamed a flag. What only this machine can say is the directory
// — the agents that resume by id refuse, or quietly start somewhere else, when
// asked from the wrong one — and whether it still exists.
//
// Read discipline is the reader's (sessionsread.go): the transcript is found
// by the same walk, opened through the same os.Root, and only its head is
// read. The one read outside a source's tree is Cursor's, below, and it lists
// directories without opening a single file.
//
// The path is printed unredacted. Redaction exists for what people typed;
// a directory name passed through it is a directory that does not exist, and
// the console asking already runs /bin/sh as this user, where `pwd` would say
// the same thing.

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	// How far into a transcript the working directory is looked for. Every
	// format that records one puts it on the first line or close to it;
	// this is the head, not a scan.
	sessWhereLines = 200

	// Directories Cursor's slug resolution may list before giving up. A slug
	// is one path's worth of names, so a real resolution lists one directory
	// per path segment plus the odd ambiguity; this bound is for a tree that
	// is all ambiguity.
	sessSlugLists = 96
)

// One `where` answer. Error is "not-found" under the same rule `open` uses
// — only off a complete walk — and Partial is set otherwise. Cwd is always
// absolute or empty: a label is not somewhere a terminal can stand. Here says
// the directory is still on disk. EditorOnly is Cursor's: the transcript is
// an editor chat, which Cursor's CLI cannot resume because its own chat store
// never held it.
type sessWhereReport struct {
	Error      string    `json:"error,omitempty"`
	Session    *sessMeta `json:"session,omitempty"`
	Cwd        string    `json:"cwd,omitempty"`
	Here       bool      `json:"here,omitempty"`
	EditorOnly bool      `json:"editor_only,omitempty"`
	Ms         int64     `json:"ms"`
	Partial    bool      `json:"partial,omitempty"`
}

func runSessionsWhereCLI(rest []string) int {
	id := ""
	asJSON := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--json":
			asJSON = true
		case a == "--id":
			if i+1 >= len(rest) {
				warnf("--id needs a value")
				return 2
			}
			i++
			id = rest[i]
		case strings.HasPrefix(a, "--id="):
			id = a[len("--id="):]
		default:
			warnf("usage: subnsub-helper sessions where --id ID [--json]")
			return 2
		}
	}
	if !sessValidID(id) {
		warnf("--id must name a session id from `sessions search` or `sessions recent`")
		return 2
	}
	rep := sessionsWhere(sessSources(), id, time.Now().Add(sessBudget))
	if asJSON {
		out, err := json.Marshal(rep)
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
	switch {
	case rep.Cwd == "":
		fmt.Println("  (the transcript does not say where it ran)")
	case !rep.Here:
		fmt.Printf("  %s  (no longer on this machine)\n", rep.Cwd)
	default:
		fmt.Printf("  %s\n", rep.Cwd)
	}
	if rep.EditorOnly {
		fmt.Println("  (an editor chat — Cursor's CLI cannot resume it)")
	}
	if rep.Partial {
		fmt.Println("(partial — some transcripts could not be listed)")
	}
	return 0
}

func sessionsWhere(sources []sessSource, id string, deadline time.Time) sessWhereReport {
	started := time.Now()
	rep := sessWhereReport{}
	roots, files, walkPartial := sessAllCandidates(sources, deadline)
	defer sessCloseRoots(roots)
	var found *sessFile
	for i := range files {
		if sessIDFromName(sources[files[i].src], files[i].rel) == id {
			found = &files[i]
			break
		}
	}
	if found == nil {
		if walkPartial {
			rep.Partial = true
		} else {
			rep.Error = "not-found"
		}
		rep.Ms = time.Since(started).Milliseconds()
		return rep
	}
	src := sources[found.src]
	project := ""
	cwd := ""
	if src.agent == "cursor" {
		// Cursor's path names the project by a slug that cannot be undone
		// by string work alone, and its transcripts do not carry a cwd. The
		// hook's label is still the right thing to SHOW.
		if src.cwd != nil {
			project = src.cwd(roots[found.src], found.rel)
		}
		cwd, rep.EditorOnly = sessCursorWhere(src.root, found.rel, id, deadline)
	} else {
		var trouble bool
		cwd, trouble = sessHeadCwd(roots[found.src], src, *found, deadline)
		if trouble {
			rep.Partial = true
		}
	}
	if cwd != "" && !filepath.IsAbs(cwd) {
		cwd = ""
	}
	if cwd != "" {
		cwd = filepath.Clean(cwd)
		if st, err := os.Stat(cwd); err == nil && st.IsDir() {
			rep.Here = true
		}
	}
	if project == "" {
		project = sessProjectLabel(cwd)
	}
	rep.Cwd = cwd
	rep.Session = &sessMeta{ID: id, Agent: src.agent, Project: project}
	rep.Ms = time.Since(started).Milliseconds()
	return rep
}

// The directory one transcript says it ran in: the source's own hook when
// the tool keeps it beside the file, otherwise the first line that names one
// (Claude on every line, codex in its opening session_meta), otherwise the
// document's own field (Amp). Only the head is read.
func sessHeadCwd(root *os.Root, src sessSource, f sessFile, deadline time.Time) (cwd string, trouble bool) {
	if src.cwd != nil {
		if c := src.cwd(root, f.rel); c != "" {
			return c, false
		}
	}
	file, ok := sessOpenIn(root, f.rel)
	if !ok {
		return "", true
	}
	defer file.Close()
	docCwd, readTrouble := sessEachMessage(file, src, func(no int, line []byte) bool {
		if no > sessWhereLines {
			return false
		}
		if time.Now().After(deadline) {
			trouble = true
			return false
		}
		var probe struct {
			Cwd     string `json:"cwd"`
			Payload struct {
				Cwd string `json:"cwd"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &probe) != nil {
			return true
		}
		if probe.Cwd != "" {
			cwd = probe.Cwd
		} else {
			cwd = probe.Payload.Cwd
		}
		return cwd == ""
	})
	if cwd == "" {
		cwd = docCwd
	}
	return cwd, trouble || (readTrouble && cwd == "")
}

// Cursor's project directory, and whether the chat is one its CLI can
// resume. projects/<slug>/ is the absolute path with every character that is
// not a letter or digit turned into '-', which loses information — "a-b" and
// "a/b" slug alike — so the slug is resolved against the filesystem itself,
// one directory listing per segment. Where that leaves several real
// candidates, the CLI's own chat store breaks the tie: it files a chat under
// chats/<md5 of the directory>/<chat id>, and only the true directory hashes
// to a folder holding this id. A transcript with no such folder anywhere is
// an editor chat.
func sessCursorWhere(projectsRoot, rel, id string, deadline time.Time) (cwd string, editorOnly bool) {
	p := sessPathParts(rel)
	if len(p) == 0 || p[0] == "" {
		return "", false
	}
	chats := filepath.Join(filepath.Dir(projectsRoot), "chats")
	hasChat := func(dir string) bool {
		sum := md5.Sum([]byte(dir))
		st, err := os.Stat(filepath.Join(chats, hex.EncodeToString(sum[:]), id))
		return err == nil && st.IsDir()
	}
	budget := sessSlugLists
	var found []string
	sessSlugResolve(string(filepath.Separator), p[0], &budget, deadline, func(dir string) bool {
		found = append(found, dir)
		return !hasChat(dir) && len(found) < 8
	})
	if len(found) == 0 {
		return "", false
	}
	for _, dir := range found {
		if hasChat(dir) {
			return dir, false
		}
	}
	// No chat to break the tie: the shallowest reading wins, because a
	// name with a dash in it ("web-app") is far commoner than two
	// nested directories that happen to spell the same slug.
	sort.SliceStable(found, func(i, j int) bool {
		return strings.Count(found[i], string(filepath.Separator)) < strings.Count(found[j], string(filepath.Separator))
	})
	return found[0], true
}

// Every directory under base whose path below base slugs to rest, handed to
// emit in listing order until emit says stop. Names are compared slugged, so
// a segment matches when its slug is a prefix of what remains and is followed
// by the '-' that stood for the separator, or by nothing at all.
func sessSlugResolve(base, rest string, budget *int, deadline time.Time, emit func(string) bool) bool {
	if rest == "" {
		return emit(base)
	}
	if *budget <= 0 || time.Now().After(deadline) {
		return true
	}
	*budget--
	ents, err := os.ReadDir(base)
	if err != nil {
		return true
	}
	for _, e := range ents {
		name := e.Name()
		s := sessSlugName(name)
		if s == "" || !strings.HasPrefix(rest, s) {
			continue
		}
		after := rest[len(s):]
		if after != "" {
			if after[0] != '-' {
				continue
			}
			after = after[1:]
		}
		dir := filepath.Join(base, name)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		if !sessSlugResolve(dir, after, budget, deadline, emit) {
			return false
		}
	}
	return true
}

// One path segment the way Cursor slugs it.
func sessSlugName(name string) string {
	return strings.Map(func(r rune) rune {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return r
		}
		return '-'
	}, name)
}
