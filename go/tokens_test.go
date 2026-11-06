package main

// The agents' token counts out of their own transcripts (tokens.go): a Claude
// reply counted once however many lines and files repeat it, Codex's running
// totals turned into steps under the model of their turn, the five kinds kept
// apart, read incrementally within a budget, and the buckets kept past the
// transcripts they came from.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tkuReset(t *testing.T) {
	t.Helper()
	wipe := func() {
		tokState.files, tokState.owner = nil, nil
		tokState.kept, tokState.keptH = nil, nil
		tokState.keptRead, tokState.dirty, tokState.savedAt = false, false, 0
		tokOut.Lock()
		tokOut.last, tokOut.at = nil, 0
		tokOut.Unlock()
	}
	wipe()
	chunk, file, pass := tokChunk, tokFileBudget, tokPassBudget
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("MON_TOKENS", "")
	// No Amp CLI set going under a test (tokens_amp_test.go stands one in).
	bin := ampTokBinary
	ampTokBinary = func() string { return "" }
	ampTok.Lock()
	ampTok.threads, ampTok.loaded, ampTok.ranAt, ampTok.complete, ampTok.legacy = nil, true, 0, false, nil
	ampTok.Unlock()
	t.Cleanup(func() {
		wipe()
		tokChunk, tokFileBudget, tokPassBudget = chunk, file, pass
		ampTokBinary = bin
	})
}

func tkuStamp(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

// One assistant line as Claude Code writes it.
func tkuClaude(at time.Time, id, req, model string, in, out, cr, cw, cw1h, think int) string {
	return fmt.Sprintf(`{"type":"assistant","timestamp":%q,"requestId":%q,"message":{"id":%q,"model":%q,"role":"assistant",`+
		`"content":[{"type":"text","text":"usage is reported below"}],"usage":{"input_tokens":%d,"output_tokens":%d,`+
		`"cache_read_input_tokens":%d,"cache_creation_input_tokens":%d,"cache_creation":{"ephemeral_1h_input_tokens":%d,"ephemeral_5m_input_tokens":%d},`+
		`"output_tokens_details":{"thinking_tokens":%d}}}}`+"\n", tkuStamp(at), req, id, model, in, out, cr, cw, cw1h, cw-cw1h, think)
}

func tkuCodexTurn(at time.Time, model string) string {
	return fmt.Sprintf(`{"timestamp":%q,"type":"turn_context","payload":{"cwd":"/w","model":%q}}`+"\n", tkuStamp(at), model)
}

// A token_count line: the running total and the turn, each [input, cached,
// output, reasoning].
func tkuCodexCount(at time.Time, total, last [4]int) string {
	u := func(v [4]int) string {
		return fmt.Sprintf(`{"input_tokens":%d,"cached_input_tokens":%d,"cache_write_input_tokens":0,"output_tokens":%d,"reasoning_output_tokens":%d,"total_tokens":%d}`,
			v[0], v[1], v[2], v[3], v[0]+v[2])
	}
	return fmt.Sprintf(`{"timestamp":%q,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":%s,"last_token_usage":%s},"rate_limits":null}}`+"\n",
		tkuStamp(at), u(total), u(last))
}

func tkuWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The answer's rows for one key, summed: hours or days.
func tkuSum(u *TokenUsage, tool, model string, days bool) tokCell {
	var c tokCell
	if u == nil {
		return c
	}
	k := int64(-1)
	for i, kk := range u.Keys {
		if kk[0] == tool && kk[1] == model {
			k = int64(i)
		}
	}
	rows := u.Hours
	if days {
		rows = u.Days
	}
	for _, r := range rows {
		if r[1] == k {
			c.add(tokCell{r[2], r[3], r[4], r[5], r[6], r[7], r[8]})
		}
	}
	return c
}

func TestTokensClaudeCountsAReplyOnce(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	at := now.Add(-30 * time.Minute)
	proj := filepath.Join(home, ".claude", "projects", "-w-app")
	// One reply written once per content block, the same usage on each line;
	// thinking inside output; a one-hour share of the cache write.
	reply := tkuClaude(at, "msg_1", "req_1", "claude-opus-5-5", 10, 300, 5000, 2000, 1500, 120)
	body := reply + reply +
		tkuClaude(at.Add(time.Minute), "msg_2", "req_2", "claude-opus-5-5", 4, 50, 7000, 0, 0, 0) +
		// A synthetic reply (an error the client made up) and an API error.
		tkuClaude(at, "msg_3", "req_3", "<synthetic>", 0, 0, 0, 0, 0, 0) +
		strings.Replace(tkuClaude(at, "msg_4", "req_4", "claude-opus-5-5", 999, 999, 0, 0, 0, 0), `"type":"assistant",`, `"type":"assistant","isApiErrorMessage":true,`, 1) +
		`{"type":"user","timestamp":"` + tkuStamp(at) + `","message":{"role":"user","content":"hello"}}` + "\n" +
		"not json at all\n"
	tkuWrite(t, filepath.Join(proj, "a.jsonl"), body)
	// A resumed session repeats the first reply, then adds its own; a
	// subagent's transcript sits a level further down.
	tkuWrite(t, filepath.Join(proj, "b.jsonl"), reply+tkuClaude(at.Add(2*time.Minute), "msg_5", "req_5", "claude-haiku-4-5", 1, 2, 3, 4, 0, 0))
	tkuWrite(t, filepath.Join(proj, "a", "subagents", "agent-x.jsonl"), tkuClaude(at, "msg_6", "req_6", "claude-opus-5-5", 1, 1, 1, 1, 0, 0))

	u := tokPass(now)
	if u == nil || u.Partial {
		t.Fatalf("answer = %+v", u)
	}
	got := tkuSum(u, "claude", "claude-opus-5-5", true)
	want := tokCell{in: 10 + 4 + 1, out: 180 + 50 + 1, cr: 5000 + 7000 + 1, cw: 2000 + 1, w1h: 1500, rs: 120, n: 3}
	if got != want {
		t.Fatalf("opus days = %+v, want %+v", got, want)
	}
	if h := tkuSum(u, "claude", "claude-opus-5-5", false); h != want {
		t.Fatalf("opus hours = %+v, want %+v", h, want)
	}
	if got := tkuSum(u, "claude", "claude-haiku-4-5", true); got != (tokCell{1, 2, 3, 4, 0, 0, 1}) {
		t.Fatalf("haiku = %+v", got)
	}
	for _, k := range u.Keys {
		if k[1] == "<synthetic>" || k[1] == "other" {
			t.Fatalf("unexpected key %v", k)
		}
	}
}

func TestTokensCodexStepsUnderTheTurnsModel(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	at := now.Add(-2 * time.Hour)
	body := tkuCodexTurn(at, "gpt-5.6-sol") +
		// First turn: its own usage (no total before it in view).
		tkuCodexCount(at, [4]int{1000, 800, 100, 40}, [4]int{1000, 800, 100, 40}) +
		// The same total written twice counts once.
		tkuCodexCount(at, [4]int{1000, 800, 100, 40}, [4]int{1000, 800, 100, 40}) +
		// The step in the running total, not the turn's own figure.
		tkuCodexCount(at.Add(time.Minute), [4]int{2500, 2000, 300, 100}, [4]int{9, 9, 9, 9}) +
		`{"timestamp":"` + tkuStamp(at) + `","type":"event_msg","payload":{"type":"token_count","info":null,"rate_limits":{}}}` + "\n" +
		tkuCodexTurn(at.Add(2*time.Minute), "gpt-5.5-mini") +
		// A total that went back (a new one): the turn's own usage.
		tkuCodexCount(at.Add(3*time.Minute), [4]int{50, 0, 10, 0}, [4]int{50, 0, 10, 0})
	tkuWrite(t, filepath.Join(home, ".codex", "sessions", "2026", "10", "27", "rollout-2026-10-27T01-00-00-abc.jsonl"), body)
	tkuWrite(t, filepath.Join(home, ".codex", "archived_sessions", "rollout-2026-10-20T01-00-00-def.jsonl"),
		tkuCodexTurn(at, "gpt-5.6-sol")+tkuCodexCount(at, [4]int{10, 0, 5, 1}, [4]int{10, 0, 5, 1}))

	u := tokPass(now)
	// 1000/800/100/40, then +1500/+1200/+200/+60, then the archived 10/0/5/1.
	want := tokCell{in: 200 + 300 + 10, cr: 800 + 1200, out: 60 + 140 + 4, rs: 40 + 60 + 1, n: 3}
	if got := tkuSum(u, "codex", "gpt-5.6-sol", true); got != want {
		t.Fatalf("sol = %+v, want %+v", got, want)
	}
	if got := tkuSum(u, "codex", "gpt-5.5-mini", true); got != (tokCell{in: 50, out: 10, n: 1}) {
		t.Fatalf("mini = %+v", got)
	}
}

func TestTokensReadOnlyWhatIsNewAndWhole(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	at := now.Add(-10 * time.Minute)
	file := filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	first := tkuClaude(at, "m1", "r1", "claude-opus-5-5", 1, 10, 0, 0, 0, 0)
	second := tkuClaude(at, "m2", "r2", "claude-opus-5-5", 2, 20, 0, 0, 0, 0)
	// The second line still being written: no newline yet.
	tkuWrite(t, file, first+second[:len(second)/2])
	if got := tkuSum(tokPass(now), "claude", "claude-opus-5-5", true); got.n != 1 || got.out != 10 {
		t.Fatalf("first pass = %+v", got)
	}
	appendTo(t, file, second[len(second)/2:])
	if got := tkuSum(tokPass(now), "claude", "claude-opus-5-5", true); got.n != 2 || got.out != 30 {
		t.Fatalf("second pass = %+v", got)
	}
	// Replaced by a shorter file: read again from its start.
	tkuWrite(t, file, tkuClaude(at, "m9", "r9", "claude-opus-5-5", 0, 5, 0, 0, 0, 0))
	got := tkuSum(tokPass(now), "claude", "claude-opus-5-5", true)
	// The kept day holds the larger count it had seen (two replies, 30 out).
	if got.n != 2 || got.out != 30 {
		t.Fatalf("after replace = %+v", got)
	}
	f := tokState.files["claude\x00"+filepath.Join(home, ".claude", "projects")+"\x00"+filepath.Join("p", "s.jsonl")]
	if f == nil || f.days == nil {
		t.Fatal("no account for the replaced file")
	}
	var live tokCell
	for _, c := range f.days {
		live.add(c)
	}
	if live.n != 1 || live.out != 5 {
		t.Fatalf("replaced file's own account = %+v", live)
	}
}

func TestTokensBudgetSpreadsAFirstPass(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	tokChunk, tokFileBudget, tokPassBudget = 1024, 2048, 4096
	now := time.Now()
	at := now.Add(-time.Hour)
	var b strings.Builder
	for i := 0; i < 60; i++ {
		b.WriteString(tkuClaude(at, fmt.Sprintf("m%d", i), "r", "claude-opus-5-5", 1, 2, 0, 0, 0, 0))
	}
	// A line longer than a whole read is passed over; the line after it counts.
	b.WriteString(`{"type":"user","message":{"content":"` + strings.Repeat("x", 3000) + `"}}` + "\n")
	b.WriteString(tkuClaude(at, "last", "r", "claude-opus-5-5", 1, 2, 0, 0, 0, 0))
	tkuWrite(t, filepath.Join(home, ".claude", "projects", "p", "big.jsonl"), b.String())

	var u *TokenUsage
	passes := 0
	for passes = 1; passes < 200; passes++ {
		u = tokPass(now)
		if !u.Partial {
			break
		}
	}
	if passes < 2 {
		t.Fatalf("a %d-byte file read in one pass on a 2048-byte budget", b.Len())
	}
	if got := tkuSum(u, "claude", "claude-opus-5-5", true); got.n != 61 || got.out != 122 {
		t.Fatalf("after %d passes = %+v", passes, got)
	}
}

func TestTokensWindowsAndKeptBuckets(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	file := filepath.Join(home, ".claude", "projects", "p", "w.jsonl")
	tkuWrite(t, file,
		tkuClaude(now.Add(-26*time.Hour), "old-hour", "r", "claude-opus-5-5", 1, 1, 0, 0, 0, 0)+ // a day row, no hour row
			tkuClaude(now.Add(-40*24*time.Hour), "too-old", "r", "claude-opus-5-5", 50, 50, 0, 0, 0, 0)+ // neither
			tkuClaude(now.Add(-5*time.Minute), "fresh", "r", "claude-opus-5-5", 2, 2, 0, 0, 0, 0))
	u := tokPass(now)
	if d, h := tkuSum(u, "claude", "claude-opus-5-5", true), tkuSum(u, "claude", "claude-opus-5-5", false); d.n != 2 || h.n != 1 {
		t.Fatalf("days %+v hours %+v", d, h)
	}
	for _, r := range u.Hours {
		if r[0] < now.Unix()/3600-tokHours+1 {
			t.Fatalf("hour row %v outside the window", r)
		}
	}
	for _, r := range u.Days {
		if r[0] < now.Unix()/86400-tokWireDays+1 {
			t.Fatalf("day row %v outside the window", r)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "subnsub-helper", "tokens.json")); err != nil {
		t.Fatalf("tokens.json not written: %v", err)
	}

	// The transcript gone and the helper restarted: the kept buckets answer.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	tokState.files, tokState.owner, tokState.kept, tokState.keptH, tokState.keptRead = nil, nil, nil, nil, false
	u = tokPass(now)
	if d, h := tkuSum(u, "claude", "claude-opus-5-5", true), tkuSum(u, "claude", "claude-opus-5-5", false); d.n != 2 || h.n != 1 {
		t.Fatalf("from tokens.json: days %+v hours %+v", d, h)
	}
}

func TestTokensFoldTheLeastUsedModels(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	var b strings.Builder
	for i := 0; i < tokMaxKeys+10; i++ {
		b.WriteString(tkuClaude(now.Add(-time.Minute), fmt.Sprintf("m%d", i), "r", fmt.Sprintf("model-%02d", i), 1, 100+i, 0, 0, 0, 0))
	}
	tkuWrite(t, filepath.Join(home, ".claude", "projects", "p", "many.jsonl"), b.String())
	u := tokPass(now)
	if len(u.Keys) > tokMaxKeys {
		t.Fatalf("%d keys, at most %d", len(u.Keys), tokMaxKeys)
	}
	var all tokCell
	for _, r := range u.Days {
		all.add(tokCell{r[2], r[3], r[4], r[5], r[6], r[7], r[8]})
	}
	if all.n != int64(tokMaxKeys+10) {
		t.Fatalf("folding lost rows: %+v", all)
	}
	// Room is kept for an "other" of each tool: the least used past that fold.
	if got := tkuSum(u, "claude", "other", true); got.n != int64(10+len(tokTools)) {
		t.Fatalf("other = %+v", got)
	}
}

func TestTokensRefuseAHardLinkAndHonourOff(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	outside := filepath.Join(home, "secret.jsonl")
	tkuWrite(t, outside, tkuClaude(now, "m", "r", "claude-opus-5-5", 1, 1, 0, 0, 0, 0))
	link := filepath.Join(home, ".claude", "projects", "p", "link.jsonl")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, link); err != nil {
		t.Skip("no hard links here:", err)
	}
	u := tokPass(now)
	if u == nil || !u.Partial || len(u.Days) != 0 {
		t.Fatalf("a hard-linked transcript was read: %+v", u)
	}
	t.Setenv("MON_TOKENS", "off")
	if tokenSnapshot() != nil {
		t.Fatal("MON_TOKENS=off still answered")
	}
}

func TestTokensModelNames(t *testing.T) {
	for in, want := range map[string]string{
		"claude-opus-5-5":                 "claude-opus-5-5",
		" gpt-5.6-sol ":                   "gpt-5.6-sol",
		"":                                "unknown",
		"a model with spaces":             "other",
		"anthropic/claude-sonnet-4-5@001": "anthropic/claude-sonnet-4-5@001",
		strings.Repeat("x", 65):           "other",
		"claude-opus-4-6[1m]":             "claude-opus-4-6[1m]",
	} {
		if got := tokModel(in); got != want {
			t.Errorf("tokModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTokensNoticeAFilePutInItsPlace(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	at := now.Add(-10 * time.Minute)
	file := filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	tkWant := func(want int64, why string) {
		t.Helper()
		f := tokState.files["claude\x00"+filepath.Join(home, ".claude", "projects")+"\x00"+filepath.Join("p", "s.jsonl")]
		var live tokCell
		for _, c := range f.days {
			live.add(c)
		}
		if live.out != want {
			t.Fatalf("%s: the file's own account says %d out, want %d", why, live.out, want)
		}
	}
	tkuWrite(t, file, tkuClaude(at, "m1", "r1", "claude-opus-5-5", 1, 10, 0, 0, 0, 0))
	tokPass(now)
	tkWant(10, "first read")
	// Another file of the same size renamed over it: read from its start.
	next := tkuClaude(at, "m2", "r2", "claude-opus-5-5", 1, 20, 0, 0, 0, 0)
	tmp := file + ".new"
	tkuWrite(t, tmp, next)
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
	tokPass(now)
	tkWant(20, "a file renamed over it")
	// Rewritten in place, longer, with a different start: read again too.
	tkuWrite(t, file, tkuClaude(at, "m3", "r3", "claude-opus-5-5", 1, 30, 0, 0, 0, 0)+tkuClaude(at, "m4", "r4", "claude-opus-5-5", 1, 40, 0, 0, 0, 0))
	tokPass(now)
	tkWant(70, "rewritten in place")
}

func TestTokensFollowASymlinkedConfigDirectory(t *testing.T) {
	home := testHome(t)
	tkuReset(t)
	now := time.Now()
	real := filepath.Join(home, ".claude", "projects")
	tkuWrite(t, filepath.Join(real, "p", "s.jsonl"), tkuClaude(now.Add(-time.Minute), "m1", "r1", "claude-opus-5-5", 1, 10, 0, 0, 0, 0))
	if err := os.MkdirAll(filepath.Join(home, ".config", "claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".config", "claude", "projects")); err != nil {
		t.Skip("no symlinks here:", err)
	}
	got := tkuSum(tokPass(now), "claude", "claude-opus-5-5", true)
	if got.n != 1 || got.out != 10 {
		t.Fatalf("through a symlinked config directory: %+v, want one reply read once", got)
	}
}
