package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The id must survive a restart, or every restart arrives at the relay as a
// brand new machine and the dashboard multiplies.
func TestAgentIDIsStableAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	first, _ := resolveAgent(dir, "", "")
	if first == "" {
		t.Fatal("no id generated")
	}
	second, _ := resolveAgent(dir, "", "")
	if second != first {
		t.Fatalf("id changed across runs: %q then %q", first, second)
	}
	// And it must actually be on disk, not merely consistent in-process.
	b, err := os.ReadFile(filepath.Join(dir, "agent-id"))
	if err != nil {
		t.Fatalf("id was not persisted: %v", err)
	}
	if strings.TrimSpace(string(b)) != first {
		t.Fatalf("file holds %q, want %q", strings.TrimSpace(string(b)), first)
	}
}

// A generated id has to satisfy the relay's own rule, or the machine silently
// loses its slot and shares the legacy one with everybody else who did.
func TestGeneratedIDPassesTheRelayRule(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		id, _ := resolveAgent(t.TempDir(), "", "")
		if cleanID(id) != id {
			t.Fatalf("generated id %q does not pass cleanID", id)
		}
		if seen[id] {
			t.Fatalf("generated the same id twice: %q", id)
		}
		seen[id] = true
	}
}

// A hand-edited or truncated file must not pin the machine to a value the
// relay will drop.
func TestUnusableIDFileIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-id")
	if err := os.WriteFile(path, []byte("not a valid id!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := resolveAgent(dir, "", "")
	if id == "not a valid id!!" {
		t.Fatal("kept an id the relay would refuse")
	}
	if cleanID(id) != id {
		t.Fatalf("replacement %q does not pass cleanID", id)
	}
	b, _ := os.ReadFile(path)
	if strings.TrimSpace(string(b)) != id {
		t.Fatal("replacement was not written back")
	}
}

// An unwritable config directory is survivable, not fatal: the machine reports
// under a per-process id and says so, rather than refusing to report at all.
func TestUnwritableDirStillYieldsAnID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	if err := os.WriteFile(dir, []byte("i am a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	// MkdirAll on a path whose parent component is a regular file fails.
	id, _ := resolveAgent(filepath.Join(dir, "sub"), "", "")
	if cleanID(id) != id || id == "" {
		t.Fatalf("no usable id from an unwritable directory: %q", id)
	}
}

func TestEnvironmentPinsTheID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent-id"), []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := resolveAgent(dir, "pinned-by-env", "")
	if id != "pinned-by-env" {
		t.Fatalf("env did not win: got %q", id)
	}
	// An env value the relay would refuse falls back to the file rather than
	// travelling as an id nothing accepts.
	id, _ = resolveAgent(dir, "not valid", "")
	if id != "from-the-file" {
		t.Fatalf("a bad env id should fall through to the file, got %q", id)
	}
}

func TestLabelPrecedenceAndPersistence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "name"), []byte("from file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, label := resolveAgent(dir, "", ""); label != "from file" {
		t.Fatalf("file label not read: %q", label)
	}
	if _, label := resolveAgent(dir, "", "from env"); label != "from file" {
		t.Fatalf("saved label must override the install-time environment: %q", label)
	}
	if _, label := resolveAgent(t.TempDir(), "", ""); label != "" {
		t.Fatalf("an unnamed machine should have no label, got %q", label)
	}

	// Pinning the id must not cost the machine its name. The container case —
	// MON_AGENT_ID set because the filesystem does not survive a restart — is
	// exactly where a human-readable name is worth most, and an early return
	// before the label file is read silently threw it away.
	if id, label := resolveAgent(dir, "pinned-by-env", ""); id != "pinned-by-env" || label != "from file" {
		t.Fatalf("pinning the id lost the name: id=%q label=%q", id, label)
	}
}

// Two helpers that started together must not stay in step: they share one
// room, the relay paces the room, and a fixed cadence makes the pair that
// collided once collide on every round forever.
func TestJitterIsBounded(t *testing.T) {
	seen := map[float64]bool{}
	for i := 0; i < 200; i++ {
		v := jitter()
		if v < 0 || v >= 1 {
			t.Fatalf("jitter() = %v, want [0,1)", v)
		}
		seen[v] = true
	}
	if len(seen) < 100 {
		t.Fatalf("jitter() produced only %d distinct values in 200 draws", len(seen))
	}
}

func TestRelayDialPrefersIPv4(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	var networks []string
	dial := func(_ context.Context, network, _ string) (net.Conn, error) {
		networks = append(networks, network)
		if network != "tcp4" {
			return nil, errors.New("unexpected fallback")
		}
		return client, nil
	}

	conn, err := ipv4FirstDialContext(dial, relayIPv4Timeout)(context.Background(), "tcp", "relay.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(networks) != 1 || networks[0] != "tcp4" {
		t.Fatalf("dialled %v, want one tcp4 attempt", networks)
	}
}

func TestRelayDialFallsBackToDualStack(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	var networks []string
	dial := func(_ context.Context, network, _ string) (net.Conn, error) {
		networks = append(networks, network)
		if network == "tcp4" {
			return nil, errors.New("no IPv4 route")
		}
		return client, nil
	}

	conn, err := ipv4FirstDialContext(dial, relayIPv4Timeout)(context.Background(), "tcp", "relay.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(networks) != 2 || networks[0] != "tcp4" || networks[1] != "tcp" {
		t.Fatalf("dialled %v, want tcp4 then ordinary tcp fallback", networks)
	}
}

func TestRelayDialDoesNotFallbackAfterCallerCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var networks []string
	dial := func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		networks = append(networks, network)
		cancel()
		<-dialCtx.Done()
		return nil, dialCtx.Err()
	}

	_, err := ipv4FirstDialContext(dial, relayIPv4Timeout)(ctx, "tcp", "relay.test:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if len(networks) != 1 || networks[0] != "tcp4" {
		t.Fatalf("dialled %v after cancellation; fallback must not start", networks)
	}
}

// The name is the only free text the helper sends. It is repaired rather than
// refused, and every repair here is about what the text can DO on a page or in
// a log — not about what it says.
func TestCleanLabel(t *testing.T) {
	cases := []struct{ in, want, why string }{
		{"tokyo build box", "tokyo build box", "ordinary text is untouched"},
		{"  padded  ", "padded", "trimmed"},
		{"two\nlines", "twolines", "a newline cannot break a log line"},
		{"\x1b[31mred", "[31mred", "an escape introducer cannot colour a terminal"},
		{"\ufeffbox", "box", "invisible padding is dropped"},
		{"a\tb", "a b", "a tab becomes a space rather than vanishing between words"},
		{"", "", "empty stays empty"},
		{"   ", "", "whitespace only is no name"},
		{strings.Repeat("x", 40), strings.Repeat("x", maxLabel), "cut to the documented length"},
	}
	for _, c := range cases {
		if got := cleanLabel(c.in); got != c.want {
			t.Errorf("%s: cleanLabel(%q) = %q, want %q", c.why, c.in, got, c.want)
		}
	}

	// Cut by RUNE. A byte-cut of CJK ends mid-character and puts a replacement
	// glyph on somebody's dashboard.
	long := strings.Repeat("\u4e1c", 40)
	got := cleanLabel(long)
	if n := len([]rune(got)); n != maxLabel {
		t.Errorf("CJK label cut to %d runes, want %d", n, maxLabel)
	}
	if strings.ContainsRune(got, '�') {
		t.Error("CJK label was cut mid-character")
	}
}

func TestCleanID(t *testing.T) {
	good := []string{"AbC-123_xy", "aaaa", strings.Repeat("z", 32)}
	for _, s := range good {
		if cleanID(s) != s {
			t.Errorf("cleanID(%q) rejected a legal id", s)
		}
	}
	bad := []string{"", "abc", strings.Repeat("z", 33), "has space", "a/../b", "café", "a.b"}
	for _, s := range bad {
		if got := cleanID(s); got != "" {
			t.Errorf("cleanID(%q) = %q, want refusal", s, got)
		}
	}
	// Refused, never repaired: an id that gets "fixed" here lands in a slot
	// neither side expects, while an empty one lands in the shared legacy slot,
	// which is visible and is the documented old behaviour.
	if got := cleanID("  spaced-out  "); got != "spaced-out" {
		t.Errorf("surrounding whitespace should be trimmed before judging, got %q", got)
	}
}

func TestSetLabelRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	conf := filepath.Join(dir, ".config", "subnsub-helper")

	if err := setLabel("  tokyo  "); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(conf, "name"))
	if err != nil {
		t.Fatalf("label not written: %v", err)
	}
	if strings.TrimSpace(string(b)) != "tokyo" {
		t.Fatalf("stored %q, want %q", strings.TrimSpace(string(b)), "tokyo")
	}
	// Clearing is persisted, so the old environment cannot resurrect a name.
	if err := setLabel(""); err != nil {
		t.Fatal(err)
	}
	if _, label := resolveAgent(conf, "", "old install name"); label != "" {
		t.Fatalf("clear did not survive restart: %q", label)
	}
}

func TestRunningAgentReadsPersistedRename(t *testing.T) {
	scratchHome(t)
	t.Setenv(labelEnv, "install name")
	if got := agentLabel(); got != "install name" {
		t.Fatalf("bootstrap = %q", got)
	}
	for _, want := range []string{"\u4e1c\u4eac\U0001f680", "second name", ""} {
		if err := setLabel(want); err != nil {
			t.Fatal(err)
		}
		if got := agentLabel(); got != want {
			t.Fatalf("running helper reports %q, want %q", got, want)
		}
		if _, got := resolveAgent(configDir(), "", "install name"); got != want {
			t.Fatalf("fresh process reports %q, want %q", got, want)
		}
	}
	// A failed atomic replacement must neither acknowledge nor lose the name.
	if err := setLabel("keep me"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(configDir(), "name.new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setLabel("lost write"); err == nil {
		t.Fatal("write failure was reported as success")
	}
	if got := agentLabel(); got != "keep me" {
		t.Fatalf("failed write changed live name to %q", got)
	}
}

// The privacy bar from system.go applies to the id too, and this is the
// assertion that keeps it honest: nothing about this machine may be derivable
// from what identifies it.
func TestAgentIDCarriesNoIdentity(t *testing.T) {
	host, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	user := os.Getenv("USER")

	for i := 0; i < 32; i++ {
		id, _ := resolveAgent(t.TempDir(), "", "")
		for _, secret := range []string{host, home, user, filepath.Base(home)} {
			if secret == "" || len(secret) < 3 {
				continue
			}
			if strings.Contains(strings.ToLower(id), strings.ToLower(secret)) {
				t.Fatalf("id %q contains %q", id, secret)
			}
		}
	}
}
