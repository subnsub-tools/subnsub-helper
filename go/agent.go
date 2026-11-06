package main

// Which machine this is — the one piece of identity the helper carries.
//
// One account holds one relay token, and the same token is what you paste on
// every machine you want to watch. Without an id, all of them push into the
// same slot and the page shows whichever one pushed last: three servers look
// like one server with a personality disorder. So each machine gets a handle.
//
// THE HANDLE IS RANDOM, NOT DERIVED. No hostname, no MAC, no machine-id, no
// disk serial, nothing hashed from any of them. That is the same bar the health
// fields clear (see system.go) and it holds here for a reason worth stating: an
// id derived from hardware is a fingerprint that survives reinstalls and can be
// correlated across accounts by whoever ends up holding the relay's storage. An
// id from crypto/rand identifies this install to its own dashboard and to
// nothing else. Delete the file and you get a new machine card; that is the
// whole extent of what it means.
//
// The optional label is different in kind: it is text the OPERATOR typed, on
// purpose, to tell their own machines apart. It is never inferred — in
// particular it is never seeded from the hostname, which would quietly
// reintroduce exactly what the paragraph above rules out.

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// Bounds the page and the relay both assume: a value that fails at the relay is dropped
// on arrival, and a machine that quietly loses its id shares a dashboard with
// every other machine that did the same.
const (
	maxLabel   = 24
	idBytes    = 9 // 12 base64url characters, no padding
	agentIDEnv = "MON_AGENT_ID"
	labelEnv   = "MON_NAME"
)

var agentOnce struct {
	sync.Once
	id string
}

var labelMu sync.RWMutex

// Where the installer keeps the token, and where the id belongs too: one
// directory per install, removed by --uninstall.
//
// os.UserConfigDir is XDG_CONFIG_HOME (or ~/.config) on Linux and
// ~/Library/Application Support on macOS — but the installer writes the token
// to ~/.config on both, so this follows the installer rather than the platform
// convention. Two directories for one install is how a --uninstall leaves
// something behind.
func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	// Either name's (name.go): a machine installed before the rename keeps
	// ~/.config/subnsub-monitor until it is installed again.
	return configDirIn(home)
}

// This machine's stable handle, created on first use.
//
// Failure to persist is NOT fatal and not silent: the process keeps a
// random id for its lifetime and says so once. A restart then arrives as a new
// machine, the old card ages out of the relay on its own, and the operator has
// a line in the log explaining why the dashboard multiplied — which beats
// refusing to report at all on a box with a read-only home directory.
func agentID() string {
	loadAgent()
	return agentOnce.id
}

// The operator's name for this machine, or "" if they never set one. The page
// falls back to the id, so an unnamed machine is unlabelled, not anonymous-
// looking-broken.
func agentLabel() string {
	loadAgent()
	labelMu.RLock()
	defer labelMu.RUnlock()
	return readLabel(configDir(), os.Getenv(labelEnv))
}

// A saved name is the operator's current configuration, including an explicit
// empty name. The install-time environment is only a bootstrap default.
func readLabel(dir, envLabel string) string {
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "name")); err == nil {
			return cleanLabel(string(b))
		}
	}
	return cleanLabel(envLabel)
}

func loadAgent() {
	agentOnce.Do(func() {
		agentOnce.id, _ = resolveAgent(configDir(),
			os.Getenv(agentIDEnv), os.Getenv(labelEnv))
	})
}

// The whole decision, with the machine's state passed in rather than read
// from the process — which is what makes it testable without a real HOME.
//
// ID precedence (names use readLabel), and each step has a reason:
//  1. the environment, so a container image or a config-management run can pin
//     the identity of a machine whose filesystem does not survive a restart;
//  2. the file, which is the ordinary case;
//  3. a fresh id, saved if the directory will take it.
func resolveAgent(dir, envID, envLabel string) (id, label string) {
	// The label is settled FIRST, before any early return. It used to be read
	// only on the path that reads the id file, so pinning MON_AGENT_ID — the
	// container case, exactly where a name is most useful — silently threw away
	// the name that `--name` had installed.
	label = readLabel(dir, envLabel)

	if v := cleanID(envID); v != "" {
		return v, label
	}
	if dir == "" {
		warnf("no home directory: this machine's id will change on restart")
		return newID(), label
	}

	path := filepath.Join(dir, "agent-id")
	if b, err := os.ReadFile(path); err == nil {
		if v := cleanID(strings.TrimSpace(string(b))); v != "" {
			return v, label
		}
		// Present but unusable — truncated write, hand-edited, whatever.
		// Overwrite it rather than carry a value the relay will reject.
	}

	id = newID()
	if err := writeID(dir, path, id); err != nil {
		warnf("could not save this machine's id: it will change on restart")
	}
	return id, label
}

func writeID(dir, path, id string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Write-then-rename, the same shape the installer uses for the token: a
	// plain create would follow a symlink to wherever it points and can leave
	// a half-written file behind if the process dies mid-write.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Save the operator's name for this machine. Written next to the id so
// --uninstall takes both, and cleaned first so the file can never hold
// something the relay would refuse.
func setLabel(s string) error {
	labelMu.Lock()
	defer labelMu.Unlock()
	dir := configDir()
	if dir == "" {
		return os.ErrNotExist
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "name")
	label := cleanLabel(s)
	// Keep an empty file when clearing: deleting it would resurrect MON_NAME.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(label+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newID() string {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		// Same judgement as the token: a predictable id is worse than none.
		// Returning "" makes this machine push without one, which lands it in
		// the shared default slot — visibly wrong rather than quietly colliding
		// with somebody else's card.
		warnf("system RNG unavailable: this machine will report without an id")
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// The alphabet the relay accepts. Anything else is not repaired, it is
// refused — an id that survives here but is dropped on arrival is worse than
// no id, because the machine then shares the default slot without saying so.
func cleanID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 4 || len(s) > 32 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return ""
		}
	}
	return s
}

// A label is free text from a human, so it is repaired rather than refused —
// a stray newline should not cost someone their machine name.
//
// Control characters go first: they are what turns a label into a line break
// in a log, a terminal escape in a shell that cats the config, or an invisible
// prefix on a dashboard. Then it is cut to a length the page can lay out.
// Cutting by RUNE, not by byte, because a byte-cut of a CJK label ends
// mid-character and produces a replacement glyph.
func cleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || r == '\ufeff' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) > maxLabel {
		s = strings.TrimSpace(string(runes[:maxLabel]))
	}
	return s
}
