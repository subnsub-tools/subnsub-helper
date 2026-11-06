package main

/* ── the helper's name, and the one it had ──

   2026-11-06 the helper was renamed subnsub-monitor → subnsub-helper: the
   binary, its directory under ~/.config, its service, the published files
   and the public repository. The dashboard and the relay are still Monitor.

   A machine installed before keeps its old names until it is installed
   again: the binary at ~/.local/bin/subnsub-monitor, ~/.config/subnsub-monitor,
   subnsub-monitor.service / com.subnsub.monitor / /etc/init.d/subnsub-monitor.
   An update replaces the file in place and changes none of that, so this
   build runs from either, and never moves an install's directory itself:
   only install.sh does, with the service stopped.

   What does not change with the name, because it is part of a protocol
   rather than a label: the salts tailnet.go and econ.go derive keys with,
   and the domain the adapter feed is signed under (adapterfeed.go). */

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	helperName = "subnsub-helper"
	legacyName = "subnsub-monitor"
)

// configDirIn is the install's directory under home: the new name's where it
// is there, else the old name's where that is, else the new name's (a first
// install, which install.sh makes).
func configDirIn(home string) string {
	cur := filepath.Join(home, ".config", helperName)
	if st, err := os.Stat(cur); err == nil && st.IsDir() {
		return cur
	}
	old := filepath.Join(home, ".config", legacyName)
	if st, err := os.Stat(old); err == nil && st.IsDir() {
		return old
	}
	return cur
}

// installName is the name this install's own things go by: the old one on
// a machine installed before the rename and not since.
func installName() string {
	if dir := configDir(); dir != "" && filepath.Base(dir) == legacyName {
		return legacyName
	}
	return helperName
}

// systemdUnit is this install's user unit, under either name, and its text;
// "" where there is none (not a systemd install).
func systemdUnit(home string) (string, []byte) {
	for _, n := range []string{installName(), helperName, legacyName} {
		p := filepath.Join(home, ".config", "systemd", "user", n+".service")
		if b, err := os.ReadFile(p); err == nil {
			return p, b
		}
	}
	return "", nil
}

// bridgeLegacyName puts a subnsub-helper link beside a binary still called
// subnsub-monitor, so the commands the pages now name (subnsub-helper
// console on, …) work on a machine installed before the rename. Once, at
// the start of a long run; quietly, since a sandboxed service cannot write
// there and a machine without it has lost nothing it had.
func bridgeLegacyName() {
	if runtime.GOOS == "windows" {
		return
	}
	self, err := os.Executable()
	if err != nil || self == "" {
		return
	}
	if real, err := filepath.EvalSymlinks(self); err == nil && real != "" {
		self = real
	}
	if filepath.Base(self) != legacyName {
		return
	}
	link := filepath.Join(filepath.Dir(self), helperName)
	if _, err := os.Lstat(link); err == nil || !os.IsNotExist(err) {
		return
	}
	os.Symlink(legacyName, link)
}
