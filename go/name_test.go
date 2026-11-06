//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDirUnderEitherName(t *testing.T) {
	home := t.TempDir()
	cur := filepath.Join(home, ".config", helperName)
	old := filepath.Join(home, ".config", legacyName)
	if got := configDirIn(home); got != cur {
		t.Fatalf("a first install: %s, want %s", got, cur)
	}
	os.MkdirAll(old, 0o700)
	if got := configDirIn(home); got != old {
		t.Fatalf("installed before the rename: %s, want %s", got, old)
	}
	os.MkdirAll(cur, 0o700)
	if got := configDirIn(home); got != cur {
		t.Fatalf("both there: %s, want the new one %s", got, cur)
	}
	// A file under the new name is not a directory to use.
	os.RemoveAll(cur)
	os.WriteFile(cur, nil, 0o600)
	if got := configDirIn(home); got != old {
		t.Fatalf("a file under the new name: %s, want %s", got, old)
	}
}

func TestInstallNameFollowsTheDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if n := installName(); n != helperName {
		t.Fatalf("a first install is %s", n)
	}
	os.MkdirAll(filepath.Join(home, ".config", legacyName), 0o700)
	if n := installName(); n != legacyName {
		t.Fatalf("an install from before the rename is %s", n)
	}
	unit := filepath.Join(home, ".config", "systemd", "user", legacyName+".service")
	os.MkdirAll(filepath.Dir(unit), 0o700)
	os.WriteFile(unit, []byte("[Unit]\n"), 0o600)
	if p, b := systemdUnit(home); p != unit || string(b) != "[Unit]\n" {
		t.Fatalf("its unit: %q %q", p, b)
	}
}
