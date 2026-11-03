//go:build !windows

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// musicDefaultDir is this account's own Music folder: the XDG music
// directory where the desktop names one (it is translated on many systems),
// else ~/Music. "" when there is none.
func musicDefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	conf := os.Getenv("XDG_CONFIG_HOME")
	if conf == "" {
		conf = filepath.Join(home, ".config")
	}
	if f, err := os.Open(filepath.Join(conf, "user-dirs.dirs")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "XDG_MUSIC_DIR=") {
				continue
			}
			v := strings.Trim(strings.TrimPrefix(line, "XDG_MUSIC_DIR="), `"`)
			v = strings.Replace(v, "$HOME", home, 1)
			if filepath.IsAbs(v) && filepath.Clean(v) != filepath.Clean(home) {
				if fi, err := os.Stat(v); err == nil && fi.IsDir() {
					f.Close()
					return v
				}
			}
		}
		f.Close()
	}
	p := filepath.Join(home, "Music")
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return p
	}
	return ""
}
