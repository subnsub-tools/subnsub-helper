//go:build !windows && !darwin

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// The account's Pictures and Desktop: the XDG folders where the desktop
// names them (translated on many systems), else the usual names.
func photosPicturesDir(home string) string {
	return photosXDG(home, "XDG_PICTURES_DIR", "Pictures")
}

func photosDesktopDir(home string) string {
	return photosXDG(home, "XDG_DESKTOP_DIR", "Desktop")
}

func photosXDG(home, key, fallback string) string {
	conf := os.Getenv("XDG_CONFIG_HOME")
	if conf == "" {
		conf = filepath.Join(home, ".config")
	}
	if f, err := os.Open(filepath.Join(conf, "user-dirs.dirs")); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, key+"=") {
				continue
			}
			v := strings.Trim(strings.TrimPrefix(line, key+"="), `"`)
			v = strings.Replace(v, "$HOME", home, 1)
			if filepath.IsAbs(v) && filepath.Clean(v) != filepath.Clean(home) {
				return filepath.Clean(v)
			}
		}
	}
	return filepath.Join(home, fallback)
}
