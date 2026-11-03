//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// musicDefaultDir is this account's Music known folder, wherever it was
// moved to (OneDrive moves it), else %USERPROFILE%\Music. "" when there is
// none.
func musicDefaultDir() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_Music, 0); err == nil && p != "" {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		p := filepath.Join(home, "Music")
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	return ""
}
