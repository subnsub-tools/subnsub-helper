//go:build windows

package main

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The account's Pictures and Desktop known folders, wherever they were moved
// to (OneDrive moves them), else the usual ones in the profile.
func photosPicturesDir(home string) string {
	return photosKnown(windows.FOLDERID_Pictures, filepath.Join(home, "Pictures"))
}

func photosDesktopDir(home string) string {
	return photosKnown(windows.FOLDERID_Desktop, filepath.Join(home, "Desktop"))
}

func photosKnown(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
		return p
	}
	return fallback
}
