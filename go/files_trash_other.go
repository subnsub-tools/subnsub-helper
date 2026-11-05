//go:build !unix || android

package main

// filesTrash: no trash this helper can put things in. On Android there is
// no system trash a file manager shares. On Windows the Recycle Bin is
// reached through the shell (SHFileOperationW), which deletes for good,
// without a word, whatever it cannot recycle (a network drive, a disk whose
// bin is switched off, a file larger than the bin) once confirmations are
// off, and asks in a dialog nobody at a service's desktop can answer once
// they are on: neither is a trash. The page is told, and nothing is removed.
func filesTrash(string) string { return "trash-unavailable" }
