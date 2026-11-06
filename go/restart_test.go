package main

import "testing"

// The updater's one job on the way out, and the reason it has one.
//
// os.Executable() is asked AFTER the rename in every caller, and after the
// rename it cannot answer: the dentry this process was executed from has been
// replaced, so Linux reports the path with " (deleted)" appended. Whatever
// restartSelf execs has to come from a note the updater left while the answer
// was still true.
func TestInstalledPathSurvivesTheSwapThatHidesIt(t *testing.T) {
	t.Cleanup(func() { noteInstalledAt("") })

	if got := installedAt(); got != "" {
		t.Fatalf("nothing installed yet, want %q, got %q", "", got)
	}
	noteInstalledAt("/home/box/.local/bin/subnsub-helper")
	if got, want := installedAt(), "/home/box/.local/bin/subnsub-helper"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	// A second update in the same process — the tunnel path can deliver one
	// while the mailbox path is still winding down — must not leave the first
	// answer standing.
	noteInstalledAt("/opt/bin/subnsub-helper")
	if got, want := installedAt(), "/opt/bin/subnsub-helper"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}
