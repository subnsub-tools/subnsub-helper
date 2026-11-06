//go:build unix

// The end-to-end update tests, and they are Unix-only for two reasons that are
// both about the thing being tested rather than about convenience.
//
// The fake releases here are `#!/bin/sh` scripts standing in for a binary, so
// the probe step ("run it and ask its version") has something to run without a
// compiler in the test. And the central invariant below — that the service path
// is never empty for an instant — is one only this platform can offer: Windows
// cannot replace a running image in place and has to move it aside first. See
// update_windows.go, which says so at length and guarantees the weaker property
// it can actually keep.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// A release bucket, standing on its own two feet: the manifest is generated
// from the bytes actually served, so a test cannot pass by having both sides
// wrong in the same way.
type fakeRelease struct {
	version string
	binary  []byte
	sums    string // overrides the generated manifest when non-empty
	hits    map[string]int
	srv     *httptest.Server
}

func newRelease(t *testing.T, version, script string) *fakeRelease {
	t.Helper()
	r := &fakeRelease{version: version, binary: []byte(script), hits: map[string]int{}}
	sum := sha256.Sum256(r.binary)
	asset := "subnsub-helper-" + runtime.GOOS + "-" + runtime.GOARCH
	r.sums = hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits[req.URL.Path]++
		switch req.URL.Path {
		case "/VERSION":
			w.Write([]byte(r.version + "\n"))
		case "/SHA256SUMS":
			w.Write([]byte(r.sums))
		case "/" + asset:
			w.Write(r.binary)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// A stand-in for the new helper. Executable, and it answers `version` the way
// the real one does — which is the whole of what the update path asks of it.
func versionScript(v string) string {
	return "#!/bin/sh\n[ \"$1\" = version ] && echo " + v + "\n"
}

// An installed helper: a file at a path, with the old contents.
func installed(t *testing.T) string {
	t.Helper()
	self := filepath.Join(t.TempDir(), "subnsub-helper")
	if err := os.WriteFile(self, []byte(versionScript("0001.01.01.1")), 0o755); err != nil {
		t.Fatal(err)
	}
	return self
}

func TestUpdateInstallsAVerifiedRelease(t *testing.T) {
	self := installed(t)
	rel := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))

	res, swap := updateFrom("cmd1", self, rel.srv.URL)
	if !swap {
		t.Fatalf("should have swapped; report was:\n%s", res.Out)
	}
	if res.Code != 0 || res.Error != "" {
		t.Fatalf("code=%d error=%q", res.Code, res.Error)
	}
	// The report has to go out BEFORE the caller exits, and it has to say what
	// happened — this is the only account of it the operator will ever get.
	if !strings.Contains(res.Out, "2999.12.31.9") {
		t.Fatalf("the report does not name the version installed:\n%s", res.Out)
	}

	got, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != versionScript("2999.12.31.9") {
		t.Fatalf("the binary in place is not the new one: %q", got)
	}
	// Executable, or the service comes back to a file it cannot start.
	if st, err := os.Stat(self); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("not executable: %v %v", st.Mode(), err)
	}
	// And the outgoing one is kept, under a name nothing will run by accident.
	if _, err := os.Stat(self + ".prev"); err != nil {
		t.Fatalf("no .prev kept: %v", err)
	}
	// Nothing staged is left lying around next to the binary.
	ents, _ := os.ReadDir(filepath.Dir(self))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".subnsub-helper-") {
			t.Fatalf("left a staged file behind: %s", e.Name())
		}
	}
}

// There must be no instant at which nothing exists at the service path.
//
// The first version of this renamed the running binary aside and then renamed
// the new one in, which leaves a hole between the two: a kill or a power cut
// inside it leaves a machine whose ExecStart names a file that is not there —
// a helper not merely un-updated but gone, on a box with no route to it. The
// backup is a second NAME for the old inode, so the install is one atomic
// rename over a path that was never vacant.
func TestUpdateNeverLeavesTheServicePathEmpty(t *testing.T) {
	self := installed(t)
	old, _ := os.ReadFile(self)
	rel := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))

	// The old inode's identity, so "the backup is the same file" is checked
	// rather than assumed from its contents.
	var oldIno uint64
	if st, err := os.Stat(self); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			oldIno = sys.Ino
		}
	}

	if _, swap := updateFrom("cmd1", self, rel.srv.URL); !swap {
		t.Fatal("no swap")
	}

	// The backup is the SAME inode the service was running, not a re-download.
	if st, err := os.Stat(self + ".prev"); err != nil {
		t.Fatalf(".prev: %v", err)
	} else if sys, ok := st.Sys().(*syscall.Stat_t); ok && oldIno != 0 && sys.Ino != oldIno {
		t.Fatal(".prev is not the inode that was running")
	}
	if got, _ := os.ReadFile(self + ".prev"); string(got) != string(old) {
		t.Fatal(".prev does not hold the outgoing build")
	}
	// And the live path holds the new one, on a different inode.
	if got, _ := os.ReadFile(self); string(got) == string(old) {
		t.Fatal("the service path still holds the old build")
	}
}

// A rename that fails must leave the machine running what it was running, with
// no orphan backup implying an install that did not happen.
func TestUpdateLeavesNothingBehindWhenTheInstallFails(t *testing.T) {
	self := installed(t)
	old, _ := os.ReadFile(self)
	rel := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))

	// A directory at the destination, so the install cannot succeed and fails
	// at the last possible moment — after the download, the checksum and the
	// smoke run, in the few lines where something has already been written.
	// (This one lands on the backup step, which caught a real leak: the copy
	// fallback created its destination before discovering it could not fill
	// it, leaving an empty .prev that looks like a restorable helper.)
	blocker := self + ".blocked"
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	res, swap := updateFrom("cmd1", blocker, rel.srv.URL)
	if swap {
		t.Fatal("claimed to have installed over a directory")
	}
	if res.Error != "update-failed" {
		t.Fatalf("error=%q out=%s", res.Error, res.Out)
	}
	if _, err := os.Stat(blocker + ".prev"); err == nil {
		t.Fatal("left a backup behind for an install that never happened")
	}
	// The real binary, untouched throughout.
	if now, _ := os.ReadFile(self); string(now) != string(old) {
		t.Fatal("touched the installed binary")
	}
}

// The check the whole exercise exists for. A binary whose bytes are not the
// published ones must not be installed, and the machine must be left running
// exactly what it was running.
func TestUpdateRefusesAChecksumMismatch(t *testing.T) {
	self := installed(t)
	before, _ := os.ReadFile(self)
	rel := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	// The manifest now describes something else — the shape of a swapped
	// binary, or of a bucket where one object was replaced and one was not.
	rel.sums = strings.Repeat("a", 64) + "  subnsub-helper-" +
		runtime.GOOS + "-" + runtime.GOARCH + "\n"

	res, swap := updateFrom("cmd1", self, rel.srv.URL)
	if swap {
		t.Fatal("installed a binary that did not match the manifest")
	}
	if res.Error != "update-failed" {
		t.Fatalf("error=%q", res.Error)
	}
	if !strings.Contains(res.Out, "checksum mismatch") {
		t.Fatalf("did not say why:\n%s", res.Out)
	}
	if now, _ := os.ReadFile(self); string(now) != string(before) {
		t.Fatal("the installed binary was touched")
	}
	if _, err := os.Stat(self + ".prev"); err == nil {
		t.Fatal("moved the old binary aside for an update that never happened")
	}
}

// Only forward. A bucket serving an older version is a rollback nobody asked
// this button for, and it must not cost a download either.
func TestUpdateWillNotGoBackwardsOrSideways(t *testing.T) {
	asset := "subnsub-helper-" + runtime.GOOS + "-" + runtime.GOARCH
	for _, v := range []string{"0000.01.01.1", helperVersion} {
		self := installed(t)
		rel := newRelease(t, v, versionScript(v))
		res, swap := updateFrom("cmd1", self, rel.srv.URL)
		if swap {
			t.Fatalf("%s: swapped", v)
		}
		// Reported as a SUCCESS with nothing to do, not as a failure: pressing
		// update on a machine that is already current is a reasonable thing to
		// have done and is not an error to be alarmed by. Marked distinctly all
		// the same, because the page must not promise a restart that is not
		// coming.
		if res.Code != 0 || res.Error != "update-none" {
			t.Fatalf("%s: code=%d error=%q", v, res.Code, res.Error)
		}
		if !strings.Contains(res.Out, "already up to date") {
			t.Fatalf("%s: %s", v, res.Out)
		}
		if rel.hits["/"+asset] != 0 {
			t.Fatalf("%s: downloaded the binary anyway", v)
		}
	}
}

// The last gate before the rename: the bytes are the published ones, but do
// they run HERE, and are they what the release claimed? A build for the wrong
// architecture passes every earlier check and fails only at this one — and
// failing here is a machine that keeps working, where failing after the rename
// is a service that no longer starts on a box with no route to it.
func TestUpdateRefusesABinaryThatWillNotRunOrLies(t *testing.T) {
	t.Run("does not run", func(t *testing.T) {
		self := installed(t)
		// Not a program: no interpreter line, no ELF header.
		rel := newRelease(t, "2999.12.31.9", "\x7fnot an executable at all")
		res, swap := updateFrom("cmd1", self, rel.srv.URL)
		if swap {
			t.Fatal("installed something that cannot be executed")
		}
		if !strings.Contains(res.Out, "would not run here") {
			t.Fatalf("%s", res.Out)
		}
		if _, err := os.Stat(self + ".prev"); err == nil {
			t.Fatal("moved the old binary aside anyway")
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		self := installed(t)
		// Published as one version, reports another. A release process that
		// stamped VERSION from a stale constant looks exactly like this, and
		// installing it would leave a machine that asks to be updated to a
		// version it already has, forever.
		rel := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.8"))
		res, swap := updateFrom("cmd1", self, rel.srv.URL)
		if swap {
			t.Fatal("installed a binary that disagrees with the release")
		}
		if !strings.Contains(res.Out, "calls itself") {
			t.Fatalf("%s", res.Out)
		}
	})
}

// A version string decides which URL is fetched and what the downloaded binary
// is held to. Anything that is not digits and dots stops the whole thing here,
// before a single byte of payload has been requested.
func TestUpdateRefusesAnUnusablePublishedVersion(t *testing.T) {
	asset := "subnsub-helper-" + runtime.GOOS + "-" + runtime.GOARCH
	self := installed(t)
	rel := newRelease(t, "../../../etc/passwd", versionScript("2999.12.31.9"))
	res, swap := updateFrom("cmd1", self, rel.srv.URL)
	if swap {
		t.Fatal("acted on a version that is not one")
	}
	if !strings.Contains(res.Out, "not a version") {
		t.Fatalf("%s", res.Out)
	}
	if rel.hits["/SHA256SUMS"] != 0 || rel.hits["/"+asset] != 0 {
		t.Fatal("kept going after refusing the version")
	}
}

// A platform with no published build gets a clear answer rather than a
// checksum error about a file that was never going to exist.
func TestUpdateSaysSoWhenThisPlatformHasNoBuild(t *testing.T) {
	self := installed(t)
	rel := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	rel.sums = strings.Repeat("b", 64) + "  subnsub-helper-plan9-mips\n"
	res, swap := updateFrom("cmd1", self, rel.srv.URL)
	if swap {
		t.Fatal("swapped")
	}
	if !strings.Contains(res.Out, "no published build") {
		t.Fatalf("%s", res.Out)
	}
}

// The report is the only thing that survives a successful update, so every
// path has to produce one — including the ones that fell over early.
func TestUpdateAlwaysReportsSomething(t *testing.T) {
	self := installed(t)
	// A base URL that answers nothing.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	res, swap := updateFrom("cmd1", self, dead.URL)
	if swap {
		t.Fatal("swapped")
	}
	if res.ID != "cmd1" {
		t.Fatalf("lost the correlation id: %q", res.ID)
	}
	if strings.TrimSpace(res.Out) == "" {
		t.Fatal("reported nothing at all")
	}
	if res.Error != "update-failed" {
		t.Fatalf("error=%q", res.Error)
	}
}
