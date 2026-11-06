package main

// Replacing this helper's own binary, when the dashboard asks it to.
//
// One sentence holds the whole design: THE DASHBOARD DECIDES WHEN, THE RELEASE
// BUCKET DECIDES WHAT. Those are deliberately not the same authority. A relay
// that has been taken over can make a machine update — and everything that
// machine will do about it is fetch the version genuinely published at
// updateBase, check it against the manifest published beside it, and run that.
// It cannot be pointed somewhere else, because no byte of the payload comes
// from the relay: the base URL is a constant in this file and there is no
// parameter, header or command field that moves it.
//
// There was no timer here until 2026-09-12, and the reason still shapes the
// one there is now: a helper that goes looking for releases on its own is a
// permanent, unattended download-and-execute channel, which is strictly
// more authority than the button grants. So the timer is its OWN switch
// (autoupdate), off until an operator turns it on at the machine, and it
// counts only on a machine that already allows remote updates — a switch
// that says "and you need not press the button" cannot mean anything on a
// machine that never granted the button. What it installs is what the
// button installs: the release bucket decides, the checksum decides, and
// the timer decides only WHEN — once an hour, whether anything is new.
//
// And why the report goes out BEFORE the process exits: this is the one
// command whose success kills the thing that would have reported it. Swapping
// the binary and then trying to say so would lose the message in exactly the
// case where the swap worked — leaving an operator watching a machine go quiet
// with no way to tell a completed update from a helper that died.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Where releases live. Constants, never a value taken from the relay or
	// from the command — see the note above about who decides what.
	//
	// The public repository's releases first: the binaries and SHA256SUMS
	// published there are the ones anybody can check against the source, so
	// a release changed on this site alone is not installed by a machine that
	// can reach GitHub (user 2026-11-06). This site second, for a machine that
	// cannot: asked at once when somebody presses Update, and by the hourly
	// look only once GitHub has been out of reach for updateGitHubGrace. A
	// GitHub that answers — with a checksum that does not match, or without
	// the version yet — is never a reason to ask this site instead.
	updateGitHub = "https://github.com/subnsub-tools/subnsub-helper/releases"
	updateBase   = "https://tools.subnsub.com/monitor"
	// Since when GitHub has been out of reach, in the install's directory.
	updateGitHubDownFile = "update-github-down"
	updateGitHubGrace    = 6 * time.Hour
	updateGitHubHeaders  = time.Minute
	// Overridable from this machine's own environment, for testing against a
	// local copy. Same precedence rule as every other switch here: the
	// environment belongs to whoever started the process, which is someone who
	// already had a shell on this box.
	updateBaseEnv = "MON_UPDATE_BASE"

	// The opt-in for a machine whose console is OFF. Existence is the setting,
	// like the console file and for the same reason: a switch whose meaning
	// depends on whether it says "0" or "false" is one somebody gets wrong in
	// the direction that leaves it on.
	updateFileName = "update"
	updateEnvVar   = "MON_UPDATE"
	// The timer's own switch (see the top): existence is the setting, and
	// it counts only alongside updateAllowed.
	autoUpdateFileName = "autoupdate"
	autoUpdateEnvVar   = "MON_AUTOUPDATE"
	// How often the timer asks the bucket what is published — one small GET.
	// Spread across the fleet by the first delay below, so a release is not
	// met by every machine at the same minute.
	autoUpdateEvery = time.Hour
	// After a pass that could not reach or finish the download.
	autoUpdateRetry = 15 * time.Minute
	// Before the first look: long enough that a machine which has just been
	// installed or updated is settled, and different on every machine.
	autoUpdateFirstMin = 3 * time.Minute
	autoUpdateFirstMax = 10 * time.Minute
	// A nudge from the relay (hint.go: the push response said a newer helper
	// is published) starts a pass at once instead of at the hour — but not
	// more often than this, so a release the download refuses cannot make a
	// machine hammer the bucket on every push.
	updateNudgeMin = 10 * time.Minute

	// The whole operation, end to end, and it has to be ONE budget rather than
	// a per-request one.
	//
	// http.Client.Timeout applies to each request separately, so three requests
	// at five minutes each is a fifteen-minute update — which outlives the
	// relay's window for relaying the result (UPD_ISSUED_TTL) and the page's
	// for waiting on it (UPD_WAIT). The update would succeed and be reported to
	// nobody. Every downstream deadline is set against THIS number, so this is
	// the one that must stay the smallest.
	updateBudget = 8 * time.Minute
	// A per-request backstop as well, for a connection that goes silent
	// without the context noticing.
	updateTimeout = 5 * time.Minute
	// The new binary has to prove it runs before it is installed, and a binary
	// that hangs on `version` must not hang this helper.
	updateProbeTimeout = 10 * time.Second
	// Nothing published here is remotely this large. It exists so a replaced or
	// redirected endpoint cannot fill the disk before the checksum gets a say.
	updateMaxBytes = 64 << 20
	// The two small text files beside the binaries.
	updateMaxText = 64 << 10
)

// May the dashboard replace this helper?
//
// The console file counts on its own, and that is not a shortcut. A machine
// with the console on has already granted the dashboard arbitrary /bin/sh as
// this user, and `curl …/install.sh | sh` typed at that prompt IS this
// operation with fewer checks and no audit line. Refusing the narrow version
// of something already permitted in its broadest form would be theatre.
//
// The separate file is for the other machine: console off, but willing to be
// upgraded. That one is a genuinely new grant — a relay that can reach a
// machine which otherwise takes no instruction at all — so it gets its own
// switch, set here, off until then.
func updateAllowed() bool {
	// An explicit environment setting wins outright, including over the
	// console. Note what "off" does and does not buy: it removes the button,
	// not the console's own power to do the same thing by hand.
	if v := strings.TrimSpace(os.Getenv(updateEnvVar)); v != "" {
		return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
	}
	if consoleEnabled() {
		return true
	}
	dir := configDir()
	if dir == "" {
		return false
	}
	// Every error is a no, for the same reason it is in consoleEnabled: there
	// is no failure here that means "probably fine".
	st, err := os.Stat(filepath.Join(dir, updateFileName))
	return err == nil && st.Mode().IsRegular()
}

// May this helper replace itself WITHOUT being asked? Only on a machine that
// allows remote updates at all: the file alone grants nothing, so `update
// off` (or MON_UPDATE=off) takes the timer with it, whatever this file says.
func autoUpdateEnabled() bool {
	if !updateAllowed() {
		return false
	}
	if v := strings.TrimSpace(os.Getenv(autoUpdateEnvVar)); v != "" {
		return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
	}
	dir := configDir()
	if dir == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(dir, autoUpdateFileName))
	return err == nil && st.Mode().IsRegular()
}

// Turn the timer's switch on or off, from the command line on the machine.
func setAutoUpdate(on bool) error {
	dir := configDir()
	if dir == "" {
		return os.ErrNotExist
	}
	path := filepath.Join(dir, autoUpdateFileName)
	if !on {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("on\n"), 0o600)
}

// The timer. Runs beside the push loop for the life of the process and
// re-reads its switch on every pass, so `autoupdate off` (or `update off`)
// takes effect within the hour without a restart. Each pass is the button's
// own path — runUpdate, behind the same one-at-a-time gate a pressed update
// takes — and a pass that finds the bucket current costs one GET. A swap
// hands over to the new binary exactly as a pressed update does; there is
// nobody to report to but this machine's own log, which runUpdate already
// writes.
var autoUpdateOnce sync.Once

// What the reading says about the timer: when its next pass is due, and how the last one
// ended — so a card can say "next check in 23 min" or "last check could not
// reach the download" instead of leaving a behind machine looking stuck.
//
// It is also the machine's own word on a PRESSED update. The result frame is one HTTP answer over one tunnel, and the
// tunnel can drop before it lands — leaving the page to guess whether the
// update happened. The reading cannot be lost that way: it is sent again
// every thirty seconds by whichever binary is running, so "installing" goes
// into it the moment the press is taken, the outcome the moment it is known,
// and — the one the old process cannot say — "installed" is said by the NEW
// process on its way up (noteInstalledFrom), naming the version it replaced.
type updateLast struct {
	At     int64  `json:"at"`
	Result string `json:"result"` // current | installing | installed | unreachable | failed | off
	// The version that was running before, on `installed` only.
	From string `json:"from,omitempty"`
}

// The environment line the outgoing binary leaves for its successor across
// the exec (restart.go): the version it was. The successor reads it once at
// start and says "installed" from it. Environment and not a file, because it
// lives exactly as long as the handover does — a file would have to be
// cleaned up, and a stale one would announce an update that never happened.
const updatedFromEnv = "MON_UPDATED_FROM"

var updState struct {
	sync.Mutex
	next  time.Time
	last  *updateLast
	nudge chan struct{}
	ran   time.Time // when a nudge last started a pass
}

func init() { updState.nudge = make(chan struct{}, 1) }

// updateSnapshot: the next pass as unix seconds (0 while the timer is off or
// has not started), and the last pass.
func updateSnapshot() (int64, *updateLast) {
	updState.Lock()
	defer updState.Unlock()
	var next int64
	if !updState.next.IsZero() && autoUpdateEnabled() {
		next = updState.next.Unix()
	}
	return next, updState.last
}

func noteUpdatePass(result string) {
	updState.Lock()
	updState.last = &updateLast{At: time.Now().Unix(), Result: result}
	updState.Unlock()
}

// noteInstalledFrom: the first thing a freshly exec'd binary says about
// updates. If the process that handed over left its version in the
// environment (restart_unix.go), the reading opens with "installed, from
// <that version>" — the one outcome the old process could never report
// itself, since reporting it would have meant still being the old process.
// Read once and unset, so a child this process spawns does not inherit a
// claim about a handover it took no part in.
func noteInstalledFrom() {
	from := strings.TrimSpace(os.Getenv(updatedFromEnv))
	if from == "" {
		return
	}
	os.Unsetenv(updatedFromEnv)
	if from == helperVersion {
		// A handover that landed on the same version is not an update.
		return
	}
	updState.Lock()
	updState.last = &updateLast{At: time.Now().Unix(), Result: "installed", From: from}
	updState.Unlock()
	warnf("update: now running %s (was %s)", helperVersion, from)
	wakePush()
}

// nudgeUpdate: the relay said a newer helper is published. Wakes the timer
// for one pass now, at most once per updateNudgeMin, and only while the
// operator has the timer on — the relay cannot switch it on.
func nudgeUpdate() {
	if !autoUpdateEnabled() {
		return
	}
	updState.Lock()
	recent := !updState.ran.IsZero() && time.Since(updState.ran) < updateNudgeMin
	updState.Unlock()
	if recent {
		return
	}
	select {
	case updState.nudge <- struct{}{}:
	default:
	}
}

// startAutoUpdate begins the timer once per process, whichever road the
// daemon runs on — the relay push loop or the tunnel alone (a direct-only
// install has no relay loop, and its snapshot would otherwise say auto:true
// for a timer that never ran).
//
// Also where the process reads what its predecessor left for it
// (noteInstalledFrom): the same once-per-process, every-daemon-mode place.
func startAutoUpdate() {
	autoUpdateOnce.Do(func() {
		noteInstalledFrom()
		// Said once at start, in the log, where a person looking for why a
		// download crawls will find it: which namespace this is.
		if ni := netnsInfo(); ni != nil && ni.Count > 1 {
			warnf("%s", netnsSay())
		}
		startRoads()
		go autoUpdateLoop()
	})
}

func autoUpdateLoop() {
	wait := autoUpdateFirstMin + time.Duration(jitter()*float64(autoUpdateFirstMax-autoUpdateFirstMin))
	for {
		updState.Lock()
		updState.next = time.Now().Add(wait)
		updState.Unlock()
		// The hour, or a nudge from the relay — whichever comes first.
		nudged := false
		select {
		case <-time.After(wait):
		case <-updState.nudge:
			nudged = true
		}
		if nudged {
			updState.Lock()
			updState.ran = time.Now()
			updState.Unlock()
		}
		if autoUpdateEnabled() && acquireCmd(context.Background()) {
			// Read again with the gate held: the wait above can be as long
			// as a shell command, and `autoupdate off` typed during it means
			// now, not after one more install.
			if !autoUpdateEnabled() {
				releaseCmd()
				noteUpdatePass("off")
			} else {
				res, swap := runUpdate("auto")
				switch {
				case swap:
					noteUpdatePass("installing")
				case res.Error == "update-failed" && strings.Contains(res.Out, "could not read the published version"):
					warnf("autoupdate: not installed this time; next look in an hour")
					noteUpdatePass("unreachable")
				case res.Error == "update-failed":
					warnf("autoupdate: not installed this time; next look in an hour")
					noteUpdatePass("failed")
				default:
					noteUpdatePass("current")
				}
				if swap {
					// The gate stays held through the handover: releasing
					// it first would let a queued command start running in
					// a process about to be replaced mid-way. restartSelf
					// returns only when the handover did not happen, and
					// then the gate is given back and this image carries on.
					restartSelf()
				}
				releaseCmd()
			}
		} else {
			noteUpdatePass("off")
		}
		wait = autoUpdateEvery
		if last := func() *updateLast { updState.Lock(); defer updState.Unlock(); return updState.last }(); last != nil &&
			(last.Result == "failed" || last.Result == "unreachable") {
			// A pass that could not reach or finish the download looks
			// again sooner: the road it will take next may be another one
			// (roads.go), and an hour is a long time to stay behind.
			wait = autoUpdateRetry
		}
	}
}

// Turn the dedicated switch on or off, from the command line on the machine.
func setRemoteUpdate(on bool) error {
	dir := configDir()
	if dir == "" {
		return os.ErrNotExist
	}
	path := filepath.Join(dir, updateFileName)
	if !on {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// 0600, like the console file: the presence of this file is a security
	// decision, and not one another local user should get to make here.
	return os.WriteFile(path, []byte("on\n"), 0o600)
}

// Whether the installed systemd unit will actually let this helper replace its
// own binary, and what to say when it will not.
//
// The same silent-disagreement problem consoleSandboxNote exists for, in a
// worse form. The unit is written once, at install time, with a hole for
// $BINDIR only if the update switch was on THEN. Flipping it afterwards
// succeeds, the dashboard grows a button, and the button fails several minutes
// in with a permission error about a temporary file — after the download, on a
// machine the operator cannot see. Saying so here is the difference between
// one more step and a feature that appears to work.
//
// Returns "" when there is nothing to say: switch off, no unit, a unit that
// already agrees, or launchd (which imposes none of this).
func updateSandboxNote(on bool) string {
	if !on {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	path, b := systemdUnit(home)
	if path == "" {
		return ""
	}
	unit := string(b)
	// A relaxed unit — which is what --console writes — confines nothing here.
	if !strings.Contains(unit, "ProtectSystem=strict") {
		return ""
	}
	self, err := os.Executable()
	if err != nil || self == "" {
		return ""
	}
	if real, err := filepath.EvalSymlinks(self); err == nil && real != "" {
		self = real
	}
	dir := filepath.Dir(self)
	if strings.Contains(unit, "ReadWritePaths=-"+dir) || strings.Contains(unit, "ReadWritePaths="+dir) {
		return ""
	}
	return "note: this machine's service is sandboxed read-only, so it cannot replace\n" +
		"      its own binary. Reinstall to lift that for " + dir + ":\n" +
		"        curl -fsSL https://tools.subnsub.com/monitor/install.sh | sh -s -- <TOKEN> --remote-update"
}

// Compare two YYYY.MM.DD.N versions component by component AS NUMBERS.
//
// The same rule as version.go and as the dashboard's vcmp, and it has to stay
// the same in all three: "2026.7.9" sorts after "2026.7.30" as a string and
// before it in every sense that matters. An empty or unparseable version is
// OLDER than everything rather than unknown — a helper that cannot say what it
// is is one from before the field existed.
func vercmp(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	n := len(x)
	if len(y) > n {
		n = len(y)
	}
	at := func(parts []string, i int) int {
		if i >= len(parts) {
			return 0
		}
		v, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil || v < 0 {
			return 0
		}
		return v
	}
	for i := 0; i < n; i++ {
		p, q := at(x, i), at(y, i)
		if p != q {
			if p < q {
				return -1
			}
			return 1
		}
	}
	return 0
}

// A version string this program is willing to act on.
//
// THE SAME SHAPE THE RELAY ENFORCES, character for character. The two are separated by a
// network and cannot share code, so the only thing keeping them honest is that
// they are written to look identical and are tested against the same cases.
//
// A looser rule here is not merely untidy: "2999..1" is digits and dots, so it
// would pass a laxer check, get installed, and then be REFUSED by the relay
// when the new helper reported it — leaving a machine that runs fine, cannot
// name itself, and shows on the board as older than everything. An update that
// makes a healthy machine look broken is worse than one that refused to start.
var versionShape = regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}\.\d{1,3}$`)

func validVersion(s string) bool { return versionShape.MatchString(s) }

// The old binary, kept under a second name.
//
// Only reached when the filesystem refuses a hard link. The destination is
// opened O_TRUNC rather than written beside and renamed, because this file is
// a spare and not the one anything runs — a half-written .prev is a worse
// spare, not a broken install.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	// A copy that failed must not leave the file it had already created. The
	// destination here is the .prev backup, and an empty or half-written one is
	// worse than none at all: it is exactly the thing somebody reaches for when
	// the update went wrong, and it would look like a helper they could restore.
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return nil
}

// The extension this platform needs on an executable.
//
// Windows will not run a file without one, and neither will Go's own exec
// resolution — a staged binary named `.subnsub-helper-1234` downloads,
// verifies, and then cannot be probed, which would fail the update at the last
// check before the swap for a reason that has nothing to do with the release.
// The published asset carries the same suffix for the same reason: the file a
// browser downloads has to be one Windows will let the user run.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Force this file's contents out to the device.
//
// Opened for WRITING although nothing is written: fsync on a read-only
// descriptor is fine on Unix, and the Windows equivalent — FlushFileBuffers —
// requires write access and fails with access denied without it. The file is
// this process's own temporary one, so asking for the stronger mode costs
// nothing anywhere.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// The same for a directory, which is what makes a rename itself durable.
// Attempted and not checked: several platforms and filesystems refuse it, and
// none of those refusals mean the install did not happen.
func syncDir(path string) {
	if f, err := os.Open(path); err == nil {
		f.Sync()
		f.Close()
	}
}

func updateClient() *http.Client {
	return &http.Client{
		Timeout: updateTimeout,
		// Refused for the same reason every other client here refuses: not the
		// token this time — these requests carry none — but because a redirect
		// is the one way the constant base URL above could still end up
		// fetching bytes from somewhere nobody chose.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchText(ctx context.Context, c *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "subnsub-helper")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", errStatus(resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, updateMaxText))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// The checksum SHA256SUMS gives for one file, or "".
//
// Matched on the exact name. A prefix match would accept the line for
// subnsub-helper-linux-arm64 when asked about subnsub-helper-linux-arm, and
// the two differ by one character in a field that decides which bytes are
// acceptable.
func sumFor(manifest, name string) string {
	for _, line := range strings.Split(manifest, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 2 {
			continue
		}
		// `sha256sum` marks binary reads with a leading '*' on the name.
		if strings.TrimPrefix(f[1], "*") != name {
			continue
		}
		h := strings.ToLower(f[0])
		if len(h) != 64 {
			return ""
		}
		for _, c := range h {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return ""
			}
		}
		return h
	}
	return ""
}

// Do it. Returns what to report, and whether the caller should now exit so the
// service manager can start the version that is already on disk.
//
// Everything that can fail happens before anything irreversible, and the one
// irreversible step — the rename — happens before the report rather than
// after, so a swap that failed is still something the operator gets told
// about. The only thing left for the caller is the exit.
func runUpdate(id string) (consoleResult, bool) {
	self, err := os.Executable()
	if err != nil || self == "" {
		return consoleResult{ID: id, Code: -1, Error: "update-failed",
			Out: "cannot work out this program's own path\n"}, false
	}
	// Through any symlink, so an install behind one replaces the real file
	// rather than turning the link into a regular binary and orphaning what it
	// pointed at.
	if real, err := filepath.EvalSymlinks(self); err == nil && real != "" {
		self = real
	}
	// A copy somebody pointed this machine at is asked alone.
	if v := strings.TrimSpace(os.Getenv(updateBaseEnv)); v != "" {
		return updateFrom(id, self, strings.TrimRight(v, "/"))
	}
	// A press asks this site the moment GitHub cannot be reached: somebody
	// is waiting on it. The hourly look waits out the grace first.
	return updateFromSrcs(id, self, []updateSrc{githubSrc(updateGitHub), siteSrc(updateBase)},
		func() bool { return id != "auto" || githubDownLong() })
}

// updateSrc is a place a release is published: where its version, its
// manifest and its files are.
type updateSrc struct {
	label    string
	version  string
	manifest func(ver string) string
	file     func(ver, name string) string
	// GitHub's answers redirect to its download host (githubRedirect).
	github bool
}

func siteSrc(base string) updateSrc {
	label := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(label, '/'); i > 0 {
		label = label[:i]
	}
	return updateSrc{label: label, version: base + "/VERSION",
		manifest: func(string) string { return base + "/SHA256SUMS" },
		file:     func(_, name string) string { return base + "/" + name }}
}

// githubSrc: releases tagged v<version>, each carrying VERSION, SHA256SUMS
// and the binaries (helper/go/release-github.sh).
func githubSrc(releases string) updateSrc {
	return updateSrc{label: "GitHub", version: releases + "/latest/download/VERSION",
		manifest: func(ver string) string { return releases + "/download/v" + ver + "/SHA256SUMS" },
		file:     func(ver, name string) string { return releases + "/download/v" + ver + "/" + name },
		github:   true}
}

// client is a road's client for this source.
//
// GitHub's also gives up on an answer that does not begin within
// updateGitHubHeaders: a host that takes the connection and then says
// nothing would otherwise hold a download (whose client has no overall
// timeout; the stall watch starts with the body) until the whole budget
// is gone, and leave none for the site.
func (s updateSrc) client(road string, timeout time.Duration) *http.Client {
	c := roadClient(road, timeout)
	if s.github {
		cc := *c
		cc.CheckRedirect = githubRedirect
		if t, ok := cc.Transport.(*http.Transport); ok {
			t = t.Clone()
			t.ResponseHeaderTimeout = updateGitHubHeaders
			cc.Transport = t
		}
		return &cc
	}
	return c
}

// GitHub answers a release file with a redirect to where it is stored; one
// that goes anywhere else is not followed. A variable, so a test's server can
// stand in for GitHub.
var updateGitHubHostOK = func(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	switch u.Hostname() {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}

// errOffGitHub: a redirect refused. An answer, not a host out of reach, so
// it never sends the update on to the site (updateAway).
var errOffGitHub = errors.New("redirect refused")

func githubRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("%w: too many", errOffGitHub)
	}
	if !updateGitHubHostOK(req.URL) {
		return fmt.Errorf("%w: to %s, not GitHub's download host", errOffGitHub, req.URL.Host)
	}
	return nil
}

// updateAway: no answer at all, or the host's own trouble — which says
// nothing about what is published there, unlike an answer.
func updateAway(err error) bool {
	if err == nil || errors.Is(err, errOffGitHub) {
		return false
	}
	var se statusError
	if errors.As(err, &se) {
		return int(se) >= 500 || int(se) == http.StatusTooManyRequests
	}
	return true
}

// Since when GitHub has been out of reach: kept in the install's directory,
// so a restart does not start the grace again, and in memory for an install
// whose directory cannot be written.
var githubDownSince struct {
	sync.Mutex
	t time.Time
}

func githubDown(away bool) {
	githubDownSince.Lock()
	defer githubDownSince.Unlock()
	p := ""
	if dir := configDir(); dir != "" {
		p = filepath.Join(dir, updateGitHubDownFile)
	}
	if !away {
		githubDownSince.t = time.Time{}
		if p != "" {
			os.Remove(p)
		}
		return
	}
	if githubDownSince.t.IsZero() {
		githubDownSince.t = time.Now()
	}
	if p != "" {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			os.WriteFile(p, []byte(strconv.FormatInt(githubDownSince.t.Unix(), 10)+"\n"), 0o600)
		}
	}
}

func githubDownLong() bool {
	githubDownSince.Lock()
	since := githubDownSince.t
	githubDownSince.Unlock()
	if dir := configDir(); dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, updateGitHubDownFile)); err == nil {
			if t, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && t > 0 {
				if ft := time.Unix(t, 0); since.IsZero() || ft.Before(since) {
					since = ft
				}
			}
		}
	}
	return !since.IsZero() && time.Since(since) >= updateGitHubGrace
}

// The same thing with the two facts about the world passed in rather than
// looked up, which is what makes every branch below reachable from a test —
// including the ones that must not install anything, which are the branches
// worth being sure about.
func updateFrom(id, self, base string) (consoleResult, bool) {
	return updateFromSrcs(id, self, []updateSrc{siteSrc(base)}, nil)
}

// updateOut is how one source's attempt ended.
type updateOut struct {
	code int
	err  string
	swap bool
	// The source could not be reached: the next may be asked.
	away bool
}

// updateFromSrcs asks each source in turn while the last could not be
// reached and fallBack allows it.
func updateFromSrcs(id, self string, srcs []updateSrc, fallBack func() bool) (consoleResult, bool) {
	res := consoleResult{ID: id, Code: -1}
	started := time.Now()

	// Said twice on purpose: once into this machine's own log, which is the
	// record that does not pass through us, and once into the report that goes
	// back to whoever pressed the button.
	var log []string
	say := func(format string, a ...any) {
		s := fmt.Sprintf(format, a...)
		log = append(log, s)
		warnf("update: %s", s)
	}
	// One deadline over the whole thing, so the numbers everything downstream
	// waits on are bounded by a figure this side actually enforces.
	ctx, cancel := context.WithTimeout(context.Background(), updateBudget)
	defer cancel()
	var out updateOut
	for i, src := range srcs {
		if i > 0 {
			say("asking %s instead", src.label)
		}
		out = updateTry(ctx, self, src, say)
		if src.github {
			githubDown(out.away)
		}
		if !out.away || i == len(srcs)-1 {
			break
		}
		if fallBack != nil && !fallBack() {
			say("GitHub could not be reached; asked again at the next look (%s is asked once it has been out of reach for %d hours)",
				srcs[i+1].label, int(updateGitHubGrace/time.Hour))
			break
		}
	}
	res.Code = out.code
	res.Error = out.err
	res.Ms = time.Since(started).Milliseconds()
	res.Out = strings.Join(log, "\n") + "\n"
	return res, out.swap
}

// updateTry is one source's attempt: its version, its manifest, the binary
// by each road in turn, the checks, the swap.
func updateTry(ctx context.Context, self string, src updateSrc, say func(string, ...any)) updateOut {
	fail := func() updateOut { return updateOut{code: -1, err: "update-failed"} }
	away := func() updateOut { return updateOut{code: -1, err: "update-failed", away: true} }
	// The roads out, fastest measured first (roads.go): the release host
	// is reached by the first that answers, and the download below moves
	// to the next when one stalls. One road — the usual machine — is the
	// client this always used.
	roadsTry := roadsRanked()
	var client *http.Client
	var road string
	var target string
	var err error
	allAway := true
	for i, name := range roadsTry {
		client = src.client(name, updateProbeTimeout)
		target, err = fetchText(ctx, client, src.version)
		if err == nil {
			road = name
			break
		}
		allAway = allAway && updateAway(err)
		if len(roadsTry) > 1 {
			say("could not read the published version from %s via %s: %v", src.label, roadLabel(name), err)
		} else {
			say("could not read the published version from %s: %v", src.label, err)
		}
		if i == len(roadsTry)-1 {
			if allAway {
				return away()
			}
			return fail()
		}
	}
	target = strings.TrimSpace(target)
	if !validVersion(target) {
		say("the published version is not a version this build will act on")
		return fail()
	}
	say("running %s; published %s on %s", helperVersion, target, src.label)

	// Only forward. A bucket serving an OLDER version than the one running is
	// either a rollback somebody performed deliberately — in which case
	// reinstalling is the honest way to do it — or an attempt to walk a fleet
	// back onto a build with a known hole. Neither is something to do because
	// a button was pressed.
	if vercmp(target, helperVersion) <= 0 {
		say("already up to date — nothing to install")
		// (an older release on GitHub than on this site is the order a
		// release is published in, not a reason to ask this site)
		// Marked so the page can say THIS rather than "done, the machine is
		// restarting". Both end successfully and neither is an error, but only
		// one of them is followed by a machine going quiet for half a minute,
		// and telling somebody to expect that when it will not happen is how a
		// working feature gets reported as broken. Release skew, a double
		// press, and a rolled-back bucket all land here.
		return updateOut{code: 0, err: "update-none"}
	}
	// Said the moment the download begins, on the hourly pass as on a
	// press: the reading goes out now with "installing", so the
	// card says Updating… while the bytes come, not only at the hand-over.
	// A pass that then fails overwrites it with its outcome (autoUpdateLoop).
	noteUpdatePass("installing")
	wakePush()

	asset := "subnsub-helper-" + runtime.GOOS + "-" + runtime.GOARCH + exeSuffix()

	manifest, err := fetchText(ctx, client, src.manifest(target))
	if err != nil {
		say("could not read the release manifest from %s: %v", src.label, err)
		if updateAway(err) {
			return away()
		}
		return fail()
	}
	want := sumFor(manifest, asset)
	if want == "" {
		// The realistic cause is a platform nobody publishes for. Saying which
		// one saves the operator from reading a release script to find out.
		say("the manifest lists no %s — this platform has no published build", asset)
		return fail()
	}

	// Staged in the SAME DIRECTORY as the binary being replaced, because the
	// swap below is a rename and a rename does not cross filesystems. /tmp is
	// its own mount often enough that using it would work everywhere it was
	// tested and fail on somebody's server.
	var tmpName string
	// Harmless after a successful rename: the name no longer exists, and
	// removing something that is not there is not an error worth branching on.
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	// The download: by the road the version came over first, then the
	// others in measured order. A road that stalls — nothing for roadStall
	// — is abandoned at once rather than at the budget (the MT3000's native
	// uplink crawled at ten kilobytes a second and timed out every hour).
	dlRoads := []string{road}
	for _, name := range roadsTry {
		if name != road {
			dlRoads = append(dlRoads, name)
		}
	}
	var h hash.Hash
	var n int64
	fetched := false
	dlAway := true
	for _, name := range dlRoads {
		tmp, err := os.CreateTemp(filepath.Dir(self), ".subnsub-helper-*"+exeSuffix())
		if err != nil {
			say("cannot write next to %s: %v", self, err)
			// The overwhelmingly likely cause on Linux, and worth naming rather
			// than leaving as a bare permission error: a helper installed WITHOUT
			// --console runs under ProtectHome=read-only, so its own binary is not
			// writable by it. That is the sandbox working, not a bug, and the way
			// through it is the installer.
			say("if this is a sandboxed service, re-run the installer with --remote-update")
			return fail()
		}
		if tmpName != "" {
			os.Remove(tmpName)
		}
		tmpName = tmp.Name()
		actx, acancel := context.WithCancel(ctx)
		req, err := http.NewRequestWithContext(actx, "GET", src.file(target, asset), nil)
		if err != nil {
			acancel()
			tmp.Close()
			say("cannot build the download request")
			return fail()
		}
		req.Header.Set("User-Agent", "subnsub-helper")
		dl := src.client(name, 0)
		started := time.Now()
		resp, err := dl.Do(req)
		if err != nil {
			acancel()
			tmp.Close()
			say("download via %s failed: %v", roadLabel(name), err)
			dlAway = dlAway && updateAway(err)
			continue
		}
		h = sha256.New()
		// Bounded by one byte more than the ceiling, so a body AT the limit is
		// distinguishable from one that was cut off at it.
		pr := &progressReader{r: io.LimitReader(resp.Body, updateMaxBytes+1)}
		stop, stalled := watchStall(actx, acancel, pr)
		var cerr error
		n, cerr = io.Copy(io.MultiWriter(tmp, h), pr)
		stop()
		resp.Body.Close()
		acancel()
		closeErr := tmp.Close()
		took := time.Since(started)
		if resp.StatusCode != 200 {
			say("download via %s failed: http %d", roadLabel(name), resp.StatusCode)
			dlAway = dlAway && updateAway(errStatus(resp.StatusCode))
			continue
		}
		if cerr != nil || closeErr != nil {
			why := "did not complete"
			if stalled.Load() {
				why = "stalled"
			}
			say("download via %s %s after %d KiB in %.0f s", roadLabel(name), why, (n+1023)/1024, took.Seconds())
			continue
		}
		if n > updateMaxBytes {
			say("the published binary is larger than this build will accept")
			return fail()
		}
		rate := float64(n) / 1024 / took.Seconds()
		if took.Seconds() < 0.001 {
			rate = 0
		}
		say("downloaded %d KiB via %s in %.0f s (%.0f KiB/s)", (n+1023)/1024, roadLabel(name), took.Seconds(), rate)
		fetched = true
		break
	}
	if !fetched {
		say("download did not complete")
		if dlAway {
			return away()
		}
		return fail()
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		// The whole point of the exercise. Nothing has been installed and
		// nothing will be.
		say("checksum mismatch — refusing to install")
		say("  expected %s", want)
		say("  got      %s", got)
		return fail()
	}
	// Rounded UP, so anything that arrived at all reads as something. A
	// truncating divide printed "downloaded 0 KiB" beside "checksum matches",
	// which is a sentence that reads as a bug in the line above it.
	say("checksum matches the manifest")

	if err := os.Chmod(tmpName, 0o755); err != nil {
		say("could not make the new binary executable: %v", err)
		return fail()
	}

	// Run it before trusting it. The checksum proves the bytes are the ones
	// that were published; this proves they are a program THIS machine can
	// execute and that it is the version the manifest claimed. A binary for the
	// wrong architecture passes every check above and fails here — which is
	// much better than failing after the rename, as a service that no longer
	// starts on a machine nobody has a route to.
	// Its own, shorter deadline, but still inside the overall budget: a binary
	// that hangs must not be able to spend what is left of it.
	pctx, pcancel := context.WithTimeout(ctx, updateProbeTimeout)
	defer pcancel()
	out, err := exec.CommandContext(pctx, tmpName, "version").Output()
	if err != nil {
		say("the new binary would not run here: %v", err)
		return fail()
	}
	if reported := strings.TrimSpace(string(out)); reported != target {
		say("the new binary calls itself %q, not %q — refusing to install", reported, target)
		return fail()
	}
	say("the new binary runs and reports %s", target)

	// ── from here it is real ────────────────────────────────────────────────
	// The bytes, before the entry that will point at them.
	//
	// A rename is atomic with respect to other processes, not with respect to
	// power. Without this a crash after the rename can leave the service path
	// pointing at a file whose contents were never written back — and the
	// machine comes up to a truncated binary that will not start, having been
	// told the update succeeded.
	if err := syncFile(tmpName); err != nil {
		say("could not flush the new binary to disk: %v", err)
		return fail()
	}
	// The outgoing binary is kept under a name that is not on anyone's PATH. It
	// costs a few megabytes and it is the difference between "restore the
	// previous helper" being a move and being another download on a machine
	// whose helper is the thing that just broke.
	//
	// HOW the swap is done is the one genuinely platform-shaped step in this
	// file — a running program's file can be replaced in place on Unix and
	// cannot on Windows — so it lives in update_unix.go and update_windows.go,
	// where each can explain the guarantee it does and does not offer. Both
	// promise the same thing on failure: nothing was replaced, and the helper
	// the service starts is the one that is running now.
	prev := self + ".prev"
	if err := installOver(tmpName, self, prev); err != nil {
		say("%v", err)
		return fail()
	}
	// Said the instant it becomes true, and before anything else can fail.
	// This path is how the successor gets started at all on a machine with no
	// service manager behind it, and it is the last moment it can be known:
	// the rename above is exactly what stops os.Executable() from being able
	// to answer. See restart.go.
	noteInstalledAt(self)
	// And the directory entry itself. Best effort: not every platform allows
	// it, and a failure here is not a reason to unpick an install that has
	// already happened.
	syncDir(filepath.Dir(self))
	say("installed %s over %s", target, helperVersion)
	// Deliberately says nothing about HOW. The helper hands over to the new
	// version itself where it can, and leaves it to a service manager where
	// that is the platform's arrangement — and on a machine with neither, the
	// old version keeps running and this line must not have promised otherwise.
	say("handing over to %s now", target)

	return updateOut{code: 0, swap: true}
}
