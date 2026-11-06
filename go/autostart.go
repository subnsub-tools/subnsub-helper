package main

// Coming back after a reboot, on OpenWrt — arranged by the helper itself.
//
// install.sh starts the helper under systemd where there is one, and
// otherwise under a keep-alive loop (keeper.sh) that a crontab @reboot line
// brings back. OpenWrt has neither: no systemd, and BusyBox's crond does not
// know @reboot. A router that was installed on, then power-cycled, stayed
// silent until somebody logged in and started it by hand.
//
// Why HERE and not only in install.sh: auto-update replaces this binary and
// nothing else. A fix in the installer reaches machines installed after it;
// a fix in the binary reaches the routers already out there on their next
// hourly update. install.sh calls the same code (`subnsub-helper autostart`),
// so there is one init script and one author of it.
//
// WHAT IT WRITES: /etc/init.d/subnsub-helper, a procd service whose whole job
// is to run the keeper loop the installer already generated — the loop knows
// the relay, reads service.env for the token, and restarts the helper when it
// dies. Then `enable`, which is a symlink in /etc/rc.d. It is NOT started:
// the keeper that is running this process holds the loop's lock, and a second
// one would only exit.
//
// THIS CHANGES HOW THE MACHINE BOOTS, unasked, which nothing else here does.
// So it is as narrow as it can be: OpenWrt only, root only, only where the
// installer's keeper exists, never over a file this did not write, and
// MON_AUTOSTART=off (or a file named autostart-off in the config directory)
// stops it. `subnsub-helper autostart` says what it did and why.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	autostartEnvVar  = "MON_AUTOSTART"
	autostartOffFile = "autostart-off"
)

// The service's name: the install's (name.go), so a router installed before
// the rename keeps its /etc/init.d/subnsub-monitor rather than gaining a
// second service beside it.
func autostartName() string { return installName() }

// The line that says a file is ours to rewrite — and, absent, that it is
// somebody's own init script and not to be touched. A script written under
// either name is ours.
func autostartMarker() string {
	return "# " + autostartName() + "-autostart v1 — written by the helper (autostart.go); MON_AUTOSTART=off stops it"
}

func autostartOurs(b []byte) bool {
	return bytes.Contains(b, []byte("# "+helperName+"-autostart ")) || bytes.Contains(b, []byte("# "+legacyName+"-autostart "))
}

// Seams for the test: the root the /etc paths hang from, who we are, and the
// two commands this runs.
var (
	autostartRoot   = ""
	autostartIsRoot = func() bool { return os.Geteuid() == 0 }
	autostartEnable = func(script string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, script, "enable").Run()
	}
	// rc.common names the symlink, so it is asked rather than guessed at:
	// `enabled` exits 0 when the service will start at boot.
	autostartEnabled = func(script string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, script, "enabled").Run() == nil
	}
)

func autostartOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(autostartEnvVar))) {
	case "0", "off", "false", "no":
		return true
	}
	if dir := configDir(); dir != "" {
		if st, err := os.Stat(filepath.Join(dir, autostartOffFile)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// shSingle quotes a string for /bin/sh: a home directory is not
// character-restricted, and this lands in a script root runs at boot.
func shSingle(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func autostartScript(home, keeper string) []byte {
	var b bytes.Buffer
	b.WriteString("#!/bin/sh /etc/rc.common\n")
	b.WriteString(autostartMarker() + "\n")
	b.WriteString("# Starts the keep-alive loop install.sh generated; the loop starts the helper.\n")
	b.WriteString("START=99\nSTOP=10\nUSE_PROCD=1\n\n")
	fmt.Fprintf(&b, "KEEPER=%s\nHELPER_HOME=%s\n\n", shSingle(keeper), shSingle(home))
	b.WriteString(`start_service() {
	[ -x "$KEEPER" ] || return 1
	procd_open_instance
	procd_set_param command "$KEEPER"
	procd_set_param env HOME="$HELPER_HOME"
	# The loop exits at once when another copy of it holds the lock; ask again
	# in a minute, for ever, rather than give up after five.
	procd_set_param respawn 3600 60 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
`)
	return b.Bytes()
}

// autostartOwner reports a file's owner; a seam, because a test is not root.
var autostartOwner = func(fi os.FileInfo) (uid uint32, ok bool) { return fileOwner(fi) }

// autostartUntrusted says why a path may not be run as root at boot, or "".
// Checked from the loop up to (and including) the home directory.
func autostartUntrusted(keeper, home string) string {
	home = filepath.Clean(home)
	for p := filepath.Clean(keeper); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return "cannot examine " + p
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return p + " is a symlink"
		}
		if uid, ok := autostartOwner(fi); !ok || uid != 0 {
			return p + " is not root's"
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return p + " is writable by others"
		}
		if p == home {
			return ""
		}
		if parent := filepath.Dir(p); parent == p || len(parent) < len(home) {
			return keeper + " is not under " + home
		}
	}
}

// ensureAutostart does the whole thing and reports it in a sentence. changed
// says whether the machine's boot was touched this call.
func ensureAutostart() (changed bool, note string) {
	if runtime.GOOS != "linux" {
		return false, "not Linux: the installer's service manager owns the restart here"
	}
	etc := filepath.Join(autostartRoot, "/etc")
	if _, err := os.Stat(filepath.Join(etc, "openwrt_release")); err != nil {
		return false, "not OpenWrt: nothing to do"
	}
	if _, err := os.Stat(filepath.Join(etc, "rc.common")); err != nil {
		return false, "OpenWrt without /etc/rc.common: not a procd system this knows"
	}
	if !autostartIsRoot() {
		return false, "not root: cannot write /etc/init.d"
	}
	home, err := os.UserHomeDir()
	dir := configDir()
	if err != nil || home == "" || dir == "" {
		return false, "no home directory"
	}
	keeper := filepath.Join(dir, "keeper.sh")
	if st, err := os.Lstat(keeper); err != nil || !st.Mode().IsRegular() {
		return false, "no " + keeper + ": this helper was not started by install.sh's loop, so there is nothing known to start at boot"
	}
	// What is registered here runs as root at every boot. "The file exists"
	// is not "the installer put it there for root": a root shell that kept a
	// user's HOME, or a loop somebody else can rewrite, would make this a way
	// to become root. So the loop and every directory from it up to the home
	// must be root's own, writable by nobody else, and not a symlink.
	if why := autostartUntrusted(keeper, home); why != "" {
		return false, "not registering " + keeper + " to run as root at boot: " + why
	}
	script := filepath.Join(etc, "init.d", autostartName())
	want := autostartScript(home, keeper)
	if st, err := os.Lstat(script); err == nil && !st.Mode().IsRegular() {
		return false, script + " exists and is not a plain file: left alone"
	}
	have, err := os.ReadFile(script)
	switch {
	case err == nil && bytes.Equal(have, want):
		// Written already — and still enabled? Somebody's `disable` without
		// MON_AUTOSTART=off would otherwise be undone on every start; but so
		// would a firmware upgrade that kept the script and lost the link,
		// and that is the case this exists for. The switch is how to say no.
		if autostartEnabled(script) {
			return false, "already arranged: " + script
		}
	case err == nil && !autostartOurs(have):
		return false, script + " exists and is not this helper's: left alone"
	case err != nil && !os.IsNotExist(err):
		return false, "cannot read " + script
	}
	// A name nobody could have planted (O_EXCL, random), written and given
	// its mode through the descriptor — never a fixed ".new" a symlink could
	// be waiting under, and never shared with a second caller (the daemon and
	// `autostart` typed at the same moment).
	f, err := os.CreateTemp(filepath.Dir(script), "."+autostartName()+".*")
	if err != nil {
		return false, "cannot write " + script + ": " + err.Error()
	}
	tmp := f.Name()
	_, werr := f.Write(want)
	if werr == nil {
		werr = f.Chmod(0o755) // CreateTemp makes it 0600
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, script)
	}
	if werr != nil {
		os.Remove(tmp)
		return false, "cannot write " + script + ": " + werr.Error()
	}
	if err := autostartEnable(script); err != nil {
		return true, "wrote " + script + " but `enable` failed: " + err.Error()
	}
	return true, "this helper now starts at boot: " + script + " (procd, enabled). MON_AUTOSTART=off, then `" + script + " disable`, undoes it."
}

// startAutostart is the daemon's call: quiet unless it did something, never
// in the way of the first push, and off when told to be.
func startAutostart() {
	if autostartOff() {
		return
	}
	go func() {
		if changed, note := ensureAutostart(); changed {
			warnf("autostart: %s", note)
		}
	}()
}
