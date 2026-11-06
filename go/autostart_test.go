package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureAutostart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("OpenWrt is Linux")
	}
	home := scratchHome(t)
	root := t.TempDir()
	enabled, enables := false, 0
	oldRoot, oldIsRoot, oldEnable, oldEnabled, oldOwner := autostartRoot, autostartIsRoot, autostartEnable, autostartEnabled, autostartOwner
	t.Cleanup(func() {
		autostartRoot, autostartIsRoot, autostartEnable, autostartEnabled, autostartOwner = oldRoot, oldIsRoot, oldEnable, oldEnabled, oldOwner
	})
	// The test is not root; its own files stand in for root's.
	foreign := ""
	autostartOwner = func(fi os.FileInfo) (uint32, bool) {
		if foreign != "" && fi.Name() == foreign {
			return 1000, true
		}
		return 0, true
	}
	must0 := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must0(os.Chmod(home, 0o755)) // TempDir is 0700 already; say so
	autostartRoot = root
	isRoot := true
	autostartIsRoot = func() bool { return isRoot }
	autostartEnable = func(string) error { enables++; enabled = true; return nil }
	autostartEnabled = func(string) bool { return enabled }
	script := filepath.Join(root, "etc/init.d", autostartName())
	keeper := filepath.Join(home, ".config/subnsub-helper/keeper.sh")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	nothing := func(why string) {
		t.Helper()
		changed, note := ensureAutostart()
		if _, err := os.Stat(script); changed || err == nil {
			t.Fatalf("%s: should have done nothing (%s)", why, note)
		}
	}

	must(os.MkdirAll(filepath.Join(root, "etc/init.d"), 0o755))
	nothing("not OpenWrt")
	must(os.WriteFile(filepath.Join(root, "etc/openwrt_release"), []byte("DISTRIB_ID='OpenWrt'\n"), 0o644))
	nothing("no rc.common")
	must(os.WriteFile(filepath.Join(root, "etc/rc.common"), []byte("#!/bin/sh\n"), 0o755))
	nothing("no keeper: not the installer's loop")
	must(os.MkdirAll(filepath.Dir(keeper), 0o700))
	must(os.WriteFile(keeper, []byte("#!/bin/sh\n"), 0o700))
	isRoot = false
	nothing("not root")
	isRoot = true

	// What runs as root at boot must be root's alone, all the way up.
	foreign = "keeper.sh"
	nothing("a loop somebody else owns")
	foreign = ".config"
	nothing("a directory somebody else owns")
	foreign = ""
	must(os.Chmod(keeper, 0o722))
	nothing("a loop others can write")
	must(os.Chmod(keeper, 0o700))
	must(os.Chmod(filepath.Dir(keeper), 0o777))
	nothing("a directory others can write")
	must(os.Chmod(filepath.Dir(keeper), 0o700))
	must(os.Rename(keeper, keeper+".real"))
	must(os.Symlink(keeper+".real", keeper))
	nothing("a symlink where the loop should be")
	must(os.Remove(keeper))
	must(os.Rename(keeper+".real", keeper))
	// And a symlink lying in wait where the init script goes is not followed.
	trap := filepath.Join(root, "victim")
	must(os.WriteFile(trap, []byte("precious\n"), 0o600))
	must(os.Symlink(trap, script))
	if changed, note := ensureAutostart(); changed || !strings.Contains(note, "not a plain file") {
		t.Fatalf("a symlinked init script: %s", note)
	}
	if b, _ := os.ReadFile(trap); string(b) != "precious\n" {
		t.Fatal("wrote through a symlink")
	}
	must(os.Remove(script))

	// The daemon's own path honours the switch; the asked-for one is below.
	t.Setenv(autostartEnvVar, "off")
	if !autostartOff() {
		t.Fatal("MON_AUTOSTART=off")
	}
	t.Setenv(autostartEnvVar, "")
	must(os.WriteFile(filepath.Join(filepath.Dir(keeper), autostartOffFile), nil, 0o600))
	if !autostartOff() {
		t.Fatal("the autostart-off file")
	}
	must(os.Remove(filepath.Join(filepath.Dir(keeper), autostartOffFile)))
	if autostartOff() {
		t.Fatal("on by default")
	}

	changed, note := ensureAutostart()
	if !changed || enables != 1 {
		t.Fatalf("first run writes and enables: %v %d %s", changed, enables, note)
	}
	b, err := os.ReadFile(script)
	must(err)
	st, _ := os.Stat(script)
	if st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", st.Mode())
	}
	for _, want := range []string{"#!/bin/sh /etc/rc.common\n", autostartMarker(), "USE_PROCD=1", "START=99",
		"KEEPER='" + keeper + "'", "HELPER_HOME='" + home + "'", `procd_set_param command "$KEEPER"`,
		`procd_set_param env HOME="$HELPER_HOME"`, "procd_set_param respawn 3600 60 0"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("script lacks %q:\n%s", want, b)
		}
	}
	if out, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
		t.Errorf("not valid shell: %v %s", err, out)
	}

	// Again: nothing to do. Disabled behind our back (a firmware upgrade that
	// kept the file and lost the link): enabled again, file untouched.
	if changed, _ := ensureAutostart(); changed || enables != 1 {
		t.Errorf("idempotent: %v %d", changed, enables)
	}
	enabled = false
	if changed, _ := ensureAutostart(); !changed || enables != 2 {
		t.Errorf("re-enabled: %v %d", changed, enables)
	}

	// Somebody's own init script under the same name is theirs.
	must(os.WriteFile(script, []byte("#!/bin/sh /etc/rc.common\n# mine\n"), 0o755))
	if changed, note := ensureAutostart(); changed || !strings.Contains(note, "left alone") {
		t.Errorf("a foreign script was overwritten: %s", note)
	}
	// An older version of OURS is brought up to date.
	must(os.WriteFile(script, []byte("#!/bin/sh /etc/rc.common\n# subnsub-helper-autostart v0\n"), 0o755))
	if changed, _ := ensureAutostart(); !changed {
		t.Error("our own older script should be rewritten")
	}
	// No temporary file is left behind, whatever happened above.
	left, _ := filepath.Glob(filepath.Join(root, "etc/init.d", ".*"))
	if len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

// A home directory with a quote in it lands in a script root runs at boot.
func TestAutostartScriptQuoting(t *testing.T) {
	b := autostartScript(`/root/it's $(reboot)`, `/root/it's $(reboot)/.config/subnsub-helper/keeper.sh`)
	if !strings.Contains(string(b), `HELPER_HOME='/root/it'\''s $(reboot)'`) {
		t.Fatalf("quoting:\n%s", b)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	if err := os.WriteFile(p, append(b, []byte("\necho \"$HELPER_HOME\"\n")...), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", p).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != `/root/it's $(reboot)` {
		t.Fatalf("the shell read it back as %q (%v)", out, err)
	}
}
