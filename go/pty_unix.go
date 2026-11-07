//go:build linux || darwin || freebsd

package main

// The terminal's shell (pty.go): started on a pseudo-terminal, as a login
// shell in the home directory of the user this helper runs as.

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
)

const ptySupported = true

// ptyShell is the user's own shell where that can be learned — the account
// database, then the environment — and otherwise the console's (a fixed
// list, never PATH). A service manager hands a daemon no $SHELL, so the
// environment alone would put everybody in /bin/sh.
func ptyShell() string {
	ok := func(p string) bool {
		if !filepath.IsAbs(p) {
			return false
		}
		fi, err := os.Stat(p)
		return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
	}
	if runtime.GOOS != "android" {
		if f, err := os.Open("/etc/passwd"); err == nil {
			uid := strconv.Itoa(os.Getuid())
			sc := bufio.NewScanner(f)
			shell := ""
			for sc.Scan() {
				p := strings.Split(sc.Text(), ":")
				if len(p) >= 7 && p[2] == uid {
					shell = p[6]
					break
				}
			}
			f.Close()
			if ok(shell) && !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "/false") {
				return shell
			}
		}
	}
	if s := os.Getenv("SHELL"); ok(s) {
		return s
	}
	if runtime.GOOS == "darwin" && ok("/bin/zsh") {
		return "/bin/zsh"
	}
	if p := androidPrefix(); p != "" && ok(p+"/bin/bash") {
		return p + "/bin/bash"
	}
	if runtime.GOOS != "android" && ok("/bin/bash") {
		return "/bin/bash"
	}
	return consoleShell()
}

// ptyStart runs the shell on a new pseudo-terminal of the given size. kill
// hangs up on the whole session — the shell is its leader, so its process
// group is everything it started in the foreground — and wait reaps it.
func ptyStart(cols, rows int) (tty *os.File, kill func(), wait func(), err error) {
	shell := ptyShell()
	cmd := exec.Command(shell)
	// A leading dash is how a shell is told it is a login shell: the
	// profile runs, and with it the PATH a person's tools are on.
	cmd.Args = []string{"-" + filepath.Base(shell)}
	env := make([]string, 0, len(os.Environ())+6)
	has := map[string]bool{}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "TERM" || name == "COLORTERM" || name == "SHELL" {
			continue
		}
		has[name] = true
		env = append(env, kv)
	}
	env = append(env, "TERM=xterm-256color", "COLORTERM=truecolor", "SHELL="+shell)
	home, _ := os.UserHomeDir()
	if !has["HOME"] && home != "" {
		env = append(env, "HOME="+home)
	}
	// Without a UTF-8 locale every non-ASCII byte an agent draws its frame
	// with comes out as a question mark.
	if !has["LANG"] && !has["LC_ALL"] && !has["LC_CTYPE"] {
		if runtime.GOOS == "darwin" {
			env = append(env, "LANG=en_US.UTF-8")
		} else {
			env = append(env, "LANG=C.UTF-8")
		}
	}
	cmd.Env = env
	if fi, serr := os.Stat(home); serr == nil && fi.IsDir() {
		cmd.Dir = home
	}
	tty, err = pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, nil, nil, err
	}
	pid := cmd.Process.Pid
	// Closed once the last signal has gone out, so whoever waits for the
	// shell (a holder about to exit) waits for that too: a job that
	// ignores the hangup is not left running because the process meant to
	// finish it off was gone first.
	swept := make(chan struct{})
	var killed atomic.Bool
	kill = func() {
		if !killed.CompareAndSwap(false, true) {
			return
		}
		// The shell leads a session of its own (its pid is the session's
		// id), and a job-control shell gives every job a process group of
		// its own inside it — so the shell's group alone is not "what it
		// started". Ask the terminal which group holds the foreground
		// before closing it; closing the master is the kernel's hangup to
		// that group and the shell, and the signals are for what ignores
		// one: a hangup now, and a moment later no appeal, to the
		// foreground group, the shell's, and — where the system can list
		// them — every process still in the session.
		fg := ptyForeground(tty)
		tty.Close()
		groups := []int{pid}
		if fg > 1 && fg != pid {
			groups = append(groups, fg)
		}
		for _, g := range groups {
			syscall.Kill(-g, syscall.SIGHUP)
		}
		go func() {
			time.Sleep(2 * time.Second)
			for _, g := range groups {
				syscall.Kill(-g, syscall.SIGKILL)
			}
			for _, p := range sessionMembers(pid) {
				syscall.Kill(p, syscall.SIGKILL)
			}
			close(swept)
		}()
	}
	wait = func() {
		cmd.Wait()
		if killed.Load() {
			<-swept
		}
	}
	return tty, kill, wait, nil
}

// ptyForeground is the process group in the terminal's foreground, or 0.
func ptyForeground(tty *os.File) int {
	var pgrp int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), uintptr(syscall.TIOCGPGRP), uintptr(unsafe.Pointer(&pgrp))); e != 0 {
		return 0
	}
	return int(pgrp)
}

// sessionMembers lists the processes whose session is sid, where /proc says
// (Linux, Android): background jobs sit in groups of their own that nothing
// else here names. Elsewhere it is empty, and the two groups above are what
// is reached.
func sessionMembers(sid int) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil || p <= 1 {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid pgrp session … — comm may hold anything,
		// so the fields are counted from the LAST parenthesis.
		i := strings.LastIndexByte(string(b), ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		if len(f) >= 4 && f[3] == strconv.Itoa(sid) {
			out = append(out, p)
		}
	}
	return out
}

func ptyResizeTTY(tty *os.File, cols, rows int) {
	pty.Setsize(tty, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}
