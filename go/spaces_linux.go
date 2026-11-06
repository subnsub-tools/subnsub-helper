//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"syscall"
)

const (
	cloneNewNet = 0x40000000 // CLONE_NEWNET
)

// Where `ip netns add` keeps its names. iproute2 says /var/run/netns; on most
// distributions /var/run is /run and both read the same. On OpenWrt there is
// no /run at all — /var is /tmp and the directory is /tmp/run/netns — which a
// helper that looked only under /run learned on a GL-MT3000 (2026-09-20): it
// saw no second exit on a router that plainly had one. Both are read; a name
// in both is one namespace.
var spacesDirs = []string{"/run/netns", "/var/run/netns"}

// setns(2) by number: package syscall was frozen before some architectures
// gained the name. Zero — an architecture not listed — means no second exits
// there, not a wrong syscall.
var sysSetns = map[string]uintptr{"amd64": 308, "arm64": 268, "arm": 375, "386": 346,
	"riscv64": 268, "loong64": 268, "mips64": 5303, "mips64le": 5303, "mips": 4344, "mipsle": 4344}[runtime.GOARCH]

func spacesAvailable() bool { return sysSetns != 0 }

// spacesFound lists the named namespaces that are not the one this process is
// already in — `ip netns exec X subnsub-helper` must not report X as a
// second exit.
// The namespace this process was started in, read once at start-up.
var spacesOwn = func() (st syscall.Stat_t) {
	syscall.Stat("/proc/self/ns/net", &st)
	return st
}()

func spacesFound() []string {
	own, haveOwn := spacesOwn, spacesOwn.Ino != 0
	seen := map[string]bool{}
	var out []string
	for _, dir := range spacesDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			var st syscall.Stat_t
			if seen[e.Name()] || syscall.Stat(filepath.Join(dir, e.Name()), &st) != nil {
				continue
			}
			if haveOwn && st.Dev == own.Dev && st.Ino == own.Ino {
				continue
			}
			seen[e.Name()] = true
			out = append(out, e.Name())
		}
	}
	return out
}

// netnsInfo: how many network namespaces this machine shows and which one
// this helper runs in. The named ones are
// `ip netns add`'s handles; the helper's own is one of them when its
// namespace matches a handle, "init" when it is the system's first
// namespace (pid 1's), and "unnamed" otherwise — a container, say. The
// count is the named ones plus the helper's own when that is not named.
func netnsInfo() *Netns {
	own := spacesOwn
	var names []string
	ownName := ""
	seen := map[string]bool{}
	for _, dir := range spacesDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if seen[e.Name()] || !spaceNameOK(e.Name()) {
				continue
			}
			var st syscall.Stat_t
			if syscall.Stat(filepath.Join(dir, e.Name()), &st) != nil {
				continue
			}
			seen[e.Name()] = true
			names = append(names, e.Name())
			if own.Ino != 0 && st.Dev == own.Dev && st.Ino == own.Ino {
				ownName = e.Name()
			}
		}
	}
	sort.Strings(names)
	if ownName == "" {
		// Pid 1's namespace handle is readable only by root (or pid 1's
		// own user): a user-level helper cannot compare, and nobody puts a
		// user-level helper in a namespace of its own without naming it —
		// so "unnamed" is said only when the comparison ran and differed.
		var first syscall.Stat_t
		ownName = "init"
		if own.Ino != 0 && syscall.Stat("/proc/1/ns/net", &first) == nil && (first.Dev != own.Dev || first.Ino != own.Ino) {
			ownName = "unnamed"
		}
	}
	count := len(names)
	if ownName == "init" || ownName == "unnamed" {
		count++
	}
	return &Netns{Count: count, Own: ownName, Names: names}
}

// spacePath is the namespace's handle: the first directory that has it.
func spacePath(name string) string {
	for _, dir := range spacesDirs {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join(spacesDirs[0], name)
}

// spaceDial opens one TCP connection from inside a namespace, without moving
// the process there.
//
// A socket belongs to the namespace of the THREAD that created it, for life.
// So: a goroutine pinned to its own thread enters the namespace, dials, and
// exits still pinned — which makes the runtime destroy the thread rather than
// hand a thread in the wrong namespace back to the scheduler. The connection
// it made works from anywhere afterwards. Nothing else in the process ever
// runs there: not the push, not the tunnel, not a collector.
//
// The address is a literal, and that is load-bearing: given a name, the
// dialler would resolve it and race address families on OTHER goroutines,
// outside the namespace.
//
// entered is set as soon as the namespace is reached (it stays false for no
// such namespace, or no permission — setns needs CAP_SYS_ADMIN). ctx bounds
// the dial: the caller gives up when it ends, and so does the thread.
func spaceDial(ctx context.Context, name, addr string, entered *atomic.Bool) (net.Conn, error) {
	if host, _, e := net.SplitHostPort(addr); e != nil || net.ParseIP(host) == nil {
		return nil, errors.New("spaceDial wants a literal address")
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	var enter func(mayHop bool)
	enter = func(mayHop bool) {
		runtime.LockOSThread()
		// NEVER the main thread. It cannot be destroyed, so it would stay in
		// the other namespace for good — and /proc/net is /proc/self/net, the
		// MAIN thread's view: every interface counter and TCP figure this
		// helper reads would silently become the VPN namespace's. Found by
		// the live test, not by reasoning. Holding the main thread pinned
		// here while a second goroutine does the work is what guarantees the
		// second one runs somewhere else.
		if syscall.Gettid() == syscall.Getpid() {
			if !mayHop {
				done <- result{err: errors.New("no side thread")}
			} else {
				hopped := make(chan struct{})
				go func() { defer close(hopped); enter(false) }()
				<-hopped
			}
			runtime.UnlockOSThread() // untouched: safe to give back
			return
		}
		// From here the thread is never unlocked: see above.
		fd, e := syscall.Open(spacePath(name), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if e != nil {
			done <- result{err: e}
			return
		}
		_, _, errno := syscall.RawSyscall(sysSetns, uintptr(fd), cloneNewNet, 0)
		syscall.Close(fd)
		if errno != 0 {
			done <- result{err: errno}
			return
		}
		entered.Store(true)
		d := net.Dialer{}
		c, e := d.DialContext(ctx, "tcp", addr)
		done <- result{conn: c, err: e}
	}
	go enter(true)
	r := <-done
	return r.conn, r.err
}
