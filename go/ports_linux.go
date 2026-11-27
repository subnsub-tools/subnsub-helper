//go:build linux

package main

// ports.go's reading on Linux, and on Android where the system allows it:
// /proc/net/tcp[6] for every listening socket (its address, its account, its
// inode), each readable program's /proc/<pid>/fd for the inodes it holds, and
// the rest of /proc/<pid> for what the page shows of it. Without root only
// this account's programs can be looked into; a socket no readable program
// holds is another account's, which /proc/net names.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func portsSupported() bool { return true }

func portsScan(ctx context.Context) ([]portProc, string) {
	var socks []portsSock
	read := false
	for _, f := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		read = true
		socks = append(socks, portsParseTable(string(raw), f.v6)...)
	}
	if !read {
		if onAndroid() {
			return nil, "android"
		}
		return nil, "unreadable"
	}
	want := map[string]bool{}
	for _, s := range socks {
		if s.inode != "" && s.inode != "0" {
			want[s.inode] = true
		}
	}
	owner := portsInodeOwners(ctx, want)
	me := os.Geteuid()
	byPID := map[int]*portProc{}
	others := map[int]*portProc{}
	var order []*portProc
	for _, s := range socks {
		a := portAddr{P: s.port, A: s.addr}
		if pid := owner[s.inode]; pid > 0 {
			p := byPID[pid]
			if p == nil {
				p = &portProc{PID: pid}
				byPID[pid] = p
				order = append(order, p)
			}
			p.Ports = append(p.Ports, a)
			continue
		}
		r := others[s.uid]
		if r == nil {
			name := portsUserName(s.uid)
			r = &portProc{Key: "u:" + strconv.Itoa(s.uid), Kind: "other", Name: name, User: name}
			others[s.uid] = r
			order = append(order, r)
		}
		r.Ports = append(r.Ports, a)
	}
	// Another account's programs are not looked into (a helper run as root
	// could): their ports join that account's row.
	for _, p := range order {
		if p.Kind == "other" {
			continue
		}
		fi, err := os.Stat("/proc/" + strconv.Itoa(p.PID))
		if err != nil {
			continue
		}
		sys, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(sys.Uid) == me {
			continue
		}
		uid := int(sys.Uid)
		r := others[uid]
		if r == nil {
			name := portsUserName(uid)
			r = &portProc{Key: "u:" + strconv.Itoa(uid), Kind: "other", Name: name, User: name}
			others[uid] = r
			order = append(order, r)
		}
		r.Ports = append(r.Ports, p.Ports...)
		p.Kind = "skip"
	}
	boot := systemBootUnix()
	desk := linuxDesktops()
	out := make([]portProc, 0, len(order))
	for _, p := range order {
		if p.Kind == "skip" {
			continue
		}
		if p.Kind != "other" {
			if !linuxProcInto(p, me, boot, true) {
				continue
			}
			linuxClassify(p, desk)
		}
		out = append(out, *p)
	}
	return out, ""
}

// portsInodeOwners: for each wanted socket inode, the lowest pid of the
// programs holding it (a server's first process; the workers it forked
// share the socket).
func portsInodeOwners(ctx context.Context, want map[string]bool) map[string]int {
	out := map[string]int{}
	if len(want) == 0 {
		return out
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	until := time.Now().Add(portsScanTime / 2)
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid < 1 {
			continue
		}
		if ctx.Err() != nil || time.Now().After(until) {
			break
		}
		dir := "/proc/" + e.Name() + "/fd"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			t, err := os.Readlink(dir + "/" + fd.Name())
			if err != nil {
				continue
			}
			v, ok := strings.CutPrefix(t, "socket:[")
			if !ok {
				continue
			}
			ino := strings.TrimSuffix(v, "]")
			if want[ino] && (out[ino] == 0 || pid < out[ino]) {
				out[ino] = pid
			}
		}
	}
	return out
}

// linuxProcInto reads what the page shows of p.PID; false: it is gone (or
// a zombie). more: the command line, folder, unit and parent too.
func linuxProcInto(p *portProc, me int, boot int64, more bool) bool {
	dir := "/proc/" + strconv.Itoa(p.PID)
	raw, ok := readSmall(dir + "/stat")
	if !ok {
		return false
	}
	st, ok := portsParseStat(raw)
	if !ok || st.state == "Z" || st.state == "X" {
		return false
	}
	p.PPID, p.sid, p.TTY = st.ppid, st.sid, st.tty != 0
	p.Start = strconv.FormatUint(st.start, 10)
	if boot > 0 {
		p.Since = boot + int64(st.start/100)
	}
	p.RSS = int64(st.rss) * int64(os.Getpagesize())
	if fi, err := os.Stat(dir); err == nil {
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			p.Own = int(sys.Uid) == me
			p.User = portsUserName(int(sys.Uid))
		}
	}
	if c, ok := readSmall(dir + "/comm"); ok {
		p.Name = strings.TrimSpace(c)
	}
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if !more {
		return true
	}
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		p.Cmd = portsArgv(b)
	}
	if cwd, err := os.Readlink(dir + "/cwd"); err == nil {
		p.Cwd = cwd
	}
	if p.PPID > 0 {
		if c, ok := readSmall("/proc/" + strconv.Itoa(p.PPID) + "/comm"); ok {
			p.Parent = strings.TrimSpace(c)
		}
	}
	return true
}

// portsArgv: a NUL-separated command line, spaced, an argument with a space
// in it quoted.
func portsArgv(b []byte) string {
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			args[i] = strconv.Quote(a)
		}
	}
	return strings.Join(args, " ")
}

func linuxClassify(p *portProc, desk *deskIndex) {
	raw, _ := readSmall("/proc/" + strconv.Itoa(p.PID) + "/cgroup")
	unit, userUnit, pkg, from, hint, container := portsCgroup(raw)
	p.Unit, p.UserUnit, p.Pkg, p.From = unit, userUnit, pkg, from
	if p.Own && p.sid > 1 && p.sid != p.PID && !p.TTY && unit == "" && pkg == "" && !container {
		if _, err := os.Stat("/proc/" + strconv.Itoa(p.sid)); err != nil && linuxHadTerminal(p.PID) {
			p.Orphan = true
		}
	}
	var e *deskEntry
	if desk != nil {
		e = desk.match(p, hint)
	}
	if e != nil {
		if e.named && e.name != "" {
			p.Name = e.name
		}
		if p.From == "" {
			p.From = e.id + ".desktop"
		}
		p.iconPath = linuxIconPath(e.icon)
	}
	switch {
	case p.TTY || p.Orphan:
		p.Kind = "term"
	case e != nil || pkg != "":
		p.Kind = "app"
	case unit != "":
		p.Kind = "service"
	case container:
		p.Kind = "sys"
	default:
		p.Kind = "proc"
	}
}

// portsProcNow is the program at pid as it is now, for ports-end's check.
// A thread's id names no program here: /proc answers for threads too, and
// the guards compare programs.
func portsProcNow(pid int) (portProc, bool) {
	p := portProc{PID: pid}
	if linuxTgid(pid) != pid || !linuxProcInto(&p, os.Geteuid(), 0, false) {
		return p, false
	}
	return p, true
}

func linuxTgid(pid int) int {
	raw, ok := readSmall("/proc/" + strconv.Itoa(pid) + "/status")
	if !ok {
		return 0
	}
	for _, line := range strings.Split(raw, "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// linuxHadTerminal: its environment says it was started in a terminal
// (TERM other than dumb, or SSH_TTY), which a daemon that left its session
// does not say.
func linuxHadTerminal(pid int) bool {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	for _, kv := range bytes.Split(b, []byte{0}) {
		if v, ok := bytes.CutPrefix(kv, []byte("TERM=")); ok && len(v) > 0 && string(v) != "dumb" {
			return true
		}
		if bytes.HasPrefix(kv, []byte("SSH_TTY=")) {
			return true
		}
	}
	return false
}

func portsPPID(pid int) int {
	raw, ok := readSmall("/proc/" + strconv.Itoa(pid) + "/stat")
	if !ok {
		return 0
	}
	st, ok := portsParseStat(raw)
	if !ok {
		return 0
	}
	return st.ppid
}

func portsIconData(path string) (string, []byte, bool) { return portsIconFile(path) }

// ── .desktop entries ─────────────────────────────────────────────────────

type deskEntry struct {
	id, name, icon string
	// named: matched by its id or class, so its Name is the program's.
	named bool
}

type deskIndex struct {
	byID, byExec, byClass map[string]*deskEntry
}

var deskCache struct {
	sync.Mutex
	idx *deskIndex
	at  time.Time
}

// The programs no .desktop entry is to be matched by: an entry that runs
// python3 is one app, not every Python program.
var deskGeneric = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "fish": true, "env": true, "python": true, "python3": true, "python2": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "java": true, "ruby": true, "perl": true, "php": true,
	"electron": true, "flatpak": true, "snap": true, "xdg-open": true, "sudo": true, "pkexec": true, "wine": true,
	"dbus-send": true, "gio": true, "kioclient": true, "kioclient5": true, "exo-open": true, "busybox": true, "systemctl": true,
}

func desktopDirs() []string {
	home, _ := os.UserHomeDir()
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" && home != "" {
		data = filepath.Join(home, ".local/share")
	}
	dirs := []string{}
	if data != "" {
		dirs = append(dirs, filepath.Join(data, "applications"), filepath.Join(data, "flatpak/exports/share/applications"))
	}
	sys := os.Getenv("XDG_DATA_DIRS")
	if sys == "" {
		sys = "/usr/local/share:/usr/share"
	}
	for _, d := range strings.Split(sys, ":") {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, filepath.Join(d, "applications"))
		}
	}
	return append(dirs, "/var/lib/flatpak/exports/share/applications", "/var/lib/snapd/desktop/applications")
}

func iconBases() []string {
	home, _ := os.UserHomeDir()
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" && home != "" {
		data = filepath.Join(home, ".local/share")
	}
	var out []string
	if data != "" {
		out = append(out, filepath.Join(data, "icons"), filepath.Join(data, "flatpak/exports/share/icons"))
	}
	if home != "" {
		out = append(out, filepath.Join(home, ".icons"))
	}
	sys := os.Getenv("XDG_DATA_DIRS")
	if sys == "" {
		sys = "/usr/local/share:/usr/share"
	}
	for _, d := range strings.Split(sys, ":") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, filepath.Join(d, "icons"))
		}
	}
	return append(out, "/var/lib/flatpak/exports/share/icons")
}

// linuxDesktops: the .desktop entries here, read again after five minutes.
func linuxDesktops() *deskIndex {
	deskCache.Lock()
	defer deskCache.Unlock()
	if deskCache.idx != nil && time.Since(deskCache.at) < 5*time.Minute {
		return deskCache.idx
	}
	idx := &deskIndex{byID: map[string]*deskEntry{}, byExec: map[string]*deskEntry{}, byClass: map[string]*deskEntry{}}
	n := 0
	for _, dir := range desktopDirs() {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if n > 4000 {
				break
			}
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			n++
			id := strings.ToLower(strings.TrimSuffix(e.Name(), ".desktop"))
			if idx.byID[id] != nil {
				continue
			}
			name, exec, icon, class, ok := parseDesktop(filepath.Join(dir, e.Name()))
			if !ok {
				continue
			}
			ent := &deskEntry{id: strings.TrimSuffix(e.Name(), ".desktop"), name: name, icon: icon}
			idx.byID[id] = ent
			if x := deskExecName(exec); x != "" && idx.byExec[x] == nil {
				idx.byExec[x] = ent
			}
			if c := strings.ToLower(class); c != "" && idx.byClass[c] == nil {
				idx.byClass[c] = ent
			}
		}
	}
	deskCache.idx, deskCache.at = idx, time.Now()
	return idx
}

// parseDesktop reads a .desktop file's own section for its name, what it
// runs, its icon and its window class; false for one that is hidden or no
// application.
func parseDesktop(path string) (name, exec, icon, class string, ok bool) {
	f, err := portsOpenRegular(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	in, typ, hidden := false, "", false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = line == "[Desktop Entry]"
			continue
		}
		if !in {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Name":
			name = v
		case "Exec":
			exec = v
		case "Icon":
			icon = v
		case "StartupWMClass":
			class = v
		case "Type":
			typ = v
		case "Hidden":
			hidden = v == "true"
		}
	}
	ok = !hidden && (typ == "" || typ == "Application")
	return
}

// deskExecName: the program a desktop entry's Exec runs, lowercased: past
// env and its settings; a Flatpak's app id.
func deskExecName(exec string) string {
	f := strings.Fields(exec)
	for i := 0; i < len(f); i++ {
		t := strings.Trim(f[i], "\"'")
		base := strings.ToLower(filepath.Base(t))
		if base == "env" || strings.Contains(t, "=") {
			continue
		}
		if base == "flatpak" {
			for j := i + 1; j < len(f); j++ {
				if a := f[j]; a != "run" && !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "@") && !strings.HasPrefix(a, "%") {
					return strings.ToLower(a)
				}
			}
			return ""
		}
		if deskGeneric[base] {
			return ""
		}
		return base
	}
	return ""
}

func (d *deskIndex) match(p *portProc, hint string) *deskEntry {
	named := func(e *deskEntry) *deskEntry {
		if e == nil {
			return nil
		}
		c := *e
		c.named = true
		return &c
	}
	from := strings.ToLower(p.From)
	if p.Pkg == "flatpak" && from != "" {
		if e := d.byID[from]; e != nil {
			return named(e)
		}
	}
	if p.Pkg == "snap" && from != "" {
		if e := d.byID[from+"_"+from]; e != nil {
			return named(e)
		}
		for id, e := range d.byID {
			if strings.HasPrefix(id, from+"_") {
				return named(e)
			}
		}
	}
	if h := strings.ToLower(hint); h != "" {
		if e := d.byID[h]; e != nil {
			return named(e)
		}
	}
	for _, n := range []string{filepath.Base(p.Exe), p.Name, filepath.Base(strings.Fields(p.Cmd + " x")[0])} {
		n = strings.ToLower(n)
		if n == "" || n == "." || n == "x" || deskGeneric[n] {
			continue
		}
		if e := d.byID[n]; e != nil {
			return named(e)
		}
		if e := d.byClass[n]; e != nil {
			return named(e)
		}
		if e := d.byExec[n]; e != nil {
			return e
		}
	}
	return nil
}

// linuxIconPath: where an icon a .desktop entry names is, as a PNG or SVG.
func linuxIconPath(icon string) string {
	icon = strings.TrimSpace(icon)
	if icon == "" {
		return ""
	}
	if filepath.IsAbs(icon) {
		if fi, err := os.Stat(icon); err == nil && fi.Mode().IsRegular() {
			return icon
		}
		return ""
	}
	if strings.ContainsAny(icon, "/\\") {
		return ""
	}
	for _, ext := range []string{".png", ".svg", ".xpm"} {
		icon = strings.TrimSuffix(icon, ext)
	}
	isFile := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.Mode().IsRegular() && fi.Size() <= portsIconMax
	}
	for _, b := range iconBases() {
		for _, s := range []string{"64x64", "48x48", "128x128", "96x96", "256x256", "32x32", "scalable"} {
			ext := ".png"
			if s == "scalable" {
				ext = ".svg"
			}
			if p := filepath.Join(b, "hicolor", s, "apps", icon+ext); isFile(p) {
				return p
			}
		}
	}
	for _, ext := range []string{".png", ".svg"} {
		if p := filepath.Join("/usr/share/pixmaps", icon+ext); isFile(p) {
			return p
		}
	}
	return ""
}
