package main

// ports.go — the Demos tab's Ports view (index.html #panel-demos,
// demos-app.js): which programs on this computer listen on a TCP port, what
// each one is, and ending one (user 2026-11-27: 有办法做吗？集成到我们 demo 这个功能里面
// … 那么如果这个机器不是 macOS，而是 Linux 或者安卓呢 … 可以做了).
//
// WHAT IS LISTED. Every TCP socket listening here, by the program that holds
// it: its name, command line, folder, parent, start and memory, and what kind
// of program it is — one started from a terminal (and whether that terminal
// is gone), an app, a service, a port a Docker container publishes. Read where
// the system lets this account read: on Linux (and Android, when it allows)
// from /proc (ports_linux.go), on macOS from lsof, netstat and ps
// (ports_darwin.go). A port another account holds is listed with that account
// where the system names it, never with its program, which this account may
// not look into. Android since 10 keeps the port table from apps: the list
// says so (limited) rather than showing nothing as if nothing listened.
//
// WHAT IS ENDED. A program of this helper's own account, the very one the
// page saw: the same process id AND the same start, read again just before
// the signal, so a number the system has since given to another program is
// not signalled. SIGTERM, or SIGKILL when the page asks again (force). Never
// this helper, a program it runs under, or Tailscale (likely the road the page
// came by); on macOS nothing of the system's own. A container's port is freed
// by stopping the container through Docker, by its id and its name.
//
// WHO MAY. The console's grant, as Files and serve.go (runFilesCommand): a
// console already runs any command as this account, kill among them.
//
// ICONS. An app's own picture: on macOS its bundle's .icns made a PNG by sips,
// on Linux the icon its .desktop entry names, from the icon themes' hicolor
// folders or pixmaps. The page asks for them apart (ports-icons), by a key
// the list gave, never by a path.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	portsRowsMax = 240
	portsCmdMax  = 600
	portsPathMax = 300
	portsNameMax = 120
	// The list's JSON, well under a result frame's ceiling once it is
	// escaped into the frame (transport Limits: 256 KiB).
	portsBodyMax = 100 << 10
	// One icon file, and the icons of one answer.
	portsIconMax  = 64 << 10
	portsIconsMax = 110 << 10
	portsIconKeys = 40
	portsScanTime = 4 * time.Second
	// How long an end waits to see the program gone.
	portsEndWait = 3 * time.Second
	// Docker: a list, and a stop (which waits up to stopWait for the
	// container to exit before Docker kills it).
	dockerTimeout  = 4 * time.Second
	dockerStopWait = 10
)

// portAddr is one listening socket: the port and the address it is bound to
// ("0.0.0.0", "::" and "*" are every address).
type portAddr struct {
	P int    `json:"p"`
	A string `json:"a"`
	// I: the port inside the container, for one Docker publishes.
	I int `json:"i,omitempty"`
}

type portContainer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
	State string `json:"state,omitempty"`
}

// portProc is one row of the list: a program and the ports it holds, a
// container and the ports it publishes, or another account's ports.
type portProc struct {
	Key string `json:"key"`
	PID int    `json:"pid,omitempty"`
	// Start: the program's start as the system words it, which with the
	// pid names one program (ports-end checks both).
	Start string `json:"start,omitempty"`
	Name  string `json:"name"`
	User  string `json:"user,omitempty"`
	// Own: this helper's account runs it.
	Own    bool   `json:"own,omitempty"`
	Cmd    string `json:"cmd,omitempty"`
	Cwd    string `json:"cwd,omitempty"`
	Exe    string `json:"exe,omitempty"`
	PPID   int    `json:"ppid,omitempty"`
	Parent string `json:"parent,omitempty"`
	// Since: when it started, Unix seconds. RSS: its memory, bytes.
	Since int64      `json:"since,omitempty"`
	RSS   int64      `json:"rss,omitempty"`
	Ports []portAddr `json:"ports"`
	// term (started from a terminal), app, service, sys, proc, helper,
	// container, other (another account's, or no program to be seen).
	Kind string `json:"kind"`
	TTY  bool   `json:"tty,omitempty"`
	// Orphan: started in a terminal session that has ended.
	Orphan bool `json:"orphan,omitempty"`
	// Unit: the systemd unit that runs it (UserUnit: the account's own).
	Unit     string `json:"unit,omitempty"`
	UserUnit bool   `json:"userUnit,omitempty"`
	// From: its .desktop entry, its Flatpak or snap, or its app's bundle
	// id. Pkg: flatpak or snap.
	From      string         `json:"from,omitempty"`
	Pkg       string         `json:"pkg,omitempty"`
	Icon      string         `json:"icon,omitempty"`
	Container *portContainer `json:"container,omitempty"`
	// Guard: why it is not ended from here — other, self, ancestor,
	// tailscale, system — or "".
	Guard string `json:"guard,omitempty"`

	sid      int
	iconPath string
}

type portsListBody struct {
	V    int    `json:"v"`
	OS   string `json:"os"`
	Me   string `json:"me,omitempty"`
	Home string `json:"home,omitempty"`
	// Limited: the port table may not be read here (android, unreadable).
	Limited string     `json:"limited,omitempty"`
	Procs   []portProc `json:"procs"`
	// Docker: ok (its containers were asked), denied (its socket is not
	// this account's to use), or "" (none found).
	Docker string `json:"docker,omitempty"`
	Cut    bool   `json:"cut,omitempty"`
	At     int64  `json:"at"`
}

func runPortsCommand(op string, arg filesArgs) (any, string) {
	if !portsSupported() {
		return nil, "unsupported"
	}
	switch op {
	case "ports-list":
		ctx, cancel := context.WithTimeout(context.Background(), portsScanTime+dockerTimeout)
		defer cancel()
		return portsList(ctx), ""
	case "ports-end":
		return portsEnd(arg.PID, arg.Start, arg.Force)
	case "ports-icons":
		return portsIcons(arg.Keys), ""
	case "ports-stop-container":
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dockerStopWait)*time.Second+dockerTimeout*2)
		defer cancel()
		if code := dockerStop(ctx, arg.ID, arg.Name); code != "" {
			return nil, code
		}
		return map[string]any{"id": arg.ID}, ""
	}
	return nil, "unknown-op"
}

func portsList(ctx context.Context) portsListBody {
	out := portsListBody{V: 1, OS: runtime.GOOS, Me: portsMe(), Procs: []portProc{}, At: time.Now().Unix()}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out.Home = filepath.Clean(home)
	}
	procs, limited := portsScan(ctx)
	out.Limited = limited
	// Past the deadline what was read is shown, said to be partial.
	out.Cut = ctx.Err() != nil
	if limited == "" {
		if cs, st := dockerContainers(ctx); st != "" {
			out.Docker = st
			procs = portsWithContainers(procs, cs)
		}
	}
	self, anc := os.Getpid(), portsAncestors()
	for i := range procs {
		p := &procs[i]
		if p.PID == self {
			p.Kind = "helper"
		}
		if p.Key == "" {
			p.Key = strconv.Itoa(p.PID) + ":" + p.Start
		}
		portsTidy(p)
		p.Guard = portsGuard(p, self, anc)
		if p.iconPath != "" {
			p.Icon = portsIconKey(p.iconPath)
		}
	}
	sort.SliceStable(procs, func(a, b int) bool {
		if x, y := portsLowest(procs[a]), portsLowest(procs[b]); x != y {
			return x < y
		}
		return procs[a].Key < procs[b].Key
	})
	if len(procs) > portsRowsMax {
		procs, out.Cut = procs[:portsRowsMax], true
	}
	out.Procs = procs
	portsFit(&out)
	return out
}

// portsFit keeps the list under portsBodyMax: command lines shortened
// first, then rows left off the end.
func portsFit(b *portsListBody) {
	size := func() int { j, _ := json.Marshal(b); return len(j) }
	if size() <= portsBodyMax {
		return
	}
	for i := range b.Procs {
		b.Procs[i].Cmd = cleanText(b.Procs[i].Cmd, 160)
	}
	for size() > portsBodyMax && len(b.Procs) > 0 {
		b.Procs, b.Cut = b.Procs[:len(b.Procs)*3/4], true
	}
}

func portsLowest(p portProc) int {
	n := 1 << 20
	for _, a := range p.Ports {
		if a.P < n {
			n = a.P
		}
	}
	return n
}

// portsTidy: its words as the page shows any text from a machine, its
// ports each once, lowest first.
func portsTidy(p *portProc) {
	p.Name = cleanText(p.Name, portsNameMax)
	if p.Name == "" {
		p.Name = "?"
	}
	p.User = cleanText(p.User, 64)
	p.Cmd = cleanText(p.Cmd, portsCmdMax)
	p.Cwd = cleanText(p.Cwd, portsPathMax)
	p.Exe = cleanText(p.Exe, portsPathMax)
	p.Parent = cleanText(p.Parent, portsNameMax)
	p.Unit = cleanText(p.Unit, portsNameMax)
	p.From = cleanText(p.From, portsNameMax)
	seen := map[string]bool{}
	ports := p.Ports[:0]
	for _, a := range p.Ports {
		k := strconv.Itoa(a.P) + "/" + a.A
		if a.P < 1 || a.P > 65535 || seen[k] {
			continue
		}
		seen[k] = true
		ports = append(ports, a)
	}
	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].P != ports[j].P {
			return ports[i].P < ports[j].P
		}
		return ports[i].A < ports[j].A
	})
	p.Ports = ports
}

// portsGuard is why a program is not ended from here, or "".
func portsGuard(p *portProc, self int, anc map[int]bool) string {
	switch {
	case p.Container != nil:
		return ""
	case p.PID <= 1 || !p.Own:
		return "other"
	case p.PID == self:
		return "self"
	case anc[p.PID]:
		return "ancestor"
	case portsTailscale(p):
		return "tailscale"
	case portsSystem(p):
		return "system"
	}
	return ""
}

func portsTailscale(p *portProc) bool {
	for _, s := range []string{p.Name, p.Exe, p.From} {
		s = strings.ToLower(s)
		if strings.Contains(s, "tailscale") || strings.Contains(s, "ipnextension") {
			return true
		}
	}
	return false
}

// portsSystem: on macOS, the system's own programs, which run as this
// account too (AirPlay's receiver, sharing) and are started again by launchd.
func portsSystem(p *portProc) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	for _, pre := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/Library/Apple/"} {
		if strings.HasPrefix(p.Exe, pre) {
			return true
		}
	}
	return false
}

// portsAncestors: the programs this helper runs under, up to the first.
func portsAncestors() map[int]bool {
	out := map[int]bool{}
	pid := os.Getppid()
	for i := 0; i < 64 && pid > 1 && !out[pid]; i++ {
		out[pid] = true
		pid = portsPPID(pid)
	}
	return out
}

// portsEnd ends the program the page saw: pid and start both still its.
func portsEnd(pid int, start string, force bool) (any, string) {
	if pid <= 1 || start == "" {
		return nil, "bad-args"
	}
	sig := "term"
	if force {
		sig = "kill"
	}
	gone := map[string]any{"gone": true, "sig": sig}
	// Held first, then checked: what is signalled is what was checked.
	pin, err := portsPinOpen(pid)
	if err != nil {
		return gone, ""
	}
	defer pin.close()
	p, ok := portsProcNow(pid)
	if !ok {
		return gone, ""
	}
	if p.Start != start {
		return nil, "changed"
	}
	if g := portsGuard(&p, os.Getpid(), portsAncestors()); g != "" {
		return nil, "guard-" + g
	}
	if !pin.exact() {
		if q, ok := portsProcNow(pid); !ok {
			return gone, ""
		} else if q.Start != start {
			return nil, "changed"
		}
	}
	if err := pin.signal(force); err != nil {
		switch {
		case errors.Is(err, errPortsGone):
			return gone, ""
		case errors.Is(err, os.ErrPermission):
			return nil, "guard-other"
		}
		return nil, "end-failed"
	}
	until := time.Now().Add(portsEndWait)
	for time.Now().Before(until) {
		time.Sleep(150 * time.Millisecond)
		if q, ok := portsProcNow(pid); !ok || q.Start != start {
			return gone, ""
		}
	}
	return map[string]any{"gone": false, "sig": sig}, ""
}

var (
	errPortsGone  = errors.New("the program has ended")
	errNotRegular = errors.New("not a regular file")
)

// ── who ──────────────────────────────────────────────────────────────────

func portsMe() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

var portsUsers sync.Map

// portsUserName names an account by its number: the system's name for it,
// Android's for an app's (u0_a312), else the number.
func portsUserName(uid int) string {
	if v, ok := portsUsers.Load(uid); ok {
		return v.(string)
	}
	name := strconv.Itoa(uid)
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	} else if onAndroid() && uid%100000 >= 10000 {
		name = "u" + strconv.Itoa(uid/100000) + "_a" + strconv.Itoa(uid%100000-10000)
	}
	portsUsers.Store(uid, name)
	return name
}

// ── reading what the system says ─────────────────────────────────────────

// portsSock is one listening socket of /proc/net/tcp[6].
type portsSock struct {
	port  int
	addr  string
	uid   int
	inode string
}

// portsParseTable reads /proc/net/tcp or tcp6 for its listening sockets:
//
//	sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
//	0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1234567
func portsParseTable(raw string, v6 bool) []portsSock {
	var out []portsSock
	for i, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 || f[3] != "0A" {
			continue
		}
		h, p, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(p, 16, 32)
		if err != nil || port == 0 || port > 65535 {
			continue
		}
		addr := portsHexAddr(h, v6)
		if addr == "" {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			uid = -1
		}
		out = append(out, portsSock{port: int(port), addr: addr, uid: uid, inode: f[9]})
	}
	return out
}

// portsHexAddr: /proc's address, each 32-bit word in the machine's order
// (little-endian on every Linux this helper is built for).
func portsHexAddr(h string, v6 bool) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	switch {
	case !v6 && len(b) == 4:
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	case v6 && len(b) == 16:
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			for j := 0; j < 4; j++ {
				ip[w*4+j] = b[w*4+3-j]
			}
		}
		return ip.String()
	}
	return ""
}

// portsStat is what the page wants of /proc/<pid>/stat.
type portsStat struct {
	state      string
	ppid, sid  int
	tty        int64
	start, rss uint64
}

// portsParseStat: the fields after the LAST ") " (a name may hold either).
func portsParseStat(raw string) (portsStat, bool) {
	end := strings.LastIndex(raw, ") ")
	if end < 0 {
		return portsStat{}, false
	}
	f := strings.Fields(raw[end+2:])
	if len(f) < 22 {
		return portsStat{}, false
	}
	var s portsStat
	var e [5]error
	s.state = f[0]
	s.ppid, e[0] = strconv.Atoi(f[1])
	s.sid, e[1] = strconv.Atoi(f[3])
	s.tty, e[2] = strconv.ParseInt(f[4], 10, 64)
	s.start, e[3] = strconv.ParseUint(f[19], 10, 64)
	s.rss, e[4] = strconv.ParseUint(f[21], 10, 64)
	for _, err := range e {
		if err != nil {
			return portsStat{}, false
		}
	}
	return s, true
}

var portsFlatpakScope = regexp.MustCompile(`^app-flatpak-(.+)-[0-9]+\.scope$`)

// portsCgroup reads /proc/<pid>/cgroup for the systemd unit that runs a
// program (unit, and whether it is the account's own manager's), its
// Flatpak or snap, the app id a desktop launched it under (hint), and
// whether it runs in a container.
func portsCgroup(raw string) (unit string, userUnit bool, pkg, from, hint string, container bool) {
	path := ""
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			path = parts[2]
			break
		}
		if parts[1] == "name=systemd" {
			path = parts[2]
		}
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	inUser := false
	for i, s := range segs {
		last := i == len(segs)-1
		switch {
		case strings.HasPrefix(s, "user@") && strings.HasSuffix(s, ".service"):
			inUser = true
			continue
		case (strings.HasPrefix(s, "docker-") && strings.HasSuffix(s, ".scope")) || s == "docker" || strings.HasPrefix(s, "libpod-"):
			container = true
		case strings.HasPrefix(s, "snap."):
			if name, _, ok := strings.Cut(strings.TrimPrefix(s, "snap."), "."); ok && name != "" {
				pkg, from = "snap", name
			}
		}
		if m := portsFlatpakScope.FindStringSubmatch(s); m != nil {
			pkg, from = "flatpak", m[1]
			continue
		}
		if strings.HasPrefix(s, "app-") && (strings.HasSuffix(s, ".scope") || strings.HasSuffix(s, ".service")) {
			hint = portsAppHint(s)
			continue
		}
		if last && strings.HasSuffix(s, ".service") {
			unit, userUnit = s, inUser
		}
	}
	return
}

var portsHintTail = regexp.MustCompile(`-[0-9]+$`)

// portsAppHint: the app id in a desktop's scope or service name —
// app-gnome-org.gnome.Nautilus-1234.scope, app-org.kde.dolphin@a1b2.service.
func portsAppHint(s string) string {
	s = strings.TrimPrefix(s, "app-")
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".scope"), ".service")
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	s = portsHintTail.ReplaceAllString(s, "")
	for _, pre := range []string{"gnome-", "kde-", "dbus-:1.2-", "flatpak-"} {
		s = strings.TrimPrefix(s, pre)
	}
	return s
}

// The macOS readers' output, apart from running them so they are tested
// where the tests run.

// portsParseLsof: lsof -F pn, a "p<pid>" line then "n<address:port>" lines.
func portsParseLsof(out string) map[int][]portAddr {
	res := map[int][]portAddr{}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			if a, ok := portsSplitAddr(line[1:], ':'); ok && pid > 0 {
				res[pid] = append(res[pid], a)
			}
		}
	}
	return res
}

// portsParseLsofCwd: lsof -d cwd -F pn, each program's folder.
func portsParseLsofCwd(out string) map[int]string {
	res := map[int]string{}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			if pid > 0 && strings.HasPrefix(line[1:], "/") {
				res[pid] = line[1:]
			}
		}
	}
	return res
}

// portsParseNetstat: netstat -an -p tcp's listening sockets, whose local
// address ends ".port" (127.0.0.1.8080, *.5000, ::1.8080).
func portsParseNetstat(out string) []portAddr {
	var res []portAddr
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || f[len(f)-1] != "LISTEN" {
			continue
		}
		if a, ok := portsSplitAddr(f[3], '.'); ok {
			res = append(res, a)
		}
	}
	return res
}

func portsSplitAddr(s string, sep byte) (portAddr, bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return portAddr{}, false
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil || n < 1 || n > 65535 {
		return portAddr{}, false
	}
	host := strings.Trim(s[:i], "[]")
	if host == "" {
		host = "*"
	}
	return portAddr{P: n, A: host}, true
}

// portsPSRow is a line of ps -o pid=,ppid=,uid=,rss=,tty=,state=,lstart=,comm=.
type portsPSRow struct {
	ppid, uid int
	rss       int64
	tty       string
	state     string
	lstart    string
	since     int64
	comm      string
}

func portsParsePS(out string) map[int]portsPSRow {
	res := map[int]portsPSRow{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 12 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		uid, e3 := strconv.Atoi(f[2])
		rss, e4 := strconv.ParseInt(f[3], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || pid < 1 {
			continue
		}
		r := portsPSRow{ppid: ppid, uid: uid, rss: rss * 1024, tty: f[4], state: f[5], lstart: strings.Join(f[6:11], " "), comm: strings.Join(f[11:], " ")}
		if t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", r.lstart, time.Local); err == nil {
			r.since = t.Unix()
		}
		res[pid] = r
	}
	return res
}

// portsParseArgs: ps -o pid=,args=, each program's command line.
func portsParseArgs(out string) map[int]string {
	res := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		p, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if pid, err := strconv.Atoi(p); err == nil {
			res[pid] = strings.TrimSpace(rest)
		}
	}
	return res
}

// ── Docker ───────────────────────────────────────────────────────────────

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
	Ports []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// dockerSocket: Docker's socket here — DOCKER_HOST's when it names one, the
// system's, a rootless one, Docker Desktop's, Colima's, OrbStack's.
func dockerSocket() string {
	var cands []string
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		cands = append(cands, strings.TrimPrefix(h, "unix://"))
	}
	cands = append(cands, "/var/run/docker.sock", "/run/docker.sock")
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		cands = append(cands, filepath.Join(d, "docker.sock"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cands = append(cands, filepath.Join(home, ".docker/run/docker.sock"), filepath.Join(home, ".colima/default/docker.sock"), filepath.Join(home, ".orbstack/run/docker.sock"))
	}
	for _, c := range cands {
		if fi, err := os.Stat(c); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return c
		}
	}
	return ""
}

func dockerDo(ctx context.Context, sock, method, path string) (int, []byte, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

func dockerDenied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "permission denied")
}

// dockerContainers: a row for each running container that publishes a TCP
// port; ok, denied, or "" when Docker is not here.
func dockerContainers(ctx context.Context) ([]portProc, string) {
	sock := dockerSocket()
	if sock == "" {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	code, raw, err := dockerDo(ctx, sock, http.MethodGet, "/containers/json")
	if err != nil {
		if dockerDenied(err) {
			return nil, "denied"
		}
		return nil, ""
	}
	if code != http.StatusOK {
		return nil, ""
	}
	var cs []dockerContainer
	if json.Unmarshal(raw, &cs) != nil {
		return nil, ""
	}
	return dockerRows(cs), "ok"
}

func dockerRows(cs []dockerContainer) []portProc {
	var out []portProc
	for _, c := range cs {
		if !dockerID.MatchString(c.ID) {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		var ports []portAddr
		for _, p := range c.Ports {
			if p.Type != "tcp" || p.PublicPort < 1 || p.PublicPort > 65535 {
				continue
			}
			a := p.IP
			if a == "" {
				a = "0.0.0.0"
			}
			ports = append(ports, portAddr{P: p.PublicPort, A: a, I: p.PrivatePort})
		}
		if len(ports) == 0 {
			continue
		}
		out = append(out, portProc{
			Key: "c:" + c.ID[:12], Name: name, Kind: "container", Ports: ports,
			Container: &portContainer{ID: c.ID[:12], Name: cleanText(name, portsNameMax), Image: cleanText(c.Image, portsNameMax), State: cleanText(c.State, 32)},
		})
	}
	return out
}

var dockerID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// portsForwarder: a program that holds a port for Docker — its proxy, Docker
// Desktop's, a VM's port forwarder — or no program to be seen.
func portsForwarder(p portProc) bool {
	if p.Kind == "other" {
		return true
	}
	n := strings.ToLower(p.Name + " " + p.Exe)
	for _, s := range []string{"docker", "vpnkit", "orbstack", "limactl", "gvproxy", "colima"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// portsWithContainers: a container's ports are taken off the forwarder that
// holds them for it, and listed under the container.
func portsWithContainers(procs, cs []portProc) []portProc {
	pub := map[int]bool{}
	for _, c := range cs {
		for _, a := range c.Ports {
			pub[a.P] = true
		}
	}
	out := procs[:0]
	for _, p := range procs {
		if portsForwarder(p) {
			kept := p.Ports[:0]
			for _, a := range p.Ports {
				if !pub[a.P] {
					kept = append(kept, a)
				}
			}
			p.Ports = kept
			if len(p.Ports) == 0 {
				continue
			}
		}
		out = append(out, p)
	}
	return append(out, cs...)
}

// dockerStop stops a container, still named name.
func dockerStop(ctx context.Context, id, name string) string {
	if !dockerID.MatchString(id) || name == "" {
		return "bad-args"
	}
	sock := dockerSocket()
	if sock == "" {
		return "docker-absent"
	}
	code, raw, err := dockerDo(ctx, sock, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json")
	switch {
	case err != nil && dockerDenied(err):
		return "docker-denied"
	case err != nil:
		return "docker-error"
	case code == http.StatusNotFound:
		return "gone"
	case code != http.StatusOK:
		return "docker-error"
	}
	var doc struct{ Name string }
	if json.Unmarshal(raw, &doc) != nil || strings.TrimPrefix(doc.Name, "/") != name {
		return "changed"
	}
	code, _, err = dockerDo(ctx, sock, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop?t="+strconv.Itoa(dockerStopWait))
	switch {
	case err != nil:
		return "docker-error"
	case code == http.StatusNoContent || code == http.StatusNotModified:
		return ""
	case code == http.StatusNotFound:
		return "gone"
	}
	return "docker-error"
}

// ── icons ────────────────────────────────────────────────────────────────

var portsIconsKnown = struct {
	sync.Mutex
	path map[string]string
	data map[string]string
}{path: map[string]string{}, data: map[string]string{}}

func portsIconKey(path string) string {
	h := sha256.Sum256([]byte(path))
	k := hex.EncodeToString(h[:8])
	portsIconsKnown.Lock()
	if len(portsIconsKnown.path) > 512 {
		portsIconsKnown.path = map[string]string{}
	}
	portsIconsKnown.path[k] = path
	portsIconsKnown.Unlock()
	return k
}

// portsIcons: the pictures of the keys a list gave, as data: addresses,
// as many as fit an answer; the rest in more, for the next ask.
func portsIcons(keys []string) map[string]any {
	icons, more, total := map[string]string{}, []string{}, 0
	for i, k := range keys {
		if i >= portsIconKeys {
			break
		}
		portsIconsKnown.Lock()
		path, data := portsIconsKnown.path[k], portsIconsKnown.data[k]
		portsIconsKnown.Unlock()
		if path == "" {
			continue
		}
		if data == "" {
			mime, b, ok := portsIconData(path)
			if !ok || len(b) == 0 || len(b) > portsIconMax {
				continue
			}
			data = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(b)
			portsIconsKnown.Lock()
			if len(portsIconsKnown.data) > 96 {
				portsIconsKnown.data = map[string]string{}
			}
			portsIconsKnown.data[k] = data
			portsIconsKnown.Unlock()
		}
		if total+len(data) > portsIconsMax {
			more = append(more, k)
			continue
		}
		icons[k], total = data, total+len(data)
	}
	return map[string]any{"icons": icons, "more": more}
}

// portsIconFile reads a PNG or SVG icon as it is.
func portsIconFile(path string) (string, []byte, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".png" && ext != ".svg" {
		return "", nil, false
	}
	f, err := portsOpenRegular(path)
	if err != nil {
		return "", nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, portsIconMax+1))
	if err != nil || len(b) == 0 || len(b) > portsIconMax {
		return "", nil, false
	}
	// What leaves is a picture, whatever the name says.
	switch {
	case ext == ".png" && bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png", b, true
	case ext == ".svg" && portsLooksSVG(b):
		return "image/svg+xml", b, true
	}
	return "", nil, false
}

// portsLooksSVG: markup whose first lines hold an <svg> element.
func portsLooksSVG(b []byte) bool {
	head := b
	if len(head) > 4096 {
		head = head[:4096]
	}
	head = bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	return len(head) > 0 && head[0] == '<' && bytes.Contains(bytes.ToLower(head), []byte("<svg"))
}
