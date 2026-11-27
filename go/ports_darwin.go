//go:build darwin

package main

// ports.go's reading on macOS, where no file says it: lsof for the ports this
// account's programs listen on (without root it sees no other account's),
// netstat for every listening port (so another account's and the system's are
// still listed, without a program), ps for each program's parent, start,
// terminal and memory. Each tool is run the way antigravity_other.go runs
// them: an absolute path from a fixed list, a deadline, bounded output.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	portsNetstatPaths = []string{"/usr/sbin/netstat"}
	portsPlutilPaths  = []string{"/usr/bin/plutil"}
	portsSipsPaths    = []string{"/usr/bin/sips"}
)

func portsSupported() bool { return true }

// macRun is agRun under the list's deadline: each tool gets at most five
// seconds, and none past the deadline of the whole list.
func macRun(ctx context.Context, bin string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, bin, args...)
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, n: 512 * 1024}
	cmd.Stdout = lw
	if err := cmd.Run(); err != nil && buf.Len() == 0 {
		return "", err
	}
	if lw.over {
		return "", errAgTruncated
	}
	return buf.String(), nil
}

// macStart is when the program at pid started, to the microsecond (ps
// says it to the second): with the pid, what ports-end checks. "" when
// there is no such program, or it has ended and waits to be reaped.
func macStart(pid int) (string, int64) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid || k.Proc.P_stat == 5 /* SZOMB */ {
		return "", 0
	}
	t := k.Proc.P_starttime
	return strconv.FormatInt(t.Sec, 10) + "." + fmt.Sprintf("%06d", t.Usec), t.Sec
}

func portsScan(ctx context.Context) ([]portProc, string) {
	lsof, ps := agTool(agLsofPaths), agTool(agPsPaths)
	if lsof == "" || ps == "" {
		return nil, "unreadable"
	}
	own := map[int][]portAddr{}
	if out, err := macRun(ctx, lsof, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"); err == nil {
		own = portsParseLsof(out)
	}
	var all []portAddr
	if ns := agTool(portsNetstatPaths); ns != "" {
		if out, err := macRun(ctx, ns, "-an", "-p", "tcp"); err == nil {
			all = portsParseNetstat(out)
		}
	}
	table := map[int]portsPSRow{}
	if out, err := macRun(ctx, ps, "-axo", "pid=,ppid=,uid=,rss=,tty=,state=,lstart=,comm="); err == nil {
		table = portsParsePS(out)
	}
	args, cwds := map[int]string{}, map[int]string{}
	if len(own) > 0 {
		ids := make([]string, 0, len(own))
		for pid := range own {
			ids = append(ids, strconv.Itoa(pid))
		}
		list := strings.Join(ids, ",")
		if out, err := macRun(ctx, ps, "-o", "pid=,args=", "-p", list); err == nil {
			args = portsParseArgs(out)
		}
		if out, err := macRun(ctx, lsof, "-a", "-d", "cwd", "-Fpn", "-p", list); err == nil {
			cwds = portsParseLsofCwd(out)
		}
	}
	me, meName := os.Geteuid(), portsMe()
	held := map[int]bool{}
	var rows []portProc
	for pid, ports := range own {
		p := portProc{PID: pid, Ports: ports, Own: true, User: meName, Cmd: args[pid], Cwd: cwds[pid]}
		if r, ok := table[pid]; ok {
			macFromPS(&p, r, me, table)
		}
		macClassify(ctx, &p)
		for _, a := range ports {
			held[a.P] = true
		}
		rows = append(rows, p)
	}
	var rest []portAddr
	for _, a := range all {
		if !held[a.P] {
			rest = append(rest, a)
		}
	}
	if len(rest) > 0 {
		rows = append(rows, portProc{Key: "u:other", Kind: "other", Name: "", Ports: rest})
	}
	return rows, ""
}

func macFromPS(p *portProc, r portsPSRow, me int, table map[int]portsPSRow) {
	p.PPID, p.Start, p.Since, p.RSS = r.ppid, r.lstart, r.since, r.rss
	if s, sec := macStart(p.PID); s != "" {
		p.Start, p.Since = s, sec
	}
	p.TTY = r.tty != "" && r.tty != "??" && r.tty != "-"
	p.Own = r.uid == me
	p.Exe = r.comm
	p.Name = filepath.Base(r.comm)
	if par, ok := table[r.ppid]; ok {
		p.Parent = filepath.Base(par.comm)
	}
}

// macBundle: the app a program belongs to, the outermost .app of its path.
func macBundle(exe string) string {
	if i := strings.Index(exe, ".app/"); i > 0 {
		return exe[:i+4]
	}
	return ""
}

type macInfo struct {
	name, id, icon string
}

var macInfos sync.Map

// macBundleInfo reads an app's Info.plist (plutil makes it JSON) for its
// name, its id and its icon file.
func macBundleInfo(ctx context.Context, bundle string) macInfo {
	if v, ok := macInfos.Load(bundle); ok {
		return v.(macInfo)
	}
	info := macInfo{name: strings.TrimSuffix(filepath.Base(bundle), ".app")}
	if pl := agTool(portsPlutilPaths); pl != "" {
		if out, err := macRun(ctx, pl, "-convert", "json", "-o", "-", filepath.Join(bundle, "Contents/Info.plist")); err == nil {
			var d struct {
				Display string `json:"CFBundleDisplayName"`
				Name    string `json:"CFBundleName"`
				ID      string `json:"CFBundleIdentifier"`
				Icon    string `json:"CFBundleIconFile"`
			}
			if json.Unmarshal([]byte(out), &d) == nil {
				if d.Display != "" {
					info.name = d.Display
				} else if d.Name != "" {
					info.name = d.Name
				}
				info.id = d.ID
				if ic := filepath.Base(d.Icon); d.Icon != "" && ic != "." && ic != "/" {
					if filepath.Ext(ic) == "" {
						ic += ".icns"
					}
					p := filepath.Join(bundle, "Contents/Resources", ic)
					if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
						info.icon = p
					}
				}
			}
		}
	}
	macInfos.Store(bundle, info)
	return info
}

func macClassify(ctx context.Context, p *portProc) {
	b := macBundle(p.Exe)
	if b != "" {
		info := macBundleInfo(ctx, b)
		p.Name, p.From, p.iconPath = info.name, info.id, info.icon
	}
	switch {
	case p.TTY:
		p.Kind = "term"
	case portsSystem(p):
		p.Kind = "sys"
	case b != "":
		p.Kind = "app"
	default:
		p.Kind = "proc"
	}
}

func portsProcNow(pid int) (portProc, bool) {
	p := portProc{PID: pid}
	ps := agTool(agPsPaths)
	if ps == "" {
		return p, false
	}
	out, err := macRun(context.Background(), ps, "-o", "pid=,ppid=,uid=,rss=,tty=,state=,lstart=,comm=", "-p", strconv.Itoa(pid))
	if err != nil {
		return p, false
	}
	r, ok := portsParsePS(out)[pid]
	if !ok || strings.HasPrefix(r.state, "Z") {
		return p, false
	}
	macFromPS(&p, r, os.Geteuid(), nil)
	if b := macBundle(p.Exe); b != "" {
		p.From = macBundleInfo(context.Background(), b).id
	}
	return p, true
}

func portsPPID(pid int) int {
	if p, ok := portsProcNow(pid); ok {
		return p.PPID
	}
	return 0
}

// portsIconData: an app's .icns as a 64-pixel PNG (sips writes it to a
// folder of its own, read and removed); a PNG as it is.
func portsIconData(path string) (string, []byte, bool) {
	if !strings.HasSuffix(strings.ToLower(path), ".icns") {
		return portsIconFile(path)
	}
	sips := agTool(portsSipsPaths)
	if sips == "" {
		return "", nil, false
	}
	dir, err := os.MkdirTemp("", "subnsub-icon-")
	if err != nil {
		return "", nil, false
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "icon.png")
	macRun(context.Background(), sips, "-s", "format", "png", "-Z", "64", path, "--out", out)
	return portsIconFile(out)
}
