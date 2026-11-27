package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPortsParseTable(t *testing.T) {
	v4 := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0\n" +
		"   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000000000000000 100 0 0 10 0\n"
	got := portsParseTable(v4, false)
	if len(got) != 2 {
		t.Fatalf("listening sockets: %+v", got)
	}
	if got[0] != (portsSock{port: 8080, addr: "127.0.0.1", uid: 1000, inode: "111"}) || got[1] != (portsSock{port: 22, addr: "0.0.0.0", uid: 0, inode: "222"}) {
		t.Errorf("v4: %+v", got)
	}
	v6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 444 1\n" +
		"   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 555 1\n" +
		"   2: 0000000000000000FFFF00000100007F:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 666 1\n"
	got = portsParseTable(v6, true)
	if len(got) != 3 || got[0].addr != "::1" || got[0].port != 5432 || got[1].addr != "::" || got[1].port != 80 || got[1].uid != 33 || got[2].addr != "127.0.0.1" || got[2].port != 3000 {
		t.Errorf("v6: %+v", got)
	}
}

func TestPortsParseStat(t *testing.T) {
	raw := "4242 (node) worker) S 4100 4242 4000 34817 4242 4194304 0 0 0 0 7 3 0 0 20 0 11 0 987654 1000000 2048 18446744073709551615"
	s, ok := portsParseStat(raw)
	if !ok || s.state != "S" || s.ppid != 4100 || s.sid != 4000 || s.tty != 34817 || s.start != 987654 || s.rss != 2048 {
		t.Errorf("stat: %+v %v", s, ok)
	}
	if _, ok := portsParseStat("12 (x) S 1 2"); ok {
		t.Error("a short stat line was read")
	}
}

func TestPortsCgroup(t *testing.T) {
	cases := []struct {
		raw, unit, pkg, from, hint string
		user, container            bool
	}{
		{raw: "0::/system.slice/cpa.service\n", unit: "cpa.service"},
		{raw: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service\n", unit: "syncthing.service", user: true},
		{raw: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.localsend.localsend_app-12345.scope\n", pkg: "flatpak", from: "org.localsend.localsend_app"},
		{raw: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.firefox.firefox-3a1b.scope\n", pkg: "snap", from: "firefox"},
		{raw: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.dolphin@a1b2c3.service\n", hint: "org.kde.dolphin"},
		{raw: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Nautilus-4411.scope\n", hint: "org.gnome.Nautilus"},
		{raw: "0::/system.slice/docker-0123456789abcdef.scope\n", container: true},
		{raw: "0::/user.slice/user-1000.slice/session-3.scope\n"},
		{raw: "12:pids:/user.slice\n1:name=systemd:/system.slice/ssh.service\n", unit: "ssh.service"},
		{raw: "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n"},
	}
	for _, c := range cases {
		unit, user, pkg, from, hint, container := portsCgroup(c.raw)
		if unit != c.unit || user != c.user || pkg != c.pkg || from != c.from || hint != c.hint || container != c.container {
			t.Errorf("%q: unit %q user %v pkg %q from %q hint %q container %v", c.raw, unit, user, pkg, from, hint, container)
		}
	}
}

func TestPortsMacReaders(t *testing.T) {
	lsof := "p645\nf9\nn*:5000\nf10\nn*:7000\np1877\nf20\nn127.0.0.1:8126\nf21\nn[::1]:8126\n"
	got := portsParseLsof(lsof)
	if len(got[645]) != 2 || got[645][0] != (portAddr{P: 5000, A: "*"}) || got[1877][1] != (portAddr{P: 8126, A: "::1"}) {
		t.Errorf("lsof: %+v", got)
	}
	ns := "Active Internet connections (including servers)\n" +
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n" +
		"tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN\n" +
		"tcp46      0      0  *.5000                 *.*                    LISTEN\n" +
		"tcp6       0      0  ::1.631                *.*                    LISTEN\n" +
		"tcp4       0      0  192.168.1.5.51234      17.1.2.3.443           ESTABLISHED\n"
	all := portsParseNetstat(ns)
	if len(all) != 3 || all[0] != (portAddr{P: 8080, A: "127.0.0.1"}) || all[1] != (portAddr{P: 5000, A: "*"}) || all[2] != (portAddr{P: 631, A: "::1"}) {
		t.Errorf("netstat: %+v", all)
	}
	ps := "  645     1   501  75776 ??       S    Thu Nov 20 09:01:02 2026     /System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter\n" +
		"14420 14401   501 120832 ttys003  S+   Thu Nov  7 18:00:00 2026     /opt/homebrew/bin/node\n" +
		"  900   1   501  1000 ??       Z    Thu Nov 27 10:00:00 2026     /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"
	rows := portsParsePS(ps)
	r := rows[14420]
	if r.ppid != 14401 || r.uid != 501 || r.rss != 120832*1024 || r.tty != "ttys003" || r.lstart != "Thu Nov 7 18:00:00 2026" || r.since == 0 || r.comm != "/opt/homebrew/bin/node" {
		t.Errorf("ps: %+v", r)
	}
	if rows[900].comm != "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" || rows[900].state != "Z" {
		t.Errorf("ps with a space in the path: %+v", rows[900])
	}
	args := portsParseArgs("14420 node /Users/a/demo/node_modules/.bin/vite --port 5174\n  645 /System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter\n")
	if args[14420] != "node /Users/a/demo/node_modules/.bin/vite --port 5174" || !strings.HasSuffix(args[645], "ControlCenter") {
		t.Errorf("args: %v", args)
	}
	cwd := portsParseLsofCwd("p14420\nfcwd\nn/Users/a/demo\np645\nfcwd\nn/\n")
	if cwd[14420] != "/Users/a/demo" || cwd[645] != "/" {
		t.Errorf("cwd: %v", cwd)
	}
	if macBundleOf := func(exe string) string {
		if i := strings.Index(exe, ".app/"); i > 0 {
			return exe[:i+4]
		}
		return ""
	}("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/x"); macBundleOf != "/Applications/Google Chrome.app" {
		t.Errorf("bundle: %q", macBundleOf)
	}
}

func TestPortsContainers(t *testing.T) {
	var cs []dockerContainer
	json.Unmarshal([]byte(`[
		{"Id":"0123456789abcdef0123","Names":["/postgres-dev"],"Image":"postgres:16","State":"running","Ports":[{"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"},{"IP":"::","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"},{"PrivatePort":9999,"Type":"tcp"}]},
		{"Id":"bad id","Names":["/x"],"Ports":[{"PrivatePort":1,"PublicPort":1,"Type":"tcp"}]},
		{"Id":"fedcba9876543210fedc","Names":["/dns"],"Ports":[{"IP":"0.0.0.0","PrivatePort":53,"PublicPort":5353,"Type":"udp"}]}
	]`), &cs)
	rows := dockerRows(cs)
	if len(rows) != 1 || rows[0].Key != "c:0123456789ab" || rows[0].Container.Name != "postgres-dev" || rows[0].Container.Image != "postgres:16" || len(rows[0].Ports) != 2 || rows[0].Ports[0].I != 5432 {
		t.Fatalf("rows: %+v", rows)
	}
	procs := []portProc{
		{Key: "u:0", Kind: "other", Name: "root", Ports: []portAddr{{P: 22, A: "0.0.0.0"}, {P: 5432, A: "0.0.0.0"}}},
		{PID: 3120, Name: "docker-proxy", Kind: "proc", Ports: []portAddr{{P: 5432, A: "::"}}},
		{PID: 4000, Name: "node", Kind: "term", Ports: []portAddr{{P: 3000, A: "127.0.0.1"}}},
	}
	out := portsWithContainers(procs, rows)
	if len(out) != 3 || out[0].Kind != "other" || len(out[0].Ports) != 1 || out[0].Ports[0].P != 22 || out[1].Name != "node" || out[2].Kind != "container" {
		t.Errorf("merged: %+v", out)
	}
}

func TestPortsGuardAndTidy(t *testing.T) {
	anc := map[int]bool{77: true}
	for _, c := range []struct {
		p    portProc
		want string
	}{
		{portProc{PID: 500, Own: true, Name: "node"}, ""},
		{portProc{PID: 500, Own: false, Name: "nginx"}, "other"},
		{portProc{Key: "u:0", Kind: "other"}, "other"},
		{portProc{PID: 10, Own: true}, "self"},
		{portProc{PID: 77, Own: true}, "ancestor"},
		{portProc{PID: 600, Own: true, Exe: "/Applications/Tailscale.app/Contents/MacOS/Tailscale"}, "tailscale"},
		{portProc{PID: 601, Own: true, Name: "tailscaled"}, "tailscale"},
		{portProc{Kind: "container", Container: &portContainer{ID: "0123456789ab", Name: "db"}}, ""},
	} {
		if g := portsGuard(&c.p, 10, anc); g != c.want {
			t.Errorf("%+v: guard %q, want %q", c.p, g, c.want)
		}
	}
	p := portProc{Name: "a\u202eb", Ports: []portAddr{{P: 8080, A: "::"}, {P: 22, A: "0.0.0.0"}, {P: 8080, A: "::"}, {P: 0, A: "x"}}}
	portsTidy(&p)
	if p.Name != "ab" || len(p.Ports) != 2 || p.Ports[0].P != 22 {
		t.Errorf("tidy: %+v", p)
	}
}

func TestPortsFit(t *testing.T) {
	b := portsListBody{V: 1}
	for i := 0; i < 900; i++ {
		b.Procs = append(b.Procs, portProc{Key: strconv.Itoa(i), Name: "n", Cmd: strings.Repeat("x", portsCmdMax), Ports: []portAddr{{P: 1000 + i, A: "::"}}})
	}
	portsFit(&b)
	j, _ := json.Marshal(b)
	if len(j) > portsBodyMax || !b.Cut || len(b.Procs) == 0 {
		t.Errorf("fit: %d bytes, cut %v, %d rows", len(j), b.Cut, len(b.Procs))
	}
}

func TestPortsIconsOnlyByKey(t *testing.T) {
	got := portsIcons([]string{"/etc/passwd", "0000000000000000"})
	if icons := got["icons"].(map[string]string); len(icons) != 0 {
		t.Errorf("an icon came for a key no list gave: %v", icons)
	}
}

func TestPortsCommandRefusals(t *testing.T) {
	if !portsSupported() {
		if _, code := runPortsCommand("ports-list", filesArgs{}); code != "unsupported" {
			t.Errorf("unsupported: %q", code)
		}
		return
	}
	if _, code := runPortsCommand("ports-end", filesArgs{PID: 1, Start: "1"}); code != "bad-args" {
		t.Errorf("pid 1: %q", code)
	}
	if _, code := runPortsCommand("ports-end", filesArgs{PID: 4242}); code != "bad-args" {
		t.Errorf("no start: %q", code)
	}
	if _, code := runPortsCommand("ports-stop-container", filesArgs{ID: "../x", Name: "db"}); code != "bad-args" {
		t.Errorf("container id: %q", code)
	}
	if _, code := runPortsCommand("ports-nope", filesArgs{}); code != "unknown-op" {
		t.Errorf("unknown: %q", code)
	}
}

func TestServeProxyAdd(t *testing.T) {
	f := &serveFake{state: "Running"}
	serveUse(t, f)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	local := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	it, code := serveProxyAdd(ctx, 8851, local, "127.0.0.1")
	if code != "" || it.Kind != "proxy" || it.Target != "http://127.0.0.1:"+strconv.Itoa(local) {
		t.Fatalf("add: %+v %q", it, code)
	}
	web := f.doc(t)["Web"].(map[string]any)
	h := web["web-1.tail1234.ts.net:8851"].(map[string]any)["Handlers"].(map[string]any)["/"].(map[string]any)
	if h["Proxy"] != it.Target {
		t.Errorf("web: %v", web)
	}
	if _, code := serveProxyAdd(ctx, 8851, local, "0.0.0.0"); code != "port-taken" {
		t.Errorf("again: %q", code)
	}
	if _, code := serveProxyAdd(ctx, 8126, local, ""); code != "bad-port" {
		t.Errorf("the tailnet road's port: %q", code)
	}
	if _, code := serveProxyAdd(ctx, 8853, local, "192.0.2.7"); code != "bad-args" {
		t.Errorf("another computer's address: %q", code)
	}
	// A port that takes connections but is no web server.
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	defer raw.Close()
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-x\r\n"))
			c.Close()
		}
	}()
	if _, code := serveProxyAdd(ctx, 8854, raw.Addr().(*net.TCPAddr).Port, "127.0.0.1"); code != "not-http" {
		t.Errorf("not a web server: %q", code)
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	free := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()
	if _, code := serveProxyAdd(ctx, 8852, free, ""); code != "not-listening" {
		t.Errorf("nothing there: %q", code)
	}
	if code := serveStop(ctx, 8851, "/", "", it.Target); code != "" {
		t.Errorf("stop: %q", code)
	}
}

func TestPortsIconFile(t *testing.T) {
	dir := t.TempDir()
	put := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	if m, _, ok := portsIconFile(put("a.png", "\x89PNG\r\n\x1a\nrest")); !ok || m != "image/png" {
		t.Errorf("png: %q %v", m, ok)
	}
	if _, _, ok := portsIconFile(put("b.png", "root:x:0:0")); ok {
		t.Error("a file named .png that is no picture was sent")
	}
	if m, _, ok := portsIconFile(put("c.svg", "\xef\xbb\xbf\n<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>")); !ok || m != "image/svg+xml" {
		t.Errorf("svg: %q %v", m, ok)
	}
	if _, _, ok := portsIconFile(put("d.svg", "hello <svg")); ok {
		t.Error("text that is no markup was sent as an svg")
	}
	if _, _, ok := portsIconFile(put("e.png", "\x89PNG\r\n\x1a\n"+strings.Repeat("x", portsIconMax))); ok {
		t.Error("an icon past the limit was sent")
	}
	if _, _, ok := portsIconFile(put("f.txt", "\x89PNG\r\n\x1a\n")); ok {
		t.Error("another kind of file was sent")
	}
}
