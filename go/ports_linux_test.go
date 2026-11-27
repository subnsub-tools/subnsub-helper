//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The child the end test listens in: it holds a port and waits.
func TestPortsHelperProcess(t *testing.T) {
	if os.Getenv("PORTS_TEST_CHILD") != "1" {
		return
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(3)
	}
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	time.Sleep(time.Minute)
	os.Exit(0)
}

func portsFind(t *testing.T, b portsListBody, port int) *portProc {
	t.Helper()
	for i := range b.Procs {
		for _, a := range b.Procs[i].Ports {
			if a.P == port {
				return &b.Procs[i]
			}
		}
	}
	return nil
}

func TestPortsListAndEnd(t *testing.T) {
	if _, err := os.ReadFile("/proc/net/tcp"); err != nil {
		t.Skip("no port table here:", err)
	}
	own, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	ownPort := own.Addr().(*net.TCPAddr).Port

	cmd := exec.Command(os.Args[0], "-test.run=^TestPortsHelperProcess$")
	cmd.Env = append(os.Environ(), "PORTS_TEST_CHILD=1")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	defer func() { cmd.Process.Kill(); <-done }()
	line, err := bufio.NewReader(out).ReadString('\n')
	go func() { done <- cmd.Wait() }()
	if err != nil {
		t.Fatal(err)
	}
	childPort, _ := strconv.Atoi(strings.TrimSpace(line))

	b := portsList(context.Background())
	if b.Limited != "" {
		t.Skip("limited:", b.Limited)
	}
	me := portsFind(t, b, ownPort)
	if me == nil || me.PID != os.Getpid() || me.Kind != "helper" || me.Guard != "self" || !me.Own || me.Start == "" {
		t.Fatalf("this process: %+v", me)
	}
	c := portsFind(t, b, childPort)
	if c == nil || c.PID != cmd.Process.Pid || !c.Own || c.Guard != "" || c.Cmd == "" || c.Cwd == "" || c.Parent == "" || c.Since == 0 || c.RSS == 0 {
		t.Fatalf("the child: %+v", c)
	}
	if c.Ports[0].A != "127.0.0.1" {
		t.Errorf("address: %+v", c.Ports)
	}
	if _, code := portsEnd(c.PID, c.Start+"1", false); code != "changed" {
		t.Errorf("another start: %q", code)
	}
	if _, code := portsEnd(os.Getpid(), me.Start, false); code != "guard-self" {
		t.Errorf("itself: %q", code)
	}
	res, code := portsEnd(c.PID, c.Start, false)
	if code != "" || !res.(map[string]any)["gone"].(bool) {
		t.Fatalf("end: %v %q", res, code)
	}
	if err := <-done; err == nil {
		t.Error("the child exited by itself")
	}
	done <- nil
	if res, code := portsEnd(c.PID, c.Start, true); code != "" || !res.(map[string]any)["gone"].(bool) {
		t.Errorf("gone already: %v %q", res, code)
	}
}

// A thread's id is not taken for its program's.
func TestPortsThreadID(t *testing.T) {
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skip(err)
	}
	for _, e := range ents {
		tid, _ := strconv.Atoi(e.Name())
		if tid > 0 && tid != os.Getpid() {
			if _, ok := portsProcNow(tid); ok {
				t.Errorf("thread %d read as a program", tid)
			}
			if res, code := portsEnd(tid, "1", false); code != "" || !res.(map[string]any)["gone"].(bool) {
				t.Errorf("ending thread %d: %v %q", tid, res, code)
			}
			return
		}
	}
	t.Skip("one thread only")
}

func TestPortsDesktops(t *testing.T) {
	data := t.TempDir()
	sys := t.TempDir()
	write := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(sys, "applications/syncthing-start.desktop"), "[Desktop Entry]\nName=Start Syncthing\nExec=/usr/bin/syncthing serve --no-browser\nIcon=syncthing\nType=Application\n")
	write(filepath.Join(sys, "applications/org.kde.kdeconnect.daemon.desktop"), "[Desktop Entry]\nName=KDE Connect\nExec=/usr/libexec/kdeconnectd\nIcon=kdeconnect\nType=Application\nNoDisplay=true\n")
	write(filepath.Join(sys, "applications/tool.desktop"), "[Desktop Entry]\nName=Some Tool\nExec=env FOO=1 python3 /opt/tool.py\nIcon=tool\n")
	write(filepath.Join(sys, "applications/gone.desktop"), "[Desktop Entry]\nName=Gone\nExec=gone\nHidden=true\n")
	// A FIFO named like an entry is passed over, not waited on.
	if err := syscall.Mkfifo(filepath.Join(sys, "applications/fifo.desktop"), 0o644); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(data, "flatpak/exports/share/applications/org.localsend.localsend_app.desktop"), "[Desktop Entry]\nName=LocalSend\nExec=/usr/bin/flatpak run --branch=stable org.localsend.localsend_app\nIcon=org.localsend.localsend_app\n")
	write(filepath.Join(sys, "icons/hicolor/64x64/apps/syncthing.png"), "\x89PNG")
	write(filepath.Join(sys, "icons/hicolor/scalable/apps/kdeconnect.svg"), "<svg/>")
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("XDG_DATA_DIRS", sys)
	deskCache.Lock()
	deskCache.idx = nil
	deskCache.Unlock()
	got := make(chan *deskIndex, 1)
	go func() { got <- linuxDesktops() }()
	var d *deskIndex
	select {
	case d = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("reading the entries waited on a FIFO")
	}

	if e := d.match(&portProc{Exe: "/usr/bin/syncthing", Name: "syncthing"}, ""); e == nil || e.id != "syncthing-start" || e.named {
		t.Errorf("syncthing: %+v", e)
	} else if p := linuxIconPath(e.icon); p != filepath.Join(sys, "icons/hicolor/64x64/apps/syncthing.png") {
		t.Errorf("syncthing's icon: %q", p)
	}
	if e := d.match(&portProc{Exe: "/usr/libexec/kdeconnectd", Name: "kdeconnectd"}, ""); e == nil || e.name != "KDE Connect" {
		t.Errorf("kdeconnectd: %+v", e)
	} else if p := linuxIconPath(e.icon); !strings.HasSuffix(p, "kdeconnect.svg") {
		t.Errorf("kdeconnect's icon: %q", p)
	}
	if e := d.match(&portProc{Pkg: "flatpak", From: "org.localsend.localsend_app", Exe: "/app/bin/localsend_app"}, ""); e == nil || !e.named || e.name != "LocalSend" {
		t.Errorf("flatpak: %+v", e)
	}
	if e := d.match(&portProc{Exe: "/usr/bin/python3.12", Name: "python3", Cmd: "python3 -m http.server"}, ""); e != nil {
		t.Errorf("a python program matched %+v", e)
	}
	if e := d.match(&portProc{Exe: "/usr/bin/gone", Name: "gone"}, ""); e != nil {
		t.Errorf("a hidden entry matched: %+v", e)
	}
	for exec, want := range map[string]string{
		"/usr/bin/flatpak run --branch=stable org.example.App %U": "org.example.app",
		"env FOO=1 /usr/bin/foo --x=1":                            "foo",
		"python3 /opt/tool.py":                                    "",
		"\"/opt/My App/app\" %u":                                  "\"/opt/my",
	} {
		if got := deskExecName(exec); got != want && !strings.HasPrefix(exec, "\"") {
			t.Errorf("exec %q: %q, want %q", exec, got, want)
		}
	}
	if linuxIconPath("../../etc/passwd") != "" {
		t.Error("an icon name walked out of the icon folders")
	}
}
