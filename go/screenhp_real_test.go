package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Against this Mac's own Screen Sharing, when given an account:
// MON_HP_REAL_USER and MON_HP_REAL_PASSWORD. Sends Shift, which types nothing.
func TestScreenHPRealMac(t *testing.T) {
	user := os.Getenv("MON_HP_REAL_USER")
	if user == "" {
		t.Skip("MON_HP_REAL_USER not set")
	}
	t.Setenv(screenHPEnvVar, "on")
	v, done := newHPViewer(t, screenPort())
	v.status(5 * time.Second)
	v.control(map[string]any{"t": "open", "codecs": []string{"avc"}, "user": user, "password": os.Getenv("MON_HP_REAL_PASSWORD"), "audio": true})
	frames, sound, configs := 0, 0, 0
	var live map[string]any
	deadline := time.After(60 * time.Second)
	for live == nil || frames < 30 {
		select {
		case f, ok := <-v.frames:
			if !ok {
				t.Fatalf("ended: live %v frames %d", live, frames)
			}
			switch f.kind {
			case swToStatus:
				t.Logf("status %s", f.body)
				if s := string(f.body); len(s) > 0 && strings.Contains(s, `"live"`) {
					live = map[string]any{"raw": s}
				}
				if strings.Contains(string(f.body), `"end"`) {
					t.Fatalf("ended: %s", f.body)
				}
			case swToVideoConfig:
				configs++
			case swToVideoFrame:
				frames++
			case swToAudio:
				sound++
			}
		case <-deadline:
			t.Fatalf("timed out: live %v frames %d", live, frames)
		}
	}
	v.send(swFromKey, []byte{1, 0, 0x38})
	v.send(swFromKey, []byte{0, 0, 0x38})
	t.Logf("live, %d configurations, %d frames, %d sound packets", configs, frames, sound)
	time.Sleep(time.Second)
	v.w.Close()
	<-done
}

// Serves put.sock's {"op":"screen-hp"} on MON_HP_SOCKET until stopped, for
// out's own test of its side (Qingyan --screen-pipe-selftest).
func TestScreenHPServeSocket(t *testing.T) {
	path := os.Getenv("MON_HP_SOCKET")
	if path == "" {
		t.Skip("MON_HP_SOCKET not set")
	}
	t.Setenv(screenHPEnvVar, "on")
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			r := bufio.NewReader(c)
			line, err := r.ReadString('\n')
			if err != nil || !strings.Contains(line, `"screen-hp"`) {
				c.Close()
				return
			}
			screenHPServe(c)
		}()
	}
}
