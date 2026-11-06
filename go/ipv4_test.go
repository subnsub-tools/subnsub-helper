package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIPv4Public(t *testing.T) {
	for in, want := range map[string]string{
		"104.28.163.142":     "104.28.163.142",
		" 52.35.237.101\n":   "52.35.237.101",
		"8.8.8.8":            "8.8.8.8",
		"10.0.0.1":           "",
		"172.16.4.4":         "",
		"192.168.1.1":        "",
		"100.64.0.1":         "", // shared address space (CGNAT)
		"100.127.255.255":    "",
		"100.128.0.1":        "100.128.0.1",
		"192.0.0.9":          "",
		"192.0.2.1":          "",
		"192.0.3.1":          "192.0.3.1",
		"192.88.99.1":        "",
		"198.18.0.1":         "",
		"198.19.255.255":     "",
		"198.20.0.1":         "198.20.0.1",
		"198.51.100.7":       "",
		"203.0.113.9":        "",
		"127.0.0.1":          "",
		"169.254.1.1":        "",
		"0.1.2.3":            "",
		"224.0.0.1":          "",
		"240.0.0.1":          "",
		"255.255.255.255":    "",
		"::ffff:8.8.8.8":     "",
		"2a09:bac5:b106::15": "",
		"8.8.8":              "",
		"<html>":             "",
		"":                   "",
	} {
		if got := ipv4Public(in); got != want {
			t.Errorf("ipv4Public(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPv4Source(t *testing.T) {
	for in, want := range map[string]string{
		"":                            ipv4DefaultURL,
		"off":                         "",
		"OFF":                         "",
		"0":                           "",
		"https://ipv4.example.net/ip": "https://ipv4.example.net/ip",
		"http://ipv4.example.net/ip":  "",
		"ipv4.example.net":            "",
	} {
		t.Setenv(ipv4EnvVar, in)
		if got := ipv4Source(); got != want {
			t.Errorf("MON_IPV4=%q: ipv4Source() = %q, want %q", in, got, want)
		}
	}
}

func TestIPv4Parse(t *testing.T) {
	trace := "fl=123abc\nh=www.cloudflare.com\nip=104.28.163.142\nts=1760000000.123\nvisit_scheme=https\nuag=subnsub-helper/x\ncolo=NRT\nsliver=none\nhttp=http/2\nloc=JP\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n"
	for name, c := range map[string]struct{ in, addr, cc string }{
		"trace":            {trace, "104.28.163.142", "JP"},
		"trace, unplaced":  {"ip=8.8.8.8\nloc=XX\n", "8.8.8.8", ""},
		"trace, tor":       {"ip=8.8.8.8\nloc=T1\n", "8.8.8.8", ""},
		"trace, lowercase": {"ip=8.8.8.8\nloc=de\n", "8.8.8.8", "DE"},
		"trace, no loc":    {"ip=8.8.8.8\n", "8.8.8.8", ""},
		"trace, no ip":     {"loc=JP\n", "", ""},
		"trace, private":   {"ip=10.0.0.1\nloc=JP\n", "", ""},
		"trace, ipv6":      {"ip=2a09:bac5:b106::15\nloc=JP\n", "", ""},
		"bare":             {" 52.35.237.101\n", "52.35.237.101", ""},
		"bare, private":    {"192.168.1.1", "", ""},
		"html":             {"<html>", "", ""},
		"empty":            {"", "", ""},
	} {
		addr, cc := ipv4Parse(c.in)
		if addr != c.addr || cc != c.cc {
			t.Errorf("%s: ipv4Parse = (%q, %q), want (%q, %q)", name, addr, cc, c.addr, c.cc)
		}
	}
}

func TestCountryCode(t *testing.T) {
	for in, want := range map[string]string{"JP": "JP", " us\n": "US", "XX": "", "T1": "", "JPN": "", "J": "", "1A": "", "": ""} {
		if got := countryCode(in); got != want {
			t.Errorf("countryCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPv4SnapshotStale(t *testing.T) {
	ipv4State.Lock()
	ipv4State.addr, ipv4State.cc, ipv4State.at = "8.8.8.8", "US", time.Now().Add(-ipv4Stale/2)
	ipv4State.Unlock()
	if got, cc := ipv4Snapshot(); got != "8.8.8.8" || cc != "US" {
		t.Fatalf("fresh answer: got %q %q", got, cc)
	}
	ipv4State.Lock()
	ipv4State.at = time.Now().Add(-ipv4Stale - 1)
	ipv4State.Unlock()
	if got, cc := ipv4Snapshot(); got != "" || cc != "" {
		t.Fatalf("stale answer: got %q %q, want none", got, cc)
	}
	ipv4State.Lock()
	ipv4State.addr = ""
	ipv4State.Unlock()
}

func TestIPv4SourceFromInstalledConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	if err := os.Unsetenv(ipv4EnvVar); err != nil {
		t.Fatal(err)
	}
	conf := configDir()
	if conf == "" {
		t.Skip("no config dir on this platform")
	}
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, tokenEnvFile), []byte("SUBNSUB_MONITOR_TOKEN=x\nMON_IPV4=off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ipv4Source(); got != "" {
		t.Fatalf("MON_IPV4=off in the installed config: ipv4Source() = %q, want none", got)
	}
}
