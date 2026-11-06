package main

// A copy helper to helper over a real tailcat tunnel and the public DERP:
// A's carrier serving its read-only grants as direct.go serves them (the
// allowlist with the grants' node keys, admitted as a grant is enrolled),
// B's fetch dialling A's address with the job's own key. Midway A's
// carrier is closed and started again from the same state, and B goes on
// from its part. Opt-in, as transport's own end-to-end passes are: it needs
// the network, and `go test ./...` must stay hermetic.
//
//	MON_E2E=1 go test -run E2EFetch -v .

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

func TestE2EFetchOverTailcat(t *testing.T) {
	if os.Getenv("MON_E2E") == "" {
		t.Skip("set MON_E2E=1 to run against a real DERP")
	}
	realDial := fetchDial
	f := newFetchFixture(t)
	fetchDial = realDial
	fetchBackoff = func(int) time.Duration { return 500 * time.Millisecond }

	state := filepath.Join(t.TempDir(), "state")
	// The page's own key, which a running helper always has on the list
	// (the carrier will not start an empty one).
	page := key.NewNode().Public()
	start := func() *transport.Tailcat {
		tc, err := transport.StartTailcat(transport.TailcatConfig{
			StateDir: state,
			Port:     directPort,
			Allowed:  func() []key.NodePublic { return append([]key.NodePublic{page}, activeGrantNodes()...) },
			Handler:  f.h,
		})
		if err != nil {
			t.Fatal(err)
		}
		setDirectAdmit(func(k key.NodePublic) {
			if !tc.Known(k) {
				tc.AddAllowed(k)
			}
		})
		return tc
	}
	tc := start()
	defer func() { tc.Close() }()
	t.Cleanup(func() { setDirectAdmit(nil) })
	addr := tc.ConnBlob()
	setDirectAddress(addr)

	src := filepath.Join(f.home, "Documents", "e2e.bin")
	want := randomFile(t, src, 24<<20+77)
	mod := time.Unix(1700000000, 0)
	os.Chtimes(src, mod, mod)
	dir := filepath.Join(f.home, "Reports")
	t0 := time.Now()
	f.startFetch(t, fetchSpec{job: "job-e2e-00000001", src: src, dir: dir, k: "partkey-e2e-00000001", addr: addr, s: int64(len(want)), m: mod.Unix()})

	waitFor := func(what string, limit time.Duration, ok func(v fetchView) bool) fetchView {
		deadline := time.Now().Add(limit)
		for {
			v := f.fetchStatus(t, "job-e2e-00000001")
			if ok(v) {
				return v
			}
			if v.St == "err" || time.Now().After(deadline) {
				// Where the job is, for whoever reads the failure.
				var buf bytes.Buffer
				pprof.Lookup("goroutine").WriteTo(&buf, 2)
				for _, g := range strings.Split(buf.String(), "\n\n") {
					if strings.Contains(g, "filesfetch.go") {
						t.Logf("%s", g)
					}
				}
				t.Fatalf("%s: %+v", what, v)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	v := waitFor("the first 6 MB", 3*time.Minute, func(v fetchView) bool { return v.Got >= 6<<20 })
	t.Logf("6 MB in %v, route %q", time.Since(t0).Round(time.Millisecond), v.Route)

	// A's carrier goes away and comes back from the same state, at the same
	// address: B asks again and goes on from its part.
	tc.Close()
	at := v.Got
	time.Sleep(2 * time.Second)
	tc = start()
	if tc.ConnBlob() != addr {
		t.Fatalf("the address changed across a restart")
	}
	v = waitFor("the whole file", 2*time.Minute, finished)
	if v.St != "done" {
		t.Fatalf("job: %+v", v)
	}
	got, err := os.ReadFile(filepath.Join(dir, "e2e.bin"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("the copy differs (%v, %d bytes)", err, len(got))
	}
	took := time.Since(t0)
	t.Logf("%d bytes in %v (%.1f MB/s), cut at %d, route %q", len(want), took.Round(time.Millisecond), float64(len(want))/took.Seconds()/(1<<20), at, v.Route)
	if ps := parts(t, dir); len(ps) != 0 {
		t.Fatalf("a part left behind: %v", ps)
	}
}
