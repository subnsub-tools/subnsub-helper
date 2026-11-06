package main

// The arithmetic in the health collector, tested directly.
//
// What this covers is deliberately the part that can be wrong QUIETLY. A
// missing disk figure is visible on the page; a CPU percentage computed from a
// wrapped counter is a plausible number that happens to be a lie, and nobody
// would ever notice. Reading /proc itself is not mocked out into a fake
// filesystem — that would test the mock — the parsers are fed the real strings
// those files produce.

import (
	"encoding/json"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
)

func hostnameForTest() (string, error) { return os.Hostname() }
func homeForTest() string              { h, _ := os.UserHomeDir(); return h }

func topLevelKeys(blob string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(blob), &m) != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func resetCPU() {
	cpuPrev.Lock()
	cpuPrev.valid, cpuPrev.busy, cpuPrev.total = false, 0, 0
	cpuPrev.Unlock()
}

func TestCPUDeltaNeedsTwoSamples(t *testing.T) {
	resetCPU()
	if got := cpuDelta(100, 1000); got != nil {
		t.Fatalf("first sample should report nothing, got %v", *got)
	}
	// 50 busy jiffies out of 100 elapsed.
	got := cpuDelta(150, 1100)
	if got == nil {
		t.Fatal("second sample should report a percentage")
	}
	if *got != 50 {
		t.Fatalf("want 50, got %v", *got)
	}
}

func TestCPUDeltaRejectsNonAdvancingAndBackwardCounters(t *testing.T) {
	for _, tc := range []struct {
		name          string
		busy1, total1 float64
		busy2, total2 float64
	}{
		{"same instant", 100, 1000, 100, 1000},
		{"total went backwards", 100, 1000, 100, 900},
		{"busy went backwards", 100, 1000, 90, 1100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCPU()
			cpuDelta(tc.busy1, tc.total1)
			if got := cpuDelta(tc.busy2, tc.total2); got != nil {
				t.Fatalf("want no reading, got %v", *got)
			}
		})
	}
}

// A counter that resets must not poison every later sample: the reading after
// the reset is skipped, and the one after THAT is correct again.
func TestCPUDeltaRecoversAfterReset(t *testing.T) {
	resetCPU()
	cpuDelta(5000, 10000)
	if got := cpuDelta(10, 20); got != nil {
		t.Fatalf("reset sample should report nothing, got %v", *got)
	}
	got := cpuDelta(35, 70)
	if got == nil || *got != 50 {
		t.Fatalf("want 50 after recovery, got %v", got)
	}
}

func TestCPUDeltaClampsToHundred(t *testing.T) {
	resetCPU()
	cpuDelta(0, 100)
	// Busy advancing faster than total cannot happen on a sane kernel; if it
	// does, 100 is the only defensible answer.
	got := cpuDelta(500, 200)
	if got == nil || *got != 100 {
		t.Fatalf("want 100, got %v", got)
	}
}

func TestShortKernel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"6.8.0-1050-oracle", "6.8"},
		{"24.5.0", "24.5"},
		{"5.15.0-generic\n", "5.15"},
		{"6.9-rc1", "6.9"},
		{"6.8", "6.8"},
	} {
		got := shortKernel(tc.in)
		if got == nil || *got != tc.want {
			t.Errorf("shortKernel(%q) = %v, want %q", tc.in, got, tc.want)
		}
	}
	// Never forward something that is not a version — this field exists to be
	// coarse, and passing an unparsed string through would defeat the point of
	// trimming it in the first place.
	for _, in := range []string{"", "linux", "  ", "notaversion", "6"} {
		if got := shortKernel(in); got != nil {
			t.Errorf("shortKernel(%q) = %q, want nil", in, *got)
		}
	}
}

// The kernel release must never carry the distro/cloud tail off the machine.
func TestShortKernelDropsVendorTail(t *testing.T) {
	got := shortKernel("6.8.0-1050-oracle")
	if got == nil {
		t.Fatal("want a version")
	}
	for _, leak := range []string{"oracle", "-", "1050"} {
		if strings.Contains(*got, leak) {
			t.Fatalf("%q leaked into %q", leak, *got)
		}
	}
}

func TestPct(t *testing.T) {
	if got := pct(50, 200); got == nil || *got != 25 {
		t.Fatalf("want 25, got %v", got)
	}
	// Rounded to two places, not truncated to an integer: a disk creeping from
	// 99.1 to 99.9 is worth seeing.
	if got := pct(1, 3); got == nil || *got != 33.33 {
		t.Fatalf("want 33.33, got %v", got)
	}
	for _, tc := range [][2]float64{{1, 0}, {1, -5}, {-1, 10}} {
		if got := pct(tc[0], tc[1]); got != nil {
			t.Errorf("pct(%v,%v) = %v, want nil", tc[0], tc[1], *got)
		}
	}
	if got := pct(300, 100); got == nil || *got != 100 {
		t.Fatalf("want clamp to 100, got %v", got)
	}
}

// The whole point of the block. Nothing identifying may appear in a snapshot,
// so this asserts against the machine's own real values rather than a fixture:
// if a future field starts carrying the hostname, this fails on the developer's
// own box before it ships.
func TestSnapshotCarriesNoIdentity(t *testing.T) {
	s := collectSystem()
	blob := string(dump(s))

	host, _ := hostnameForTest()
	forbidden := []string{}
	if host != "" && len(host) > 3 {
		forbidden = append(forbidden, host)
	}
	if home := homeForTest(); home != "" && len(home) > 3 {
		forbidden = append(forbidden, home)
	}
	for _, f := range forbidden {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(f)) {
			t.Errorf("snapshot leaked %q: %s", f, blob)
		}
	}
	// Keys are a closed set; a new one must be a deliberate decision reviewed
	// against the privacy bar, not something that arrived with a struct field.
	allowed := map[string]bool{
		"ok": true, "platform": true, "arch": true, "os_version": true,
		"cpu_count": true, "cpu_percent": true, "load1": true, "load5": true,
		"load15": true, "mem_total": true, "mem_used_percent": true,
		"swap_total": true, "swap_used_percent": true, "disk_total": true,
		"disk_used": true, "disk_used_percent": true, "uptime_sec": true,
		"net_rx_bps": true, "net_tx_bps": true, "procs": true, "temp_c": true,
		"tcp_estab": true, "tcp_time_wait": true, "tcp_retrans_ps": true,
		"missing": true,
		// Added 2026-08-06 by an explicit operator decision, not by a struct
		// field arriving unnoticed: interface names and local addresses were
		// refused until then (see the NICs note in system.go), and the ruling
		// was that a dashboard compared against other probes has to carry what
		// they carry, with the self-hosted relay as the answer for anyone
		// unwilling to send it.
		"net_rx_total": true, "net_tx_total": true, "nics": true,
		// The 2026-08-07 round, every one of them a reading about the machine's
		// WORK rather than about who it belongs to:
		//   cpu_*        where the CPU went (steal and iowait are the two that
		//                explain a slow box the percentage calls idle)
		//   mem_*        the cache/available split behind mem_used_percent
		//   swap_*_bps   pages actually moving, which is thrashing; the
		//                percentage alone cannot tell that from swap at rest
		//   disk_*_bps   the only fast-moving reading the card was missing
		//   net_*        packets, errors and drops from the row the byte
		//                counters already came from
		//   mounts       the OTHER filesystems. The one entry here carrying a
		//                string from the machine, and the reason foldMountPath
		//                exists. What that fold promises is narrower than "no
		//                identifying strings", and mounts.go says so at length:
		//                the segments an OS GENERATES from an account — the user
		//                under a home directory, the account under an automount
		//                root — are dropped, while a mount point somebody chose
		//                the words for, a Mac's disk label among them, is sent
		//                as written. The test above holds the first half
		//                against this box's own $HOME; TestFoldMountPath does it
		//                exhaustively.
		"cpu_user": true, "cpu_system": true, "cpu_iowait": true, "cpu_steal": true,
		"mem_available": true, "mem_cached": true, "mem_balloon": true,
		"swap_in_bps": true, "swap_out_bps": true,
		"disk_read_bps": true, "disk_write_bps": true, "mounts": true,
		"net_rx_packets": true, "net_tx_packets": true,
		"net_rx_errs": true, "net_tx_errs": true,
		"net_rx_drops": true, "net_tx_drops": true,
		// 2026-09-28, asked for by the operator: temp_c said a machine was hot
		// and not what on it was. One row per sensor — the kernel driver's name
		// and channel label, which come from kernel source rather than from
		// the machine, and numbers (temps.go).
		"temps": true,
		// 2026-10-26, asked for by the operator: a history of the temperature.
		// One number, the processor's or the hottest, and which of the two.
		"temp_main_c": true, "temp_main_cpu": true,
		// 2026-11-05, asked for by the operator: what the machine is, so the
		// page can draw a MacBook as a MacBook and a NAS as a NAS. Vendor,
		// model name, Apple's model identifier, a shape and a NAS's system —
		// a product line, never the serial or UUID that name one unit
		// (device.go, TestDeviceCarriesNoSerial).
		"device": true,
	}
	for _, k := range topLevelKeys(blob) {
		if !allowed[k] {
			t.Errorf("unexpected key %q in health snapshot", k)
		}
	}
}

func TestSnapshotReportsPlatform(t *testing.T) {
	s := collectSystem()
	if s.Platform != runtime.GOOS {
		t.Fatalf("platform %q, want %q", s.Platform, runtime.GOOS)
	}
	if s.Arch != runtime.GOARCH {
		t.Fatalf("arch %q, want %q", s.Arch, runtime.GOARCH)
	}
	// Every platform must account for what it cannot read. A collector that
	// silently reports nothing and claims nothing is missing is the failure
	// mode this whole design exists to avoid.
	if !s.OK && len(s.Missing) == 0 {
		t.Fatal("a snapshot that measured nothing must say what is missing")
	}
	for _, m := range s.Missing {
		switch m {
		case mCPU, mMemory, mSwap, mDisk, mDiskIO, mLoad, mUptime, mNetwork, mProcs:
		default:
			t.Errorf("unknown missing category %q", m)
		}
	}
}

func resetNet() { netPrev.reset() }

func TestNetDeltaNeedsTwoSamples(t *testing.T) {
	resetNet()
	rx, tx := netDelta(1000, 2000, 100)
	if rx != nil || tx != nil {
		t.Fatal("first sample should report nothing")
	}
	rx, tx = netDelta(11000, 4000, 110)
	if rx == nil || tx == nil {
		t.Fatal("second sample should report rates")
	}
	if *rx != 1000 || *tx != 200 {
		t.Fatalf("want 1000/200 B/s, got %v/%v", *rx, *tx)
	}
}

func TestNetDeltaRejectsShrinkingSumAndFrozenClock(t *testing.T) {
	resetNet()
	netDelta(50000, 50000, 100)
	// An interface vanished: the sum went backwards. No reading — and the new
	// (smaller) sample must become the baseline so the NEXT interval is real.
	if rx, _ := netDelta(40000, 50000, 130); rx != nil {
		t.Fatalf("shrinking rx must report nothing, got %v", *rx)
	}
	if rx, tx := netDelta(43000, 53000, 160); rx == nil || *rx != 100 || *tx != 100 {
		t.Fatal("interval after a reset should report against the new baseline")
	}
	// Same wall-clock twice — a rate with dt=0 is not a number.
	if rx, _ := netDelta(44000, 54000, 160); rx != nil {
		t.Fatal("non-advancing clock must report nothing")
	}
}

func TestNetDeltaIsSilentlyAbsentInMissingVocabulary(t *testing.T) {
	// temp has no missing word on purpose; network and procs do. This pins the
	// vocabulary so a rename in one place cannot silently orphan the page's
	// rendering of the other.
	for _, m := range []string{mNetwork, mProcs} {
		if m == "" {
			t.Fatal("missing vocabulary word is empty")
		}
	}
	if mNetwork != "network" || mProcs != "procs" {
		t.Fatalf("vocabulary drifted: %q %q", mNetwork, mProcs)
	}
}

func resetTCP() {
	tcpPrev.Lock()
	tcpPrev.valid, tcpPrev.retransAt, tcpPrev.at = false, 0, 0
	tcpPrev.Unlock()
}

func TestTCPDeltaNeedsTwoSamplesAndRecoversAfterReset(t *testing.T) {
	resetTCP()
	if got := tcpDelta(1000, 10); got != nil {
		t.Fatal("first retransmission sample should report nothing")
	}
	if got := tcpDelta(1010, 15); got == nil || *got != 2 {
		t.Fatalf("want 2 retransmissions/s, got %v", got)
	}
	if got := tcpDelta(3, 20); got != nil {
		t.Fatalf("reset sample should report nothing, got %v", *got)
	}
	if got := tcpDelta(8, 25); got == nil || *got != 1 {
		t.Fatalf("want recovery at 1/s, got %v", got)
	}
}

// The CPU split, which is cpuDelta's arithmetic applied four times with two
// extra ways to be wrong: a platform that keeps only some of the counters, and
// a bucket that outran the total it is a share of.
func TestCPUPartsDelta(t *testing.T) {
	resetCPUParts()
	// user, system, iowait, steal — the same order the collectors fill.
	if got := cpuPartsDelta([4]float64{10, 5, 1, 0}, 100); got[0] != nil {
		t.Fatal("first sample should report nothing")
	}
	got := cpuPartsDelta([4]float64{30, 15, 6, 2}, 200)
	// 20 of 100 jiffies to user, 10 to system, 5 to iowait, 2 to steal.
	for i, want := range []float64{20, 10, 5, 2} {
		if got[i] == nil {
			t.Fatalf("part %d missing", i)
		}
		if *got[i] != want {
			t.Errorf("part %d = %v, want %v", i, *got[i], want)
		}
	}
}

func TestCPUPartsDeltaOmitsWhatAPlatformCannotKeep(t *testing.T) {
	resetCPUParts()
	nan := math.NaN()
	cpuPartsDelta([4]float64{10, 5, nan, nan}, 100)
	got := cpuPartsDelta([4]float64{30, 15, nan, nan}, 200)
	if got[0] == nil || got[1] == nil {
		t.Fatal("the two Windows keeps should report")
	}
	// Not zero: "0% steal" is a claim about a hypervisor Windows cannot see.
	if got[2] != nil || got[3] != nil {
		t.Errorf("absent counters must stay absent, got %v/%v", got[2], got[3])
	}
}

func TestCPUPartsDeltaRejectsResetsAndImpossibleShares(t *testing.T) {
	resetCPUParts()
	cpuPartsDelta([4]float64{100, 50, 10, 5}, 1000)
	// Counters that went backwards — a reboot, or a container's view being
	// replaced. Not a negative share of the CPU.
	if got := cpuPartsDelta([4]float64{10, 5, 1, 0}, 2000); got[0] != nil {
		t.Errorf("a reset counter must report nothing, got %v", *got[0])
	}

	// ALL FOUR go, not just the one that went backwards. They come off a
	// single line of a single file, so one bucket resetting means the line is
	// from a different epoch — and the buckets whose arithmetic still works
	// would be a split assembled from two intervals and presented as one.
	resetCPUParts()
	cpuPartsDelta([4]float64{100, 50, 10, 5}, 1000)
	got := cpuPartsDelta([4]float64{200, 50, 10, 5}, 2000) // user grew, system flat, iowait…
	if got[0] == nil {
		t.Fatal("a clean interval should report")
	}
	resetCPUParts()
	cpuPartsDelta([4]float64{100, 50, 10, 5}, 1000)
	// …now the same interval with ONE bucket having gone backwards.
	got = cpuPartsDelta([4]float64{200, 150, 1, 25}, 2000)
	for i, v := range got {
		if v != nil {
			t.Errorf("bucket %d reported %v across a partial reset", i, *v)
		}
	}
	resetCPUParts()
	cpuPartsDelta([4]float64{0, 0, 0, 0}, 0)
	// A bucket that grew more than the total it is a share of means the two
	// were read at different instants.
	if got := cpuPartsDelta([4]float64{500, 0, 0, 0}, 100); got[0] != nil {
		t.Errorf("a share over 100%% must report nothing, got %v", *got[0])
	}
	resetCPUParts()
	cpuPartsDelta([4]float64{10, 5, 1, 0}, 100)
	// A total that did not move: two reads inside the same jiffy.
	if got := cpuPartsDelta([4]float64{10, 5, 1, 0}, 100); got[0] != nil {
		t.Errorf("a frozen total must report nothing, got %v", *got[0])
	}
}

func resetCPUParts() {
	cpuPartsPrev.Lock()
	cpuPartsPrev.valid, cpuPartsPrev.parts, cpuPartsPrev.total = false, [4]float64{}, 0
	cpuPartsPrev.Unlock()
}
