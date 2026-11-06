package main

// Machine health, reported alongside the quota numbers.
//
// THE BAR EVERY FIELD HERE HAS TO CLEAR: useful for deciding whether a machine
// needs attention, useless for working out whose machine it is. No hostname, no
// username, no serial, no MAC; mount paths folded so a home directory's name
// never travels (foldMountPath). "93% of the disk is gone" is actionable; "93% of
// /home/alice on build-07 is gone" is the same fact wearing an identity, and
// the relay has no business holding the second one.
//
// Three lines that were once held here have since been lifted by the operator,
// and the public threat-model page (monitor-security.html) says so in plain
// words rather than this file pretending otherwise: interface names and the
// addresses bound to them ARE sent (NICs below, nics.go, since 2026-08-06),
// the machine's public IPv4 IS looked up and sent unless MON_IPV4=off
// (ipv4.go), and a Mac's external disks go out under their volume labels
// (mounts.go, since 2026-10-23). Process NAMES are still never part of a
// snapshot: the twenty busiest processes go only on request (inspect.go) — in
// clear through the relay to the asking browser, which does not keep them —
// and the machine's OWN history file keeps the busiest program names per
// bucket (prochist.go), served over the tunnel only. The kernel version is
// deliberately cut to major.minor — "6.8" tells you whether a box is ancient,
// "6.8.0-1050-oracle" also tells an attacker who reads the relay which cloud
// to look at and which CVEs to try.
//
// COVERAGE IS HONEST RATHER THAN UNIFORM. Linux gets everything, because /proc
// hands it over for free. macOS gets what the standard library can reach
// without cgo, which is far less than you would hope: syscall.Sysctl returns a
// Go string cut at the first NUL byte, and SysctlUint32 refuses anything that
// is not exactly four bytes wide. Between them that rules out hw.memsize (64
// bits, leading zero bytes), vm.loadavg (a struct) and kern.boottime (a
// timeval) — every one of which would come back either empty or, worse,
// plausibly wrong. CGO_ENABLED=0 is not negotiable here (build.sh needs the
// Linux binaries genuinely static), so the mach APIs that would answer these
// are out of reach.
//
// So a platform reports what it can actually read, names what it cannot in
// `missing`, and the page renders that gap instead of a zero. A fabricated
// number is worse than an absent one: absent looks like a gap, wrong looks
// like a healthy machine.

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// One machine's health. Every measured field is a pointer: absent and zero are
// different claims, and "0% memory used" is not something any running computer
// should ever be able to say.
type System struct {
	OK       bool   `json:"ok"`
	Platform string `json:"platform"` // GOOS — "linux", "darwin"
	Arch     string `json:"arch"`     // GOARCH

	// Kernel release, cut to major.minor. Never the full uname string.
	OSVersion *string `json:"os_version,omitempty"`

	// What the machine is: a Mac mini or a MacBook, a Synology, a Raspberry
	// Pi, a cloud VM (device.go). A product line and a model name, never
	// anything that tells one machine of that model from another.
	Device *Device `json:"device,omitempty"`

	CPUCount   int      `json:"cpu_count,omitempty"`
	CPUPercent *float64 `json:"cpu_percent,omitempty"` // 0–100, differential

	// Where that percentage went, same differential and same units. One number
	// cannot answer the question people actually bring to a busy machine, and
	// two of these four answer it outright:
	//
	//	iowait  the CPU is idle and waiting for a disk. "Busy" is the wrong
	//	        word for it, which is why it is excluded from CPUPercent above
	//	        — but a box sitting at 40% iowait has a storage problem, and
	//	        with only CPUPercent to look at it appears to be resting.
	//	steal   time the hypervisor gave to somebody else. On an oversold VPS
	//	        this is the whole explanation for a machine that is slow while
	//	        reporting spare CPU, and it is the one number a tenant can act
	//	        on (by leaving).
	//
	// Platforms that cannot split the reading omit the fields rather than
	// reporting zeroes: "0% steal" is a claim about the hypervisor, and a Mac
	// is in no position to make it.
	CPUUser   *float64 `json:"cpu_user,omitempty"`
	CPUSystem *float64 `json:"cpu_system,omitempty"`
	CPUIOWait *float64 `json:"cpu_iowait,omitempty"`
	CPUSteal  *float64 `json:"cpu_steal,omitempty"`

	Load1  *float64 `json:"load1,omitempty"`
	Load5  *float64 `json:"load5,omitempty"`
	Load15 *float64 `json:"load15,omitempty"`

	MemTotal       *float64 `json:"mem_total,omitempty"` // bytes
	MemUsedPercent *float64 `json:"mem_used_percent,omitempty"`

	// The two figures behind that percentage, in bytes.
	//
	// MemUsedPercent is already computed against MemAvailable rather than
	// MemFree, so this helper never had the classic "Linux looks 90% full when
	// it is fine" bug. What it did have is no way for a reader to CHECK that:
	// a single percentage cannot say whether the missing memory is a process
	// or a page cache, and those need different reactions. Cached is what the
	// kernel would hand back under pressure; Available is what it promises it
	// can hand back.
	MemAvailable *float64 `json:"mem_available,omitempty"`
	MemCached    *float64 `json:"mem_cached,omitempty"`

	// Bytes the hypervisor has taken back through a virtio balloon, in bytes.
	//
	// On an overcommitted host (the Grok sandbox machines are the case in
	// hand) the guest's balloon driver hands idle pages to the host, and from
	// inside the VM those pages are neither free nor cache: they count as
	// used, MemAvailable shrinks by exactly that much, and a machine running
	// 2 GB of processes reads 80% full. The percentage above is honest — the
	// memory really is unavailable right now — but a reader has no way to
	// tell "a process grew" from "the host took it", and only the first is
	// something to do anything about. Linux only, from /proc/vmstat, and sent
	// only while it is non-zero: a VM whose balloon is deflated and a bare
	// metal box look the same, and should.
	MemBalloon *float64 `json:"mem_balloon,omitempty"`

	SwapTotal       *float64 `json:"swap_total,omitempty"`
	SwapUsedPercent *float64 `json:"swap_used_percent,omitempty"`

	// Swap TRAFFIC, bytes per second, differential like the network rates.
	//
	// Not the same question as SwapUsedPercent, and the more urgent one: swap
	// that was written days ago and never touched since costs nothing, so a
	// machine can sit at 80% swap used and be perfectly healthy. A machine
	// that is moving pages in and out right now is thrashing, and that shows
	// up here while the percentage barely moves.
	SwapInBps  *float64 `json:"swap_in_bps,omitempty"`
	SwapOutBps *float64 `json:"swap_out_bps,omitempty"`

	// The root filesystem only. A list of every mount would be a map of
	// somebody's machine, and the question this answers — "is it about to run
	// out of room" — is nearly always about /.
	//
	// DiskUsed is sent rather than left for the page to derive: the percentage
	// deliberately excludes root-reserved blocks and DiskTotal includes them,
	// so total × percent is not the used figure and overstates it.
	DiskTotal       *float64 `json:"disk_total,omitempty"`
	DiskUsed        *float64 `json:"disk_used,omitempty"`
	DiskUsedPercent *float64 `json:"disk_used_percent,omitempty"`

	// The OTHER filesystems, when a machine has any. The note above is still
	// right that "is it about to run out of room" is nearly always about /;
	// what it missed is that on a server with a data disk the answer is nearly
	// always about the data disk, and a card showing a comfortable root while
	// /data sits at 99% is confidently wrong.
	//
	// Paths are FOLDED before they are sent (see mounts.go): two segments at
	// most, and anything under a home directory collapses to the home itself.
	// That keeps `/mnt/backup` — which describes a disk — and refuses
	// `/home/alice/projects`, which describes a person. Root is not repeated
	// here; it has its own fields above.
	Mounts []Mount `json:"mounts,omitempty"`

	// Disk THROUGHPUT for the whole machine, bytes per second, summed over
	// physical block devices. A rate, so like every other rate here it needs
	// two samples and reports nothing on the first.
	//
	// The gap this closes: CPU and network were the only two fast-moving
	// numbers on the card, so a machine pinned by its disk looked idle in
	// every reading it sent. Paired with cpu_iowait above, the pair says which
	// of "waiting on the disk" and "the disk is working hard" is happening.
	DiskReadBps  *float64 `json:"disk_read_bps,omitempty"`
	DiskWriteBps *float64 `json:"disk_write_bps,omitempty"`

	UptimeSec *float64 `json:"uptime_sec,omitempty"`

	// Whole-box traffic, bytes per second, summed over every interface except
	// loopback. A rate like CPUPercent, so it needs two samples and the first
	// collection reports nothing. The SUM is the privacy line here: per-
	// interface rows would name interfaces, and interface names on a modern box
	// (wg0, tailscale0, br-<hash>) describe what the machine is connected to.
	NetRxBps *float64 `json:"net_rx_bps,omitempty"`
	NetTxBps *float64 `json:"net_tx_bps,omitempty"`

	// Total bytes moved since boot, over the same interfaces as the rate above.
	// A rate answers "is it busy now"; the total answers "how much of this
	// month's allowance is gone", which on a metered box is the question that
	// actually costs money. Counters reset when the machine does, and nothing
	// here pretends otherwise — the page shows what the box reports.
	NetRxTotal *float64 `json:"net_rx_total,omitempty"`
	NetTxTotal *float64 `json:"net_tx_total,omitempty"`

	// Packets, errors and drops over those same interfaces, cumulative.
	//
	// Counts rather than rates, and the packet totals are here so they can be
	// read as a PROPORTION: a thousand dropped packets is a catastrophe on a
	// machine that has sent ten thousand and a rounding error on one that has
	// sent ten billion, and a bare drop count cannot tell those apart. The
	// division is left to the reader — the helper does not send a computed
	// ratio, because the two counters can be reset by different things (an
	// interface disappearing takes both of ITS numbers out of the sum).
	//
	// What this catches that the byte counters cannot: a link that is losing
	// traffic. Bytes keep flowing and the rate looks healthy right up until
	// somebody asks why everything feels slow.
	NetRxPackets *float64 `json:"net_rx_packets,omitempty"`
	NetTxPackets *float64 `json:"net_tx_packets,omitempty"`
	NetRxErrs    *float64 `json:"net_rx_errs,omitempty"`
	NetTxErrs    *float64 `json:"net_tx_errs,omitempty"`
	NetRxDrops   *float64 `json:"net_rx_drops,omitempty"`
	NetTxDrops   *float64 `json:"net_tx_drops,omitempty"`

	// Every interface the machine has, with the addresses bound to it.
	//
	// This is the one section of this file that used to refuse to exist: the
	// note on NetRxBps held that interface names describe what a machine is
	// connected to, and it was right. The operator lifted the line on
	// 2026-08-06 — a dashboard people compare against other probes has to show
	// what those show, and anyone unwilling to send this has a self-hosted
	// relay to point the helper at instead.
	//
	// It is also the only place the machine's own IPv6 can come from: the
	// egress address on the card is what the edge observed of ONE connection,
	// so a dual-stack box has an address the relay can never see.
	NICs []NIC `json:"nics,omitempty"`

	// Aggregate TCP health: counts and a retransmission rate, never endpoints,
	// addresses, ports or interface names. Like network throughput, the counter
	// rate needs two samples and is omitted on the first collection.
	TCPEstab     *float64 `json:"tcp_estab,omitempty"`
	TCPTimeWait  *float64 `json:"tcp_time_wait,omitempty"`
	TCPRetransPS *float64 `json:"tcp_retrans_ps,omitempty"`

	// How many processes exist, not what any of them is. The count answers
	// "is something leaking processes"; a list would answer "what does this
	// person run", which is the question this file refuses.
	Procs *float64 `json:"procs,omitempty"`

	// Hottest sensor, °C. Absent-and-silent when the platform exposes no
	// sensor — which is every VM — so, unlike the fields above, absence here is
	// a configuration and never reported in `missing`. Same judgement as swap.
	TempC *float64 `json:"temp_c,omitempty"`

	// The machine's main temperature (temps.go mainTemp): the processor's,
	// taken over every sensor rather than the rows Temps has room for, or the
	// hottest where no processor sensor is known — TempMainCPU says which.
	// What the page's Temp tile shows and what the history keeps.
	TempMainC   *float64 `json:"temp_main_c,omitempty"`
	TempMainCPU bool     `json:"temp_main_cpu,omitempty"`

	// The sensors that number is the hottest of, one row each (temps.go):
	// driver name, channel label, reading and the driver's own limits. Linux
	// only, and absent on the same machines temp_c is.
	Temps []Temp `json:"temps,omitempty"`

	// What this platform could not read, so the page can say "not available
	// here" rather than leaving a reader to guess whether the machine is idle
	// or the collector is broken.
	Missing []string `json:"missing,omitempty"`

	// The fast-moving readings above, sampled every `step` seconds since the
	// last push instead of once when it happened. Absent unless a sampler is
	// running (see sampler.go) — one-shot and serve collections carry the
	// snapshot alone, which is all a single collection can honestly claim.
	Series *SysSeries `json:"series,omitempty"`
}

// One interface as the machine sees it: what it is called, what is bound to
// it, and how much it has carried since boot. Built by fillNICs (nics.go);
// the counters are attached by whichever platform collector already walks the
// per-interface table for the whole-box sum.
type NIC struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips,omitempty"`
	RxTotal *float64 `json:"rx_total,omitempty"`
	TxTotal *float64 `json:"tx_total,omitempty"`
	Up      bool     `json:"up,omitempty"`
}

// One filesystem other than root. Path is already folded (foldMountPath) by
// the time it lands here; Used and UsedPercent are split for the same reason
// the root fields are — the percentage's denominator excludes root-reserved
// blocks and Total includes them, so one cannot be derived from the other.
type Mount struct {
	Path        string   `json:"path"`
	Total       *float64 `json:"total,omitempty"`
	Used        *float64 `json:"used,omitempty"`
	UsedPercent *float64 `json:"used_percent,omitempty"`
}

// One frame's worth of samples, oldest first, laid on a fixed grid.
//
// The last slot of every array is the snapshot this rides on — the same
// measurement, rounded for the wire — so the gauges and the end of the line
// can never disagree. Only the readings that visibly move are carried: disk, swap, load,
// process count and temperature change on a scale where one point per push is
// already more resolution than the eye asks for, and thirty copies of an
// unchanged number would be most of the frame.
type SysSeries struct {
	// When the LAST slot was taken, on the machine's clock. The page anchors
	// the series to the relay's clock through this: the frame's captured_at is
	// the same clock, so (captured_at − at) is a lag the page can subtract
	// from the relay's seen_at without ever trusting a machine's absolute time.
	At   float64 `json:"at"`
	Step float64 `json:"step"` // seconds per slot

	// nil where the platform cannot read that metric at all; a nil ELEMENT is
	// a slot with no sample in it.
	CPU []*float64 `json:"cpu,omitempty"`
	Mem []*float64 `json:"mem,omitempty"`
	Rx  []*float64 `json:"rx,omitempty"`
	Tx  []*float64 `json:"tx,omitempty"`
	// The disk's two rates, a second at a time (audit 2026-10-16): the
	// history keeps their peak, as it keeps the network's.
	IORead  []*float64 `json:"io_read,omitempty"`
	IOWrite []*float64 `json:"io_write,omitempty"`
}

// Ordered so the page can render a stable list; also the vocabulary Missing
// draws from, kept in one place so a typo cannot invent a category.
const (
	mCPU     = "cpu"
	mMemory  = "memory"
	mSwap    = "swap"
	mDisk    = "disk"
	mLoad    = "load"
	mUptime  = "uptime"
	mNetwork = "network"
	mProcs   = "procs"
	// Disk THROUGHPUT, which is a separate answer from mDisk (capacity): Linux
	// reads both, and the platforms that can only measure how full a disk is
	// say so rather than letting the absent rate read as a quiet disk.
	mDiskIO = "diskio"
	// No mTemp: a sensorless machine is a configuration, not a gap — see TempC.
	// No mMounts either, for the same reason: a machine with one filesystem is
	// a normal machine, not one that failed to report the others.
)

func (s *System) miss(what string) { s.Missing = append(s.Missing, what) }

// CPU usage is a rate, and a rate needs two samples. The first collection
// after startup therefore has no percentage to report — which is correct and
// stated, not filled in with the since-boot average. That average is a
// different quantity that happens to have the same units, and on a box that
// was hammered last week and is idle now it reads as permanently busy.
var cpuPrev struct {
	sync.Mutex
	valid       bool
	busy, total float64
}

// Feed one /proc/stat-style reading in, get the percentage since the previous
// one out. Split from the Linux collector so the arithmetic — which is where
// the counter-wrap and divide-by-zero traps live — can be tested directly.
func cpuDelta(busy, total float64) *float64 {
	cpuPrev.Lock()
	defer cpuPrev.Unlock()

	prevValid, prevBusy, prevTotal := cpuPrev.valid, cpuPrev.busy, cpuPrev.total
	cpuPrev.valid, cpuPrev.busy, cpuPrev.total = true, busy, total

	if !prevValid {
		return nil
	}
	dt, db := total-prevTotal, busy-prevBusy
	// Two pushes inside the same jiffy give dt == 0; a counter that went
	// backwards means a reset (or a machine that slept through it). Neither is
	// a reading — report nothing rather than 0%, NaN or a spike.
	if dt <= 0 || db < 0 {
		return nil
	}
	pct := db / dt * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return fp(round2(pct))
}

// The same differencing cpuDelta does, applied to the counters BEHIND that
// percentage. NaN marks a counter this platform does not keep — Windows has
// neither iowait nor steal — and comes back nil, never as a zero that would
// read as "measured, and none".
//
// Separate previous-reading state from cpuPrev rather than one struct holding
// both: the two are always read from the same line and updated together, and
// keeping them apart means a platform can adopt one without the other (macOS
// reports its split as percentages that never touch this path at all).
var cpuPartsPrev struct {
	sync.Mutex
	valid bool
	parts [4]float64
	total float64
}

func cpuPartsDelta(parts [4]float64, total float64) [4]*float64 {
	cpuPartsPrev.Lock()
	defer cpuPartsPrev.Unlock()

	prevValid, prevParts, prevTotal := cpuPartsPrev.valid, cpuPartsPrev.parts, cpuPartsPrev.total
	cpuPartsPrev.valid, cpuPartsPrev.parts, cpuPartsPrev.total = true, parts, total

	var out [4]*float64
	if !prevValid {
		return out
	}
	dt := total - prevTotal
	if dt <= 0 {
		return out
	}
	// ALL OR NOTHING across the four. They are read from one line of one file,
	// so a bucket that went backwards means the whole line came from a
	// different epoch — a container's view being replaced, a counter reset —
	// and the buckets that happen to still make arithmetic sense would be a
	// split from two different intervals presented as one.
	var d [4]float64
	for i, v := range parts {
		if math.IsNaN(v) || math.IsNaN(prevParts[i]) {
			continue // this platform does not keep this counter at all
		}
		d[i] = v - prevParts[i]
		// One that outran the total means the two were read at different
		// instants; one that went backwards is a reset.
		if d[i] < 0 || d[i] > dt {
			return out
		}
	}
	for i, v := range parts {
		if math.IsNaN(v) || math.IsNaN(prevParts[i]) {
			continue
		}
		out[i] = fp(round2(d[i] / dt * 100))
	}
	return out
}

// Two cumulative counters and a clock in, two per-second rates out.
//
// Network bytes, disk bytes and swapped pages are all this shape, and all three
// share the traps: a rate needs two samples AND the wall-clock span between
// them (unlike cpuDelta, whose jiffies carry their own time base), the first
// sample can only report nothing, and a counter that went BACKWARDS is a reset
// rather than a negative rate. That last one is not hypothetical for any of the
// three — the network sum shrinks whenever an interface disappears (a
// container's veth being torn down is routine), the disk sum shrinks when a
// device is unplugged, and both counters restart from zero on a reboot.
type pairRate struct {
	sync.Mutex
	valid    bool
	a, b, at float64
	// Which population the counters were summed over, when the caller has one
	// — see deltaOver. Empty for the callers whose set cannot change.
	key string
}

func (p *pairRate) delta(a, b, at float64) (aps, bps *float64) {
	return p.deltaOver("", a, b, at)
}

// The same rate, over a named POPULATION — the set of devices or interfaces the
// two counters were summed across. A different population is a different sum,
// and differencing across the change invents traffic that never happened: plug
// in a disk that has served a terabyte and its whole lifetime counter lands in
// one second of I/O.
//
// The key is compared, the baseline is dropped and the new one is seeded all
// inside ONE critical section, which is the half that a first attempt at this
// got wrong: with the membership check in its own lock, two collections can
// interleave so that the one which noticed the change publishes the new key
// first and the other then differences the new population against the old
// baseline — producing exactly the spike the check exists to prevent.
func (p *pairRate) deltaOver(key string, a, b, at float64) (aps, bps *float64) {
	p.Lock()
	defer p.Unlock()

	prevValid, prevA, prevB, prevAt := p.valid, p.a, p.b, p.at
	sameKey := p.key == key
	p.valid, p.a, p.b, p.at, p.key = true, a, b, at, key

	if !prevValid || !sameKey {
		return nil, nil
	}
	dt := at - prevAt
	if dt <= 0 {
		return nil, nil
	}
	dA, dB := a-prevA, b-prevB
	if dA < 0 || dB < 0 {
		return nil, nil
	}
	return fp(round2(dA / dt)), fp(round2(dB / dt))
}

func (p *pairRate) reset() {
	p.Lock()
	defer p.Unlock()
	p.valid, p.a, p.b, p.at, p.key = false, 0, 0, 0, ""
}

var netPrev pairRate

// Bytes read and written across the machine's physical block devices, and
// bytes swapped in and out. Their own previous-reading state, because they are
// read from different files at different times and one being unavailable must
// not blank the other.
var diskIOPrev, swapIOPrev pairRate

var tcpPrev struct {
	sync.Mutex
	valid     bool
	retransAt float64
	at        float64
}

func tcpDelta(retrans, at float64) *float64 {
	tcpPrev.Lock()
	defer tcpPrev.Unlock()
	valid, old, oldAt := tcpPrev.valid, tcpPrev.retransAt, tcpPrev.at
	tcpPrev.valid, tcpPrev.retransAt, tcpPrev.at = true, retrans, at
	if !valid || at <= oldAt || retrans < old {
		return nil
	}
	return fp(round2((retrans - old) / (at - oldAt)))
}

// Feed one cumulative (rx, tx) reading in, get bytes-per-second since the
// previous one out. Named rather than called through the type, because both
// platform collectors already say netDelta and the name is the documentation.
func netDelta(rx, tx, at float64) (rxBps, txBps *float64) {
	return netPrev.delta(rx, tx, at)
}

// Kernel release trimmed to major.minor: "6.8.0-1050-oracle" -> "6.8",
// "24.5.0" -> "24.5". Anything that does not look like a version at all is
// dropped entirely rather than forwarded — this field exists to be coarse.
func shortKernel(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return nil
	}
	major, err1 := strconv.Atoi(parts[0])
	minorField := parts[1]
	// "8-rc1" and friends: keep the leading digits, drop the rest.
	end := 0
	for end < len(minorField) && minorField[end] >= '0' && minorField[end] <= '9' {
		end++
	}
	minor, err2 := strconv.Atoi(minorField[:end])
	if err1 != nil || err2 != nil || major < 0 || minor < 0 {
		return nil
	}
	return sp(strconv.Itoa(major) + "." + strconv.Itoa(minor))
}

// Read a small pseudo-file. /proc entries are generated on read and are tiny,
// but this runs on other people's machines against paths this program does not
// own, so the read is bounded anyway.
func readSmall(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	n, err := f.Read(buf)
	if n <= 0 || (err != nil && n == 0) {
		return "", false
	}
	return string(buf[:n]), true
}

func pct(used, total float64) *float64 {
	if total <= 0 || used < 0 {
		return nil
	}
	p := used / total * 100
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return fp(round2(p))
}

// Collect, contained. Same reasoning as safeCollect for providers: this reads
// files and syscalls on machines the author has never seen, and a panic here
// must not take the quota numbers down with it.
func collectSystem() (s System) {
	defer func() {
		if r := recover(); r != nil {
			s = System{OK: false, Platform: runtime.GOOS, Arch: runtime.GOARCH,
				Missing: []string{mCPU, mMemory, mSwap, mDisk, mDiskIO, mLoad, mUptime, mNetwork, mProcs}}
		}
	}()
	return systemSnapshot()
}

// The shell every platform collector starts from, so none of them can forget
// the fields that are free everywhere. The interface list is one of them —
// net.Interfaces() is stdlib on every target, so a platform with no collector
// of its own still reports its addresses rather than nothing.
func baseSystem() System {
	s := System{Platform: runtime.GOOS, Arch: runtime.GOARCH, CPUCount: runtime.NumCPU(), Device: machineDevice()}
	fillNICs(&s)
	return s
}
