//go:build linux

package main

// Linux reads everything out of /proc and one statfs. No cgo, no shelling out,
// no /etc/os-release (that file carries a pretty name and sometimes a build ID,
// and the kernel release alone answers the question this field is for).
//
// Android is Linux and compiles this file, but an app there is refused most of
// /proc (android_linux.go says which files and since when). Where a syscall
// answers the same question, the collector falls back to it; where nothing
// does, it reports the gap like every other platform. The one place Android
// changes WHAT is measured rather than how: "/" there is a read-only system
// image, so the root disk is /data — see linuxRootPath.

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func systemSnapshot() System {
	s := baseSystem()

	if v, ok := readSmall("/proc/sys/kernel/osrelease"); ok {
		s.OSVersion = shortKernel(v)
	} else if v := unameRelease(); v != "" {
		// The file is refused to Android apps; uname(2) is refused to nobody.
		s.OSVersion = shortKernel(v)
	}

	linuxCPU(&s)
	linuxMem(&s)
	linuxBalloon(&s)
	linuxSwapIO(&s)
	linuxLoad(&s)
	linuxUptime(&s)
	statfsRoot(&s, linuxRootPath())
	linuxMounts(&s)
	linuxDiskIO(&s)
	linuxNet(&s)
	linuxTCP(&s)
	linuxProcs(&s)
	linuxTemp(&s)

	// "ok" means the collector ran and produced at least one measurement — not
	// that everything worked. A machine where /proc is masked (some hardened
	// containers) still reports its platform and core count, and the page shows
	// the gaps rather than an error card.
	s.OK = s.CPUPercent != nil || s.MemUsedPercent != nil || s.Load1 != nil ||
		s.UptimeSec != nil || s.DiskUsedPercent != nil || s.TCPEstab != nil || s.TCPTimeWait != nil
	return s
}

// First line of /proc/stat:
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
//
// Everything is busy except idle and iowait. guest and guest_nice are already
// counted inside user and nice — adding them again inflates total and quietly
// deflates the percentage, which is the classic way to write this wrong.
func linuxCPU(s *System) {
	raw, ok := readSmall("/proc/stat")
	if !ok {
		s.miss(mCPU)
		return
	}
	line := raw
	if i := strings.IndexByte(raw, '\n'); i >= 0 {
		line = raw[:i]
	}
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		s.miss(mCPU)
		return
	}
	var total, idle float64
	// user+nice, system+irq+softirq, iowait, steal — the four the card shows.
	// nice rides with user and the two interrupt buckets ride with system on
	// purpose: they are the same time viewed at a finer grain than the question
	// "where did the CPU go" is ever asked at, and four numbers that sum with
	// idle to a hundred is a thing a reader can check at a glance. Five that
	// nearly do is not.
	var parts [4]float64
	for i, v := range f[1:] {
		if i >= 8 { // stop before guest / guest_nice
			break
		}
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			s.miss(mCPU)
			return
		}
		total += n
		switch i {
		case 0, 1: // user, nice
			parts[0] += n
		case 2, 5, 6: // system, irq, softirq
			parts[1] += n
		case 3: // idle
			idle += n
		case 4: // iowait — idle for the purposes of CPUPercent, and its own
			idle += n // number here, because a machine stuck on its disk is not resting
			parts[2] += n
		case 7: // steal
			parts[3] += n
		}
	}
	// Taken unconditionally, even on the branch that reports no percentage:
	// this differencer holds its own previous reading, and skipping the call
	// would leave it holding one from before whatever gap just happened.
	split := cpuPartsDelta(parts, total)
	s.CPUUser, s.CPUSystem, s.CPUIOWait, s.CPUSteal = split[0], split[1], split[2], split[3]
	if p := cpuDelta(total-idle, total); p != nil {
		s.CPUPercent = p
	} else {
		// No previous sample yet (or the counters moved backwards). Say so:
		// the very first push after install would otherwise show a machine
		// with no CPU line and no explanation.
		s.miss(mCPU)
	}
}

// MemAvailable, not MemFree. MemFree on a healthy Linux box is small by design
// — the page cache is doing its job — and reporting it as "used" makes every
// machine look like it is about to die.
func linuxMem(s *System) {
	raw, ok := readSmall("/proc/meminfo")
	if !ok {
		s.miss(mMemory)
		s.miss(mSwap)
		return
	}
	kb := map[string]float64{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseFloat(fields[0], 64)
		if err != nil || n < 0 {
			continue
		}
		kb[k] = n * 1024 // every value in meminfo is kB
	}

	// comma-ok on every lookup, because a map's zero value and a real zero are
	// indistinguishable and the failure is silent AND alarming: MemAvailable
	// is absent on kernels before 3.14, and reading that missing key as 0
	// reports the machine at 100% memory — a fake emergency on an idle box.
	// Same for SwapFree if the read was truncated.
	total, okT := kb["MemTotal"]
	avail, okA := kb["MemAvailable"]
	if okT && okA && total > 0 && avail >= 0 && avail <= total {
		s.MemTotal = fp(total)
		s.MemUsedPercent = pct(total-avail, total)
		s.MemAvailable = fp(avail)
		s.MemCached = linuxCached(kb, total)
	} else {
		s.miss(mMemory)
	}

	swTotal, okS := kb["SwapTotal"]
	swFree, okF := kb["SwapFree"]
	if okS && swTotal > 0 {
		s.SwapTotal = fp(swTotal)
		if okF && swFree >= 0 && swFree <= swTotal {
			s.SwapUsedPercent = pct(swTotal-swFree, swTotal)
		} else {
			s.miss(mSwap)
		}
	}
	// Swap being absent entirely is a configuration, not a failure — most cloud
	// images ship without it — so THAT case is not reported as missing.
}

// The reclaimable part of what memory is being used for, in bytes.
//
// Cached + Buffers + SReclaimable, MINUS Shmem, and the subtraction is the
// whole reason this is a function rather than a lookup: tmpfs pages (a /run,
// a /dev/shm, a container's writable layer) are counted inside Cached and are
// NOT reclaimable — they are somebody's data with nowhere else to live. A card
// that showed them as cache would tell an operator with a full /dev/shm that
// the kernel could give the memory back on demand, which it cannot.
//
// Every part is optional and missing ones simply contribute nothing: kernels
// disagree about which of these exist, and this is a supporting figure. It is
// dropped entirely if it comes out impossible, which is what a disagreement
// between the two would look like.
func linuxCached(kb map[string]float64, total float64) *float64 {
	cached, ok := kb["Cached"]
	if !ok {
		return nil
	}
	v := cached + kb["Buffers"] + kb["SReclaimable"] - kb["Shmem"]
	if v < 0 || v > total || !finite(v) {
		return nil
	}
	return fp(v)
}

// Memory the host has taken back through a virtio balloon, from /proc/vmstat.
//
// balloon_inflate and balloon_deflate are cumulative page counts (the
// counters exist only when the kernel was built with the balloon driver and
// are zero until a device shows up), so their difference is the number of
// pages the balloon holds right now. Held pages are what the host has
// reclaimed: the guest cannot touch them until the host deflates, or — with
// DEFLATE_ON_OOM negotiated — until the guest is about to kill something.
//
// Only reported while non-zero. The counters are present on every distro
// kernel, including bare metal where they will never move, and "0 B taken by
// host" on every card would be noise saying nothing.
func linuxBalloon(s *System) {
	raw, ok := readSmall("/proc/vmstat")
	if !ok {
		return
	}
	if v, ok := balloonBytes(raw, float64(os.Getpagesize())); ok {
		s.MemBalloon = fp(v)
	}
}

// The balloon's current size in bytes, or false when there is nothing to
// say: no counters, a page size that makes no sense, or a deflate count
// ahead of inflate (which a real kernel never produces and which would
// otherwise turn into a negative figure on a card).
func balloonBytes(vmstat string, page float64) (float64, bool) {
	var inflate, deflate float64
	var okIn, okDe bool
	for _, line := range strings.Split(vmstat, "\n") {
		k, v, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || n < 0 || !finite(n) {
			continue
		}
		switch k {
		case "balloon_inflate":
			inflate, okIn = n, true
		case "balloon_deflate":
			deflate, okDe = n, true
		}
	}
	if !okIn || !okDe || page <= 0 || deflate > inflate {
		return 0, false
	}
	held := (inflate - deflate) * page
	if held <= 0 || !finite(held) {
		return 0, false
	}
	return held, true
}

// Swap traffic, from /proc/vmstat's cumulative page counters.
//
// pswpin/pswpout count PAGES, and the page size is read from the runtime
// rather than assumed to be 4 KiB: arm64 kernels are built with 4, 16 and 64
// KiB pages, and a Raspberry Pi reporting a sixteenth of its real swap traffic
// would look calm while it thrashed.
func linuxSwapIO(s *System) {
	raw, ok := readSmall("/proc/vmstat")
	if !ok {
		return
	}
	var in, out float64
	var okIn, okOut bool
	for _, line := range strings.Split(raw, "\n") {
		k, v, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || n < 0 || !finite(n) {
			continue
		}
		switch k {
		case "pswpin":
			in, okIn = n, true
		case "pswpout":
			out, okOut = n, true
		}
	}
	if !okIn || !okOut {
		return
	}
	page := float64(os.Getpagesize())
	if page <= 0 {
		return
	}
	// No `missing` entry on the first sample, unlike the network rate: swap
	// traffic is almost always zero, so a machine that has never swapped and a
	// machine that has not been measured yet look identical on the card either
	// way. Saying "swap I/O not reported" about a healthy box would be noise.
	s.SwapInBps, s.SwapOutBps = swapIOPrev.delta(in*page, out*page, now())
}

// df/statvfs scale block counts by the fundamental fragment size, not by
// f_bsize (which Linux reports as the optimal transfer size). They are equal
// on most filesystems, which is exactly why using the wrong one survives
// casual testing and then reports a wrong total on the one filesystem where
// they differ.
func fsBlockSize(st *syscall.Statfs_t) float64 {
	if st.Frsize > 0 {
		return float64(st.Frsize)
	}
	return float64(st.Bsize)
}

// /proc/net/dev, everything summed except loopback:
//
//	Inter-|   Receive                            ...|  Transmit
//	 face |bytes    packets errs drop fifo frame ...|bytes    packets ...
//	    lo: 1234567     890    0    0    0     0    ...
//	  eth0: 9876543    2109    0    0    0     0    ...
//
// The sum is what travels (see NetRxBps in system.go for why no per-interface
// rows), and lo is excluded because local chatter would drown the number the
// gauge exists to show. Interface names are read to make that one exclusion
// and are never kept.
func linuxNet(s *System) {
	raw, ok := readSmall("/proc/net/dev")
	if !ok {
		// Refused to Android apps since 10. sysfs may still answer.
		linuxNetSysfs(s)
		return
	}
	var rx, tx float64
	var sawAny bool
	// Packets, errors and drops from the same rows. Summed separately from the
	// bytes because the columns that carry them arrive later on the line and an
	// interface driver that reports a short row must cost its error counts and
	// not its traffic.
	var rxPk, txPk, rxErr, txErr, rxDrop, txDrop float64
	var sawCounts bool
	countsWhole := true
	// The same walk now feeds the per-interface rows too — one read of the
	// table, two uses of it (see nicCounters).
	perRx := make(map[string]float64, 8)
	perTx := make(map[string]float64, 8)
	for _, line := range strings.Split(raw, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "lo" {
			continue
		}
		f := strings.Fields(rest)
		// bytes is field 0 on the receive side and field 8 on the transmit side.
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseFloat(f[0], 64)
		t, err2 := strconv.ParseFloat(f[8], 64)
		if err1 != nil || err2 != nil || r < 0 || t < 0 || !finite(r) || !finite(t) {
			continue
		}
		rx += r
		tx += t
		perRx[name], perTx[name] = r, t
		sawAny = true

		// Receive:  bytes packets errs drop fifo frame compressed multicast
		// Transmit: bytes packets errs drop fifo colls carrier compressed
		// — so packets/errs/drop are 1/2/3 on the receive side and 9/10/11 on
		// the transmit side. All six or none: a row this cannot fully account
		// for is a row whose columns are not where this thinks they are, and
		// half-parsing it would add one interface's errors to another's total.
		// EVERY interface that contributed bytes has to contribute counts too,
		// or none of them do. An interface whose byte columns parse while its
		// count columns are short leaves a total that covers a different set of
		// interfaces than the byte total does — and the page divides one by the
		// other to say how bad a drop rate is.
		if len(f) < 12 {
			countsWhole = false
			continue
		}
		v, okCounts := parseNonNeg(f[1], f[2], f[3], f[9], f[10], f[11])
		if !okCounts {
			countsWhole = false
			continue
		}
		rxPk, rxErr, rxDrop = rxPk+v[0], rxErr+v[1], rxDrop+v[2]
		txPk, txErr, txDrop = txPk+v[3], txErr+v[4], txDrop+v[5]
		sawCounts = true
	}
	if !sawAny {
		s.miss(mNetwork)
		return
	}
	if sawCounts && countsWhole {
		s.NetRxPackets, s.NetTxPackets = fp(rxPk), fp(txPk)
		s.NetRxErrs, s.NetTxErrs = fp(rxErr), fp(txErr)
		s.NetRxDrops, s.NetTxDrops = fp(rxDrop), fp(txDrop)
	}
	// The totals stand on their own: unlike the rate below they need no second
	// sample, so the first push after a restart already carries them.
	s.NetRxTotal, s.NetTxTotal = fp(rx), fp(tx)
	nicCounters(s, perRx, perTx)
	rxBps, txBps := netDelta(rx, tx, now())
	if rxBps == nil {
		// First sample since startup, or the sum went backwards (an interface
		// vanished). Both are "no reading yet", and saying so beats a zero.
		s.miss(mNetwork)
		return
	}
	s.NetRxBps, s.NetTxBps = rxBps, txBps
}

// The whole-box byte counters from sysfs, for a process that may not read
// /proc/net/dev. /sys/class/net lists the interfaces and each one's
// statistics directory holds one number per file. Packets, errors and drops
// are left out here on purpose: six more files per interface for a fallback
// road, when the rate and the totals are what the card cannot do without.
func linuxNetSysfs(s *System) {
	perRx, perTx, ok := sysfsNetCounters()
	if !ok {
		s.miss(mNetwork)
		return
	}
	var rx, tx float64
	for name := range perRx {
		rx += perRx[name]
		tx += perTx[name]
	}
	s.NetRxTotal, s.NetTxTotal = fp(rx), fp(tx)
	nicCounters(s, perRx, perTx)
	rxBps, txBps := netDelta(rx, tx, now())
	if rxBps == nil {
		s.miss(mNetwork)
		return
	}
	s.NetRxBps, s.NetTxBps = rxBps, txBps
}

func sysfsNetCounters() (rx, tx map[string]float64, ok bool) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, nil, false
	}
	rx, tx = map[string]float64{}, map[string]float64{}
	for _, e := range entries {
		name := e.Name()
		if name == "" || name == "lo" {
			continue
		}
		r, okR := readSysfsNumber("/sys/class/net/" + name + "/statistics/rx_bytes")
		t, okT := readSysfsNumber("/sys/class/net/" + name + "/statistics/tx_bytes")
		if !okR || !okT {
			continue
		}
		rx[name], tx[name] = r, t
	}
	return rx, tx, len(rx) > 0
}

func readSysfsNumber(path string) (float64, bool) {
	raw, ok := readSmall(path)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || n < 0 || !finite(n) {
		return 0, false
	}
	return n, true
}

// The filesystem that answers "is this machine running out of room". On a
// Linux distribution that is "/". On Android "/" is the system image — a
// read-only partition shipped nearly full, whose 97% would be a permanent
// false alarm — and everything the machine writes lives on /data, which is
// also the one partition an app may statfs beyond its own directories.
func linuxRootPath() string {
	if onAndroid() {
		var st syscall.Statfs_t
		if syscall.Statfs("/data", &st) == nil {
			return "/data"
		}
	}
	return "/"
}

// Android's mount table is mostly the operating system talking to itself: a
// dozen /apex/* module images, /system, /vendor, /product, /odm, each an ext4
// or erofs partition sized to its contents and therefore always "full", and a
// FUSE view of /data at /storage/emulated. None is a disk a person can fill
// or empty. What is: /data (the root, above) and removable or adopted media,
// which the platform mounts under these roots.
func androidMountWorthListing(path string) bool {
	for _, p := range []string{"/storage/", "/mnt/media_rw/", "/mnt/expand/"} {
		if strings.HasPrefix(path, p) {
			return !strings.HasPrefix(path, "/storage/emulated")
		}
	}
	return false
}

// Parse a fixed group of counters, all or nothing. Whole numbers that only
// ever grow: anything negative, non-finite or unparseable means the columns
// are not where the caller thinks they are, and a partial answer would put one
// column's number under another column's name.
func parseNonNeg(fields ...string) ([]float64, bool) {
	out := make([]float64, len(fields))
	for i, f := range fields {
		n, err := strconv.ParseFloat(f, 64)
		if err != nil || n < 0 || !finite(n) {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// Disk throughput, from /proc/diskstats:
//
//	  8       0 sda 12 0 3456 78 90 0 1234 56 0 0 0
//	major minor name reads rd_merged SECTORS_READ ms writes wr_merged SECTORS_WRITTEN ...
//
// Sectors, always 512 bytes here. That is not the device's sector size — a
// modern NVMe reports 4096 — but the unit the kernel's diskstats interface is
// specified in, and converting by the hardware's figure (which is what makes
// this look like a bug worth fixing) overstates every reading eightfold.
//
// WHICH DEVICES COUNT is the other half, and getting it wrong is silent: the
// same write appears under a partition and its whole disk, under a device
// mapper target and the disk beneath it, under an md array and every member.
// Summing everything /proc/diskstats lists therefore double-counts, triple-counts
// on LVM-on-RAID, and produces a number that is never obviously wrong — just
// always too big. So the sum is over WHOLE devices only (the ones with a
// directory in /sys/block, which excludes partitions) minus the virtual layers
// that stack on top of them.
func linuxDiskIO(s *System) {
	blocks, err := os.ReadDir("/sys/block")
	if err != nil {
		s.miss(mDiskIO)
		return
	}
	whole := make(map[string]bool, len(blocks))
	for _, b := range blocks {
		name := b.Name()
		// loop (every snap package is one), ram/zram (memory pretending to be a
		// disk), dm- (LVM/crypt, which re-counts its backing device), md (RAID,
		// same), sr/fd (optical, floppy — no traffic worth a card).
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "dm-") ||
			strings.HasPrefix(name, "md") || strings.HasPrefix(name, "sr") ||
			strings.HasPrefix(name, "fd") {
			continue
		}
		whole[name] = true
	}
	raw, ok := readSmall("/proc/diskstats")
	if !ok || len(whole) == 0 {
		s.miss(mDiskIO)
		return
	}
	var read, written float64
	var sawAny bool
	// Which devices this sum is over, so the next one can tell whether it is
	// comparing like with like — see below.
	seen := make([]string, 0, len(whole))
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || !whole[f[2]] {
			continue
		}
		v, okRow := parseNonNeg(f[5], f[9])
		if !okRow {
			continue
		}
		read += v[0] * 512
		written += v[1] * 512
		seen = append(seen, f[2])
		sawAny = true
	}
	if !sawAny {
		s.miss(mDiskIO)
		return
	}
	// A DIFFERENT SET OF DEVICES IS A DIFFERENT SUM, and differencing across
	// the change invents traffic that never happened: plug in a disk that has
	// served a terabyte since its own boot and its whole lifetime counter
	// lands in one second's worth of I/O. The counters-went-backwards guard in
	// pairRate catches removals only when the loss outweighs everything else's
	// growth, and catches additions never — so the baseline is dropped
	// outright whenever the membership changes, and the next sample starts a
	// clean interval. One missing reading beats one fabricated spike.
	sort.Strings(seen)
	// The device set travels WITH the counters into the differencer, so the
	// membership check, the dropped baseline and the new one all happen under
	// one lock — see deltaOver. Checking membership separately let two
	// concurrent collections interleave into the very spike the check exists
	// to prevent.
	rBps, wBps := diskIOPrev.deltaOver(strings.Join(seen, ","), read, written, now())
	if rBps == nil {
		// First sample since startup, or a device went away and took its
		// counters out of the sum. Stated rather than shown as an idle disk —
		// the same rule the network rate follows one function up.
		s.miss(mDiskIO)
		return
	}
	s.DiskReadBps, s.DiskWriteBps = rBps, wBps
}

// The filesystems other than root, from /proc/self/mounts.
//
// Read there rather than from /etc/fstab (which describes intent, not what is
// mounted) and parsed with the kernel's own escaping in mind: a mount point
// containing a space arrives as `\040`, and a parser that misses that reads one
// path as two fields and measures the wrong thing. /proc/self/mounts rather
// than /proc/mounts: the same table (the latter is a link to the former), but
// the link is one of the /proc entries Android refuses to apps and the file
// behind it is not.
func linuxMounts(s *System) { fillMounts(s, scanLinuxMounts) }

// The bool is "could the mount table be read at all", not "were there any
// extra filesystems" — see fillMounts for why the two must not collapse.
func scanLinuxMounts() ([]Mount, bool) {
	raw, ok := readSmall("/proc/self/mounts")
	if !ok {
		return nil, false
	}
	root, android := linuxRootPath(), onAndroid()
	var found []Mount
	seenDev := make(map[string]bool, 8)
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		dev, path, fstype := unescapeMountField(f[0]), unescapeMountField(f[1]), f[2]
		if !realFsTypes[fstype] || path == "/" || path == root {
			continue
		}
		if android && !androidMountWorthListing(path) {
			continue
		}
		// One row per DEVICE. A btrfs volume with four subvolumes mounted is
		// four rows with identical numbers, and a bind mount is the same
		// filesystem seen twice — neither is a second disk, and listing them
		// would spend the whole cap on one filesystem.
		if dev == "" || seenDev[dev] {
			continue
		}
		seenDev[dev] = true
		total, used, usedPct, okFS := statfsUsage(path)
		if !okFS {
			continue
		}
		found = append(found, Mount{Path: path, Total: fp(total), Used: fp(used), UsedPercent: usedPct})
		// A machine with hundreds of mounts (a Kubernetes node) must not be
		// walked in full: every entry costs a statfs, which BLOCKS on a network
		// filesystem whose server is away. This bounds the WORK, and it is not
		// the same bound as the eight rows that get sent — capMounts picks the
		// fullest of whatever reaches it, so a stop here can still cost a full
		// disk its row. Eight times the row cap because the two answers are
		// different questions: sixty-four real block-device filesystems on one
		// machine is already beyond anything this is built for, while thirty-two
		// was inside the range a container host can reach.
		if len(found) >= 8*maxMounts {
			break
		}
	}
	return found, true
}

// The kernel escapes space, tab, newline and backslash in mount fields as
// three-digit OCTAL after a backslash. Anything else after a backslash is left
// exactly as it was found: inventing an interpretation for it would be this
// parser deciding what a path means.
func unescapeMountField(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i+3 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		n, err := strconv.ParseUint(v[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(v[i])
			continue
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String()
}

// TCP MIB values are named by the preceding header line; their positions have
// changed across kernels, so a positional parser can quietly turn MaxConn or
// InSegs into a plausible-looking established count. MaxConn is legitimately
// -1 and is ignored rather than making the whole line invalid.
func parseLinuxTCPSNMP(raw string) (estab, retrans float64, ok bool) {
	lines := strings.Split(raw, "\n")
	for i := 0; i+1 < len(lines); i++ {
		h := strings.Fields(lines[i])
		v := strings.Fields(lines[i+1])
		if len(h) < 2 || len(v) != len(h) || h[0] != "Tcp:" || v[0] != "Tcp:" {
			continue
		}
		cols := make(map[string]string, len(h)-1)
		for j := 1; j < len(h); j++ {
			cols[h[j]] = v[j]
		}
		e, e1 := strconv.ParseFloat(cols["CurrEstab"], 64)
		r, e2 := strconv.ParseFloat(cols["RetransSegs"], 64)
		if e1 != nil || e2 != nil || e < 0 || r < 0 || !finite(e) || !finite(r) {
			return 0, 0, false
		}
		return e, r, true
	}
	return 0, 0, false
}

func parseLinuxTCPTimeWait(raw string) (float64, bool) {
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "TCP:" {
			continue
		}
		for i := 1; i+1 < len(f); i += 2 {
			if f[i] != "tw" {
				continue
			}
			n, err := strconv.ParseFloat(f[i+1], 64)
			return n, err == nil && n >= 0 && finite(n)
		}
	}
	return 0, false
}

func linuxTCP(s *System) {
	if raw, read := readSmall("/proc/net/snmp"); read {
		if estab, retrans, ok := parseLinuxTCPSNMP(raw); ok {
			s.TCPEstab = fp(estab)
			s.TCPRetransPS = tcpDelta(retrans, now())
		}
	}
	if raw, read := readSmall("/proc/net/sockstat"); read {
		if tw, ok := parseLinuxTCPTimeWait(raw); ok {
			s.TCPTimeWait = fp(tw)
		}
	}
}

// PROCESSES, counted as the numeric directories under /proc. An earlier
// version read /proc/loadavg's "runnable/total" — cheaper, but total there is
// scheduling ENTITIES, i.e. threads, and one busy JVM inflates it by
// thousands. The card says "procs", so it counts processes: names only, no
// entry is opened, and directory names carry none of the identity this file
// refuses (see the header — cmdlines are exactly what this walk does NOT
// read).
func linuxProcs(s *System) {
	if !procTreeVisible() {
		// hidepid: the directories under /proc are this program's own, and
		// counting them would report a machine of six processes.
		s.miss(mProcs)
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		s.miss(mProcs)
		return
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "" || name[0] < '1' || name[0] > '9' {
			continue // PIDs never start with 0
		}
		digits := true
		for i := 1; i < len(name); i++ {
			if name[i] < '0' || name[i] > '9' {
				digits = false
				break
			}
		}
		if digits {
			n++
		}
	}
	if n == 0 {
		s.miss(mProcs)
		return
	}
	s.Procs = fp(float64(n))
}

// Every temperature sensor the kernel exposes, and the hottest of them. The
// scan and what it reads are in temps.go. No reading at all is silent by
// design — see TempC in system.go.
func linuxTemp(s *System) { fillTemps(s, tempsRefreshSec, localTemps) }

// What `subnsub-helper temps` prints, and what the collector reads.
func localTemps() []Temp { return scanTemps("/sys/class/hwmon", "/sys/class/thermal") }

func linuxLoad(s *System) {
	raw, ok := readSmall("/proc/loadavg")
	if !ok {
		s.miss(mLoad)
		return
	}
	f := strings.Fields(raw)
	if len(f) < 3 {
		s.miss(mLoad)
		return
	}
	out := make([]*float64, 3)
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseFloat(f[i], 64)
		if err != nil || n < 0 || !finite(n) {
			s.miss(mLoad)
			return
		}
		out[i] = fp(round2(n))
	}
	s.Load1, s.Load5, s.Load15 = out[0], out[1], out[2]
}

func linuxUptime(s *System) {
	raw, ok := readSmall("/proc/uptime")
	if !ok {
		// Refused to Android apps; the clock behind it is refused to nobody.
		if v, ok := bootSeconds(); ok {
			s.UptimeSec = fp(round2(v))
			return
		}
		s.miss(mUptime)
		return
	}
	f := strings.Fields(raw)
	if len(f) < 1 {
		s.miss(mUptime)
		return
	}
	n, err := strconv.ParseFloat(f[0], 64)
	if err != nil || n < 0 || !finite(n) {
		s.miss(mUptime)
		return
	}
	s.UptimeSec = fp(round2(n))
}
