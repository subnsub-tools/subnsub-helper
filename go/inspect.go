package main

// Read-only, on-demand diagnostics.
//
// This is deliberately not a smaller spelling of the console. The request has
// a closed target, carries no command string, and every target is implemented
// here with native reads. Reading process resource use never implies that the
// dashboard may run a shell command, replace the helper, or read process
// arguments and environment.
//
// It is not a switch: wherever /proc shows other processes
// the names are read, kept beside the CPU history and served over the tunnel.
// The marker file and MON_DIAGNOSTICS that used to decide it are ignored;
// `subnsub-helper diagnostics` only reports.

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	inspectProcessLimit = 20
	inspectSampleWait   = 250 * time.Millisecond
)

// The first target is implemented from Linux /proc. Other platforms report no
// capability rather than showing a drawer whose only possible result is an
// error. More targets can extend this switch without widening the wire format.
//
// Linux includes Android, and on either the question is not the platform but
// whether /proc shows other processes: an Android app is refused them
// (hidepid=2 since 7.0), a shell or root there is not, and a hardened
// container may be either. A table that could only ever list this program
// is not a diagnostic, so the capability follows the probe.
func diagnosticsAvailable() bool {
	return (runtime.GOOS == "linux" || runtime.GOOS == "android") && procStatReadable()
}

// On wherever it can be: the one question is the probe above.
func diagnosticsEnabled() bool {
	return diagnosticsAvailable()
}

type inspectData struct {
	Processes []inspectProcess `json:"processes"`
}

type inspectProcess struct {
	PID           int      `json:"pid"`
	Name          string   `json:"name"`
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent *float64 `json:"memory_percent,omitempty"`
	RSSBytes      float64  `json:"rss_bytes"`
	ElapsedSec    *float64 `json:"elapsed_sec,omitempty"`
}

type processSample struct {
	start, ticks float64
	rss          float64
	name         string
}

// /proc/<pid>/stat starts with "pid (comm) state ...". comm may itself contain
// spaces and ')', so splitting the whole line — or stopping at the first ')' —
// shifts every later field. The kernel's delimiter is the LAST ") ".
func parseProcessStat(raw string) (start, ticks, rssPages float64, ok bool) {
	end := strings.LastIndex(raw, ") ")
	if end < 0 {
		return 0, 0, 0, false
	}
	f := strings.Fields(raw[end+2:])
	// f[0] is field 3 (state), so utime=14→11, stime=15→12,
	// starttime=22→19, rss=24→21.
	if len(f) < 22 {
		return 0, 0, 0, false
	}
	utime, e1 := strconv.ParseFloat(f[11], 64)
	stime, e2 := strconv.ParseFloat(f[12], 64)
	start, e3 := strconv.ParseFloat(f[19], 64)
	rssPages, e4 := strconv.ParseFloat(f[21], 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil ||
		utime < 0 || stime < 0 || start < 0 || rssPages < 0 ||
		!finite(utime) || !finite(stime) || !finite(start) || !finite(rssPages) {
		return 0, 0, 0, false
	}
	return start, utime + stime, rssPages, true
}

// Process names are display text from a machine, not trusted markup. Linux
// comm is only 15 bytes today; the slightly wider rune cap is a compatibility
// ceiling, not permission to carry a command line.
func cleanProcessName(raw string) string {
	out := make([]rune, 0, 16)
	for _, r := range strings.TrimSpace(raw) {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
			r == 0x200e || r == 0x200f || r == 0xfeff {
			continue
		}
		out = append(out, r)
		if len(out) == 16 {
			break
		}
	}
	return strings.TrimSpace(string(out))
}

func readProcessSample() (map[int]processSample, float64, bool) {
	stat, ok := readSmall("/proc/stat")
	if !ok {
		return nil, 0, false
	}
	line := stat
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	total, ok := parseTotalCPUTicks(line)
	if !ok {
		return nil, 0, false
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, false
	}
	out := make(map[int]processSample)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid < 1 {
			continue
		}
		raw, ok := readSmall(filepath.Join("/proc", e.Name(), "stat"))
		if !ok {
			continue // exited, hidden, or not ours to inspect
		}
		start, ticks, pages, ok := parseProcessStat(raw)
		if !ok {
			continue
		}
		nameRaw, ok := readSmall(filepath.Join("/proc", e.Name(), "comm"))
		if !ok {
			continue
		}
		name := cleanProcessName(nameRaw)
		if name == "" {
			continue
		}
		out[pid] = processSample{
			start: start, ticks: ticks,
			rss:  pages * float64(os.Getpagesize()),
			name: name,
		}
	}
	return out, total, true
}

func parseTotalCPUTicks(line string) (float64, bool) {
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, false
	}
	/* guest and guest_nice are already included in user and nice. Linux tools
	   sum through steal (the first eight counters) and must not count those two
	   trailing fields again, or process CPU is understated on virtual machines. */
	values := f[1:]
	if len(values) > 8 {
		values = values[:8]
	}
	var total float64
	for _, raw := range values {
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil || n < 0 || !finite(n) {
			return 0, false
		}
		total += n
	}
	return total, total > 0
}

func linuxMemTotal() float64 {
	raw, ok := readSmall("/proc/meminfo")
	if !ok {
		return 0
	}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "MemTotal:"))
		if len(f) == 0 {
			return 0
		}
		kb, err := strconv.ParseFloat(f[0], 64)
		if err == nil && kb > 0 && finite(kb) {
			return kb * 1024
		}
		return 0
	}
	return 0
}

func linuxProcessUptime() float64 {
	raw, ok := readSmall("/proc/uptime")
	if !ok {
		return 0
	}
	f := strings.Fields(raw)
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v <= 0 || !finite(v) {
		return 0
	}
	return v
}

func inspectProcesses() ([]inspectProcess, bool) {
	first, total1, ok := readProcessSample()
	if !ok {
		return nil, false
	}
	time.Sleep(inspectSampleWait)
	second, total2, ok := readProcessSample()
	if !ok || total2 <= total1 {
		return nil, false
	}
	memTotal := linuxMemTotal()
	uptime := linuxProcessUptime()
	rows := make([]inspectProcess, 0, len(second))
	for pid, cur := range second {
		row := inspectProcess{PID: pid, Name: cur.name, RSSBytes: cur.rss}
		if prev, found := first[pid]; found && prev.start == cur.start && cur.ticks >= prev.ticks {
			v := round2((cur.ticks - prev.ticks) / (total2 - total1) * 100)
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			row.CPUPercent = fp(v)
		}
		if memTotal > 0 {
			v := round2(cur.rss / memTotal * 100)
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			row.MemoryPercent = fp(v)
		}
		/* /proc's time fields are exposed in the Linux USER_HZ ABI (100 ticks
		   per second), independent of the kernel's internal scheduler HZ. */
		if uptime > 0 {
			v := uptime - cur.start/100
			if v >= 0 && finite(v) {
				v = float64(int64(v))
				row.ElapsedSec = fp(v)
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		ci, cj := -1.0, -1.0
		if rows[i].CPUPercent != nil {
			ci = *rows[i].CPUPercent
		}
		if rows[j].CPUPercent != nil {
			cj = *rows[j].CPUPercent
		}
		if ci != cj {
			return ci > cj
		}
		if rows[i].RSSBytes != rows[j].RSSBytes {
			return rows[i].RSSBytes > rows[j].RSSBytes
		}
		return rows[i].PID < rows[j].PID
	})
	if len(rows) > inspectProcessLimit {
		rows = rows[:inspectProcessLimit]
	}
	return rows, true
}

func runInspect(id, target string) (res consoleResult) {
	res = consoleResult{ID: id, Kind: "inspect", Target: target, Code: -1}
	started := time.Now()
	defer func() { res.Ms = time.Since(started).Milliseconds() }()
	if !diagnosticsEnabled() {
		res.Error = "diagnostics-off"
		return res
	}
	if target != "process" {
		res.Error = "unknown-target"
		return res
	}
	rows, ok := inspectProcesses()
	if !ok {
		res.Error = "unavailable"
		return res
	}
	res.Code = 0
	res.Data = &inspectData{Processes: rows}
	return res
}
