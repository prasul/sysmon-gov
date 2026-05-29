package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessInfo holds the data we display for a single process.
type ProcessInfo struct {
	PID        int
	Name       string
	CPUPercent float64
	MemMB      float64
	MemPercent float64
}

// prevProcCPU stores the last snapshot of per-PID CPU ticks so we can
// compute deltas on the next collection cycle.  Protected by a mutex
// because the UI refresh goroutine drives collection.
var (
	prevProcCPU      map[int]procCPUSnap
	prevProcCPUMutex sync.Mutex
	prevProcTime     time.Time
)

type procCPUSnap struct {
	utime uint64 // user-mode ticks
	stime uint64 // kernel-mode ticks
}

// GetTopProcesses scans every numeric directory under /proc, reads the
// process stats, computes CPU% via tick deltas, and returns two slices
// sorted by CPU and memory respectively.  `n` controls how many entries
// each list contains.
func GetTopProcesses(n int) (byCPU []ProcessInfo, byMem []ProcessInfo, err error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil, fmt.Errorf("reading /proc: %w", err)
	}

	// We need total system memory to compute per-process memory %.
	totalMemKB := getTotalMemKB()

	// Clock ticks per second — almost always 100 on Linux, but we
	// read it properly via sysconf if available.  Hardcoding 100 is
	// the pragmatic choice (Go's syscall package doesn't expose
	// sysconf); every major distro uses CONFIG_HZ=100 for userspace.
	const clockTicks = 100.0

	now := time.Now()
	current := make(map[int]procCPUSnap)
	var procs []ProcessInfo

	for _, entry := range entries {
		// Only numeric directory names are PIDs.
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		info, snap, ok := readProcessInfo(pid, totalMemKB)
		if !ok {
			continue
		}

		current[pid] = snap
		procs = append(procs, info)
	}

	// ── Compute CPU % from deltas ──────────────────────────────
	prevProcCPUMutex.Lock()
	elapsed := now.Sub(prevProcTime).Seconds()

	if prevProcCPU != nil && elapsed > 0 {
		for i := range procs {
			pid := procs[i].PID
			prev, ok := prevProcCPU[pid]
			if !ok {
				continue
			}
			cur := current[pid]
			deltaU := cur.utime - prev.utime
			deltaS := cur.stime - prev.stime
			totalDelta := float64(deltaU + deltaS)

			// Convert ticks → seconds → percentage of wall-clock time.
			procs[i].CPUPercent = (totalDelta / clockTicks / elapsed) * 100.0
		}
	}

	prevProcCPU = current
	prevProcTime = now
	prevProcCPUMutex.Unlock()

	// ── Sort and return top N ──────────────────────────────────
	// By CPU
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].CPUPercent > procs[j].CPUPercent
	})
	byCPU = topN(procs, n)

	// By Memory
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].MemPercent > procs[j].MemPercent
	})
	byMem = topN(procs, n)

	return byCPU, byMem, nil
}

// readProcessInfo reads /proc/<pid>/stat and /proc/<pid>/status for a
// single process.  Returns false if the process vanished (race with
// process exit) or is unreadable.
func readProcessInfo(pid int, totalMemKB uint64) (ProcessInfo, procCPUSnap, bool) {
	pidDir := filepath.Join("/proc", strconv.Itoa(pid))

	// ── /proc/<pid>/stat ───────────────────────────────────────
	// Format (simplified):
	//   pid (comm) state ppid ... utime stime ...
	// Fields are space-separated, but the command name (field 2) can
	// contain spaces and is wrapped in parentheses.  We find the last
	// ')' to safely split the rest.
	statData, err := os.ReadFile(filepath.Join(pidDir, "stat"))
	if err != nil {
		return ProcessInfo{}, procCPUSnap{}, false
	}

	statStr := string(statData)
	// Find the command name between first '(' and last ')'.
	nameStart := strings.IndexByte(statStr, '(')
	nameEnd := strings.LastIndexByte(statStr, ')')
	if nameStart < 0 || nameEnd < 0 || nameEnd <= nameStart {
		return ProcessInfo{}, procCPUSnap{}, false
	}
	name := statStr[nameStart+1 : nameEnd]

	// Everything after ") " is space-separated fields starting at
	// index 0 = state.  utime is field index 11, stime is 12
	// (relative to the part after the command name).
	rest := strings.Fields(statStr[nameEnd+2:])
	if len(rest) < 13 {
		return ProcessInfo{}, procCPUSnap{}, false
	}
	utime, _ := strconv.ParseUint(rest[11], 10, 64)
	stime, _ := strconv.ParseUint(rest[12], 10, 64)

	// ── /proc/<pid>/status → VmRSS ────────────────────────────
	// VmRSS is the resident set size in kB — actual physical RAM
	// the process is using right now.
	var rssKB uint64
	if statusData, err := os.ReadFile(filepath.Join(pidDir, "status")); err == nil {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					rssKB, _ = strconv.ParseUint(parts[1], 10, 64)
				}
				break
			}
		}
	}

	var memPct float64
	if totalMemKB > 0 {
		memPct = float64(rssKB) / float64(totalMemKB) * 100.0
	}

	info := ProcessInfo{
		PID:        pid,
		Name:       name,
		MemMB:      float64(rssKB) / 1024.0,
		MemPercent: memPct,
		// CPUPercent is computed later from deltas.
	}
	snap := procCPUSnap{utime: utime, stime: stime}
	return info, snap, true
}

// getTotalMemKB reads MemTotal from /proc/meminfo.  Returns 0 on error
// (which simply makes memory percentages show as 0%).
func getTotalMemKB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				return val
			}
		}
	}
	return 0
}

// topN returns the first n elements (or all if fewer than n).
func topN(procs []ProcessInfo, n int) []ProcessInfo {
	if len(procs) <= n {
		result := make([]ProcessInfo, len(procs))
		copy(result, procs)
		return result
	}
	result := make([]ProcessInfo, n)
	copy(result, procs[:n])
	return result
}
