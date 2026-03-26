// Package metrics provides system metric collectors that read from
// the Linux /proc and /sys filesystems. Every collector is safe for
// concurrent use and returns plain Go structs — no UI coupling.
package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUUsage holds the computed usage percentage for a single logical core
// or for the aggregate "cpu" line.
type CPUUsage struct {
	Name    string  // "cpu" (total) or "cpu0", "cpu1", …
	Percent float64 // 0.0 – 100.0
}

// cpuSnapshot stores the raw counters from one read of /proc/stat.
type cpuSnapshot struct {
	idle  uint64
	total uint64
}

// prevCPU keeps the last snapshot so we can compute deltas.
// A sync.Mutex protects it because the UI refresh goroutine
// and any future concurrent callers must not race.
var (
	prevCPU   map[string]cpuSnapshot
	prevMutex sync.Mutex
)

// GetCPUUsage reads /proc/stat twice (with a short sleep) on the first
// call, then reuses the previous snapshot on subsequent calls so that
// the refresh interval itself becomes the measurement window.
func GetCPUUsage() ([]CPUUsage, error) {
	current, err := readProcStat()
	if err != nil {
		return nil, err
	}

	prevMutex.Lock()
	defer prevMutex.Unlock()

	// First call — we have no previous snapshot, so take one now,
	// sleep briefly, and read again to bootstrap a delta.
	if prevCPU == nil {
		prevCPU = current
		time.Sleep(200 * time.Millisecond)
		current, err = readProcStat()
		if err != nil {
			return nil, err
		}
	}

	results := make([]CPUUsage, 0, len(current))
	for name, cur := range current {
		prev, ok := prevCPU[name]
		if !ok {
			continue
		}
		deltaTotal := cur.total - prev.total
		deltaIdle := cur.idle - prev.idle

		var pct float64
		if deltaTotal > 0 {
			pct = (1.0 - float64(deltaIdle)/float64(deltaTotal)) * 100.0
		}
		results = append(results, CPUUsage{Name: name, Percent: pct})
	}

	// Store current as the new baseline for the next call.
	prevCPU = current
	return results, nil
}

// readProcStat parses every "cpu" line from /proc/stat into a map of
// snapshots. The format of each line is:
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
//
// We sum all fields to get 'total' and keep 'idle + iowait' as 'idle'.
func readProcStat() (map[string]cpuSnapshot, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/stat: %w", err)
	}

	snapshots := make(map[string]cpuSnapshot)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		name := fields[0]
		var vals []uint64
		for _, f := range fields[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			vals = append(vals, v)
		}

		var total uint64
		for _, v := range vals {
			total += v
		}

		// idle = idle (index 3) + iowait (index 4)
		idle := vals[3]
		if len(vals) > 4 {
			idle += vals[4]
		}

		snapshots[name] = cpuSnapshot{idle: idle, total: total}
	}

	return snapshots, nil
}
