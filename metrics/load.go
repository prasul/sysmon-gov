package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadAvg holds the three standard Unix load averages and the
// running/total process counts.
type LoadAvg struct {
	Load1       float64 // 1-minute average
	Load5       float64 // 5-minute average
	Load15      float64 // 15-minute average
	RunningProcs int     // currently running/runnable processes
	TotalProcs   int     // total number of processes
}

// GetLoadAvg reads /proc/loadavg which has the format:
//
//	0.32 0.18 0.12 2/345 9876
//
// Fields: load1 load5 load15 running/total lastPID
func GetLoadAvg() (*LoadAvg, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/loadavg: %w", err)
	}

	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 4 {
		return nil, fmt.Errorf("unexpected /proc/loadavg format")
	}

	l := &LoadAvg{}
	l.Load1, _ = strconv.ParseFloat(fields[0], 64)
	l.Load5, _ = strconv.ParseFloat(fields[1], 64)
	l.Load15, _ = strconv.ParseFloat(fields[2], 64)

	// "running/total" is in the 4th field.
	procs := strings.SplitN(fields[3], "/", 2)
	if len(procs) == 2 {
		l.RunningProcs, _ = strconv.Atoi(procs[0])
		l.TotalProcs, _ = strconv.Atoi(procs[1])
	}

	return l, nil
}
