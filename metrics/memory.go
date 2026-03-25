package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MemoryInfo holds RAM and swap statistics in human-friendly units.
type MemoryInfo struct {
	TotalMB     uint64
	UsedMB      uint64
	AvailableMB uint64
	UsedPercent float64

	SwapTotalMB   uint64
	SwapUsedMB    uint64
	SwapUsedPercent float64
}

// GetMemoryInfo reads /proc/meminfo and returns a computed MemoryInfo.
// Linux always exposes MemAvailable (kernel ≥ 3.14) which accounts for
// reclaimable caches, so our "used" figure is realistic — not inflated
// the way "MemTotal − MemFree" would be.
func GetMemoryInfo() (*MemoryInfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/meminfo: %w", err)
	}

	fields := parseMeminfo(string(data))

	total := fields["MemTotal"]
	available := fields["MemAvailable"]
	used := total - available

	swapTotal := fields["SwapTotal"]
	swapFree := fields["SwapFree"]
	swapUsed := swapTotal - swapFree

	info := &MemoryInfo{
		TotalMB:     total / 1024,
		UsedMB:      used / 1024,
		AvailableMB: available / 1024,
		SwapTotalMB: swapTotal / 1024,
		SwapUsedMB:  swapUsed / 1024,
	}

	if total > 0 {
		info.UsedPercent = float64(used) / float64(total) * 100
	}
	if swapTotal > 0 {
		info.SwapUsedPercent = float64(swapUsed) / float64(swapTotal) * 100
	}

	return info, nil
}

// parseMeminfo turns the "Key: 12345 kB" lines into a map of
// key → value-in-kB.
func parseMeminfo(data string) map[string]uint64 {
	result := make(map[string]uint64)
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		valStr = strings.TrimSuffix(valStr, " kB")
		valStr = strings.TrimSpace(valStr)
		val, _ := strconv.ParseUint(valStr, 10, 64)
		result[key] = val
	}
	return result
}
