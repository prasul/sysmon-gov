package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// HostInfo holds static and semi-static system identity data.
type HostInfo struct {
	Hostname string
	Kernel   string
	Uptime   time.Duration
}

// GetHostInfo reads hostname, kernel release, and system uptime.
func GetHostInfo() (*HostInfo, error) {
	info := &HostInfo{}

	// --- Hostname ---
	name, err := os.Hostname()
	if err == nil {
		info.Hostname = name
	}

	// --- Kernel version from /proc/version ---
	// Format: "Linux version 5.15.0-generic (user@host) (gcc …) #1 SMP …"
	// We extract just the version string (second field).
	if data, err := os.ReadFile("/proc/version"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			info.Kernel = parts[2]
		}
	}

	// --- Uptime from /proc/uptime ---
	// Format: "12345.67 98765.43"  (seconds since boot, idle seconds)
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			secs, _ := strconv.ParseFloat(fields[0], 64)
			info.Uptime = time.Duration(secs * float64(time.Second))
		}
	}

	return info, nil
}

// FormatUptime turns a duration into a human-friendly string like
// "3d 7h 42m 15s".
func FormatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, mins, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	return fmt.Sprintf("%dm %ds", mins, secs)
}
