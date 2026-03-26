package metrics

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// DiskInfo holds usage details for a single mounted filesystem.
type DiskInfo struct {
	Device      string
	MountPoint  string
	TotalGB     float64
	UsedGB      float64
	AvailGB     float64
	UsedPercent float64
}

// GetDiskUsage scans /proc/mounts for real block-device filesystems,
// calls statfs on each mount point, and returns the results.
// Virtual filesystems (proc, sysfs, tmpfs, etc.) are skipped to keep
// the output relevant.
func GetDiskUsage() ([]DiskInfo, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/mounts: %w", err)
	}

	// Filesystem types we want to skip — they are virtual / in-memory.
	skip := map[string]bool{
		"proc": true, "sysfs": true, "tmpfs": true, "devtmpfs": true,
		"devpts": true, "cgroup": true, "cgroup2": true, "securityfs": true,
		"pstore": true, "debugfs": true, "tracefs": true, "hugetlbfs": true,
		"mqueue": true, "fusectl": true, "binfmt_misc": true, "autofs": true,
		"configfs": true, "efivarfs": true, "bpf": true, "nsfs": true,
		"ramfs": true,
	}

	seen := make(map[string]bool) // avoid duplicate mount points
	var disks []DiskInfo

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device := fields[0]
		mount := fields[1]
		fstype := fields[2]

		if skip[fstype] || seen[mount] {
			continue
		}
		// Only include real devices (starts with /) or common virtual disks like overlayfs
		if !strings.HasPrefix(device, "/") && fstype != "overlay" {
			continue
		}
		seen[mount] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount, &stat); err != nil {
			continue // silently skip mounts we cannot stat
		}

		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bavail * uint64(stat.Bsize) // Bavail = available to non-root
		usedBytes := totalBytes - (stat.Bfree * uint64(stat.Bsize))

		toGB := func(b uint64) float64 { return float64(b) / (1024 * 1024 * 1024) }

		d := DiskInfo{
			Device:     device,
			MountPoint: mount,
			TotalGB:    toGB(totalBytes),
			UsedGB:     toGB(usedBytes),
			AvailGB:    toGB(freeBytes),
		}
		if totalBytes > 0 {
			d.UsedPercent = float64(usedBytes) / float64(totalBytes) * 100
		}
		disks = append(disks, d)
	}

	return disks, nil
}
