package metrics

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ========================================================================
//  IP ALLOWLIST (never-block list)
// ========================================================================
//
// Loads a file of IPs/CIDRs that must NEVER be blocked — monitoring
// probes, office IPs, uptime checkers, etc.  When sysmon encounters
// one of these it labels it (e.g. "BigScoots monitoring IP") instead
// of offering to block it.
//
// File format (/etc/sysmon/allowlist.txt):
//
//   # Comments start with hash
//   149.56.101.50            BigScoots monitoring IP
//   149.56.96.39             BigScoots monitoring IP
//   51.222.136.175           BigScoots monitoring IP
//   203.0.113.0/24           Office network
//   198.51.100.7
//
// - One entry per line: IP or CIDR, optional label after whitespace.
// - Blank lines and #-comments ignored.
// - If no label given, a default is used.
// - The file is re-read automatically when it changes on disk, so you
//   can edit it live without restarting sysmon.

const defaultAllowlistLabel = "allowlisted (never block)"

// AllowlistEntry is one whitelisted IP or network with its label.
type AllowlistEntry struct {
	Raw   string     // original string
	IP    net.IP     // set for single-IP entries
	Net   *net.IPNet // set for CIDR entries
	Label string
}

// Allowlist holds the never-block set, reloaded from disk on change.
type Allowlist struct {
	mu sync.RWMutex

	path    string
	entries []AllowlistEntry
	modTime time.Time
	lastErr string
}

// NewAllowlist creates an allowlist backed by the given file path.
// If path is empty, /etc/sysmon/allowlist.txt is used.
//
// On first run (file absent), the embedded default — including the
// BigScoots monitoring IPs — is written out to the path so the operator
// has an editable file.  Existing files are never overwritten.
func NewAllowlist(path string) *Allowlist {
	if path == "" {
		path = "/etc/sysmon/allowlist.txt"
	}

	// Self-install the default on first run.  Ignore errors (e.g. no
	// permission to write /etc) — the allowlist just stays empty and
	// sysmon keeps running.
	_, _ = EnsureAllowlistFile(path)

	al := &Allowlist{path: path}
	al.Reload()
	return al
}

// Path returns the file path backing this allowlist.
func (al *Allowlist) Path() string {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.path
}

// Reload reads the file from disk.  Safe to call anytime; it's cheap
// and used both at startup and on-change.
func (al *Allowlist) Reload() {
	f, err := os.Open(al.path)
	if err != nil {
		al.mu.Lock()
		al.lastErr = err.Error()
		al.entries = nil // file gone → empty allowlist
		al.mu.Unlock()
		return
	}
	defer f.Close()

	fi, _ := f.Stat()

	var entries []AllowlistEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split into IP/CIDR token + optional label.
		var token, label string
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			token = strings.TrimSpace(line[:idx])
			label = strings.TrimSpace(line[idx+1:])
		} else {
			token = line
		}
		if label == "" {
			label = defaultAllowlistLabel
		}

		entry := AllowlistEntry{Raw: token, Label: label}

		// CIDR?
		if strings.Contains(token, "/") {
			_, ipnet, err := net.ParseCIDR(token)
			if err != nil {
				continue // skip malformed
			}
			entry.Net = ipnet
		} else {
			ip := net.ParseIP(token)
			if ip == nil {
				continue // skip malformed
			}
			entry.IP = ip
		}
		entries = append(entries, entry)
	}

	al.mu.Lock()
	al.entries = entries
	al.lastErr = ""
	if fi != nil {
		al.modTime = fi.ModTime()
	}
	al.mu.Unlock()
}

// reloadIfChanged re-reads the file only if its mtime changed since the
// last load.  Called before lookups so live edits take effect without
// a restart, but without stat-ing on a hot path more than necessary.
func (al *Allowlist) reloadIfChanged() {
	fi, err := os.Stat(al.path)
	if err != nil {
		return
	}
	al.mu.RLock()
	unchanged := fi.ModTime().Equal(al.modTime)
	al.mu.RUnlock()
	if !unchanged {
		al.Reload()
	}
}

// Lookup returns (true, label) if the given IP string is on the
// allowlist.  Handles both single IPs and CIDR ranges.  Re-reads the
// file first if it changed on disk.
func (al *Allowlist) Lookup(ipStr string) (bool, string) {
	al.reloadIfChanged()

	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false, ""
	}

	al.mu.RLock()
	defer al.mu.RUnlock()

	for _, e := range al.entries {
		if e.IP != nil && e.IP.Equal(ip) {
			return true, e.Label
		}
		if e.Net != nil && e.Net.Contains(ip) {
			return true, e.Label
		}
	}
	return false, ""
}

// IsAllowed is a convenience wrapper returning just the boolean.
func (al *Allowlist) IsAllowed(ipStr string) bool {
	ok, _ := al.Lookup(ipStr)
	return ok
}

// Label returns the allowlist label for an IP, or "" if not listed.
func (al *Allowlist) Label(ipStr string) string {
	_, label := al.Lookup(ipStr)
	return label
}

// Count returns the number of loaded entries.
func (al *Allowlist) Count() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return len(al.entries)
}

// LastError returns the last file-read error, if any.
func (al *Allowlist) LastError() string {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.lastErr
}
