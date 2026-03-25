package metrics

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Public types ────────────────────────────────────────────────────

// LiveLogEntry represents a single parsed log line for the live view.
type LiveLogEntry struct {
	Timestamp time.Time
	Domain    string
	IP        string // IPv4 or IPv6
	Path      string
	Status    string // HTTP status code or error type
	Source    string // "access" or "error"
}

// ── Tailer ──────────────────────────────────────────────────────────

// LiveTailer maintains a rolling buffer of the most recent log entries
// across all monitored access and error logs.  Each Collect() call
// reads only new bytes (incremental) and appends parsed entries to
// the ring buffer.
type LiveTailer struct {
	mu sync.Mutex

	accessGlob string
	errorGlob  string
	maxEntries int // ring buffer capacity

	offsets map[string]int64
	entries []LiveLogEntry
}

// NewLiveTailer creates a tailer that watches both access and error
// logs.  maxEntries controls how many recent entries are kept in
// memory (the ring buffer size).
func NewLiveTailer(accessGlob, errorGlob string, maxEntries int) *LiveTailer {
	return &LiveTailer{
		accessGlob: accessGlob,
		errorGlob:  errorGlob,
		maxEntries: maxEntries,
		offsets:    make(map[string]int64),
	}
}

// Collect reads new lines from all watched log files.
func (t *LiveTailer) Collect() {
	t.mu.Lock()
	defer t.mu.Unlock()

	var newEntries []LiveLogEntry

	// ── Access logs ─────────────────────────────────────────────
	accessFiles, _ := filepath.Glob(t.accessGlob)
	for _, logPath := range accessFiles {
		domain := extractDomain(logPath) // reuse from nginx.go
		if domain == "" {
			continue
		}
		lines := t.readNewLines(logPath)
		for _, line := range lines {
			entry, ok := parseAccessForLive(line, domain)
			if !ok {
				continue
			}
			newEntries = append(newEntries, entry)
		}
	}

	// ── Error logs ──────────────────────────────────────────────
	errorFiles, _ := filepath.Glob(t.errorGlob)
	for _, logPath := range errorFiles {
		domain := extractDomain(logPath)
		lines := t.readNewLines(logPath)
		for _, line := range lines {
			entry, ok := parseErrorForLive(line, domain)
			if !ok {
				continue
			}
			newEntries = append(newEntries, entry)
		}
	}

	// Sort new entries by timestamp.
	sort.Slice(newEntries, func(i, j int) bool {
		return newEntries[i].Timestamp.Before(newEntries[j].Timestamp)
	})

	// Append to ring buffer.
	t.entries = append(t.entries, newEntries...)

	// Trim to max capacity — keep the most recent entries.
	if len(t.entries) > t.maxEntries {
		t.entries = t.entries[len(t.entries)-t.maxEntries:]
	}
}

// RecentEntries returns the last n entries (most recent last).
func (t *LiveTailer) RecentEntries(n int) []LiveLogEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.entries) <= n {
		result := make([]LiveLogEntry, len(t.entries))
		copy(result, t.entries)
		return result
	}
	result := make([]LiveLogEntry, n)
	copy(result, t.entries[len(t.entries)-n:])
	return result
}

// TotalSeen returns the total number of entries in the buffer.
func (t *LiveTailer) TotalSeen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// ── Internal: incremental reading ───────────────────────────────────

func (t *LiveTailer) readNewLines(logPath string) []string {
	fi, err := os.Stat(logPath)
	if err != nil {
		return nil
	}
	currentSize := fi.Size()
	lastOffset := t.offsets[logPath]
	if currentSize < lastOffset {
		lastOffset = 0
	}
	if currentSize == lastOffset {
		return nil
	}

	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	if lastOffset > 0 {
		if _, err := f.Seek(lastOffset, 0); err != nil {
			return nil
		}
	}

	// Read in chunks — for the live view we want speed.
	buf := make([]byte, currentSize-lastOffset)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	t.offsets[logPath] = currentSize

	var lines []string
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// ── Parsers ─────────────────────────────────────────────────────────

// parseAccessForLive extracts fields from a Combined Log Format line.
// Returns IP (IPv4 or IPv6), path, status code, and timestamp.
func parseAccessForLive(line, domain string) (LiveLogEntry, bool) {
	entry := LiveLogEntry{Source: "access", Domain: domain}

	// IP: everything before the first space.
	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx <= 0 {
		return entry, false
	}
	entry.IP = line[:spaceIdx]

	// Timestamp: between '[' and ']'.
	entry.Timestamp = extractTimestamp(line) // reuse from wplogin.go

	// Request path: first quoted string.
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return entry, false
	}
	rest := line[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return entry, false
	}
	reqParts := strings.Fields(rest[:q2])
	if len(reqParts) >= 2 {
		entry.Path = reqParts[1]
		// Strip query strings.
		if idx := strings.IndexByte(entry.Path, '?'); idx >= 0 {
			entry.Path = entry.Path[:idx]
		}
	}

	// Status code: first field after the closing quote.
	afterReq := rest[q2+1:]
	afterFields := strings.Fields(afterReq)
	if len(afterFields) >= 2 {
		entry.Status = afterFields[0] // HTTP status code
	}

	if entry.Path == "" {
		return entry, false
	}

	return entry, true
}

// parseErrorForLive extracts fields from an nginx error log line.
func parseErrorForLive(line, fallbackDomain string) (LiveLogEntry, bool) {
	entry := LiveLogEntry{Source: "error"}

	// Only process [error] level.
	if !strings.Contains(line, "[error]") {
		return entry, false
	}

	// Timestamp: "2026/03/24 23:36:20" at the start.
	if len(line) >= 19 {
		t, err := time.Parse("2006/01/02 15:04:05", line[:19])
		if err == nil {
			entry.Timestamp = t
		}
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Extract fields using the same helpers as ngxerror.go.
	entry.IP = extractField(line, "client:")
	entry.Domain = extractField(line, "server:")
	if entry.Domain == "" {
		entry.Domain = fallbackDomain
	}

	// Request path.
	reqRaw := extractField(line, "request:")
	reqRaw = strings.Trim(reqRaw, "\"")
	parts := strings.Fields(reqRaw)
	if len(parts) >= 2 {
		entry.Path = parts[1]
	}

	// Error type as the status.
	entry.Status = classifyNginxError(line)

	if entry.Path == "" && entry.IP == "" {
		return entry, false
	}
	if entry.Path == "" {
		entry.Path = "(unknown)"
	}

	return entry, true
}
