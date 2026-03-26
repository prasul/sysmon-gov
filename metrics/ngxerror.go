package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ── Public types ────────────────────────────────────────────────────

// NginxErrorHit represents an aggregated error pattern: a specific
// domain + path + IP combination that appears in error logs.
type NginxErrorHit struct {
	Count  int
	Domain string
	Path   string
	IP     string
	Error  string // short error label, e.g. "forbidden", "not found"
}

// ── Collector ───────────────────────────────────────────────────────

// NginxErrorCollector parses nginx error.log files and aggregates
// error entries by domain + path + IP.  Uses incremental reading.
type NginxErrorCollector struct {
	mu sync.Mutex

	logGlob string
	offsets map[string]int64

	// hits keyed by "domain\x00path\x00ip"
	hits map[string]*ngxErrAccum
}

type ngxErrAccum struct {
	count  int
	domain string
	path   string
	ip     string
	errTyp string
}

// NewNginxErrorCollector creates a collector for error logs matching
// the given glob (e.g. "/home/nginx/domains/*/log/error.log").
func NewNginxErrorCollector(logGlob string) *NginxErrorCollector {
	return &NginxErrorCollector{
		logGlob: logGlob,
		offsets: make(map[string]int64),
		hits:    make(map[string]*ngxErrAccum),
	}
}

// Collect reads new lines from all matching error log files.
func (c *NginxErrorCollector) Collect() {
	files, err := filepath.Glob(c.logGlob)
	if err != nil || len(files) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, logPath := range files {
		lines := c.readNewLines(logPath)
		for _, line := range lines {
			entry, ok := parseErrorLine(line)
			if !ok {
				continue
			}

			key := entry.domain + "\x00" + entry.path + "\x00" + entry.ip
			if h, ok := c.hits[key]; ok {
				h.count++
			} else {
				c.hits[key] = &ngxErrAccum{
					count:  1,
					domain: entry.domain,
					path:   entry.path,
					ip:     entry.ip,
					errTyp: entry.errTyp,
				}
			}
		}
	}
}

// TopErrors returns the top n error patterns sorted by count.
func (c *NginxErrorCollector) TopErrors(n int) []NginxErrorHit {
	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]NginxErrorHit, 0, len(c.hits))
	for _, h := range c.hits {
		all = append(all, NginxErrorHit{
			Count:  h.count,
			Domain: h.domain,
			Path:   h.path,
			IP:     h.ip,
			Error:  h.errTyp,
		})
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Count > all[j].Count
	})

	if len(all) > n {
		return all[:n]
	}
	return all
}

// TotalErrors returns the grand total of error log entries.
func (c *NginxErrorCollector) TotalErrors() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, h := range c.hits {
		total += h.count
	}
	return total
}

// ── Internal: incremental reading ───────────────────────────────────

func (c *NginxErrorCollector) readNewLines(logPath string) []string {
	fi, err := os.Stat(logPath)
	if err != nil {
		return nil
	}
	currentSize := fi.Size()
	lastOffset := c.offsets[logPath]
	if currentSize < lastOffset {
		lastOffset = 0 // log rotation
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

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}

	c.offsets[logPath] = currentSize
	return lines
}

// ── Internal: line parser ───────────────────────────────────────────

// parsedError holds extracted fields from one error line.
type parsedError struct {
	domain string
	path   string
	ip     string
	errTyp string
}

// parseErrorLine extracts structured data from an nginx error log line.
//
// Nginx error format (from the sample):
//
//	2026/03/24 23:36:20 [error] 3448025#3448025: *5251 access forbidden
//	  by rule, client: 45.94.31.67, server: www.recipesbynora.com,
//	  request: "GET /wp-content/themes/style.php HTTP/2.0",
//	  host: "www.recipesbynora.com", referrer: "…"
//
// The fields are comma-separated key: value pairs after the initial
// error description.  We extract client, server, and request.
func parseErrorLine(line string) (parsedError, bool) {
	var entry parsedError

	// Must contain [error] — skip [warn], [info], [notice], etc.
	if !strings.Contains(line, "[error]") {
		return entry, false
	}

	// ── Extract error type from the description ─────────────────
	// The error description sits between the ":" after the PID info
	// and the first "client:" field.
	// Examples:
	//   "access forbidden by rule"
	//   "open() \"/path/…\" failed (2: No such file or directory)"
	entry.errTyp = classifyNginxError(line)

	// ── Extract key-value pairs ─────────────────────────────────
	// Split on ", " to get "client: IP", "server: DOMAIN", etc.
	// This is more reliable than regex for nginx's format.

	entry.ip = extractField(line, "client:")
	entry.domain = extractField(line, "server:")

	// Request is quoted: request: "GET /path HTTP/ver"
	reqRaw := extractField(line, "request:")
	reqRaw = strings.Trim(reqRaw, "\"")
	parts := strings.Fields(reqRaw)
	if len(parts) >= 2 {
		entry.path = parts[1]
	}

	// Must have at least a domain to be useful.
	if entry.domain == "" {
		return entry, false
	}
	if entry.path == "" {
		entry.path = "(unknown)"
	}
	if entry.ip == "" {
		entry.ip = "—"
	}

	return entry, true
}

// extractField finds "key: value" within a comma-separated nginx
// error line and returns the trimmed value.
//
// For "…, client: 45.94.31.67, server: www.example.com, …"
// extractField(line, "client:") returns "45.94.31.67"
func extractField(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	// Skip past the key itself.
	start := idx + len(key)
	rest := line[start:]

	// The value ends at the next comma or end of line.
	end := strings.IndexByte(rest, ',')
	if end < 0 {
		end = len(rest)
	}

	return strings.TrimSpace(rest[:end])
}

// classifyNginxError extracts a short human-readable error label.
func classifyNginxError(line string) string {
	lower := strings.ToLower(line)

	switch {
	case strings.Contains(lower, "access forbidden"):
		return "forbidden"
	case strings.Contains(lower, "no such file"):
		return "not found"
	case strings.Contains(lower, "is not found"):
		return "not found"
	case strings.Contains(lower, "directory index"):
		return "no index"
	case strings.Contains(lower, "timed out"):
		return "timeout"
	case strings.Contains(lower, "connection refused"):
		return "conn refused"
	case strings.Contains(lower, "connection reset"):
		return "conn reset"
	case strings.Contains(lower, "broken pipe"):
		return "broken pipe"
	case strings.Contains(lower, "too many open files"):
		return "fd limit"
	case strings.Contains(lower, "ssl"):
		return "SSL error"
	case strings.Contains(lower, "upstream"):
		return "upstream err"
	case strings.Contains(lower, "permission denied"):
		return "perm denied"
	case strings.Contains(lower, "client intended to send too large body"):
		return "body too large"
	default:
		return "error"
	}
}
