package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ── Public types returned to the UI ─────────────────────────────────

// NginxPathHit represents aggregate hits for one domain+path pair.
type NginxPathHit struct {
	Count  int
	Domain string
	Path   string
}

// NginxIPHit represents aggregate hits for one domain+IP pair.
type NginxIPHit struct {
	Count   int
	Domain  string
	IP      string
	Country string
}

// ── Collector ───────────────────────────────────────────────────────

// NginxCollector accumulates hit counts from nginx access logs.
// It is safe for concurrent use — the UI refresh goroutine is the
// only caller, but we guard with a mutex for correctness.
type NginxCollector struct {
	mu sync.Mutex

	logGlob   string                    // glob pattern for access logs
	geoLookup func(string) string       // IP → country code

	offsets  map[string]int64           // file path → last read byte offset
	pathHits map[string]map[string]int  // domain → path → count
	ipHits   map[string]map[string]int  // domain → IP → count
	geoCache map[string]string          // IP → cached country code
}

// NewNginxCollector creates a collector that watches logs matching the
// given glob pattern (e.g. "/home/nginx/domains/*/log/access.log").
// The geoLookup function is called once per unique IP and cached.
func NewNginxCollector(logGlob string, geoLookup func(string) string) *NginxCollector {
	return &NginxCollector{
		logGlob:   logGlob,
		geoLookup: geoLookup,
		offsets:    make(map[string]int64),
		pathHits:   make(map[string]map[string]int),
		ipHits:     make(map[string]map[string]int),
		geoCache:   make(map[string]string),
	}
}

// Collect scans all matching log files for new lines since the last
// call.  On the very first call, each file is read from the beginning
// (giving you historical data).  On subsequent calls, only new bytes
// are processed — exactly like "tail -f" but in Go.
//
// If a file shrinks (log rotation), the offset resets to zero so the
// new file is read from the start.
func (c *NginxCollector) Collect() {
	files, err := filepath.Glob(c.logGlob)
	if err != nil || len(files) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, logPath := range files {
		domain := extractDomain(logPath)
		if domain == "" {
			continue
		}

		lines := c.readNewLines(logPath)
		for _, line := range lines {
			ip, path, ok := parseLogLine(line)
			if !ok {
				continue
			}

			// ── Accumulate path hits ──
			if c.pathHits[domain] == nil {
				c.pathHits[domain] = make(map[string]int)
			}
			c.pathHits[domain][path]++

			// ── Accumulate IP hits ──
			if c.ipHits[domain] == nil {
				c.ipHits[domain] = make(map[string]int)
			}
			c.ipHits[domain][ip]++

			// ── Resolve country once per unique IP ──
			if _, cached := c.geoCache[ip]; !cached {
				c.geoCache[ip] = c.geoLookup(ip)
			}
		}
	}
}

// TopPaths returns the top n domain+path combinations across all
// monitored domains, sorted by hit count descending.
func (c *NginxCollector) TopPaths(n int) []NginxPathHit {
	c.mu.Lock()
	defer c.mu.Unlock()

	var all []NginxPathHit
	for domain, paths := range c.pathHits {
		for path, count := range paths {
			all = append(all, NginxPathHit{
				Count:  count,
				Domain: domain,
				Path:   path,
			})
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Count > all[j].Count
	})

	if len(all) > n {
		return all[:n]
	}
	return all
}

// TopIPs returns the top n domain+IP combinations across all
// monitored domains, sorted by hit count descending.
func (c *NginxCollector) TopIPs(n int) []NginxIPHit {
	c.mu.Lock()
	defer c.mu.Unlock()

	var all []NginxIPHit
	for domain, ips := range c.ipHits {
		for ip, count := range ips {
			country := c.geoCache[ip]
			if country == "" {
				country = "—"
			}
			all = append(all, NginxIPHit{
				Count:   count,
				Domain:  domain,
				IP:      ip,
				Country: country,
			})
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Count > all[j].Count
	})

	if len(all) > n {
		return all[:n]
	}
	return all
}

// TotalRequests returns the grand total of all requests seen so far.
func (c *NginxCollector) TotalRequests() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := 0
	for _, paths := range c.pathHits {
		for _, count := range paths {
			total += count
		}
	}
	return total
}

// ── Internal helpers ────────────────────────────────────────────────

// readNewLines reads only the bytes added since the last call.
// MUST be called with c.mu held.
func (c *NginxCollector) readNewLines(logPath string) []string {
	fi, err := os.Stat(logPath)
	if err != nil {
		return nil
	}

	currentSize := fi.Size()
	lastOffset := c.offsets[logPath]

	// File was truncated or rotated → restart from beginning.
	if currentSize < lastOffset {
		lastOffset = 0
	}

	// No new data since last read.
	if currentSize == lastOffset {
		return nil
	}

	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Seek to where we left off.
	if lastOffset > 0 {
		if _, err := f.Seek(lastOffset, 0); err != nil {
			return nil
		}
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	// Nginx lines with long query strings can exceed the 64 KB
	// default.  512 KB per line is generous.
	scanner.Buffer(make([]byte, 0, 512*1024), 512*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Update the offset for next call.
	c.offsets[logPath] = currentSize
	return lines
}

// extractDomain pulls the domain name from a log file path.
// Given "/home/nginx/domains/example.com/log/access.log" it returns
// "example.com".  It looks for the "domains" path component and takes
// the next segment.
func extractDomain(logPath string) string {
	parts := strings.Split(filepath.ToSlash(logPath), "/")
	for i, p := range parts {
		if p == "domains" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// parseLogLine extracts the client IP and request path from a
// standard Combined Log Format line.
//
// Format:
//
//	IP - - [time] "METHOD /path HTTP/ver" status size "ref" "ua"
//
// It handles IPv6 addresses and long URLs correctly.
func parseLogLine(line string) (ip, path string, ok bool) {
	// ── IP: everything before the first space ──
	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx <= 0 {
		return "", "", false
	}
	ip = line[:spaceIdx]

	// ── Request line: between the first pair of double-quotes ──
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return "", "", false
	}
	rest := line[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return "", "", false
	}
	requestLine := rest[:q2] // e.g. "GET /some/path HTTP/2.0"

	// Split on space to get [METHOD, PATH, VERSION].
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return "", "", false
	}
	path = parts[1]

	// Strip query strings for cleaner grouping — "/page?q=1" → "/page".
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}

	// Skip static assets (images, CSS, JS, fonts) — they are noise
	// in a "top URLs" table.  Operators care about page/API hits.
	if isStaticAsset(path) {
		return "", "", false
	}

	return ip, path, true
}

// isStaticAsset returns true for common static file extensions that
// would clutter the "top paths" list.
func isStaticAsset(path string) bool {
	lower := strings.ToLower(path)
	staticExts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
		".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
		".map", ".br", ".gz",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
