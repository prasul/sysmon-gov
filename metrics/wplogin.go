package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Public types ────────────────────────────────────────────────────

// WPLoginHit represents aggregate brute-force attempts against
// wp-login.php for one domain+IP combination.
type WPLoginHit struct {
	Count    int
	Domain   string
	IP       string
	Country  string
	LastSeen time.Time // most recent hit from this IP
	IsLive   bool      // true if a hit arrived in the last collection cycle
}

// ── Collector ───────────────────────────────────────────────────────

// WPLoginCollector watches nginx access logs for wp-login.php requests.
// It uses the same incremental-read strategy as NginxCollector: full
// file on first run (historical), then only new bytes on each refresh.
type WPLoginCollector struct {
	mu sync.Mutex

	logGlob   string
	geoLookup func(string) string

	offsets  map[string]int64 // file path → last read byte offset
	geoCache map[string]string

	// hits is keyed by "domain\x00ip" for fast lookup.
	hits map[string]*wpHitAccum

	// liveIPs tracks IPs seen in the CURRENT collection cycle.
	// Cleared at the start of each Collect() call.
	liveIPs map[string]bool
}

// wpHitAccum accumulates hits for one domain+IP pair.
type wpHitAccum struct {
	count    int
	domain   string
	ip       string
	lastSeen time.Time
}

// NewWPLoginCollector creates a collector watching the given log glob
// for wp-login.php hits.  The geoLookup function resolves IP→country
// and is called once per unique IP.
func NewWPLoginCollector(logGlob string, geoLookup func(string) string) *WPLoginCollector {
	return &WPLoginCollector{
		logGlob:   logGlob,
		geoLookup: geoLookup,
		offsets:    make(map[string]int64),
		geoCache:   make(map[string]string),
		hits:       make(map[string]*wpHitAccum),
		liveIPs:    make(map[string]bool),
	}
}

// Collect scans all matching log files for new lines containing
// wp-login.php.  On first run the entire file is read (historical
// data); subsequent runs read only new bytes.
func (c *WPLoginCollector) Collect() {
	files, err := filepath.Glob(c.logGlob)
	if err != nil || len(files) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset the live-hit tracker for this cycle.
	c.liveIPs = make(map[string]bool)

	for _, logPath := range files {
		domain := extractDomain(logPath) // reuse from nginx.go
		if domain == "" {
			continue
		}

		lines := c.readNewLines(logPath)
		for _, line := range lines {
			if !isWPLoginHit(line) {
				continue
			}

			ip := extractIP(line)
			if ip == "" {
				continue
			}

			// Parse the timestamp from the log line for LastSeen.
			ts := extractTimestamp(line)

			key := domain + "\x00" + ip
			if h, ok := c.hits[key]; ok {
				h.count++
				if ts.After(h.lastSeen) {
					h.lastSeen = ts
				}
			} else {
				c.hits[key] = &wpHitAccum{
					count:    1,
					domain:   domain,
					ip:       ip,
					lastSeen: ts,
				}
			}

			// Mark this domain+IP as having fresh activity.
			c.liveIPs[key] = true

			// Resolve country once per unique IP.
			if _, cached := c.geoCache[ip]; !cached {
				c.geoCache[ip] = c.geoLookup(ip)
			}
		}
	}
}

// TopHits returns the top n wp-login.php attackers sorted by count.
// The IsLive flag is set on entries that had new hits since the last
// Collect() — the UI uses this to trigger the blinking indicator.
func (c *WPLoginCollector) TopHits(n int) []WPLoginHit {
	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]WPLoginHit, 0, len(c.hits))
	for key, h := range c.hits {
		country := c.geoCache[h.ip]
		if country == "" {
			country = "—"
		}
		all = append(all, WPLoginHit{
			Count:    h.count,
			Domain:   h.domain,
			IP:       h.ip,
			Country:  country,
			LastSeen: h.lastSeen,
			IsLive:   c.liveIPs[key],
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

// TotalHits returns the grand total of wp-login.php requests seen.
func (c *WPLoginCollector) TotalHits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, h := range c.hits {
		total += h.count
	}
	return total
}

// HasLiveAttack returns true if ANY wp-login.php hits arrived during
// the most recent collection cycle.
func (c *WPLoginCollector) HasLiveAttack() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.liveIPs) > 0
}

// ── Internal helpers ────────────────────────────────────────────────

// readNewLines reads only newly-appended bytes since the last call.
// MUST be called with c.mu held.
func (c *WPLoginCollector) readNewLines(logPath string) []string {
	fi, err := os.Stat(logPath)
	if err != nil {
		return nil
	}

	currentSize := fi.Size()
	lastOffset := c.offsets[logPath]

	// File rotated → restart from beginning.
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

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 512*1024), 512*1024)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}

	c.offsets[logPath] = currentSize
	return lines
}

// isWPLoginHit checks if a log line is a request to wp-login.php.
// We check the request portion between the first pair of quotes.
// Matches POST and GET — brute-force attacks use both.
func isWPLoginHit(line string) bool {
	// Quick pre-filter before doing any string parsing.
	if !strings.Contains(line, "wp-login.php") {
		return false
	}

	// Verify it's in the actual request path, not the referer or UA.
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return false
	}
	rest := line[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return false
	}
	requestLine := rest[:q2]
	return strings.Contains(requestLine, "wp-login.php")
}

// extractIP pulls the client IP from the start of a Combined Log
// Format line (everything before the first space).
func extractIP(line string) string {
	idx := strings.IndexByte(line, ' ')
	if idx <= 0 {
		return ""
	}
	return line[:idx]
}

// extractTimestamp parses the [dd/Mon/yyyy:HH:MM:SS zone] portion
// of a Combined Log Format log line.  Returns time.Now() on failure
// so the "last seen" value is still meaningful.
func extractTimestamp(line string) time.Time {
	// Timestamp sits between '[' and ']'.
	start := strings.IndexByte(line, '[')
	if start < 0 {
		return time.Now()
	}
	end := strings.IndexByte(line[start:], ']')
	if end < 0 {
		return time.Now()
	}
	raw := line[start+1 : start+end]

	// Standard CLF timestamp format: 02/Jan/2006:15:04:05 -0700
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", raw)
	if err != nil {
		return time.Now()
	}
	return t
}
