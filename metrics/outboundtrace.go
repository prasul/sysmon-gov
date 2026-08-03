package metrics

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ========================================================================
//  OUTBOUND HTTP TRACE COLLECTOR
// ========================================================================
//
// Reads /var/log/sysmon-outbound.log, written by the WordPress
// mu-plugin sysmon-outbound-tracer.php.  Each line records a slow or
// failed outbound HTTP call (wp_remote_get/post) with the plugin that
// made it — so a hung external call is traced to its source instantly.
//
// Line format (pipe-delimited):
//   ts|domain|elapsed|timeout|status|host|culprit|url
//
// This is the PHP-side companion to outbound.go (the socket-side
// detector).  Together they answer both "what remote is our server
// stuck on?" (outbound.go) and "which plugin on which site is calling
// it?" (this collector).

// OutboundCall is one logged slow/failed outbound HTTP request.
type OutboundCall struct {
	Time    time.Time
	Domain  string
	Elapsed float64 // seconds
	Timeout string
	Status  string
	Host    string // remote host being called
	Culprit string // plugin:name file:line
	URL     string
}

// OutboundHostSummary aggregates calls to one remote host.
type OutboundHostSummary struct {
	Host       string
	Count      int
	Errors     int
	MaxElapsed float64
	Culprits   map[string]int // culprit → count
	Domains    map[string]int // affected domains
}

// OutboundTraceCollector reads and aggregates the tracer log.
type OutboundTraceCollector struct {
	mu sync.Mutex

	logPath string
	offset  int64

	// Recent calls (ring buffer).
	recent    []OutboundCall
	maxRecent int

	// Aggregated by host.
	hosts map[string]*OutboundHostSummary
}

// NewOutboundTraceCollector creates a collector for the tracer log.
func NewOutboundTraceCollector(logPath string) *OutboundTraceCollector {
	if logPath == "" {
		logPath = "/var/log/sysmon-outbound.log"
	}
	return &OutboundTraceCollector{
		logPath:   logPath,
		maxRecent: 100,
		hosts:     make(map[string]*OutboundHostSummary),
	}
}

// Collect reads new lines from the tracer log since the last call.
func (c *OutboundTraceCollector) Collect() {
	fi, err := os.Stat(c.logPath)
	if err != nil {
		return // log doesn't exist yet — tracer not installed
	}

	size := fi.Size()
	c.mu.Lock()
	last := c.offset
	c.mu.Unlock()

	if size < last {
		last = 0 // rotated
	}
	if size == last {
		return // nothing new
	}

	f, err := os.Open(c.logPath)
	if err != nil {
		return
	}
	defer f.Close()

	if last > 0 {
		f.Seek(last, 0)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	var newCalls []OutboundCall
	for scanner.Scan() {
		if call, ok := parseOutboundLine(scanner.Text()); ok {
			newCalls = append(newCalls, call)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = size

	for _, call := range newCalls {
		// Append to ring buffer.
		c.recent = append(c.recent, call)
		if len(c.recent) > c.maxRecent {
			c.recent = c.recent[len(c.recent)-c.maxRecent:]
		}

		// Aggregate by host.
		h, ok := c.hosts[call.Host]
		if !ok {
			h = &OutboundHostSummary{
				Host:     call.Host,
				Culprits: make(map[string]int),
				Domains:  make(map[string]int),
			}
			c.hosts[call.Host] = h
		}
		h.Count++
		if strings.HasPrefix(call.Status, "ERROR") {
			h.Errors++
		}
		if call.Elapsed > h.MaxElapsed {
			h.MaxElapsed = call.Elapsed
		}
		h.Culprits[call.Culprit]++
		h.Domains[call.Domain]++
	}
}

// TopHosts returns the hosts with the most slow/failed calls.
func (c *OutboundTraceCollector) TopHosts(n int) []OutboundHostSummary {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]OutboundHostSummary, 0, len(c.hosts))
	for _, h := range c.hosts {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		// Errors first, then volume.
		if out[i].Errors != out[j].Errors {
			return out[i].Errors > out[j].Errors
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// RecentCalls returns the most recent logged calls.
func (c *OutboundTraceCollector) RecentCalls(n int) []OutboundCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > len(c.recent) {
		n = len(c.recent)
	}
	out := make([]OutboundCall, n)
	copy(out, c.recent[len(c.recent)-n:])
	// Reverse so newest is first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// HasActivity reports whether any slow/failed outbound calls are logged.
func (c *OutboundTraceCollector) HasActivity() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.recent) > 0
}

// TopCulprit returns the single worst plugin across all hosts, for
// the Immediate Attention banner.  Returns "" if nothing logged.
func (c *OutboundTraceCollector) TopCulprit() (culprit, host string, count int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	best := 0
	for _, h := range c.hosts {
		for cul, n := range h.Culprits {
			if n > best {
				best = n
				culprit = cul
				host = h.Host
				count = n
			}
		}
	}
	return culprit, host, count
}

// parseOutboundLine parses one pipe-delimited tracer log line.
// Format: ts|domain|elapsed|timeout|status|host|culprit|url
func parseOutboundLine(line string) (OutboundCall, bool) {
	parts := strings.SplitN(line, "|", 8)
	if len(parts) != 8 {
		return OutboundCall{}, false
	}

	ts, _ := time.Parse("2006-01-02 15:04:05", parts[0])
	elapsed, _ := strconv.ParseFloat(parts[2], 64)

	return OutboundCall{
		Time:    ts,
		Domain:  parts[1],
		Elapsed: elapsed,
		Timeout: parts[3],
		Status:  parts[4],
		Host:    parts[5],
		Culprit: parts[6],
		URL:     parts[7],
	}, true
}
