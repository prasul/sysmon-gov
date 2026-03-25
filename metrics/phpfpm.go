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

// PHPSlowEntry represents an aggregated slow-log pattern: a specific
// domain + plugin + function combination that appears repeatedly.
type PHPSlowEntry struct {
	Count    int
	Domain   string
	Plugin   string // plugin or theme name extracted from the path
	Function string // the blocking function at the top of the stack
}

// ── Collector ───────────────────────────────────────────────────────

// PHPSlowCollector parses the PHP-FPM slow log and aggregates entries
// by domain + plugin + function.  Uses incremental reading so only
// new entries are processed on each refresh cycle.
type PHPSlowCollector struct {
	mu sync.Mutex

	logPaths []string // one or more slow log file paths
	offsets  map[string]int64

	// hits is keyed by "domain\x00plugin\x00function".
	hits map[string]*phpSlowAccum
}

type phpSlowAccum struct {
	count    int
	domain   string
	plugin   string
	function string
}

// NewPHPSlowCollector creates a collector for the given slow log
// file paths (supports globs like "/var/log/php-fpm/*.slow.log").
func NewPHPSlowCollector(logGlob string) *PHPSlowCollector {
	return &PHPSlowCollector{
		logPaths: []string{logGlob}, // resolved at collection time
		offsets:  make(map[string]int64),
		hits:     make(map[string]*phpSlowAccum),
	}
}

// Collect reads any new entries from all matching slow log files.
// The slow log format is multi-line blocks separated by blank lines:
//
//	[timestamp]  [pool NAME] pid NNNN
//	script_filename = /home/nginx/domains/DOMAIN/public/…
//	[0xaddr] function() /path/to/file.php:NN
//	[0xaddr] function() /path/to/file.php:NN
//	…
//	<blank line>
//
// We read all new lines, split them into blocks, then parse each block.
func (c *PHPSlowCollector) Collect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Resolve globs each cycle in case new log files appear.
	var allFiles []string
	for _, pattern := range c.logPaths {
		matched, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		allFiles = append(allFiles, matched...)
	}

	for _, logPath := range allFiles {
		lines := c.readNewLines(logPath)
		blocks := splitBlocks(lines)

		for _, block := range blocks {
			entry, ok := parseSlowBlock(block)
			if !ok {
				continue
			}

			key := entry.domain + "\x00" + entry.plugin + "\x00" + entry.function
			if h, ok := c.hits[key]; ok {
				h.count++
			} else {
				c.hits[key] = &phpSlowAccum{
					count:    1,
					domain:   entry.domain,
					plugin:   entry.plugin,
					function: entry.function,
				}
			}
		}
	}
}

// TopEntries returns the top n slow-log patterns sorted by count.
func (c *PHPSlowCollector) TopEntries(n int) []PHPSlowEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]PHPSlowEntry, 0, len(c.hits))
	for _, h := range c.hits {
		all = append(all, PHPSlowEntry{
			Count:    h.count,
			Domain:   h.domain,
			Plugin:   h.plugin,
			Function: h.function,
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

// TotalEntries returns the grand total of slow log entries parsed.
func (c *PHPSlowCollector) TotalEntries() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, h := range c.hits {
		total += h.count
	}
	return total
}

// ── Internal: incremental file reading ──────────────────────────────

func (c *PHPSlowCollector) readNewLines(logPath string) []string {
	fi, err := os.Stat(logPath)
	if err != nil {
		return nil
	}

	currentSize := fi.Size()
	lastOffset := c.offsets[logPath]

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
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	c.offsets[logPath] = currentSize
	return lines
}

// ── Internal: parsing ───────────────────────────────────────────────

// splitBlocks divides the raw lines into individual log entries.
// Each entry starts with a "[" timestamp line and ends at the next
// blank line (or the next timestamp line).
func splitBlocks(lines []string) [][]string {
	var blocks [][]string
	var current []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Blank line or a new timestamp header marks a block boundary.
		if trimmed == "" {
			if len(current) > 0 {
				blocks = append(blocks, current)
				current = nil
			}
			continue
		}

		// A new entry starts with "[" (the timestamp).
		// If we already have lines in current, flush the previous block.
		if strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "[0x") {
			if len(current) > 0 {
				blocks = append(blocks, current)
			}
			current = []string{trimmed}
			continue
		}

		current = append(current, trimmed)
	}

	// Don't forget the last block.
	if len(current) > 0 {
		blocks = append(blocks, current)
	}

	return blocks
}

// parsedSlowEntry is internal — we convert to public PHPSlowEntry later.
type parsedSlowEntry struct {
	domain   string
	plugin   string
	function string
}

// parseSlowBlock extracts domain, plugin, and function from a single
// slow-log entry block.
//
// Example block:
//
//	[24-Mar-2026 04:55:26]  [pool php81-www] pid 1898552
//	script_filename = /home/nginx/domains/example.com/public/wp-admin/admin-ajax.php
//	[0x…] sleep() /home/…/plugins/wpforms/vendor/…/file.php:53
//	[0x…] handle() /home/…/plugins/wpforms/vendor/…/file.php:174
//	…
func parseSlowBlock(block []string) (parsedSlowEntry, bool) {
	var entry parsedSlowEntry

	// ── Extract domain from script_filename ─────────────────────
	for _, line := range block {
		if strings.HasPrefix(line, "script_filename") {
			entry.domain = extractDomainFromScriptPath(line)
			break
		}
	}
	if entry.domain == "" {
		return entry, false
	}

	// ── Extract top function and plugin from stack frames ────────
	// Stack frames start with "[0x" — the first one is the
	// function that was actually blocking.
	topFuncFound := false
	for _, line := range block {
		if !strings.HasPrefix(line, "[0x") {
			continue
		}

		// Extract the function name — sits between "] " and "() " or "("
		funcName := extractFuncName(line)

		if !topFuncFound && funcName != "" {
			entry.function = funcName
			topFuncFound = true
		}

		// Extract plugin/theme name from the file path in this frame.
		// We look through the whole stack because the top frame might
		// be in WordPress core (e.g. sleep, curl_exec) — the *caller*
		// in the plugin is more useful.
		if entry.plugin == "" {
			entry.plugin = extractPluginName(line)
		}
	}

	// Fallback labels for entries without a clear plugin or function.
	if entry.function == "" {
		entry.function = "(unknown)"
	}
	if entry.plugin == "" {
		entry.plugin = "(core/other)"
	}

	return entry, true
}

// extractDomainFromScriptPath parses:
//
//	script_filename = /home/nginx/domains/example.com/public/…
//
// and returns "example.com".
func extractDomainFromScriptPath(line string) string {
	// Split on "=" to get the path portion.
	parts := strings.SplitN(line, "=", 2)
	if len(parts) < 2 {
		return ""
	}
	path := strings.TrimSpace(parts[1])

	// Walk the path segments looking for "domains" then take the next one.
	segments := strings.Split(filepath.ToSlash(path), "/")
	for i, s := range segments {
		if s == "domains" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return ""
}

// extractFuncName parses a stack frame line like:
//
//	[0x0000796d65613e20] sleep() /home/…/file.php:53
//
// and returns "sleep".
func extractFuncName(line string) string {
	// Skip the "[0x…] " prefix — find the first "]".
	closeBracket := strings.IndexByte(line, ']')
	if closeBracket < 0 || closeBracket+2 >= len(line) {
		return ""
	}
	rest := strings.TrimSpace(line[closeBracket+1:])

	// The function name ends at "(" — e.g. "sleep() /path…"
	parenIdx := strings.IndexByte(rest, '(')
	if parenIdx <= 0 {
		return ""
	}
	return rest[:parenIdx]
}

// extractPluginName looks for "/wp-content/plugins/<name>/" or
// "/wp-content/themes/<name>/" in a stack frame's file path and
// returns the plugin or theme name.
//
// Example path fragment:
//
//	/wp-content/plugins/wpforms/vendor/woocommerce/action-scheduler/…
//
// → returns "wpforms"
func extractPluginName(line string) string {
	// Try plugins first, then themes.
	for _, marker := range []string{"/wp-content/plugins/", "/wp-content/themes/"} {
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		after := line[idx+len(marker):]
		// The plugin name is everything up to the next "/".
		slashIdx := strings.IndexByte(after, '/')
		if slashIdx <= 0 {
			continue
		}
		name := after[:slashIdx]
		if name != "" {
			return name
		}
	}
	return ""
}
