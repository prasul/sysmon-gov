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

// WPFileChange represents a group of recently modified files within
// a single plugin or theme on one domain.
type WPFileChange struct {
	Count      int       // number of files changed
	Domain     string    // e.g. "example.com"
	Name       string    // plugin or theme name
	Kind       string    // "plugin" or "theme"
	LastChange time.Time // most recent modification timestamp
}

// ── Collector ───────────────────────────────────────────────────────

// WPFileCollector scans WordPress plugin and theme directories for
// files modified within a rolling time window (default 48 hours).
//
// Unlike the log-based collectors, this one re-scans the filesystem
// from scratch on each call — file modification times are the source
// of truth.  The scan is throttled so it only runs once per
// configured interval (not every dashboard refresh tick).
type WPFileCollector struct {
	mu sync.Mutex

	domainsGlob string        // e.g. "/home/nginx/domains/*"
	window      time.Duration // how far back to look (48h)
	scanEvery   time.Duration // minimum time between full scans
	lastScan    time.Time

	// Cached results from the last scan.
	results []WPFileChange
}

// NewWPFileCollector creates a collector that scans plugin and theme
// directories under the given domains glob.  window controls how far
// back to look for changes.
func NewWPFileCollector(domainsGlob string, window time.Duration) *WPFileCollector {
	// Default to a reasonable scan interval — filesystem walks are
	// expensive, so we don't want to do them every 2 seconds.
	scanEvery := 30 * time.Second
	if window < time.Hour {
		scanEvery = 10 * time.Second
	}

	return &WPFileCollector{
		domainsGlob: domainsGlob,
		window:      window,
		scanEvery:   scanEvery,
	}
}

// Collect runs a filesystem scan if enough time has elapsed since
// the last one.  The results are cached and returned by TopChanges.
func (c *WPFileCollector) Collect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.lastScan) < c.scanEvery {
		return // use cached results
	}
	c.lastScan = time.Now()
	c.results = c.scan()
}

// TopChanges returns the top n plugin/theme entries with the most
// recently modified files.
func (c *WPFileCollector) TopChanges(n int) []WPFileChange {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.results) <= n {
		return c.results
	}
	return c.results[:n]
}

// TotalChanges returns the sum of all changed files across all
// plugins/themes.
func (c *WPFileCollector) TotalChanges() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, r := range c.results {
		total += r.Count
	}
	return total
}

// ── Internal scan ───────────────────────────────────────────────────

func (c *WPFileCollector) scan() []WPFileChange {
	cutoff := time.Now().Add(-c.window)

	// Discover domain directories.
	domainDirs, err := filepath.Glob(c.domainsGlob)
	if err != nil || len(domainDirs) == 0 {
		return nil
	}

	// accum keyed by "domain\x00kind\x00name"
	type accum struct {
		count      int
		domain     string
		name       string
		kind       string
		lastChange time.Time
	}
	hits := make(map[string]*accum)

	for _, domainDir := range domainDirs {
		domain := filepath.Base(domainDir)

		// Scan both plugins and themes.
		for _, sub := range []struct {
			path string
			kind string
		}{
			{filepath.Join(domainDir, "public", "wp-content", "plugins"), "plugin"},
			{filepath.Join(domainDir, "public", "wp-content", "themes"), "theme"},
		} {
			// Check the directory exists before walking.
			if _, err := os.Stat(sub.path); err != nil {
				continue
			}

			// List top-level entries (each is a plugin/theme).
			entries, err := os.ReadDir(sub.path)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if !entry.IsDir() {
					continue // skip loose files like index.php
				}
				name := entry.Name()
				pluginDir := filepath.Join(sub.path, name)

				// Walk this plugin/theme directory looking for
				// recently modified files.
				count, latest := countRecentFiles(pluginDir, cutoff)
				if count == 0 {
					continue
				}

				key := domain + "\x00" + sub.kind + "\x00" + name
				hits[key] = &accum{
					count:      count,
					domain:     domain,
					name:       name,
					kind:       sub.kind,
					lastChange: latest,
				}
			}
		}
	}

	// Convert to slice and sort by count descending.
	results := make([]WPFileChange, 0, len(hits))
	for _, h := range hits {
		results = append(results, WPFileChange{
			Count:      h.count,
			Domain:     h.domain,
			Name:       h.name,
			Kind:       h.kind,
			LastChange: h.lastChange,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})

	return results
}

// countRecentFiles walks a directory tree and counts files whose
// modification time is after the cutoff.  Returns the count and
// the most recent modification time found.
//
// We use filepath.WalkDir (not Walk) for better performance —
// it avoids Stat() on every entry when we only need type info.
func countRecentFiles(root string, cutoff time.Time) (int, time.Time) {
	count := 0
	var latest time.Time

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir // skip unreadable dirs
			}
			return nil
		}

		// Skip directories and non-regular files.
		if d.IsDir() {
			// Skip hidden directories and vendor/node_modules.
			name := d.Name()
			if name != "." && (name[0] == '.' || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		// Only check PHP, JS, and common web files — skip
		// images, fonts, and other binary assets.
		if !isCodeFile(d.Name()) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		modTime := info.ModTime()
		if modTime.After(cutoff) {
			count++
			if modTime.After(latest) {
				latest = modTime
			}
		}

		return nil
	})

	return count, latest
}

// isCodeFile returns true for file extensions commonly modified
// in plugin/theme attacks or legitimate updates.
func isCodeFile(name string) bool {
	lower := strings.ToLower(name)
	codeExts := []string{
		".php", ".js", ".css", ".html", ".htm",
		".json", ".xml", ".tpl", ".twig", ".blade",
		".sh", ".py", ".rb", ".sql",
	}
	for _, ext := range codeExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
