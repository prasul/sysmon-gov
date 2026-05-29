package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ========================================================================
//  SHARED LOG READER
// ========================================================================
//
// Before this optimization, three collectors (NginxCollector, BotCollector,
// WPLoginCollector) each independently:
//   1. filepath.Glob() the same pattern
//   2. os.Stat() each matching file
//   3. os.Open() + Seek() + bufio.Scan() to read new lines
//
// With 5 domains, that's 15 Stat + 15 Open + 15 Seek + 15 Read calls
// every 2 seconds — for the SAME bytes from the SAME files.
//
// LogReader reads each file ONCE and dispatches raw lines to registered
// subscribers.  This cuts access-log I/O by ~70%.

// LogLine is a raw line plus the domain it came from.
type LogLine struct {
	Line   string
	Domain string
}

// LogSubscriber is a function that receives batches of new lines.
// Subscribers are called synchronously during Collect().
type LogSubscriber func(lines []LogLine)

// LogReader reads log files incrementally and dispatches to subscribers.
type LogReader struct {
	mu sync.Mutex

	glob        string
	subscribers []LogSubscriber

	// Offset tracking per file.
	offsets map[string]int64

	// Cached glob results — re-glob only every 30 seconds.
	cachedFiles     []string
	lastGlob        time.Time
	globCacheExpiry time.Duration

	// Reusable scanner buffer (avoids 512KB alloc per file per tick).
	scanBuf []byte
}

// NewLogReader creates a shared reader for the given log glob pattern.
func NewLogReader(glob string) *LogReader {
	return &LogReader{
		glob:            glob,
		offsets:         make(map[string]int64),
		globCacheExpiry: 30 * time.Second,
		scanBuf:         make([]byte, 512*1024), // allocated ONCE, reused
	}
}

// Subscribe registers a function to receive new log lines.
// Call before the first Collect().
func (r *LogReader) Subscribe(fn LogSubscriber) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscribers = append(r.subscribers, fn)
}

// Collect reads new bytes from all matching log files and dispatches
// the parsed lines to all subscribers.  Each file is opened, read, and
// closed exactly ONCE per call — regardless of how many subscribers
// are registered.
func (r *LogReader) Collect() {
	r.mu.Lock()
	defer r.mu.Unlock()

	files := r.resolveFiles()
	if len(files) == 0 {
		return
	}

	// Collect all new lines across all files.
	var allLines []LogLine

	for _, logPath := range files {
		domain := extractDomain(logPath)
		if domain == "" {
			continue
		}

		lines := r.readNewLines(logPath)
		for _, line := range lines {
			allLines = append(allLines, LogLine{Line: line, Domain: domain})
		}
	}

	if len(allLines) == 0 {
		return
	}

	// Dispatch to all subscribers.
	for _, sub := range r.subscribers {
		sub(allLines)
	}
}

// resolveFiles returns the list of files matching the glob.
// Results are cached for globCacheExpiry to avoid re-globbing every tick.
func (r *LogReader) resolveFiles() []string {
	if time.Since(r.lastGlob) < r.globCacheExpiry && r.cachedFiles != nil {
		return r.cachedFiles
	}

	files, err := filepath.Glob(r.glob)
	if err != nil {
		return nil
	}
	r.cachedFiles = files
	r.lastGlob = time.Now()
	return files
}

// readNewLines reads only the bytes appended since the last call.
// Reuses r.scanBuf to avoid per-call allocations.
func (r *LogReader) readNewLines(logPath string) []string {
	fi, err := os.Stat(logPath)
	if err != nil {
		return nil
	}

	currentSize := fi.Size()
	lastOffset := r.offsets[logPath]

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

	if lastOffset > 0 {
		if _, err := f.Seek(lastOffset, 0); err != nil {
			return nil
		}
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	// Reuse the pre-allocated buffer instead of allocating 512KB.
	scanner.Buffer(r.scanBuf, len(r.scanBuf))

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	r.offsets[logPath] = currentSize
	return lines
}

// ========================================================================
//  SUBSCRIBER ADAPTERS
// ========================================================================
//
// These adapt the existing collectors to work as LogReader subscribers.
// Each collector's Collect() method is replaced by a subscriber function
// that processes only its portion of each line.

// NginxSubscriber returns a subscriber that feeds lines into an
// NginxCollector without the collector doing its own file I/O.
func NginxSubscriber(c *NginxCollector) LogSubscriber {
	return func(lines []LogLine) {
		c.mu.Lock()
		defer c.mu.Unlock()

		for _, ll := range lines {
			ip, path, ok := parseLogLine(ll.Line)
			if !ok {
				continue
			}

			if c.pathHits[ll.Domain] == nil {
				c.pathHits[ll.Domain] = make(map[string]int)
			}
			c.pathHits[ll.Domain][path]++

			if c.ipHits[ll.Domain] == nil {
				c.ipHits[ll.Domain] = make(map[string]int)
			}
			c.ipHits[ll.Domain][ip]++

			if _, cached := c.geoCache[ip]; !cached {
				c.geoCache[ip] = c.geoLookup(ip)
			}
		}
	}
}

// BotSubscriber returns a subscriber that feeds lines into a
// BotCollector without the collector doing its own file I/O.
func BotSubscriber(c *BotCollector) LogSubscriber {
	return func(lines []LogLine) {
		c.mu.Lock()
		defer c.mu.Unlock()

		for _, ll := range lines {
			botName, botType := classifyBot(ll.Line)
			if botName == "" {
				continue
			}

			path := extractPathFromLine(ll.Line)
			key := botName + "\x00" + ll.Domain
			if h, ok := c.botDomainHits[key]; ok {
				h.count++
				h.pathCounts[path]++
			} else {
				c.botDomainHits[key] = &botAccum{
					count:      1,
					botName:    botName,
					botType:    botType,
					domain:     ll.Domain,
					pathCounts: map[string]int{path: 1},
				}
			}
		}
	}
}

// WPLoginSubscriber returns a subscriber that feeds lines into a
// WPLoginCollector without the collector doing its own file I/O.
func WPLoginSubscriber(c *WPLoginCollector) LogSubscriber {
	return func(lines []LogLine) {
		c.mu.Lock()
		defer c.mu.Unlock()

		for _, ll := range lines {
			if !isWPLoginHit(ll.Line) {
				continue
			}

			ip := extractIP(ll.Line)
			if ip == "" {
				continue
			}

			ts := extractTimestamp(ll.Line)
			key := ll.Domain + "\x00" + ip

			if h, ok := c.hits[key]; ok {
				h.count++
				if ts.After(h.lastSeen) {
					h.lastSeen = ts
				}
			} else {
				c.hits[key] = &wpHitAccum{
					count:    1,
					domain:   ll.Domain,
					ip:       ip,
					lastSeen: ts,
				}
			}

			c.liveIPs[key] = true

			if _, cached := c.geoCache[ip]; !cached {
				c.geoCache[ip] = c.geoLookup(ip)
			}
		}
	}
}
