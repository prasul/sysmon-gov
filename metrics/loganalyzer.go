package metrics

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ========================================================================
//  LOG ANALYZER  (memory-optimized)
// ========================================================================
//
// Go port of the "NGINX LOG INVESTIGATOR & ABUSE DETECTOR" bash script.
//
// Concurrency model:
//   - MaybeAnalyze()/ForceAnalyze() spawn ONE background goroutine,
//     self-throttled to the 3-minute interval.  The UI thread never
//     blocks; it reads finished snapshots via Results() under mutex.
//
// Memory model (the optimization):
//   - Each domain's log tail is read as ONE ≤4MB block.  Lines are
//     produced by slicing that block — Go string slicing shares the
//     backing array, so there are ZERO per-line copies.
//   - The line parser is single-pass with byte scanning.  It never
//     calls strings.Fields/Split, so no per-line slice allocations.
//   - Count maps hold substrings of the block during analysis; the
//     block + maps are garbage the moment the domain finishes.
//   - Only top-N labels survive, and they are strings.Clone()d so
//     they don't pin the 4MB block in memory after the scan.
//
// Peak memory per scan ≈ 4MB (one domain block) + count maps,
// regardless of how many domains exist.  Retained between scans
// ≈ a few KB per domain.

const (
	defaultAnalyzeLines    = 10000
	defaultAnalyzeInterval = 3 * time.Minute
	maxTailBytes           = 4 * 1024 * 1024 // read at most 4MB from file end
)

// LogAnalyzer periodically deep-analyzes domain access logs.
type LogAnalyzer struct {
	mu sync.Mutex

	domainsGlob string // e.g. /home/nginx/domains/*
	linesToScan int
	interval    time.Duration

	results     []DomainAnalysis
	lastRun     time.Time
	running     bool
	runDuration time.Duration

	// Previous unique-IP counts per domain, for delta tracking.
	prevUniqueIPs map[string]int
}

// DomainAnalysis holds the full investigation report for one domain.
type DomainAnalysis struct {
	Domain     string
	LinesRead  int
	AnalyzedAt time.Time

	TopMinutes   []CountItem // [1] spike detection
	TopIPs       []CountItem // [2] top talkers
	Methods      []CountItem // [3] HTTP methods
	StatusCodes  []CountItem // [4] status codes
	TopURLs      []CountItem // [5] endpoints
	TopReferrers []CountItem // [6] referrers
	BlankUACount int         // [7] blank user agents

	// POST hot spots — IP→URL pairs receiving heavy POST traffic.
	// Surfaces brute-force/spam targets (wp-login.php, xmlrpc.php).
	TopPosts  []PostHit
	PostTotal int


	// Attack signatures (from NginxHunter port)
	Attacks []AttackSummary

	// IP delta tracking (new vs bash script)
	UniqueIPs     int
	UniqueIPDelta int  // change since previous run; 0 on first run
	HasPrevRun    bool // true if delta is meaningful

	// [8] Threat assessment
	Threats     []ThreatFinding
	ThreatLevel int // 0=clear, 1=warning, 2=critical
}

// CountItem is a generic count + label pair.
type CountItem struct {
	Count int
	Label string
}

// PostHit records POST volume to a specific IP+URL combination.
type PostHit struct {
	Count int
	IP    string
	URL   string
}

// ThreatFinding is a single threat assessment result.
type ThreatFinding struct {
	Severity int // 1=warning, 2=critical
	Message  string
}

// NewLogAnalyzer creates an analyzer for the given domains glob.
func NewLogAnalyzer(domainsGlob string) *LogAnalyzer {
	return &LogAnalyzer{
		domainsGlob:   domainsGlob,
		linesToScan:   defaultAnalyzeLines,
		interval:      defaultAnalyzeInterval,
		prevUniqueIPs: make(map[string]int),
	}
}

// MaybeAnalyze triggers a background analysis if the interval has
// elapsed.  Call every tick; it self-throttles.
func (la *LogAnalyzer) MaybeAnalyze() {
	la.mu.Lock()
	if la.running || time.Since(la.lastRun) < la.interval {
		la.mu.Unlock()
		return
	}
	la.running = true
	la.mu.Unlock()

	go la.analyze()
}

// ForceAnalyze triggers an immediate analysis (bound to the 'r' key).
func (la *LogAnalyzer) ForceAnalyze() {
	la.mu.Lock()
	if la.running {
		la.mu.Unlock()
		return
	}
	la.running = true
	la.mu.Unlock()

	go la.analyze()
}

// IsRunning returns true while an analysis is in progress.
func (la *LogAnalyzer) IsRunning() bool {
	la.mu.Lock()
	defer la.mu.Unlock()
	return la.running
}

// Results returns the latest analysis results and metadata.
func (la *LogAnalyzer) Results() ([]DomainAnalysis, time.Time, time.Duration) {
	la.mu.Lock()
	defer la.mu.Unlock()
	return la.results, la.lastRun, la.runDuration
}

// NextRunIn returns the time until the next scheduled analysis.
func (la *LogAnalyzer) NextRunIn() time.Duration {
	la.mu.Lock()
	defer la.mu.Unlock()
	if la.lastRun.IsZero() {
		return 0
	}
	remaining := la.interval - time.Since(la.lastRun)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ── Core analysis ───────────────────────────────────────────────────

// analyzeTarget pairs a domain label with the access-log file to read
// for it. Built differently depending on server layout (see below).
type analyzeTarget struct {
	domain  string
	logFile string
}

func (la *LogAnalyzer) analyze() {
	start := time.Now()

	targets, err := la.resolveTargets()
	if err != nil {
		la.finish(nil, start)
		return
	}

	var results []DomainAnalysis

	for _, t := range targets {
		// Read the tail as ONE block.  All line "strings" below are
		// slices into this block — no per-line copies.
		block := readTailBlock(t.logFile)
		if block == "" {
			continue
		}

		da := la.analyzeDomain(t.domain, block)
		results = append(results, da)
		// block + count maps become garbage here; GC reclaims
		// before the next domain is read.
	}

	// Sort: critical first, then warning, then by domain name.
	sort.Slice(results, func(i, j int) bool {
		if results[i].ThreatLevel != results[j].ThreatLevel {
			return results[i].ThreatLevel > results[j].ThreatLevel
		}
		return results[i].Domain < results[j].Domain
	})

	la.finish(results, start)
}

// resolveTargets discovers (domain, access-log-file) pairs according
// to the configured server layout:
//
//   - LEMP: la.domainsGlob matches domain DIRECTORIES; the access log
//     lives at <dir>/log/access.log.
//   - Apache/cPanel: la.domainsGlob matches LOG FILES directly (main.go
//     points it at the same domlogs glob used by the other collectors
//     in this mode). Non-access-log files are skipped. The -ssl_log
//     file is kept as its own target rather than merged into its HTTP
//     counterpart — unlike the accumulating collectors (NginxCollector
//     et al.), this analyzer produces one independent report per file,
//     so merging would mean reading and interleaving two separate
//     4MB tail blocks. It's labeled "domain.com [ssl]" so it isn't
//     mistaken for a duplicate.
func (la *LogAnalyzer) resolveTargets() ([]analyzeTarget, error) {
	matches, err := filepath.Glob(la.domainsGlob)
	if err != nil {
		return nil, err
	}

	var targets []analyzeTarget

	if currentServerMode == ServerApache {
		for _, path := range matches {
			base := filepath.Base(path)
			if isIgnorableApacheLog(base) {
				continue
			}
			fi, err := os.Stat(path)
			if err != nil || fi.IsDir() {
				continue
			}
			domain := base
			if strings.HasSuffix(base, "-ssl_log") {
				domain = strings.TrimSuffix(base, "-ssl_log") + " [ssl]"
			}
			targets = append(targets, analyzeTarget{domain: domain, logFile: path})
		}
		return targets, nil
	}

	for _, dir := range matches {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		targets = append(targets, analyzeTarget{
			domain:  filepath.Base(dir),
			logFile: filepath.Join(dir, "log", "access.log"),
		})
	}
	return targets, nil
}

func (la *LogAnalyzer) finish(results []DomainAnalysis, start time.Time) {
	la.mu.Lock()
	defer la.mu.Unlock()
	if results != nil {
		la.results = results
	}
	la.lastRun = time.Now()
	la.runDuration = time.Since(start)
	la.running = false
}

// analyzeDomain runs all 8 sections of the investigation on one
// domain's log block, iterating line by line with zero copies.
func (la *LogAnalyzer) analyzeDomain(domain string, block string) DomainAnalysis {
	da := DomainAnalysis{
		Domain:     domain,
		AnalyzedAt: time.Now(),
	}

	// Locate the start of the last linesToScan lines (single
	// backward byte scan, no allocation).
	startIdx := lastNLinesStart(block, la.linesToScan)

	minuteCounts := make(map[string]int)
	ipCounts := make(map[string]int, 1024)
	methodCounts := make(map[string]int, 8)
	statusCounts := make(map[string]int, 16)
	urlCounts := make(map[string]int, 1024)
	refCounts := make(map[string]int, 256)
	postCounts := make(map[string]*PostHit, 256) // key: ip+"\x00"+url
	blankUA := 0
	wpAttacks := 0
	badCodes := 0
	lineCount := 0

	// Iterate lines by slicing the block — no scanner, no copies.
	for pos := startIdx; pos < len(block); {
		nl := strings.IndexByte(block[pos:], '\n')
		var line string
		if nl < 0 {
			line = block[pos:]
			pos = len(block)
		} else {
			line = block[pos : pos+nl]
			pos += nl + 1
		}
		if line == "" {
			continue
		}
		lineCount++

		// ── Single-pass parse (no strings.Fields anywhere) ──
		p := parseAccessLine(line)

		if p.ip != "" {
			ipCounts[p.ip]++
		}
		if p.minute != "" {
			minuteCounts[p.minute]++
		}
		if p.method != "" {
			methodCounts[p.method]++
			// Track POST volume per IP+URL to surface brute-force /
			// spam targets.  Key joins ip and url with a NUL byte.
			if p.method == "POST" && p.ip != "" && p.url != "" {
				key := p.ip + "\x00" + p.url
				if h, ok := postCounts[key]; ok {
					h.Count++
				} else {
					postCounts[key] = &PostHit{Count: 1, IP: p.ip, URL: p.url}
				}
			}
		}
		if p.url != "" {
			urlCounts[p.url]++
			// Brute force endpoints — check the URL, not the whole line.
			if strings.Contains(p.url, "wp-login.php") || strings.Contains(p.url, "xmlrpc.php") {
				wpAttacks++
			}
		}
		if p.status != "" {
			statusCounts[p.status]++
			if p.status[0] == '4' || p.status[0] == '5' {
				badCodes++
			}
		}
		if p.ref != "" && p.ref != "-" {
			refCounts[p.ref]++
		}
		if p.ua == "" || p.ua == "-" {
			blankUA++
		}
	}

	da.LinesRead = lineCount

	// topCounts CLONES the kept labels so the 4MB block is not
	// pinned in memory after this function returns.
	da.TopMinutes = topCounts(minuteCounts, 3)
	da.TopIPs = topCounts(ipCounts, 5)
	da.Methods = topCounts(methodCounts, 10)
	da.StatusCodes = topCounts(statusCounts, 10)
	da.TopURLs = topCounts(urlCounts, 5)
	da.TopReferrers = topCounts(refCounts, 3)
	da.BlankUACount = blankUA

	// ── POST hot spots ──
	// Flatten the IP+URL map, sort by volume, keep top 5.  Labels
	// are cloned so they don't pin the 4MB block.
	posts := make([]PostHit, 0, len(postCounts))
	for _, h := range postCounts {
		da.PostTotal += h.Count
		posts = append(posts, PostHit{
			Count: h.Count,
			IP:    strings.Clone(h.IP),
			URL:   strings.Clone(h.URL),
		})
	}
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Count > posts[j].Count
	})
	if len(posts) > 5 {
		posts = posts[:5]
	}
	da.TopPosts = posts

	// ── Unique IP delta tracking ──
	da.UniqueIPs = len(ipCounts)
	la.mu.Lock()
	if prev, ok := la.prevUniqueIPs[domain]; ok {
		da.UniqueIPDelta = da.UniqueIPs - prev
		da.HasPrevRun = true
	}
	la.prevUniqueIPs[domain] = da.UniqueIPs
	la.mu.Unlock()

	// ── [8] Threat assessment (same thresholds as bash script) ──
	if wpAttacks > 200 {
		da.Threats = append(da.Threats, ThreatFinding{
			Severity: 2,
			Message:  fmt.Sprintf("%d brute force attempts on login/XML-RPC endpoints", wpAttacks),
		})
	}

	if lineCount > 0 && badCodes > lineCount/4 {
		da.Threats = append(da.Threats, ThreatFinding{
			Severity: 1,
			Message:  fmt.Sprintf("over 25%% of requests (%d) are 4xx/5xx — likely bot scanner", badCodes),
		})
	}

	if len(da.TopIPs) > 0 && lineCount > 0 {
		top := da.TopIPs[0]
		if top.Count > lineCount*4/10 {
			da.Threats = append(da.Threats, ThreatFinding{
				Severity: 2,
				Message: fmt.Sprintf("IP %s dominates traffic: %d hits (%d%% of sample)",
					top.Label, top.Count, top.Count*100/lineCount),
			})
		}
	}

	// Rapid influx of new IPs (botnet indicator) — new check vs bash.
	if da.HasPrevRun && da.UniqueIPDelta > 500 {
		da.Threats = append(da.Threats, ThreatFinding{
			Severity: 1,
			Message: fmt.Sprintf("unique IP count jumped by %d since last scan — possible distributed attack",
				da.UniqueIPDelta),
		})
	}

	// Concentrated POST flood from a single IP to one endpoint —
	// the classic brute-force / form-spam signature.
	if len(da.TopPosts) > 0 {
		worst := da.TopPosts[0]
		if worst.Count > 100 {
			da.Threats = append(da.Threats, ThreatFinding{
				Severity: 2,
				Message: fmt.Sprintf("IP %s sent %d POSTs to %s — brute force / spam",
					worst.IP, worst.Count, truncForThreat(worst.URL)),
			})
		} else if worst.Count > 30 {
			da.Threats = append(da.Threats, ThreatFinding{
				Severity: 1,
				Message: fmt.Sprintf("IP %s sent %d POSTs to %s",
					worst.IP, worst.Count, truncForThreat(worst.URL)),
			})
		}
	}

	for _, t := range da.Threats {
		if t.Severity > da.ThreatLevel {
			da.ThreatLevel = t.Severity
		}
	}

	return da
}

// truncForThreat shortens a URL for threat messages.
func truncForThreat(url string) string {
	if len(url) <= 40 {
		return url
	}
	return url[:39] + "…"
}

// ── Single-pass line parser ─────────────────────────────────────────

// parsedLine holds the fields extracted from one access log line.
// All fields are slices into the original block — zero copies.
type parsedLine struct {
	ip     string
	minute string // "HH:MM"
	method string
	url    string
	status string
	ref    string
	ua     string
}

// parseAccessLine extracts all needed fields in a single left-to-right
// scan.  Combined log format:
//
//	IP - - [10/Jun/2026:14:23:45 +0000] "GET /path HTTP/1.1" 200 1234 "ref" "ua"
//
// No strings.Fields, no strings.Split — only IndexByte and slicing.
func parseAccessLine(line string) parsedLine {
	var p parsedLine

	// ── IP: everything up to the first space ──
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return p
	}
	p.ip = line[:sp]

	// ── Timestamp minute: between '[' and ']', take HH:MM ──
	lb := strings.IndexByte(line, '[')
	if lb < 0 {
		return p
	}
	rest := line[lb+1:]
	rb := strings.IndexByte(rest, ']')
	if rb < 0 {
		return p
	}
	ts := rest[:rb]
	// ts = "10/Jun/2026:14:23:45 +0000" — minute is between the
	// 1st and 3rd colons.
	c1 := strings.IndexByte(ts, ':')
	if c1 >= 0 {
		c2 := strings.IndexByte(ts[c1+1:], ':')
		if c2 >= 0 {
			c3 := strings.IndexByte(ts[c1+1+c2+1:], ':')
			if c3 >= 0 {
				p.minute = ts[c1+1 : c1+1+c2+1+c3] // "HH:MM"
			}
		}
	}

	// ── Quoted fields: request, referrer, user-agent ──
	// Scan for quote pairs once; remember up to 3 quoted spans.
	after := line[lb+rb+2:] // everything after the ']'
	var spans [3]string
	nSpans := 0
	for i := 0; i < len(after) && nSpans < 3; {
		q1 := strings.IndexByte(after[i:], '"')
		if q1 < 0 {
			break
		}
		q1 += i
		q2 := strings.IndexByte(after[q1+1:], '"')
		if q2 < 0 {
			break
		}
		q2 += q1 + 1
		spans[nSpans] = after[q1+1 : q2]
		nSpans++

		// ── Status code: the token right after the request's
		//    closing quote (only after the first span) ──
		if nSpans == 1 {
			tail := after[q2+1:]
			j := 0
			for j < len(tail) && tail[j] == ' ' {
				j++
			}
			k := j
			for k < len(tail) && tail[k] != ' ' {
				k++
			}
			st := tail[j:k]
			if len(st) == 3 && st[0] >= '1' && st[0] <= '5' && isDigits(st) {
				p.status = st
			}
		}

		i = q2 + 1
	}

	// spans[0] = "GET /path HTTP/1.1"
	if nSpans >= 1 {
		req := spans[0]
		m := strings.IndexByte(req, ' ')
		if m > 0 {
			method := req[:m]
			if isUpperAlpha(method) {
				p.method = method
			}
			urlEnd := strings.IndexByte(req[m+1:], ' ')
			if urlEnd > 0 {
				p.url = req[m+1 : m+1+urlEnd]
			} else {
				p.url = req[m+1:]
			}
		}
	}
	if nSpans >= 2 {
		p.ref = spans[1]
	}
	if nSpans >= 3 {
		p.ua = spans[2]
	}

	return p
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isUpperAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return len(s) > 0
}

// topCounts converts a count map to a sorted slice, keeping top N.
// Labels are CLONED so they don't pin the parent log block in memory.
func topCounts(m map[string]int, n int) []CountItem {
	items := make([]CountItem, 0, len(m))
	for label, count := range m {
		items = append(items, CountItem{Count: count, Label: label})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Label < items[j].Label
	})
	if len(items) > n {
		items = items[:n]
	}
	// Clone the survivors — without this, each kept label keeps the
	// entire 4MB block alive via its backing array.
	for i := range items {
		items[i].Label = strings.Clone(items[i].Label)
	}
	return items
}

// ── Block reading ───────────────────────────────────────────────────

// readTailBlock reads the last ≤maxTailBytes of a file as a single
// string.  One allocation for the whole block; every line is later
// produced by slicing it.
func readTailBlock(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return ""
	}

	var offset int64
	if fi.Size() > maxTailBytes {
		offset = fi.Size() - maxTailBytes
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}

	data, err := io.ReadAll(f)
	if err != nil || len(data) == 0 {
		return ""
	}

	block := string(data)

	// If we seeked mid-file, drop the first (partial) line.
	if offset > 0 {
		if nl := strings.IndexByte(block, '\n'); nl >= 0 {
			block = block[nl+1:]
		}
	}
	return block
}

// lastNLinesStart returns the index in block where the last n lines
// begin.  Single backward byte scan, no allocations.
func lastNLinesStart(block string, n int) int {
	idx := len(block)
	// Ignore a trailing newline so it doesn't count as a line.
	if idx > 0 && block[idx-1] == '\n' {
		idx--
	}
	count := 0
	for count < n {
		j := strings.LastIndexByte(block[:idx], '\n')
		if j < 0 {
			return 0
		}
		idx = j
		count++
	}
	return idx + 1
}