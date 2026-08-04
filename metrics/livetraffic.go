package metrics

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// ========================================================================
//  LIVE TRAFFIC ANALYZER
// ========================================================================
//
// Feeds on the same log entries as the live tail, but instead of a
// scrolling list it maintains rolling-window and session aggregates:
//
//   ROLLING (short window, "what's happening now"):
//     - Flooding IPs      — req/s per IP over the last N seconds, with
//                           % of total load and top target endpoint.
//                           THE panel for the block decision.
//     - Traffic by domain — req/s per domain (which site is hot).
//     - Response codes    — 2xx/3xx/4xx/5xx counts (is it healthy).
//
//   SESSION (since the live view opened, "what's persistent"):
//     - Domain totals     — cumulative requests per domain.
//     - Persistent IPs    — cumulative per IP, with first-seen /
//                           last-seen / active-minutes so a slow
//                           scraper is distinguishable from a burst.
//
// Load-reduction principle: flooding is sorted by RATE (req/s over a
// few seconds), because load is instantaneous — an IP's total count
// doesn't matter, its current velocity does.  The % column tells you
// how much load you'd shed by blocking each IP.

const (
	floodWindow   = 5 * time.Second  // rate window for flooding detection
	domainWindow  = 10 * time.Second // rate window for domain / codes
	sessionIPCap  = 10000            // max session IPs tracked (memory bound)
	activeBucket  = time.Minute      // granularity for "active minutes"
)

// timedHit is one request kept in a rolling ring for windowed rates.
type timedHit struct {
	t      time.Time
	ip     string
	domain string
	path   string
	status string
}

// FloodingIP is one entry in the flooding panel.
type FloodingIP struct {
	IP         string
	RatePerSec float64
	Count      int     // hits in the flood window
	PctOfTotal float64 // share of all traffic in the window
	TopPath    string  // most-hit endpoint by this IP
	Allowlist  string  // allowlist label if listed, else ""
}

// DomainRate is one entry in the traffic-by-domain panel.
type DomainRate struct {
	Domain     string
	RatePerSec float64
	Count      int
}

// CodeCounts holds response-code class counts for a window.
type CodeCounts struct {
	C2xx, C3xx, C4xx, C5xx, Other int
	Total                         int
	RatePerSec                    float64
}

// SessionDomain is cumulative per-domain traffic since session start.
type SessionDomain struct {
	Domain string
	Count  int
}

// SessionIP is cumulative per-IP traffic with persistence tracking.
type SessionIP struct {
	IP           string
	Count        int
	FirstSeen    time.Time
	LastSeen     time.Time
	ActiveMins   int // distinct minute-buckets this IP appeared in
	activeBuckets map[int64]bool
}

// LiveTrafficStats is the full snapshot rendered by the UI.
type LiveTrafficStats struct {
	// Rolling
	Flooding    []FloodingIP
	DomainRates []DomainRate
	Codes       CodeCounts
	TotalRate   float64

	// Session
	SessionDomains []SessionDomain
	PersistentIPs  []SessionIP
	SessionStart   time.Time
	SessionReqs    int
}

// LiveTrafficAnalyzer accumulates rolling + session traffic stats.
type LiveTrafficAnalyzer struct {
	mu sync.Mutex

	// Rolling ring of recent hits (trimmed to the longest window).
	ring []timedHit

	// Session accumulators.
	sessionStart   time.Time
	sessionReqs    int
	sessionDomains map[string]int
	sessionIPs     map[string]*SessionIP

	// Optional allowlist for labeling flooding IPs.
	allowlist *Allowlist
}

// NewLiveTrafficAnalyzer creates the analyzer.  Pass an allowlist (or
// nil) so flooding IPs can be tagged.
func NewLiveTrafficAnalyzer(al *Allowlist) *LiveTrafficAnalyzer {
	return &LiveTrafficAnalyzer{
		sessionStart:   time.Now(),
		sessionDomains: make(map[string]int),
		sessionIPs:     make(map[string]*SessionIP),
		allowlist:      al,
	}
}

// ResetSession zeroes the session accumulators (bound to a key, e.g. R).
func (a *LiveTrafficAnalyzer) ResetSession() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionStart = time.Now()
	a.sessionReqs = 0
	a.sessionDomains = make(map[string]int)
	a.sessionIPs = make(map[string]*SessionIP)
}

// Ingest feeds new log entries into both rolling and session views.
// Call each tick with the entries the live tailer just read.
func (a *LiveTrafficAnalyzer) Ingest(entries []LiveLogEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	for _, e := range entries {
		// Skip error-log lines (no meaningful status/path for rates).
		if e.Source == "error" || e.IP == "" {
			continue
		}

		ts := e.Timestamp
		if ts.IsZero() {
			ts = now
		}

		// ── Rolling ring ──
		a.ring = append(a.ring, timedHit{
			t:      ts,
			ip:     e.IP,
			domain: e.Domain,
			path:   e.Path,
			status: e.Status,
		})

		// ── Session domain ──
		a.sessionReqs++
		a.sessionDomains[e.Domain]++

		// ── Session IP with persistence ──
		si, ok := a.sessionIPs[e.IP]
		if !ok {
			// Evict smallest if at cap.
			if len(a.sessionIPs) >= sessionIPCap {
				a.evictSmallestIP()
			}
			si = &SessionIP{
				IP:            e.IP,
				FirstSeen:     ts,
				activeBuckets: make(map[int64]bool),
			}
			a.sessionIPs[e.IP] = si
		}
		si.Count++
		si.LastSeen = ts
		si.activeBuckets[ts.Unix()/int64(activeBucket.Seconds())] = true
		si.ActiveMins = len(si.activeBuckets)
	}

	// Trim ring to the longest window we care about.
	a.trimRing(now)
}

// trimRing drops hits older than the longest rolling window.
func (a *LiveTrafficAnalyzer) trimRing(now time.Time) {
	cutoff := now.Add(-domainWindow)
	i := 0
	for i < len(a.ring) && a.ring[i].t.Before(cutoff) {
		i++
	}
	if i > 0 {
		a.ring = a.ring[i:]
	}
}

// evictSmallestIP removes the lowest-count session IP to bound memory.
func (a *LiveTrafficAnalyzer) evictSmallestIP() {
	var minKey string
	minCount := int(^uint(0) >> 1)
	for k, v := range a.sessionIPs {
		if v.Count < minCount {
			minCount = v.Count
			minKey = k
		}
	}
	if minKey != "" {
		delete(a.sessionIPs, minKey)
	}
}

// Snapshot computes the current stats for rendering.
func (a *LiveTrafficAnalyzer) Snapshot() LiveTrafficStats {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	stats := LiveTrafficStats{
		SessionStart: a.sessionStart,
		SessionReqs:  a.sessionReqs,
	}

	// ── Flooding (last floodWindow) ──
	floodCut := now.Add(-floodWindow)
	ipCount := make(map[string]int)
	ipPaths := make(map[string]map[string]int)
	floodTotal := 0
	for _, h := range a.ring {
		if h.t.Before(floodCut) {
			continue
		}
		ipCount[h.ip]++
		floodTotal++
		if ipPaths[h.ip] == nil {
			ipPaths[h.ip] = make(map[string]int)
		}
		ipPaths[h.ip][h.path]++
	}

	floodSecs := floodWindow.Seconds()
	for ip, c := range ipCount {
		fi := FloodingIP{
			IP:         ip,
			Count:      c,
			RatePerSec: float64(c) / floodSecs,
		}
		if floodTotal > 0 {
			fi.PctOfTotal = float64(c) / float64(floodTotal) * 100.0
		}
		// Top path for this IP.
		best := 0
		for p, n := range ipPaths[ip] {
			if n > best {
				best = n
				fi.TopPath = p
			}
		}
		// Allowlist tag.
		if a.allowlist != nil {
			if ok, label := a.allowlist.Lookup(ip); ok {
				fi.Allowlist = label
			}
		}
		stats.Flooding = append(stats.Flooding, fi)
	}
	sort.Slice(stats.Flooding, func(i, j int) bool {
		return stats.Flooding[i].Count > stats.Flooding[j].Count
	})
	if len(stats.Flooding) > 8 {
		stats.Flooding = stats.Flooding[:8]
	}
	stats.TotalRate = float64(floodTotal) / floodSecs

	// ── Domain rates + response codes (last domainWindow) ──
	domCut := now.Add(-domainWindow)
	domCount := make(map[string]int)
	var codes CodeCounts
	for _, h := range a.ring {
		if h.t.Before(domCut) {
			continue
		}
		domCount[h.domain]++
		codes.Total++
		switch {
		case strings.HasPrefix(h.status, "2"):
			codes.C2xx++
		case strings.HasPrefix(h.status, "3"):
			codes.C3xx++
		case strings.HasPrefix(h.status, "4"):
			codes.C4xx++
		case strings.HasPrefix(h.status, "5"):
			codes.C5xx++
		default:
			codes.Other++
		}
	}
	domSecs := domainWindow.Seconds()
	for d, c := range domCount {
		stats.DomainRates = append(stats.DomainRates, DomainRate{
			Domain:     d,
			Count:      c,
			RatePerSec: float64(c) / domSecs,
		})
	}
	sort.Slice(stats.DomainRates, func(i, j int) bool {
		return stats.DomainRates[i].Count > stats.DomainRates[j].Count
	})
	if len(stats.DomainRates) > 6 {
		stats.DomainRates = stats.DomainRates[:6]
	}
	codes.RatePerSec = float64(codes.Total) / domSecs
	stats.Codes = codes

	// ── Session domains ──
	for d, c := range a.sessionDomains {
		stats.SessionDomains = append(stats.SessionDomains, SessionDomain{
			Domain: d, Count: c,
		})
	}
	sort.Slice(stats.SessionDomains, func(i, j int) bool {
		return stats.SessionDomains[i].Count > stats.SessionDomains[j].Count
	})
	if len(stats.SessionDomains) > 6 {
		stats.SessionDomains = stats.SessionDomains[:6]
	}

	// ── Persistent IPs (session, sorted by total) ──
	for _, si := range a.sessionIPs {
		stats.PersistentIPs = append(stats.PersistentIPs, *si)
	}
	sort.Slice(stats.PersistentIPs, func(i, j int) bool {
		return stats.PersistentIPs[i].Count > stats.PersistentIPs[j].Count
	})
	if len(stats.PersistentIPs) > 8 {
		stats.PersistentIPs = stats.PersistentIPs[:8]
	}

	return stats
}

// SessionDuration returns how long the session has been running.
func (a *LiveTrafficAnalyzer) SessionDuration() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.sessionStart)
}
