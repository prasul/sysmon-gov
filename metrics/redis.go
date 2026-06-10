package metrics

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ========================================================================
//  REDIS COLLECTOR
// ========================================================================
//
// Two collection modes:
//   1. CollectInfo()  — runs every dashboard tick (2s).  Executes
//      "redis-cli INFO memory" and "redis-cli INFO keyspace" which
//      return instantly.
//   2. CollectKeys()  — runs every 60 seconds (or on demand).
//      Samples N keys, measures their memory, groups by prefix/type.
//      This is the expensive operation from the original bash script.

// RedisCollector gathers Redis statistics.
type RedisCollector struct {
	mu sync.Mutex

	host string
	port string

	// Fast stats (from INFO, updated every tick).
	Info RedisInfo

	// Expensive stats (from key scan, updated periodically).
	KeyStats      RedisKeyStats
	lastKeyScan   time.Time
	keyScanEvery  time.Duration
	keySampleSize int
	keyScanning   bool // true while a scan goroutine is running

	// Set to true once the first INFO succeeds.
	available bool
	lastError string
}

// RedisInfo holds the parsed output from INFO memory + INFO keyspace.
type RedisInfo struct {
	// Memory
	UsedMemory         int64   // bytes
	UsedMemoryHuman    string  // e.g. "128.50M"
	UsedMemoryPeak     int64
	UsedMemoryPeakHuman string
	UsedMemoryRSS      int64
	UsedMemoryRSSHuman  string
	MaxMemory          int64
	MaxMemoryHuman     string
	MaxMemoryPolicy    string
	FragRatio          float64

	// Stats
	ConnectedClients int
	BlockedClients   int
	HitRate          float64 // keyspace_hits / (hits + misses)

	// Keyspace
	Databases []RedisDB
	TotalKeys int64
}

// RedisDB holds per-database key counts.
type RedisDB struct {
	DB      string // "db0", "db1", etc.
	Keys    int64
	Expires int64
	AvgTTL  int64 // milliseconds
}

// RedisKeyStats holds the results of the expensive key scan.
type RedisKeyStats struct {
	SampleSize   int
	Scanned      int
	TopKeys      []RedisKeyInfo
	ByPrefix     []RedisPrefixStats
	ByType       []RedisTypeStats
	NoTTLKeys    []RedisKeyInfo
	ScanDuration time.Duration
}

// RedisKeyInfo holds info about a single key.
type RedisKeyInfo struct {
	Key    string
	Size   int64  // bytes from MEMORY USAGE
	TTL    int64  // seconds, -1 = no expiry, -2 = not found
	Type   string // string, list, set, zset, hash, stream
	Prefix string // first segment before ':'
}

// RedisPrefixStats holds aggregated memory by key prefix.
type RedisPrefixStats struct {
	Prefix   string
	TotalMem int64
	Count    int
}

// RedisTypeStats holds aggregated memory by key type.
type RedisTypeStats struct {
	Type     string
	TotalMem int64
	Count    int
}

// NewRedisCollector creates a Redis collector.
func NewRedisCollector(host, port string) *RedisCollector {
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "6379"
	}
	return &RedisCollector{
		host:          host,
		port:          port,
		keyScanEvery:  60 * time.Second,
		keySampleSize: 1000, // lower than bash script for dashboard use
	}
}

// IsAvailable returns true if Redis is reachable.
func (r *RedisCollector) IsAvailable() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.available
}

// LastError returns the last connection error message.
func (r *RedisCollector) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastError
}

// ========================================================================
//  FAST COLLECTION (every tick)
// ========================================================================

// CollectInfo runs "redis-cli INFO" and parses memory + keyspace stats.
// This is fast (~1ms) and safe to call every 2 seconds.
func (r *RedisCollector) CollectInfo() {
	// INFO memory
	memOut, err := r.redisCLI("INFO", "memory")
	if err != nil {
		r.mu.Lock()
		r.available = false
		r.lastError = err.Error()
		r.mu.Unlock()
		return
	}

	// INFO keyspace
	ksOut, _ := r.redisCLI("INFO", "keyspace")

	// INFO stats (for hit rate)
	statsOut, _ := r.redisCLI("INFO", "stats")

	// INFO clients
	clientsOut, _ := r.redisCLI("INFO", "clients")

	r.mu.Lock()
	defer r.mu.Unlock()

	r.available = true
	r.lastError = ""
	r.parseInfoMemory(memOut)
	r.parseInfoKeyspace(ksOut)
	r.parseInfoStats(statsOut)
	r.parseInfoClients(clientsOut)
}

// GetInfo returns a snapshot of the current Redis info.
func (r *RedisCollector) GetInfo() RedisInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Info
}

// ========================================================================
//  EXPENSIVE COLLECTION (periodic key scan)
// ========================================================================

// MaybeCollectKeys runs the key scan if enough time has elapsed.
// The scan runs in a background goroutine so it doesn't block the
// dashboard refresh.  Call this every tick; it self-throttles.
func (r *RedisCollector) MaybeCollectKeys() {
	r.mu.Lock()
	if r.keyScanning || time.Since(r.lastKeyScan) < r.keyScanEvery || !r.available {
		r.mu.Unlock()
		return
	}
	r.keyScanning = true
	r.mu.Unlock()

	go func() {
		stats := r.scanKeys()
		r.mu.Lock()
		r.KeyStats = stats
		r.lastKeyScan = time.Now()
		r.keyScanning = false
		r.mu.Unlock()
	}()
}

// ForceCollectKeys triggers an immediate key scan regardless of timer.
func (r *RedisCollector) ForceCollectKeys() {
	r.mu.Lock()
	if r.keyScanning {
		r.mu.Unlock()
		return
	}
	r.keyScanning = true
	r.mu.Unlock()

	go func() {
		stats := r.scanKeys()
		r.mu.Lock()
		r.KeyStats = stats
		r.lastKeyScan = time.Now()
		r.keyScanning = false
		r.mu.Unlock()
	}()
}

// IsScanning returns true if a key scan is currently in progress.
func (r *RedisCollector) IsScanning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keyScanning
}

// GetKeyStats returns a snapshot of the last key scan results.
func (r *RedisCollector) GetKeyStats() RedisKeyStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.KeyStats
}

// scanKeys performs the expensive key sampling.
func (r *RedisCollector) scanKeys() RedisKeyStats {
	start := time.Now()
	stats := RedisKeyStats{SampleSize: r.keySampleSize}

	// SCAN for keys (non-blocking scan, not KEYS *).
	scanOut, err := r.redisCLI("--scan")
	if err != nil {
		return stats
	}

	allKeys := strings.Split(strings.TrimSpace(scanOut), "\n")
	if len(allKeys) == 0 {
		return stats
	}

	// Sample: take up to keySampleSize keys evenly distributed.
	sampleKeys := sampleSlice(allKeys, r.keySampleSize)

	var keys []RedisKeyInfo

	for _, key := range sampleKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		// MEMORY USAGE <key>
		sizeStr, err := r.redisCLI("MEMORY", "USAGE", key)
		if err != nil {
			continue
		}
		sizeStr = strings.TrimSpace(sizeStr)
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			continue
		}

		// TTL <key>
		ttlStr, _ := r.redisCLI("TTL", key)
		ttl, _ := strconv.ParseInt(strings.TrimSpace(ttlStr), 10, 64)

		// TYPE <key>
		typeStr, _ := r.redisCLI("TYPE", key)
		typeStr = strings.TrimSpace(typeStr)

		// Extract prefix (first segment before ':')
		prefix := key
		if idx := strings.IndexByte(key, ':'); idx > 0 {
			prefix = key[:idx]
		}

		keys = append(keys, RedisKeyInfo{
			Key:    key,
			Size:   size,
			TTL:    ttl,
			Type:   typeStr,
			Prefix: prefix,
		})
		stats.Scanned++
	}

	// Top keys by size.
	sort.Slice(keys, func(i, j int) bool { return keys[i].Size > keys[j].Size })
	if len(keys) > 50 {
		stats.TopKeys = keys[:50]
	} else {
		stats.TopKeys = keys
	}

	// Group by prefix.
	prefixMap := make(map[string]*RedisPrefixStats)
	for _, k := range keys {
		if ps, ok := prefixMap[k.Prefix]; ok {
			ps.TotalMem += k.Size
			ps.Count++
		} else {
			prefixMap[k.Prefix] = &RedisPrefixStats{
				Prefix:   k.Prefix,
				TotalMem: k.Size,
				Count:    1,
			}
		}
	}
	for _, ps := range prefixMap {
		stats.ByPrefix = append(stats.ByPrefix, *ps)
	}
	sort.Slice(stats.ByPrefix, func(i, j int) bool {
		return stats.ByPrefix[i].TotalMem > stats.ByPrefix[j].TotalMem
	})

	// Group by type.
	typeMap := make(map[string]*RedisTypeStats)
	for _, k := range keys {
		if ts, ok := typeMap[k.Type]; ok {
			ts.TotalMem += k.Size
			ts.Count++
		} else {
			typeMap[k.Type] = &RedisTypeStats{
				Type:     k.Type,
				TotalMem: k.Size,
				Count:    1,
			}
		}
	}
	for _, ts := range typeMap {
		stats.ByType = append(stats.ByType, *ts)
	}
	sort.Slice(stats.ByType, func(i, j int) bool {
		return stats.ByType[i].TotalMem > stats.ByType[j].TotalMem
	})

	// Large keys without TTL.
	var noTTL []RedisKeyInfo
	for _, k := range keys {
		if k.TTL == -1 {
			noTTL = append(noTTL, k)
		}
	}
	sort.Slice(noTTL, func(i, j int) bool { return noTTL[i].Size > noTTL[j].Size })
	if len(noTTL) > 20 {
		stats.NoTTLKeys = noTTL[:20]
	} else {
		stats.NoTTLKeys = noTTL
	}

	stats.ScanDuration = time.Since(start)
	return stats
}

// ========================================================================
//  HELPERS
// ========================================================================

// redisCLI runs redis-cli with the configured host/port and returns stdout.
func (r *RedisCollector) redisCLI(args ...string) (string, error) {
	fullArgs := []string{"-h", r.host, "-p", r.port}
	fullArgs = append(fullArgs, args...)
	cmd := exec.Command("redis-cli", fullArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("redis-cli %s: %w", strings.Join(args, " "), err)
	}
	result := strings.TrimSpace(string(out))
	// redis-cli returns errors as strings starting with "ERR" or "NOAUTH"
	if strings.HasPrefix(result, "ERR") || strings.HasPrefix(result, "NOAUTH") {
		return result, fmt.Errorf("redis: %s", result)
	}
	return result, nil
}

func (r *RedisCollector) parseInfoMemory(data string) {
	m := parseInfoFields(data)
	r.Info.UsedMemory, _ = strconv.ParseInt(m["used_memory"], 10, 64)
	r.Info.UsedMemoryHuman = m["used_memory_human"]
	r.Info.UsedMemoryPeak, _ = strconv.ParseInt(m["used_memory_peak"], 10, 64)
	r.Info.UsedMemoryPeakHuman = m["used_memory_peak_human"]
	r.Info.UsedMemoryRSS, _ = strconv.ParseInt(m["used_memory_rss"], 10, 64)
	r.Info.UsedMemoryRSSHuman = m["used_memory_rss_human"]
	r.Info.MaxMemory, _ = strconv.ParseInt(m["maxmemory"], 10, 64)
	r.Info.MaxMemoryHuman = m["maxmemory_human"]
	r.Info.MaxMemoryPolicy = m["maxmemory_policy"]
	r.Info.FragRatio, _ = strconv.ParseFloat(m["mem_fragmentation_ratio"], 64)
}

func (r *RedisCollector) parseInfoKeyspace(data string) {
	r.Info.Databases = nil
	r.Info.TotalKeys = 0

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "db") {
			continue
		}
		// Format: db0:keys=15234,expires=12100,avg_ttl=45000
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		db := RedisDB{DB: parts[0]}
		for _, field := range strings.Split(parts[1], ",") {
			kv := strings.SplitN(field, "=", 2)
			if len(kv) != 2 {
				continue
			}
			val, _ := strconv.ParseInt(kv[1], 10, 64)
			switch kv[0] {
			case "keys":
				db.Keys = val
			case "expires":
				db.Expires = val
			case "avg_ttl":
				db.AvgTTL = val
			}
		}
		r.Info.TotalKeys += db.Keys
		r.Info.Databases = append(r.Info.Databases, db)
	}
}

func (r *RedisCollector) parseInfoStats(data string) {
	m := parseInfoFields(data)
	hits, _ := strconv.ParseFloat(m["keyspace_hits"], 64)
	misses, _ := strconv.ParseFloat(m["keyspace_misses"], 64)
	if hits+misses > 0 {
		r.Info.HitRate = hits / (hits + misses) * 100.0
	}
}

func (r *RedisCollector) parseInfoClients(data string) {
	m := parseInfoFields(data)
	r.Info.ConnectedClients, _ = strconv.Atoi(m["connected_clients"])
	r.Info.BlockedClients, _ = strconv.Atoi(m["blocked_clients"])
}

// parseInfoFields parses redis INFO output into a key→value map.
// INFO format: "key:value\r\n", with section headers starting with '#'.
func parseInfoFields(data string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

// sampleSlice returns up to n items evenly distributed from the input.
func sampleSlice(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	step := float64(len(items)) / float64(n)
	result := make([]string, 0, n)
	for i := 0; i < n; i++ {
		idx := int(float64(i) * step)
		if idx < len(items) {
			result = append(result, items[idx])
		}
	}
	return result
}

// FormatBytes formats bytes into a human-readable string.
func FormatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
