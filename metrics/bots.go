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

// BotHit represents aggregate traffic from a single identified bot
// on one domain.
type BotHit struct {
	Count    int
	BotName  string // human-friendly label, e.g. "GPTBot"
	BotType  string // category: "ai", "search", "social", "other"
	Domain   string
	TopPath  string // most-requested path by this bot+domain
}

// ── Known bot signatures ────────────────────────────────────────────
// Each entry maps a substring found in the User-Agent to a
// human-friendly name and a category for color-coding.

type botSignature struct {
	substr  string // substring to search for in UA
	name    string // display name
	botType string // "ai", "search", "social", "monitor", "other"
}

var knownBots = []botSignature{
	// AI crawlers
	{substr: "GPTBot", name: "GPTBot", botType: "ai"},
	{substr: "ChatGPT-User", name: "ChatGPT", botType: "ai"},
	{substr: "Claude-SearchBot", name: "ClaudeBot", botType: "ai"},
	{substr: "ClaudeBot", name: "ClaudeBot", botType: "ai"},
	{substr: "anthropic-ai", name: "Anthropic", botType: "ai"},
	{substr: "Amazonbot", name: "Amazonbot", botType: "ai"},
	{substr: "Bytespider", name: "Bytespider", botType: "ai"},
	{substr: "CCBot", name: "CCBot", botType: "ai"},
	{substr: "cohere-ai", name: "Cohere", botType: "ai"},
	{substr: "PerplexityBot", name: "Perplexity", botType: "ai"},
	{substr: "YouBot", name: "YouBot", botType: "ai"},
	{substr: "Diffbot", name: "Diffbot", botType: "ai"},
	{substr: "ImagesiftBot", name: "ImagesiftBot", botType: "ai"},
	{substr: "Applebot", name: "Applebot", botType: "ai"},

	// Search engine crawlers
	{substr: "Googlebot", name: "Googlebot", botType: "search"},
	{substr: "bingbot", name: "Bingbot", botType: "search"},
	{substr: "YandexBot", name: "YandexBot", botType: "search"},
	{substr: "Baiduspider", name: "Baidu", botType: "search"},
	{substr: "DuckDuckBot", name: "DuckDuckBot", botType: "search"},
	{substr: "Sogou", name: "Sogou", botType: "search"},
	{substr: "SemrushBot", name: "SemrushBot", botType: "search"},
	{substr: "AhrefsBot", name: "AhrefsBot", botType: "search"},
	{substr: "MJ12bot", name: "MajesticBot", botType: "search"},
	{substr: "DotBot", name: "DotBot", botType: "search"},
	{substr: "PetalBot", name: "PetalBot", botType: "search"},

	// Social media
	{substr: "meta-externalagent", name: "Meta", botType: "social"},
	{substr: "facebookexternalhit", name: "Facebook", botType: "social"},
	{substr: "Twitterbot", name: "Twitter/X", botType: "social"},
	{substr: "LinkedInBot", name: "LinkedIn", botType: "social"},
	{substr: "Pinterest", name: "Pinterest", botType: "social"},
	{substr: "Slackbot", name: "Slackbot", botType: "social"},
	{substr: "TelegramBot", name: "Telegram", botType: "social"},
	{substr: "Discordbot", name: "Discord", botType: "social"},
	{substr: "WhatsApp", name: "WhatsApp", botType: "social"},

	// Monitoring / infra
	{substr: "UptimeRobot", name: "UptimeRobot", botType: "monitor"},
	{substr: "StatusCake", name: "StatusCake", botType: "monitor"},
	{substr: "Pingdom", name: "Pingdom", botType: "monitor"},
	{substr: "Site24x7", name: "Site24x7", botType: "monitor"},
}

// ── Collector ───────────────────────────────────────────────────────

// BotCollector classifies nginx access log traffic by bot identity.
type BotCollector struct {
	mu sync.Mutex

	logGlob string
	offsets map[string]int64

	// botDomainHits: "botName\x00domain" → count
	botDomainHits map[string]*botAccum
}

type botAccum struct {
	count   int
	botName string
	botType string
	domain  string
	// pathCounts tracks path hits for this bot+domain to find the top path.
	pathCounts map[string]int
}

// NewBotCollector creates a collector for bot traffic analysis.
func NewBotCollector(logGlob string) *BotCollector {
	return &BotCollector{
		logGlob:       logGlob,
		offsets:       make(map[string]int64),
		botDomainHits: make(map[string]*botAccum),
	}
}

// Collect reads new log lines and classifies bot traffic.
func (c *BotCollector) Collect() {
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
			botName, botType := classifyBot(line)
			if botName == "" {
				continue // not a bot
			}

			path := extractPathFromLine(line)

			key := botName + "\x00" + domain
			if h, ok := c.botDomainHits[key]; ok {
				h.count++
				h.pathCounts[path]++
			} else {
				c.botDomainHits[key] = &botAccum{
					count:      1,
					botName:    botName,
					botType:    botType,
					domain:     domain,
					pathCounts: map[string]int{path: 1},
				}
			}
		}
	}
}

// TopBots returns the top n bot+domain combinations by hit count.
func (c *BotCollector) TopBots(n int) []BotHit {
	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]BotHit, 0, len(c.botDomainHits))
	for _, h := range c.botDomainHits {
		// Find top path for this bot+domain.
		topPath := ""
		topCount := 0
		for p, cnt := range h.pathCounts {
			if cnt > topCount {
				topPath = p
				topCount = cnt
			}
		}

		all = append(all, BotHit{
			Count:   h.count,
			BotName: h.botName,
			BotType: h.botType,
			Domain:  h.domain,
			TopPath: topPath,
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

// TotalBotHits returns the grand total of identified bot requests.
func (c *BotCollector) TotalBotHits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, h := range c.botDomainHits {
		total += h.count
	}
	return total
}

// ── Internal ────────────────────────────────────────────────────────

func (c *BotCollector) readNewLines(logPath string) []string {
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
	scanner.Buffer(make([]byte, 0, 512*1024), 512*1024)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	c.offsets[logPath] = currentSize
	return lines
}

// classifyBot checks the User-Agent (last quoted field) against
// known bot signatures.  Returns ("", "") for regular browsers.
func classifyBot(line string) (name, botType string) {
	// UA is the last quoted string in CLF.  Find it by scanning
	// from the end — more reliable than counting quote pairs.
	ua := extractLastQuoted(line)
	if ua == "" {
		return "", ""
	}

	for _, sig := range knownBots {
		if strings.Contains(ua, sig.substr) {
			return sig.name, sig.botType
		}
	}
	return "", ""
}

// extractLastQuoted returns the content of the last "…" pair in a line.
func extractLastQuoted(line string) string {
	lastClose := strings.LastIndexByte(line, '"')
	if lastClose <= 0 {
		return ""
	}
	lastOpen := strings.LastIndexByte(line[:lastClose], '"')
	if lastOpen < 0 || lastOpen >= lastClose-1 {
		return ""
	}
	return line[lastOpen+1 : lastClose]
}

// extractPathFromLine gets the request path from a CLF log line
// (between the first quote pair), stripped of query strings.
func extractPathFromLine(line string) string {
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return "/"
	}
	rest := line[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return "/"
	}
	parts := strings.Fields(rest[:q2])
	if len(parts) < 2 {
		return "/"
	}
	path := parts[1]
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	return path
}
