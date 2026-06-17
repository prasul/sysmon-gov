package metrics

import (
	"sort"
	"strings"
)

// ========================================================================
//  ATTACK SIGNATURE DETECTION
// ========================================================================
//
// Ported from NginxHunter (github.com/emrekybs/NginxHunter), adapted to
// run inside the analyzer's existing single-pass parser.  Instead of the
// original's per-pattern `ag` regex passes over the whole file, these are
// cheap substring checks against the already-parsed request URL — they
// add near-zero cost to the existing scan.
//
// Each request is matched against five attack categories.  Only requests
// that returned 200 or 500 are counted as "successful/interesting" (same
// filter NginxHunter uses), since a blocked 403/404 probe is far less
// concerning than one the server actually processed.

// AttackCategory identifies a class of malicious request.
type AttackCategory int

const (
	AttackSQLi AttackCategory = iota
	AttackScanner
	AttackSensitivePath
	AttackExploit
	AttackWebshell
	attackCategoryCount
)

func (c AttackCategory) String() string {
	switch c {
	case AttackSQLi:
		return "SQL Injection"
	case AttackScanner:
		return "Scanner / Hack Tool"
	case AttackSensitivePath:
		return "Sensitive Path Probe"
	case AttackExploit:
		return "Exploit Attempt"
	case AttackWebshell:
		return "Webshell Access"
	}
	return "Unknown"
}

// AttackStats accumulates attack matches for one domain during a scan.
// It lives only for the duration of analyzeDomain — like the count maps.
type AttackStats struct {
	// Per-category total hit count.
	CategoryCounts [attackCategoryCount]int

	// Per-category top offending IPs.
	categoryIPs [attackCategoryCount]map[string]int

	// A few example request URLs per category (for the detail view).
	categorySamples [attackCategoryCount][]AttackSample
}

// AttackSample is one example malicious request.
type AttackSample struct {
	IP     string
	URL    string
	Status string
}

// AttackSummary is the finished, retained result for one category.
type AttackSummary struct {
	Category AttackCategory
	Count    int
	TopIPs   []CountItem
	Samples  []AttackSample
}

const maxAttackSamples = 5

// newAttackStats initializes the per-category maps.
func newAttackStats() *AttackStats {
	as := &AttackStats{}
	for i := range as.categoryIPs {
		as.categoryIPs[i] = make(map[string]int)
	}
	return as
}

// inspect checks one parsed line against all attack signatures.
// Called once per log line inside the existing parse loop.  Only the
// URL (lowercased once) is scanned, so cost is a handful of substring
// checks per line — no regex, no allocation beyond the lowercase.
func (as *AttackStats) inspect(p parsedLine) {
	if p.url == "" {
		return
	}
	// NginxHunter only counts requests the server actually served
	// (200) or errored on (500).  Skip everything else.
	if p.status != "200" && p.status != "500" {
		return
	}

	// Lowercase once for case-insensitive matching.
	lurl := strings.ToLower(p.url)

	if matchSQLi(lurl) {
		as.record(AttackSQLi, p)
	}
	if matchScanner(lurl, p.ua) {
		as.record(AttackScanner, p)
	}
	if matchSensitivePath(lurl) {
		as.record(AttackSensitivePath, p)
	}
	if matchExploit(lurl) {
		as.record(AttackExploit, p)
	}
	if matchWebshell(lurl) {
		as.record(AttackWebshell, p)
	}
}

func (as *AttackStats) record(cat AttackCategory, p parsedLine) {
	as.CategoryCounts[cat]++
	as.categoryIPs[cat][p.ip]++
	if len(as.categorySamples[cat]) < maxAttackSamples {
		as.categorySamples[cat] = append(as.categorySamples[cat], AttackSample{
			IP:     p.ip,
			URL:    p.url,
			Status: p.status,
		})
	}
}

// summarize converts the working stats into retained summaries.
// Labels and URLs are cloned so they don't pin the 4MB log block.
func (as *AttackStats) summarize() []AttackSummary {
	var out []AttackSummary
	for cat := AttackCategory(0); cat < attackCategoryCount; cat++ {
		if as.CategoryCounts[cat] == 0 {
			continue
		}

		// Top IPs for this category.
		ips := make([]CountItem, 0, len(as.categoryIPs[cat]))
		for ip, n := range as.categoryIPs[cat] {
			ips = append(ips, CountItem{Count: n, Label: strings.Clone(ip)})
		}
		sort.Slice(ips, func(i, j int) bool {
			if ips[i].Count != ips[j].Count {
				return ips[i].Count > ips[j].Count
			}
			return ips[i].Label < ips[j].Label
		})
		if len(ips) > 5 {
			ips = ips[:5]
		}

		// Clone sample URLs/IPs so they don't pin the block.
		samples := make([]AttackSample, len(as.categorySamples[cat]))
		for i, s := range as.categorySamples[cat] {
			samples[i] = AttackSample{
				IP:     strings.Clone(s.IP),
				URL:    strings.Clone(s.URL),
				Status: s.Status,
			}
		}

		out = append(out, AttackSummary{
			Category: cat,
			Count:    as.CategoryCounts[cat],
			TopIPs:   ips,
			Samples:  samples,
		})
	}
	return out
}

// ── Signature matchers ──────────────────────────────────────────────
//
// These use containsAny (plain substring scan) rather than regex.
// Tokens are lowercase; the caller lowercases the URL once.  The token
// lists are the high-signal subset of NginxHunter's regexes — the ones
// that rarely appear in legitimate WordPress traffic.

func matchSQLi(lurl string) bool {
	return containsAny(lurl,
		"union select", "union%20select", "%20union%20",
		"information_schema", "table_name", "table_schema",
		"load_file", "benchmark(", "concat(", "concat_ws(",
		"extractvalue", "updatexml", "/**/", "sqlmap",
		"and 1=1", "and%201=1", "and 1=2", "and%201=2",
		"or 1=1", "or%201=1", "xp_cmdshell",
		"0x5f", "0x7e", "0x27", "version(", "database(",
		"%27", "'or'", "'and'",
	)
}

func matchScanner(lurl, ua string) bool {
	if containsAny(lurl,
		"acunetix", "by_wvs", "nikto", "netsparker", "nsfocus",
		"webcruiser", "owasp", "appscan", "w3af", "openvas",
		"jsky", "wwwscan", "wscan", "antsword", "webvulnscan",
		"webinspect", "360webscan", "webscan", "xss@here", "xss%40here",
	) {
		return true
	}
	// User-agent based scanner fingerprints.
	if ua != "" {
		lua := strings.ToLower(ua)
		return containsAny(lua,
			"nikto", "nmap", "nessus", "masscan", "sqlmap",
			"acunetix", "netsparker", "burpsuite", "zap",
			"python-requests", "python-urllib", "ltx71", "winhttprequest",
		)
	}
	return false
}

func matchSensitivePath(lurl string) bool {
	return containsAny(lurl,
		"phpinfo", "info.php", "/web-console", "jmxinvokerservlet",
		"/manager/html", "axis2-admin", "axis2-web", "phpmyadmin",
		"/admin-console", "/jmx-console", "/console/",
		".tar.gz", ".tar", ".tar.xz", ".mdb", ".inc", ".sql",
		"/.config", ".bak", "/.svn/", "/.git/", ".hg",
		".ds_store", ".htaccess", "nginx.conf", ".bash_history",
		"/cvs/", "web.config", "/.env", "wp-config.php.bak",
	)
}

func matchExploit(lurl string) bool {
	return containsAny(lurl,
		"%00", "/win.ini", "/my.ini", "../../", "..%2f..%2f",
		"/etc/shadow", "/etc/passwd", "%0d%0a", "file:/",
		"gopher:/", "dict:/", "windowspowershell", "/wls-wsat/",
		"call_user_func_array", "uddiexplorer", "@default_member_access",
		"@java.lang.runtime", "ognlcontext", "/bin/bash", "cmd.exe",
		"wget ", "wget%20", "curl ", "curl%20", "/think\\",
	)
}

func matchWebshell(lurl string) bool {
	return containsAny(lurl,
		"=whoami", "dbname=", "exec=", "cmd=", "/r57", "/c99",
		"/c100", "/b374k", "adminer.php", "eval(", "assert(",
		"%eval", "%execute", "tunnel.php", "tunnel.asp", "tunnel.jsp",
		"aioshell", "ghost.php", "r00ts", "90sec", "t00ls",
		"editor.aspx", "wso.php", "wso.aspx", "o=vlogin",
	)
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
