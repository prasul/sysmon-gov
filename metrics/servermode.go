package metrics

import "strings"

// ========================================================================
//  SERVER MODE
// ========================================================================
//
// sysmon was originally built for LEMP hosts, where nginx keeps one
// directory per domain:
//
//	/home/nginx/domains/example.com/log/access.log
//	/home/nginx/domains/example.com/log/error.log
//
// cPanel/WHM boxes running Apache use a completely different, FLAT
// layout — every domain's access log lives directly in one shared
// directory, with the domain encoded in the filename instead of a
// parent directory:
//
//	/usr/local/apache/logs/domlogs/example.com
//	/usr/local/apache/logs/domlogs/example.com-ssl_log   (HTTPS vhost)
//	/usr/local/apache/logs/domlogs/example.com-bytes_log (NOT an access log)
//	/usr/local/apache/logs/domlogs/example.com-ftp_log   (NOT an access log)
//
// ServerMode lets the same collectors (NginxCollector, LogReader,
// BotCollector, WPLoginCollector, LiveTailer, LogAnalyzer) work against
// either layout by changing how a log path resolves to (a) a domain
// name and (b) whether it's a real Combined-Log-Format access log at
// all.

// ServerMode selects the on-disk convention used to discover and label
// per-domain access logs.
type ServerMode int

const (
	// ServerLEMP is the original nginx layout: one directory per domain,
	// domain name taken from the path segment after "domains".
	ServerLEMP ServerMode = iota

	// ServerApache is the cPanel/WHM layout: a flat domlogs directory,
	// domain name taken from the filename.
	ServerApache
)

var currentServerMode = ServerLEMP

// SetServerMode configures how domains are discovered/extracted from
// log paths for the remainder of the process's lifetime. Call once at
// startup, before any collector's first Collect(). Accepts "lemp"
// (default) or "apache"/"cpanel" (case-insensitive); anything else
// falls back to LEMP.
func SetServerMode(mode string) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "apache", "cpanel":
		currentServerMode = ServerApache
	default:
		currentServerMode = ServerLEMP
	}
}

// IsApacheMode reports whether sysmon is currently configured for the
// cPanel/Apache flat domlogs layout. Exported so main.go can adjust
// default flag values without duplicating the mode string parsing.
func IsApacheMode() bool {
	return currentServerMode == ServerApache
}

// isIgnorableApacheLog reports whether a file in a cPanel domlogs
// directory is NOT a Combined-Log-Format access log. cPanel drops
// several other file types in the same directory:
//
//   - "*-bytes_log" — just a running byte counter, one number per line
//   - "*-ftp_log"   — FTP transfer log, different format entirely
//   - "*.gz"         — rotated/compressed archives
//   - anything containing ".offset" — cPanel's own tail-offset bookkeeping
//
// Parsing any of these as if they were access logs would misread $1
// (the "IP" field) and corrupt aggregation — this is what silently
// happened before this file existed.
func isIgnorableApacheLog(base string) bool {
	switch {
	case strings.HasSuffix(base, "-bytes_log"),
		strings.HasSuffix(base, "-ftp_log"),
		strings.HasSuffix(base, ".gz"),
		strings.Contains(base, ".offset"):
		return true
	}
	return false
}
