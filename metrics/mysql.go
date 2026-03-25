package metrics

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ── Public types ────────────────────────────────────────────────────

// MySQLProcess represents one active query from SHOW PROCESSLIST.
type MySQLProcess struct {
	ID      int64
	User    string
	Host    string
	DB      string
	Command string
	TimeSec int64
	State   string
	Query   string
}

// MySQLStats holds aggregate connection statistics alongside the
// active query list.
type MySQLStats struct {
	TotalConnections int
	ActiveQueries    int
	QueriesPerSec    float64 // from SHOW GLOBAL STATUS
	SlowQueries      int64
	Uptime           int64 // server uptime in seconds
	ThreadsRunning   int64
	ThreadsConnected int64
	Processes        []MySQLProcess
}

// MyCnfConfig holds credentials parsed from a .my.cnf file.
type MyCnfConfig struct {
	User     string
	Password string
	Host     string
	Port     string
	Socket   string
}

// ── .my.cnf Parser ──────────────────────────────────────────────────

// Common locations for MySQL option files, checked in order.
// The first file found wins — this matches mysql client behavior.
var myCnfPaths = []string{
	"/root/.my.cnf",
	"/root/.mylogin.cnf",
	filepath.Join(os.Getenv("HOME"), ".my.cnf"),
	"/etc/mysql/debian.cnf",
	"/etc/my.cnf",
}

// Common MySQL socket paths across distributions.
var commonSockets = []string{
	"/var/run/mysqld/mysqld.sock",    // Debian/Ubuntu
	"/var/lib/mysql/mysql.sock",      // RHEL/CentOS/Rocky
	"/tmp/mysql.sock",                // macOS / some custom installs
	"/run/mysqld/mysqld.sock",        // Arch / newer systemd
	"/var/run/mysql/mysql.sock",      // older Debian
	"/usr/local/var/mysql/mysql.sock", // Homebrew
}

// ParseMyCnf reads a MySQL option file and returns the [client]
// section credentials.  The format is standard INI:
//
//	[client]
//	user=root
//	password=s3cret
//	socket=/var/run/mysqld/mysqld.sock
//
// Lines with "password" are often quoted — we strip quotes.
// Returns an empty config (not an error) if the file is unreadable.
func ParseMyCnf(path string) MyCnfConfig {
	cfg := MyCnfConfig{}

	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	defer f.Close()

	inClientSection := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines.
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Section headers: [client], [mysqld], etc.
		if line[0] == '[' {
			section := strings.ToLower(strings.Trim(line, "[] "))
			// We want [client] or [mysqladmin] sections — both
			// contain user/password that work for monitoring.
			inClientSection = (section == "client" || section == "mysqladmin")
			continue
		}

		if !inClientSection {
			continue
		}

		// Key=value parsing.  Some files use "key = value" with spaces.
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.TrimSpace(parts[1])

		// Strip surrounding quotes (single or double).
		val = stripQuotes(val)

		switch key {
		case "user":
			cfg.User = val
		case "password":
			cfg.Password = val
		case "host":
			cfg.Host = val
		case "port":
			cfg.Port = val
		case "socket":
			cfg.Socket = val
		}
	}

	return cfg
}

// AutoDetectMyCnf searches common paths for a .my.cnf file and
// returns the parsed credentials from the first one found.
// Returns an empty config if none are found.
func AutoDetectMyCnf() (MyCnfConfig, string) {
	for _, p := range myCnfPaths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			cfg := ParseMyCnf(p)
			// Only return if we got at least a user or password.
			if cfg.User != "" || cfg.Password != "" {
				return cfg, p
			}
		}
	}
	return MyCnfConfig{}, ""
}

// FindMySQLSocket probes common socket locations and returns the
// first one that exists on disk.  Returns "" if none found.
func FindMySQLSocket() string {
	for _, s := range commonSockets {
		if _, err := os.Stat(s); err == nil {
			return s
		}
	}
	return ""
}

// ── Collector ───────────────────────────────────────────────────────

// MySQLCollector monitors live MySQL queries.
type MySQLCollector struct {
	mu  sync.Mutex
	dsn string
	db  *sql.DB

	connected  bool
	lastErr    string
	dsnDisplay string // sanitized DSN for status display (no password)
}

// NewMySQLCollector creates a collector with the given DSN.
// If dsn is empty, MySQL monitoring is disabled.
func NewMySQLCollector(dsn string) *MySQLCollector {
	return &MySQLCollector{
		dsn:        dsn,
		dsnDisplay: sanitizeDSN(dsn),
	}
}

// IsEnabled returns true if a DSN was provided.
func (c *MySQLCollector) IsEnabled() bool {
	return c.dsn != ""
}

// Collect queries MySQL for the current process list and server stats.
func (c *MySQLCollector) Collect() *MySQLStats {
	if c.dsn == "" {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy-open the connection pool on first use.
	if c.db == nil {
		db, err := sql.Open("mysql", c.dsn)
		if err != nil {
			c.connected = false
			c.lastErr = err.Error()
			return nil
		}
		db.SetMaxOpenConns(2)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(5 * time.Minute)
		c.db = db
	}

	// Quick connectivity check — Ping is cheaper than a failed query.
	if err := c.db.Ping(); err != nil {
		c.connected = false
		c.lastErr = err.Error()
		c.db.Close()
		c.db = nil
		return nil
	}

	stats := &MySQLStats{}

	// ── SHOW GLOBAL STATUS for server-wide stats ────────────────
	c.collectGlobalStatus(stats)

	// ── SHOW FULL PROCESSLIST for active queries ────────────────
	c.collectProcessList(stats)

	c.connected = true
	c.lastErr = ""
	return stats
}

// collectGlobalStatus reads key performance counters from MySQL.
func (c *MySQLCollector) collectGlobalStatus(stats *MySQLStats) {
	rows, err := c.db.Query("SHOW GLOBAL STATUS WHERE Variable_name IN ('Queries','Slow_queries','Uptime','Threads_running','Threads_connected')")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			continue
		}
		v, _ := strconv.ParseInt(value, 10, 64)

		switch name {
		case "Queries":
			uptime, _ := strconv.ParseFloat(value, 64)
			// QPS will be computed below after we have Uptime.
			stats.QueriesPerSec = uptime // temporarily store total queries
		case "Slow_queries":
			stats.SlowQueries = v
		case "Uptime":
			stats.Uptime = v
		case "Threads_running":
			stats.ThreadsRunning = v
		case "Threads_connected":
			stats.ThreadsConnected = v
		}
	}

	// Compute QPS: total queries / uptime seconds.
	if stats.Uptime > 0 && stats.QueriesPerSec > 0 {
		stats.QueriesPerSec = stats.QueriesPerSec / float64(stats.Uptime)
	} else {
		stats.QueriesPerSec = 0
	}
}

// collectProcessList reads active queries.
func (c *MySQLCollector) collectProcessList(stats *MySQLStats) {
	rows, err := c.db.Query("SHOW FULL PROCESSLIST")
	if err != nil {
		c.connected = false
		c.lastErr = err.Error()
		c.db.Close()
		c.db = nil
		return
	}
	defer rows.Close()

	for rows.Next() {
		var p MySQLProcess
		var dbVal, stateVal, infoVal sql.NullString
		var timeVal sql.NullInt64

		err := rows.Scan(&p.ID, &p.User, &p.Host, &dbVal, &p.Command, &timeVal, &stateVal, &infoVal)
		if err != nil {
			continue
		}

		p.DB = nullStr(dbVal, "—")
		p.State = nullStr(stateVal, "—")
		p.Query = nullStr(infoVal, "")
		if timeVal.Valid {
			p.TimeSec = timeVal.Int64
		}

		stats.TotalConnections++

		// Skip idle connections and our own query.
		if strings.EqualFold(p.Command, "Sleep") {
			continue
		}
		if strings.EqualFold(p.Command, "Daemon") {
			continue
		}
		if strings.Contains(p.Query, "PROCESSLIST") {
			continue
		}
		if strings.Contains(p.Query, "GLOBAL STATUS") {
			continue
		}

		// Truncate and clean for display.
		if len(p.Query) > 120 {
			p.Query = p.Query[:117] + "…"
		}
		p.Query = collapseWhitespace(p.Query)

		// Shorten host — strip the port portion for readability.
		if idx := strings.LastIndexByte(p.Host, ':'); idx > 0 {
			p.Host = p.Host[:idx]
		}

		stats.Processes = append(stats.Processes, p)
	}

	// Sort by run time descending — slowest queries first.
	sort.Slice(stats.Processes, func(i, j int) bool {
		return stats.Processes[i].TimeSec > stats.Processes[j].TimeSec
	})

	stats.ActiveQueries = len(stats.Processes)
}

// Status returns connection info for the dashboard.
func (c *MySQLCollector) Status() (connected bool, errMsg string, display string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected, c.lastErr, c.dsnDisplay
}

// Close shuts down the connection pool.
func (c *MySQLCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.db != nil {
		c.db.Close()
		c.db = nil
	}
}

// ── DSN Builder ─────────────────────────────────────────────────────

// BuildDSN constructs a go-sql-driver/mysql DSN from individual parts.
// Prefers socket if provided, otherwise uses TCP.
func BuildDSN(user, password, host, socket string) string {
	if user == "" {
		user = "root"
	}

	var authPart string
	if password != "" {
		authPart = fmt.Sprintf("%s:%s", user, password)
	} else {
		authPart = user
	}

	if socket != "" {
		return fmt.Sprintf("%s@unix(%s)/", authPart, socket)
	}

	if host == "" {
		host = "127.0.0.1:3306"
	}
	if !strings.Contains(host, ":") {
		host = host + ":3306"
	}
	return fmt.Sprintf("%s@tcp(%s)/", authPart, host)
}

// BuildDSNFromConfig builds a DSN from a parsed MyCnfConfig,
// with optional CLI overrides.  CLI values take precedence
// when non-empty.
func BuildDSNFromConfig(cfg MyCnfConfig, cliUser, cliPass, cliHost, cliSocket string) string {
	user := firstNonEmpty(cliUser, cfg.User, "root")
	pass := firstNonEmpty(cliPass, cfg.Password)
	socket := firstNonEmpty(cliSocket, cfg.Socket)
	host := firstNonEmpty(cliHost, cfg.Host)

	// If config says "localhost", MySQL convention is to use socket.
	if host == "localhost" {
		host = ""
	}

	// Add port from config if host has no port.
	if host != "" && !strings.Contains(host, ":") && cfg.Port != "" {
		host = host + ":" + cfg.Port
	}

	// If we have a socket path, verify it exists on disk.
	if socket != "" {
		if _, err := os.Stat(socket); err != nil {
			socket = "" // doesn't exist, try TCP instead
		}
	}

	// If still no socket, try to auto-detect one.
	if socket == "" && host == "" {
		socket = FindMySQLSocket()
	}

	return BuildDSN(user, pass, host, socket)
}

// ── Helpers ─────────────────────────────────────────────────────────

func nullStr(ns sql.NullString, fallback string) string {
	if ns.Valid && ns.String != "" {
		return ns.String
	}
	return fallback
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// SanitizeDSNForLog removes the password from a DSN for safe display.
// "root:s3cret@unix(/tmp/mysql.sock)/" → "root:***@unix(/tmp/mysql.sock)/"
func SanitizeDSNForLog(dsn string) string {
	return sanitizeDSN(dsn)
}

func sanitizeDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	atIdx := strings.IndexByte(dsn, '@')
	if atIdx < 0 {
		return dsn
	}
	auth := dsn[:atIdx]
	rest := dsn[atIdx:]
	colonIdx := strings.IndexByte(auth, ':')
	if colonIdx < 0 {
		return dsn // no password
	}
	return auth[:colonIdx] + ":***" + rest
}
