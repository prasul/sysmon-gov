package metrics

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ── Public types ────────────────────────────────────────────────────

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

type MySQLStats struct {
	TotalConnections int
	ActiveQueries    int
	QueriesPerSec    float64
	SlowQueries      int64
	Uptime           int64
	ThreadsRunning   int64
	ThreadsConnected int64
	Processes        []MySQLProcess
}

// ── .my.cnf types and parser (unchanged) ────────────────────────────

type MyCnfConfig struct {
	User     string
	Password string
	Host     string
	Port     string
	Socket   string
}

var myCnfPaths = []string{
	"/root/.my.cnf",
	"/root/.mylogin.cnf",
	filepath.Join(os.Getenv("HOME"), ".my.cnf"),
	"/etc/mysql/debian.cnf",
	"/etc/my.cnf",
}

var commonSockets = []string{
	"/var/run/mysqld/mysqld.sock",
	"/var/lib/mysql/mysql.sock",
	"/tmp/mysql.sock",
	"/run/mysqld/mysqld.sock",
	"/var/run/mysql/mysql.sock",
	"/usr/local/var/mysql/mysql.sock",
}

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
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			section := strings.ToLower(strings.Trim(line, "[] "))
			inClientSection = (section == "client" || section == "mysqladmin")
			continue
		}
		if !inClientSection {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := stripQuotes(strings.TrimSpace(parts[1]))
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

func AutoDetectMyCnf() (MyCnfConfig, string) {
	for _, p := range myCnfPaths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			cfg := ParseMyCnf(p)
			if cfg.User != "" || cfg.Password != "" {
				return cfg, p
			}
		}
	}
	return MyCnfConfig{}, ""
}

func FindMySQLSocket() string {
	for _, s := range commonSockets {
		if _, err := os.Stat(s); err == nil {
			return s
		}
	}
	return ""
}

// ── Collector ───────────────────────────────────────────────────────

type MySQLCollector struct {
	mu  sync.Mutex
	dsn string
	db  *sql.DB

	connected  bool
	lastErr    string
	dsnDisplay string
	useCmd     bool   // true = fall back to mysqladmin command
	cnfPath    string // path to .my.cnf for command fallback
}

func NewMySQLCollector(dsn string) *MySQLCollector {
	return &MySQLCollector{
		dsn:        dsn,
		dsnDisplay: sanitizeDSN(dsn),
	}
}

// NewMySQLCollectorWithCnf creates a collector that can fall back to
// the mysqladmin command using the given .my.cnf file.
func NewMySQLCollectorWithCnf(dsn, cnfPath string) *MySQLCollector {
	return &MySQLCollector{
		dsn:        dsn,
		dsnDisplay: sanitizeDSN(dsn),
		cnfPath:    cnfPath,
	}
}

func (c *MySQLCollector) IsEnabled() bool {
	return c.dsn != ""
}

// Collect tries the Go SQL driver first.  If that fails, it falls
// back to shelling out to mysqladmin (which reads .my.cnf natively).
func (c *MySQLCollector) Collect() *MySQLStats {
	if c.dsn == "" {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If we've previously determined the Go driver doesn't work,
	// go straight to the command fallback.
	if c.useCmd {
		return c.collectViaCommand()
	}

	stats := c.collectViaDriver()
	if stats != nil {
		return stats
	}

	// Driver failed — try the command fallback.
	cmdStats := c.collectViaCommand()
	if cmdStats != nil {
		c.useCmd = true // remember to skip the driver next time
	}
	return cmdStats
}

// ── Go SQL driver path ──────────────────────────────────────────────

func (c *MySQLCollector) collectViaDriver() *MySQLStats {
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

	if err := c.db.Ping(); err != nil {
		c.connected = false
		c.lastErr = err.Error()
		c.db.Close()
		c.db = nil
		return nil
	}

	stats := &MySQLStats{}
	c.driverGlobalStatus(stats)
	c.driverProcessList(stats)

	if !c.connected {
		return nil
	}
	return stats
}

func (c *MySQLCollector) driverGlobalStatus(stats *MySQLStats) {
	rows, err := c.db.Query("SHOW GLOBAL STATUS WHERE Variable_name IN ('Queries','Slow_queries','Uptime','Threads_running','Threads_connected')")
	if err != nil {
		return
	}
	defer rows.Close()

	var totalQueries float64
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			continue
		}
		v, _ := strconv.ParseInt(value, 10, 64)
		switch name {
		case "Queries":
			totalQueries, _ = strconv.ParseFloat(value, 64)
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
	if stats.Uptime > 0 && totalQueries > 0 {
		stats.QueriesPerSec = totalQueries / float64(stats.Uptime)
	}
}

// driverProcessList handles variable column counts across MySQL,
// MariaDB, and Percona.  Instead of scanning into fixed variables,
// we read column names dynamically and map by name.
func (c *MySQLCollector) driverProcessList(stats *MySQLStats) {
	rows, err := c.db.Query("SHOW FULL PROCESSLIST")
	if err != nil {
		c.connected = false
		c.lastErr = err.Error()
		c.db.Close()
		c.db = nil
		return
	}
	defer rows.Close()

	c.connected = true
	c.lastErr = ""

	// ── Read column names to build index map ────────────────────
	cols, err := rows.Columns()
	if err != nil {
		return
	}
	colIdx := make(map[string]int)
	for i, name := range cols {
		colIdx[strings.ToLower(name)] = i
	}

	for rows.Next() {
		// Create a slice of interface{} to scan any number of columns.
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		// Helper to read a column by name as string.
		getStr := func(name string) string {
			idx, ok := colIdx[name]
			if !ok {
				return ""
			}
			v := values[idx]
			if v == nil {
				return ""
			}
			switch val := v.(type) {
			case []byte:
				return string(val)
			case string:
				return val
			default:
				return fmt.Sprintf("%v", val)
			}
		}
		getInt := func(name string) int64 {
			s := getStr(name)
			v, _ := strconv.ParseInt(s, 10, 64)
			return v
		}

		p := MySQLProcess{
			ID:      getInt("id"),
			User:    getStr("user"),
			Host:    getStr("host"),
			DB:      getStr("db"),
			Command: getStr("command"),
			TimeSec: getInt("time"),
			State:   getStr("state"),
			Query:   getStr("info"),
		}
		if p.DB == "" {
			p.DB = "—"
		}
		if p.State == "" {
			p.State = "—"
		}

		stats.TotalConnections++

		// Filter out idle/internal connections.
		if strings.EqualFold(p.Command, "Sleep") {
			continue
		}
		if strings.EqualFold(p.Command, "Daemon") {
			continue
		}
		if strings.EqualFold(p.Command, "Binlog Dump") {
			continue
		}
		if strings.Contains(p.Query, "PROCESSLIST") || strings.Contains(p.Query, "GLOBAL STATUS") {
			continue
		}

		// Clean for display.
		if len(p.Query) > 120 {
			p.Query = p.Query[:117] + "…"
		}
		p.Query = collapseWhitespace(p.Query)
		if idx := strings.LastIndexByte(p.Host, ':'); idx > 0 {
			p.Host = p.Host[:idx]
		}

		stats.Processes = append(stats.Processes, p)
	}

	sort.Slice(stats.Processes, func(i, j int) bool {
		return stats.Processes[i].TimeSec > stats.Processes[j].TimeSec
	})
	stats.ActiveQueries = len(stats.Processes)
}

// ── mysqladmin command fallback ─────────────────────────────────────

func (c *MySQLCollector) collectViaCommand() *MySQLStats {
	// Find mysqladmin binary.
	bin, err := exec.LookPath("mysqladmin")
	if err != nil {
		c.lastErr = "mysqladmin not in PATH"
		return nil
	}

	// Build args — if we have a .my.cnf, use --defaults-file.
	var args []string
	if c.cnfPath != "" {
		args = append(args, fmt.Sprintf("--defaults-file=%s", c.cnfPath))
	}
	args = append(args, "processlist", "status", "--verbose")

	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		c.connected = false
		c.lastErr = fmt.Sprintf("mysqladmin: %v", err)
		return nil
	}

	c.connected = true
	c.lastErr = ""

	stats := &MySQLStats{}
	lines := strings.Split(string(out), "\n")
	inProcessList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect the processlist table (pipe-delimited).
		if strings.HasPrefix(line, "+") && strings.Contains(line, "+") {
			inProcessList = true
			continue
		}

		// Parse status line: "Uptime: 12345  Threads: 5  Questions: 67890 ..."
		if strings.HasPrefix(line, "Uptime:") {
			c.parseStatusLine(stats, line)
			continue
		}

		if !inProcessList || !strings.HasPrefix(line, "|") {
			continue
		}

		// Parse a processlist row.
		p, ok := c.parseProcessRow(line)
		if !ok {
			continue
		}

		stats.TotalConnections++
		if strings.EqualFold(p.Command, "Sleep") || strings.EqualFold(p.Command, "Daemon") {
			continue
		}
		if strings.Contains(p.Query, "processlist") {
			continue
		}
		stats.Processes = append(stats.Processes, p)
	}

	sort.Slice(stats.Processes, func(i, j int) bool {
		return stats.Processes[i].TimeSec > stats.Processes[j].TimeSec
	})
	stats.ActiveQueries = len(stats.Processes)
	return stats
}

func (c *MySQLCollector) parseStatusLine(stats *MySQLStats, line string) {
	// "Uptime: 12345  Threads: 5  Questions: 67890  Slow queries: 2 ..."
	parts := strings.Fields(line)
	for i := 0; i < len(parts)-1; i++ {
		key := strings.TrimSuffix(parts[i], ":")
		val := strings.TrimSpace(parts[i+1])
		v, _ := strconv.ParseInt(val, 10, 64)
		switch strings.ToLower(key) {
		case "uptime":
			stats.Uptime = v
		case "threads":
			stats.ThreadsConnected = v
		case "questions":
			if stats.Uptime > 0 {
				stats.QueriesPerSec = float64(v) / float64(stats.Uptime)
			}
		}
	}
	// Parse "Slow queries: N" specifically.
	if idx := strings.Index(line, "Slow queries:"); idx >= 0 {
		after := strings.Fields(line[idx+len("Slow queries:"):])
		if len(after) > 0 {
			stats.SlowQueries, _ = strconv.ParseInt(after[0], 10, 64)
		}
	}
}

func (c *MySQLCollector) parseProcessRow(line string) (MySQLProcess, bool) {
	// Split by | and trim.
	fields := strings.Split(line, "|")
	var cleaned []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			cleaned = append(cleaned, f)
		}
	}
	// Expect at least: Id, User, Host, db, Command, Time, State, Info
	if len(cleaned) < 7 {
		return MySQLProcess{}, false
	}

	// Skip header row.
	if strings.EqualFold(cleaned[0], "Id") {
		return MySQLProcess{}, false
	}

	p := MySQLProcess{}
	p.ID, _ = strconv.ParseInt(cleaned[0], 10, 64)
	p.User = cleaned[1]
	p.Host = cleaned[2]
	if len(cleaned) > 3 {
		p.DB = cleaned[3]
	}
	if len(cleaned) > 4 {
		p.Command = cleaned[4]
	}
	if len(cleaned) > 5 {
		p.TimeSec, _ = strconv.ParseInt(cleaned[5], 10, 64)
	}
	if len(cleaned) > 6 {
		p.State = cleaned[6]
	}
	if len(cleaned) > 7 {
		p.Query = cleaned[7]
		if len(p.Query) > 120 {
			p.Query = p.Query[:117] + "…"
		}
		p.Query = collapseWhitespace(p.Query)
	}
	if p.DB == "" {
		p.DB = "—"
	}
	if idx := strings.LastIndexByte(p.Host, ':'); idx > 0 {
		p.Host = p.Host[:idx]
	}

	return p, true
}

func (c *MySQLCollector) Status() (connected bool, errMsg string, display string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected, c.lastErr, c.dsnDisplay
}

func (c *MySQLCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.db != nil {
		c.db.Close()
		c.db = nil
	}
}

// ── DSN Builder ─────────────────────────────────────────────────────

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

func BuildDSNFromConfig(cfg MyCnfConfig, cliUser, cliPass, cliHost, cliSocket string) string {
	user := firstNonEmpty(cliUser, cfg.User, "root")
	pass := firstNonEmpty(cliPass, cfg.Password)
	socket := firstNonEmpty(cliSocket, cfg.Socket)
	host := firstNonEmpty(cliHost, cfg.Host)
	if host == "localhost" {
		host = ""
	}
	if host != "" && !strings.Contains(host, ":") && cfg.Port != "" {
		host = host + ":" + cfg.Port
	}
	if socket != "" {
		if _, err := os.Stat(socket); err != nil {
			socket = ""
		}
	}
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

func SanitizeDSNForLog(dsn string) string { return sanitizeDSN(dsn) }

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
		return dsn
	}
	return auth[:colonIdx] + ":***" + rest
}
