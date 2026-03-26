// sysmon — A real-time Linux server load monitor for the terminal.
//
// Two pages: Dashboard (D) and Live View (L).
// MySQL credentials are auto-detected from /root/.my.cnf.
//
// Keybindings:
//
//	q / Ctrl-C    Quit
//	L / →         Switch to Live View
//	Esc / D / ←   Switch to Dashboard
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"sysmon/metrics"
	"sysmon/ui"
)

func main() {
	// ── CLI Flags ───────────────────────────────────────────────
	intervalFlag := flag.String("interval", "2s",
		"Dashboard refresh interval (e.g. 2s, 500ms, 1m)")

	domainsFlag := flag.String("domains",
		"/home/nginx/domains/*",
		"Glob for domain directories (used by file scanner)")

	logPathFlag := flag.String("logpath",
		"/home/nginx/domains/*/log/access.log",
		"Glob pattern for nginx access logs")

	errorLogFlag := flag.String("errorlog",
		"/home/nginx/domains/*/log/error.log",
		"Glob pattern for nginx error logs")

	slowLogFlag := flag.String("slowlog",
		"/var/log/php-fpm/www-slow.log",
		"Glob pattern for PHP-FPM slow logs")

	geoIPFlag := flag.String("geoip", "",
		"Path to GeoLite2-Country.mmdb (auto-detected if empty)")

	fileWindowFlag := flag.String("file-window", "48h",
		"Time window for file change detection (e.g. 48h, 24h)")

	liveBufferFlag := flag.Int("live-buffer", 500,
		"Number of log entries to keep in live tail buffer")

	// MySQL flags
	mysqlDSN := flag.String("mysql-dsn", "",
		"Full MySQL DSN (overrides everything)")
	mysqlUser := flag.String("mysql-user", "",
		"MySQL user (overrides .my.cnf)")
	mysqlPass := flag.String("mysql-pass", "",
		"MySQL password (overrides .my.cnf)")
	mysqlHost := flag.String("mysql-host", "",
		"MySQL TCP host:port (overrides .my.cnf)")
	mysqlSocket := flag.String("mysql-socket", "",
		"MySQL unix socket (overrides .my.cnf)")
	mysqlCnf := flag.String("mysql-cnf", "",
		"Path to .my.cnf (auto-detected if empty)")

	flag.Parse()

	// ── Validate interval ───────────────────────────────────────
	interval, err := time.ParseDuration(*intervalFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid interval %q\n", *intervalFlag)
		os.Exit(1)
	}
	if interval < 200*time.Millisecond {
		fmt.Fprintln(os.Stderr, "Warning: intervals below 200ms may cause high CPU usage.")
	}

	// ── Parse file change window ────────────────────────────────
	fileWindow, err := time.ParseDuration(*fileWindowFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid file-window %q\n", *fileWindowFlag)
		os.Exit(1)
	}

	// ── Initialize collectors ───────────────────────────────────
	geoFn := metrics.NewGeoIPLookup(*geoIPFlag)

	nginx := metrics.NewNginxCollector(*logPathFlag, geoFn)
	bots := metrics.NewBotCollector(*logPathFlag)
	wpLogin := metrics.NewWPLoginCollector(*logPathFlag, geoFn)
	phpSlow := metrics.NewPHPSlowCollector(*slowLogFlag)
	wpFiles := metrics.NewWPFileCollector(*domainsFlag, fileWindow)
	ngxErrors := metrics.NewNginxErrorCollector(*errorLogFlag)
	liveTail := metrics.NewLiveTailer(*logPathFlag, *errorLogFlag, *liveBufferFlag)

	// ── MySQL auto-detect ───────────────────────────────────────
	dsn := *mysqlDSN
	var cnfPathForFallback string
	if dsn == "" {
		var cfg metrics.MyCnfConfig
		var cnfPath string

		if *mysqlCnf != "" {
			cfg = metrics.ParseMyCnf(*mysqlCnf)
			cnfPath = *mysqlCnf
		} else {
			cfg, cnfPath = metrics.AutoDetectMyCnf()
		}

		cnfPathForFallback = cnfPath
		if cnfPath != "" {
			fmt.Fprintf(os.Stderr, "sysmon: MySQL from %s (user=%s)\n",
				cnfPath, firstNonEmpty(cfg.User, "(default)"))
		}

		dsn = metrics.BuildDSNFromConfig(cfg, *mysqlUser, *mysqlPass, *mysqlHost, *mysqlSocket)
	}

	if dsn != "" {
		fmt.Fprintf(os.Stderr, "sysmon: MySQL DSN → %s\n", metrics.SanitizeDSNForLog(dsn))
	}

	mysql := metrics.NewMySQLCollectorWithCnf(dsn, cnfPathForFallback)

	// ── Launch ──────────────────────────────────────────────────
	deps := ui.Deps{
		Nginx:     nginx,
		Bots:      bots,
		WPLogin:   wpLogin,
		PHPSlow:   phpSlow,
		MySQL:     mysql,
		WPFiles:   wpFiles,
		NgxErrors: ngxErrors,
		LiveTail:  liveTail,
	}
	app := ui.New(interval, deps)
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %v\n", err)
		os.Exit(1)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
