# Release v1.0.0 — Initial Release

**sysmon** — A real-time, full-screen terminal dashboard for monitoring WordPress/LEMP Linux servers.

Built with Go and [tview](https://github.com/rivo/tview). Zero external dependencies at runtime — a single static binary.

---

## Features

### Two-Page Interface
- **Dashboard** — 14-panel overview of system health, web traffic, security, and database
- **Live View** — Real-time log tail with SYN flood detection and connection monitoring
- Navigate with `L` / `→` (live) and `Esc` / `D` / `←` (dashboard)

### System Monitoring
- CPU usage via `/proc/stat` delta snapshots
- RAM and swap usage via `/proc/meminfo`
- Disk usage via `syscall.Statfs` on real filesystems
- Load averages and process counts via `/proc/loadavg`
- Top processes by CPU and memory via `/proc/*/stat`

### Nginx Log Analysis
- **Top Paths** — Most-hit URL paths across all domains (static assets filtered)
- **Top IPs** — Busiest client IPs with GeoIP country resolution
- **Bot Traffic** — 40+ known bot signatures classified into AI, Search, Social, and Monitor categories
- **Error Logs** — Aggregated nginx error patterns with error type classification
- Incremental reading — only new log lines are processed on each refresh

### WordPress Security
- **WP-Login Attack Monitor** — Tracks brute-force attempts with per-IP hit counts, country resolution, and blinking live-attack indicator
- **File Change Scanner** — Detects recently modified code files in plugins and themes (configurable 48h window) — early warning for compromised sites

### PHP-FPM Slow Log
- Parses multi-line PHP-FPM slow log entries
- Extracts domain, plugin/theme name, and blocking function from stack traces
- Aggregates by pattern to surface repeat offenders

### MySQL Monitoring
- Auto-detects credentials from `/root/.my.cnf` (or `/etc/mysql/debian.cnf`, etc.)
- Auto-discovers MySQL socket path across distributions
- Shows active queries from `SHOW FULL PROCESSLIST` sorted by duration
- Server stats from `SHOW GLOBAL STATUS`: QPS, slow queries, thread counts
- CLI flags override auto-detected values when needed

### Network & Live View
- **SYN Flood Detection** — Reads `/proc/net/tcp` and `/proc/net/tcp6` for half-open connections; flags IPs with ≥10 SYN_RECV as attackers
- **TCP Connection Summary** — ESTABLISHED, SYN_RECV, TIME_WAIT, CLOSE_WAIT, LISTEN counts
- **Top Connections** — IPs with the most connections, broken down by state
- **Live Log Tail** — Merged chronological stream from all access and error logs with full IPv6 support

### GeoIP
- MaxMind GeoLite2-Country database (optional)
- Auto-probes common install paths; degrades gracefully to "—" if not found

### Design
- Centralized color theme in `ui/theme.go` — easy to reskin
- Category-coded panel borders: blue (system), purple (web), red (security), amber (performance), teal (database)
- Severity color scale: green → yellow → red for percentages, hit counts, and query times
- Modern bar characters (`━╌`) and clean typography

---

## Requirements

- **Go 1.21+** to build
- **Linux** — reads from `/proc` filesystem
- **Root access** recommended (for log files, MySQL socket, `/proc/net/tcp`)
- **GeoLite2-Country.mmdb** (optional) — for IP country resolution

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/sysmon.git
cd sysmon
go mod tidy
go build -o sysmon .
sudo ./sysmon
```

## All CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-interval` | `2s` | Refresh interval |
| `-domains` | `/home/nginx/domains/*` | Domain directory glob |
| `-logpath` | `/home/nginx/domains/*/log/access.log` | Nginx access log glob |
| `-errorlog` | `/home/nginx/domains/*/log/error.log` | Nginx error log glob |
| `-slowlog` | `/var/log/php-fpm/www-slow.log` | PHP-FPM slow log glob |
| `-geoip` | *(auto)* | GeoLite2 .mmdb path |
| `-file-window` | `48h` | File change detection window |
| `-live-buffer` | `500` | Live tail ring buffer size |
| `-mysql-socket` | *(auto)* | MySQL unix socket |
| `-mysql-user` | *(from .my.cnf)* | MySQL username |
| `-mysql-pass` | *(from .my.cnf)* | MySQL password |
| `-mysql-host` | *(from .my.cnf)* | MySQL TCP host:port |
| `-mysql-dsn` | *(auto-built)* | Full DSN override |
| `-mysql-cnf` | *(auto-detected)* | Path to .my.cnf |

## Keybindings

| Key | Action |
|-----|--------|
| `q` / `Ctrl-C` | Quit |
| `L` / `→` | Switch to Live View |
| `Esc` / `D` / `←` | Switch to Dashboard |

---

**20 Go source files · ~5000 lines · 0 runtime dependencies**
