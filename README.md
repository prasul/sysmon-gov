# sysmon

A real-time, full-screen terminal dashboard for monitoring WordPress/LEMP Linux servers. Built with Go and [tview](https://github.com/rivo/tview).

Single binary. Zero runtime dependencies. Reads directly from `/proc`, log files, and MySQL.

## Dashboard

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ■ SYSMON │ myhost │ Kernel 6.1.0 │ 2026-03-25 12:00:00                 │
├──────────────────────────────┬───────────────────────────────────────────┤
│ ⚡ Load                      │ 🧠 Memory                                │
│ 1m 0.42  5m 0.31  15m 0.12  │ RAM  ━━━━━━━━╌╌╌╌  62%  512/1024 MB     │
├──────────────────────────────┼───────────────────────────────────────────┤
│ ▲ Top CPU                    │ ▲ Top Memory                             │
│ 1 chrome      3142  42.1%   │ 1 java        8821  812MB  18.3%        │
├──────────────────────────────┼───────────────────────────────────────────┤
│ ◆ Top Paths [42.1K]         │ ◆ Top IPs                                │
│ 1  1832 example.com /api    │ 1  1832 example.com 1.2.3.4   US        │
├──────────────────────────────┼───────────────────────────────────────────┤
│ ◈ Bot Traffic [8.2K]        │ ◉ MySQL [42 conn / 3 active / 847 qps]  │
│ 1  2841 GPTBot    AI  ex.co │ 12 root  mydb  3s  Sending  SELECT …    │
├──────────────────────────────┼───────────────────────────────────────────┤
│ ✦ WP-Login ● LIVE  [342]    │ ✧ PHP Slow [28]                          │
│ 1   89 ex.com 1.2.3.4 CN 5s│ 1  12 ex.com  wpforms     sleep         │
├──────────────────────────────┼───────────────────────────────────────────┤
│ ⚑ File Changes [47 files]   │ ✖ Nginx Errors [1.2K]                    │
│ 1  47 ex.com [P] wpforms 2h│ 1  89 ex.com /themes/style.php forbidden │
├──────────────────────────────┴───────────────────────────────────────────┤
│ ▪ Disk  /dev/sda1  /  50G  32G  18G  64%  ━━━━━━━━━━╌╌╌╌╌╌           │
├──────────────────────────────────────────────────────────────────────────┤
│ q quit │ L / → live view │ refresh 2s │ sysmon                         │
└──────────────────────────────────────────────────────────────────────────┘
```

## Live View (press L)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ■ SYSMON LIVE VIEW │ 15:04:05  ● SYN FLOOD DETECTED                    │
├──────────────────────────────────────────────────────────────────────────┤
│ ⚡ ESTAB 342  SYN_RECV 48  TIME_WAIT 89  CLOSE_WAIT 3  LISTEN 12      │
├──────────────────────────────┬───────────────────────────────────────────┤
│ ⚠ SYN FLOOD ● ACTIVE        │ ◆ Top Connections                        │
│ 1  45.94.31.67       48     │ 1  1.2.3.4         342  280  0   62     │
│ 2  103.22.41.5       23     │ 2  2a09:bac2::4c4  189  150  3   36     │
├──────────────────────────────┴───────────────────────────────────────────┤
│ ● Live Log Tail [423 in buffer]                                         │
│ 15:04:05  ACC  example.com   1.2.3.4              /api/v2       200    │
│ 15:04:05  ERR  blog.io       45.94.31.67          /style.php    forbid │
│ 15:04:06  ACC  example.com   2a09:bac2:b8eb::4c4  /feed         301    │
├──────────────────────────────────────────────────────────────────────────┤
│ Esc / D dashboard │ q quit │ refresh 2s │ sysmon live                   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Installation

### From source

```bash
# Requires Go 1.21+
git clone https://github.com/YOUR_USERNAME/sysmon.git
cd sysmon
go mod tidy
go build -o sysmon .
sudo ./sysmon
```

### Optional: Install system-wide

```bash
sudo cp sysmon /usr/local/bin/
sudo sysmon
```

## What It Monitors

| Panel | Source | Data |
|-------|--------|------|
| CPU / Memory / Disk | `/proc/stat`, `/proc/meminfo`, `syscall.Statfs` | Real-time system metrics |
| Top Processes | `/proc/*/stat`, `/proc/*/status` | CPU% and memory per process |
| Nginx Top Paths & IPs | Access logs (incremental) | Hit counts with GeoIP country |
| Bot Traffic | Access log User-Agent | 40+ bot signatures: AI, Search, Social |
| MySQL Queries | `SHOW FULL PROCESSLIST` | Active queries sorted by duration |
| WP-Login Attacks | Access logs | Brute-force detection with live alert |
| PHP Slow Log | `/var/log/php-fpm/www-slow.log` | Plugin name + blocking function |
| File Changes | Filesystem walk | Recently modified plugin/theme files |
| Nginx Errors | Error logs (incremental) | Error type, IP, path |
| SYN Floods | `/proc/net/tcp`, `/proc/net/tcp6` | Half-open connections per IP |
| Live Tail | Access + error logs merged | Chronological real-time stream |

## MySQL Auto-Detection

Credentials are automatically read from `/root/.my.cnf` (the same file `mysql` CLI uses). The socket path is auto-discovered. No flags needed on most servers:

```bash
sudo ./sysmon  # just works
```

Override when needed:

```bash
sudo ./sysmon -mysql-user monitor -mysql-pass secret
sudo ./sysmon -mysql-dsn "user:pass@tcp(db.internal:3306)/"
```

## GeoIP Setup (Optional)

Country resolution uses MaxMind's free GeoLite2 database. Without it, the country column shows "—".

```bash
# Debian/Ubuntu
sudo apt install geoipupdate
sudo geoipupdate

# Or download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-interval` | `2s` | Refresh interval |
| `-domains` | `/home/nginx/domains/*` | Domain directory glob |
| `-logpath` | `/home/nginx/domains/*/log/access.log` | Access log glob |
| `-errorlog` | `/home/nginx/domains/*/log/error.log` | Error log glob |
| `-slowlog` | `/var/log/php-fpm/www-slow.log` | PHP-FPM slow log |
| `-geoip` | *(auto)* | GeoLite2 .mmdb path |
| `-file-window` | `48h` | File change window |
| `-live-buffer` | `500` | Live tail buffer size |
| `-mysql-socket` | *(auto)* | MySQL socket |
| `-mysql-user` | *(from .my.cnf)* | MySQL user |
| `-mysql-pass` | *(from .my.cnf)* | MySQL password |
| `-mysql-host` | *(from .my.cnf)* | MySQL host:port |
| `-mysql-dsn` | *(auto)* | Full DSN override |
| `-mysql-cnf` | *(auto)* | .my.cnf path |

## Keybindings

| Key | Action |
|-----|--------|
| `q` / `Ctrl-C` | Quit |
| `L` / `→` | Live View |
| `Esc` / `D` / `←` | Dashboard |

## Project Structure

```
sysmon/
├── main.go              Entry point, CLI flags, dependency wiring
├── metrics/
│   ├── cpu.go           CPU usage (delta-based)
│   ├── memory.go        RAM & swap
│   ├── disk.go          Filesystem usage
│   ├── load.go          Load averages
│   ├── host.go          Hostname, kernel, uptime
│   ├── process.go       Top processes by CPU/memory
│   ├── nginx.go         Access log parser
│   ├── ngxerror.go      Error log parser
│   ├── bots.go          Bot classifier (40+ signatures)
│   ├── wplogin.go       WP-Login attack detector
│   ├── wpfiles.go       File change scanner
│   ├── phpfpm.go        PHP-FPM slow log parser
│   ├── mysql.go         MySQL monitor + .my.cnf reader
│   ├── geoip.go         MaxMind GeoLite2 resolver
│   ├── network.go       SYN flood detector
│   └── livetail.go      Real-time log merger
└── ui/
    ├── theme.go         Color palette
    ├── app.go           Dashboard page
    └── livepage.go      Live view page
```

## License

MIT
