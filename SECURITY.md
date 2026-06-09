# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in sysmon, please report it responsibly.

**Email:** prasuls at gmail.com

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- The version of sysmon you're running (`sysmon --version` or check the release tag)
- Your server environment (OS, distribution, stack)

I will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues. Please do not open a public GitHub issue for security vulnerabilities.

---

## Security Model

sysmon is a **local, root-privileged terminal dashboard** designed to run on the same server it monitors. It is not a network service — it does not listen on any port, accept remote connections, or expose an API.

### Privilege Requirements

sysmon requires root access for:

- Reading `/proc/*/stat` and `/proc/*/statm` for all processes
- Reading web server log files (typically owned by root or www-data)
- Reading MySQL credentials from `/root/.my.cnf`
- Executing firewall commands (`csf`, `iptables`, `ufw`)
- Executing service restarts (`nprestart`, `scoots`, `systemctl`)
- Writing the action audit log to `/var/log/sysmon-actions.log`

**sysmon should only be run by authorized server administrators.** It is not designed for shared hosting environments where unprivileged users would execute it.

---

## Attack Surface

### Command Execution

sysmon executes system commands in two contexts:

**1. IP blocking/unblocking (`b` / `u` keys)**

All IP addresses are validated through Go's `net.ParseIP()` and `net.ParseCIDR()` before any command execution. This prevents shell injection — only syntactically valid IPv4/IPv6 addresses and CIDR notation pass validation.

Commands are executed via Go's `exec.Command()` (direct exec, no shell interpolation) or through `bash -l -c` for shell functions (`nprestart`, `scoots`). When `bash -l -c` is used with user-supplied IP addresses, the IP has already been validated by `net.ParseIP()` to contain only valid IP characters (digits, dots, colons, slashes).

**2. Service actions (`:` command palette)**

All service commands are predefined in the source code. There is no mechanism for users to type arbitrary commands — the command palette presents a fixed list of options. Commands include:

| Action | Command | User Input |
|--------|---------|------------|
| Restart Nginx | `bash -l -c "nprestart"` | None |
| Restart PHP-FPM | `bash -l -c "scoots php restart all"` | None |
| Restart CSF | `csf -ra` | None |
| Nginx Config Test | `nginx -t` | None |
| Flush OPcache | `php -r "opcache_reset();"` | None |
| Bounce Full Stack | Parallel: nginx + php + mysql + redis | None |
| Block IP | `csf -d {ip}` + `scoots ip block {ip}` | IP (validated) |
| Unblock IP | `csf -dr {ip}` + `scoots ip unblock {ip}` | IP (validated) |

No command accepts free-form text input beyond the validated IP address.

### Self-IP Protection

sysmon reads the `SSH_CLIENT` and `SSH_CONNECTION` environment variables to detect the operator's own IP address. If a block operation targets the operator's SSH session IP, sysmon refuses the action with an explicit warning. This prevents accidental self-lockout.

### Audit Logging

Every action (block, unblock, service restart) is logged to `/var/log/sysmon-actions.log` with:

- Timestamp (UTC)
- Unix user who initiated the action
- Action type and target
- Execution result

The log file is created with mode `0600` (owner-only read/write). Example entry:

```
[2026-06-09 10:15:32] user=root action=BLOCK_IP detail=203.0.113.50 result=executed
[2026-06-09 10:15:45] user=root action=SERVICE detail=Bounce Full Stack result=completed
```

### File System Access

sysmon reads from the following locations. It **does not write** to any of these:

| Path | Purpose | Access |
|------|---------|--------|
| `/proc/stat` | CPU usage | Read |
| `/proc/meminfo` | Memory usage | Read |
| `/proc/loadavg` | Load averages | Read |
| `/proc/mounts` | Disk filesystem list | Read |
| `/proc/*/stat` | Per-process CPU ticks | Read |
| `/proc/*/statm` | Per-process RSS | Read |
| Web server access logs | Traffic analysis | Read |
| Web server error logs | Error monitoring | Read |
| PHP-FPM slow log | Slow request tracking | Read |
| `/root/.my.cnf` | MySQL credentials | Read |
| GeoLite2 `.mmdb` | IP country resolution | Read |

The only file sysmon writes to is the action audit log at `/var/log/sysmon-actions.log`.

### MySQL Access

sysmon connects to MySQL/MariaDB to run two read-only queries:

- `SHOW FULL PROCESSLIST` — to display active queries
- `SHOW GLOBAL STATUS` — to display server statistics

It does not execute any data-modifying queries (INSERT, UPDATE, DELETE, DROP, etc.). For defense in depth, consider creating a dedicated read-only MySQL user:

```sql
CREATE USER 'sysmon'@'localhost' IDENTIFIED BY 'strong-password-here';
GRANT PROCESS ON *.* TO 'sysmon'@'localhost';
FLUSH PRIVILEGES;
```

Then configure sysmon to use it:

```bash
sudo sysmon -mysql-user sysmon -mysql-pass 'strong-password-here'
```

### Network Access

sysmon makes **no outbound network connections** when using the default MaxMind GeoIP provider (local `.mmdb` file). If configured to use an HTTP-based GeoIP provider (`ip-api`, `ipinfo`, `ipdata`), it will make outbound HTTPS requests to the respective API endpoint for IP geolocation lookups.

sysmon does not listen on any port and cannot be accessed remotely.

### Dependencies

sysmon uses four external Go modules:

| Module | Purpose | License |
|--------|---------|---------|
| `github.com/rivo/tview` | Terminal UI framework | MIT |
| `github.com/gdamore/tcell/v2` | Terminal cell library | Apache-2.0 |
| `github.com/oschwald/geoip2-golang` | MaxMind GeoIP reader | ISC |
| `github.com/go-sql-driver/mysql` | MySQL driver | MPL-2.0 |

The compiled binary is statically linked and has zero runtime dependencies.

---

## Hardening Recommendations

### 1. Restrict binary permissions

```bash
chown root:root /usr/local/bin/sysmonitor
chmod 700 /usr/local/bin/sysmonitor
```

This ensures only root can execute the binary.

### 2. Use a dedicated MySQL user

As described above, grant only `PROCESS` privilege rather than using the root MySQL account.

### 3. Rotate the action log

Add a logrotate entry:

```
/var/log/sysmon-actions.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    create 0600 root root
}
```

### 4. Review the action log

Periodically review `/var/log/sysmon-actions.log` to verify that all block/unblock and service restart actions were intentional.

### 5. Keep GeoIP data current

If using MaxMind GeoLite2, update the `.mmdb` file regularly. MaxMind provides a free update tool (`geoipupdate`) that can be scheduled via cron.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x | Yes |
| < 1.0.0 | No (pre-release) |

Security fixes are applied to the latest release only.

---

## Scope

The following are **in scope** for security reports:

- Command injection via any user input path
- Privilege escalation beyond the running user
- Information disclosure (credentials, sensitive data in logs or output)
- Denial of service through crafted log entries or input
- Bypass of self-IP protection
- Unsafe file permissions on created files

The following are **out of scope**:

- Attacks requiring prior root access (sysmon already runs as root)
- Social engineering of the server administrator
- Vulnerabilities in upstream dependencies (report these to the respective projects, but do let me know so I can update)
- Physical access attacks
