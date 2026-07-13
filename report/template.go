package report

// reportTemplate is the single self-contained HTML document. No
// external CSS, fonts, or scripts are loaded — charts are inline SVG
// (see charts.go) and everything else is plain HTML/CSS, so the file
// opens correctly offline and is safe to email or drop in a shared
// drive. All dynamic text goes through html/template's automatic
// escaping except the pre-built SVG chart fields, which are escaped
// internally before being marked template.HTML.
const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>sysmon report — {{.Hostname}} — {{.GeneratedAt.Format "Jan 2, 2006 15:04:05"}}</title>
<style>
  :root {
    --bg: #f5f6f8;
    --card: #ffffff;
    --border: #e5e7eb;
    --text: #111827;
    --muted: #6b7280;
    --accent: #2563eb;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 32px 16px 64px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
  }
  .wrap { max-width: 880px; margin: 0 auto; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 20px;
  }
  h1 { font-size: 22px; font-weight: 600; margin: 0 0 4px; }
  h2 { font-size: 15px; font-weight: 600; margin: 0 0 12px; color: var(--text); }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 0; }
  .header-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    white-space: nowrap;
  }
  .badge-critical { background: #fee2e2; color: #991b1b; }
  .badge-elevated { background: #fef3c7; color: #92400e; }
  .badge-normal   { background: #d1fae5; color: #065f46; }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 12px;
    margin-top: 16px;
  }
  .stat { border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
  .stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
  .stat .value { font-size: 20px; font-weight: 600; margin-top: 2px; }
  .findings { margin: 12px 0 0; padding-left: 20px; }
  .findings li { margin-bottom: 8px; font-size: 14px; }
  .headline { font-size: 15px; font-weight: 600; margin-top: 4px; }
  .chart-caption { color: var(--muted); font-size: 12px; margin: -6px 0 12px; }
  svg { width: 100%; height: auto; display: block; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.02em; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .empty { color: var(--muted); font-size: 13px; padding: 8px 0; }
  .footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 24px; }
  .live-dot { color: #dc2626; font-weight: 600; }
  @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
  @media print {
    body { background: #fff; padding: 0; }
    .card { border: none; box-shadow: none; break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="wrap">

  <div class="card">
    <div class="header-row">
      <div>
        <h1>sysmon load report</h1>
        <p class="subtitle">{{.Hostname}} · generated {{.GeneratedAt.Format "Jan 2, 2006 15:04:05 MST"}} · refresh interval {{.Interval}}</p>
      </div>
      <span class="badge badge-{{.Analysis.Severity}}">{{.Analysis.Severity}}</span>
    </div>

    <div class="summary-grid">
      <div class="stat">
        <div class="label">Load 1m / 5m</div>
        <div class="value">{{if .Load}}{{printf "%.2f" .Load.Load1}} / {{printf "%.2f" .Load.Load5}}{{else}}—{{end}}</div>
      </div>
      <div class="stat">
        <div class="label">CPU cores</div>
        <div class="value">{{.NumCPU}}</div>
      </div>
      <div class="stat">
        <div class="label">CPU used</div>
        <div class="value">{{printf "%.0f" .CPUPercent}}%</div>
      </div>
      <div class="stat">
        <div class="label">Memory used</div>
        <div class="value">{{if .Mem}}{{printf "%.0f" .Mem.UsedPercent}}%{{else}}—{{end}}</div>
      </div>
      <div class="stat">
        <div class="label">Requests seen</div>
        <div class="value">{{.NginxTotal}}</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Probable cause</h2>
    <div class="headline">{{.Analysis.Headline}}</div>
    <ul class="findings">
      {{range .Analysis.Findings}}<li>{{.}}</li>
      {{end}}
    </ul>
  </div>

  <div class="card">
    <h2>Load / CPU / memory over time</h2>
    <p class="chart-caption">{{.WindowLabel}}</p>
    {{.TimelineSVG}}
  </div>

  <div class="two-col">

    <div class="card">
      <h2>Top CPU processes</h2>
      {{.CPUBarSVG}}
      {{if .TopCPU}}
      <table>
        <tr><th>Process</th><th>PID</th><th class="num">CPU%</th><th class="num">Mem</th></tr>
        {{range .TopCPU}}<tr><td>{{.Name}}</td><td>{{.PID}}</td><td class="num">{{printf "%.1f" .CPUPercent}}%</td><td class="num">{{printf "%.0f" .MemMB}} MB</td></tr>
        {{end}}
      </table>
      {{else}}<p class="empty">no process data</p>{{end}}
    </div>

    <div class="card">
      <h2>Top memory processes</h2>
      {{.MemBarSVG}}
      {{if .TopMem}}
      <table>
        <tr><th>Process</th><th>PID</th><th class="num">Mem</th><th class="num">Mem%</th></tr>
        {{range .TopMem}}<tr><td>{{.Name}}</td><td>{{.PID}}</td><td class="num">{{printf "%.0f" .MemMB}} MB</td><td class="num">{{printf "%.1f" .MemPercent}}%</td></tr>
        {{end}}
      </table>
      {{else}}<p class="empty">no process data</p>{{end}}
    </div>

  </div>

  <div class="two-col">

    <div class="card">
      <h2>Top nginx paths <span style="color:var(--muted);font-weight:400;">({{.NginxTotal}} requests)</span></h2>
      {{.PathsBarSVG}}
      {{if .NginxPaths}}
      <table>
        <tr><th>Domain</th><th>Path</th><th class="num">Hits</th></tr>
        {{range .NginxPaths}}<tr><td>{{.Domain}}</td><td>{{.Path}}</td><td class="num">{{.Count}}</td></tr>
        {{end}}
      </table>
      {{else}}<p class="empty">no traffic data</p>{{end}}
    </div>

    <div class="card">
      <h2>Top nginx IPs</h2>
      {{.IPsBarSVG}}
      {{if .NginxIPs}}
      <table>
        <tr><th>Domain</th><th>IP</th><th>Country</th><th class="num">Hits</th></tr>
        {{range .NginxIPs}}<tr><td>{{.Domain}}</td><td>{{.IP}}</td><td>{{.Country}}</td><td class="num">{{.Count}}</td></tr>
        {{end}}
      </table>
      {{else}}<p class="empty">no traffic data</p>{{end}}
    </div>

  </div>

  <div class="card">
    <h2>PHP-FPM slow log <span style="color:var(--muted);font-weight:400;">({{.PHPTotal}} total)</span></h2>
    {{.PHPBarSVG}}
    {{if .PHPSlow}}
    <table>
      <tr><th>Domain</th><th>Plugin</th><th>Function</th><th class="num">Count</th></tr>
      {{range .PHPSlow}}<tr><td>{{.Domain}}</td><td>{{.Plugin}}</td><td>{{.Function}}</td><td class="num">{{.Count}}</td></tr>
      {{end}}
    </table>
    {{else}}<p class="empty">no slow requests logged</p>{{end}}
  </div>

  <div class="two-col">

    <div class="card">
      <h2>Bot traffic <span style="color:var(--muted);font-weight:400;">({{.BotTotal}} total)</span></h2>
      {{.BotsBarSVG}}
      {{if .Bots}}
      <table>
        <tr><th>Bot</th><th>Type</th><th>Domain</th><th class="num">Hits</th></tr>
        {{range .Bots}}<tr><td>{{.BotName}}</td><td>{{.BotType}}</td><td>{{.Domain}}</td><td class="num">{{.Count}}</td></tr>
        {{end}}
      </table>
      {{else}}<p class="empty">no bot traffic detected</p>{{end}}
    </div>

    <div class="card">
      <h2>WP-Login attackers <span style="color:var(--muted);font-weight:400;">({{.WPTotal}} total)</span></h2>
      {{.WPBarSVG}}
      {{if .WPLogin}}
      <table>
        <tr><th>IP</th><th>Country</th><th>Last seen</th><th class="num">Hits</th></tr>
        {{range .WPLogin}}<tr><td>{{.IP}}</td><td>{{.Country}}</td><td>{{.LastSeen.Format "15:04:05"}}{{if .IsLive}} <span class="live-dot">● live</span>{{end}}</td><td class="num">{{.Count}}</td></tr>
        {{end}}
      </table>
      {{else}}<p class="empty">no wp-login attempts</p>{{end}}
    </div>

  </div>

  <div class="card">
    <h2>Nginx errors <span style="color:var(--muted);font-weight:400;">({{.ErrTotal}} total)</span></h2>
    {{.ErrBarSVG}}
    {{if .NgxErrors}}
    <table>
      <tr><th>Error</th><th>Domain</th><th>Path</th><th>IP</th><th class="num">Count</th></tr>
      {{range .NgxErrors}}<tr><td>{{.Error}}</td><td>{{.Domain}}</td><td>{{.Path}}</td><td>{{.IP}}</td><td class="num">{{.Count}}</td></tr>
      {{end}}
    </table>
    {{else}}<p class="empty">no errors logged</p>{{end}}
  </div>

  {{if .MySQL}}
  <div class="card">
    <h2>MySQL <span style="color:var(--muted);font-weight:400;">({{.MySQL.TotalConnections}} conn · {{.MySQL.ActiveQueries}} active · {{printf "%.0f" .MySQL.QueriesPerSec}} qps · {{.MySQL.SlowQueries}} slow)</span></h2>
    {{if .MySQL.Processes}}
    <table>
      <tr><th>ID</th><th>User</th><th>DB</th><th class="num">Time</th><th>State</th><th>Query</th></tr>
      {{range .MySQL.Processes}}<tr><td>{{.ID}}</td><td>{{.User}}</td><td>{{.DB}}</td><td class="num">{{.TimeSec}}s</td><td>{{.State}}</td><td>{{.Query}}</td></tr>
      {{end}}
    </table>
    {{else}}<p class="empty">all idle</p>{{end}}
  </div>
  {{end}}

  {{if .FileChanges}}
  <div class="card">
    <h2>Recent file changes <span style="color:var(--muted);font-weight:400;">({{.FileTotal}} files)</span></h2>
    <table>
      <tr><th>Domain</th><th>Plugin / theme</th><th>Kind</th><th>Last changed</th><th class="num">Files</th></tr>
      {{range .FileChanges}}<tr><td>{{.Domain}}</td><td>{{.Name}}</td><td>{{.Kind}}</td><td>{{.LastChange.Format "Jan 2 15:04"}}</td><td class="num">{{.Count}}</td></tr>
      {{end}}
    </table>
  </div>
  {{end}}

  {{if .Disks}}
  <div class="card">
    <h2>Disk</h2>
    <table>
      <tr><th>Mount</th><th class="num">Total</th><th class="num">Used</th><th class="num">Avail</th><th class="num">Use%</th></tr>
      {{range .Disks}}<tr><td>{{.MountPoint}}</td><td class="num">{{printf "%.1f" .TotalGB}}G</td><td class="num">{{printf "%.1f" .UsedGB}}G</td><td class="num">{{printf "%.1f" .AvailGB}}G</td><td class="num">{{printf "%.0f" .UsedPercent}}%</td></tr>
      {{end}}
    </table>
  </div>
  {{end}}

  <p class="footer">Generated by sysmon on {{.Hostname}} — press "s" in the dashboard to generate a new report.</p>

</div>
</body>
</html>
`
