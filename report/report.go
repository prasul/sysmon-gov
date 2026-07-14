// Package report builds a self-contained HTML report summarizing
// server load and what most likely caused it, from a point-in-time
// snapshot of the dashboard's collectors plus a short in-memory
// history buffer. It has no external dependencies — charts are
// rendered as inline SVG (see charts.go), and the whole document is
// one HTML file with no CDN or JS library references.
package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"sysmon/metrics"
)

// Snapshot is everything the report needs. It is built by the UI
// layer from the most recently collected dashboard data plus the
// rolling history buffer — report generation itself does not touch
// /proc, logs, or MySQL, so pressing the report key never blocks on
// a fresh collection cycle.
type Snapshot struct {
	GeneratedAt time.Time
	Hostname    string
	Interval    time.Duration

	Load       *metrics.LoadAvg
	Mem        *metrics.MemoryInfo
	Disks      []metrics.DiskInfo
	CPUPercent float64

	TopCPU []metrics.ProcessInfo
	TopMem []metrics.ProcessInfo

	NginxPaths []metrics.NginxPathHit
	NginxIPs   []metrics.NginxIPHit
	NginxTotal int

	Bots     []metrics.BotHit
	BotTotal int

	MySQL *metrics.MySQLStats

	WPLogin []metrics.WPLoginHit
	WPTotal int

	PHPSlow  []metrics.PHPSlowEntry
	PHPTotal int

	NgxErrors []metrics.NginxErrorHit
	ErrTotal  int

	FileChanges []metrics.WPFileChange
	FileTotal   int

	History []metrics.HistorySample
}

// Generate renders an HTML report from s and writes it to outDir,
// creating the directory if needed. It returns the path to the
// written file.
func Generate(s Snapshot, outDir string) (string, error) {
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("creating report dir: %w", err)
	}

	if s.GeneratedAt.IsZero() {
		s.GeneratedAt = time.Now()
	}
	filename := fmt.Sprintf("sysmon-report-%s.html", s.GeneratedAt.Format("2006-01-02_15-04-05"))
	path := filepath.Join(outDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return "", fmt.Errorf("parsing report template: %w", err)
	}

	if err := tmpl.Execute(f, buildView(s)); err != nil {
		return "", fmt.Errorf("rendering report: %w", err)
	}

	return path, nil
}

// ── View model ───────────────────────────────────────────────────────

type reportView struct {
	Snapshot
	Analysis    causeAnalysis
	NumCPU      int
	WindowLabel string

	TimelineSVG template.HTML
	CPUBarSVG   template.HTML
	MemBarSVG   template.HTML
	PathsBarSVG template.HTML
	IPsBarSVG   template.HTML
	BotsBarSVG  template.HTML
	WPBarSVG    template.HTML
	ErrBarSVG   template.HTML
	PHPBarSVG   template.HTML
}

// maxMySQLReportRows caps how many MySQL processes the report renders.
// Unlike the dashboard's other panels (all capped at 8 by the
// collectors before they ever reach the UI), MySQLStats.Processes is
// the full, uncapped list of active queries — during a real
// connection storm that could be hundreds of rows.
const maxMySQLReportRows = 25

func buildView(s Snapshot) reportView {
	numCPU := runtime.NumCPU()
	if numCPU < 1 {
		numCPU = 1
	}

	if s.MySQL != nil && len(s.MySQL.Processes) > maxMySQLReportRows {
		trimmed := *s.MySQL
		trimmed.Processes = s.MySQL.Processes[:maxMySQLReportRows]
		s.MySQL = &trimmed
	}

	var times []string
	var loadPct, cpuVals, memVals []float64
	for _, h := range s.History {
		times = append(times, h.Time.Format("15:04:05"))
		loadPct = append(loadPct, (h.Load1/float64(numCPU))*100)
		cpuVals = append(cpuVals, h.CPUPct)
		memVals = append(memVals, h.MemPct)
	}

	timeline := timeSeriesChart(760, 220, times, []lineSeries{
		{Label: "Load (% of cores)", Color: "#ef4444", Vals: loadPct},
		{Label: "CPU %", Color: "#3b82f6", Vals: cpuVals},
		{Label: "Memory %", Color: "#10b981", Vals: memVals},
	}, 100)

	var cpuRows, memRows, pathRows, ipRows, botRows, wpRows, errRows, phpRows []barRow

	for _, p := range s.TopCPU {
		cpuRows = append(cpuRows, barRow{
			Label: p.Name, Sub: fmt.Sprintf("pid %d", p.PID),
			Value: p.CPUPercent, ValueLabel: fmt.Sprintf("%.1f%%", p.CPUPercent),
			Color: "#3b82f6",
		})
	}
	for _, p := range s.TopMem {
		memRows = append(memRows, barRow{
			Label: p.Name, Sub: fmt.Sprintf("pid %d", p.PID),
			Value: p.MemPercent, ValueLabel: fmt.Sprintf("%.0f MB", p.MemMB),
			Color: "#10b981",
		})
	}
	for _, p := range s.NginxPaths {
		pathRows = append(pathRows, barRow{
			Label: p.Path, Sub: p.Domain,
			Value: float64(p.Count), ValueLabel: fmt.Sprintf("%d", p.Count),
			Color: "#8b5cf6",
		})
	}
	for _, p := range s.NginxIPs {
		ipRows = append(ipRows, barRow{
			Label: p.IP, Sub: fmt.Sprintf("%s · %s", p.Domain, p.Country),
			Value: float64(p.Count), ValueLabel: fmt.Sprintf("%d", p.Count),
			Color: "#6366f1",
		})
	}
	for _, bo := range s.Bots {
		botRows = append(botRows, barRow{
			Label: bo.BotName, Sub: bo.Domain,
			Value: float64(bo.Count), ValueLabel: fmt.Sprintf("%d", bo.Count),
			Color: "#f59e0b",
		})
	}
	for _, w := range s.WPLogin {
		wpRows = append(wpRows, barRow{
			Label: w.IP, Sub: w.Country,
			Value: float64(w.Count), ValueLabel: fmt.Sprintf("%d", w.Count),
			Color: "#ef4444",
		})
	}
	for _, e := range s.NgxErrors {
		errRows = append(errRows, barRow{
			Label: e.Error, Sub: e.Domain,
			Value: float64(e.Count), ValueLabel: fmt.Sprintf("%d", e.Count),
			Color: "#dc2626",
		})
	}
	for _, p := range s.PHPSlow {
		phpRows = append(phpRows, barRow{
			Label: fmt.Sprintf("%s / %s", p.Plugin, p.Function), Sub: p.Domain,
			Value: float64(p.Count), ValueLabel: fmt.Sprintf("%d", p.Count),
			Color: "#ea580c",
		})
	}

	windowLabel := "no history yet — leave sysmon running a few minutes"
	if len(s.History) > 1 {
		d := s.History[len(s.History)-1].Time.Sub(s.History[0].Time)
		windowLabel = fmt.Sprintf("last %s · %d samples", d.Round(time.Second), len(s.History))
	}

	return reportView{
		Snapshot:    s,
		Analysis:    analyze(s, numCPU),
		NumCPU:      numCPU,
		WindowLabel: windowLabel,
		TimelineSVG: template.HTML(timeline),
		CPUBarSVG:   template.HTML(barChart(720, cpuRows)),
		MemBarSVG:   template.HTML(barChart(720, memRows)),
		PathsBarSVG: template.HTML(barChart(720, pathRows)),
		IPsBarSVG:   template.HTML(barChart(720, ipRows)),
		BotsBarSVG:  template.HTML(barChart(720, botRows)),
		WPBarSVG:    template.HTML(barChart(720, wpRows)),
		ErrBarSVG:   template.HTML(barChart(720, errRows)),
		PHPBarSVG:   template.HTML(barChart(720, phpRows)),
	}
}

// ── Probable-cause heuristic ────────────────────────────────────────
//
// This is intentionally simple and transparent rather than a black
// box: every finding is one observable fact about the snapshot
// (MySQL contention, an attack, a runaway process, ...) with a score
// used only for ranking. The report always shows *why* each finding
// was flagged.

type finding struct {
	score int
	text  string
}

type causeAnalysis struct {
	Severity string // "critical" | "elevated" | "normal"
	Headline string
	Findings []string
}

func analyze(s Snapshot, numCPU int) causeAnalysis {
	peakLoad := 0.0
	if s.Load != nil {
		peakLoad = s.Load.Load1
	}
	for _, h := range s.History {
		if h.Load1 > peakLoad {
			peakLoad = h.Load1
		}
	}
	loadRatio := peakLoad / float64(numCPU)

	sev := "normal"
	switch {
	case loadRatio >= 2:
		sev = "critical"
	case loadRatio >= 1:
		sev = "elevated"
	}

	var findings []finding

	if s.MySQL != nil {
		if s.MySQL.ActiveQueries >= 5 {
			findings = append(findings, finding{
				score: s.MySQL.ActiveQueries * 4,
				text: fmt.Sprintf("MySQL: %d queries running concurrently at %.0f queries/sec — database contention is a strong candidate.",
					s.MySQL.ActiveQueries, s.MySQL.QueriesPerSec),
			})
		}
		var slowest int64
		for _, p := range s.MySQL.Processes {
			if p.TimeSec > slowest {
				slowest = p.TimeSec
			}
		}
		if slowest >= 10 {
			findings = append(findings, finding{
				score: int(slowest),
				text:  fmt.Sprintf("MySQL: the slowest query has been running %ds — a long-held query may be blocking others.", slowest),
			})
		}
	}

	if s.WPTotal > 0 {
		findings = append(findings, finding{
			score: s.WPTotal/5 + 10,
			text: fmt.Sprintf("WP-Login: %d brute-force attempts against wp-login.php from %d IP(s) — attack traffic may be contributing.",
				s.WPTotal, len(s.WPLogin)),
		})
	}

	if s.BotTotal > 500 {
		topBot := "unknown"
		if len(s.Bots) > 0 {
			topBot = s.Bots[0].BotName
		}
		findings = append(findings, finding{
			score: s.BotTotal / 20,
			text: fmt.Sprintf("Bot traffic: %d requests from automated crawlers (top: %s) — elevated crawl volume may be adding request load.",
				s.BotTotal, topBot),
		})
	}

	if s.PHPTotal > 0 {
		top := "unknown"
		if len(s.PHPSlow) > 0 {
			top = fmt.Sprintf("%s (%s)", s.PHPSlow[0].Plugin, s.PHPSlow[0].Function)
		}
		findings = append(findings, finding{
			score: s.PHPTotal*3 + 5,
			text: fmt.Sprintf("PHP-FPM slow log: %d slow requests, most often blocked in %s — a specific plugin/function may be the bottleneck.",
				s.PHPTotal, top),
		})
	}

	if s.ErrTotal > 100 {
		findings = append(findings, finding{
			score: s.ErrTotal / 10,
			text:  fmt.Sprintf("Nginx errors: %d errors logged — the backend may be timing out or rejecting requests under load.", s.ErrTotal),
		})
	}

	if len(s.TopCPU) > 0 && s.TopCPU[0].CPUPercent >= 50 {
		findings = append(findings, finding{
			score: int(s.TopCPU[0].CPUPercent) + 15,
			text: fmt.Sprintf("Process: %s (pid %d) is using %.0f%% CPU on its own — a single process is a likely factor.",
				s.TopCPU[0].Name, s.TopCPU[0].PID, s.TopCPU[0].CPUPercent),
		})
	}

	for _, d := range s.Disks {
		if d.UsedPercent >= 90 {
			findings = append(findings, finding{
				score: int(d.UsedPercent),
				text:  fmt.Sprintf("Disk: %s is %.0f%% full — I/O pressure or failed writes are possible.", d.MountPoint, d.UsedPercent),
			})
		}
	}

	if s.FileTotal > 0 {
		findings = append(findings, finding{
			score: s.FileTotal,
			text:  fmt.Sprintf("File changes: %d plugin/theme files modified recently — worth checking this wasn't an unexpected deploy or compromise.", s.FileTotal),
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].score > findings[j].score })

	var texts []string
	for i, f := range findings {
		if i >= 6 {
			break
		}
		texts = append(texts, f.text)
	}

	headline := fmt.Sprintf("Load average %.2f across %d CPU core(s) — %.1fx", peakLoad, numCPU, loadRatio)
	if len(texts) == 0 {
		texts = []string{"No single dominant cause stood out — load looks broadly distributed across normal traffic and background work."}
	}

	return causeAnalysis{Severity: sev, Headline: headline, Findings: texts}
}
