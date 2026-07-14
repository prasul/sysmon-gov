package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"

	"sysmon/metrics"
	"sysmon/report"
)

// dashSnapshot holds the most recently rendered dashboard values so
// that pressing the report key produces a report of "what's
// happening right now" instantly, without waiting for the next
// refresh tick or re-running any collectors.
type dashSnapshot struct {
	Time time.Time

	Host       *metrics.HostInfo
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
}

// recordSnapshot is called at the end of every dashboard refresh
// tick (see refresh() in app.go). It updates the "last known"
// snapshot used by report generation and appends one sample to the
// rolling history buffer used for the report's timeline chart.
func (a *App) recordSnapshot(
	host *metrics.HostInfo,
	load *metrics.LoadAvg,
	mem *metrics.MemoryInfo,
	disks []metrics.DiskInfo,
	cpuPct float64,
	topCPU, topMem []metrics.ProcessInfo,
	topPaths []metrics.NginxPathHit,
	topIPs []metrics.NginxIPHit,
	totalReqs int,
	botHits []metrics.BotHit,
	botTotal int,
	wpHits []metrics.WPLoginHit,
	wpTotal int,
	phpEnts []metrics.PHPSlowEntry,
	phpTotal int,
	ngxErrs []metrics.NginxErrorHit,
	errTotal int,
	mysqlStats *metrics.MySQLStats,
	fileChanges []metrics.WPFileChange,
	fileTotal int,
) {
	now := time.Now()

	a.snapMu.Lock()
	a.snap = dashSnapshot{
		Time:        now,
		Host:        host,
		Load:        load,
		Mem:         mem,
		Disks:       disks,
		CPUPercent:  cpuPct,
		TopCPU:      topCPU,
		TopMem:      topMem,
		NginxPaths:  topPaths,
		NginxIPs:    topIPs,
		NginxTotal:  totalReqs,
		Bots:        botHits,
		BotTotal:    botTotal,
		MySQL:       mysqlStats,
		WPLogin:     wpHits,
		WPTotal:     wpTotal,
		PHPSlow:     phpEnts,
		PHPTotal:    phpTotal,
		NgxErrors:   ngxErrs,
		ErrTotal:    errTotal,
		FileChanges: fileChanges,
		FileTotal:   fileTotal,
	}
	a.snapMu.Unlock()

	if a.deps.History == nil {
		return
	}

	hs := metrics.HistorySample{
		Time:       now,
		CPUPct:     cpuPct,
		ReqTotal:   totalReqs,
		WPLoginHit: wpTotal,
		BotHits:    botTotal,
		PHPSlow:    phpTotal,
		NgxErrors:  errTotal,
	}
	if load != nil {
		hs.Load1 = load.Load1
		hs.Load5 = load.Load5
	}
	if mem != nil {
		hs.MemPct = mem.UsedPercent
	}
	if len(topCPU) > 0 {
		hs.TopCPUProc = topCPU[0].Name
		hs.TopCPUPercent = topCPU[0].CPUPercent
	}
	if len(topMem) > 0 {
		hs.TopMemProc = topMem[0].Name
		hs.TopMemPercent = topMem[0].MemPercent
	}
	if mysqlStats != nil {
		hs.MySQLActive = mysqlStats.ActiveQueries
		hs.MySQLQPS = mysqlStats.QueriesPerSec
	}
	a.deps.History.Record(hs)
}

// generateReport builds an HTML report from the most recent snapshot
// plus the in-memory history buffer, writes it to a.reportDir, and
// flashes the result in the footer. Bound to the 's' key from any
// page.
//
// IMPORTANT: this is invoked synchronously from tview's SetInputCapture
// callback, which runs ON tview's single event-loop goroutine (the same
// goroutine that runs Application.Run()). Calling QueueUpdateDraw from
// that goroutine deadlocks the whole app: QueueUpdateDraw sends a
// closure down a channel that only the event loop itself drains, and
// the event loop can't get back to draining it while it's still up the
// call stack inside this handler. That's why "s" froze the UI —
// flashFooter() (which uses QueueUpdateDraw) was being called directly
// from here.
//
// The fix: do the actual work (snapshot copy is cheap and fine inline,
// but file I/O + template rendering is not) in a background goroutine,
// and use setFooterMessage — a direct, non-queued mutation — for any
// UI update that happens on this goroutine. flashFooter (QueueUpdateDraw)
// is only ever called from the background goroutine below, which is
// exactly what it's designed for.
func (a *App) generateReport() {
	a.snapMu.Lock()
	snap := a.snap
	a.snapMu.Unlock()

	if snap.Time.IsZero() {
		a.setFooterMessage(" collecting data — try again in a couple seconds ", sevYellow)
		return
	}

	// Immediate feedback so the keypress doesn't feel like a no-op
	// while the goroutine below does file I/O.
	a.setFooterMessage(" generating report… ", textAccent)

	go func() {
		var samples []metrics.HistorySample
		if a.deps.History != nil {
			samples = a.deps.History.Samples()
		}

		hostName := "unknown-host"
		if snap.Host != nil && snap.Host.Hostname != "" {
			hostName = snap.Host.Hostname
		}

		in := report.Snapshot{
			GeneratedAt: time.Now(),
			Hostname:    hostName,
			Interval:    a.interval,

			Load:       snap.Load,
			Mem:        snap.Mem,
			Disks:      snap.Disks,
			CPUPercent: snap.CPUPercent,

			TopCPU: snap.TopCPU,
			TopMem: snap.TopMem,

			NginxPaths: snap.NginxPaths,
			NginxIPs:   snap.NginxIPs,
			NginxTotal: snap.NginxTotal,

			Bots:     snap.Bots,
			BotTotal: snap.BotTotal,

			MySQL: snap.MySQL,

			WPLogin: snap.WPLogin,
			WPTotal: snap.WPTotal,

			PHPSlow:  snap.PHPSlow,
			PHPTotal: snap.PHPTotal,

			NgxErrors: snap.NgxErrors,
			ErrTotal:  snap.ErrTotal,

			FileChanges: snap.FileChanges,
			FileTotal:   snap.FileTotal,

			History: samples,
		}

		path, err := report.Generate(in, a.reportDir)
		if err != nil {
			a.flashFooter(fmt.Sprintf(" ✗ report failed: %v ", err), sevRed)
			return
		}
		a.flashFooter(fmt.Sprintf(" ✓ report saved → %s ", path), sevGreen)
	}()
}

// setFooterMessage overwrites the footer immediately. Only call this
// from tview's main goroutine (e.g. directly inside a SetInputCapture
// handler) — it mutates the primitive in place with no locking, which
// is safe there and only there.
func (a *App) setFooterMessage(msg string, color tcell.Color) {
	fmt.Fprintf(a.footer.Clear(), "[%s::b]%s[-:-:-]", cHex(color), msg)
	a.tviewApp.Draw()
}

// flashFooter temporarily overrides the footer with a status message,
// then restores the normal footer after a few seconds. Safe to call
// from ANY goroutine except tview's own event-loop goroutine — it goes
// through QueueUpdateDraw, which needs a goroutine other than the one
// running Application.Run() to be able to marshal the update across.
func (a *App) flashFooter(msg string, color tcell.Color) {
	a.tviewApp.QueueUpdateDraw(func() {
		fmt.Fprintf(a.footer.Clear(), "[%s::b]%s[-:-:-]", cHex(color), msg)
	})
	time.AfterFunc(4*time.Second, func() {
		a.tviewApp.QueueUpdateDraw(a.renderFooter)
	})
}
