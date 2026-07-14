package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gdamore/tcell/v2"

	"sysmon/metrics"
	"sysmon/report"
)

// dashSnapshot holds the most recently rendered dashboard values so
// that pressing the report key produces a report of "what's
// happening right now" instantly, without waiting for (or re-running)
// a fresh collection cycle.
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

// reportJob is what gets queued when 's' is pressed. Building it
// (copying a.snap, reading the history buffer) is cheap, in-memory,
// and safe to do inline on tview's event-loop goroutine. Everything
// that follows — disk I/O, JSON encoding, SVG/HTML rendering — must
// never happen there, so it's handed off to reportWorker() instead.
type reportJob struct {
	requestedAt time.Time
	snapshot    dashSnapshot
	history     []metrics.HistorySample
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

// generateReport is bound to the 's' key. SetInputCapture callbacks
// always run ON tview's single event-loop goroutine, so this must
// return almost immediately and must never call anything that blocks
// on that same goroutine making progress — no QueueUpdateDraw, no
// Draw(), nothing that waits on a channel or lock the event loop
// itself needs in order to continue.
//
// All the real work — writing the raw JSON dump, building SVG charts,
// rendering the HTML file — happens on reportWorker's own goroutine,
// started once (for the life of the process) from Run(). This handler
// only copies the already-cached snapshot (cheap, in-memory, guarded
// by snapMu — safe here) and hands it off over a channel.
func (a *App) generateReport() {
	a.snapMu.Lock()
	snap := a.snap
	a.snapMu.Unlock()

	if snap.Time.IsZero() {
		a.setFooterMessage(" collecting data — try again in a couple seconds ", sevYellow)
		return
	}

	var samples []metrics.HistorySample
	if a.deps.History != nil {
		samples = a.deps.History.Samples()
	}

	job := reportJob{
		requestedAt: time.Now(),
		snapshot:    snap,
		history:     samples,
	}

	select {
	case a.reportQueue <- job:
		a.setFooterMessage(" queued report… ", textAccent)
	default:
		// The worker is still processing a previous request — never
		// block the event loop waiting for room in the queue.
		a.setFooterMessage(" a report is already generating — try again in a moment ", sevYellow)
	}
}

// reportWorker drains reportQueue for the lifetime of the process, on
// its own goroutine, entirely decoupled from tview. It's the only
// place report generation actually happens.
func (a *App) reportWorker() {
	for job := range a.reportQueue {
		a.processReportJob(job)
	}
}

// processReportJob writes the raw snapshot to disk as JSON, then
// renders the HTML report from it. Runs on reportWorker's goroutine —
// never on tview's event-loop goroutine — so flashFooter() (which
// uses QueueUpdateDraw) is safe to call here.
func (a *App) processReportJob(job reportJob) {
	dir := a.reportDir
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		a.flashFooter(fmt.Sprintf(" ✗ report failed: could not create %s: %v ", dir, err), sevRed)
		return
	}

	stamp := job.requestedAt.Format("2006-01-02_15-04-05")

	// ── Raw data dump ────────────────────────────────────────────
	// Written first and independently of HTML rendering, so a bug in
	// the template/chart code never costs you the underlying data.
	// This is the permanent, re-processable record of exactly what
	// sysmon saw at the moment "s" was pressed — every collector's
	// full output plus the in-memory history buffer, unfiltered.
	rawPath := filepath.Join(dir, fmt.Sprintf("sysmon-raw-%s.json", stamp))
	dump := struct {
		SavedAt  time.Time               `json:"saved_at"`
		Snapshot dashSnapshot            `json:"snapshot"`
		History  []metrics.HistorySample `json:"history"`
	}{
		SavedAt:  job.requestedAt,
		Snapshot: job.snapshot,
		History:  job.history,
	}
	rawOK := false
	if raw, err := json.MarshalIndent(dump, "", "  "); err == nil {
		if err := os.WriteFile(rawPath, raw, 0o644); err == nil {
			rawOK = true
		}
	}

	// ── HTML report ──────────────────────────────────────────────
	snap := job.snapshot
	hostName := "unknown-host"
	if snap.Host != nil && snap.Host.Hostname != "" {
		hostName = snap.Host.Hostname
	}

	in := report.Snapshot{
		GeneratedAt: job.requestedAt,
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

		History: job.history,
	}

	htmlPath, err := report.Generate(in, dir)
	if err != nil {
		if rawOK {
			a.flashFooter(fmt.Sprintf(" ✗ html render failed (raw data saved → %s): %v ", rawPath, err), sevRed)
		} else {
			a.flashFooter(fmt.Sprintf(" ✗ report failed: %v ", err), sevRed)
		}
		return
	}
	a.flashFooter(fmt.Sprintf(" ✓ report saved → %s ", htmlPath), sevGreen)
}

// setFooterMessage overwrites the footer immediately with a direct,
// un-queued mutation of the TextView's contents. Only ever call this
// from tview's own event-loop goroutine (e.g. straight from a
// SetInputCapture handler, as generateReport does above).
//
// Deliberately does NOT call Draw() afterward: tview redraws
// automatically once its event loop finishes handling the current
// input event, and calling Draw() (or QueueUpdateDraw, or anything
// else that touches Application's internal locking/channels)
// synchronously from inside a handler tview is already dispatching is
// exactly what caused the freeze — twice now. Plain field mutation
// here is safe because it's the same pattern the existing b/u/:
// handlers already use (e.g. a.pages.SwitchToPage(...) elsewhere in
// this file's switch statement) without any issue.
func (a *App) setFooterMessage(msg string, color tcell.Color) {
	fmt.Fprintf(a.footer.Clear(), "[%s::b]%s[-:-:-]", cHex(color), msg)
}

// flashFooter temporarily overrides the footer with a status message,
// then restores the normal footer after a few seconds. Only call this
// from a goroutine OTHER than tview's event-loop goroutine (e.g. from
// reportWorker, as above) — that's what QueueUpdateDraw requires to
// marshal the update across without deadlocking against itself.
func (a *App) flashFooter(msg string, color tcell.Color) {
	a.tviewApp.QueueUpdateDraw(func() {
		fmt.Fprintf(a.footer.Clear(), "[%s::b]%s[-:-:-]", cHex(color), msg)
	})
	time.AfterFunc(4*time.Second, func() {
		a.tviewApp.QueueUpdateDraw(a.renderFooter)
	})
}
