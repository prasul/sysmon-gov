// Package ui builds the full-screen terminal dashboard.
package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/prasul/sysmon-gov/metrics"
)

// ── Constants ───────────────────────────────────────────────────────

const (
	maxProcs     = 8
	maxNginxRows = 8
	maxBotRows   = 8
	maxMySQLRows = 8
	maxWPRows    = 8
	maxPHPRows   = 8
	maxFileRows  = 8
	maxErrRows   = 8
)

// ── Deps bundles all collectors injected from main.go ───────────────

type Deps struct {
	Nginx     *metrics.NginxCollector
	Bots      *metrics.BotCollector
	WPLogin   *metrics.WPLoginCollector
	PHPSlow   *metrics.PHPSlowCollector
	MySQL     *metrics.MySQLCollector
	WPFiles   *metrics.WPFileCollector
	NgxErrors *metrics.NginxErrorCollector
	LiveTail  *metrics.LiveTailer
}

// Page names for tview.Pages.
const (
	pageDashboard = "dashboard"
	pageLive      = "live"
)

// ── App ─────────────────────────────────────────────────────────────

type App struct {
	tviewApp    *tview.Application
	interval    time.Duration
	deps        Deps
	blinkTick   int
	currentPage string // tracks which page is visible
	pages       *tview.Pages

	// Dashboard panels
	header       *tview.TextView
	loadView     *tview.TextView
	memView      *tview.TextView
	procCPUTable *tview.Table
	procMemTable *tview.Table
	ngxPathTable *tview.Table
	ngxIPTable   *tview.Table
	botTable     *tview.Table
	mysqlTable   *tview.Table
	wpLoginTable *tview.Table
	phpSlowTable *tview.Table
	wpFilesTable *tview.Table
	ngxErrTable  *tview.Table
	diskTable    *tview.Table
	footer       *tview.TextView

	// Live page panels
	liveHeader    *tview.TextView
	connSummary   *tview.TextView
	synFloodTable *tview.Table
	topConnTable  *tview.Table
	liveTailTable *tview.Table
	liveFooter    *tview.TextView
}

func New(interval time.Duration, deps Deps) *App {
	a := &App{
		tviewApp:    tview.NewApplication(),
		interval:    interval,
		deps:        deps,
		currentPage: pageDashboard,
	}
	a.buildLayout()
	return a
}

func (a *App) Run() error {
	go a.refreshLoop()
	return a.tviewApp.Run()
}

// ── Layout ──────────────────────────────────────────────────────────

func (a *App) buildLayout() {

	// ── Create all panels with themed borders ───────────────────
	a.header = styledTextView(tview.AlignCenter)
	a.header.SetBackgroundColor(barBg)

	a.loadView = styledTextView(tview.AlignLeft)
	applyBorder(a.loadView.Box, " ⚡ Load ", borderSystem, titleSystem)

	a.memView = styledTextView(tview.AlignLeft)
	applyBorder(a.memView.Box, " 🧠 Memory ", borderSystem, titleSystem)

	a.procCPUTable = styledTable()
	applyBorder(a.procCPUTable.Box, " ▲ Top CPU ", borderSystem, titleSystem)

	a.procMemTable = styledTable()
	applyBorder(a.procMemTable.Box, " ▲ Top Memory ", borderSystem, titleSystem)

	a.ngxPathTable = styledTable()
	applyBorder(a.ngxPathTable.Box, " ◆ Top Paths ", borderWeb, titleWeb)

	a.ngxIPTable = styledTable()
	applyBorder(a.ngxIPTable.Box, " ◆ Top IPs ", borderWeb, titleWeb)

	a.botTable = styledTable()
	applyBorder(a.botTable.Box, " ◈ Bot Traffic ", borderWeb, titleWeb)

	a.mysqlTable = styledTable()
	applyBorder(a.mysqlTable.Box, " ◉ MySQL Queries ", borderData, titleData)

	a.wpLoginTable = styledTable()
	applyBorder(a.wpLoginTable.Box, " ✦ WP-Login ", borderSecurity, titleSecurity)

	a.phpSlowTable = styledTable()
	applyBorder(a.phpSlowTable.Box, " ✧ PHP Slow ", borderPerf, titlePerf)

	a.wpFilesTable = styledTable()
	applyBorder(a.wpFilesTable.Box, " ⚑ File Changes (48h) ", borderSecurity, titleSecurity)

	a.ngxErrTable = styledTable()
	applyBorder(a.ngxErrTable.Box, " ✖ Nginx Errors ", borderSecurity, titleSecurity)

	a.diskTable = styledTable()
	applyBorder(a.diskTable.Box, " ▪ Disk ", borderSystem, titleSystem)

	a.footer = styledTextView(tview.AlignCenter)
	a.footer.SetBackgroundColor(barBg)

	// ── Grid ────────────────────────────────────────────────────
	// Row 0: header               (1)
	// Row 1: load + memory        (6)
	// Row 2: procCPU + procMem    (flex)
	// Row 3: ngxPaths + ngxIPs    (flex)
	// Row 4: bots + mysql         (flex)
	// Row 5: wpLogin + phpSlow    (flex)
	// Row 6: wpFiles + ngxErrors  (flex)  ← NEW
	// Row 7: disk                 (5)
	// Row 8: footer               (1)
	grid := tview.NewGrid().
		SetRows(1, 6, 0, 0, 0, 0, 0, 5, 1).
		SetColumns(0, 0).
		SetBorders(false)

	grid.AddItem(a.header, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.loadView, 1, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.memView, 1, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.procCPUTable, 2, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.procMemTable, 2, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.ngxPathTable, 3, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.ngxIPTable, 3, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.botTable, 4, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.mysqlTable, 4, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.wpLoginTable, 5, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.phpSlowTable, 5, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.wpFilesTable, 6, 0, 1, 1, 0, 0, false) // ← NEW
	grid.AddItem(a.ngxErrTable, 6, 1, 1, 1, 0, 0, false)  // ← NEW
	grid.AddItem(a.diskTable, 7, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.footer, 8, 0, 1, 2, 0, 0, false)

	// ── Build the live page ─────────────────────────────────────
	liveGrid := a.buildLivePage()

	// ── Pages container ─────────────────────────────────────────
	a.pages = tview.NewPages().
		AddPage(pageDashboard, grid, true, true).
		AddPage(pageLive, liveGrid, true, false)

	// ── Global keybindings ──────────────────────────────────────
	a.tviewApp.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch {
		case event.Rune() == 'q' || event.Key() == tcell.KeyCtrlC:
			a.tviewApp.Stop()
			return nil

		case event.Rune() == 'l' || event.Rune() == 'L':
			// Switch to live view.
			a.currentPage = pageLive
			a.pages.SwitchToPage(pageLive)
			return nil

		case event.Key() == tcell.KeyEscape || event.Rune() == 'd' || event.Rune() == 'D':
			// Switch back to dashboard (only from live page).
			if a.currentPage == pageLive {
				a.currentPage = pageDashboard
				a.pages.SwitchToPage(pageDashboard)
				return nil
			}

		case event.Key() == tcell.KeyLeft:
			if a.currentPage == pageLive {
				a.currentPage = pageDashboard
				a.pages.SwitchToPage(pageDashboard)
				return nil
			}

		case event.Key() == tcell.KeyRight:
			if a.currentPage == pageDashboard {
				a.currentPage = pageLive
				a.pages.SwitchToPage(pageLive)
				return nil
			}
		}
		return event
	})

	a.tviewApp.SetRoot(a.pages, true)
}

// ── Refresh ─────────────────────────────────────────────────────────

func (a *App) refreshLoop() {
	a.doRefresh()
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for range ticker.C {
		a.doRefresh()
	}
}

// doRefresh dispatches to the correct page's refresh.
// Only the visible page is updated — saves CPU.
func (a *App) doRefresh() {
	switch a.currentPage {
	case pageLive:
		a.refreshLive()
	default:
		a.refresh()
	}
}

func (a *App) refresh() {
	a.blinkTick++

	// System
	host, _ := metrics.GetHostInfo()
	load, _ := metrics.GetLoadAvg()
	mem, _ := metrics.GetMemoryInfo()
	disks, _ := metrics.GetDiskUsage()
	topCPU, topMem, _ := metrics.GetTopProcesses(maxProcs)

	// Nginx + Bots
	if a.deps.Nginx != nil {
		a.deps.Nginx.Collect()
	}
	if a.deps.Bots != nil {
		a.deps.Bots.Collect()
	}
	var topPaths []metrics.NginxPathHit
	var topIPs []metrics.NginxIPHit
	var totalReqs int
	if a.deps.Nginx != nil {
		topPaths = a.deps.Nginx.TopPaths(maxNginxRows)
		topIPs = a.deps.Nginx.TopIPs(maxNginxRows)
		totalReqs = a.deps.Nginx.TotalRequests()
	}
	var botHits []metrics.BotHit
	var botTotal int
	if a.deps.Bots != nil {
		botHits = a.deps.Bots.TopBots(maxBotRows)
		botTotal = a.deps.Bots.TotalBotHits()
	}

	// MySQL
	var mysqlStats *metrics.MySQLStats
	if a.deps.MySQL != nil && a.deps.MySQL.IsEnabled() {
		mysqlStats = a.deps.MySQL.Collect()
	}

	// WP-Login + PHP Slow
	if a.deps.WPLogin != nil {
		a.deps.WPLogin.Collect()
	}
	if a.deps.PHPSlow != nil {
		a.deps.PHPSlow.Collect()
	}
	var wpHits []metrics.WPLoginHit
	var wpTotal int
	var wpLive bool
	if a.deps.WPLogin != nil {
		wpHits = a.deps.WPLogin.TopHits(maxWPRows)
		wpTotal = a.deps.WPLogin.TotalHits()
		wpLive = a.deps.WPLogin.HasLiveAttack()
	}
	var phpEntries []metrics.PHPSlowEntry
	var phpTotal int
	if a.deps.PHPSlow != nil {
		phpEntries = a.deps.PHPSlow.TopEntries(maxPHPRows)
		phpTotal = a.deps.PHPSlow.TotalEntries()
	}

	// WP File Changes
	if a.deps.WPFiles != nil {
		a.deps.WPFiles.Collect()
	}
	var fileChanges []metrics.WPFileChange
	var fileTotal int
	if a.deps.WPFiles != nil {
		fileChanges = a.deps.WPFiles.TopChanges(maxFileRows)
		fileTotal = a.deps.WPFiles.TotalChanges()
	}

	// Nginx Errors
	if a.deps.NgxErrors != nil {
		a.deps.NgxErrors.Collect()
	}
	var ngxErrors []metrics.NginxErrorHit
	var errTotal int
	if a.deps.NgxErrors != nil {
		ngxErrors = a.deps.NgxErrors.TopErrors(maxErrRows)
		errTotal = a.deps.NgxErrors.TotalErrors()
	}

	a.tviewApp.QueueUpdateDraw(func() {
		a.renderHeader(host)
		a.renderLoad(load, host)
		a.renderMemory(mem)
		a.renderProcCPU(topCPU)
		a.renderProcMem(topMem)
		a.renderNginxPaths(topPaths, totalReqs)
		a.renderNginxIPs(topIPs)
		a.renderBots(botHits, botTotal)
		a.renderMySQL(mysqlStats)
		a.renderWPLogin(wpHits, wpTotal, wpLive)
		a.renderPHPSlow(phpEntries, phpTotal)
		a.renderWPFiles(fileChanges, fileTotal)
		a.renderNgxErrors(ngxErrors, errTotal)
		a.renderDisk(disks)
		a.renderFooter()
	})
}

// ═══════════════════════════════════════════════════════════════════
//  RENDERERS
// ═══════════════════════════════════════════════════════════════════

// ── Header ──────────────────────────────────────────────────────────

func (a *App) renderHeader(h *metrics.HostInfo) {
	if h == nil {
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(a.header.Clear(),
		"[::b] ■ SYSMON[::-]  [%s]│[-]  %s  [%s]│[-]  Kernel %s  [%s]│[-]  %s ",
		cHex(textSecondary), h.Hostname, cHex(textSecondary), h.Kernel, cHex(textSecondary), now,
	)
}

// ── Load ────────────────────────────────────────────────────────────

func (a *App) renderLoad(l *metrics.LoadAvg, h *metrics.HostInfo) {
	a.loadView.Clear()
	if l == nil {
		return
	}
	uptime := "N/A"
	if h != nil {
		uptime = metrics.FormatUptime(h.Uptime)
	}

	cl := func(v float64) string {
		c := sevGreen
		if v >= 4.0 {
			c = sevRed
		} else if v >= 2.0 {
			c = sevYellow
		}
		return fmt.Sprintf("[%s::b]%.2f[-:-:-]", cHex(c), v)
	}

	fmt.Fprintf(a.loadView,
		"\n [::b]1m[-:-:-] %s  [::b]5m[-:-:-] %s  [::b]15m[-:-:-] %s\n [::b]Procs[-:-:-] [%s]%d[-] run / [%s]%d[-] total  [::b]Up[-:-:-] [%s]%s[-]",
		cl(l.Load1), cl(l.Load5), cl(l.Load15),
		cHex(textAccent), l.RunningProcs, cHex(textAccent), l.TotalProcs,
		cHex(textAccent), uptime,
	)
}

// ── Memory ──────────────────────────────────────────────────────────

func (a *App) renderMemory(m *metrics.MemoryInfo) {
	a.memView.Clear()
	if m == nil {
		return
	}
	fmt.Fprintf(a.memView,
		"\n [::b]RAM[-:-:-]  %s  [%s]%d[-] / %d MB  [%s]%.1f%%[-]\n [::b]Swap[-:-:-] %s  [%s]%d[-] / %d MB  [%s]%.1f%%[-]",
		themedBar(m.UsedPercent, 20), cHex(textAccent), m.UsedMB, m.TotalMB, cHex(sevColor(m.UsedPercent)), m.UsedPercent,
		themedBar(m.SwapUsedPercent, 20), cHex(textAccent), m.SwapUsedMB, m.SwapTotalMB, cHex(sevColor(m.SwapUsedPercent)), m.SwapUsedPercent,
	)
}

// ── Process tables ──────────────────────────────────────────────────

func (a *App) renderProcCPU(procs []metrics.ProcessInfo) {
	a.procCPUTable.Clear()
	setHeaders(a.procCPUTable, " #", "Process", "PID", "CPU%", "")
	if len(procs) == 0 {
		a.procCPUTable.SetCell(1, 1, cellMuted("  collecting…"))
		return
	}
	for i, p := range procs {
		r := i + 1
		a.procCPUTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.procCPUTable.SetCell(r, 1, cellPrimary(truncate(p.Name, 18)))
		a.procCPUTable.SetCell(r, 2, cellAccent(fmt.Sprintf("%d", p.PID)))
		a.procCPUTable.SetCell(r, 3, cellSev(fmt.Sprintf("%.1f%%", p.CPUPercent), p.CPUPercent))
		a.procCPUTable.SetCell(r, 4, tview.NewTableCell(plainBar(p.CPUPercent, 12)).SetExpansion(1).SetTextColor(sevColor(p.CPUPercent)))
	}
}

func (a *App) renderProcMem(procs []metrics.ProcessInfo) {
	a.procMemTable.Clear()
	setHeaders(a.procMemTable, " #", "Process", "PID", "MB", "MEM%", "")
	if len(procs) == 0 {
		a.procMemTable.SetCell(1, 1, cellMuted("  collecting…"))
		return
	}
	for i, p := range procs {
		r := i + 1
		a.procMemTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.procMemTable.SetCell(r, 1, cellPrimary(truncate(p.Name, 18)))
		a.procMemTable.SetCell(r, 2, cellAccent(fmt.Sprintf("%d", p.PID)))
		a.procMemTable.SetCell(r, 3, cellPrimary(fmt.Sprintf("%.0f", p.MemMB)))
		a.procMemTable.SetCell(r, 4, cellSev(fmt.Sprintf("%.1f%%", p.MemPercent), p.MemPercent))
		a.procMemTable.SetCell(r, 5, tview.NewTableCell(plainBar(p.MemPercent, 10)).SetExpansion(1).SetTextColor(sevColor(p.MemPercent)))
	}
}

// ── Nginx tables ────────────────────────────────────────────────────

func (a *App) renderNginxPaths(paths []metrics.NginxPathHit, total int) {
	a.ngxPathTable.Clear()
	if total > 0 {
		a.ngxPathTable.SetTitle(fmt.Sprintf(" ◆ Top Paths  [%s] ", fmtCount(total)))
	}
	setHeaders(a.ngxPathTable, " #", "Hits", "Domain", "Path")
	if len(paths) == 0 {
		a.ngxPathTable.SetCell(1, 2, cellMuted("  no data"))
		return
	}
	for i, p := range paths {
		r := i + 1
		a.ngxPathTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.ngxPathTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", p.Count), p.Count, paths[0].Count))
		a.ngxPathTable.SetCell(r, 2, cellAccent(truncate(p.Domain, 20)))
		a.ngxPathTable.SetCell(r, 3, tview.NewTableCell(truncate(p.Path, 36)).SetTextColor(textPrimary).SetExpansion(1))
	}
}

func (a *App) renderNginxIPs(ips []metrics.NginxIPHit) {
	a.ngxIPTable.Clear()
	setHeaders(a.ngxIPTable, " #", "Hits", "Domain", "IP Address", "CC")
	if len(ips) == 0 {
		a.ngxIPTable.SetCell(1, 2, cellMuted("  no data"))
		return
	}
	for i, p := range ips {
		r := i + 1
		a.ngxIPTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.ngxIPTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", p.Count), p.Count, ips[0].Count))
		a.ngxIPTable.SetCell(r, 2, cellAccent(truncate(p.Domain, 18)))
		a.ngxIPTable.SetCell(r, 3, cellPrimary(p.IP))
		cc := textMuted
		if p.Country != "—" {
			cc = titleWeb
		}
		a.ngxIPTable.SetCell(r, 4, tview.NewTableCell(p.Country).SetTextColor(cc).SetAttributes(tcell.AttrBold))
	}
}

// ── Bot Traffic ─────────────────────────────────────────────────────

func (a *App) renderBots(bots []metrics.BotHit, total int) {
	a.botTable.Clear()
	if total > 0 {
		a.botTable.SetTitle(fmt.Sprintf(" ◈ Bot Traffic  [%s] ", fmtCount(total)))
	}
	setHeaders(a.botTable, " #", "Hits", "Bot", "Type", "Domain", "Top Path")
	if len(bots) == 0 {
		a.botTable.SetCell(1, 2, cellMuted("  no bots detected"))
		return
	}
	for i, b := range bots {
		r := i + 1
		a.botTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.botTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", b.Count), b.Count, bots[0].Count))

		// Bot name — colored by type for instant visual classification.
		nameColor := botTypeColor(b.BotType)
		a.botTable.SetCell(r, 2,
			tview.NewTableCell(b.BotName).SetTextColor(nameColor).SetAttributes(tcell.AttrBold))

		// Type tag — compact label.
		tag := strings.ToUpper(b.BotType)
		a.botTable.SetCell(r, 3,
			tview.NewTableCell(tag).SetTextColor(nameColor))

		a.botTable.SetCell(r, 4, cellAccent(truncate(b.Domain, 18)))
		a.botTable.SetCell(r, 5,
			tview.NewTableCell(truncate(b.TopPath, 28)).SetTextColor(textPrimary).SetExpansion(1))
	}
}

// ── MySQL Queries ───────────────────────────────────────────────────

func (a *App) renderMySQL(stats *metrics.MySQLStats) {
	a.mysqlTable.Clear()

	// Check connection status for disabled / error states.
	if a.deps.MySQL == nil || !a.deps.MySQL.IsEnabled() {
		setHeaders(a.mysqlTable, "")
		a.mysqlTable.SetCell(1, 0, cellMuted("  MySQL disabled — no .my.cnf or socket found"))
		a.mysqlTable.SetCell(2, 0, cellMuted("  use: -mysql-dsn, -mysql-cnf, or -mysql-socket"))
		return
	}

	connected, errMsg, dsnDisplay := a.deps.MySQL.Status()
	if !connected {
		setHeaders(a.mysqlTable, "")
		msg := "  connecting…"
		if errMsg != "" {
			msg = fmt.Sprintf("  ✗ %s", truncate(errMsg, 55))
		}
		a.mysqlTable.SetCell(1, 0, cellMuted(msg))
		if dsnDisplay != "" {
			a.mysqlTable.SetCell(2, 0, cellMuted(fmt.Sprintf("  DSN: %s", truncate(dsnDisplay, 55))))
		}
		return
	}

	if stats == nil {
		return
	}

	// Rich title with server stats: connections, QPS, slow queries.
	a.mysqlTable.SetTitle(fmt.Sprintf(
		" ◉ MySQL  [%d conn / %d active / %.0f qps / %d slow] ",
		stats.TotalConnections, stats.ActiveQueries,
		stats.QueriesPerSec, stats.SlowQueries))

	setHeaders(a.mysqlTable, " ID", "User", "DB", "Time", "State", "Query")

	if len(stats.Processes) == 0 {
		a.mysqlTable.SetCell(1, 4, cellMuted("  all idle"))
		return
	}

	limit := maxMySQLRows
	if len(stats.Processes) < limit {
		limit = len(stats.Processes)
	}

	for i := 0; i < limit; i++ {
		p := stats.Processes[i]
		r := i + 1

		a.mysqlTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", p.ID)))
		a.mysqlTable.SetCell(r, 1, cellAccent(truncate(p.User, 12)))
		a.mysqlTable.SetCell(r, 2, cellPrimary(truncate(p.DB, 14)))

		// Time — color by duration: >10s red, >3s yellow, else green.
		timeColor := sevGreen
		if p.TimeSec >= 10 {
			timeColor = sevRed
		} else if p.TimeSec >= 3 {
			timeColor = sevYellow
		}
		a.mysqlTable.SetCell(r, 3,
			tview.NewTableCell(fmt.Sprintf("%ds", p.TimeSec)).
				SetTextColor(timeColor).SetAttributes(tcell.AttrBold))

		a.mysqlTable.SetCell(r, 4,
			tview.NewTableCell(truncate(p.State, 16)).SetTextColor(mysqlTime))

		a.mysqlTable.SetCell(r, 5,
			tview.NewTableCell(truncate(p.Query, 50)).SetTextColor(mysqlQuery).SetExpansion(1))
	}
}

// ── WP-Login Attacks ────────────────────────────────────────────────

func (a *App) renderWPLogin(hits []metrics.WPLoginHit, total int, live bool) {
	a.wpLoginTable.Clear()

	// Dynamic title + blinking border.
	title := " ✦ WP-Login "
	bc := borderSecurity
	if live {
		if a.blinkTick%2 == 0 {
			title = " ✦ WP-Login  ● LIVE ATTACK "
			bc = accentLive
		} else {
			title = " ✦ WP-Login  ○ LIVE ATTACK "
			bc = accentLiveDim
		}
	}
	if total > 0 {
		title = fmt.Sprintf("%s [%s] ", title, fmtCount(total))
	}
	a.wpLoginTable.SetTitle(title).SetBorderColor(bc)

	setHeaders(a.wpLoginTable, " #", "Hits", "Domain", "IP", "CC", "Seen", "")
	if len(hits) == 0 {
		a.wpLoginTable.SetCell(1, 2,
			tview.NewTableCell("  no wp-login hits").SetTextColor(sevGreen))
		return
	}

	for i, h := range hits {
		r := i + 1
		a.wpLoginTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.wpLoginTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", h.Count), h.Count, hits[0].Count))
		a.wpLoginTable.SetCell(r, 2, cellAccent(truncate(h.Domain, 18)))
		a.wpLoginTable.SetCell(r, 3, cellPrimary(h.IP))

		cc := textMuted
		if h.Country != "—" {
			cc = titleWeb
		}
		a.wpLoginTable.SetCell(r, 4, tview.NewTableCell(h.Country).SetTextColor(cc).SetAttributes(tcell.AttrBold))

		// Last seen — relative time with severity coloring.
		age := time.Since(h.LastSeen)
		seenStr := h.LastSeen.Format("15:04:05")
		seenColor := textPrimary
		if age < 2*time.Minute {
			seenStr = fmtDuration(age) + " ago"
			seenColor = sevRed
		} else if age < 30*time.Minute {
			seenStr = fmtDuration(age) + " ago"
			seenColor = sevYellow
		}
		a.wpLoginTable.SetCell(r, 5,
			tview.NewTableCell(seenStr).SetTextColor(seenColor))

		// Live indicator.
		if h.IsLive {
			dot, dc := "●", accentLive
			if a.blinkTick%2 == 1 {
				dot, dc = "○", accentLiveDim
			}
			a.wpLoginTable.SetCell(r, 6,
				tview.NewTableCell(" "+dot).SetTextColor(dc).SetAttributes(tcell.AttrBold))
		} else {
			a.wpLoginTable.SetCell(r, 6, cellDim(""))
		}
	}
}

// ── PHP Slow Log ────────────────────────────────────────────────────

func (a *App) renderPHPSlow(entries []metrics.PHPSlowEntry, total int) {
	a.phpSlowTable.Clear()
	if total > 0 {
		a.phpSlowTable.SetTitle(fmt.Sprintf(" ✧ PHP Slow  [%s] ", fmtCount(total)))
	}

	setHeaders(a.phpSlowTable, " #", "Count", "Domain", "Plugin", "Function")
	if len(entries) == 0 {
		a.phpSlowTable.SetCell(1, 2, cellMuted("  no slow entries"))
		return
	}

	for i, e := range entries {
		r := i + 1
		a.phpSlowTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.phpSlowTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", e.Count), e.Count, entries[0].Count))
		a.phpSlowTable.SetCell(r, 2, cellAccent(truncate(e.Domain, 18)))

		pc := accentPlugin
		if e.Plugin == "(core/other)" {
			pc = textMuted
		}
		a.phpSlowTable.SetCell(r, 3,
			tview.NewTableCell(truncate(e.Plugin, 18)).SetTextColor(pc).SetAttributes(tcell.AttrBold))

		fc := accentFunction
		if e.Function == "(unknown)" {
			fc = textMuted
		}
		a.phpSlowTable.SetCell(r, 4,
			tview.NewTableCell(truncate(e.Function, 22)).SetTextColor(fc).SetExpansion(1))
	}
}

// ── WP File Changes ─────────────────────────────────────────────────

// renderWPFiles shows plugins/themes with recently modified code files.
// Columns: # │ Count │ Domain │ Plugin/Theme │ Last Changed
func (a *App) renderWPFiles(changes []metrics.WPFileChange, total int) {
	a.wpFilesTable.Clear()
	if total > 0 {
		a.wpFilesTable.SetTitle(fmt.Sprintf(" ⚑ File Changes  [%d files] ", total))
	}

	setHeaders(a.wpFilesTable, " #", "Files", "Domain", "Plugin/Theme", "Last Changed")
	if len(changes) == 0 {
		a.wpFilesTable.SetCell(1, 2, cellMuted("  no recent changes"))
		return
	}

	for i, c := range changes {
		r := i + 1
		a.wpFilesTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))

		// File count — higher counts are more suspicious.
		a.wpFilesTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", c.Count), c.Count, changes[0].Count))

		// Domain
		a.wpFilesTable.SetCell(r, 2, cellAccent(truncate(c.Domain, 18)))

		// Plugin/theme name with type indicator.
		tag := "P"
		if c.Kind == "theme" {
			tag = "T"
		}
		nameStr := fmt.Sprintf("[%s] %s", tag, c.Name)
		nameColor := accentPlugin
		a.wpFilesTable.SetCell(r, 3,
			tview.NewTableCell(truncate(nameStr, 22)).
				SetTextColor(nameColor).SetAttributes(tcell.AttrBold))

		// Last change — relative time with coloring.
		age := time.Since(c.LastChange)
		ageStr := c.LastChange.Format("Jan 02 15:04")
		ageColor := textPrimary
		if age < 2*time.Hour {
			ageStr = fmtDuration(age) + " ago"
			ageColor = sevRed
		} else if age < 12*time.Hour {
			ageStr = fmtDuration(age) + " ago"
			ageColor = sevYellow
		}
		a.wpFilesTable.SetCell(r, 4,
			tview.NewTableCell(ageStr).SetTextColor(ageColor).SetExpansion(1))
	}
}

// ── Nginx Errors ────────────────────────────────────────────────────

// renderNgxErrors shows top nginx error log patterns.
// Columns: # │ Count │ Domain │ Path │ IP │ Error
func (a *App) renderNgxErrors(errors []metrics.NginxErrorHit, total int) {
	a.ngxErrTable.Clear()
	if total > 0 {
		a.ngxErrTable.SetTitle(fmt.Sprintf(" ✖ Nginx Errors  [%s] ", fmtCount(total)))
	}

	setHeaders(a.ngxErrTable, " #", "Hits", "Domain", "Path", "IP", "Error")
	if len(errors) == 0 {
		a.ngxErrTable.SetCell(1, 2, cellMuted("  no errors"))
		return
	}

	for i, e := range errors {
		r := i + 1
		a.ngxErrTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.ngxErrTable.SetCell(r, 1, cellHeat(fmt.Sprintf("%d", e.Count), e.Count, errors[0].Count))
		a.ngxErrTable.SetCell(r, 2, cellAccent(truncate(e.Domain, 16)))
		a.ngxErrTable.SetCell(r, 3, cellPrimary(truncate(e.Path, 26)))
		a.ngxErrTable.SetCell(r, 4, cellPrimary(truncate(e.IP, 16)))

		// Error type — color by severity.
		errColor := sevYellow
		switch e.Error {
		case "forbidden", "perm denied":
			errColor = sevRed
		case "not found", "no index":
			errColor = textSecondary
		case "timeout", "conn refused", "conn reset", "upstream err":
			errColor = sevRed
		}
		a.ngxErrTable.SetCell(r, 5,
			tview.NewTableCell(e.Error).SetTextColor(errColor).
				SetAttributes(tcell.AttrBold).SetExpansion(1))
	}
}

// ── Disk ────────────────────────────────────────────────────────────

func (a *App) renderDisk(disks []metrics.DiskInfo) {
	a.diskTable.Clear()
	if disks == nil {
		return
	}
	setHeaders(a.diskTable, " Device", "Mount", "Total", "Used", "Avail", "Use%", "")
	for i, d := range disks {
		r := i + 1
		a.diskTable.SetCell(r, 0, cellPrimary(" "+truncate(d.Device, 16)))
		a.diskTable.SetCell(r, 1, cellAccent(truncate(d.MountPoint, 14)))
		a.diskTable.SetCell(r, 2, cellPrimary(fmt.Sprintf("%.1fG", d.TotalGB)))
		a.diskTable.SetCell(r, 3, cellPrimary(fmt.Sprintf("%.1fG", d.UsedGB)))
		a.diskTable.SetCell(r, 4, cellPrimary(fmt.Sprintf("%.1fG", d.AvailGB)))
		a.diskTable.SetCell(r, 5, cellSev(fmt.Sprintf("%.0f%%", d.UsedPercent), d.UsedPercent))
		a.diskTable.SetCell(r, 6,
			tview.NewTableCell(plainBar(d.UsedPercent, 16)).SetTextColor(sevColor(d.UsedPercent)).SetExpansion(1))
	}
}

// ── Footer ──────────────────────────────────────────────────────────

func (a *App) renderFooter() {
	fmt.Fprintf(a.footer.Clear(),
		" [%s::b]q[-:-:-] quit  [%s]│[-]  [%s::b]L[-:-:-] / [%s::b]→[-:-:-] live view  [%s]│[-]  refresh [%s::b]%s[-:-:-]  [%s]│[-]  [%s]sysmon[-]",
		cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(sevYellow), cHex(textSecondary),
		cHex(textAccent), a.interval,
		cHex(textSecondary), cHex(textMuted),
	)
}

// ═══════════════════════════════════════════════════════════════════
//  WIDGET FACTORIES
// ═══════════════════════════════════════════════════════════════════

func styledTextView(align int) *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetTextAlign(align)
	return tv
}

func styledTable() *tview.Table {
	return tview.NewTable().SetBorders(false).SetSelectable(false, false)
}

func applyBorder(box *tview.Box, title string, border, titleC tcell.Color) {
	box.SetBorder(true).
		SetBorderColor(border).
		SetTitle(title).
		SetTitleColor(titleC).
		SetTitleAlign(tview.AlignLeft)
}

// ═══════════════════════════════════════════════════════════════════
//  CELL FACTORIES
// ═══════════════════════════════════════════════════════════════════

func setHeaders(t *tview.Table, headers ...string) {
	for c, h := range headers {
		t.SetCell(0, c,
			tview.NewTableCell(h).
				SetTextColor(textSecondary).
				SetAttributes(tcell.AttrBold).
				SetSelectable(false))
	}
}

func cellDim(s string) *tview.TableCell {
	return tview.NewTableCell(s).SetTextColor(textSecondary)
}
func cellMuted(s string) *tview.TableCell {
	return tview.NewTableCell(s).SetTextColor(textMuted)
}
func cellPrimary(s string) *tview.TableCell {
	return tview.NewTableCell(s).SetTextColor(textPrimary)
}
func cellAccent(s string) *tview.TableCell {
	return tview.NewTableCell(s).SetTextColor(textAccent)
}
func cellSev(s string, pct float64) *tview.TableCell {
	return tview.NewTableCell(s).SetTextColor(sevColor(pct)).SetAttributes(tcell.AttrBold)
}
func cellHeat(s string, count, maxCount int) *tview.TableCell {
	return tview.NewTableCell(s).SetTextColor(heatColor(count, maxCount)).SetAttributes(tcell.AttrBold)
}

// ═══════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════

func sevColor(pct float64) tcell.Color {
	if pct >= 90 {
		return sevRed
	}
	if pct >= 70 {
		return sevYellow
	}
	return sevGreen
}

func heatColor(count, max int) tcell.Color {
	if max <= 0 {
		return sevGreen
	}
	r := float64(count) / float64(max)
	if r >= 0.75 {
		return sevRed
	}
	if r >= 0.40 {
		return sevYellow
	}
	return sevGreen
}

func botTypeColor(t string) tcell.Color {
	switch t {
	case "ai":
		return botAI
	case "search":
		return botSearch
	case "social":
		return botSocial
	case "monitor":
		return botMonitor
	default:
		return botOther
	}
}

// themedBar renders a colored bar for TextViews using tview tags.
func themedBar(pct float64, width int) string {
	filled := int(pct / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	c := cHex(sevColor(pct))
	return fmt.Sprintf("[%s]%s[%s]%s[-]",
		c, strings.Repeat(barFilled, filled),
		cHex(textMuted), strings.Repeat(barEmpty, width-filled))
}

// plainBar renders a bar for Table cells (no tview color tags).
func plainBar(pct float64, width int) string {
	filled := int(pct / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	return strings.Repeat(barFilled, filled) + strings.Repeat(barEmpty, width-filled)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return s[:max-1] + "…"
}

func fmtCount(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func fmtDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// cHex converts a tcell.Color to a tview hex color string "#rrggbb".
func cHex(c tcell.Color) string {
	r, g, b := c.RGB()
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}
