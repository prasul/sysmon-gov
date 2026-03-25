package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/prasul/sysmon-gov/metrics"
)

// maxLiveRows is how many log entries we display in the tail view.
const maxLiveRows = 60

// buildLivePage creates the live-view layout.  Called once during
// buildLayout().  Returns the root primitive for this page.
func (a *App) buildLivePage() tview.Primitive {

	// ── Header bar ──────────────────────────────────────────────
	a.liveHeader = styledTextView(tview.AlignCenter)
	a.liveHeader.SetBackgroundColor(barBg)

	// ── Connection summary bar ──────────────────────────────────
	a.connSummary = styledTextView(tview.AlignLeft)
	applyBorder(a.connSummary.Box, " ⚡ TCP Connections ", borderSystem, titleSystem)

	// ── SYN Flood / Top Connections (left) ──────────────────────
	a.synFloodTable = styledTable()
	applyBorder(a.synFloodTable.Box, " ⚠ SYN Flood Monitor ", borderSecurity, titleSecurity)

	// ── Top Connections (right) ─────────────────────────────────
	a.topConnTable = styledTable()
	applyBorder(a.topConnTable.Box, " ◆ Top Connections ", borderWeb, titleWeb)

	// ── Live Log Tail ───────────────────────────────────────────
	a.liveTailTable = styledTable()
	applyBorder(a.liveTailTable.Box, " ● Live Log Tail ", borderData, titleData)

	// ── Footer bar ──────────────────────────────────────────────
	a.liveFooter = styledTextView(tview.AlignCenter)
	a.liveFooter.SetBackgroundColor(barBg)

	// ── Grid ────────────────────────────────────────────────────
	// Row 0: header           (1)
	// Row 1: conn summary     (4)
	// Row 2: synFlood + top   (10)
	// Row 3: live tail        (flex — fills remaining space)
	// Row 4: footer           (1)
	grid := tview.NewGrid().
		SetRows(1, 4, 10, 0, 1).
		SetColumns(0, 0).
		SetBorders(false)

	grid.AddItem(a.liveHeader, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.connSummary, 1, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.synFloodTable, 2, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.topConnTable, 2, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.liveTailTable, 3, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.liveFooter, 4, 0, 1, 2, 0, 0, false)

	return grid
}

// ── Live page renderers ─────────────────────────────────────────────

func (a *App) refreshLive() {
	a.blinkTick++

	// Network stats.
	netStats, _ := metrics.GetNetworkStats(12)

	// Live log tail.
	if a.deps.LiveTail != nil {
		a.deps.LiveTail.Collect()
	}
	var liveEntries []metrics.LiveLogEntry
	if a.deps.LiveTail != nil {
		liveEntries = a.deps.LiveTail.RecentEntries(maxLiveRows)
	}

	a.tviewApp.QueueUpdateDraw(func() {
		a.renderLiveHeader(netStats)
		a.renderConnSummary(netStats)
		a.renderSynFlood(netStats)
		a.renderTopConns(netStats)
		a.renderLiveTail(liveEntries)
		a.renderLiveFooter()
	})
}

func (a *App) renderLiveHeader(stats *metrics.NetworkStats) {
	a.liveHeader.Clear()
	attackStr := ""
	if stats != nil && stats.IsUnderAttack {
		if a.blinkTick%2 == 0 {
			attackStr = fmt.Sprintf("  [%s::b]● SYN FLOOD DETECTED[-:-:-]", cHex(accentLive))
		} else {
			attackStr = fmt.Sprintf("  [%s::b]○ SYN FLOOD DETECTED[-:-:-]", cHex(accentLiveDim))
		}
	}
	now := time.Now().Format("15:04:05")
	fmt.Fprintf(a.liveHeader,
		"[::b] ■ SYSMON LIVE VIEW[::-]  [%s]│[-]  %s%s ",
		cHex(textSecondary), now, attackStr)
}

func (a *App) renderConnSummary(stats *metrics.NetworkStats) {
	a.connSummary.Clear()
	if stats == nil {
		fmt.Fprintf(a.connSummary, "\n [%s]reading /proc/net/tcp…[-]", cHex(textMuted))
		return
	}
	s := stats.States

	estC := cHex(sevGreen)
	synC := cHex(sevGreen)
	twC := cHex(textPrimary)
	cwC := cHex(textPrimary)

	if s.SynRecv >= 50 {
		synC = cHex(sevRed)
	} else if s.SynRecv >= 10 {
		synC = cHex(sevYellow)
	}
	if s.CloseWait >= 100 {
		cwC = cHex(sevYellow)
	}
	if s.TimeWait >= 500 {
		twC = cHex(sevYellow)
	}

	fmt.Fprintf(a.connSummary,
		"\n [::b]ESTAB[-:-:-] [%s]%d[-]    [::b]SYN_RECV[-:-:-] [%s]%d[-]    [::b]TIME_WAIT[-:-:-] [%s]%d[-]    [::b]CLOSE_WAIT[-:-:-] [%s]%d[-]    [::b]LISTEN[-:-:-] [%s]%d[-]    [::b]Total[-:-:-] [%s]%d[-]",
		estC, s.Established,
		synC, s.SynRecv,
		twC, s.TimeWait,
		cwC, s.CloseWait,
		cHex(textAccent), s.Listen,
		cHex(textAccent), s.Total,
	)
}

func (a *App) renderSynFlood(stats *metrics.NetworkStats) {
	a.synFloodTable.Clear()

	if stats != nil && stats.IsUnderAttack {
		bc := accentLive
		title := " ⚠ SYN FLOOD ● ACTIVE "
		if a.blinkTick%2 == 1 {
			bc = accentLiveDim
			title = " ⚠ SYN FLOOD ○ ACTIVE "
		}
		a.synFloodTable.SetBorderColor(bc).SetTitle(title)
	} else {
		a.synFloodTable.SetBorderColor(borderSecurity).
			SetTitle(" ⚠ SYN Flood Monitor ")
	}

	setHeaders(a.synFloodTable, " #", "IP Address", "SYN_RECV Count")

	if stats == nil || len(stats.SynFloods) == 0 {
		a.synFloodTable.SetCell(1, 1,
			tview.NewTableCell("  no SYN flood detected").SetTextColor(sevGreen))
		return
	}

	for i, s := range stats.SynFloods {
		r := i + 1
		a.synFloodTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.synFloodTable.SetCell(r, 1, cellPrimary(s.IP))
		a.synFloodTable.SetCell(r, 2,
			tview.NewTableCell(fmt.Sprintf("%d", s.Count)).
				SetTextColor(sevRed).SetAttributes(tcell.AttrBold))
	}
}

func (a *App) renderTopConns(stats *metrics.NetworkStats) {
	a.topConnTable.Clear()
	setHeaders(a.topConnTable, " #", "IP Address", "Total", "ESTAB", "SYN_RCV", "TW")

	if stats == nil || len(stats.TopConns) == 0 {
		a.topConnTable.SetCell(1, 1, cellMuted("  no connections"))
		return
	}

	for i, c := range stats.TopConns {
		r := i + 1
		a.topConnTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.topConnTable.SetCell(r, 1, cellPrimary(c.IP))
		a.topConnTable.SetCell(r, 2, cellHeat(fmt.Sprintf("%d", c.Total), c.Total, stats.TopConns[0].Total))
		a.topConnTable.SetCell(r, 3, cellAccent(fmt.Sprintf("%d", c.Established)))

		synColor := sevGreen
		if c.SynRecv >= 10 {
			synColor = sevRed
		} else if c.SynRecv >= 3 {
			synColor = sevYellow
		}
		a.topConnTable.SetCell(r, 4,
			tview.NewTableCell(fmt.Sprintf("%d", c.SynRecv)).
				SetTextColor(synColor).SetAttributes(tcell.AttrBold))

		a.topConnTable.SetCell(r, 5, cellDim(fmt.Sprintf("%d", c.TimeWait)))
	}
}

func (a *App) renderLiveTail(entries []metrics.LiveLogEntry) {
	a.liveTailTable.Clear()

	total := 0
	if a.deps.LiveTail != nil {
		total = a.deps.LiveTail.TotalSeen()
	}
	if total > 0 {
		a.liveTailTable.SetTitle(fmt.Sprintf(" ● Live Log Tail  [%s in buffer] ", fmtCount(total)))
	}

	setHeaders(a.liveTailTable, " Time", "Src", "Domain", "IP", "Path", "Status")

	if len(entries) == 0 {
		a.liveTailTable.SetCell(1, 2, cellMuted("  waiting for log data…"))
		return
	}

	for i, e := range entries {
		r := i + 1

		// Timestamp.
		timeStr := e.Timestamp.Format("15:04:05")
		a.liveTailTable.SetCell(r, 0, cellDim(" "+timeStr))

		// Source tag — "ACC" or "ERR".
		srcColor := textAccent
		srcTag := "ACC"
		if e.Source == "error" {
			srcColor = sevRed
			srcTag = "ERR"
		}
		a.liveTailTable.SetCell(r, 1,
			tview.NewTableCell(srcTag).SetTextColor(srcColor).SetAttributes(tcell.AttrBold))

		// Domain.
		a.liveTailTable.SetCell(r, 2, cellAccent(truncate(e.Domain, 20)))

		// IP — show full IPv6 if needed.
		a.liveTailTable.SetCell(r, 3, cellPrimary(truncate(e.IP, 24)))

		// Path.
		a.liveTailTable.SetCell(r, 4,
			tview.NewTableCell(truncate(e.Path, 36)).
				SetTextColor(textPrimary).SetExpansion(1))

		// Status — color by type.
		statusColor := textPrimary
		switch {
		case e.Status == "forbidden" || e.Status == "perm denied":
			statusColor = sevRed
		case e.Status == "not found":
			statusColor = textSecondary
		case e.Status == "timeout" || e.Status == "upstream err":
			statusColor = sevRed
		case len(e.Status) == 3: // HTTP status code
			code := e.Status[0]
			switch {
			case code == '2':
				statusColor = sevGreen
			case code == '3':
				statusColor = textAccent
			case code == '4':
				statusColor = sevYellow
			case code == '5':
				statusColor = sevRed
			}
		}
		a.liveTailTable.SetCell(r, 5,
			tview.NewTableCell(e.Status).SetTextColor(statusColor).SetAttributes(tcell.AttrBold))
	}
}

func (a *App) renderLiveFooter() {
	fmt.Fprintf(a.liveFooter.Clear(),
		" [%s::b]Esc[-:-:-] / [%s::b]D[-:-:-] dashboard  [%s]│[-]  [%s::b]q[-:-:-] quit  [%s]│[-]  refresh [%s::b]%s[-:-:-]  [%s]│[-]  [%s]sysmon live[-]",
		cHex(sevYellow), cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(textSecondary),
		cHex(textAccent), a.interval, cHex(textSecondary), cHex(textMuted),
	)
}
