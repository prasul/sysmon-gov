package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"sysmon/metrics"
)

const maxLiveRows = 50

func (a *App) buildLivePage() tview.Primitive {

	a.liveHeader = styledTextView(tview.AlignCenter)
	a.liveHeader.SetBackgroundColor(barBg)

	a.connSummary = styledTextView(tview.AlignLeft)
	applyBorder(a.connSummary.Box, " ⚡ TCP Connections ", borderSystem, titleSystem)

	a.synFloodTable = styledTable()
	applyBorder(a.synFloodTable.Box, " ⚠ SYN Flood Monitor ", borderSecurity, titleSecurity)

	a.topConnTable = styledTable()
	applyBorder(a.topConnTable.Box, " ◆ Top Connections ", borderWeb, titleWeb)

	a.liveMysqlTable = styledTable()
	applyBorder(a.liveMysqlTable.Box, " ◉ MySQL Live ", borderData, titleData)

	a.liveTailTable = styledTable()
	applyBorder(a.liveTailTable.Box, " ● Live Log Tail ", borderData, titleData)

	a.liveFooter = styledTextView(tview.AlignCenter)
	a.liveFooter.SetBackgroundColor(barBg)

	// ── Grid ────────────────────────────────────────────────────
	// Row 0: header                  (1)
	// Row 1: conn summary            (4)
	// Row 2: synFlood + topConn      (10)
	// Row 3: mysql live              (10)
	// Row 4: live tail               (flex)
	// Row 5: footer                  (1)
	grid := tview.NewGrid().
		SetRows(1, 4, 10, 10, 0, 1).
		SetColumns(0, 0).
		SetBorders(false)

	grid.AddItem(a.liveHeader, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.connSummary, 1, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.synFloodTable, 2, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.topConnTable, 2, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.liveMysqlTable, 3, 0, 1, 2, 0, 0, false) // full width
	grid.AddItem(a.liveTailTable, 4, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.liveFooter, 5, 0, 1, 2, 0, 0, false)

	return grid
}

// ── Live page refresh ───────────────────────────────────────────────

func (a *App) refreshLive() {
	a.blinkTick++

	netStats, _ := metrics.GetNetworkStats(12)

	// MySQL — collect fresh data on the live page too.
	var mysqlStats *metrics.MySQLStats
	if a.deps.MySQL != nil && a.deps.MySQL.IsEnabled() {
		mysqlStats = a.deps.MySQL.Collect()
	}

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
		a.renderLiveMySQL(mysqlStats)
		a.renderLiveTail(liveEntries)
		a.renderLiveFooter()
	})
}

// ── Renderers ───────────────────────────────────────────────────────

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
		fmt.Fprintf(a.connSummary, "\n [%s]reading network state…[-]", cHex(textMuted))
		return
	}
	s := stats.States

	synC := cHex(sevGreen)
	if s.SynRecv >= 50 {
		synC = cHex(sevRed)
	} else if s.SynRecv >= 5 {
		synC = cHex(sevYellow)
	}

	cwC := cHex(textPrimary)
	if s.CloseWait >= 100 {
		cwC = cHex(sevYellow)
	}

	twC := cHex(textPrimary)
	if s.TimeWait >= 500 {
		twC = cHex(sevYellow)
	}

	fmt.Fprintf(a.connSummary,
		"\n [::b]ESTAB[-:-:-] [%s]%d[-]    [::b]SYN_RECV[-:-:-] [%s::b]%d[-:-:-]    [::b]TIME_WAIT[-:-:-] [%s]%d[-]    [::b]CLOSE_WAIT[-:-:-] [%s]%d[-]    [::b]LISTEN[-:-:-] [%s]%d[-]    [::b]Total[-:-:-] [%s]%d[-]",
		cHex(sevGreen), s.Established,
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

	setHeaders(a.synFloodTable, " #", "IP Address", "SYN_RECV")
	if stats == nil || len(stats.SynFloods) == 0 {
		msg := "  no SYN flood detected"
		synCount := 0
		if stats != nil {
			synCount = stats.States.SynRecv
		}
		if synCount > 0 {
			msg = fmt.Sprintf("  %d SYN_RECV total (below per-IP threshold)", synCount)
		}
		a.synFloodTable.SetCell(1, 1,
			tview.NewTableCell(msg).SetTextColor(sevGreen))
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
	setHeaders(a.topConnTable, " #", "IP Address", "Total", "ESTAB", "SYN", "TW")

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
		if c.SynRecv >= 3 {
			synColor = sevRed
		} else if c.SynRecv >= 2 {
			synColor = sevYellow
		}
		a.topConnTable.SetCell(r, 4,
			tview.NewTableCell(fmt.Sprintf("%d", c.SynRecv)).
				SetTextColor(synColor).SetAttributes(tcell.AttrBold))

		a.topConnTable.SetCell(r, 5, cellDim(fmt.Sprintf("%d", c.TimeWait)))
	}
}

// ── MySQL Live ──────────────────────────────────────────────────────

func (a *App) renderLiveMySQL(stats *metrics.MySQLStats) {
	a.liveMysqlTable.Clear()

	if a.deps.MySQL == nil || !a.deps.MySQL.IsEnabled() {
		setHeaders(a.liveMysqlTable, "")
		a.liveMysqlTable.SetCell(1, 0, cellMuted("  MySQL disabled"))
		return
	}

	connected, errMsg, _ := a.deps.MySQL.Status()
	if !connected {
		setHeaders(a.liveMysqlTable, "")
		msg := "  connecting…"
		if errMsg != "" {
			msg = fmt.Sprintf("  ✗ %s", truncate(errMsg, 60))
		}
		a.liveMysqlTable.SetCell(1, 0, cellMuted(msg))
		return
	}

	if stats == nil {
		return
	}

	// Rich title.
	a.liveMysqlTable.SetTitle(fmt.Sprintf(
		" ◉ MySQL Live  [%d conn / %d active / %.0f qps / %d slow] ",
		stats.TotalConnections, stats.ActiveQueries,
		stats.QueriesPerSec, stats.SlowQueries))

	setHeaders(a.liveMysqlTable, " ID", "User", "Host", "DB", "Time", "State", "Query")

	if len(stats.Processes) == 0 {
		a.liveMysqlTable.SetCell(1, 5, cellMuted("  all idle"))
		return
	}

	limit := 8
	if len(stats.Processes) < limit {
		limit = len(stats.Processes)
	}

	for i := 0; i < limit; i++ {
		p := stats.Processes[i]
		r := i + 1

		a.liveMysqlTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", p.ID)))
		a.liveMysqlTable.SetCell(r, 1, cellAccent(truncate(p.User, 10)))
		a.liveMysqlTable.SetCell(r, 2, cellDim(truncate(p.Host, 14)))
		a.liveMysqlTable.SetCell(r, 3, cellPrimary(truncate(p.DB, 12)))

		timeColor := sevGreen
		if p.TimeSec >= 10 {
			timeColor = sevRed
		} else if p.TimeSec >= 3 {
			timeColor = sevYellow
		}
		a.liveMysqlTable.SetCell(r, 4,
			tview.NewTableCell(fmt.Sprintf("%ds", p.TimeSec)).
				SetTextColor(timeColor).SetAttributes(tcell.AttrBold))

		a.liveMysqlTable.SetCell(r, 5,
			tview.NewTableCell(truncate(p.State, 14)).SetTextColor(mysqlTime))

		a.liveMysqlTable.SetCell(r, 6,
			tview.NewTableCell(truncate(p.Query, 60)).SetTextColor(mysqlQuery).SetExpansion(1))
	}
}

// ── Live Tail ───────────────────────────────────────────────────────

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

		timeStr := e.Timestamp.Format("15:04:05")
		a.liveTailTable.SetCell(r, 0, cellDim(" "+timeStr))

		srcColor := textAccent
		srcTag := "ACC"
		if e.Source == "error" {
			srcColor = sevRed
			srcTag = "ERR"
		}
		a.liveTailTable.SetCell(r, 1,
			tview.NewTableCell(srcTag).SetTextColor(srcColor).SetAttributes(tcell.AttrBold))

		a.liveTailTable.SetCell(r, 2, cellAccent(truncate(e.Domain, 20)))
		a.liveTailTable.SetCell(r, 3, cellPrimary(truncate(e.IP, 24)))
		a.liveTailTable.SetCell(r, 4,
			tview.NewTableCell(truncate(e.Path, 36)).
				SetTextColor(textPrimary).SetExpansion(1))

		statusColor := textPrimary
		switch {
		case e.Status == "forbidden" || e.Status == "perm denied":
			statusColor = sevRed
		case e.Status == "not found":
			statusColor = textSecondary
		case e.Status == "timeout" || e.Status == "upstream err":
			statusColor = sevRed
		case len(e.Status) == 3:
			switch e.Status[0] {
			case '2':
				statusColor = sevGreen
			case '3':
				statusColor = textAccent
			case '4':
				statusColor = sevYellow
			case '5':
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
