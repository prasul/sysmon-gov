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

	// NEW: outbound connection monitor (server → remote).
	a.outboundTable = styledTable()
	applyBorder(a.outboundTable.Box, " ⬆ Outbound Connections ", borderWeb, titleWeb)

	a.liveMysqlTable = styledTable()
	applyBorder(a.liveMysqlTable.Box, " ◉ MySQL Live ", borderData, titleData)

	a.redisInfoView = styledTextView(tview.AlignLeft)
	applyBorder(a.redisInfoView.Box, " ◈ Redis Memory ", borderData, titleData)

	a.redisKeysTable = styledTable()
	applyBorder(a.redisKeysTable.Box, " ◈ Redis Top Keys ", borderData, titleData)

	a.liveTailTable = styledTable()
	applyBorder(a.liveTailTable.Box, " ● Live Log Tail ", borderData, titleData)

	a.liveFooter = styledTextView(tview.AlignCenter)
	a.liveFooter.SetBackgroundColor(barBg)

	// ── Grid ────────────────────────────────────────────────────
	// Row 0: header                    (1)
	// Row 1: conn summary              (4)
	// Row 2: synFlood + topConn        (10)
	// Row 3: outbound (full width)     (9)
	// Row 4: mysql live                (10)
	// Row 5: redis info + redis keys   (9)
	// Row 6: live tail                 (flex)
	// Row 7: footer                    (1)
	grid := tview.NewGrid().
		SetRows(1, 4, 10, 9, 10, 9, 0, 1).
		SetColumns(0, 0).
		SetBorders(false)

	grid.AddItem(a.liveHeader, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.connSummary, 1, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.synFloodTable, 2, 0, 1, 1, 0, 0, false)
	grid.AddItem(a.topConnTable, 2, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.outboundTable, 3, 0, 1, 2, 0, 0, false)  // full width
	grid.AddItem(a.liveMysqlTable, 4, 0, 1, 2, 0, 0, false) // full width
	grid.AddItem(a.redisInfoView, 5, 0, 1, 1, 0, 0, false)  // left half
	grid.AddItem(a.redisKeysTable, 5, 1, 1, 1, 0, 0, false) // right half
	grid.AddItem(a.liveTailTable, 6, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.liveFooter, 7, 0, 1, 2, 0, 0, false)

	return grid
}

// ── Live page refresh ───────────────────────────────────────────────

func (a *App) refreshLive() {
	a.blinkTick++

	netStats, _ := metrics.GetNetworkStats(12)

	// Outbound connection stats (server → remote pileup detection).
	outStats, _ := metrics.GetOutboundStats(10)

	// MySQL — collect fresh data on the live page too.
	var mysqlStats *metrics.MySQLStats
	if a.deps.MySQL != nil && a.deps.MySQL.IsEnabled() {
		mysqlStats = a.deps.MySQL.Collect()
	}

	// Redis — fast INFO every tick, key scan throttled internally.
	if a.deps.Redis != nil {
		a.deps.Redis.CollectInfo()
		a.deps.Redis.MaybeCollectKeys()
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
		a.renderOutbound(outStats)
		a.renderLiveMySQL(mysqlStats)
		a.renderRedisInfo()
		a.renderRedisKeys()
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

// ── Outbound Connections (server → remote pileup detection) ─────────

func (a *App) renderOutbound(s *metrics.OutboundStats) {
	a.outboundTable.Clear()

	if s == nil {
		setHeaders(a.outboundTable, "")
		a.outboundTable.SetCell(1, 0, cellMuted("  reading outbound state…"))
		return
	}

	// Title + border reflect stress state.
	if s.IsUnderStress {
		bc := accentLive
		title := " ⬆ OUTBOUND STRESS ● "
		if a.blinkTick%2 == 1 {
			bc = accentLiveDim
			title = " ⬆ OUTBOUND STRESS ○ "
		}
		a.outboundTable.SetBorderColor(bc).SetTitle(title)
	} else {
		a.outboundTable.SetBorderColor(borderWeb).
			SetTitle(" ⬆ Outbound Connections ")
	}

	setHeaders(a.outboundTable, " Remote", "Port", "Total", "Estab", "Stuck", "Process")

	if len(s.TopRemotes) == 0 {
		a.outboundTable.SetCell(1, 0, cellMuted("  no significant outbound traffic"))
		return
	}

	for i, r := range s.TopRemotes {
		row := i + 1

		// Concern color: stuck OR high established both flag.
		estabColor := textPrimary
		if r.Established >= 25 {
			estabColor = sevRed
		} else if r.Established >= 10 {
			estabColor = sevYellow
		}

		stuckColor := sevGreen
		if r.Stuck >= 40 {
			stuckColor = sevRed
		} else if r.Stuck >= 15 {
			stuckColor = sevYellow
		}

		// Busiest owning process.
		proc := ""
		best := 0
		for name, n := range r.Procs {
			if n > best {
				best = n
				proc = fmt.Sprintf("%s ×%d", name, n)
			}
		}

		a.outboundTable.SetCell(row, 0, cellPrimary(" "+r.RemoteIP))
		a.outboundTable.SetCell(row, 1, cellDim(fmt.Sprintf("%d", r.RemotePort)))
		a.outboundTable.SetCell(row, 2, cellAccent(fmt.Sprintf("%d", r.Total)))
		a.outboundTable.SetCell(row, 3,
			tview.NewTableCell(fmt.Sprintf("%d", r.Established)).
				SetTextColor(estabColor).SetAttributes(tcell.AttrBold))
		a.outboundTable.SetCell(row, 4,
			tview.NewTableCell(fmt.Sprintf("%d", r.Stuck)).
				SetTextColor(stuckColor).SetAttributes(tcell.AttrBold))
		a.outboundTable.SetCell(row, 5, cellDim(proc))
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

// ── Redis Info (left panel) ─────────────────────────────────────────

func (a *App) renderRedisInfo() {
	a.redisInfoView.Clear()

	if a.deps.Redis == nil {
		fmt.Fprintf(a.redisInfoView, "\n [%s]Redis not configured[-]", cHex(textMuted))
		return
	}

	if !a.deps.Redis.IsAvailable() {
		errMsg := a.deps.Redis.LastError()
		if errMsg != "" {
			fmt.Fprintf(a.redisInfoView, "\n [%s]✗ %s[-]", cHex(sevRed), truncate(errMsg, 50))
		} else {
			fmt.Fprintf(a.redisInfoView, "\n [%s]connecting…[-]", cHex(textMuted))
		}
		return
	}

	info := a.deps.Redis.GetInfo()

	a.redisInfoView.Box.SetTitle(fmt.Sprintf(
		" ◈ Redis Memory  [%s keys] ", fmtCount64(info.TotalKeys)))

	fragColor := cHex(sevGreen)
	if info.FragRatio > 1.5 {
		fragColor = cHex(sevRed)
	} else if info.FragRatio > 1.2 {
		fragColor = cHex(sevYellow)
	}

	hitColor := cHex(sevGreen)
	if info.HitRate < 80 {
		hitColor = cHex(sevRed)
	} else if info.HitRate < 95 {
		hitColor = cHex(sevYellow)
	}

	usedPct := 0.0
	if info.MaxMemory > 0 {
		usedPct = float64(info.UsedMemory) / float64(info.MaxMemory) * 100.0
	}
	memColor := cHex(sevGreen)
	if usedPct > 90 {
		memColor = cHex(sevRed)
	} else if usedPct > 75 {
		memColor = cHex(sevYellow)
	}

	maxStr := "no limit"
	if info.MaxMemoryHuman != "" && info.MaxMemory > 0 {
		maxStr = info.MaxMemoryHuman
	}

	fmt.Fprintf(a.redisInfoView,
		"\n [::b]Used[-:-:-]   [%s]%s[-]  [%s]Peak[-] %s  [%s]RSS[-] %s",
		memColor, info.UsedMemoryHuman,
		cHex(textSecondary), info.UsedMemoryPeakHuman,
		cHex(textSecondary), info.UsedMemoryRSSHuman)

	fmt.Fprintf(a.redisInfoView,
		"\n [::b]Max[-:-:-]    %s  [::b]Policy[-:-:-] %s",
		maxStr, info.MaxMemoryPolicy)

	fmt.Fprintf(a.redisInfoView,
		"\n [::b]Frag[-:-:-]   [%s]%.2f[-]  [::b]Hit%%[-:-:-] [%s]%.1f%%[-]  [::b]Clients[-:-:-] %d",
		fragColor, info.FragRatio,
		hitColor, info.HitRate,
		info.ConnectedClients)

	if usedPct > 0 {
		fmt.Fprintf(a.redisInfoView,
			"\n [::b]Capacity[-:-:-] [%s]%.1f%% used[-]  %s",
			memColor, usedPct, plainBar(usedPct, 20))
	}

	for _, db := range info.Databases {
		fmt.Fprintf(a.redisInfoView,
			"\n [%s]%s[-] %s keys  [%s]%s expires[-]",
			cHex(textAccent), db.DB,
			fmtCount64(db.Keys),
			cHex(textSecondary), fmtCount64(db.Expires))
	}
}

// ── Redis Keys (right panel) ────────────────────────────────────────

func (a *App) renderRedisKeys() {
	a.redisKeysTable.Clear()

	if a.deps.Redis == nil || !a.deps.Redis.IsAvailable() {
		setHeaders(a.redisKeysTable, "")
		a.redisKeysTable.SetCell(1, 0, cellMuted("  waiting for Redis…"))
		return
	}

	ks := a.deps.Redis.GetKeyStats()

	if a.deps.Redis.IsScanning() {
		scanTitle := " ◈ Redis Keys  [scanning…] "
		if a.blinkTick%2 == 0 {
			scanTitle = " ◈ Redis Keys  [scanning ●] "
		}
		a.redisKeysTable.SetTitle(scanTitle)
	} else if ks.Scanned > 0 {
		a.redisKeysTable.SetTitle(fmt.Sprintf(
			" ◈ Redis Keys  [%d sampled in %s] ",
			ks.Scanned, ks.ScanDuration.Round(time.Millisecond)))
	}

	if ks.Scanned == 0 {
		setHeaders(a.redisKeysTable, "")
		a.redisKeysTable.SetCell(1, 0, cellMuted("  scan pending…"))
		return
	}

	setHeaders(a.redisKeysTable, " #", "Prefix", "Memory", "Keys", "Largest Key")

	limit := 8
	if len(ks.ByPrefix) < limit {
		limit = len(ks.ByPrefix)
	}

	for i := 0; i < limit; i++ {
		p := ks.ByPrefix[i]
		r := i + 1

		a.redisKeysTable.SetCell(r, 0, cellDim(fmt.Sprintf(" %d", r)))
		a.redisKeysTable.SetCell(r, 1, cellAccent(truncate(p.Prefix, 20)))

		memColor := sevGreen
		if p.TotalMem > 50*1024*1024 {
			memColor = sevRed
		} else if p.TotalMem > 10*1024*1024 {
			memColor = sevYellow
		}
		a.redisKeysTable.SetCell(r, 2,
			tview.NewTableCell(metrics.FormatBytes(p.TotalMem)).
				SetTextColor(memColor).SetAttributes(tcell.AttrBold))

		a.redisKeysTable.SetCell(r, 3, cellDim(fmt.Sprintf("%d", p.Count)))

		largestKey := ""
		for _, k := range ks.TopKeys {
			if k.Prefix == p.Prefix {
				largestKey = k.Key
				break
			}
		}
		a.redisKeysTable.SetCell(r, 4,
			tview.NewTableCell(truncate(largestKey, 36)).
				SetTextColor(textPrimary).SetExpansion(1))
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

// fmtCount64 formats an int64 with comma separators.
func fmtCount64(n int64) string {
	return fmtCount(int(n))
}
