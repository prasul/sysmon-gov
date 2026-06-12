package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

)

// ========================================================================
//  LOG ANALYZER PAGE
// ========================================================================
//
// Third page (key: A).  Shows the periodic deep-analysis of each
// domain's access log — a TUI version of the bash "NGINX LOG
// INVESTIGATOR & ABUSE DETECTOR" script.
//
// Layout:
//   ┌─ header ──────────────────────────────────────────┐
//   ├─ domain list (left) ─┬─ investigation (right) ────┤
//   │  ● domain1  CRIT     │  [1] Top minutes           │
//   │  ● domain2  WARN     │  [2] Top IPs               │
//   │  ● domain3  ok       │  [3] Methods ...           │
//   ├─ footer ──────────────────────────────────────────┤
//
// Keys:  ↑/↓ or j/k — select domain
//        r           — force re-scan now
//        Esc / D     — back to dashboard

func (a *App) buildAnalyzerPage() tview.Primitive {

	a.anHeader = styledTextView(tview.AlignCenter)
	a.anHeader.SetBackgroundColor(barBg)

	a.anDomainList = styledTable()
	a.anDomainList.SetSelectable(true, false)
	applyBorder(a.anDomainList.Box, " 🌐 Domains ", borderWeb, titleWeb)

	a.anDetailView = styledTextView(tview.AlignLeft)
	a.anDetailView.SetScrollable(true)
	applyBorder(a.anDetailView.Box, " 🔍 Investigation ", borderSecurity, titleSecurity)

	a.anFooter = styledTextView(tview.AlignCenter)
	a.anFooter.SetBackgroundColor(barBg)

	// Selection change → re-render detail pane.
	a.anDomainList.SetSelectionChangedFunc(func(row, col int) {
		if row >= 1 {
			a.anSelected = row - 1
			a.renderAnalyzerDetail()
		}
	})

	grid := tview.NewGrid().
		SetRows(1, 0, 1).
		SetColumns(34, 0).
		SetBorders(false)

	grid.AddItem(a.anHeader, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(a.anDomainList, 1, 0, 1, 1, 0, 0, true)
	grid.AddItem(a.anDetailView, 1, 1, 1, 1, 0, 0, false)
	grid.AddItem(a.anFooter, 2, 0, 1, 2, 0, 0, false)

	return grid
}

// ── Refresh ─────────────────────────────────────────────────────────

func (a *App) refreshAnalyzer() {
	a.blinkTick++

	// Trigger the background analysis if 3 minutes have elapsed.
	if a.deps.Analyzer != nil {
		a.deps.Analyzer.MaybeAnalyze()
	}

	a.tviewApp.QueueUpdateDraw(func() {
		a.renderAnalyzerHeader()
		a.renderAnalyzerDomains()
		a.renderAnalyzerDetail()
		a.renderAnalyzerFooter()
	})
}

func (a *App) renderAnalyzerHeader() {
	a.anHeader.Clear()

	scanState := ""
	if a.deps.Analyzer != nil {
		if a.deps.Analyzer.IsRunning() {
			dot := "●"
			if a.blinkTick%2 == 1 {
				dot = "○"
			}
			scanState = fmt.Sprintf("  [%s::b]%s SCANNING[-:-:-]", cHex(sevYellow), dot)
		} else {
			next := a.deps.Analyzer.NextRunIn()
			scanState = fmt.Sprintf("  [%s]next scan in %s[-]",
				cHex(textSecondary), next.Round(time.Second))
		}
	}

	now := time.Now().Format("15:04:05")
	fmt.Fprintf(a.anHeader,
		"[::b] ■ LOG ANALYZER — ABUSE DETECTOR[::-]  [%s]│[-]  %s%s ",
		cHex(textSecondary), now, scanState)
}

func (a *App) renderAnalyzerDomains() {
	a.anDomainList.Clear()
	setHeaders(a.anDomainList, " Domain", "IPs", "Δ", "Status")

	if a.deps.Analyzer == nil {
		a.anDomainList.SetCell(1, 0, cellMuted("  analyzer disabled"))
		return
	}

	results, lastRun, _ := a.deps.Analyzer.Results()
	if len(results) == 0 {
		msg := "  first scan pending…"
		if !lastRun.IsZero() {
			msg = "  no domain logs found"
		}
		a.anDomainList.SetCell(1, 0, cellMuted(msg))
		return
	}

	for i, r := range results {
		row := i + 1

		// Threat status icon + color.
		var statusText string
		var statusColor tcell.Color
		switch r.ThreatLevel {
		case 2:
			statusText = "CRIT"
			statusColor = sevRed
		case 1:
			statusText = "WARN"
			statusColor = sevYellow
		default:
			statusText = "ok"
			statusColor = sevGreen
		}

		a.anDomainList.SetCell(row, 0, cellPrimary(" "+truncate(r.Domain, 18)))
		a.anDomainList.SetCell(row, 1, cellAccent(fmt.Sprintf("%d", r.UniqueIPs)))

		// Delta column — the "change in IP count" indicator.
		deltaStr := "—"
		deltaColor := textMuted
		if r.HasPrevRun {
			switch {
			case r.UniqueIPDelta > 0:
				deltaStr = fmt.Sprintf("+%d", r.UniqueIPDelta)
				deltaColor = sevYellow
				if r.UniqueIPDelta > 500 {
					deltaColor = sevRed
				}
			case r.UniqueIPDelta < 0:
				deltaStr = fmt.Sprintf("%d", r.UniqueIPDelta)
				deltaColor = sevGreen
			default:
				deltaStr = "0"
				deltaColor = textSecondary
			}
		}
		a.anDomainList.SetCell(row, 2,
			tview.NewTableCell(deltaStr).SetTextColor(deltaColor).SetAttributes(tcell.AttrBold))

		a.anDomainList.SetCell(row, 3,
			tview.NewTableCell(statusText).SetTextColor(statusColor).SetAttributes(tcell.AttrBold))
	}

	// Keep selection in range.
	if a.anSelected >= len(results) {
		a.anSelected = 0
	}
	a.anDomainList.Select(a.anSelected+1, 0)
}

func (a *App) renderAnalyzerDetail() {
	a.anDetailView.Clear()

	if a.deps.Analyzer == nil {
		return
	}
	results, _, dur := a.deps.Analyzer.Results()
	if len(results) == 0 || a.anSelected >= len(results) {
		fmt.Fprintf(a.anDetailView, "\n [%s]waiting for first scan…[-]", cHex(textMuted))
		return
	}

	r := results[a.anSelected]
	v := a.anDetailView

	a.anDetailView.Box.SetTitle(fmt.Sprintf(
		" 🔍 %s  [%d lines · scanned in %s] ",
		r.Domain, r.LinesRead, dur.Round(time.Millisecond)))

	dim := cHex(textSecondary)
	acc := cHex(textAccent)

	// ── Threat assessment first (most important) ──
	fmt.Fprintf(v, "\n [::b]⚠ THREAT ASSESSMENT[-:-:-]\n")
	if len(r.Threats) == 0 {
		fmt.Fprintf(v, "   [%s]🟢 Clear — traffic patterns appear normal[-]\n", cHex(sevGreen))
	} else {
		for _, t := range r.Threats {
			icon, col := "🟡", cHex(sevYellow)
			if t.Severity == 2 {
				icon, col = "🔴", cHex(sevRed)
			}
			fmt.Fprintf(v, "   %s [%s]%s[-]\n", icon, col, t.Message)
		}
	}

	// ── Unique IPs + delta ──
	deltaStr := "first scan"
	if r.HasPrevRun {
		if r.UniqueIPDelta >= 0 {
			deltaStr = fmt.Sprintf("+%d since last scan", r.UniqueIPDelta)
		} else {
			deltaStr = fmt.Sprintf("%d since last scan", r.UniqueIPDelta)
		}
	}
	fmt.Fprintf(v, "\n [::b]UNIQUE IPs[-:-:-]  [%s]%d[-]  [%s](%s)[-]\n",
		acc, r.UniqueIPs, dim, deltaStr)

	// ── [1] Spike detection ──
	fmt.Fprintf(v, "\n [::b][1] TOP HIGH-TRAFFIC MINUTES[-:-:-]  [%s](spike detection)[-]\n", dim)
	for _, m := range r.TopMinutes {
		fmt.Fprintf(v, "   [%s]%6d[-]  %s\n", acc, m.Count, m.Label)
	}

	// ── [2] Top IPs ──
	fmt.Fprintf(v, "\n [::b][2] TOP IP ADDRESSES[-:-:-]\n")
	for _, ip := range r.TopIPs {
		pct := 0
		if r.LinesRead > 0 {
			pct = ip.Count * 100 / r.LinesRead
		}
		col := cHex(textPrimary)
		if pct > 40 {
			col = cHex(sevRed)
		} else if pct > 15 {
			col = cHex(sevYellow)
		}
		fmt.Fprintf(v, "   [%s]%6d[-]  [%s]%s[-]  [%s](%d%%)[-]\n",
			acc, ip.Count, col, ip.Label, dim, pct)
	}

	// ── [3] Methods ──
	fmt.Fprintf(v, "\n [::b][3] HTTP METHODS[-:-:-]  [%s](high POST = form/login spam)[-]\n", dim)
	for _, m := range r.Methods {
		col := cHex(textPrimary)
		if m.Label == "POST" && r.LinesRead > 0 && m.Count*100/r.LinesRead > 30 {
			col = cHex(sevYellow)
		}
		fmt.Fprintf(v, "   [%s]%6d[-]  [%s]%s[-]\n", acc, m.Count, col, m.Label)
	}

	// ── [4] Status codes ──
	fmt.Fprintf(v, "\n [::b][4] STATUS CODES[-:-:-]  [%s](high 4xx/5xx = scanner or crash)[-]\n", dim)
	for _, s := range r.StatusCodes {
		col := cHex(sevGreen)
		if len(s.Label) == 3 {
			switch s.Label[0] {
			case '3':
				col = cHex(textAccent)
			case '4':
				col = cHex(sevYellow)
			case '5':
				col = cHex(sevRed)
			}
		}
		fmt.Fprintf(v, "   [%s]%6d[-]  [%s]%s[-]\n", acc, s.Count, col, s.Label)
	}

	// ── [5] Top URLs ──
	fmt.Fprintf(v, "\n [::b][5] TOP REQUESTED URLS[-:-:-]\n")
	for _, u := range r.TopURLs {
		fmt.Fprintf(v, "   [%s]%6d[-]  %s\n", acc, u.Count, tview.Escape(truncate(u.Label, 64)))
	}

	// ── [6] Referrers ──
	fmt.Fprintf(v, "\n [::b][6] TOP REFERRERS[-:-:-]\n")
	if len(r.TopReferrers) == 0 {
		fmt.Fprintf(v, "   [%s]none / direct only[-]\n", dim)
	}
	for _, ref := range r.TopReferrers {
		fmt.Fprintf(v, "   [%s]%6d[-]  %s\n", acc, ref.Count, tview.Escape(truncate(ref.Label, 64)))
	}

	// ── [7] Blank UAs ──
	uaCol := cHex(sevGreen)
	if r.BlankUACount > 100 {
		uaCol = cHex(sevRed)
	} else if r.BlankUACount > 20 {
		uaCol = cHex(sevYellow)
	}
	fmt.Fprintf(v, "\n [::b][7] BLANK USER-AGENTS[-:-:-]  [%s]%d[-]  [%s](bots rarely send UAs)[-]\n",
		uaCol, r.BlankUACount, dim)

	v.ScrollToBeginning()
}

func (a *App) renderAnalyzerFooter() {
	fmt.Fprintf(a.anFooter.Clear(),
		" [%s::b]↑/↓[-:-:-] select domain  [%s]│[-]  [%s::b]r[-:-:-] re-scan now  [%s]│[-]  [%s::b]Esc[-:-:-]/[%s::b]D[-:-:-] dashboard  [%s]│[-]  [%s::b]L[-:-:-] live  [%s]│[-]  [%s::b]q[-:-:-] quit",
		cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(textSecondary), cHex(sevYellow),
	)
}
