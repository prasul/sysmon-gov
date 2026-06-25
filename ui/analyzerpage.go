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

func (a *App) renderAnalyzerFooter() {
	fmt.Fprintf(a.anFooter.Clear(),
		" [%s::b]↑/↓[-:-:-] select domain  [%s]│[-]  [%s::b]r[-:-:-] re-scan now  [%s]│[-]  [%s::b]Esc[-:-:-]/[%s::b]D[-:-:-] dashboard  [%s]│[-]  [%s::b]L[-:-:-] live  [%s]│[-]  [%s::b]q[-:-:-] quit",
		cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(sevYellow), cHex(textSecondary),
		cHex(sevYellow), cHex(textSecondary), cHex(sevYellow),
	)
}