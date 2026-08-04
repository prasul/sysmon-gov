package ui

// ========================================================================
//  LIVE TRAFFIC PANELS
// ========================================================================
//
// Four renderers for the restructured live view:
//   renderFlooding      — rate-based block-decision panel (hero)
//   renderDomainRates   — traffic by domain, rolling
//   renderCodes         — response-code health, rolling
//   renderSessionView   — persistent IPs + domain totals, cumulative
//
// Add the corresponding table/text fields to the App struct and build
// them in buildLivePage (see integration notes at the bottom).

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"sysmon/metrics"
)

// ── Flooding IPs (the hero panel — sorted by current rate) ──────────

func (a *App) renderFlooding(s *metrics.LiveTrafficStats) {
	a.floodTable.Clear()

	title := " ⚡ Flooding Now "
	underStress := len(s.Flooding) > 0 && s.Flooding[0].RatePerSec >= 20
	if underStress {
		bc := accentLive
		title = fmt.Sprintf(" ⚡ FLOODING ● %.0f req/s ", s.TotalRate)
		if a.blinkTick%2 == 1 {
			bc = accentLiveDim
			title = fmt.Sprintf(" ⚡ FLOODING ○ %.0f req/s ", s.TotalRate)
		}
		a.floodTable.SetBorderColor(bc).SetTitle(title)
	} else {
		a.floodTable.SetBorderColor(borderSecurity).
			SetTitle(fmt.Sprintf(" ⚡ Flooding Now  [%.0f req/s] ", s.TotalRate))
	}

	setHeaders(a.floodTable, " Rate", "%", "IP Address", "Target", "")

	if len(s.Flooding) == 0 {
		a.floodTable.SetCell(1, 2, cellMuted("  no significant traffic"))
		return
	}

	maxCount := s.Flooding[0].Count
	for i, f := range s.Flooding {
		r := i + 1

		// Rate cell — colored by intensity.
		rateColor := sevGreen
		if f.RatePerSec >= 40 {
			rateColor = sevRed
		} else if f.RatePerSec >= 15 {
			rateColor = sevYellow
		}
		a.floodTable.SetCell(r, 0,
			tview.NewTableCell(fmt.Sprintf(" %.0f/s", f.RatePerSec)).
				SetTextColor(rateColor).SetAttributes(tcell.AttrBold))

		// % of total load — the block-impact number.
		pctColor := textPrimary
		if f.PctOfTotal >= 40 {
			pctColor = sevRed
		} else if f.PctOfTotal >= 20 {
			pctColor = sevYellow
		}
		a.floodTable.SetCell(r, 1,
			tview.NewTableCell(fmt.Sprintf("%.0f%%", f.PctOfTotal)).
				SetTextColor(pctColor))

		// IP — heat-colored by relative volume.
		ipCell := cellHeat(f.IP, f.Count, maxCount)
		a.floodTable.SetCell(r, 2, ipCell)

		// Target endpoint — attack tells in color.
		target := truncate(f.TopPath, 22)
		targetColor := textSecondary
		if isAttackPath(f.TopPath) {
			targetColor = sevRed
		}
		a.floodTable.SetCell(r, 3,
			tview.NewTableCell(target).SetTextColor(targetColor))

		// Allowlist tag (don't block your CDN!).
		tag := ""
		tagColor := textMuted
		if f.Allowlist != "" {
			tag = "✓ " + truncate(f.Allowlist, 20)
			tagColor = sevGreen
		}
		a.floodTable.SetCell(r, 4,
			tview.NewTableCell(tag).SetTextColor(tagColor))
	}
}

// isAttackPath flags endpoints commonly targeted by brute force / abuse.
func isAttackPath(path string) bool {
	for _, p := range []string{"wp-login", "xmlrpc", "/wp-admin", "phpmyadmin", ".env", "/.git"} {
		if containsFold(path, p) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	// simple case-insensitive substring index
	ls, lsub := len(s), len(sub)
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			c1, c2 := s[i+j], sub[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ── Traffic by domain (rolling) ─────────────────────────────────────

func (a *App) renderDomainRates(s *metrics.LiveTrafficStats) {
	a.domainRateTable.Clear()
	a.domainRateTable.SetTitle(" ◆ Traffic by Domain  [10s] ")

	setHeaders(a.domainRateTable, " Rate", "Domain", "")

	if len(s.DomainRates) == 0 {
		a.domainRateTable.SetCell(1, 1, cellMuted("  no traffic"))
		return
	}

	max := s.DomainRates[0].Count
	for i, d := range s.DomainRates {
		r := i + 1
		rateColor := textAccent
		if d.RatePerSec >= 100 {
			rateColor = sevRed
		} else if d.RatePerSec >= 40 {
			rateColor = sevYellow
		}
		a.domainRateTable.SetCell(r, 0,
			tview.NewTableCell(fmt.Sprintf(" %.0f/s", d.RatePerSec)).
				SetTextColor(rateColor).SetAttributes(tcell.AttrBold))
		a.domainRateTable.SetCell(r, 1, cellAccent(truncate(d.Domain, 22)))
		a.domainRateTable.SetCell(r, 2,
			tview.NewTableCell(miniBar(d.Count, max, 10)).
				SetTextColor(rateColor))
	}
}

// ── Response codes (rolling health) ─────────────────────────────────

func (a *App) renderCodes(s *metrics.LiveTrafficStats) {
	a.codesView.Clear()
	c := s.Codes

	// Alert border if 5xx or heavy 4xx.
	if c.C5xx > 0 || (c.Total > 0 && c.C4xx*100/max1(c.Total) > 40) {
		a.codesView.Box.SetBorderColor(sevRed).
			SetTitle(fmt.Sprintf(" ◆ Response Codes ⚠  [%.0f/s] ", c.RatePerSec))
	} else {
		a.codesView.Box.SetBorderColor(borderWeb).
			SetTitle(fmt.Sprintf(" ◆ Response Codes  [%.0f/s] ", c.RatePerSec))
	}

	if c.Total == 0 {
		fmt.Fprintf(a.codesView, "\n  [%s]no traffic in window[-]", cHex(textMuted))
		return
	}

	bar := func(n int) string { return miniBar(n, c.Total, 16) }

	fmt.Fprintf(a.codesView,
		"\n [%s::b]2xx[-:-:-] [%s]%s[-] [%s]%d[-]  [%s](%d%%)[-]",
		cHex(sevGreen), cHex(sevGreen), bar(c.C2xx), cHex(textPrimary), c.C2xx,
		cHex(textSecondary), c.C2xx*100/max1(c.Total))
	fmt.Fprintf(a.codesView,
		"\n [%s::b]3xx[-:-:-] [%s]%s[-] [%s]%d[-]  [%s](%d%%)[-]",
		cHex(textAccent), cHex(textAccent), bar(c.C3xx), cHex(textPrimary), c.C3xx,
		cHex(textSecondary), c.C3xx*100/max1(c.Total))

	c4Color := cHex(sevYellow)
	fmt.Fprintf(a.codesView,
		"\n [%s::b]4xx[-:-:-] [%s]%s[-] [%s]%d[-]  [%s](%d%%)[-]",
		c4Color, c4Color, bar(c.C4xx), cHex(textPrimary), c.C4xx,
		cHex(textSecondary), c.C4xx*100/max1(c.Total))

	c5Color := cHex(sevGreen)
	if c.C5xx > 0 {
		c5Color = cHex(sevRed)
	}
	fmt.Fprintf(a.codesView,
		"\n [%s::b]5xx[-:-:-] [%s]%s[-] [%s]%d[-]  [%s](%d%%)[-]",
		c5Color, c5Color, bar(c.C5xx), cHex(textPrimary), c.C5xx,
		cHex(textSecondary), c.C5xx*100/max1(c.Total))
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// ── Session view (persistent IPs + domain totals) ───────────────────

func (a *App) renderSessionView(s *metrics.LiveTrafficStats) {
	a.sessionTable.Clear()

	dur := time.Since(s.SessionStart).Round(time.Second)
	a.sessionTable.SetTitle(fmt.Sprintf(
		" ◈ Session  [%s · %s reqs] ", shortDur(dur), fmtCount(s.SessionReqs)))

	setHeaders(a.sessionTable, " Total", "IP Address", "Active", "First")

	if len(s.PersistentIPs) == 0 {
		a.sessionTable.SetCell(1, 1, cellMuted("  accumulating…"))
		return
	}

	maxCount := s.PersistentIPs[0].Count
	for i, ip := range s.PersistentIPs {
		r := i + 1

		a.sessionTable.SetCell(r, 0, cellHeat(fmt.Sprintf("%d", ip.Count), ip.Count, maxCount))
		a.sessionTable.SetCell(r, 1, cellPrimary(ip.IP))

		// Active-minutes: the burst-vs-persistent tell.
		activeColor := textSecondary
		if ip.ActiveMins >= 10 {
			activeColor = sevYellow // sustained presence
		}
		if ip.ActiveMins >= 30 {
			activeColor = sevRed // very persistent
		}
		a.sessionTable.SetCell(r, 2,
			tview.NewTableCell(fmt.Sprintf("%dm", ip.ActiveMins)).
				SetTextColor(activeColor))

		a.sessionTable.SetCell(r, 3,
			cellDim(ip.FirstSeen.Format("15:04")))
	}
}

// shortDur formats a duration compactly (e.g. "1h23m", "45m", "12s").
func shortDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m)
}
