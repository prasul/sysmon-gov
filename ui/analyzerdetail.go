package ui

// ========================================================================
//  ANALYZER DETAIL — GoAccess-style presentation
// ========================================================================
//
// Replaces renderAnalyzerDetail() in ui/analyzerpage.go.
//
// Design goals (vs the old raw-report look):
//   - A one-line health verdict at the top (GREEN/WARN/CRITICAL).
//   - Inline proportion bars so volume is visible at a glance.
//   - Plain-language section names ("Busiest Minutes", not "[1] TOP
//     HIGH-TRAFFIC MINUTES (spike detection)").
//   - Right-aligned counts in a fixed column so the eye scans cleanly.
//   - Generous spacing between sections.
//   - Attack signatures shown as a prominent block when present.
//
// Uses only existing helpers: cHex, plainBar, truncate, tview.Escape.

import (
	"fmt"
	"time"

	"github.com/rivo/tview"

	"sysmon/metrics"
)

// miniBar draws a short proportion bar (count relative to max).
// Uses the same block glyphs as plainBar but sized to a value/max ratio.
func miniBar(value, max, width int) string {
	if max <= 0 {
		return ""
	}
	pct := float64(value) / float64(max) * 100.0
	return plainBar(pct, width)
}

// barColor picks a color for a proportion bar by percentage.
func barColorPct(pct float64) string {
	switch {
	case pct >= 50:
		return cHex(sevRed)
	case pct >= 20:
		return cHex(sevYellow)
	default:
		return cHex(textAccent)
	}
}

func (a *App) renderAnalyzerDetail() {
	a.anDetailView.Clear()

	if a.deps.Analyzer == nil {
		return
	}
	results, _, dur := a.deps.Analyzer.Results()
	if len(results) == 0 || a.anSelected >= len(results) {
		fmt.Fprintf(a.anDetailView, "\n  [%s]Waiting for first scan…[-]", cHex(textMuted))
		return
	}

	r := results[a.anSelected]
	v := a.anDetailView

	a.anDetailView.Box.SetTitle(fmt.Sprintf(" 🔍 %s ", r.Domain))

	dim := cHex(textSecondary)
	acc := cHex(textAccent)
	mut := cHex(textMuted)

	// ── Verdict banner ──────────────────────────────────────────
	var verdict, vColor string
	switch r.ThreatLevel {
	case 2:
		verdict, vColor = "● CRITICAL — attacks detected", cHex(sevRed)
	case 1:
		verdict, vColor = "● WARNING — suspicious activity", cHex(sevYellow)
	default:
		verdict, vColor = "● HEALTHY — traffic looks normal", cHex(sevGreen)
	}
	fmt.Fprintf(v, "\n  [%s::b]%s[-:-:-]\n", vColor, verdict)

	// ── Stat strip ──────────────────────────────────────────────
	deltaStr := ""
	if r.HasPrevRun {
		switch {
		case r.UniqueIPDelta > 0:
			dc := cHex(sevYellow)
			if r.UniqueIPDelta > 500 {
				dc = cHex(sevRed)
			}
			deltaStr = fmt.Sprintf("  [%s](+%d new)[-]", dc, r.UniqueIPDelta)
		case r.UniqueIPDelta < 0:
			deltaStr = fmt.Sprintf("  [%s](%d)[-]", cHex(sevGreen), r.UniqueIPDelta)
		}
	}
	fmt.Fprintf(v,
		"  [%s]%s requests   ·   %s visitors%s   ·   scanned %s ago[-]\n",
		dim, fmtCount(r.LinesRead), fmtCount(r.UniqueIPs), deltaStr,
		shortAgo(dur))

	// ── Attack signatures (only if present, shown prominently) ──
	if len(r.Attacks) > 0 {
		fmt.Fprintf(v, "\n  [%s::b]⚠ ATTACKS[-:-:-]\n", cHex(sevRed))
		for _, atk := range r.Attacks {
			catCol := cHex(sevYellow)
			switch atk.Category {
			case metrics.AttackSQLi, metrics.AttackExploit, metrics.AttackWebshell:
				catCol = cHex(sevRed)
			}
			fmt.Fprintf(v, "  [%s]%-22s[-] [%s::b]%4d[-:-:-] [%s]hits from %d IP(s)[-]\n",
				catCol, atk.Category.String(), acc, atk.Count, dim, len(atk.TopIPs))

			// Worst offender + one example.
			if len(atk.TopIPs) > 0 {
				fmt.Fprintf(v, "  [%s]   worst:[-] %s [%s](%d)[-]\n",
					mut, atk.TopIPs[0].Label, dim, atk.TopIPs[0].Count)
			}
			if len(atk.Samples) > 0 {
				fmt.Fprintf(v, "  [%s]   sample:[-] [%s]%s[-]\n",
					mut, dim, tview.Escape(truncate(atk.Samples[0].URL, 58)))
			}
		}
	}

	// ── Top visitors (with bars) ────────────────────────────────
	if len(r.TopIPs) > 0 {
		sectionTitle(v, "TOP VISITORS", acc)
		max := r.TopIPs[0].Count
		for _, ip := range r.TopIPs {
			pct := 0.0
			if r.LinesRead > 0 {
				pct = float64(ip.Count) / float64(r.LinesRead) * 100.0
			}
			ipCol := cHex(textPrimary)
			if pct > 40 {
				ipCol = cHex(sevRed)
			} else if pct > 15 {
				ipCol = cHex(sevYellow)
			}
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%-24s[-] [%s]%4.1f%%[-]\n",
				barColorPct(pct), miniBar(ip.Count, max, 12),
				ip.Count, ipCol, ip.Label, dim, pct)
		}
	}

	// ── Busiest minutes (with bars) ─────────────────────────────
	if len(r.TopMinutes) > 0 {
		sectionTitle(v, "BUSIEST MINUTES", acc)
		max := r.TopMinutes[0].Count
		for _, m := range r.TopMinutes {
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%s[-]\n",
				cHex(textAccent), miniBar(m.Count, max, 12),
				m.Count, cHex(textPrimary), m.Label)
		}
	}

	// ── Requests: methods + status side by side as bars ─────────
	if len(r.Methods) > 0 {
		sectionTitle(v, "REQUEST METHODS", acc)
		maxM := r.Methods[0].Count
		for _, m := range r.Methods {
			mc := cHex(textPrimary)
			// Flag heavy POST (login/form spam indicator).
			if m.Label == "POST" && r.LinesRead > 0 &&
				m.Count*100/r.LinesRead > 30 {
				mc = cHex(sevYellow)
			}
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%s[-]\n",
				cHex(textAccent), miniBar(m.Count, maxM, 12),
				m.Count, mc, m.Label)
		}
	}

	// ── POST hot spots (who is POSTing where, and how much) ─────
	// Shown when POST traffic is concentrated — the brute-force /
	// form-spam tell.  Lists IP → URL with volume.
	if len(r.TopPosts) > 0 && r.TopPosts[0].Count >= 10 {
		sectionTitle(v, "POST ACTIVITY", acc)
		max := r.TopPosts[0].Count
		for _, ph := range r.TopPosts {
			if ph.Count < 5 {
				continue // skip incidental POSTs
			}
			// Color by intensity — heavy single-target POSTs are red.
			barCol := cHex(textAccent)
			ipCol := cHex(textPrimary)
			switch {
			case ph.Count > 100:
				barCol, ipCol = cHex(sevRed), cHex(sevRed)
			case ph.Count > 30:
				barCol, ipCol = cHex(sevYellow), cHex(sevYellow)
			}
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%s[-]\n",
				barCol, miniBar(ph.Count, max, 12), ph.Count,
				ipCol, ph.IP)
			fmt.Fprintf(v, "  %s            [%s]→ %s[-]\n",
				"", dim, tview.Escape(truncate(ph.URL, 50)))
		}
	}

	// ── Status codes (colored by class, with bars) ──────────────
	if len(r.StatusCodes) > 0 {
		sectionTitle(v, "RESPONSE CODES", acc)
		maxS := r.StatusCodes[0].Count
		for _, s := range r.StatusCodes {
			col := cHex(sevGreen)
			label := s.Label
			if len(s.Label) == 3 {
				switch s.Label[0] {
				case '2':
					col = cHex(sevGreen)
					label = s.Label + " ok"
				case '3':
					col = cHex(textAccent)
					label = s.Label + " redirect"
				case '4':
					col = cHex(sevYellow)
					label = s.Label + " client err"
				case '5':
					col = cHex(sevRed)
					label = s.Label + " server err"
				}
			}
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%s[-]\n",
				col, miniBar(s.Count, maxS, 12), s.Count, col, label)
		}
	}

	// ── Top pages ───────────────────────────────────────────────
	if len(r.TopURLs) > 0 {
		sectionTitle(v, "TOP PAGES", acc)
		maxU := r.TopURLs[0].Count
		for _, u := range r.TopURLs {
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%s[-]\n",
				cHex(textAccent), miniBar(u.Count, maxU, 12),
				u.Count, cHex(textPrimary), tview.Escape(truncate(u.Label, 52)))
		}
	}

	// ── Top referrers ───────────────────────────────────────────
	if len(r.TopReferrers) > 0 {
		sectionTitle(v, "TOP REFERRERS", acc)
		maxR := r.TopReferrers[0].Count
		for _, ref := range r.TopReferrers {
			fmt.Fprintf(v, "  [%s]%s[-]  %6d  [%s]%s[-]\n",
				cHex(textAccent), miniBar(ref.Count, maxR, 12),
				ref.Count, cHex(textPrimary), tview.Escape(truncate(ref.Label, 52)))
		}
	}

	// ── Footnote: blank UAs ─────────────────────────────────────
	uaCol := cHex(sevGreen)
	uaNote := "normal"
	if r.BlankUACount > 100 {
		uaCol = cHex(sevRed)
		uaNote = "high — likely bots"
	} else if r.BlankUACount > 20 {
		uaCol = cHex(sevYellow)
		uaNote = "elevated"
	}
	fmt.Fprintf(v, "\n  [%s]Blank user-agents: [%s]%d[-] [%s](%s)[-]\n",
		dim, uaCol, r.BlankUACount, dim, uaNote)

	v.ScrollToBeginning()
}

// sectionTitle prints a spaced, underlined-feel section header.
func sectionTitle(v *tview.TextView, title, color string) {
	fmt.Fprintf(v, "\n  [%s::b]%s[-:-:-]\n", color, title)
}

// shortAgo formats a scan duration into a compact "Xms"/"Xs" string.
func shortAgo(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}