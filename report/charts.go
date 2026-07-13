package report

import (
	"fmt"
	"html"
	"strings"
)

// ── SVG chart rendering ─────────────────────────────────────────────
//
// Charts are generated as plain inline SVG — no JS charting library,
// no CDN, no external assets. This keeps the report a single
// self-contained HTML file that opens correctly offline, forever,
// matching sysmon's "single binary, zero runtime dependencies"
// philosophy.
//
// Every dynamic text value spliced into an SVG string (process names,
// request paths, IPs, bot names, user agents...) originates from log
// data an attacker can influence. It is HTML-escaped via esc() before
// being written into the markup, then the composed SVG is marked
// template.HTML by the caller. This mirrors the fix recommended in
// the earlier code review for the live TUI (which renders the same
// untrusted strings via tview and does not escape them) — here we
// close that gap for anything that ends up in the report.

const chartFont = `font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;`

// esc HTML-escapes untrusted text before it is spliced into a
// hand-built SVG string.
func esc(s string) string {
	return html.EscapeString(s)
}

func truncateStr(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Line/area timeline chart ────────────────────────────────────────

type lineSeries struct {
	Label string
	Color string
	Vals  []float64
}

// timeSeriesChart renders a multi-line chart over a shared time axis.
// times are pre-formatted, trusted labels (built by the report layer,
// not user input).
func timeSeriesChart(width, height int, times []string, seriesList []lineSeries, yMax float64) string {
	const padL, padR, padT, padB = 46, 16, 34, 28

	plotW := float64(width - padL - padR)
	plotH := float64(height - padT - padB)
	if yMax <= 0 {
		yMax = 1
	}
	n := len(times)

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Timeline of load, CPU, and memory">`, width, height)
	fmt.Fprintf(&b, `<rect x="0" y="0" width="%d" height="%d" fill="#ffffff"/>`, width, height)

	if n == 0 {
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="13" fill="#9ca3af" %s text-anchor="middle">not enough history yet — leave sysmon running a few minutes and try again</text>`,
			width/2, height/2, chartFont)
		b.WriteString(`</svg>`)
		return b.String()
	}

	// Horizontal gridlines + Y-axis labels.
	for i := 0; i <= 4; i++ {
		frac := float64(i) / 4
		y := padT + plotH*(1-frac)
		val := yMax * frac
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#e5e7eb" stroke-width="1"/>`,
			padL, y, width-padR, y)
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" font-size="10" fill="#6b7280" %s text-anchor="end">%.0f</text>`,
			padL-6, y+3, chartFont, val)
	}

	// X-axis labels — first, middle, last sample.
	idxs := []int{0}
	if n > 2 {
		idxs = append(idxs, n/2)
	}
	if n > 1 {
		idxs = append(idxs, n-1)
	}
	for _, i := range idxs {
		x := padL + plotW*float64(i)/float64(maxInt(n-1, 1))
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" font-size="10" fill="#6b7280" %s text-anchor="middle">%s</text>`,
			x, height-8, chartFont, esc(times[i]))
	}

	// Axes.
	fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#d1d5db" stroke-width="1"/>`,
		padL, padT, padL, height-padB)
	fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#d1d5db" stroke-width="1"/>`,
		padL, height-padB, width-padR, height-padB)

	// Series lines.
	for _, s := range seriesList {
		if len(s.Vals) == 0 {
			continue
		}
		var pts strings.Builder
		for i, v := range s.Vals {
			x := padL + plotW*float64(i)/float64(maxInt(n-1, 1))
			frac := v / yMax
			if frac > 1 {
				frac = 1
			}
			if frac < 0 {
				frac = 0
			}
			y := padT + plotH*(1-frac)
			if i > 0 {
				pts.WriteString(" ")
			}
			fmt.Fprintf(&pts, "%.1f,%.1f", x, y)
		}
		fmt.Fprintf(&b, `<polyline points="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`,
			pts.String(), s.Color)
	}

	// Legend (top-left, above the plot area).
	const legendY = 14
	for i, s := range seriesList {
		lx := padL + i*150
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="10" height="10" rx="2" fill="%s"/>`, lx, legendY, s.Color)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11" fill="#374151" %s>%s</text>`, lx+14, legendY+9, chartFont, esc(s.Label))
	}

	b.WriteString(`</svg>`)
	return b.String()
}

// ── Horizontal bar chart ────────────────────────────────────────────

type barRow struct {
	Label      string // primary label, e.g. process name, path, bot name
	Sub        string // secondary label, e.g. "pid 3142", a domain, a country
	Value      float64
	ValueLabel string // pre-formatted value text, e.g. "42.1%", "1,832"
	Color      string
}

func barChart(width int, rows []barRow) string {
	const rowH = 26
	const padT = 10
	const labelW = 190.0
	const padR = 70.0

	if len(rows) == 0 {
		height := 60
		var b strings.Builder
		fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="No data">`, width, height)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="12" fill="#9ca3af" %s text-anchor="middle">no data</text>`,
			width/2, height/2, chartFont)
		b.WriteString(`</svg>`)
		return b.String()
	}

	height := padT + len(rows)*rowH + 8

	maxVal := 0.0
	for _, r := range rows {
		if r.Value > maxVal {
			maxVal = r.Value
		}
	}
	if maxVal <= 0 {
		maxVal = 1
	}

	barAreaW := float64(width) - labelW - padR

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Ranked bar chart">`, width, height)
	fmt.Fprintf(&b, `<rect x="0" y="0" width="%d" height="%d" fill="#ffffff"/>`, width, height)

	for i, r := range rows {
		y := padT + i*rowH
		barW := barAreaW * (r.Value / maxVal)
		if barW < 2 {
			barW = 2
		}
		color := r.Color
		if color == "" {
			color = "#3b82f6"
		}

		label := esc(truncateStr(r.Label, 26))
		if r.Sub != "" {
			label = fmt.Sprintf(`%s <tspan fill="#9ca3af">%s</tspan>`, label, esc(truncateStr(r.Sub, 18)))
		}
		fmt.Fprintf(&b, `<text x="0" y="%d" font-size="11" fill="#374151" %s>%s</text>`,
			y+16, chartFont, label)
		fmt.Fprintf(&b, `<rect x="%.0f" y="%d" width="%.1f" height="14" rx="3" fill="%s"/>`,
			labelW, y+5, barW, color)
		fmt.Fprintf(&b, `<text x="%.0f" y="%d" font-size="11" fill="#111827" %s>%s</text>`,
			labelW+barW+6, y+16, chartFont, esc(r.ValueLabel))
	}

	b.WriteString(`</svg>`)
	return b.String()
}
