package ui

// attention.go - Immediate Attention banner for the sysmon dashboard.
//
// Surfaces critical issues at the top of the screen so you stop scanning
// 14 panels. Checks metric values against configurable thresholds and
// renders a color-coded, auto-collapsing banner.
//
// Usage in app.go:
//
//   attn := NewAttentionBanner()
//   // Add to the TOP of your main Flex layout:
//   dashFlex.AddItem(attn.View, 0, 0, false)  // height auto-managed
//
//   // In your refresh loop, feed it metrics:
//   attn.Update(app, AttentionMetrics{
//       SynFloodIPs:    synData,
//       WPLoginHits:    wpData,
//       DiskPercent:    diskPct,
//       ...
//   })

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"
)

// ========================================================================
//  SEVERITY LEVELS
// ========================================================================

// Severity represents alert priority.
type Severity int

const (
	SevInfo     Severity = 0
	SevWarning  Severity = 1
	SevCritical Severity = 2
)

// colorTag returns the tview color tag for a severity.
func (s Severity) colorTag() string {
	switch s {
	case SevCritical:
		return "[red::b]"
	case SevWarning:
		return "[yellow]"
	default:
		return "[grey]"
	}
}

// icon returns the severity prefix icon.
func (s Severity) icon() string {
	switch s {
	case SevCritical:
		return "[red::b]\u25cf CRITICAL[-]"
	case SevWarning:
		return "[yellow]\u25cb WARNING[-]"
	default:
		return "[grey]\u25cb INFO[-]"
	}
}

// ========================================================================
//  ALERT ITEM
// ========================================================================

// AlertItem is a single attention item to display in the banner.
type AlertItem struct {
	Severity Severity
	Source   string // e.g. "SYN Flood", "Disk", "WP-Login"
	Message  string
	Time     time.Time
}

// ========================================================================
//  METRIC INPUTS - feed these from your refresh loop
// ========================================================================

// SynFloodEntry represents one IP doing a SYN flood.
type SynFloodEntry struct {
	IP    string
	Count int
}

// WPLoginEntry represents one IP hitting wp-login.
type WPLoginEntry struct {
	IP      string
	Hits    int
	Country string
}

// AttentionMetrics holds all the values the attention system checks.
// Feed this struct from your dashboard refresh loop.
type AttentionMetrics struct {
	// SYN flood: IPs with high SYN_RECV counts
	SynFloodIPs []SynFloodEntry

	// WP-Login: IPs with brute force attempts
	WPLoginIPs    []WPLoginEntry
	WPLoginTotal  int // total hits across all IPs in window

	// Disk usage percentage (0-100) per mount point
	DiskUsages []DiskUsage

	// CPU usage percentage (0-100)
	CPUPercent float64

	// Memory usage percentage (0-100)
	MemPercent float64

	// Load average (1 min)
	Load1m  float64
	NumCPUs int // to compare load against core count

	// MySQL: longest running query in seconds
	MySQLSlowest float64
	// MySQL: total active connections
	MySQLActive int

	// PHP-FPM slow log: count of slow entries in current window
	PHPSlowCount int

	// Nginx error rate: count of errors in current window
	NginxErrorCount int

	// File changes: count of recently modified code files
	FileChangeCount int
}

// DiskUsage is a single mount point's usage.
type DiskUsage struct {
	Mount   string
	Percent float64
	Total   string // e.g. "50G"
	Used    string // e.g. "45G"
}

// ========================================================================
//  THRESHOLDS - configurable (will move to config file later)
// ========================================================================

// AttentionThresholds defines when alerts trigger.
type AttentionThresholds struct {
	SynFloodPerIP   int     // SYN_RECV count per IP to flag (default: 10)
	WPLoginRate     int     // total wp-login hits to flag (default: 50)
	WPLoginPerIP    int     // per-IP wp-login hits to flag (default: 20)
	DiskCritical    float64 // disk % critical (default: 90)
	DiskWarning     float64 // disk % warning (default: 80)
	CPUCritical     float64 // CPU % critical (default: 95)
	CPUWarning      float64 // CPU % warning (default: 85)
	MemCritical     float64 // memory % critical (default: 95)
	MemWarning      float64 // memory % warning (default: 85)
	LoadMultiplier  float64 // load / numcpus threshold (default: 2.0)
	MySQLSlowSec    float64 // query seconds to flag (default: 10)
	MySQLActiveWarn int     // active connections warning (default: 50)
	PHPSlowWarn     int     // slow log entries to flag (default: 5)
	NginxErrorWarn  int     // error log entries to flag (default: 50)
	FileChangeWarn  int     // modified files to flag (default: 10)
}

// DefaultThresholds returns sensible defaults.
func DefaultThresholds() AttentionThresholds {
	return AttentionThresholds{
		SynFloodPerIP:   10,
		WPLoginRate:     50,
		WPLoginPerIP:    20,
		DiskCritical:    90,
		DiskWarning:     80,
		CPUCritical:     95,
		CPUWarning:      85,
		MemCritical:     95,
		MemWarning:      85,
		LoadMultiplier:  2.0,
		MySQLSlowSec:    10,
		MySQLActiveWarn: 50,
		PHPSlowWarn:     5,
		NginxErrorWarn:  50,
		FileChangeWarn:  10,
	}
}

// ========================================================================
//  ATTENTION BANNER WIDGET
// ========================================================================

// AttentionBanner is the top-of-screen alert widget.
type AttentionBanner struct {
	View       *tview.TextView
	Thresholds AttentionThresholds

	mu          sync.Mutex
	alerts      []AlertItem
	blinkState  bool
	maxHeight   int // maximum banner lines (0 = auto)
}

// NewAttentionBanner creates the banner with default thresholds.
func NewAttentionBanner() *AttentionBanner {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft).
		SetScrollable(false)

	tv.SetBorder(false)
	tv.SetBackgroundColor(0)

	ab := &AttentionBanner{
		View:       tv,
		Thresholds: DefaultThresholds(),
		maxHeight:  5,
	}

	// Start with "all clear"
	ab.renderClear()

	return ab
}

// ========================================================================
//  CHECK METRICS AND GENERATE ALERTS
// ========================================================================

// Update checks all metrics against thresholds, generates alerts,
// and re-renders the banner. Call this from your dashboard refresh loop.
//
// Usage:
//
//   app.QueueUpdateDraw(func() {
//       attn.Update(app, metrics)
//   })
func (ab *AttentionBanner) Update(app *tview.Application, m AttentionMetrics) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	now := time.Now()
	ab.alerts = ab.alerts[:0] // reset
	t := ab.Thresholds

	// ── SYN Flood ───────────────────────────────────────────
	for _, s := range m.SynFloodIPs {
		if s.Count >= t.SynFloodPerIP {
			ab.alerts = append(ab.alerts, AlertItem{
				Severity: SevCritical,
				Source:   "SYN Flood",
				Message:  fmt.Sprintf("%s (%d half-open)", s.IP, s.Count),
				Time:     now,
			})
		}
	}

	// ── WP-Login Brute Force ────────────────────────────────
	if m.WPLoginTotal >= t.WPLoginRate {
		topIPs := ""
		count := 0
		for _, w := range m.WPLoginIPs {
			if w.Hits >= t.WPLoginPerIP {
				count++
			}
		}
		if count > 0 {
			topIPs = fmt.Sprintf("%d IPs", count)
		}
		sev := SevWarning
		if m.WPLoginTotal >= t.WPLoginRate*3 {
			sev = SevCritical
		}
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: sev,
			Source:   "WP-Login",
			Message:  fmt.Sprintf("brute force: %s, %d attempts", topIPs, m.WPLoginTotal),
			Time:     now,
		})
	}

	// ── Disk Usage ──────────────────────────────────────────
	for _, d := range m.DiskUsages {
		if d.Percent >= t.DiskCritical {
			ab.alerts = append(ab.alerts, AlertItem{
				Severity: SevCritical,
				Source:   "Disk",
				Message:  fmt.Sprintf("%s at %.0f%% (%s/%s)", d.Mount, d.Percent, d.Used, d.Total),
				Time:     now,
			})
		} else if d.Percent >= t.DiskWarning {
			ab.alerts = append(ab.alerts, AlertItem{
				Severity: SevWarning,
				Source:   "Disk",
				Message:  fmt.Sprintf("%s at %.0f%% (%s/%s)", d.Mount, d.Percent, d.Used, d.Total),
				Time:     now,
			})
		}
	}

	// ── CPU Usage ───────────────────────────────────────────
	if m.CPUPercent >= t.CPUCritical {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevCritical,
			Source:   "CPU",
			Message:  fmt.Sprintf("usage at %.1f%%", m.CPUPercent),
			Time:     now,
		})
	} else if m.CPUPercent >= t.CPUWarning {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevWarning,
			Source:   "CPU",
			Message:  fmt.Sprintf("usage at %.1f%%", m.CPUPercent),
			Time:     now,
		})
	}

	// ── Memory Usage ────────────────────────────────────────
	if m.MemPercent >= t.MemCritical {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevCritical,
			Source:   "Memory",
			Message:  fmt.Sprintf("usage at %.1f%%", m.MemPercent),
			Time:     now,
		})
	} else if m.MemPercent >= t.MemWarning {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevWarning,
			Source:   "Memory",
			Message:  fmt.Sprintf("usage at %.1f%%", m.MemPercent),
			Time:     now,
		})
	}

	// ── Load Average ────────────────────────────────────────
	if m.NumCPUs > 0 && m.Load1m > float64(m.NumCPUs)*t.LoadMultiplier {
		sev := SevWarning
		if m.Load1m > float64(m.NumCPUs)*t.LoadMultiplier*1.5 {
			sev = SevCritical
		}
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: sev,
			Source:   "Load",
			Message:  fmt.Sprintf("1m avg %.2f (%d cores)", m.Load1m, m.NumCPUs),
			Time:     now,
		})
	}

	// ── MySQL ───────────────────────────────────────────────
	if m.MySQLSlowest >= t.MySQLSlowSec {
		sev := SevWarning
		if m.MySQLSlowest >= t.MySQLSlowSec*3 {
			sev = SevCritical
		}
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: sev,
			Source:   "MySQL",
			Message:  fmt.Sprintf("query running %.0fs", m.MySQLSlowest),
			Time:     now,
		})
	}
	if m.MySQLActive >= t.MySQLActiveWarn {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevWarning,
			Source:   "MySQL",
			Message:  fmt.Sprintf("%d active connections", m.MySQLActive),
			Time:     now,
		})
	}

	// ── PHP-FPM Slow ────────────────────────────────────────
	if m.PHPSlowCount >= t.PHPSlowWarn {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevWarning,
			Source:   "PHP Slow",
			Message:  fmt.Sprintf("%d slow requests", m.PHPSlowCount),
			Time:     now,
		})
	}

	// ── Nginx Errors ────────────────────────────────────────
	if m.NginxErrorCount >= t.NginxErrorWarn {
		sev := SevWarning
		if m.NginxErrorCount >= t.NginxErrorWarn*5 {
			sev = SevCritical
		}
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: sev,
			Source:   "Nginx Errors",
			Message:  fmt.Sprintf("%d errors", m.NginxErrorCount),
			Time:     now,
		})
	}

	// ── File Changes ────────────────────────────────────────
	if m.FileChangeCount >= t.FileChangeWarn {
		ab.alerts = append(ab.alerts, AlertItem{
			Severity: SevWarning,
			Source:   "File Changes",
			Message:  fmt.Sprintf("%d modified code files", m.FileChangeCount),
			Time:     now,
		})
	}

	// ── Render ──────────────────────────────────────────────
	if len(ab.alerts) == 0 {
		ab.renderClear()
	} else {
		ab.renderAlerts()
	}
}

// ========================================================================
//  RENDERING
// ========================================================================

// renderClear shows a single green "all clear" line.
func (ab *AttentionBanner) renderClear() {
	ab.View.SetText(" [green::b]\u2713[-][green] All systems clear[-]")
	// Keep fixed at 1 row height - caller should use fixedSize=1
}

// renderAlerts renders the alert banner with severity-sorted items.
func (ab *AttentionBanner) renderAlerts() {
	// Sort by severity descending (critical first)
	sort.SliceStable(ab.alerts, func(i, j int) bool {
		return ab.alerts[i].Severity > ab.alerts[j].Severity
	})

	// Toggle blink state for critical alerts
	ab.blinkState = !ab.blinkState

	var sb strings.Builder

	// Header line
	hasCritical := len(ab.alerts) > 0 && ab.alerts[0].Severity == SevCritical
	if hasCritical {
		if ab.blinkState {
			sb.WriteString(" [red::b]\u26a0 ATTENTION[-]")
		} else {
			sb.WriteString(" [red::b]\u26a0[-][white::b] ATTENTION[-]")
		}
	} else {
		sb.WriteString(" [yellow::b]\u26a0 ATTENTION[-]")
	}

	critCount := 0
	warnCount := 0
	for _, a := range ab.alerts {
		if a.Severity == SevCritical {
			critCount++
		} else if a.Severity == SevWarning {
			warnCount++
		}
	}

	sb.WriteString("  [grey]")
	if critCount > 0 {
		sb.WriteString(fmt.Sprintf("[red]%d critical[-] ", critCount))
	}
	if warnCount > 0 {
		sb.WriteString(fmt.Sprintf("[yellow]%d warning[-] ", warnCount))
	}
	sb.WriteString("[-]")

	// Alert lines (capped to maxHeight - 1 for header)
	maxItems := len(ab.alerts)
	if ab.maxHeight > 0 && maxItems > ab.maxHeight-1 {
		maxItems = ab.maxHeight - 1
	}

	for i := 0; i < maxItems; i++ {
		a := ab.alerts[i]
		sb.WriteString("\n ")
		sb.WriteString(a.Severity.colorTag())
		sb.WriteString(fmt.Sprintf(" \u2502 %-14s", a.Source))
		sb.WriteString("[-] ")
		sb.WriteString(a.Message)
	}

	remaining := len(ab.alerts) - maxItems
	if remaining > 0 {
		sb.WriteString(fmt.Sprintf("\n [grey] ... and %d more[-]", remaining))
	}

	ab.View.SetText(sb.String())
}

// ========================================================================
//  HELPERS
// ========================================================================

// AlertCount returns the number of current alerts.
func (ab *AttentionBanner) AlertCount() int {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	return len(ab.alerts)
}

// HasCritical returns true if any critical alert is active.
func (ab *AttentionBanner) HasCritical() bool {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	for _, a := range ab.alerts {
		if a.Severity == SevCritical {
			return true
		}
	}
	return false
}

// Alerts returns a copy of current alerts (for reports, logging, etc.)
func (ab *AttentionBanner) Alerts() []AlertItem {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	out := make([]AlertItem, len(ab.alerts))
	copy(out, ab.alerts)
	return out
}

// BannerHeight returns how many rows the banner needs.
// Use this to dynamically resize the banner in your Flex layout.
func (ab *AttentionBanner) BannerHeight() int {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	if len(ab.alerts) == 0 {
		return 1 // single "all clear" line
	}
	lines := 1 // header
	items := len(ab.alerts)
	if ab.maxHeight > 0 && items > ab.maxHeight-1 {
		items = ab.maxHeight - 1
		lines++ // "... and N more" line
	}
	lines += items
	return lines
}
