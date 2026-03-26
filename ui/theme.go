package ui

import "github.com/gdamore/tcell/v2"

// ── Color Palette ───────────────────────────────────────────────────
// Unified color scheme — change these to reskin the entire dashboard.
//
// The design uses a layered approach:
//   Surface  — panel backgrounds (default terminal bg)
//   Border   — panel outlines, category-coded
//   Text     — primary (white), secondary (gray), accent (aqua)
//   Semantic — green/yellow/red for severity, plus category-specific

// Panel border colors — one per functional category.
var (
	borderSystem   = tcell.NewRGBColor(70, 130, 180)  // steel blue
	borderWeb      = tcell.NewRGBColor(140, 100, 180) // muted purple
	borderSecurity = tcell.NewRGBColor(180, 60, 60)   // muted red
	borderPerf     = tcell.NewRGBColor(200, 120, 50)  // amber
	borderData     = tcell.NewRGBColor(60, 140, 140)  // teal
)

// Title colors — slightly brighter than borders for readability.
var (
	titleSystem   = tcell.NewRGBColor(120, 170, 220)
	titleWeb      = tcell.NewRGBColor(180, 140, 220)
	titleSecurity = tcell.NewRGBColor(255, 100, 100)
	titlePerf     = tcell.NewRGBColor(255, 170, 80)
	titleData     = tcell.NewRGBColor(100, 200, 200)
)

// Text hierarchy.
var (
	textPrimary   = tcell.NewRGBColor(220, 220, 220) // main content
	textSecondary = tcell.NewRGBColor(130, 130, 140) // dimmed / rank numbers
	textAccent    = tcell.NewRGBColor(100, 200, 220) // highlights (domains, PIDs)
	textMuted     = tcell.NewRGBColor(80, 80, 90)    // placeholder text
)

// Severity scale — used for percentages and hit counts.
var (
	sevGreen  = tcell.NewRGBColor(80, 200, 120)
	sevYellow = tcell.NewRGBColor(230, 200, 60)
	sevRed    = tcell.NewRGBColor(240, 80, 80)
)

// Bot type colors.
var (
	botAI      = tcell.NewRGBColor(255, 100, 100) // red — AI crawlers
	botSearch  = tcell.NewRGBColor(100, 180, 255) // blue — search engines
	botSocial  = tcell.NewRGBColor(100, 220, 140) // green — social media
	botMonitor = tcell.NewRGBColor(180, 180, 100) // olive — monitoring
	botOther   = tcell.ColorDarkGray
)

// Accent colors.
var (
	accentLive     = tcell.NewRGBColor(255, 60, 60)   // live-attack blink ON
	accentLiveDim  = tcell.NewRGBColor(140, 40, 40)   // live-attack blink OFF
	accentPlugin   = tcell.NewRGBColor(230, 190, 60)   // plugin names
	accentFunction = tcell.NewRGBColor(230, 130, 60)   // function names
)

// Header / footer bar background.
var barBg = tcell.NewRGBColor(30, 35, 45)

// MySQL-specific.
var (
	mysqlQuery   = tcell.NewRGBColor(180, 180, 200) // query text
	mysqlTime    = tcell.NewRGBColor(230, 160, 60)  // elapsed time
)

// ── Bar characters ──────────────────────────────────────────────────
// Using lighter block characters for a more modern look.
const (
	barFilled = "━"
	barEmpty  = "╌"
)
