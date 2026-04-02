package ui

// clipboard.go - Copy-to-clipboard support for sysmon dashboard tables.
//
// Drop this file into ui/ alongside app.go, livepage.go, theme.go.
//
// Any text selected (clicked / Enter) in a tview.Table is copied to the
// system clipboard. A brief green flash confirms the copy in the status bar.
//
// On headless SSH sessions where xclip/xsel are not installed, it falls
// back to the OSC 52 terminal escape which most modern terminals honour.
//
// New keybinding:  y / c  on a focused TextView copies its full content.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ========================================================================
//  CLIPBOARD BACKEND
// ========================================================================

// copyToClipboard sends text to the system clipboard using OS-native tools.
// Returns nil on success.
func copyToClipboard(text string) error {
	if text == "" {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		return copyLinux(text)
	case "darwin":
		return pipeToCmd("pbcopy", nil, text)
	default:
		return fmt.Errorf("clipboard: unsupported OS %q", runtime.GOOS)
	}
}

// copyLinux tries available clipboard helpers in order of preference.
func copyLinux(text string) error {
	if p, err := exec.LookPath("xclip"); err == nil {
		return pipeToCmd(p, []string{"-selection", "clipboard"}, text)
	}
	if p, err := exec.LookPath("xsel"); err == nil {
		return pipeToCmd(p, []string{"--clipboard", "--input"}, text)
	}
	if p, err := exec.LookPath("wl-copy"); err == nil {
		return pipeToCmd(p, nil, text)
	}
	return fmt.Errorf("clipboard: no tool found (install xclip, xsel, or wl-copy)")
}

// pipeToCmd writes text to the stdin of an external command.
func pipeToCmd(name string, args []string, text string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// ========================================================================
//  OSC 52 FALLBACK  (works over SSH, tmux, etc.)
// ========================================================================

// copyViaOSC52 writes the OSC 52 clipboard-set escape sequence directly
// to /dev/tty, bypassing tview's screen entirely.  Most modern terminals
// (iTerm2, kitty, alacritty, foot, WezTerm, Windows Terminal, and tmux
// with set -g set-clipboard on) honour this.
func copyViaOSC52(text string) {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer tty.Close()
	encoded := b64encode([]byte(text))
	fmt.Fprintf(tty, "\033]52;c;%s\a", encoded)
}

// b64encode is a minimal base64 encoder to avoid an extra import.
func b64encode(data []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	sb.Grow(((len(data) + 2) / 3) * 4)
	for i := 0; i < len(data); i += 3 {
		remaining := len(data) - i
		var n uint32
		switch {
		case remaining >= 3:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			sb.WriteByte(alpha[(n>>18)&0x3F])
			sb.WriteByte(alpha[(n>>12)&0x3F])
			sb.WriteByte(alpha[(n>>6)&0x3F])
			sb.WriteByte(alpha[n&0x3F])
		case remaining == 2:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8
			sb.WriteByte(alpha[(n>>18)&0x3F])
			sb.WriteByte(alpha[(n>>12)&0x3F])
			sb.WriteByte(alpha[(n>>6)&0x3F])
			sb.WriteByte('=')
		case remaining == 1:
			n = uint32(data[i]) << 16
			sb.WriteByte(alpha[(n>>18)&0x3F])
			sb.WriteByte(alpha[(n>>12)&0x3F])
			sb.WriteByte('=')
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// ========================================================================
//  STATUS BAR FLASH
// ========================================================================

// flashCopied shows a green confirmation for 2 seconds, then restores
// the original status bar content.
func flashCopied(app *tview.Application, statusBar *tview.TextView, text string) {
	if statusBar == nil || app == nil {
		return
	}
	display := text
	if len(display) > 50 {
		display = display[:47] + "..."
	}
	original := statusBar.GetText(true)
	statusBar.SetText(fmt.Sprintf(" [green]Copied:[white] %s", display))

	go func() {
		time.Sleep(2 * time.Second)
		app.QueueUpdateDraw(func() {
			statusBar.SetText(original)
		})
	}()
}

// ========================================================================
//  TVIEW COLOR TAG STRIPPING
// ========================================================================

// cleanCellText extracts plain text from a tview table cell, stripping
// all color/style tags like [yellow], [red::b], [-], etc.
func cleanCellText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return stripTviewTags(raw)
}

// stripTviewTags removes [...] style tags that tview uses for colors.
func stripTviewTags(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '[' {
			j := strings.IndexByte(s[i:], ']')
			if j > 0 {
				tag := s[i+1 : i+j]
				if looksLikeTviewTag(tag) {
					i = i + j + 1
					continue
				}
			}
		}
		buf.WriteByte(s[i])
		i++
	}
	return strings.TrimSpace(buf.String())
}

// looksLikeTviewTag returns true if the content between [ ] looks like
// a tview color/style tag rather than literal bracket content.
func looksLikeTviewTag(tag string) bool {
	if tag == "" || tag == "-" || tag == "::" {
		return true
	}
	parts := strings.Split(tag, ":")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "-" {
			continue
		}
		if !isKnownColor(p) && !isKnownAttr(p) && !isHexColor(p) {
			return false
		}
	}
	return true
}

func isHexColor(s string) bool {
	if len(s) < 2 || s[0] != '#' {
		return false
	}
	for _, c := range s[1:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

var knownColors = map[string]bool{
	"red": true, "green": true, "yellow": true, "blue": true,
	"white": true, "black": true, "cyan": true, "magenta": true,
	"orange": true, "purple": true, "grey": true, "gray": true,
	"darkred": true, "darkgreen": true, "darkcyan": true,
	"darkblue": true, "darkmagenta": true, "darkyellow": true,
	"lightgray": true, "lightgrey": true,
	"aqua": true, "fuchsia": true, "lime": true, "maroon": true,
	"navy": true, "olive": true, "silver": true, "teal": true,
}

func isKnownColor(s string) bool {
	return knownColors[strings.ToLower(s)]
}

var knownAttrs = map[string]bool{
	"b": true, "bold": true, "i": true, "italic": true,
	"u": true, "underline": true, "d": true, "dim": true,
	"s": true, "strikethrough": true, "l": true, "blink": true,
	"r": true, "reverse": true,
}

func isKnownAttr(s string) bool {
	return knownAttrs[strings.ToLower(s)]
}

// ========================================================================
//  PUBLIC WIRING HELPERS - call these from app.go / livepage.go
// ========================================================================

// MakeTableCopyable enables click-to-copy on any tview.Table.
//
// When a user selects (clicks or presses Enter on) any cell, its text
// content is stripped of color tags, copied to the system clipboard,
// and a confirmation flash is shown in the status bar.
//
// This makes rows AND columns individually selectable.
//
// Usage in app.go:
//
//	MakeTableCopyable(app, topIPsTable, statusBar)
//	MakeTableCopyable(app, topPathsTable, statusBar)
func MakeTableCopyable(app *tview.Application, table *tview.Table, statusBar *tview.TextView) {
	table.SetSelectable(true, true)
	table.SetSelectedFunc(func(row, col int) {
		cell := table.GetCell(row, col)
		if cell == nil {
			return
		}
		text := cleanCellText(cell.Text)
		if text == "" {
			return
		}

		err := copyToClipboard(text)
		if err != nil {
			copyViaOSC52(text)
		}
		flashCopied(app, statusBar, text)
	})
}

// MakeTextViewCopyable lets the user press 'y' or 'c' on a focused
// TextView to copy its full content (stripped of color tags) to the
// clipboard.
//
// Usage in livepage.go:
//
//	MakeTextViewCopyable(app, logTailView, statusBar)
func MakeTextViewCopyable(app *tview.Application, tv *tview.TextView, statusBar *tview.TextView) {
	original := tv.GetInputCapture()
	tv.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'y' || event.Rune() == 'c' {
			text := cleanCellText(tv.GetText(true))
			if text != "" {
				err := copyToClipboard(text)
				if err != nil {
					copyViaOSC52(text)
				}
				flashCopied(app, statusBar, text)
			}
			return nil
		}
		if original != nil {
			return original(event)
		}
		return event
	})
}

// NewStatusBar creates a one-line status bar with dynamic colors enabled.
// Place this at the bottom of your layout (or reuse your existing footer).
func NewStatusBar() *tview.TextView {
	return tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft).
		SetText(" [grey]q quit | L/-> live | Enter/click = copy | sysmon")
}
