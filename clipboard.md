# Clipboard Copy Feature — Integration Guide

## Overview

This feature lets users click (or press Enter) on **any cell in any table** on the
sysmon dashboard to copy that cell's text to the system clipboard. It also works
on TextViews (press `y` or `c`). A green "✓ Copied: ..." flash confirms the action.

No new Go dependencies are needed — the feature uses `os/exec` to call native OS
clipboard tools (`xclip`, `xsel`, `wl-copy`, or `pbcopy`), with an OSC 52 terminal
escape fallback for SSH sessions.

---

## Files to Add

Copy these into your `ui/` directory:

```
ui/
├── app.go           (existing — needs edits below)
├── livepage.go      (existing — needs edits below)
├── theme.go         (existing — no changes)
├── clipboard.go     ← NEW
└── clipboard_test.go ← NEW (optional, for tests)
```

---

## Step 1: Add `clipboard.go` to `ui/`

Just copy the `clipboard.go` file into `ui/`. It compiles as part of `package ui`
and exports three public functions:

| Function | Purpose |
|---|---|
| `MakeTableCopyable(app, table, statusBar)` | Wire click-to-copy on a `*tview.Table` |
| `MakeTextViewCopyable(app, tv, statusBar)` | Wire `y`/`c` key copy on a `*tview.TextView` |
| `NewStatusBar()` | Create a pre-configured status bar `*tview.TextView` |

---

## Step 2: Edit `ui/app.go` — Dashboard Page

### 2a. Add a status bar to the Deps/App struct (or as a local variable)

In your `New()` function or wherever the dashboard layout is built, create
a status bar:

```go
// Create the status bar — reuse this for ALL tables on the page
statusBar := NewStatusBar()
```

### 2b. Wire every table

For each table you create in the dashboard, add **one line** after creating it:

```go
// ── Top Paths table ─────────────────────────────────────────
topPathsTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, topPathsTable, statusBar)   // ← ADD THIS

// ── Top IPs table ───────────────────────────────────────────
topIPsTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, topIPsTable, statusBar)      // ← ADD THIS

// ── Bot Traffic table ───────────────────────────────────────
botTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, botTable, statusBar)          // ← ADD THIS

// ── MySQL table ─────────────────────────────────────────────
mysqlTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, mysqlTable, statusBar)        // ← ADD THIS

// ── WP-Login table ──────────────────────────────────────────
wpLoginTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, wpLoginTable, statusBar)      // ← ADD THIS

// ── PHP Slow table ──────────────────────────────────────────
phpSlowTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, phpSlowTable, statusBar)      // ← ADD THIS

// ── File Changes table ──────────────────────────────────────
fileChangesTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, fileChangesTable, statusBar)  // ← ADD THIS

// ── Nginx Errors table ──────────────────────────────────────
ngxErrorTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, ngxErrorTable, statusBar)     // ← ADD THIS

// ── Top CPU Processes table ─────────────────────────────────
topCPUTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, topCPUTable, statusBar)       // ← ADD THIS

// ── Top Memory Processes table ──────────────────────────────
topMemTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, topMemTable, statusBar)       // ← ADD THIS
```

### 2c. Add the status bar to the bottom of your layout

Your dashboard layout is likely a `tview.Flex`. Add the status bar as the
last row with a fixed height of 1:

```go
// BEFORE (your existing footer row):
dashFlex.AddItem(footerRow, 1, 0, false)

// AFTER (replace the footer with the status bar, or add it alongside):
dashFlex.AddItem(statusBar, 1, 0, false)
```

If you want to keep your existing footer text, you can set the initial text
of `statusBar` to match:

```go
statusBar.SetText(" [grey]q quit │ L/→ live │ Enter/click = copy │ refresh 2s │ sysmon")
```

---

## Step 3: Edit `ui/livepage.go` — Live View Page

Same pattern — create a status bar and wire the tables + text views:

```go
// Create status bar for live view
liveStatusBar := NewStatusBar()
liveStatusBar.SetText(" [grey]Esc/D dashboard │ q quit │ Enter/click = copy │ sysmon live")

// ── SYN Flood table ─────────────────────────────────────────
synFloodTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, synFloodTable, liveStatusBar) // ← ADD THIS

// ── Top Connections table ───────────────────────────────────
topConnTable := tview.NewTable().SetBorders(false)
// ... your existing setup ...
MakeTableCopyable(app, topConnTable, liveStatusBar)  // ← ADD THIS

// ── Live Log Tail (TextView) ────────────────────────────────
logTailView := tview.NewTextView().SetDynamicColors(true)
// ... your existing setup ...
MakeTextViewCopyable(app, logTailView, liveStatusBar) // ← ADD THIS

// Add status bar to the live page layout
liveFlex.AddItem(liveStatusBar, 1, 0, false)
```

---

## Step 4: Update Keybindings Documentation

Add to your README and release notes:

```
| Key                   | Action                                      |
|-----------------------|---------------------------------------------|
| Enter / Click on cell | Copy cell text to system clipboard           |
| y / c (on log view)   | Copy full log view text to clipboard         |
```

---

## How It Works Internally

1. `MakeTableCopyable()` sets `table.SetSelectable(true, true)` making individual
   cells clickable, then registers a `SetSelectedFunc` callback.

2. On selection, the callback:
   - Extracts the cell's `.Text`
   - Strips all tview color tags (`[yellow]`, `[red::b]`, `[-]`, etc.)
   - Tries `copyToClipboard()` which calls xclip/xsel/wl-copy via `os/exec`
   - If that fails (e.g., SSH without X forwarding), falls back to OSC 52
   - Flashes "✓ Copied: 1.2.3.4" in the status bar for 2 seconds

3. The OSC 52 fallback works because most modern terminals interpret the
   `\033]52;c;<base64>\a` escape sequence as "set the system clipboard".
   This works even over SSH without needing xclip installed on the server.

---

## Prerequisites on the Server

For the **best** experience, install one clipboard tool:

```bash
# Ubuntu/Debian (X11)
sudo apt install xclip

# or
sudo apt install xsel

# Wayland
sudo apt install wl-clipboard
```

If none are available, the OSC 52 fallback still works with:
- iTerm2, kitty, alacritty, foot, WezTerm, Windows Terminal
- tmux (needs `set -g set-clipboard on` in `.tmux.conf`)

---

## Testing

Run the unit tests:

```bash
cd sysmon
go test ./ui/ -run TestCleanCellText -v
go test ./ui/ -run TestB64encode -v
go test ./ui/ -v
```

---

## Quick Sanity Check

After building, launch sysmon and:

1. Click on any IP address in the "Top IPs" panel
2. You should see a green "✓ Copied: 1.2.3.4" flash at the bottom
3. Paste somewhere to verify — the IP (or whatever text you clicked) is in your clipboard
4. Try clicking domain names, paths, process names, MySQL queries — they all copy
5. Switch to Live View (`L`), click an IP in the connections table — same behavior
6. Focus the log tail view and press `y` — the visible log text is copied

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Nothing copies | Install `xclip` or `xsel` on the server |
| Flash shows but clipboard empty | Check if OSC 52 is supported by your terminal |
| tmux blocks OSC 52 | Add `set -g set-clipboard on` to `.tmux.conf` |
| Copied text has `[yellow]` etc. | Bug in tag stripping — open an issue |
| Cell not clickable | Ensure `MakeTableCopyable()` is called AFTER creating the table |
