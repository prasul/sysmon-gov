package ui

// actions.go - IP blocking, service restarts, and action logging.
//
// Keybindings:
//   b  - Block IP (popup form)
//   u  - Unblock IP (popup form)
//   :  - Command palette (service actions)
//
// All actions:
//   1. Validate input strictly (IP regex, self-IP protection)
//   2. Require confirmation before execution
//   3. Run predefined commands only (no shell interpolation)
//   4. Log every action to /var/log/sysmon-actions.log
//
// Block IP runs BOTH csf and scoots, then auto-restarts:
//   csf -d {ip} "Blocked by sysmon"
//   scoots ip block {ip}
//   csf -ra
//   nprestart
//   scoots php restart all

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ========================================================================
//  CONSTANTS
// ========================================================================

const (
	actionLogPath  = "/var/log/sysmon-actions.log"
	pageActionForm = "action-form"
	pageConfirm    = "action-confirm"
	pagePalette    = "action-palette"
	pageResult     = "action-result"
)

// ========================================================================
//  ACTION LOG
// ========================================================================

var actionLogMu sync.Mutex

// logAction appends a timestamped entry to the action log file.
func logAction(action, detail, result string) {
	actionLogMu.Lock()
	defer actionLogMu.Unlock()

	f, err := os.OpenFile(actionLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	ts := time.Now().Format("2006-01-02 15:04:05")
	user := os.Getenv("USER")
	if user == "" {
		user = "root"
	}
	fmt.Fprintf(f, "[%s] user=%s action=%s detail=%s result=%s\n",
		ts, user, action, detail, result)
}

// ========================================================================
//  BLOCKED IP TRACKER
// ========================================================================

// BlockedIP represents an IP that was blocked during this session.
type BlockedIP struct {
	IP        string
	BlockedAt time.Time
	BlockedBy string // "csf+scoots", "csf", "scoots"
}

// ActionTracker keeps a session record of all actions performed.
type ActionTracker struct {
	mu         sync.Mutex
	BlockedIPs []BlockedIP
}

// NewActionTracker creates a new tracker.
func NewActionTracker() *ActionTracker {
	return &ActionTracker{}
}

// AddBlocked records a blocked IP.
func (t *ActionTracker) AddBlocked(ip, method string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.BlockedIPs = append(t.BlockedIPs, BlockedIP{
		IP:        ip,
		BlockedAt: time.Now(),
		BlockedBy: method,
	})
}

// RemoveBlocked removes an IP from the blocked list.
func (t *ActionTracker) RemoveBlocked(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, b := range t.BlockedIPs {
		if b.IP == ip {
			t.BlockedIPs = append(t.BlockedIPs[:i], t.BlockedIPs[i+1:]...)
			return
		}
	}
}

// IsBlocked returns true if the IP is in the session blocked list.
func (t *ActionTracker) IsBlocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range t.BlockedIPs {
		if b.IP == ip {
			return true
		}
	}
	return false
}

// ========================================================================
//  IP VALIDATION
// ========================================================================

// validateIP checks that the string is a valid IPv4 or IPv6 address.
// Returns an error message or empty string if valid.
func validateIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "IP address cannot be empty"
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Try CIDR notation
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Sprintf("%q is not a valid IP address", ip)
		}
	}
	return ""
}

// getSelfIP returns the current SSH session's source IP, if available.
func getSelfIP() string {
	// SSH_CLIENT format: "source_ip source_port dest_port"
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient == "" {
		sshClient = os.Getenv("SSH_CONNECTION")
	}
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) >= 1 {
			return parts[0]
		}
	}
	return ""
}

// isSelfIP checks if the given IP matches the current SSH session IP.
func isSelfIP(ip string) bool {
	self := getSelfIP()
	if self == "" {
		return false
	}
	return strings.TrimSpace(ip) == self
}

// ========================================================================
//  COMMAND EXECUTION (no shell - safe from injection)
// ========================================================================

// runCmd executes a command directly (no shell) and returns combined output.
func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ========================================================================
//  BLOCK IP - runs both csf and scoots, then auto-restarts
// ========================================================================

// blockIP executes the full block sequence and returns a result summary.
func blockIP(ip string) string {
	ip = strings.TrimSpace(ip)
	var results []string

	// Step 1: CSF block
	out, err := runCmd("csf", "-d", ip, "Blocked by sysmon")
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]csf -d:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]csf -d:[-] OK"))
	}

	// Step 2: scoots block
	out, err = runCmd("scoots", "ip", "block", ip)
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]scoots block:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]scoots block:[-] OK"))
	}

	// Step 3: Auto-restart CSF
	out, err = runCmd("csf", "-ra")
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]csf -ra:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]csf -ra:[-] OK"))
	}

	// Step 4: Auto-restart nginx
	out, err = runCmd("nprestart")
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]nprestart:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]nprestart:[-] OK"))
	}

	// Step 5: Auto-restart PHP-FPM
	out, err = runCmd("scoots", "php", "restart", "all")
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]scoots php restart:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]scoots php restart:[-] OK"))
	}

	return strings.Join(results, "\n")
}

// ========================================================================
//  UNBLOCK IP
// ========================================================================

func unblockIP(ip string) string {
	ip = strings.TrimSpace(ip)
	var results []string

	out, err := runCmd("csf", "-dr", ip)
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]csf -dr:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]csf -dr:[-] OK"))
	}

	out, err = runCmd("scoots", "ip", "unblock", ip)
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]scoots unblock:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]scoots unblock:[-] OK"))
	}

	// Restart CSF to apply
	out, err = runCmd("csf", "-ra")
	if err != nil {
		results = append(results, fmt.Sprintf("[yellow]csf -ra:[-] %s (%v)", out, err))
	} else {
		results = append(results, fmt.Sprintf("[green]csf -ra:[-] OK"))
	}

	return strings.Join(results, "\n")
}

// ========================================================================
//  SERVICE COMMANDS
// ========================================================================

// ServiceAction defines a command palette entry.
type ServiceAction struct {
	Name    string
	Desc    string
	Run     func() string
	Confirm bool
}

// DefaultServiceActions returns the predefined service actions.
func DefaultServiceActions() []ServiceAction {
	return []ServiceAction{
		{
			Name:    "Restart Nginx",
			Desc:    "nprestart",
			Confirm: true,
			Run: func() string {
				out, err := runCmd("nprestart")
				if err != nil {
					return fmt.Sprintf("[red]FAILED:[-] %s (%v)", out, err)
				}
				return fmt.Sprintf("[green]OK:[-] nginx restarted")
			},
		},
		{
			Name:    "Restart PHP-FPM (all)",
			Desc:    "scoots php restart all",
			Confirm: true,
			Run: func() string {
				out, err := runCmd("scoots", "php", "restart", "all")
				if err != nil {
					return fmt.Sprintf("[red]FAILED:[-] %s (%v)", out, err)
				}
				return fmt.Sprintf("[green]OK:[-] PHP-FPM restarted")
			},
		},
		{
			Name:    "Restart CSF Firewall",
			Desc:    "csf -ra",
			Confirm: true,
			Run: func() string {
				out, err := runCmd("csf", "-ra")
				if err != nil {
					return fmt.Sprintf("[red]FAILED:[-] %s (%v)", out, err)
				}
				return fmt.Sprintf("[green]OK:[-] CSF restarted")
			},
		},
		{
			Name:    "Nginx Config Test",
			Desc:    "nginx -t",
			Confirm: false,
			Run: func() string {
				out, err := runCmd("nginx", "-t")
				if err != nil {
					return fmt.Sprintf("[red]FAILED:[-]\n%s", out)
				}
				return fmt.Sprintf("[green]OK:[-] %s", out)
			},
		},
		{
			Name:    "Flush OPcache",
			Desc:    "php -r opcache_reset()",
			Confirm: false,
			Run: func() string {
				out, err := runCmd("php", "-r", "opcache_reset();")
				if err != nil {
					return fmt.Sprintf("[yellow]Note:[-] CLI opcache is separate from FPM (%v)", err)
				}
				return fmt.Sprintf("[green]OK:[-] %s", out)
			},
		},
	}
}

// ========================================================================
//  UI: BLOCK IP FORM (popup modal)
// ========================================================================

// ShowBlockIPForm displays the block IP popup.
// Call this from the keybinding handler in app.go.
func ShowBlockIPForm(app *tview.Application, pages *tview.Pages, tracker *ActionTracker, onDone func()) {
	showIPForm(app, pages, tracker, "block", onDone)
}

// ShowUnblockIPForm displays the unblock IP popup.
func ShowUnblockIPForm(app *tview.Application, pages *tview.Pages, tracker *ActionTracker, onDone func()) {
	showIPForm(app, pages, tracker, "unblock", onDone)
}

func showIPForm(app *tview.Application, pages *tview.Pages, tracker *ActionTracker, mode string, onDone func()) {
	title := " Block IP "
	if mode == "unblock" {
		title = " Unblock IP "
	}

	// Input field for IP
	ipInput := tview.NewInputField().
		SetLabel(" IP Address: ").
		SetFieldWidth(45).
		SetFieldBackgroundColor(tcell.ColorDarkSlateGray).
		SetFieldTextColor(tcell.ColorWhite)

	// Status/error label
	statusView := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)

	// Form layout
	formFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ipInput, 1, 0, true).
		AddItem(statusView, 3, 0, false)

	formFlex.SetBorder(true).
		SetTitle(title).
		SetTitleColor(tcell.ColorRed).
		SetBorderColor(tcell.ColorRed).
		SetTitleAlign(tview.AlignLeft)

	// Center the modal
	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(formFlex, 7, 0, true).
			AddItem(nil, 0, 1, false),
			60, 0, true).
		AddItem(nil, 0, 1, false)

	// Handle input
	ipInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			pages.RemovePage(pageActionForm)
			if onDone != nil {
				onDone()
			}
			return nil

		case tcell.KeyEnter:
			ip := strings.TrimSpace(ipInput.GetText())

			// Validate
			if errMsg := validateIP(ip); errMsg != "" {
				statusView.SetText(fmt.Sprintf(" [red]Error:[-] %s", errMsg))
				return nil
			}

			// Self-IP protection
			if mode == "block" && isSelfIP(ip) {
				selfIP := getSelfIP()
				statusView.SetText(fmt.Sprintf(
					" [red]REFUSED:[-] %s is your SSH session IP (%s)\n Cannot block yourself!",
					ip, selfIP))
				return nil
			}

			// Show confirmation
			pages.RemovePage(pageActionForm)
			showConfirm(app, pages, tracker, mode, ip, onDone)
			return nil
		}
		return event
	})

	selfIP := getSelfIP()
	hint := " [grey]Enter IP and press Enter. Esc to cancel.[-]"
	if selfIP != "" {
		hint = fmt.Sprintf(" [grey]Your SSH IP: %s (protected). Esc to cancel.[-]", selfIP)
	}
	statusView.SetText(hint)

	pages.AddPage(pageActionForm, modal, true, true)
	app.SetFocus(ipInput)
}

// ========================================================================
//  UI: CONFIRMATION DIALOG
// ========================================================================

func showConfirm(app *tview.Application, pages *tview.Pages, tracker *ActionTracker, mode, ip string, onDone func()) {
	action := "BLOCK"
	detail := fmt.Sprintf(
		"[white]IP:[-] [red::b]%s[-:-:-]\n\n"+
			"[white]Commands to execute:[-]\n"+
			" [grey]1.[-] csf -d %s\n"+
			" [grey]2.[-] scoots ip block %s\n"+
			" [grey]3.[-] csf -ra [grey](auto-restart CSF)[-]\n"+
			" [grey]4.[-] nprestart [grey](auto-restart nginx)[-]\n"+
			" [grey]5.[-] scoots php restart all\n",
		ip, ip, ip)

	if mode == "unblock" {
		action = "UNBLOCK"
		detail = fmt.Sprintf(
			"[white]IP:[-] [green::b]%s[-:-:-]\n\n"+
				"[white]Commands to execute:[-]\n"+
				" [grey]1.[-] csf -dr %s\n"+
				" [grey]2.[-] scoots ip unblock %s\n"+
				" [grey]3.[-] csf -ra [grey](auto-restart CSF)[-]\n",
			ip, ip, ip)
	}

	confirmView := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf(
			" [red::b]Confirm %s[-:-:-]\n\n%s\n [yellow]Press Y to confirm, N or Esc to cancel[-]",
			action, detail))

	confirmView.SetBorder(true).
		SetTitle(fmt.Sprintf(" Confirm %s ", action)).
		SetTitleColor(tcell.ColorYellow).
		SetBorderColor(tcell.ColorYellow).
		SetTitleAlign(tview.AlignLeft)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(confirmView, 14, 0, true).
			AddItem(nil, 0, 1, false),
			65, 0, true).
		AddItem(nil, 0, 1, false)

	confirmView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'y', 'Y':
			pages.RemovePage(pageConfirm)
			go executeAction(app, pages, tracker, mode, ip, onDone)
			return nil
		case 'n', 'N':
			pages.RemovePage(pageConfirm)
			if onDone != nil {
				onDone()
			}
			return nil
		}
		if event.Key() == tcell.KeyEscape {
			pages.RemovePage(pageConfirm)
			if onDone != nil {
				onDone()
			}
			return nil
		}
		return event
	})

	pages.AddPage(pageConfirm, modal, true, true)
	app.SetFocus(confirmView)
}

// ========================================================================
//  EXECUTE ACTION (runs in goroutine, updates UI)
// ========================================================================

func executeAction(app *tview.Application, pages *tview.Pages, tracker *ActionTracker, mode, ip string, onDone func()) {
	// Show "executing..." overlay
	app.QueueUpdateDraw(func() {
		spinView := tview.NewTextView().
			SetDynamicColors(true).
			SetTextAlign(tview.AlignCenter).
			SetText(fmt.Sprintf("\n\n [yellow]Executing %s on %s...[-]", mode, ip))
		spinView.SetBorder(true).SetBorderColor(tcell.ColorYellow)

		spinModal := tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(nil, 0, 1, false).
				AddItem(spinView, 5, 0, false).
				AddItem(nil, 0, 1, false),
				50, 0, false).
			AddItem(nil, 0, 1, false)

		pages.AddPage(pageResult, spinModal, true, true)
	})

	// Execute commands
	var result string
	if mode == "block" {
		result = blockIP(ip)
		tracker.AddBlocked(ip, "csf+scoots")
		logAction("BLOCK_IP", ip, "executed")
	} else {
		result = unblockIP(ip)
		tracker.RemoveBlocked(ip)
		logAction("UNBLOCK_IP", ip, "executed")
	}

	// Show result
	app.QueueUpdateDraw(func() {
		pages.RemovePage(pageResult)

		resultTitle := fmt.Sprintf(" %s Result: %s ", strings.ToUpper(mode), ip)
		resultView := tview.NewTextView().
			SetDynamicColors(true).
			SetText(fmt.Sprintf("\n %s\n\n [grey]Press any key to close[-]", result))

		resultView.SetBorder(true).
			SetTitle(resultTitle).
			SetTitleColor(tcell.ColorGreen).
			SetBorderColor(tcell.ColorGreen).
			SetTitleAlign(tview.AlignLeft)

		resultView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			pages.RemovePage(pageResult)
			if onDone != nil {
				onDone()
			}
			return nil
		})

		resultModal := tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(nil, 0, 1, false).
				AddItem(resultView, 12, 0, true).
				AddItem(nil, 0, 1, false),
				65, 0, true).
			AddItem(nil, 0, 1, false)

		pages.AddPage(pageResult, resultModal, true, true)
		app.SetFocus(resultView)
	})
}

// ========================================================================
//  UI: COMMAND PALETTE (service actions)
// ========================================================================

// ShowCommandPalette displays the service action list.
func ShowCommandPalette(app *tview.Application, pages *tview.Pages, onDone func()) {
	actions := DefaultServiceActions()

	list := tview.NewList()
	list.SetBorder(true).
		SetTitle(" Service Actions ").
		SetTitleColor(tcell.ColorAqua).
		SetBorderColor(tcell.ColorAqua).
		SetTitleAlign(tview.AlignLeft)
	list.SetBackgroundColor(tcell.ColorDefault)
	list.SetMainTextColor(tcell.ColorWhite)
	list.SetSecondaryTextColor(tcell.ColorGray)
	list.SetShortcutColor(tcell.ColorYellow)

	for i, action := range actions {
		shortcut := rune('1' + i)
		act := action // capture for closure
		list.AddItem(act.Name, act.Desc, shortcut, func() {
			pages.RemovePage(pagePalette)
			if act.Confirm {
				showServiceConfirm(app, pages, act, onDone)
			} else {
				go executeServiceAction(app, pages, act, onDone)
			}
		})
	}

	list.AddItem("Cancel", "Esc to close", 'c', func() {
		pages.RemovePage(pagePalette)
		if onDone != nil {
			onDone()
		}
	})

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			pages.RemovePage(pagePalette)
			if onDone != nil {
				onDone()
			}
			return nil
		}
		return event
	})

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(list, 14, 0, true).
			AddItem(nil, 0, 1, false),
			55, 0, true).
		AddItem(nil, 0, 1, false)

	pages.AddPage(pagePalette, modal, true, true)
	app.SetFocus(list)
}

// ========================================================================
//  SERVICE CONFIRM + EXECUTE
// ========================================================================

func showServiceConfirm(app *tview.Application, pages *tview.Pages, action ServiceAction, onDone func()) {
	confirmView := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf(
			"\n [yellow::b]Confirm: %s[-:-:-]\n\n"+
				" Command: [white]%s[-]\n\n"+
				" [yellow]Press Y to confirm, N or Esc to cancel[-]",
			action.Name, action.Desc))

	confirmView.SetBorder(true).
		SetTitle(" Confirm Service Action ").
		SetTitleColor(tcell.ColorYellow).
		SetBorderColor(tcell.ColorYellow).
		SetTitleAlign(tview.AlignLeft)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(confirmView, 9, 0, true).
			AddItem(nil, 0, 1, false),
			55, 0, true).
		AddItem(nil, 0, 1, false)

	confirmView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'y', 'Y':
			pages.RemovePage(pageConfirm)
			go executeServiceAction(app, pages, action, onDone)
			return nil
		case 'n', 'N':
			pages.RemovePage(pageConfirm)
			if onDone != nil {
				onDone()
			}
			return nil
		}
		if event.Key() == tcell.KeyEscape {
			pages.RemovePage(pageConfirm)
			if onDone != nil {
				onDone()
			}
			return nil
		}
		return event
	})

	pages.AddPage(pageConfirm, modal, true, true)
	app.SetFocus(confirmView)
}

func executeServiceAction(app *tview.Application, pages *tview.Pages, action ServiceAction, onDone func()) {
	logAction("SERVICE", action.Name, "started")
	result := action.Run()
	logAction("SERVICE", action.Name, "completed")

	app.QueueUpdateDraw(func() {
		resultView := tview.NewTextView().
			SetDynamicColors(true).
			SetText(fmt.Sprintf("\n [white::b]%s[-:-:-]\n\n %s\n\n [grey]Press any key to close[-]",
				action.Name, result))

		resultView.SetBorder(true).
			SetTitle(" Result ").
			SetTitleColor(tcell.ColorGreen).
			SetBorderColor(tcell.ColorGreen).
			SetTitleAlign(tview.AlignLeft)

		resultView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			pages.RemovePage(pageResult)
			if onDone != nil {
				onDone()
			}
			return nil
		})

		resultModal := tview.NewFlex().
			AddItem(nil, 0, 1, false).
			AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(nil, 0, 1, false).
				AddItem(resultView, 9, 0, true).
				AddItem(nil, 0, 1, false),
				55, 0, true).
			AddItem(nil, 0, 1, false)

		pages.AddPage(pageResult, resultModal, true, true)
		app.SetFocus(resultView)
	})
}
