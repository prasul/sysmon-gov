package metrics

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// ========================================================================
//  OUTBOUND CONNECTION MONITOR
// ========================================================================
//
// Detects the failure mode that caused the outage:  the SERVER making
// outbound connections that pile up because the remote end stops
// responding.  A hung plugin (e.g. wp-rocket's Mixpanel telemetry)
// fires wp_remote_get() to a remote host; those sockets stack up in
// FIN_WAIT1 / SYN_SENT and eventually exhaust ephemeral ports.
//
// The existing SYN flood detector only watches INBOUND (SYN_RECV).
// This watches OUTBOUND, grouped by REMOTE destination, and flags:
//
//   - Many FIN_WAIT1 to one remote  → remote stopped ACKing our FIN
//     (our close is stuck; the classic "hung outbound call" signature)
//   - Many SYN_SENT to one remote   → we can't even connect (remote
//     down / firewalled / DNS blackhole)
//   - High total outbound to one remote → runaway plugin / scraper
//
// States that indicate trouble (per remote):
//   SYN_SENT   — connection attempt, no reply yet
//   FIN_WAIT1  — we sent FIN, waiting for ACK (stuck if remote gone)
//   FIN_WAIT2  — remote ACKed our FIN, waiting for their FIN
//   CLOSE_WAIT — remote closed, WE haven't (app not closing socket)

// OutboundRemote aggregates outbound connections to one remote IP:port.
type OutboundRemote struct {
	RemoteIP    string
	RemotePort  int
	Total       int
	Established int
	SynSent     int
	FinWait1    int
	FinWait2    int
	TimeWait    int
	CloseWait   int

	// Stuck = SynSent + FinWait1 + FinWait2 + CloseWait — the states
	// that indicate the remote is unresponsive or the app is leaking.
	Stuck int

	// Process attribution — which processes own these sockets.
	// Populated from `ss -tnp`.  Key insight: many php-fpm workers
	// tied up on one remote = workers starved from serving real
	// traffic, EVEN while connections are still ESTABLISHED.
	Procs     map[string]int // "php-fpm" → count
	WorkerPIDs []int         // distinct owning PIDs (capped)
}

// OutboundStats is the full outbound picture.
type OutboundStats struct {
	TopRemotes    []OutboundRemote
	TotalOutbound int
	TotalStuck    int

	// Alerts are human-readable warnings about specific remotes.
	Alerts []OutboundAlert

	IsUnderStress bool // true if any remote crossed a threshold
}

// OutboundAlert describes one flagged remote.
type OutboundAlert struct {
	Severity int // 1=warning, 2=critical
	RemoteIP string
	Message  string
}

// Thresholds for outbound pileup detection.
const (
	// Stuck connections to a single remote that trigger warning/critical.
	outboundStuckWarn = 15
	outboundStuckCrit = 40

	// Total outbound to a single remote (runaway plugin indicator).
	outboundTotalWarn = 60

	// ESTABLISHED connections to a single remote — the EARLY warning,
	// before sockets time out into FIN_WAIT1.  Many workers tied up
	// on one remote means they can't serve real traffic.  This is the
	// window where the earlier snapshot (10+ ESTABLISHED php-fpm to
	// 5.249.224.2) should have fired.
	outboundEstabWarn = 10
	outboundEstabCrit = 25
)

// GetOutboundStats scans for outbound connections grouped by remote.
// Uses `ss -tn state all` which includes non-ESTABLISHED states, then
// filters to connections where the LOCAL side is the ephemeral (high)
// port — i.e. connections WE initiated.
func GetOutboundStats(topN int) (*OutboundStats, error) {
	stats := &OutboundStats{}

	// `ss -tnp state connected` lists all non-listening TCP with
	// numeric addresses AND the owning process (-p).  We include all
	// states so FIN_WAIT1 etc. show up (default `ss -tn` shows only
	// ESTABLISHED).  The -p flag adds a process column like:
	//   users:(("php-fpm",pid=540906,fd=12))
	out, err := exec.Command("ss", "-tnp", "state", "connected").Output()
	if err != nil {
		// Fallback: try the broader form (may lack process info if
		// not run as root).
		out, err = exec.Command("ss", "-tanp").Output()
		if err != nil {
			// Last resort: no process info.
			out, err = exec.Command("ss", "-tn", "state", "connected").Output()
			if err != nil {
				return stats, err
			}
		}
	}

	remotes := make(map[string]*OutboundRemote)

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// `ss -tanp` format: State Recv-Q Send-Q Local Peer Process
		// `ss -tnp state connected`: Recv-Q Send-Q Local Peer Process
		var state, local, peer, procInfo string
		if isState(fields[0]) {
			state = fields[0]
			local = fields[3]
			peer = fields[4]
			if len(fields) >= 6 {
				procInfo = fields[5]
			}
		} else {
			state = "ESTAB"
			local = fields[2]
			peer = fields[3]
			if len(fields) >= 5 {
				procInfo = fields[4]
			}
		}

		localPort := ParsePort(local)
		remoteIP := extractIPFromAddr(peer)
		remotePort := ParsePort(peer)

		if remoteIP == "" || remoteIP == "0.0.0.0" || remoteIP == "*" {
			continue
		}

		if !isLikelyOutbound(localPort, remotePort) {
			continue
		}

		key := remoteIP + ":" + strconv.Itoa(remotePort)
		r, ok := remotes[key]
		if !ok {
			r = &OutboundRemote{
				RemoteIP:   remoteIP,
				RemotePort: remotePort,
				Procs:      make(map[string]int),
			}
			remotes[key] = r
		}
		r.Total++
		stats.TotalOutbound++

		// Attribute to the owning process.
		if procInfo != "" {
			pname, pid := parseSSProcess(procInfo)
			if pname != "" {
				r.Procs[pname]++
			}
			if pid > 0 && len(r.WorkerPIDs) < 20 {
				r.WorkerPIDs = append(r.WorkerPIDs, pid)
			}
		}

		switch state {
		case "ESTAB":
			r.Established++
		case "SYN-SENT":
			r.SynSent++
			r.Stuck++
			stats.TotalStuck++
		case "FIN-WAIT-1":
			r.FinWait1++
			r.Stuck++
			stats.TotalStuck++
		case "FIN-WAIT-2":
			r.FinWait2++
			r.Stuck++
			stats.TotalStuck++
		case "TIME-WAIT":
			r.TimeWait++
		case "CLOSE-WAIT":
			r.CloseWait++
			r.Stuck++
			stats.TotalStuck++
		}
	}

	// Flatten + sort.  Sort by a "concern score": stuck connections
	// weigh most, but a large ESTABLISHED count to one remote is also
	// concerning (the early-stage signal), so factor it in.
	for _, r := range remotes {
		stats.TopRemotes = append(stats.TopRemotes, *r)
	}
	sort.Slice(stats.TopRemotes, func(i, j int) bool {
		si := concernScore(stats.TopRemotes[i])
		sj := concernScore(stats.TopRemotes[j])
		if si != sj {
			return si > sj
		}
		return stats.TopRemotes[i].Total > stats.TopRemotes[j].Total
	})

	// ── Generate alerts ──
	for i := range stats.TopRemotes {
		r := &stats.TopRemotes[i]
		procStr := topProcName(r.Procs)

		switch {
		// Stuck sockets (late stage — already timing out).
		case r.Stuck >= outboundStuckCrit:
			stats.IsUnderStress = true
			stats.Alerts = append(stats.Alerts, OutboundAlert{
				Severity: 2,
				RemoteIP: r.RemoteIP,
				Message: fmtOut("%d stuck outbound to %s:%d (%d FIN_WAIT1, %d SYN_SENT)%s — remote unresponsive, exhausting sockets",
					r.Stuck, r.RemoteIP, r.RemotePort, r.FinWait1, r.SynSent, procStr),
			})

		// ESTABLISHED pileup (EARLY stage — the window we missed).
		// Many workers tied up on ONE remote, still connected but
		// starved from serving real traffic.
		case r.Established >= outboundEstabCrit:
			stats.IsUnderStress = true
			stats.Alerts = append(stats.Alerts, OutboundAlert{
				Severity: 2,
				RemoteIP: r.RemoteIP,
				Message: fmtOut("%d workers tied up on %s:%d%s — outbound call storm, workers starved",
					r.Established, r.RemoteIP, r.RemotePort, procStr),
			})

		case r.Stuck >= outboundStuckWarn:
			stats.IsUnderStress = true
			stats.Alerts = append(stats.Alerts, OutboundAlert{
				Severity: 1,
				RemoteIP: r.RemoteIP,
				Message: fmtOut("%d stuck outbound to %s:%d%s — remote may be slow/down",
					r.Stuck, r.RemoteIP, r.RemotePort, procStr),
			})

		case r.Established >= outboundEstabWarn:
			stats.IsUnderStress = true
			stats.Alerts = append(stats.Alerts, OutboundAlert{
				Severity: 1,
				RemoteIP: r.RemoteIP,
				Message: fmtOut("%d workers connected to %s:%d%s — watch for outbound storm",
					r.Established, r.RemoteIP, r.RemotePort, procStr),
			})

		case r.Total >= outboundTotalWarn:
			stats.IsUnderStress = true
			stats.Alerts = append(stats.Alerts, OutboundAlert{
				Severity: 1,
				RemoteIP: r.RemoteIP,
				Message: fmtOut("%d outbound to %s:%d%s — runaway plugin/scraper?",
					r.Total, r.RemoteIP, r.RemotePort, procStr),
			})
		}
	}

	// Keep top N for display.
	if len(stats.TopRemotes) > topN {
		stats.TopRemotes = stats.TopRemotes[:topN]
	}

	return stats, nil
}

// concernScore ranks a remote by how worrying it is.  Stuck sockets
// count triple (they indicate an active problem); established count
// singly (early warning).
func concernScore(r OutboundRemote) int {
	return r.Stuck*3 + r.Established
}

// topProcName returns a " [php-fpm ×12]" suffix for the busiest process
// owning connections to a remote, or "" if unknown.
func topProcName(procs map[string]int) string {
	best := ""
	bestN := 0
	for name, n := range procs {
		if n > bestN {
			bestN = n
			best = name
		}
	}
	if best == "" {
		return ""
	}
	return fmtOut(" [%s ×%d]", best, bestN)
}

// parseSSProcess extracts process name and PID from an ss -p process
// field like:  users:(("php-fpm",pid=540906,fd=12))
func parseSSProcess(s string) (name string, pid int) {
	// Find the first quoted name.
	q1 := strings.IndexByte(s, '"')
	if q1 < 0 {
		return "", 0
	}
	q2 := strings.IndexByte(s[q1+1:], '"')
	if q2 < 0 {
		return "", 0
	}
	name = s[q1+1 : q1+1+q2]

	// Find pid=NNNN.
	if idx := strings.Index(s, "pid="); idx >= 0 {
		rest := s[idx+4:]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		pid, _ = strconv.Atoi(rest[:end])
	}
	return name, pid
}

// isLikelyOutbound returns true if the port pattern suggests we are
// the client (outbound connection).
func isLikelyOutbound(localPort, remotePort int) bool {
	// Remote is a well-known service port and local is ephemeral.
	commonRemotePorts := map[int]bool{
		443: true, 80: true, 8080: true, 8443: true,
		3306: true, 5432: true, 6379: true, 11211: true,
		25: true, 587: true, 465: true, 993: true, 995: true,
		53: true, 123: true, 9200: true, 27017: true,
	}
	if commonRemotePorts[remotePort] && localPort >= 1024 {
		return true
	}
	// Both high ports but local higher than remote — ambiguous, skip.
	return false
}

// isState reports whether a token is a TCP state name (as printed by ss).
func isState(s string) bool {
	switch s {
	case "ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2",
		"TIME-WAIT", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "CLOSE",
		"LISTEN", "UNCONN":
		return true
	}
	return false
}

func fmtOut(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
