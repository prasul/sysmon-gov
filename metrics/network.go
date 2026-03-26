package metrics

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// ── Public types ────────────────────────────────────────────────────

type ConnState struct {
	Established int
	SynRecv     int
	TimeWait    int
	CloseWait   int
	FinWait     int
	Listen      int
	Other       int
	Total       int
}

type SynFloodEntry struct {
	IP    string
	Count int
}

type TopConnection struct {
	IP          string
	Total       int
	Established int
	SynRecv     int
	TimeWait    int
}

type NetworkStats struct {
	States        ConnState
	SynFloods     []SynFloodEntry
	TopConns      []TopConnection
	IsUnderAttack bool
}

// SYN flood threshold — lowered to 3 for early detection.
// On a healthy server, no single IP should have more than 1-2
// SYN_RECV connections at any instant.
const synFloodThreshold = 3

// ── Collector ───────────────────────────────────────────────────────

// GetNetworkStats combines data from two sources:
// 1. `ss` command (netlink) — sees SYN_RECV even with SYN cookies
// 2. /proc/net/tcp — general connection state counts
//
// This hybrid approach ensures we catch SYN floods regardless of
// kernel SYN cookie settings.
func GetNetworkStats(topN int) (*NetworkStats, error) {
	stats := &NetworkStats{}
	ipMap := make(map[string]*connAccum)

	// ── Primary: ss command for accurate state data ─────────────
	ssAvailable := collectFromSS(stats, ipMap)

	// ── Supplement: /proc/net/tcp if ss isn't available ──────────
	if !ssAvailable {
		collectFromProc(stats, ipMap)
	}

	// ── SYN-specific scan (always run for best detection) ───────
	collectSynRecvFromSS(stats, ipMap)

	// ── Build results ───────────────────────────────────────────
	for ip, acc := range ipMap {
		if acc.synRecv >= synFloodThreshold {
			stats.SynFloods = append(stats.SynFloods, SynFloodEntry{
				IP:    ip,
				Count: acc.synRecv,
			})
			stats.IsUnderAttack = true
		}
	}
	sort.Slice(stats.SynFloods, func(i, j int) bool {
		return stats.SynFloods[i].Count > stats.SynFloods[j].Count
	})

	allConns := make([]TopConnection, 0, len(ipMap))
	for ip, acc := range ipMap {
		allConns = append(allConns, TopConnection{
			IP:          ip,
			Total:       acc.total,
			Established: acc.established,
			SynRecv:     acc.synRecv,
			TimeWait:    acc.timeWait,
		})
	}
	sort.Slice(allConns, func(i, j int) bool {
		return allConns[i].Total > allConns[j].Total
	})
	if len(allConns) > topN {
		stats.TopConns = allConns[:topN]
	} else {
		stats.TopConns = allConns
	}

	return stats, nil
}

type connAccum struct {
	total       int
	established int
	synRecv     int
	timeWait    int
}

// ── ss command parsing ──────────────────────────────────────────────

// collectFromSS runs `ss -tn` and parses the output for general
// connection state counts.  Returns false if ss isn't available.
func collectFromSS(stats *NetworkStats, ipMap map[string]*connAccum) bool {
	out, err := exec.Command("ss", "-tn").Output()
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		state := fields[0]
		remoteAddr := fields[4]

		// Extract IP from addr:port or [ipv6]:port.
		ip := extractIPFromAddr(remoteAddr)
		if ip == "" || ip == "*" || ip == "0.0.0.0" || ip == "::" {
			continue
		}

		stats.States.Total++
		acc := getOrCreate(ipMap, ip)
		acc.total++

		switch state {
		case "ESTAB":
			stats.States.Established++
			acc.established++
		case "SYN-RECV":
			stats.States.SynRecv++
			acc.synRecv++
		case "TIME-WAIT":
			stats.States.TimeWait++
			acc.timeWait++
		case "CLOSE-WAIT":
			stats.States.CloseWait++
		case "FIN-WAIT-1", "FIN-WAIT-2":
			stats.States.FinWait++
		case "LISTEN":
			stats.States.Listen++
		default:
			stats.States.Other++
		}
	}
	return true
}

// collectSynRecvFromSS specifically queries for SYN_RECV connections.
// `ss -tn state syn-recv` uses netlink and sees the SYN backlog even
// when SYN cookies are enabled — unlike /proc/net/tcp.
func collectSynRecvFromSS(stats *NetworkStats, ipMap map[string]*connAccum) {
	out, err := exec.Command("ss", "-tn", "state", "syn-recv").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header.
		if fields[0] == "Recv-Q" || fields[0] == "State" {
			continue
		}

		// In `ss state syn-recv` output, the format is:
		// Recv-Q  Send-Q  Local  Peer
		// The state column is omitted since we filtered by state.
		var remoteAddr string
		if len(fields) >= 4 {
			remoteAddr = fields[3]
		} else if len(fields) >= 3 {
			remoteAddr = fields[2]
		}

		ip := extractIPFromAddr(remoteAddr)
		if ip == "" || ip == "*" {
			continue
		}

		acc := getOrCreate(ipMap, ip)
		// Only count if we haven't already counted this from the
		// general ss -tn scan above.
		if acc.synRecv == 0 {
			stats.States.SynRecv++
			stats.States.Total++
			acc.total++
		}
		acc.synRecv++
	}
}

// ── /proc/net/tcp fallback ──────────────────────────────────────────

func collectFromProc(stats *NetworkStats, ipMap map[string]*connAccum) {
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(procFile)
		if err != nil {
			continue
		}

		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}

			state := fields[3]
			remoteAddr := fields[2]
			ip := parseHexIP(remoteAddr)

			if ip == "0.0.0.0" || ip == "::" {
				continue
			}

			stats.States.Total++

			switch state {
			case "01":
				stats.States.Established++
			case "03":
				stats.States.SynRecv++
			case "06":
				stats.States.TimeWait++
			case "08":
				stats.States.CloseWait++
			case "04", "05":
				stats.States.FinWait++
			case "0A":
				stats.States.Listen++
				continue // don't count LISTEN in per-IP
			default:
				stats.States.Other++
			}

			acc := getOrCreate(ipMap, ip)
			acc.total++
			switch state {
			case "01":
				acc.established++
			case "03":
				acc.synRecv++
			case "06":
				acc.timeWait++
			}
		}
	}
}

// ── IP extraction helpers ───────────────────────────────────────────

// extractIPFromAddr parses an IP from ss output formats:
//   "1.2.3.4:80"
//   "[::1]:80"
//   "[2a09:bac2::4c4]:443"
//   "*:80"
func extractIPFromAddr(addr string) string {
	if addr == "" {
		return ""
	}

	// IPv6 in brackets: [addr]:port
	if strings.HasPrefix(addr, "[") {
		end := strings.IndexByte(addr, ']')
		if end > 1 {
			return addr[1:end]
		}
		return ""
	}

	// IPv4 or bare IPv6: find the last colon (port separator).
	// For IPv6 without brackets (rare in ss output), we check for
	// multiple colons.
	lastColon := strings.LastIndexByte(addr, ':')
	if lastColon <= 0 {
		return addr
	}

	host := addr[:lastColon]

	// If host contains colons, it's IPv6 — return as-is.
	if strings.Contains(host, ":") {
		return host
	}

	return host
}

// parseHexIP converts hex-encoded IP:port from /proc/net/tcp.
func parseHexIP(addrPort string) string {
	parts := strings.SplitN(addrPort, ":", 2)
	if len(parts) < 1 {
		return ""
	}
	hexIP := parts[0]

	switch len(hexIP) {
	case 8:
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 4 {
			return hexIP
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])

	case 32:
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 16 {
			return hexIP
		}
		for i := 0; i < 16; i += 4 {
			b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
		}
		return net.IP(b).String()

	default:
		return hexIP
	}
}

func ParsePort(addrPort string) int {
	parts := strings.SplitN(addrPort, ":", 2)
	if len(parts) < 2 {
		return 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	return int(port)
}

func getOrCreate(m map[string]*connAccum, ip string) *connAccum {
	acc, ok := m[ip]
	if !ok {
		acc = &connAccum{}
		m[ip] = acc
	}
	return acc
}
