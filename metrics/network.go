package metrics

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ── Public types ────────────────────────────────────────────────────

// ConnState summarizes connection counts by TCP state.
type ConnState struct {
	Established int
	SynRecv     int // SYN_RECV — key indicator of SYN floods
	TimeWait    int
	CloseWait   int
	FinWait     int
	Listen      int
	Other       int
	Total       int
}

// SynFloodEntry represents one IP with an abnormal number of
// SYN_RECV connections — a strong indicator of a SYN flood attack.
type SynFloodEntry struct {
	IP    string
	Count int
}

// TopConnection represents a remote IP with the most connections
// (any state) to this server.
type TopConnection struct {
	IP          string
	Total       int
	Established int
	SynRecv     int
	TimeWait    int
}

// NetworkStats holds the complete snapshot.
type NetworkStats struct {
	States     ConnState
	SynFloods  []SynFloodEntry  // IPs with SYN_RECV count ≥ threshold
	TopConns   []TopConnection  // IPs with most total connections
	IsUnderAttack bool          // true if any IP has SYN_RECV ≥ threshold
}

// TCP state codes from the Linux kernel (include/net/tcp_states.h).
const (
	tcpEstablished = "01"
	tcpSynSent     = "02"
	tcpSynRecv     = "03"
	tcpFinWait1    = "04"
	tcpFinWait2    = "05"
	tcpTimeWait    = "06"
	tcpClose       = "07"
	tcpCloseWait   = "08"
	tcpLastAck     = "09"
	tcpListen      = "0A"
	tcpClosing     = "0B"
)

// SYN flood threshold — an IP with this many SYN_RECV connections
// is flagged as a potential attacker.
const synFloodThreshold = 10

// ── Collector ───────────────────────────────────────────────────────

// GetNetworkStats reads /proc/net/tcp and /proc/net/tcp6 and returns
// a complete connection snapshot with SYN flood detection.
func GetNetworkStats(topN int) (*NetworkStats, error) {
	stats := &NetworkStats{}

	// Per-IP accumulators.
	type ipAccum struct {
		total       int
		established int
		synRecv     int
		timeWait    int
	}
	ipMap := make(map[string]*ipAccum)

	// Parse both IPv4 and IPv6.
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(procFile)
		if err != nil {
			continue // IPv6 might not be loaded
		}

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // header line
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}

			// Field 1: local_address (hex_ip:hex_port)
			// Field 2: remote_address (hex_ip:hex_port)
			// Field 3: state (hex, 2 digits)
			state := fields[3]
			remoteAddr := fields[2]

			// Parse remote IP.
			remoteIP := parseHexIP(remoteAddr)

			// Aggregate by state.
			stats.States.Total++
			switch state {
			case tcpEstablished:
				stats.States.Established++
			case tcpSynRecv:
				stats.States.SynRecv++
			case tcpTimeWait:
				stats.States.TimeWait++
			case tcpCloseWait:
				stats.States.CloseWait++
			case tcpFinWait1, tcpFinWait2:
				stats.States.FinWait++
			case tcpListen:
				stats.States.Listen++
			default:
				stats.States.Other++
			}

			// Skip listening sockets and connections to 0.0.0.0
			if state == tcpListen || remoteIP == "0.0.0.0" || remoteIP == "::" {
				continue
			}

			// Aggregate per remote IP.
			acc, ok := ipMap[remoteIP]
			if !ok {
				acc = &ipAccum{}
				ipMap[remoteIP] = acc
			}
			acc.total++
			switch state {
			case tcpEstablished:
				acc.established++
			case tcpSynRecv:
				acc.synRecv++
			case tcpTimeWait:
				acc.timeWait++
			}
		}
	}

	// ── SYN Flood detection ─────────────────────────────────────
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

	// ── Top connections by total count ───────────────────────────
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

// ── Hex IP parsing ──────────────────────────────────────────────────

// parseHexIP converts the hex-encoded IP:port from /proc/net/tcp
// into a human-readable IP string.
//
// IPv4 format: "0100007F:0050" → "127.0.0.1"
// IPv6 format: "00000000000000000000000001000000:0050" → "::1"
//
// Linux stores IPv4 addresses in little-endian (reversed bytes).
// IPv6 addresses are stored as four 32-bit words, each in host
// byte order (little-endian on x86).
func parseHexIP(addrPort string) string {
	parts := strings.SplitN(addrPort, ":", 2)
	if len(parts) < 1 {
		return ""
	}
	hexIP := parts[0]

	switch len(hexIP) {
	case 8:
		// IPv4 — 4 bytes in little-endian hex.
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 4 {
			return hexIP
		}
		// Reverse byte order (little-endian → big-endian).
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])

	case 32:
		// IPv6 — 16 bytes as four 32-bit LE words.
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 16 {
			return hexIP
		}
		// Reverse each 4-byte word.
		for i := 0; i < 16; i += 4 {
			b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
		}
		ip := net.IP(b)
		return ip.String()

	default:
		return hexIP
	}
}

// ── Helper for UI ───────────────────────────────────────────────────

// FormatConnState returns a one-line summary of connection states.
func FormatConnState(s ConnState) string {
	return fmt.Sprintf("ESTAB:%d  SYN_RECV:%d  TIME_WAIT:%d  CLOSE_WAIT:%d  LISTEN:%d  Total:%d",
		s.Established, s.SynRecv, s.TimeWait, s.CloseWait, s.Listen, s.Total)
}

// ParsePort extracts the port number from a hex "IP:PORT" string.
func ParsePort(addrPort string) int {
	parts := strings.SplitN(addrPort, ":", 2)
	if len(parts) < 2 {
		return 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	return int(port)
}
