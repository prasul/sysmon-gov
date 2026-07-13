package metrics

import (
	"sync"
	"time"
)

// HistorySample is one point-in-time snapshot of the metrics that
// matter most for after-the-fact "what caused this" analysis: load,
// memory, CPU, and how busy the noisiest subsystems were.
//
// Cumulative counters (ReqTotal, WPLoginHit, BotHits, PHPSlow,
// NgxErrors) are recorded as running totals at sample time — the
// report layer diffs consecutive samples to get a rate.
type HistorySample struct {
	Time time.Time

	Load1  float64
	Load5  float64
	CPUPct float64
	MemPct float64

	TopCPUProc    string
	TopCPUPercent float64
	TopMemProc    string
	TopMemPercent float64

	MySQLActive int
	MySQLQPS    float64

	ReqTotal   int
	WPLoginHit int
	BotHits    int
	PHPSlow    int
	NgxErrors  int
}

// History keeps a rolling window of samples in memory so a report
// generated on demand can show a timeline instead of a single
// snapshot, and can show roughly when a spike started. There is no
// disk persistence — history resets when sysmon restarts.
type History struct {
	mu      sync.Mutex
	window  time.Duration
	samples []HistorySample
}

// NewHistory creates a history buffer that retains samples for the
// given window (e.g. 30 minutes). Older samples are evicted as new
// ones are recorded.
func NewHistory(window time.Duration) *History {
	if window <= 0 {
		window = 30 * time.Minute
	}
	return &History{window: window}
}

// Record appends a sample and evicts anything older than the window.
func (h *History) Record(s HistorySample) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.samples = append(h.samples, s)

	cutoff := s.Time.Add(-h.window)
	i := 0
	for i < len(h.samples) && h.samples[i].Time.Before(cutoff) {
		i++
	}
	if i > 0 {
		h.samples = h.samples[i:]
	}
}

// Samples returns a copy of the current buffer, oldest first.
func (h *History) Samples() []HistorySample {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]HistorySample, len(h.samples))
	copy(out, h.samples)
	return out
}

// Window reports the configured retention window.
func (h *History) Window() time.Duration {
	return h.window
}
