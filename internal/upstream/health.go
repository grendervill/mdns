package upstream

import (
	"context"
	"log/slog"
	"time"

	"github.com/miekg/dns"
)

// idleAfter is how long an unused upstream keeps its active cadence
// before the monitor drops it to the idle one.
const idleAfter = 30 * time.Second

// MonitorOptions tune the health probing.
type MonitorOptions struct {
	// Interval is the probing period for recently used upstreams.
	Interval time.Duration
	// IdleInterval is the period for upstreams unused for idleAfter.
	IdleInterval time.Duration
	// Timeout bounds one probe.
	Timeout time.Duration
}

// DefaultMonitorOptions returns the production cadence: 1s for active
// upstreams, 5s for idle ones, 2s per probe.
func DefaultMonitorOptions() MonitorOptions {
	return MonitorOptions{
		Interval:     time.Second,
		IdleInterval: 5 * time.Second,
		Timeout:      2 * time.Second,
	}
}

// Monitor probes upstreams with "NS ." queries and feeds the results
// into each upstream's health state.
type Monitor struct {
	ups  []*Upstream
	opts MonitorOptions
	log  *slog.Logger
}

// NewMonitor builds a monitor over ups; zero-valued options fall back
// to DefaultMonitorOptions, and a nil logger to slog.Default.
func NewMonitor(ups []*Upstream, opts MonitorOptions, logger *slog.Logger) *Monitor {
	def := DefaultMonitorOptions()
	if opts.Interval <= 0 {
		opts.Interval = def.Interval
	}
	if opts.IdleInterval <= 0 {
		opts.IdleInterval = def.IdleInterval
	}
	if opts.Timeout <= 0 {
		opts.Timeout = def.Timeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{ups: ups, opts: opts, log: logger}
}

// Probe runs one probing pass over every enabled upstream. The wizard
// uses it for its latency table; Run uses the cadence below.
func (m *Monitor) Probe(ctx context.Context) {
	for _, u := range m.ups {
		if !u.Enabled() {
			continue
		}
		m.probeOne(ctx, u)
	}
}

// Run probes until ctx is cancelled: recently used upstreams every
// Interval, idle ones every IdleInterval.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.opts.Interval)
	defer ticker.Stop()

	lastProbe := make(map[*Upstream]time.Time)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, u := range m.ups {
				if !u.Enabled() {
					continue
				}

				recent := !u.lastUsedTime().IsZero() && now.Sub(u.lastUsedTime()) < idleAfter
				want := m.opts.IdleInterval
				if recent {
					want = m.opts.Interval
				}
				if now.Sub(lastProbe[u]) < want {
					continue
				}
				lastProbe[u] = now
				m.probeOne(ctx, u)
			}
		}
	}
}

// probeOne sends the probe query through u and records the outcome.
// The reply counts as healthy when it arrives in time, is not
// truncated and is not SERVFAIL or REFUSED: NXDOMAIN is a fine answer
// to "NS ." and means the upstream resolves.
func (m *Monitor) probeOne(ctx context.Context, u *Upstream) {
	pctx, cancel := context.WithTimeout(ctx, m.opts.Timeout)
	defer cancel()

	q := new(dns.Msg)
	q.SetQuestion(".", dns.TypeNS)

	// The probe goes through the transport directly: it must not count
	// as upstream activity, or an idle upstream would look active (its
	// own probes keeping it "used") and never drop to the idle
	// cadence.
	start := time.Now()
	resp, err := u.Transport().Exchange(pctx, q)
	if err != nil {
		u.ObserveProbe(false, 0)
		m.log.Debug("probe failed", "upstream", u.ID, "error", err)
		return
	}

	if resp.Truncated || resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
		u.ObserveProbe(false, 0)
		m.log.Debug("probe rejected",
			"upstream", u.ID,
			"rcode", dns.RcodeToString[resp.Rcode],
			"truncated", resp.Truncated,
		)
		return
	}
	u.ObserveProbe(true, time.Since(start))
}
