// Package upstream wraps a transport with the identity and live health
// state that the router and the health monitor work with.
package upstream

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/transport"
)

// Status is an upstream's health state as seen by the monitor.
type Status int

const (
	// Healthy is the initial state and the state a successful probe
	// restores.
	Healthy Status = iota
	// Unhealthy is reached after unhealthyAfter failed probes in a row.
	Unhealthy
)

// EWMA constants: alpha 0.2 as an exact integer fraction; an unhealthy
// probe sets the average to the penalty value, so a recovered upstream
// climbs back toward its real latency instead of jumping to the top.
const (
	ewmaAlphaNum   = 2
	ewmaAlphaDen   = 10
	ewmaPenalty    = 5 * time.Second
	unhealthyAfter = 3
)

// Upstream is one configured upstream resolver with its live health
// state. All methods are safe for concurrent use.
type Upstream struct {
	ID       string
	Name     string
	Priority int
	Address  string

	tr      transport.Transport
	enabled bool

	mu       sync.Mutex
	ewma     time.Duration
	measured bool // false until the first probe result arrives
	status   Status
	failures int

	sent     atomic.Uint64
	failed   atomic.Uint64
	lastUsed atomic.Int64 // unix nanoseconds; 0 means never used
}

// New builds the upstream's transport from cfg.
func New(cfg config.UpstreamConfig) (*Upstream, error) {
	tr, err := transport.New(cfg)
	if err != nil {
		return nil, err
	}
	return NewWithTransport(cfg, tr), nil
}

// NewWithTransport builds an upstream around tr instead of creating
// one from cfg.Transport; tests and custom wiring use it.
func NewWithTransport(cfg config.UpstreamConfig, tr transport.Transport) *Upstream {
	return &Upstream{
		ID:       cfg.ID,
		Name:     cfg.Name,
		Priority: cfg.Priority,
		Address:  cfg.Address,
		tr:       tr,
		enabled:  cfg.Enabled,
		status:   Healthy,
	}
}

// Transport returns the underlying transport.
func (u *Upstream) Transport() transport.Transport { return u.tr }

// Enabled reports whether the upstream takes part in routing.
func (u *Upstream) Enabled() bool { return u.enabled }

// Exchange sends the query through the transport, records the activity
// time (which drives the monitor's probing cadence) and updates the
// sent and failed counters.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	u.lastUsed.Store(time.Now().UnixNano())

	resp, err := u.tr.Exchange(ctx, req)
	u.sent.Add(1)
	if err != nil {
		u.failed.Add(1)
		return nil, err
	}
	return resp, nil
}

// ObserveProbe folds one health probe result into the EWMA and the
// status. A failure sets the average to the penalty value; the
// unhealthyAfter-th consecutive failure marks the upstream unhealthy;
// a single success brings it back.
func (u *Upstream) ObserveProbe(success bool, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !success {
		u.failures++
		u.ewma = ewmaPenalty
		u.measured = true
		if u.failures >= unhealthyAfter {
			u.status = Unhealthy
		}
		return
	}

	u.failures = 0
	if !u.measured {
		u.ewma = latency
	} else {
		u.ewma = time.Duration(
			(int64(latency)*ewmaAlphaNum + int64(u.ewma)*(ewmaAlphaDen-ewmaAlphaNum)) / ewmaAlphaDen,
		)
	}
	u.measured = true
	u.status = Healthy
}

// Status returns the current health state.
func (u *Upstream) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

// EWMA returns the smoothed probe latency.
func (u *Upstream) EWMA() time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ewma
}

// Stats returns how many exchanges were sent and how many failed.
func (u *Upstream) Stats() (sent, failed uint64) {
	return u.sent.Load(), u.failed.Load()
}

// lastUsedTime returns when the upstream last answered an exchange, or
// the zero time if it never did.
func (u *Upstream) lastUsedTime() time.Time {
	n := u.lastUsed.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
