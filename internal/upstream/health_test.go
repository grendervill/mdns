package upstream

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/testutil/scripted"
)

// discardLogger returns a logger that drops everything.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestMonitorRunStopsWithContext checks that Run returns once the
// context is cancelled.
func TestMonitorRunStopsWithContext(t *testing.T) {
	u := newTestUpstream(t, nil)

	opts := DefaultMonitorOptions()
	opts.Interval = 10 * time.Millisecond
	opts.IdleInterval = 10 * time.Millisecond

	m := NewMonitor([]*Upstream{u}, opts, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after the context was cancelled")
	}
}

// TestMonitorRunProbes checks that Run keeps probing while the context
// is alive.
func TestMonitorRunProbes(t *testing.T) {
	tr := scripted.New()
	tr.SetReply(func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(req)
		return m, nil
	})
	u := newTestUpstream(t, tr)

	opts := DefaultMonitorOptions()
	opts.Interval = 5 * time.Millisecond
	opts.IdleInterval = 5 * time.Millisecond

	m := NewMonitor([]*Upstream{u}, opts, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	m.Run(ctx)

	if got := tr.Calls(); got == 0 {
		t.Errorf("probes during Run = 0, want > 0")
	}
}

// TestMonitorRunRespectsIdleInterval checks the probing cadence: an
// upstream not used for a while is probed on the idle interval, while
// a recently used one is probed on the active interval.
func TestMonitorRunRespectsIdleInterval(t *testing.T) {
	tr := scripted.New()
	tr.SetReply(func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(req)
		return m, nil
	})
	u := newTestUpstream(t, tr)

	opts := DefaultMonitorOptions()
	opts.Interval = 5 * time.Millisecond
	opts.IdleInterval = 500 * time.Millisecond // much slower than the run window

	m := NewMonitor([]*Upstream{u}, opts, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	m.Run(ctx)

	// The never-used upstream is idle, so it should have been probed
	// once at most (the first pass), not on every active tick.
	if got := tr.Calls(); got > 2 {
		t.Errorf("probes for an idle upstream = %d, want <= 2 (idle interval 500ms)", got)
	}
}
