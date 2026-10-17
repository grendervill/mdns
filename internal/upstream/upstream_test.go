package upstream

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/transport"
)

// scriptedTransport is a hand-scripted Transport for tests: replies
// come from a settable function and every request is recorded.
type scriptedTransport struct {
	mu    sync.Mutex
	reply func(*dns.Msg) (*dns.Msg, error)
	calls []*dns.Msg
}

func (s *scriptedTransport) Name() string { return "scripted" }

func (s *scriptedTransport) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req.Copy())
	f := s.reply
	s.mu.Unlock()

	if f == nil {
		return nil, fmt.Errorf("scripted: no reply configured")
	}
	return f(req)
}

func (s *scriptedTransport) Close() error { return nil }

func (s *scriptedTransport) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *scriptedTransport) lastCall(t *testing.T) *dns.Msg {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("scriptedTransport saw no calls")
	}
	return s.calls[len(s.calls)-1]
}

// newTestUpstream builds an upstream around tr; a nil tr is replaced by
// a scripted one.
func newTestUpstream(t *testing.T, tr transport.Transport) *Upstream {
	t.Helper()
	if tr == nil {
		tr = &scriptedTransport{}
	}
	return NewWithTransport(config.UpstreamConfig{
		ID:        "test",
		Name:      "Test upstream",
		Transport: "plain",
		Address:   "127.0.0.1:53",
		Priority:  0,
		Enabled:   true,
	}, tr)
}

// TestNewBuildsTransport checks that New wires a real transport from
// the config and carries the identity fields over.
func TestNewBuildsTransport(t *testing.T) {
	u, err := New(config.UpstreamConfig{
		ID:        "cloudflare-doh",
		Name:      "Cloudflare",
		Transport: "doh",
		Address:   "https://cloudflare-dns.com/dns-query",
		Priority:  2,
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
	if u.ID != "cloudflare-doh" || u.Name != "Cloudflare" || u.Priority != 2 {
		t.Errorf("identity = (%q, %q, %d), want (cloudflare-doh, Cloudflare, 2)", u.ID, u.Name, u.Priority)
	}
	if got := u.Transport().Name(); got != "doh" {
		t.Errorf("Transport().Name() = %q, want doh", got)
	}
	if !u.Enabled() {
		t.Errorf("Enabled() = false, want true")
	}

	if _, err := New(config.UpstreamConfig{ID: "x", Transport: "quic", Address: "127.0.0.1:1"}); err == nil {
		t.Errorf("New(quic) = nil error, want unsupported transport error")
	}
}

// TestExchangeCountsStats checks that Exchange delegates to the
// transport and tracks sent and failed queries.
func TestExchangeCountsStats(t *testing.T) {
	tr := &scriptedTransport{}
	u := newTestUpstream(t, tr)

	tr.reply = func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(req)
		return m, nil
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	if _, err := u.Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if sent, failed := u.Stats(); sent != 1 || failed != 0 {
		t.Errorf("Stats() = (%d, %d), want (1, 0)", sent, failed)
	}

	tr.reply = func(*dns.Msg) (*dns.Msg, error) { return nil, fmt.Errorf("dial refused") }
	if _, err := u.Exchange(context.Background(), q); err == nil {
		t.Fatalf("Exchange() = nil error, want the transport's error")
	}
	if sent, failed := u.Stats(); sent != 2 || failed != 1 {
		t.Errorf("Stats() = (%d, %d), want (2, 1)", sent, failed)
	}
}

// TestObserveProbeEWMA checks the EWMA math (alpha = 0.2): the first
// success seeds the average, later ones decay toward the new value.
func TestObserveProbeEWMA(t *testing.T) {
	u := newTestUpstream(t, nil)

	u.ObserveProbe(true, 10*time.Millisecond)
	if got := u.EWMA(); got != 10*time.Millisecond {
		t.Errorf("EWMA after first probe = %v, want 10ms", got)
	}
	u.ObserveProbe(true, 20*time.Millisecond)
	if got := u.EWMA(); got != 12*time.Millisecond { // 0.2*20 + 0.8*10
		t.Errorf("EWMA after second probe = %v, want 12ms", got)
	}
	if got := u.Status(); got != Healthy {
		t.Errorf("Status() = %v, want Healthy", got)
	}
}

// TestUnhealthyAfterThreeFailures checks the failure threshold and the
// penalty value: three failures in a row mark the upstream unhealthy
// and push its EWMA to 5s.
func TestUnhealthyAfterThreeFailures(t *testing.T) {
	u := newTestUpstream(t, nil)

	u.ObserveProbe(false, 0)
	u.ObserveProbe(false, 0)
	if got := u.Status(); got != Healthy {
		t.Errorf("Status() after two failures = %v, want Healthy", got)
	}

	u.ObserveProbe(false, 0)
	if got := u.Status(); got != Unhealthy {
		t.Errorf("Status() after three failures = %v, want Unhealthy", got)
	}
	if got := u.EWMA(); got != 5*time.Second {
		t.Errorf("EWMA while unhealthy = %v, want 5s", got)
	}
}

// TestRecovery checks that one successful probe marks the upstream
// healthy again and that its EWMA recovers from the penalty value.
func TestRecovery(t *testing.T) {
	u := newTestUpstream(t, nil)

	for i := 0; i < 3; i++ {
		u.ObserveProbe(false, 0)
	}

	u.ObserveProbe(true, 100*time.Millisecond)
	if got := u.Status(); got != Healthy {
		t.Fatalf("Status() after one success = %v, want Healthy", got)
	}
	want := 4020 * time.Millisecond // (0.2*100ms + 0.8*5s)
	if got := u.EWMA(); got != want {
		t.Errorf("EWMA after recovery = %v, want %v", got, want)
	}
}

// TestProbeSendsNSRoot checks that Probe asks each upstream "NS .".
func TestProbeSendsNSRoot(t *testing.T) {
	tr := &scriptedTransport{}
	tr.reply = func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(req)
		return m, nil
	}
	u := newTestUpstream(t, tr)

	m := NewMonitor([]*Upstream{u}, DefaultMonitorOptions(), discardLogger())
	m.Probe(context.Background())

	last := tr.lastCall(t)
	if len(last.Question) != 1 {
		t.Fatalf("probe questions = %d, want 1", len(last.Question))
	}
	if q := last.Question[0]; q.Name != "." || q.Qtype != dns.TypeNS {
		t.Errorf("probe question = %s %s, want . NS", q.Name, dns.TypeToString[q.Qtype])
	}
	if got := u.EWMA(); got <= 0 {
		t.Errorf("EWMA after probe = %v, want > 0", got)
	}
}

// TestProbeSERVFAILIsFailure checks that a SERVFAIL probe counts as a
// failure: three of them make the upstream unhealthy.
func TestProbeSERVFAILIsFailure(t *testing.T) {
	tr := &scriptedTransport{}
	tr.reply = func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m, nil
	}
	u := newTestUpstream(t, tr)
	m := NewMonitor([]*Upstream{u}, DefaultMonitorOptions(), discardLogger())

	for i := 0; i < 3; i++ {
		m.Probe(context.Background())
	}
	if got := u.Status(); got != Unhealthy {
		t.Errorf("Status() after three SERVFAIL probes = %v, want Unhealthy", got)
	}
}

// TestProbeNXDOMAINIsSuccess checks that NXDOMAIN counts as a healthy
// answer: probe failures must reflect reachability, not answer content.
func TestProbeNXDOMAINIsSuccess(t *testing.T) {
	tr := &scriptedTransport{}
	tr.reply = func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		return m, nil
	}
	u := newTestUpstream(t, tr)
	m := NewMonitor([]*Upstream{u}, DefaultMonitorOptions(), discardLogger())

	for i := 0; i < 3; i++ {
		m.Probe(context.Background())
	}
	if got := u.Status(); got != Healthy {
		t.Errorf("Status() after three NXDOMAIN probes = %v, want Healthy", got)
	}
}

// TestProbeTimeoutIsFailure checks that an upstream that outlives the
// monitor's timeout counts as a failure.
func TestProbeTimeoutIsFailure(t *testing.T) {
	tr := &scriptedTransport{}
	tr.reply = func(req *dns.Msg) (*dns.Msg, error) {
		return nil, context.DeadlineExceeded // the monitor's timeout fired
	}
	u := newTestUpstream(t, tr)

	opts := DefaultMonitorOptions()
	opts.Timeout = 20 * time.Millisecond
	m := NewMonitor([]*Upstream{u}, opts, discardLogger())

	for i := 0; i < 3; i++ {
		m.Probe(context.Background())
	}
	if got := u.Status(); got != Unhealthy {
		t.Errorf("Status() after three timed-out probes = %v, want Unhealthy", got)
	}
}
