package core_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/qlog"
	"mydns/internal/testutil/scripted"
	"mydns/internal/upstream"
)

// discardLogger returns a logger that drops everything.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeResolver scripts the core's forwarding results.
type fakeResolver struct {
	mu    sync.Mutex
	calls int
	fn    func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error)
}

func (f *fakeResolver) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.fn(req)
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// testUpstream builds a placeholder upstream used as the resolver's
// returned owner.
func testUpstream(t *testing.T) *upstream.Upstream {
	t.Helper()
	return upstream.NewWithTransport(config.UpstreamConfig{
		ID: "u1", Name: "u1", Transport: "plain", Address: "127.0.0.1:53", Enabled: true,
	}, scripted.New())
}

// answer builds a NOERROR reply with one A record.
func answer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   nil,
	})
	return m
}

// query builds a single-question A query.
func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// newTestCore wires a core over the given resolver with a real cache
// and log.
func newTestCore(t *testing.T, res core.Resolver) (*core.Core, *cache.Cache, *qlog.Log) {
	t.Helper()

	c := cache.New(100, 0, 86400)
	l, err := qlog.New(100, "", 0)
	if err != nil {
		t.Fatalf("qlog.New() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	return core.New(res, c, l, discardLogger()), c, l
}

// TestCacheHitSkipsResolver checks that a cached answer is served
// without touching the resolver.
func TestCacheHitSkipsResolver(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		t.Errorf("resolver was called for a cached query")
		return nil, nil, fmt.Errorf("unreachable")
	}}
	c, cacheStore, _ := newTestCore(t, res)

	q := query("example.com")
	cacheStore.Put(q, answer(q)) // seed the cache the core reads from

	resp := c.Resolve(context.Background(), q, core.Meta{Proto: "udp", ClientIP: netip.MustParseAddr("192.0.2.1")})
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Resolve() rcode = %d, want NOERROR", resp.Rcode)
	}
	if got := res.callCount(); got != 0 {
		t.Errorf("resolver calls = %d, want 0", got)
	}
}

// TestMissForwardsAndCaches checks that the first query goes to the
// resolver, the second is answered from the cache, and the log
// reflects both.
func TestMissForwardsAndCaches(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return answer(req), testUpstream(t), nil
	}}
	c, _, l := newTestCore(t, res)

	meta := core.Meta{Proto: "udp", ClientIP: netip.MustParseAddr("192.0.2.1")}

	if resp := c.Resolve(context.Background(), query("example.com"), meta); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Resolve() #1 rcode = %d, want NOERROR", resp.Rcode)
	}
	if got := res.callCount(); got != 1 {
		t.Fatalf("resolver calls after #1 = %d, want 1", got)
	}

	if resp := c.Resolve(context.Background(), query("example.com"), meta); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Resolve() #2 rcode = %d, want NOERROR", resp.Rcode)
	}
	if got := res.callCount(); got != 1 {
		t.Errorf("resolver calls after #2 = %d, want 1 (cache hit)", got)
	}

	recent := l.Recent(2)
	if len(recent) != 2 {
		t.Fatalf("Recent(2) length = %d, want 2", len(recent))
	}
	if recent[0].CacheHit {
		t.Errorf("entry #1 CacheHit = true, want false")
	}
	if !recent[1].CacheHit {
		t.Errorf("entry #2 CacheHit = false, want true")
	}
}

// TestResolverErrorBecomesSERVFAIL checks that forwarding failures turn
// into SERVFAIL replies with no leak of the internal error.
func TestResolverErrorBecomesSERVFAIL(t *testing.T) {
	res := &fakeResolver{fn: func(*dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return nil, nil, fmt.Errorf("all upstreams failed")
	}}
	c, _, _ := newTestCore(t, res)

	resp := c.Resolve(context.Background(), query("example.com"), core.Meta{Proto: "udp"})
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Resolve() rcode = %d, want SERVFAIL", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Resolve() has %d answers, want none", len(resp.Answer))
	}
}

// TestFormErrOnBadQuestions checks that malformed requests never reach
// the resolver.
func TestFormErrOnBadQuestions(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		t.Errorf("resolver was called with a malformed request")
		return nil, nil, fmt.Errorf("unreachable")
	}}
	c, _, _ := newTestCore(t, res)

	empty := new(dns.Msg)
	empty.Id = dns.Id()
	if resp := c.Resolve(context.Background(), empty, core.Meta{Proto: "udp"}); resp.Rcode != dns.RcodeFormatError {
		t.Errorf("Resolve(no questions) rcode = %d, want FORMERR", resp.Rcode)
	}

	two := query("example.com")
	two.Question = append(two.Question, two.Question[0])
	if resp := c.Resolve(context.Background(), two, core.Meta{Proto: "udp"}); resp.Rcode != dns.RcodeFormatError {
		t.Errorf("Resolve(two questions) rcode = %d, want FORMERR", resp.Rcode)
	}

	if got := res.callCount(); got != 0 {
		t.Errorf("resolver calls = %d, want 0", got)
	}
}

// TestLogEntryFields checks the fields the live views rely on.
func TestLogEntryFields(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return answer(req), testUpstream(t), nil
	}}
	c, _, l := newTestCore(t, res)

	c.Resolve(context.Background(), query("example.com"), core.Meta{
		Proto:    "dot",
		ClientIP: netip.MustParseAddr("198.51.100.7"),
	})

	recent := l.Recent(1)
	if len(recent) != 1 {
		t.Fatalf("Recent(1) length = %d, want 1", len(recent))
	}
	e := recent[0]
	if e.QName != "example.com." || e.QType != dns.TypeA {
		t.Errorf("question fields = (%q, %d), want (example.com., A)", e.QName, e.QType)
	}
	if e.Proto != "dot" || e.ClientIP != "198.51.100.7" {
		t.Errorf("client fields = (%q, %q), want (dot, 198.51.100.7)", e.Proto, e.ClientIP)
	}
	if e.Upstream != "u1" {
		t.Errorf("Upstream = %q, want u1", e.Upstream)
	}
	if e.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", e.Rcode)
	}
	if e.CacheHit {
		t.Errorf("CacheHit = true, want false")
	}
	if e.LatencyMS < 0 {
		t.Errorf("LatencyMS = %v, want >= 0", e.LatencyMS)
	}
}
