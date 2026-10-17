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
	return newTestCoreFilter(t, res, nil, "zero")
}

// newTestCoreFilter is newTestCore with a filter and a block mode.
func newTestCoreFilter(t *testing.T, res core.Resolver, f core.Filter, mode string) (*core.Core, *cache.Cache, *qlog.Log) {
	t.Helper()

	c := cache.New(100, 0, 86400)
	l, err := qlog.New(100, "", 0)
	if err != nil {
		t.Fatalf("qlog.New() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	return core.New(res, c, l, f, mode, discardLogger()), c, l
}

// fakeFilter scripts the core's filter stage.
type fakeFilter struct {
	fn func(qname string) (bool, string)
}

func (f *fakeFilter) Check(qname string) (bool, string) { return f.fn(qname) }

// TestCacheHitRewritesID checks that an answer served from the cache
// carries the querying client's message ID, not the ID of whoever
// populated the cache first.
func TestCacheHitRewritesID(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return answer(req), testUpstream(t), nil
	}}
	c, cacheStore, _ := newTestCore(t, res)

	seed := query("example.com")
	seed.Id = 1111
	cached := answer(seed) // carries ID 1111
	cacheStore.Put(seed, cached)

	q := query("example.com")
	q.Id = 2222
	resp := c.Resolve(context.Background(), q, core.Meta{Proto: "udp"})
	if resp.Id != 2222 {
		t.Errorf("cached reply ID = %d, want 2222 (the client's ID)", resp.Id)
	}
}

// TestFilterBlocksBeforeCache checks that a blocked domain is answered
// with the block reply even when a previous answer sits in the cache,
// and the resolver is never called.
func TestFilterBlocksBeforeCache(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		t.Errorf("resolver was called for a blocked query")
		return nil, nil, fmt.Errorf("unreachable")
	}}
	blockAll := &fakeFilter{fn: func(string) (bool, string) { return true, "list-1" }}
	c, cacheStore, _ := newTestCoreFilter(t, res, blockAll, "zero")

	q := query("example.com")
	cacheStore.Put(q, answer(q)) // a stale cached answer must not win

	resp := c.Resolve(context.Background(), q, core.Meta{Proto: "udp"})
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want the block answer", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "0.0.0.0" {
		t.Errorf("Answer = %v, want A 0.0.0.0", resp.Answer[0])
	}
	if got := res.callCount(); got != 0 {
		t.Errorf("resolver calls = %d, want 0", got)
	}
}

// TestFilterBlockModes checks every block mode: zero, nxdomain and
// refused.
func TestFilterBlockModes(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return answer(req), testUpstream(t), nil
	}}
	blockAll := &fakeFilter{fn: func(string) (bool, string) { return true, "l" }}

	t.Run("zero A", func(t *testing.T) {
		c, _, _ := newTestCoreFilter(t, res, blockAll, "zero")
		resp := c.Resolve(context.Background(), query("example.com"), core.Meta{Proto: "udp"})
		a, ok := resp.Answer[0].(*dns.A)
		if !ok || a.A.String() != "0.0.0.0" {
			t.Fatalf("Answer = %v, want A 0.0.0.0", resp.Answer[0])
		}
		if a.Hdr.Ttl != 10 {
			t.Errorf("TTL = %d, want 10", a.Hdr.Ttl)
		}
	})
	t.Run("zero AAAA", func(t *testing.T) {
		c, _, _ := newTestCoreFilter(t, res, blockAll, "zero")
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeAAAA)
		resp := c.Resolve(context.Background(), q, core.Meta{Proto: "udp"})
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok || aaaa.AAAA.String() != "::" {
			t.Fatalf("Answer = %v, want AAAA ::", resp.Answer[0])
		}
	})
	t.Run("zero other type is NODATA", func(t *testing.T) {
		c, _, _ := newTestCoreFilter(t, res, blockAll, "zero")
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeTXT)
		resp := c.Resolve(context.Background(), q, core.Meta{Proto: "udp"})
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
			t.Errorf("reply = (%d, %d answers), want NOERROR with none", resp.Rcode, len(resp.Answer))
		}
	})
	t.Run("nxdomain", func(t *testing.T) {
		c, _, _ := newTestCoreFilter(t, res, blockAll, "nxdomain")
		resp := c.Resolve(context.Background(), query("example.com"), core.Meta{Proto: "udp"})
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("Rcode = %d, want NXDOMAIN", resp.Rcode)
		}
	})
	t.Run("refused", func(t *testing.T) {
		c, _, _ := newTestCoreFilter(t, res, blockAll, "refused")
		resp := c.Resolve(context.Background(), query("example.com"), core.Meta{Proto: "udp"})
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("Rcode = %d, want REFUSED", resp.Rcode)
		}
	})
}

// TestFilterAllowPasses checks that a non-blocked name follows the
// normal path.
func TestFilterAllowPasses(t *testing.T) {
	res := &fakeResolver{fn: func(req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return answer(req), testUpstream(t), nil
	}}
	f := &fakeFilter{fn: func(string) (bool, string) { return false, "" }}
	c, _, _ := newTestCoreFilter(t, res, f, "zero")

	resp := c.Resolve(context.Background(), query("example.com"), core.Meta{Proto: "udp"})
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer = %v, want the resolver's answer", resp.Answer)
	}
	if _, ok := resp.Answer[0].(*dns.A); !ok {
		t.Errorf("Answer = %v, want an A record from the resolver", resp.Answer[0])
	}
	if got := res.callCount(); got != 1 {
		t.Errorf("resolver calls = %d, want 1", got)
	}
}

// TestFilterLogsBlocked checks the journal entry of a blocked query.
func TestFilterLogsBlocked(t *testing.T) {
	res := &fakeResolver{fn: func(*dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
		return nil, nil, fmt.Errorf("unreachable")
	}}
	blockAll := &fakeFilter{fn: func(string) (bool, string) { return true, "list-9" }}
	c, _, l := newTestCoreFilter(t, res, blockAll, "zero")

	c.Resolve(context.Background(), query("ads.example.com"), core.Meta{Proto: "udp"})

	recent := l.Recent(1)
	if len(recent) != 1 {
		t.Fatalf("Recent(1) length = %d, want 1", len(recent))
	}
	if !recent[0].Blocked || recent[0].BlockSource != "list-9" {
		t.Errorf("entry = %+v, want Blocked with source list-9", recent[0])
	}
	if recent[0].Upstream != "" {
		t.Errorf("Upstream = %q, want empty for a blocked query", recent[0].Upstream)
	}
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
