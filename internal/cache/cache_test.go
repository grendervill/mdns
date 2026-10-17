package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testClock controls the cache's time in tests.
type testClock struct {
	now time.Time
}

func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// newTestCache builds a cache of the given size with TTL clamp
// [minTTL, maxTTL] and a controllable clock.
func newTestCache(t *testing.T, size int, minTTL, maxTTL uint32) (*Cache, *testClock) {
	t.Helper()

	clk := &testClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	c := New(size, minTTL, maxTTL)
	c.now = func() time.Time { return clk.now }
	return c, clk
}

// query builds a single-question A query for name.
func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// reply builds a NOERROR reply with one A answer carrying ttl.
func reply(req *dns.Msg, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   nil,
	})
	return m
}

// soa builds the SOA record used by negative replies.
func soa(ttl, minttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns1.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  minttl,
	}
}

// TestGetMissEmpty checks that an empty cache misses.
func TestGetMissEmpty(t *testing.T) {
	c, _ := newTestCache(t, 10, 0, 86400)
	if resp, ok := c.Get(query("example.com")); ok || resp != nil {
		t.Fatalf("Get() = (%v, %v), want (nil, false) on an empty cache", resp, ok)
	}
}

// TestPutGet checks the happy path and TTL countdown: the stored answer
// comes back with its TTL reduced by the elapsed seconds, never raised.
func TestPutGet(t *testing.T) {
	c, clk := newTestCache(t, 10, 0, 86400)
	q := query("example.com")
	c.Put(q, reply(q, 300))

	resp, ok := c.Get(query("example.com"))
	if !ok {
		t.Fatalf("Get() = miss, want hit")
	}
	if got := resp.Answer[0].Header().Ttl; got != 300 {
		t.Errorf("TTL = %d, want 300", got)
	}

	clk.advance(1 * time.Second)
	resp, ok = c.Get(query("example.com"))
	if !ok {
		t.Fatalf("Get() after 1s = miss, want hit")
	}
	if got := resp.Answer[0].Header().Ttl; got != 299 {
		t.Errorf("TTL after 1s = %d, want 299", got)
	}

	clk.advance(500 * time.Millisecond) // partial seconds do not count as full ones
	resp, _ = c.Get(query("example.com"))
	if got := resp.Answer[0].Header().Ttl; got != 299 {
		t.Errorf("TTL after 1.5s = %d, want 299", got)
	}
}

// TestExpiry checks that an entry disappears once its TTL elapses.
func TestExpiry(t *testing.T) {
	c, clk := newTestCache(t, 10, 0, 86400)
	q := query("example.com")
	c.Put(q, reply(q, 5))

	clk.advance(6 * time.Second)
	if resp, ok := c.Get(query("example.com")); ok || resp != nil {
		t.Fatalf("Get() after TTL = (%v, %v), want (nil, false)", resp, ok)
	}
}

// TestNegativeCacheNXDOMAIN checks the RFC 2308 negative caching: an
// NXDOMAIN with an SOA lives for min(SOA TTL, SOA MINTTL).
func TestNegativeCacheNXDOMAIN(t *testing.T) {
	c, clk := newTestCache(t, 10, 0, 86400)
	q := query("missing.example.com")

	resp := new(dns.Msg)
	resp.SetRcode(q, dns.RcodeNameError)
	resp.Ns = append(resp.Ns, soa(60, 30)) // MINTTL 30 wins
	c.Put(q, resp)

	clk.advance(29 * time.Second)
	got, ok := c.Get(query("missing.example.com"))
	if !ok {
		t.Fatalf("Get() at 29s = miss, want hit")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN", got.Rcode)
	}

	clk.advance(2 * time.Second)
	if _, ok := c.Get(query("missing.example.com")); ok {
		t.Fatalf("Get() at 31s = hit, want miss (negative TTL 30s)")
	}
}

// TestNoCacheSERVFAILAndTruncated checks that failures and truncated
// replies are never cached.
func TestNoCacheSERVFAILAndTruncated(t *testing.T) {
	c, _ := newTestCache(t, 10, 0, 86400)

	q := query("example.com")
	servfail := new(dns.Msg)
	servfail.SetRcode(q, dns.RcodeServerFailure)
	c.Put(q, servfail)
	if _, ok := c.Get(query("example.com")); ok {
		t.Errorf("SERVFAIL was cached, want not cached")
	}

	trunc := reply(q, 300)
	trunc.Truncated = true
	c.Put(q, trunc)
	if _, ok := c.Get(query("example.com")); ok {
		t.Errorf("truncated reply was cached, want not cached")
	}
}

// TestTTLClamp checks that stored TTLs respect the min and max clamp
// while the returned answer keeps its real TTL.
func TestTTLClamp(t *testing.T) {
	c, clk := newTestCache(t, 10, 5, 86400)

	q := query("short.example.com")
	c.Put(q, reply(q, 1)) // clamped up to 5s
	clk.advance(4 * time.Second)
	if _, ok := c.Get(query("short.example.com")); !ok {
		t.Fatalf("Get() at 4s = miss, want hit (min TTL 5s)")
	}
	clk.advance(2 * time.Second)
	if _, ok := c.Get(query("short.example.com")); ok {
		t.Fatalf("Get() at 6s = hit, want miss (min TTL 5s)")
	}

	c2, clk2 := newTestCache(t, 10, 0, 60)
	q2 := query("long.example.com")
	resp := reply(q2, 999999)
	c2.Put(q2, resp)
	clk2.advance(59 * time.Second)
	got, ok := c2.Get(query("long.example.com"))
	if !ok {
		t.Fatalf("Get() at 59s = miss, want hit (max TTL 60s)")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 999940 {
		// The returned TTL counts down from the upstream's 999999 by
		// the 59 elapsed seconds; the 60s max clamp bounds only how
		// long the entry is stored, not the TTL served to clients.
		t.Errorf("returned TTL = %d, want 999940 (original 999999 minus 59s)", ttl)
	}
	clk2.advance(2 * time.Second)
	if _, ok := c2.Get(query("long.example.com")); ok {
		t.Fatalf("Get() at 61s = hit, want miss (max TTL 60s)")
	}
}

// TestLRUEviction checks that a cache at capacity evicts the least
// recently used entry.
func TestLRUEviction(t *testing.T) {
	c, _ := newTestCache(t, 2, 0, 86400)

	a, b, cc := query("a.example.com"), query("b.example.com"), query("c.example.com")
	c.Put(a, reply(a, 300))
	c.Put(b, reply(b, 300))

	if _, ok := c.Get(a); !ok {
		t.Fatalf("Get(a) = miss, want hit; the test depends on it")
	}
	c.Put(cc, reply(cc, 300)) // b is now the least recently used

	if _, ok := c.Get(b); ok {
		t.Errorf("Get(b) = hit, want miss (evicted)")
	}
	if _, ok := c.Get(a); !ok {
		t.Errorf("Get(a) = miss, want hit (used just before the insert)")
	}
	if _, ok := c.Get(cc); !ok {
		t.Errorf("Get(c) = miss, want hit (just inserted)")
	}
}

// TestKeyIncludesDOBit checks that DNSSEC-Ok requests and plain ones
// do not share entries.
func TestKeyIncludesDOBit(t *testing.T) {
	c, _ := newTestCache(t, 10, 0, 86400)

	q := query("example.com")
	c.Put(q, reply(q, 300))

	doQuery := query("example.com")
	doQuery.SetEdns0(1232, true) // DO bit set
	if _, ok := c.Get(doQuery); ok {
		t.Errorf("Get(DO=1) = hit, want miss (DO=0 entry stored)")
	}
	if _, ok := c.Get(query("example.com")); !ok {
		t.Errorf("Get(DO=0) = miss, want hit")
	}
}

// TestStatsAndFlush checks hit and miss counters and that Flush empties
// the cache.
func TestStatsAndFlush(t *testing.T) {
	c, _ := newTestCache(t, 10, 0, 86400)

	if _, ok := c.Get(query("example.com")); ok {
		t.Fatalf("Get() = hit, want miss on an empty cache")
	}
	q := query("example.com")
	c.Put(q, reply(q, 300))
	if _, ok := c.Get(query("example.com")); !ok {
		t.Fatalf("Get() = miss, want hit")
	}

	st := c.Stats()
	if st.Hits != 1 || st.Misses != 1 || st.Size != 1 {
		t.Fatalf("Stats() = %+v, want Hits 1, Misses 1, Size 1", st)
	}

	c.Flush()
	st = c.Stats()
	if st.Size != 0 {
		t.Errorf("Size after Flush = %d, want 0", st.Size)
	}
	if _, ok := c.Get(query("example.com")); ok {
		t.Errorf("Get() after Flush = hit, want miss")
	}
	if st := c.Stats(); st.Misses != 2 {
		t.Errorf("Misses after Flush = %d, want 2; stats: %s", st.Misses, fmt.Sprint(st))
	}
}
