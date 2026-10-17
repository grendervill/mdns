package ratelimit_test

import (
	"net/netip"
	"testing"
	"time"

	"mydns/internal/ratelimit"
)

// testClock drives the limiter's time in tests.
type testClock struct{ now time.Time }

func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// newTestLimiter builds a limiter with the given rps and no trusted
// CIDRs, on a controllable clock.
func newTestLimiter(t *testing.T, rps int) (*ratelimit.Limiter, *testClock) {
	t.Helper()

	clk := &testClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	l, err := ratelimit.New(rps, nil, func() time.Time { return clk.now })
	if err != nil {
		t.Fatalf("New(%d) = %v, want nil", rps, err)
	}
	return l, clk
}

// TestBurstThenRefill checks the token bucket: rps immediate requests
// pass, the next one is refused until tokens refill at the rps rate.
func TestBurstThenRefill(t *testing.T) {
	l, clk := newTestLimiter(t, 3)
	ip := netip.MustParseAddr("192.0.2.10")

	for i := 1; i <= 3; i++ {
		if !l.Allow(ip) {
			t.Fatalf("Allow() #%d = false, want true (within burst)", i)
		}
	}
	if l.Allow(ip) {
		t.Fatalf("Allow() #4 = true, want false (burst exhausted)")
	}

	// A partial refill (100ms * 3rps = 0.3 tokens) is not a token yet.
	clk.advance(100 * time.Millisecond)
	if l.Allow(ip) {
		t.Fatalf("Allow() after 100ms = true, want false (0.3 tokens)")
	}

	// After 500ms in total the bucket holds 1.5 tokens: exactly one
	// request passes.
	clk.advance(400 * time.Millisecond)
	if !l.Allow(ip) {
		t.Fatalf("Allow() after 500ms = false, want true (1.5 tokens)")
	}
	if l.Allow(ip) {
		t.Fatalf("Allow() second after 500ms = true, want false (0.5 tokens left)")
	}

	// A full second refills the whole burst.
	clk.advance(time.Second)
	for i := 1; i <= 3; i++ {
		if !l.Allow(ip) {
			t.Fatalf("Allow() after full refill #%d = false, want true", i)
		}
	}
}

// TestIndependentIPs checks that exhausting one address does not
// affect another.
func TestIndependentIPs(t *testing.T) {
	l, _ := newTestLimiter(t, 1)
	a := netip.MustParseAddr("192.0.2.10")
	b := netip.MustParseAddr("198.51.100.20")

	if !l.Allow(a) {
		t.Fatalf("Allow(a) #1 = false, want true")
	}
	if l.Allow(a) {
		t.Fatalf("Allow(a) #2 = true, want false")
	}
	if !l.Allow(b) {
		t.Fatalf("Allow(b) = false, want true (independent bucket)")
	}
}

// TestTrustedExempt checks that trusted CIDRs bypass the limit.
func TestTrustedExempt(t *testing.T) {
	clk := &testClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	l, err := ratelimit.New(1, []string{"10.0.0.0/8", "2001:db8::/32"}, func() time.Time { return clk.now })
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}

	for _, s := range []string{"10.1.2.3", "2001:db8::1"} {
		ip := netip.MustParseAddr(s)
		if !l.Exempt(ip) {
			t.Errorf("Exempt(%s) = false, want true", ip)
		}
		for i := 0; i < 10; i++ {
			if !l.Allow(ip) {
				t.Fatalf("Allow(%s) #%d = false, want true (exempt)", ip, i+1)
			}
		}
	}

	if l.Exempt(netip.MustParseAddr("192.0.2.10")) {
		t.Errorf("Exempt(192.0.2.10) = true, want false")
	}
}

// TestDisabled checks that rps 0 turns the limiter off.
func TestDisabled(t *testing.T) {
	l, _ := newTestLimiter(t, 0)
	ip := netip.MustParseAddr("192.0.2.10")

	for i := 0; i < 100; i++ {
		if !l.Allow(ip) {
			t.Fatalf("Allow() #%d = false, want true (limiter disabled)", i+1)
		}
	}
}

// TestReload checks that new parameters apply immediately and a bad
// CIDR leaves the previous ones in place.
func TestReload(t *testing.T) {
	l, _ := newTestLimiter(t, 10)
	ip := netip.MustParseAddr("192.0.2.10")

	for i := 0; i < 10; i++ {
		if !l.Allow(ip) {
			t.Fatalf("Allow() #%d = false under 10 rps", i+1)
		}
	}

	if err := l.Reload(1, nil); err != nil {
		t.Fatalf("Reload(1) = %v, want nil", err)
	}
	if !l.Allow(ip) {
		t.Fatalf("first Allow after Reload = false, want true (fresh bucket)")
	}
	if l.Allow(ip) {
		t.Fatalf("second Allow after Reload = true, want false (1 rps)")
	}

	if err := l.Reload(1, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("Reload(trusted) = %v, want nil", err)
	}
	if !l.Exempt(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("Exempt(10.1.2.3) = false after Reload")
	}

	if err := l.Reload(1, []string{"bad/33"}); err == nil {
		t.Errorf("Reload(bad CIDR) = nil, want an error")
	}
	if !l.Exempt(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("trusted list lost after a failed Reload")
	}
}

// TestRejectsInvalidCIDR checks that a broken CIDR is reported at
// construction time.
func TestRejectsInvalidCIDR(t *testing.T) {
	if _, err := ratelimit.New(10, []string{"10.0.0.0/33"}, time.Now); err == nil {
		t.Fatalf("New(bad CIDR) = nil error, want an error")
	}
}
