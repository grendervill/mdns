// Package ratelimit throttles plain-DNS clients per source address: a
// token bucket of rpsPerIP tokens refilling at rpsPerIP tokens per
// second, with trusted CIDRs exempted entirely.
package ratelimit

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// gcInterval is how often expired buckets are collected, and
// bucketTTL how long an untouched bucket is kept.
const (
	gcInterval = time.Minute
	bucketTTL  = 10 * time.Minute
)

// Limiter is safe for concurrent use.
type Limiter struct {
	rps     float64
	trusted []netip.Prefix
	now     func() time.Time

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	lastGC  time.Time
}

// bucket is one address's token bucket.
type bucket struct {
	tokens float64
	last   time.Time
}

// New builds a limiter allowing rpsPerIP requests per second per
// address (capacity and refill rate are both rpsPerIP; a value of 0
// disables the limit). Addresses inside trustedCIDRs are never
// limited. The now function may be nil for the real clock.
func New(rpsPerIP int, trustedCIDRs []string, now func() time.Time) (*Limiter, error) {
	if now == nil {
		now = time.Now
	}

	l := &Limiter{
		rps:     float64(rpsPerIP),
		now:     now,
		buckets: make(map[netip.Addr]*bucket),
	}
	for _, s := range trustedCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("ratelimit: invalid trusted CIDR %q: %w", s, err)
		}
		l.trusted = append(l.trusted, p)
	}
	return l, nil
}

// Exempt reports whether addr falls inside a trusted CIDR. IPv4
// addresses in IPv6 form are matched against IPv4 prefixes too.
func (l *Limiter) Exempt(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range l.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Allow consumes one token for addr and reports whether the request
// may proceed. A disabled limiter and exempt addresses always pass.
func (l *Limiter) Allow(addr netip.Addr) bool {
	if l.rps <= 0 || l.Exempt(addr) {
		return true
	}
	addr = addr.Unmap()

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.collect(now)

	b := l.buckets[addr]
	if b == nil {
		b = &bucket{tokens: l.rps, last: now}
		l.buckets[addr] = b
	}

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.rps {
			b.tokens = l.rps
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// collect drops buckets untouched for bucketTTL, at most once a
// minute, so the map cannot grow without bound. The caller must hold
// l.mu.
func (l *Limiter) collect(now time.Time) {
	if now.Sub(l.lastGC) < gcInterval {
		return
	}
	l.lastGC = now
	for addr, b := range l.buckets {
		if now.Sub(b.last) > bucketTTL {
			delete(l.buckets, addr)
		}
	}
}
