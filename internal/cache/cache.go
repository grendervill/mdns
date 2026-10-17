// Package cache is an in-memory DNS answer cache: a TTL-aware,
// size-bounded LRU store shared by all of the server's listeners.
package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// key identifies one cached answer: the question plus the DNSSEC-Ok
// bit, which changes the upstream's reply and therefore must not share
// an entry.
type key struct {
	name   string
	qtype  uint16
	qclass uint16
	do     bool
}

// entry is one cached answer. resp is a private copy; storedAt anchors
// the TTL countdown served to clients.
type entry struct {
	key      key
	resp     *dns.Msg
	storedAt time.Time
	expires  time.Time
}

// Stats reports cumulative counters and the current number of entries.
type Stats struct {
	Hits   uint64
	Misses uint64
	Size   int
}

// Cache is safe for concurrent use.
type Cache struct {
	mu     sync.Mutex
	size   int
	minTTL uint32
	maxTTL uint32
	now    func() time.Time

	entries map[key]*list.Element
	lru     *list.List // front: most recently used; Value: *entry

	hits   uint64
	misses uint64
}

// New returns a cache holding at most size entries. minTTL and maxTTL
// clamp how long an answer stays cached; the answer handed to clients
// keeps the upstream's real TTL. The zero MinTTL keeps zero-TTL replies
// uncacheable; a non-zero MinTTL raises them.
func New(size int, minTTL, maxTTL uint32) *Cache {
	return &Cache{
		size:    size,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
		now:     time.Now,
		entries: make(map[key]*list.Element),
		lru:     list.New(),
	}
}

// Get looks req up and, on a hit, returns a copy of the stored answer
// with every TTL reduced by the elapsed whole seconds. The question
// must carry exactly one question.
func (c *Cache) Get(req *dns.Msg) (*dns.Msg, bool) {
	if len(req.Question) != 1 {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	el, ok := c.entries[keyFor(req)]
	if !ok {
		c.misses++
		return nil, false
	}

	e := el.Value.(*entry)
	if !now.Before(e.expires) {
		c.removeElement(el)
		c.misses++
		return nil, false
	}

	c.lru.MoveToFront(el)
	c.hits++
	return copyWithElapsed(e.resp, now.Sub(e.storedAt)), true
}

// Put stores resp for req's question. Replies that must not be cached
// (truncated, SERVFAIL, refused, or without any TTL source) and replies
// whose clamped TTL is zero are silently dropped.
func (c *Cache) Put(req, resp *dns.Msg) {
	if len(req.Question) != 1 || resp == nil || resp.Truncated {
		return
	}

	ttl, ok := ttlFor(resp)
	if !ok {
		return
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	k := keyFor(req)
	if el, ok := c.entries[k]; ok {
		e := el.Value.(*entry)
		e.resp = resp.Copy()
		e.storedAt = now
		e.expires = now.Add(time.Duration(ttl) * time.Second)
		c.lru.MoveToFront(el)
		return
	}

	if len(c.entries) >= c.size {
		if back := c.lru.Back(); back != nil {
			c.removeElement(back)
		}
	}

	e := &entry{
		key:      k,
		resp:     resp.Copy(),
		storedAt: now,
		expires:  now.Add(time.Duration(ttl) * time.Second),
	}
	c.entries[k] = c.lru.PushFront(e)
}

// Flush drops every entry. Cumulative hit and miss counters survive.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[key]*list.Element)
	c.lru.Init()
}

// Stats returns cumulative counters and the current entry count.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Hits: c.hits, Misses: c.misses, Size: len(c.entries)}
}

// removeElement removes el from both the map and the LRU list. The
// caller must hold c.mu.
func (c *Cache) removeElement(el *list.Element) {
	e := el.Value.(*entry)
	delete(c.entries, e.key)
	c.lru.Remove(el)
}

// keyFor derives the cache key of req.
func keyFor(req *dns.Msg) key {
	q := req.Question[0]
	k := key{
		name:   strings.ToLower(q.Name),
		qtype:  q.Qtype,
		qclass: q.Qclass,
	}
	if e := req.IsEdns0(); e != nil {
		k.do = e.Do()
	}
	return k
}

// ttlFor derives the cache lifetime of resp: the smallest answer TTL
// for positive replies; for NXDOMAIN and NODATA the SOA's
// min(TTL, MINTTL), per RFC 2308. It reports false when the reply
// carries no usable TTL source or must not be cached at all.
func ttlFor(resp *dns.Msg) (uint32, bool) {
	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(resp.Answer) > 0 {
			min := resp.Answer[0].Header().Ttl
			for _, rr := range resp.Answer[1:] {
				if ttl := rr.Header().Ttl; ttl < min {
					min = ttl
				}
			}
			return min, true
		}
		return soaTTL(resp)
	case dns.RcodeNameError:
		return soaTTL(resp)
	default:
		return 0, false
	}
}

// soaTTL returns min(SOA TTL, SOA MINTTL) of the first SOA in the
// authority section.
func soaTTL(resp *dns.Msg) (uint32, bool) {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			ttl := soa.Hdr.Ttl
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			return ttl, true
		}
	}
	return 0, false
}

// copyWithElapsed returns a private copy of resp with every record's
// TTL reduced by the elapsed whole seconds, floored at zero.
func copyWithElapsed(resp *dns.Msg, elapsed time.Duration) *dns.Msg {
	secs := uint32(elapsed / time.Second)

	out := resp.Copy()
	for _, sec := range [][]dns.RR{out.Answer, out.Ns, out.Extra} {
		for _, rr := range sec {
			ttl := rr.Header().Ttl
			if ttl > secs {
				rr.Header().Ttl = ttl - secs
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
	return out
}
