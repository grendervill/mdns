// Package core is the per-request pipeline: validate, filter, serve
// from the cache or forward through the router, and record what
// happened in the query log. Blocked names are answered before the
// cache and the upstream are touched.
package core

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/cache"
	"mydns/internal/qlog"
	"mydns/internal/upstream"
)

// Meta describes where a request came in.
type Meta struct {
	Proto    string // udp, tcp, doh, dot, doq
	ClientIP netip.Addr
}

// Resolver forwards one query and reports which upstream answered;
// routing.Router satisfies it.
type Resolver interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, *upstream.Upstream, error)
}

// Filter decides whether a query name must be blocked; filter.Engine
// satisfies it. A nil Filter disables the stage.
type Filter interface {
	Check(qname string) (blocked bool, source string)
}

// Observer receives every recorded query, after the entry has reached
// the query log. It is the pipeline's counterpart of qlog's observer
// hook: a component that outlives a runtime generation (the stats
// collector) is fed here even when its generation is rebuilt. SetObserver
// installs one; a nil observer disables the hook.
type Observer interface {
	Observe(qlog.Entry)
}

// observerSlot boxes the observer so it can live behind an atomic
// pointer: SetObserver runs on a configuration change while Resolve
// reads the hook on every request.
type observerSlot struct {
	observer Observer
}

// Core is safe for concurrent use.
type Core struct {
	resolver Resolver
	cache    *cache.Cache
	log      *qlog.Log
	filter   Filter
	logger   *slog.Logger

	observer atomic.Pointer[observerSlot]

	blockMode atomic.Value // string: zero | nxdomain | refused
}

// New wires the pipeline. mode selects how blocked names are answered:
// "zero", "nxdomain" or "refused". A nil logger falls back to
// slog.Default.
func New(r Resolver, c *cache.Cache, l *qlog.Log, f Filter, mode string, logger *slog.Logger) *Core {
	if logger == nil {
		logger = slog.Default()
	}
	core := &Core{resolver: r, cache: c, log: l, filter: f, logger: logger}
	core.blockMode.Store(mode)
	return core
}

// SetBlockMode replaces the answer mode for blocked names live.
func (c *Core) SetBlockMode(mode string) {
	c.blockMode.Store(mode)
}

// SetObserver installs the callback invoked after every recorded query;
// nil removes it. It is safe to call while requests are in flight.
func (c *Core) SetObserver(o Observer) {
	if o == nil {
		c.observer.Store(nil)
		return
	}
	c.observer.Store(&observerSlot{observer: o})
}

// Resolve answers one request and always returns a message: internal
// failures become SERVFAIL, malformed requests FORMERR. The filter
// stage runs before the cache, so a blocked name is blocked even when
// a stale answer sits in the cache. A cached answer short-circuits the
// resolver.
func (c *Core) Resolve(ctx context.Context, req *dns.Msg, meta Meta) *dns.Msg {
	start := time.Now()

	if len(req.Question) != 1 {
		resp := replyWithRcode(req, dns.RcodeFormatError)
		c.record(req, meta, resp, nil, start, false, false, "")
		return resp
	}

	if c.filter != nil {
		if blocked, source := c.filter.Check(req.Question[0].Name); blocked {
			mode, _ := c.blockMode.Load().(string)
			resp := blockedReply(req, mode)
			c.record(req, meta, resp, nil, start, false, true, source)
			return resp
		}
	}

	if resp, ok := c.cache.Get(req); ok {
		c.record(req, meta, resp, nil, start, true, false, "")
		return resp
	}

	resp, u, err := c.resolver.Exchange(ctx, req)
	if err != nil {
		c.logger.Warn("resolve failed",
			"qname", req.Question[0].Name,
			"qtype", dns.TypeToString[req.Question[0].Qtype],
			"error", err,
		)
		resp := replyWithRcode(req, dns.RcodeServerFailure)
		c.record(req, meta, resp, nil, start, false, false, "")
		return resp
	}

	c.cache.Put(req, resp)
	c.record(req, meta, resp, u, start, false, false, "")
	return resp
}

// replyWithRcode builds a reply carrying the given rcode.
func replyWithRcode(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}

// blockedTTL is the TTL of synthesized block answers: deliberately
// short, so unblocking a domain takes effect quickly on downstream
// caches as well.
const blockedTTL = 10

// blockedReply builds the configured answer for a blocked name:
// "zero" points A at 0.0.0.0 and AAAA at :: (other types get NODATA);
// "nxdomain" and "refused" set the rcode.
func blockedReply(req *dns.Msg, mode string) *dns.Msg {
	m := new(dns.Msg)

	switch mode {
	case "nxdomain":
		m.SetRcode(req, dns.RcodeNameError)
		return m
	case "refused":
		m.SetRcode(req, dns.RcodeRefused)
		return m
	default: // "zero"
		m.SetReply(req)
		q := req.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: blockedTTL},
				A:   net.IPv4zero,
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: blockedTTL},
				AAAA: net.IPv6zero,
			})
		}
		return m
	}
}

// record appends one query-log entry. The caller measured the start of
// the whole pipeline; u is nil for cache hits, errors and blocked
// queries. Malformed requests may carry no question at all, so the
// question fields are filled defensively.
func (c *Core) record(req *dns.Msg, meta Meta, resp *dns.Msg, u *upstream.Upstream, start time.Time, cacheHit, blocked bool, blockSource string) {
	var qname string
	var qtype uint16
	if len(req.Question) > 0 {
		qname = req.Question[0].Name
		qtype = req.Question[0].Qtype
	}

	e := qlog.Entry{
		ClientIP:    meta.ClientIP.String(),
		Proto:       meta.Proto,
		QName:       qname,
		QType:       qtype,
		Rcode:       resp.Rcode,
		LatencyMS:   float64(time.Since(start).Microseconds()) / 1000,
		CacheHit:    cacheHit,
		Blocked:     blocked,
		BlockSource: blockSource,
	}
	if u != nil {
		e.Upstream = u.ID
	}
	c.log.Add(e)

	// The observer runs after the entry reached the log, so a slow
	// collector cannot hold a query out of the ring.
	if s := c.observer.Load(); s != nil {
		s.observer.Observe(e)
	}
}
