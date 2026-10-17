// Package core is the per-request pipeline: validate, serve from the
// cache or forward through the router, and record what happened in the
// query log. The filtering stage joins this pipeline in a later plan.
package core

import (
	"context"
	"log/slog"
	"net/netip"
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

// Core is safe for concurrent use.
type Core struct {
	resolver Resolver
	cache    *cache.Cache
	log      *qlog.Log
	logger   *slog.Logger
}

// New wires the pipeline. A nil logger falls back to slog.Default.
func New(r Resolver, c *cache.Cache, l *qlog.Log, logger *slog.Logger) *Core {
	if logger == nil {
		logger = slog.Default()
	}
	return &Core{resolver: r, cache: c, log: l, logger: logger}
}

// Resolve answers one request and always returns a message: internal
// failures become SERVFAIL, malformed requests FORMERR. A cached
// answer short-circuits the resolver.
func (c *Core) Resolve(ctx context.Context, req *dns.Msg, meta Meta) *dns.Msg {
	start := time.Now()

	if len(req.Question) != 1 {
		resp := replyWithRcode(req, dns.RcodeFormatError)
		c.record(req, meta, resp, nil, start, false)
		return resp
	}

	if resp, ok := c.cache.Get(req); ok {
		c.record(req, meta, resp, nil, start, true)
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
		c.record(req, meta, resp, nil, start, false)
		return resp
	}

	c.cache.Put(req, resp)
	c.record(req, meta, resp, u, start, false)
	return resp
}

// replyWithRcode builds a reply carrying the given rcode.
func replyWithRcode(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}

// record appends one query-log entry. The caller measured the start of
// the whole pipeline; u is nil for cache hits and errors. Malformed
// requests may carry no question at all, so the question fields are
// filled defensively.
func (c *Core) record(req *dns.Msg, meta Meta, resp *dns.Msg, u *upstream.Upstream, start time.Time, cacheHit bool) {
	var qname string
	var qtype uint16
	if len(req.Question) > 0 {
		qname = req.Question[0].Name
		qtype = req.Question[0].Qtype
	}

	e := qlog.Entry{
		ClientIP:  meta.ClientIP.String(),
		Proto:     meta.Proto,
		QName:     qname,
		QType:     qtype,
		Rcode:     resp.Rcode,
		LatencyMS: float64(time.Since(start).Microseconds()) / 1000,
		CacheHit:  cacheHit,
	}
	if u != nil {
		e.Upstream = u.ID
	}
	c.log.Add(e)
}
