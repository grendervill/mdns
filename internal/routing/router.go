package routing

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"

	"mydns/internal/upstream"
)

// ErrNoUpstreams is returned when no upstream is configured or
// enabled.
var ErrNoUpstreams = errors.New("routing: no upstreams available")

// Router resolves queries through the ordered upstreams of its
// strategy, failing over on transport errors and SERVFAIL replies.
type Router struct {
	strategy  Strategy
	upstreams []*upstream.Upstream
}

// New builds a router over ups with the named strategy.
func New(ups []*upstream.Upstream, strategyName string) (*Router, error) {
	st, err := NewStrategy(strategyName)
	if err != nil {
		return nil, err
	}
	return &Router{strategy: st, upstreams: ups}, nil
}

// Exchange walks the strategy's order and returns the first usable
// reply: a transport error or a SERVFAIL moves on to the next
// upstream, while any other reply (NOERROR, NXDOMAIN, REFUSED) is
// final. The upstream that produced the reply is returned alongside
// it. When every candidate fails, the error wraps the last failure.
func (r *Router) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, *upstream.Upstream, error) {
	order := r.strategy.Order(r.upstreams)
	if len(order) == 0 {
		return nil, nil, ErrNoUpstreams
	}

	var lastErr error
	for _, u := range order {
		resp, err := u.Exchange(ctx, req)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", u.ID, err)
			if ctx.Err() != nil {
				break // the caller's context is gone: stop walking
			}
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure {
			lastErr = fmt.Errorf("%s: upstream answered SERVFAIL", u.ID)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		return resp, u, nil
	}

	return nil, nil, fmt.Errorf("routing: all upstreams failed: %w", lastErr)
}
