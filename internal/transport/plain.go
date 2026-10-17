package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// queryTimeout bounds a single UDP or TCP exchange when the caller's
// context carries no earlier deadline; an earlier context deadline
// always wins.
const queryTimeout = 2 * time.Second

// Plain is an upstream over plain DNS: queries go out over UDP, and a
// reply with the TC bit set is resent over TCP, where the size limit
// does not apply. It keeps no state between queries, so Exchange is
// safe for concurrent use and Close is a no-op.
type Plain struct {
	addr string
}

// Name implements Transport.
func (p *Plain) Name() string { return "plain" }

// Exchange implements Transport: it sends req as is over UDP and, when
// the reply has the TC bit set, repeats the same request over TCP and
// returns the full reply.
func (p *Plain) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: queryTimeout}
	resp, _, err := udp.ExchangeContext(ctx, req, p.addr)
	if err != nil {
		return nil, fmt.Errorf("plain udp %s: %w", p.addr, err)
	}
	if !resp.Truncated {
		return resp, nil
	}

	tcp := &dns.Client{Net: "tcp", Timeout: queryTimeout}
	resp, _, err = tcp.ExchangeContext(ctx, req, p.addr)
	if err != nil {
		return nil, fmt.Errorf("plain tcp fallback %s: %w", p.addr, err)
	}
	return resp, nil
}

// Close implements Transport; Plain holds no connections.
func (p *Plain) Close() error { return nil }
