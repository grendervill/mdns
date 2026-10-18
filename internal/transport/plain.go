package transport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
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
	addr     string
	resolver *bootstrapResolver
}

// newPlainWithResolver is New's plain variant with the hostname resolver
// injected, mirroring newDoHWithResolver so a test can point the
// bootstrap lookup at a local fake DNS server.
func newPlainWithResolver(cfg config.UpstreamConfig, resolver *bootstrapResolver) *Plain {
	return &Plain{addr: cfg.Address, resolver: resolver}
}

// Name implements Transport.
func (p *Plain) Name() string { return "plain" }

// Exchange implements Transport: it sends req as is over UDP and, when
// the reply has the TC bit set, repeats the same request over TCP and
// returns the full reply. A hostname address is resolved through the
// bootstrap resolver once per exchange, before the UDP query, and the
// same IP is reused for the TCP fallback.
func (p *Plain) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	addrs, err := p.resolver.resolveAddr(ctx, p.addr)
	if err != nil {
		return nil, fmt.Errorf("plain resolve %s: %w", p.addr, err)
	}

	var errs []error
	for _, addr := range addrs {
		resp, err := p.exchangeAddr(ctx, req, addr)
		if err == nil {
			return resp, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no addresses resolved"))
	}
	return nil, fmt.Errorf("plain %s: %w", p.addr, errors.Join(errs...))
}

// exchangeAddr sends one query to an already resolved address and
// performs the TCP fallback on the same address when the UDP reply is
// truncated.
func (p *Plain) exchangeAddr(ctx context.Context, req *dns.Msg, addr string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: queryTimeout}
	resp, _, err := udp.ExchangeContext(ctx, req, addr)
	if err != nil {
		return nil, err
	}
	if !resp.Truncated {
		return resp, nil
	}

	tcp := &dns.Client{Net: "tcp", Timeout: queryTimeout}
	resp, _, err = tcp.ExchangeContext(ctx, req, addr)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close implements Transport; Plain holds no connections.
func (p *Plain) Close() error { return nil }
