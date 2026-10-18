package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"

	"mydns/internal/config"
)

// DoT is an upstream over DNS-over-TLS (RFC 7858). Every query opens
// its own TLS connection: there is no connection pool, so a stale
// connection can never keep answering after the server rotates its
// certificate. It keeps no mutable state, so Exchange is safe for
// concurrent use and Close is a no-op.
type DoT struct {
	addr      string
	tlsConfig *tls.Config
	resolver  *bootstrapResolver
}

// newDoT builds the DoT transport from cfg. The SNI comes from
// cfg.ServerName; when that is empty, the address's host is used, and
// an address it cannot split simply leaves the SNI empty. The
// cfg.InsecureSkipVerify flag passes through for self-signed
// upstreams.
func newDoT(cfg config.UpstreamConfig) *DoT {
	serverName := cfg.ServerName
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(cfg.Address)
	}

	return &DoT{
		addr: cfg.Address,
		tlsConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			NextProtos:         []string{"dot"},
		},
		resolver: defaultResolver,
	}
}

// Name implements Transport.
func (d *DoT) Name() string { return "dot" }

// Exchange implements Transport: it resolves the upstream's hostname,
// dials TLS to the resolved address, sends req as is and returns the
// upstream's reply.
func (d *DoT) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	addrs, err := d.resolver.resolveAddr(ctx, d.addr)
	if err != nil {
		return nil, fmt.Errorf("dot resolve %s: %w", d.addr, err)
	}

	var errs []error
	for _, addr := range addrs {
		resp, err := d.exchangeAddr(ctx, req, addr)
		if err == nil {
			return resp, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no addresses resolved"))
	}
	return nil, fmt.Errorf("dot %s: %w", d.addr, errors.Join(errs...))
}

// exchangeAddr performs one TLS handshake and one DNS exchange against
// an already resolved address.
func (d *DoT) exchangeAddr(ctx context.Context, req *dns.Msg, addr string) (*dns.Msg, error) {
	raw, err := (&net.Dialer{Timeout: queryTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(raw, d.tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	defer conn.Close()

	client := &dns.Client{Net: "tcp", Timeout: queryTimeout}
	resp, _, err := client.ExchangeWithConnContext(ctx, req, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close implements Transport; DoT holds no connections.
func (d *DoT) Close() error { return nil }
