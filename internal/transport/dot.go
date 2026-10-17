package transport

import (
	"context"
	"crypto/tls"
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
	}
}

// Name implements Transport.
func (d *DoT) Name() string { return "dot" }

// Exchange implements Transport: it dials TLS, sends req as is and
// returns the upstream's reply.
func (d *DoT) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "tcp-tls", Timeout: queryTimeout, TLSConfig: d.tlsConfig}
	resp, _, err := c.ExchangeContext(ctx, req, d.addr)
	if err != nil {
		return nil, fmt.Errorf("dot %s: %w", d.addr, err)
	}
	return resp, nil
}

// Close implements Transport; DoT holds no connections.
func (d *DoT) Close() error { return nil }
