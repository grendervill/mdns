package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
)

// dohTimeout bounds one whole DoH exchange: connect, request, reply.
const dohTimeout = 5 * time.Second

// maxDoHResponse caps how much of the reply body is read, so a broken
// or hostile upstream cannot make the process allocate without bound.
const maxDoHResponse = 64 << 10

// DoH is an upstream over DNS-over-HTTPS (RFC 8484). Every query is an
// HTTP POST of the wire-format request to the configured URL, with the
// DNS media type; replies must be HTTP 200 with that same media type.
// The HTTP client attempts HTTP/2 and keeps idle connections for
// reuse; Close releases them.
type DoH struct {
	url    string
	client *http.Client
}

// newDoH builds the DoH transport from cfg. The SNI normally comes
// from the URL's host; cfg.ServerName overrides it for upstreams
// addressed by IP. cfg.InsecureSkipVerify passes through for
// self-signed upstreams.
func newDoH(cfg config.UpstreamConfig) *DoH {
	return newDoHWithResolver(cfg, defaultResolver)
}

// newDoHWithResolver is newDoH with the hostname resolver injected, so
// tests can resolve the URL's host without real DNS.
func newDoHWithResolver(cfg config.UpstreamConfig, resolver *bootstrapResolver) *DoH {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}

	client := &http.Client{
		Timeout: dohTimeout,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   tlsCfg,
			DialContext:       resolver.dialContext,
		},
	}
	return &DoH{url: cfg.Address, client: client}
}

// Name implements Transport.
func (d *DoH) Name() string { return "doh" }

// Exchange implements Transport: it POSTs req's wire format to the
// DoH endpoint and returns the decoded reply.
func (d *DoH) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh pack %s: %w", d.url, err)
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("doh request %s: %w", d.url, err)
	}
	hreq.Header.Set("Content-Type", "application/dns-message")
	hreq.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("doh %s: %w", d.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: unexpected status %s", d.url, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		return nil, fmt.Errorf("doh %s: unexpected content type %q", d.url, ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponse))
	if err != nil {
		return nil, fmt.Errorf("doh %s: read body: %w", d.url, err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh %s: unpack reply: %w", d.url, err)
	}
	return out, nil
}

// Close implements Transport: it closes idle HTTP connections.
func (d *DoH) Close() error {
	d.client.CloseIdleConnections()
	return nil
}
