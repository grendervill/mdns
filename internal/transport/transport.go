// Package transport sends DNS requests to upstream resolvers. Each
// supported upstream protocol implements Transport; New builds the
// implementation selected by the config.
package transport

import (
	"context"
	"fmt"

	"github.com/miekg/dns"

	"mydns/internal/config"
)

// Transport is one configured upstream resolver. Implementations are
// safe for concurrent use.
type Transport interface {
	// Name returns the protocol name: "plain", "dot", "doh" or "doq".
	Name() string
	// Exchange sends one DNS request as is, with the request's ID, and
	// returns the upstream's reply. It returns no later than the
	// context's deadline.
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	// Close releases the transport's resources.
	Close() error
}

// New returns the Transport named by cfg.Transport: "plain", "dot",
// "doh" or "doq".
func New(cfg config.UpstreamConfig) (Transport, error) {
	switch cfg.Transport {
	case "plain":
		return &Plain{addr: cfg.Address}, nil
	case "dot":
		return newDoT(cfg), nil
	case "doh":
		return newDoH(cfg), nil
	case "doq":
		return newDoQ(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
}
