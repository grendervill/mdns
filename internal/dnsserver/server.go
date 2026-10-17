// Package dnsserver exposes the core pipeline on the wire: plain DNS
// (UDP/TCP) today, with DoT, DoH (h1/h2/h3) and DoQ listeners joining
// in later tasks. Every listener is optional and configured by port.
package dnsserver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/ratelimit"
	"mydns/internal/tlscert"
)

// Server owns every enabled listener. Configure it before Start;
// Start and Shutdown are not meant to race each other.
type Server struct {
	cfg     *config.Config
	core    *core.Core
	certs   *tlscert.Store
	limiter *ratelimit.Limiter
	logger  *slog.Logger

	mu      sync.Mutex
	started bool
	servers []*dns.Server
	baseCtx context.Context
	cancel  context.CancelFunc
}

// New builds the server; a nil logger falls back to slog.Default.
func New(cfg *config.Config, c *core.Core, certs *tlscert.Store, lim *ratelimit.Limiter, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, core: c, certs: certs, limiter: lim, logger: logger}
}

// Start binds and serves every enabled listener. A bind failure stops
// the listeners already started and returns the error, so a partial
// start never lingers.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("dnsserver: already started")
	}
	s.baseCtx, s.cancel = context.WithCancel(ctx)

	if s.cfg.Protocols.Plain.Enabled {
		if err := s.startPlain(); err != nil {
			s.stopLocked(context.Background())
			return err
		}
	}
	// DoT, DoH and DoQ listeners join here in the following tasks.

	s.started = true
	return nil
}

// Shutdown stops every listener and cancels the base context given to
// Start, releasing handler work.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stopLocked(ctx)
	s.started = false
	return nil
}

// stopLocked cancels the base context and stops all listeners. The
// caller must hold s.mu.
func (s *Server) stopLocked(ctx context.Context) {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	for _, srv := range s.servers {
		_ = srv.ShutdownContext(ctx)
	}
	s.servers = nil
}

// track registers a listener for shutdown.
func (s *Server) track(srv *dns.Server) {
	s.servers = append(s.servers, srv)
}

// serve runs one listener loop and logs failures that are not part of
// a requested shutdown.
func (s *Server) serve(srv *dns.Server, proto string, port int) {
	if err := srv.ActivateAndServe(); err != nil {
		s.logger.Warn("listener stopped", "proto", proto, "port", port, "error", err)
	}
}
