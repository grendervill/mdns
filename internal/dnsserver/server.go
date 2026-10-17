// Package dnsserver exposes the core pipeline on the wire: plain DNS
// (UDP/TCP) today, with DoT, DoH (h1/h2/h3) and DoQ listeners joining
// in later tasks. Every listener is optional and configured by port.
package dnsserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

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
	httpSrv *http.Server
	h3Srv   *http3.Server
	quicLn  *quic.Listener
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
	if s.cfg.Protocols.DoT.Enabled {
		if err := s.startDoT(); err != nil {
			s.stopLocked(context.Background())
			return err
		}
	}
	if s.cfg.Protocols.DoH.Enabled {
		if err := s.startDoH(); err != nil {
			s.stopLocked(context.Background())
			return err
		}
	}
	if s.cfg.Protocols.DoQ.Enabled {
		if err := s.startDoQ(); err != nil {
			s.stopLocked(context.Background())
			return err
		}
	}

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

	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(ctx)
		s.httpSrv = nil
	}
	if s.h3Srv != nil {
		_ = s.h3Srv.Close()
		s.h3Srv = nil
	}
	if s.quicLn != nil {
		_ = s.quicLn.Close()
		s.quicLn = nil
	}
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

// coreHandler answers one decoded query through the core pipeline; the
// plain and DoT listeners share it.
type coreHandler struct {
	core  *core.Core
	proto string
	ctx   context.Context
}

// ServeDNS implements dns.Handler.
func (h *coreHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := h.core.Resolve(h.ctx, req, core.Meta{Proto: h.proto, ClientIP: remoteIP(w.RemoteAddr())})
	_ = w.WriteMsg(resp)
}

// remoteIP extracts the client address of a connection.
func remoteIP(addr net.Addr) netip.Addr {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}
