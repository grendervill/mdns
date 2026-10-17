// Package dnsserver exposes the core pipeline on the wire: plain DNS
// (UDP/TCP), DoT, DoH (HTTP/1.1, HTTP/2 and HTTP/3) and DoQ listeners.
// Every listener is optional and configured by port.
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
			_ = s.stopLocked(context.Background())
			return err
		}
	}
	if s.cfg.Protocols.DoT.Enabled {
		if err := s.startDoT(); err != nil {
			_ = s.stopLocked(context.Background())
			return err
		}
	}
	if s.cfg.Protocols.DoH.Enabled {
		if err := s.startDoH(); err != nil {
			_ = s.stopLocked(context.Background())
			return err
		}
	}
	if s.cfg.Protocols.DoQ.Enabled {
		if err := s.startDoQ(); err != nil {
			_ = s.stopLocked(context.Background())
			return err
		}
	}

	s.started = true
	return nil
}

// Shutdown stops every listener and cancels the base context given to
// Start, releasing handler work. It returns the first error any
// listener reported while stopping.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.stopLocked(ctx)
	s.started = false
	return err
}

// stopLocked cancels the base context and stops all listeners,
// collecting the first error. The caller must hold s.mu.
func (s *Server) stopLocked(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	var firstErr error
	for _, srv := range s.servers {
		if err := srv.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.servers = nil

	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		s.httpSrv = nil
	}
	if s.h3Srv != nil {
		if err := s.h3Srv.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.h3Srv = nil
	}
	if s.quicLn != nil {
		if err := s.quicLn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.quicLn = nil
	}
	return firstErr
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

// udpMaxResponse is the largest UDP response this server sends, which
// keeps datagrams under the fragmentation threshold (the project's
// 1232-byte policy) while leaving classic 512-byte clients working.
const udpMaxResponse = 1232

// coreHandler answers one decoded query through the core pipeline; the
// plain and DoT listeners share it.
type coreHandler struct {
	core   *core.Core
	proto  string
	ctx    context.Context
	logger *slog.Logger
}

// ServeDNS implements dns.Handler.
func (h *coreHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := h.core.Resolve(h.ctx, req, core.Meta{Proto: h.proto, ClientIP: remoteIP(w.RemoteAddr())})
	if h.proto == "udp" {
		resp.Truncate(udpResponseLimit(req))
	}
	if err := w.WriteMsg(resp); err != nil {
		h.logger.Warn("write reply failed", "proto", h.proto, "error", err)
	}
}

// udpResponseLimit returns the largest response sent over UDP to this
// client: udpMaxResponse, lowered to a smaller EDNS0 receive buffer
// the client advertised (never below the classic 512 bytes).
func udpResponseLimit(req *dns.Msg) int {
	limit := udpMaxResponse
	if opt := req.IsEdns0(); opt != nil {
		if size := int(opt.UDPSize()); size >= dns.MinMsgSize && size < limit {
			limit = size
		}
	}
	return limit
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
