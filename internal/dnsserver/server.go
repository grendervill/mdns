// Package dnsserver exposes the core pipeline on the wire: plain DNS
// (UDP/TCP), DoT, DoH (HTTP/1.1, HTTP/2 and HTTP/3) and DoQ listeners.
// Every listener is optional and configured by port.
package dnsserver

import (
	"context"
	"errors"
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
// Start and Shutdown are not meant to race each other. The TLS
// listeners additionally wait for the certificate source to become
// ready and are then brought up by StartTLS.
type Server struct {
	cfg     *config.Config
	core    *core.Core
	certs   tlscert.Source
	limiter *ratelimit.Limiter
	logger  *slog.Logger

	mu         sync.Mutex
	started    bool
	tlsStarted bool
	plainSrv   []*dns.Server
	tlsSrv     []*dns.Server
	httpSrv    *http.Server
	h3Srv      *http3.Server
	quicLn     *quic.Listener
	challenge  *http.Server
	baseCtx    context.Context
	cancel     context.CancelFunc
}

// New builds the server; a nil logger falls back to slog.Default.
func New(cfg *config.Config, c *core.Core, certs tlscert.Source, lim *ratelimit.Limiter, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, core: c, certs: certs, limiter: lim, logger: logger}
}

// Start binds and serves the enabled listeners: plain DNS always, the
// TLS trio (DoT, DoH, DoQ) only once the certificate source is ready.
// Without a certificate the TLS listeners wait for StartTLS. A bind
// failure stops the listeners already started and returns the error,
// so a partial start never lingers.
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

	if s.certs != nil && s.certs.Ready() {
		if err := s.startTLS(); err != nil {
			_ = s.stopLocked(context.Background())
			return err
		}
		s.tlsStarted = true
	} else {
		s.logger.Info("TLS listeners waiting for the certificate")
	}

	s.started = true
	return nil
}

// StartTLS brings the TLS trio (DoT, DoH, DoQ) up on demand, e.g. once
// the ACME manager obtained the first certificate. It is idempotent
// and safe to call from another goroutine after Start; on a partial
// failure the TLS listeners started so far are rolled back and the
// plain listener is left running.
func (s *Server) StartTLS() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tlsStarted {
		return nil
	}
	if !s.started {
		return fmt.Errorf("dnsserver: Start must run before StartTLS")
	}
	if s.certs == nil || !s.certs.Ready() {
		return fmt.Errorf("dnsserver: TLS listeners need a ready certificate")
	}

	if err := s.startTLS(); err != nil {
		_ = s.stopTLSLocked(context.Background())
		return err
	}
	s.tlsStarted = true
	return nil
}

// TLSStarted reports whether the TLS listeners are up.
func (s *Server) TLSStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsStarted
}

// startTLS binds the enabled TLS listeners in order: DoT, DoH, DoQ.
// The caller must hold s.mu and have set s.baseCtx.
func (s *Server) startTLS() error {
	if s.cfg.Protocols.DoT.Enabled {
		if err := s.startDoT(); err != nil {
			return err
		}
	}
	if s.cfg.Protocols.DoH.Enabled {
		if err := s.startDoH(); err != nil {
			return err
		}
	}
	if s.cfg.Protocols.DoQ.Enabled {
		if err := s.startDoQ(); err != nil {
			return err
		}
	}
	return nil
}

// Listeners reports the listeners actually running as "proto:port",
// ordered plain, doh, dot, doq. A listener is listed only when it is
// enabled and started: the TLS entries appear once StartTLS ran. The
// result is a fresh slice the caller may keep.
func (s *Server) Listeners() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	if s.cfg.Protocols.Plain.Enabled && len(s.plainSrv) > 0 {
		out = append(out, fmt.Sprintf("plain:%d", s.cfg.Protocols.Plain.Port))
	}
	if s.tlsStarted {
		if s.cfg.Protocols.DoH.Enabled {
			out = append(out, fmt.Sprintf("doh:%d", s.cfg.Protocols.DoH.Port))
		}
		if s.cfg.Protocols.DoT.Enabled {
			out = append(out, fmt.Sprintf("dot:%d", s.cfg.Protocols.DoT.Port))
		}
		if s.cfg.Protocols.DoQ.Enabled {
			out = append(out, fmt.Sprintf("doq:%d", s.cfg.Protocols.DoQ.Port))
		}
	}
	return out
}

// StartChallengeHTTP binds a plain HTTP responder on 0.0.0.0:port and
// serves handler on it (the ACME HTTP-01 challenge, port 80). It is
// independent of Start and StartTLS; a second call while one is
// running is an error.
func (s *Server) StartChallengeHTTP(handler http.Handler, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.challenge != nil {
		return fmt.Errorf("dnsserver: challenge listener already running")
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("challenge http :%d: %w", port, err)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: dohReadHeaderTimeout,
		ReadTimeout:       dohReadTimeout,
		WriteTimeout:      dohWriteTimeout,
		IdleTimeout:       dohIdleTimeout,
		MaxHeaderBytes:    dohMaxHeaderBytes,
	}
	s.challenge = srv

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Warn("challenge HTTP listener stopped", "port", port, "error", err)
		}
	}()

	s.logger.Info("ACME HTTP challenge listener listening", "port", port)
	return nil
}

// StopChallengeHTTP shuts the challenge responder down; stopping when
// none runs is a no-op.
func (s *Server) StopChallengeHTTP(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopChallengeLocked(ctx)
}

// Shutdown stops every listener and cancels the base context given to
// Start, releasing handler work. It returns the first error any
// listener reported while stopping.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.stopLocked(ctx)
	if cerr := s.stopChallengeLocked(ctx); cerr != nil && err == nil {
		err = cerr
	}
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
	for _, srv := range s.plainSrv {
		if err := srv.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.plainSrv = nil

	if err := s.stopTLSLocked(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// stopTLSLocked stops the TLS listeners (DoT, DoH, DoQ) and marks the
// group down, without touching the base context or the plain listener.
// The caller must hold s.mu.
func (s *Server) stopTLSLocked(ctx context.Context) error {
	var firstErr error
	for _, srv := range s.tlsSrv {
		if err := srv.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.tlsSrv = nil

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

	s.tlsStarted = false
	return firstErr
}

// stopChallengeLocked stops the ACME HTTP-01 responder if one runs.
// The caller must hold s.mu.
func (s *Server) stopChallengeLocked(ctx context.Context) error {
	if s.challenge == nil {
		return nil
	}
	err := s.challenge.Shutdown(ctx)
	s.challenge = nil
	return err
}

// trackPlain registers a plain listener for shutdown.
func (s *Server) trackPlain(srv *dns.Server) {
	s.plainSrv = append(s.plainSrv, srv)
}

// trackTLS registers a TLS (DoT) listener for shutdown.
func (s *Server) trackTLS(srv *dns.Server) {
	s.tlsSrv = append(s.tlsSrv, srv)
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
