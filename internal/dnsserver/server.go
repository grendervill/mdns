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

// acmeALPNPort is the port ACME TLS-ALPN-01 validation lands on
// (RFC 8737): an HTTPS listener there has to be running before the
// first certificate exists, or the order could never be validated.
const acmeALPNPort = 443

// Server owns every enabled listener. Configure it before Start;
// Start and Shutdown are not meant to race each other. The TLS
// listeners additionally wait for the certificate source to become
// ready and are then brought up by StartTLS — except the DoH listener
// on the ACME TLS-ALPN port, which starts eagerly when the source
// serves TLS-ALPN challenges.
type Server struct {
	cfg     *config.Config
	core    *core.Core
	certs   tlscert.Source
	limiter *ratelimit.Limiter
	logger  *slog.Logger

	// panel is the optional admin web UI served by the DoH listener. It
	// is configured before Start with SetPanel and never changes while
	// the server runs, so startDoH can read it under the lock.
	panel Panel

	// alpnPort is the TCP port ACME TLS-ALPN-01 validation uses; it is
	// acmeALPNPort and only a test overrides it, so the eager-DoH path
	// can be exercised on an unprivileged port.
	alpnPort int

	mu       sync.Mutex
	started  bool
	dotUp    bool
	dohUp    bool
	doqUp    bool
	plainSrv []*dns.Server
	tlsSrv   []*dns.Server
	dohLn    net.Listener
	httpSrv  *http.Server
	h3Srv    *http3.Server
	// quicLn, quicTr and quicUDP are the DoQ endpoint: the listener, its
	// transport, and the UDP socket the server bound for it. The
	// transport only closes a socket it created itself, so the server
	// closes quicUDP explicitly to free the DoQ port for the next
	// generation.
	quicLn    *quic.Listener
	quicTr    *quic.Transport
	quicUDP   net.PacketConn
	challenge *http.Server
	// challengeLn is the socket behind the ACME HTTP-01 responder. It
	// is kept so ReleaseListeners can free the port on a runtime swap
	// while the HTTP server stays up to finish in-flight responses.
	challengeLn net.Listener
	baseCtx     context.Context
	cancel      context.CancelFunc
}

// New builds the server; a nil logger falls back to slog.Default.
func New(cfg *config.Config, c *core.Core, certs tlscert.Source, lim *ratelimit.Limiter, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, core: c, certs: certs, limiter: lim, logger: logger, alpnPort: acmeALPNPort}
}

// SetPanel installs the optional admin web UI on the DoH listener. It
// must be called before Start; a nil panel (the default) leaves the
// listener with the DoH endpoint only.
func (s *Server) SetPanel(p Panel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.panel = p
}

// needsEagerDoH reports whether the DoH listener must start before the
// certificate exists: an ACME source that serves TLS-ALPN-01
// challenges on the DoH port would otherwise never get its first
// certificate. The caller passes the validation port so it can be
// driven from tests.
func needsEagerDoH(certs tlscert.Source, cfg *config.Config, alpnPort int) bool {
	return certs != nil && certs.ACMEALPN() && cfg.Protocols.DoH.Enabled && cfg.Protocols.DoH.Port == alpnPort
}

// Start binds and serves the enabled listeners: plain DNS always and
// the TLS trio (DoT, DoH, DoQ) once the certificate source is ready.
// Without a certificate the TLS listeners wait for StartTLS, except
// the DoH listener on the ACME TLS-ALPN port, which starts eagerly so
// the first TLS-ALPN-01 challenge can be answered. A bind failure
// stops the listeners already started and returns the error, so a
// partial start never lingers.
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

	switch {
	case s.certs != nil && s.certs.Ready():
		if err := s.startTLS(); err != nil {
			_ = s.stopLocked(context.Background())
			return err
		}
	case needsEagerDoH(s.certs, s.cfg, s.alpnPort):
		// The challenge handshake arrives at the DoH listener itself,
		// so it must be up; until a certificate is issued normal HTTPS
		// handshakes fail through GetCertificate.
		if err := s.startDoH(); err != nil {
			_ = s.stopLocked(context.Background())
			return err
		}
		s.dohUp = true
		s.logger.Info("DoH listening for ACME TLS-ALPN-01 ahead of the certificate", "port", s.cfg.Protocols.DoH.Port)
	default:
		s.logger.Info("TLS listeners waiting for the certificate")
	}

	s.started = true
	return nil
}

// StartTLS starts the enabled TLS listeners that are not up yet, e.g.
// once the ACME manager obtained its first certificate; a DoH listener
// already running eagerly is left alone. It is idempotent, safe to
// call from another goroutine after Start, and on a bind failure it
// rolls back only the listeners this call started, leaving the plain
// listener and any earlier TLS listener running.
func (s *Server) StartTLS() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return fmt.Errorf("dnsserver: Start must run before StartTLS")
	}
	if s.tlsUpLocked() {
		return nil
	}
	if s.certs == nil || !s.certs.Ready() {
		return fmt.Errorf("dnsserver: TLS listeners need a ready certificate")
	}

	before := s.tlsUpState()
	if err := s.startTLS(); err != nil {
		_ = s.rollbackTLS(before, context.Background())
		return err
	}
	return nil
}

// TLSStarted reports whether the whole TLS group is up, i.e. every
// enabled TLS listener (DoT, DoH, DoQ) is running. It is true when no
// TLS protocol is enabled, so it answers "is there any TLS listener
// still waiting to start?" rather than "was StartTLS called?".
func (s *Server) TLSStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsUpLocked()
}

// tlsUpLocked reports whether every enabled TLS listener is up. The
// caller must hold s.mu.
func (s *Server) tlsUpLocked() bool {
	return (!s.cfg.Protocols.DoT.Enabled || s.dotUp) &&
		(!s.cfg.Protocols.DoH.Enabled || s.dohUp) &&
		(!s.cfg.Protocols.DoQ.Enabled || s.doqUp)
}

// tlsUpState snapshots which TLS listeners are up.
func (s *Server) tlsUpState() tlsState {
	return tlsState{dot: s.dotUp, doh: s.dohUp, doq: s.doqUp}
}

// tlsState records which TLS listeners were up at a point in time.
type tlsState struct {
	dot, doh, doq bool
}

// startTLS binds the enabled TLS listeners that are not up yet, in
// order DoT, DoH, DoQ. The caller must hold s.mu and have set s.baseCtx.
func (s *Server) startTLS() error {
	if s.cfg.Protocols.DoT.Enabled && !s.dotUp {
		if err := s.startDoT(); err != nil {
			return err
		}
		s.dotUp = true
	}
	if s.cfg.Protocols.DoH.Enabled && !s.dohUp {
		if err := s.startDoH(); err != nil {
			return err
		}
		s.dohUp = true
	}
	if s.cfg.Protocols.DoQ.Enabled && !s.doqUp {
		if err := s.startDoQ(); err != nil {
			return err
		}
		s.doqUp = true
	}
	return nil
}

// Listeners reports the listeners actually running as "proto:port",
// ordered plain, doh, dot, doq. A listener is listed only when it is
// enabled and started, so in ACME mode the eagerly started DoH
// listener appears before the rest of the TLS group does. The result
// is a fresh slice the caller may keep.
func (s *Server) Listeners() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	if s.cfg.Protocols.Plain.Enabled && len(s.plainSrv) > 0 {
		out = append(out, fmt.Sprintf("plain:%d", s.cfg.Protocols.Plain.Port))
	}
	if s.dohUp {
		out = append(out, fmt.Sprintf("doh:%d", s.cfg.Protocols.DoH.Port))
	}
	if s.dotUp {
		out = append(out, fmt.Sprintf("dot:%d", s.cfg.Protocols.DoT.Port))
	}
	if s.doqUp {
		out = append(out, fmt.Sprintf("doq:%d", s.cfg.Protocols.DoQ.Port))
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
	s.challengeLn = ln

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
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

// ReleaseListeners frees every listening socket without cancelling
// s.baseCtx and without calling httpSrv.Shutdown. The HTTP server stays
// up so the management POST that triggered a runtime swap — in flight on
// the very listener being released — can still write its response; only
// the sockets go, so the next generation can bind the same ports. The
// accepted connections keep being served by the old HTTP server until
// the retirement goroutine stops it. A second call is a no-op.
func (s *Server) ReleaseListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, srv := range s.plainSrv {
		if srv.PacketConn != nil {
			_ = srv.PacketConn.Close()
		}
		if srv.Listener != nil {
			_ = srv.Listener.Close()
		}
	}
	s.plainSrv = nil

	for _, srv := range s.tlsSrv {
		if srv.Listener != nil {
			_ = srv.Listener.Close()
		}
	}
	s.tlsSrv = nil

	if s.dohLn != nil {
		_ = s.dohLn.Close()
		s.dohLn = nil
	}
	// The HTTPS (HTTP/1.1 + HTTP/2) server above stays up for in-flight
	// responses; only its socket is freed. HTTP/3 cannot be kept that
	// way — its connections share the QUIC socket — so they are closed
	// outright. We never emit an Alt-Svc header for the panel and
	// browsers only learn about HTTP/3 from one, so clients fall back to
	// HTTPS without noticing.
	if s.h3Srv != nil {
		_ = s.h3Srv.Close()
		s.h3Srv = nil
	}
	// DoQ cannot be kept alive either: its connections share the QUIC
	// socket, and a live connection would hold the UDP port open and
	// stop the next generation from rebinding it, so the endpoint is
	// closed outright. DoQ queries are short-lived, and RFC 9250
	// clients retry on a new connection.
	s.closeDoQLocked()
	// The challenge listener goes too so the port is free for the next
	// generation, but s.challenge stays up: the in-flight challenge
	// response must remain writable. The retirement stop calls Shutdown
	// on the already-closed listener and finishes it.
	if s.challengeLn != nil {
		_ = s.challengeLn.Close()
		s.challengeLn = nil
	}
}

// ForceClose closes the remaining HTTP and HTTP/3 servers outright
// (Close, not Shutdown). It is the retirement goroutine's fallback when
// the graceful stop times out because a handler — the management POST
// that triggered the swap — is still writing on an accepted connection.
func (s *Server) ForceClose() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
		s.httpSrv = nil
	}
	if s.h3Srv != nil {
		_ = s.h3Srv.Close()
		s.h3Srv = nil
	}
	// A stale challenge responder must not outlive a timed-out retire:
	// Close it outright and drop the reference, so its goroutine cannot
	// keep serving after the drain gave up on it.
	if s.challenge != nil {
		_ = s.challenge.Close()
		s.challenge = nil
		s.challengeLn = nil
	}
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

// stopTLSLocked stops every TLS listener (DoT, DoH, DoQ), without
// touching the base context or the plain listener. The caller must
// hold s.mu.
func (s *Server) stopTLSLocked(ctx context.Context) error {
	var firstErr error
	for _, stop := range []func(context.Context) error{s.stopDoTLocked, s.stopDoHLocked, s.stopDoQLocked} {
		if err := stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// rollbackTLS stops the TLS listeners that came up since the snapshot
// before, i.e. exactly the ones a failed StartTLS call started. The
// caller must hold s.mu.
func (s *Server) rollbackTLS(before tlsState, ctx context.Context) error {
	var firstErr error
	merge := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.dotUp && !before.dot {
		merge(s.stopDoTLocked(ctx))
	}
	if s.dohUp && !before.doh {
		merge(s.stopDoHLocked(ctx))
	}
	if s.doqUp && !before.doq {
		merge(s.stopDoQLocked(ctx))
	}
	return firstErr
}

// stopDoTLocked stops the DoT listener. The caller must hold s.mu.
func (s *Server) stopDoTLocked(ctx context.Context) error {
	var firstErr error
	for _, srv := range s.tlsSrv {
		if err := srv.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.tlsSrv = nil
	s.dotUp = false
	return firstErr
}

// stopDoHLocked stops the DoH listeners, HTTPS over TCP and HTTP/3.
// The caller must hold s.mu.
func (s *Server) stopDoHLocked(ctx context.Context) error {
	var firstErr error
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
	s.dohLn = nil
	s.dohUp = false
	return firstErr
}

// stopDoQLocked stops the DoQ endpoint. The caller must hold s.mu.
func (s *Server) stopDoQLocked(ctx context.Context) error {
	s.closeDoQLocked()
	s.doqUp = false
	return nil
}

// closeDoQLocked closes the DoQ endpoint and drops its live connections.
// The listener goes first, so a pending Accept returns quic.ErrServerClosed
// instead of the transport's close error; then the transport, which drops
// every live connection; and finally the UDP socket, which the transport
// does not own because the server bound it. Every Close tolerates an
// already-closed endpoint, so the call is idempotent: ReleaseListeners
// releases the socket on a swap and the retirement Shutdown finds nothing
// left, without a warning. The caller must hold s.mu.
func (s *Server) closeDoQLocked() {
	if s.quicLn != nil {
		_ = s.quicLn.Close()
		s.quicLn = nil
	}
	if s.quicTr != nil {
		_ = s.quicTr.Close()
		s.quicTr = nil
	}
	if s.quicUDP != nil {
		_ = s.quicUDP.Close()
		s.quicUDP = nil
	}
}

// stopChallengeLocked stops the ACME HTTP-01 responder if one runs.
// The caller must hold s.mu.
func (s *Server) stopChallengeLocked(ctx context.Context) error {
	if s.challenge == nil {
		return nil
	}
	err := s.challenge.Shutdown(ctx)
	s.challenge = nil
	s.challengeLn = nil
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

// serve runs one listener loop. It returns only once the loop is
// actually serving: miekg/dns sets its started flag inside
// ActivateAndServe, so a Shutdown racing the goroutine would otherwise
// see "server not started" and leak the listener, leaving the port
// bound. NotifyStartedFunc fires after that flag is set, so waiting on
// it closes the race. A listener released by ReleaseListeners makes the
// loop return net.ErrClosed, which is a normal swap and not a warning.
func (s *Server) serve(srv *dns.Server, proto string, port int) {
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.ActivateAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.logger.Warn("listener stopped", "proto", proto, "port", port, "error", err)
		}
	}()

	select {
	case <-started:
	case <-done:
		// ActivateAndServe returned before signalling: bad listeners.
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
