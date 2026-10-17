package dnsserver

import (
	"fmt"
	"net"

	"github.com/miekg/dns"

	"mydns/internal/ratelimit"
)

// startPlain binds the plain DNS listeners, UDP and TCP on the same
// port. The caller must hold s.mu and have set s.baseCtx.
func (s *Server) startPlain() error {
	port := s.cfg.Protocols.Plain.Port

	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("plain udp :%d: %w", port, err)
	}
	udpSrv := &dns.Server{
		PacketConn: pc,
		UDPSize:    udpMaxResponse, // receive buffer: large EDNS0 queries must parse
		Handler: &plainHandler{
			coreHandler: coreHandler{core: s.core, proto: "udp", ctx: s.baseCtx, logger: s.logger},
			limiter:     s.limiter,
		},
	}
	s.track(udpSrv)
	go s.serve(udpSrv, "udp", port)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		_ = udpSrv.Shutdown() // roll the UDP listener back
		return fmt.Errorf("plain tcp :%d: %w", port, err)
	}
	tcpSrv := &dns.Server{
		Listener: ln,
		Handler: &plainHandler{
			coreHandler: coreHandler{core: s.core, proto: "tcp", ctx: s.baseCtx, logger: s.logger},
			limiter:     s.limiter,
		},
	}
	s.track(tcpSrv)
	go s.serve(tcpSrv, "tcp", port)

	s.logger.Info("plain DNS listening", "port", port)
	return nil
}

// plainHandler answers one plain query through the core pipeline,
// after the per-IP rate limiter. Over-limit UDP requests are dropped
// silently (no amplification), over-limit TCP requests get REFUSED.
type plainHandler struct {
	coreHandler
	limiter *ratelimit.Limiter
}

// ServeDNS implements dns.Handler.
func (h *plainHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if !h.limiter.Allow(remoteIP(w.RemoteAddr())) {
		h.logger.Debug("query dropped by rate limit", "proto", h.proto, "client", w.RemoteAddr().String())
		if h.proto == "udp" {
			return
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	h.coreHandler.ServeDNS(w, req)
}
