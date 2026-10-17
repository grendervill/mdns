package dnsserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"

	"mydns/internal/core"
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
		Handler:    &plainHandler{core: s.core, limiter: s.limiter, proto: "udp", ctx: s.baseCtx},
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
		Handler:  &plainHandler{core: s.core, limiter: s.limiter, proto: "tcp", ctx: s.baseCtx},
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
	core    *core.Core
	limiter *ratelimit.Limiter
	proto   string
	ctx     context.Context
}

// ServeDNS implements dns.Handler.
func (h *plainHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	ip := remoteIP(w.RemoteAddr())
	if !h.limiter.Allow(ip) {
		if h.proto == "udp" {
			return
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	resp := h.core.Resolve(h.ctx, req, core.Meta{Proto: h.proto, ClientIP: ip})
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
