package dnsserver

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// startDoT binds the DNS-over-TLS listener (RFC 7858): TLS on the
// configured TCP port, the "dot" ALPN protocol, certificates from the
// store. The caller must hold s.mu and have set s.baseCtx.
func (s *Server) startDoT() error {
	port := s.cfg.Protocols.DoT.Port

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("dot tcp :%d: %w", port, err)
	}

	tlsCfg := &tls.Config{
		GetCertificate: s.certs.GetCertificate,
		NextProtos:     []string{"dot"},
	}
	srv := &dns.Server{
		Listener: tls.NewListener(ln, tlsCfg),
		Handler:  &coreHandler{core: s.core, proto: "dot", ctx: s.baseCtx, logger: s.logger},
	}
	s.trackTLS(srv)
	s.serve(srv, "dot", port)

	s.logger.Info("DoT listening", "port", port)
	return nil
}
