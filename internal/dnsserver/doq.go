package dnsserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"mydns/internal/core"
	"mydns/internal/doq"
)

// maxDoQStreams bounds concurrent incoming streams per connection.
const maxDoQStreams = 128

// startDoQ binds the DNS-over-QUIC listener (RFC 9250): one QUIC
// endpoint on the configured UDP port, the "doq" ALPN protocol, one
// query per stream. The caller must hold s.mu and have set s.baseCtx.
func (s *Server) startDoQ() error {
	port := s.cfg.Protocols.DoQ.Port

	ln, err := quic.ListenAddr(
		fmt.Sprintf(":%d", port),
		&tls.Config{
			GetCertificate: s.certs.GetCertificate,
			NextProtos:     []string{"doq"},
		},
		&quic.Config{MaxIncomingStreams: maxDoQStreams},
	)
	if err != nil {
		return fmt.Errorf("doq udp :%d: %w", port, err)
	}
	s.quicLn = ln
	go s.serveDoQ(ln)

	s.logger.Info("DoQ listening", "port", port)
	return nil
}

// serveDoQ accepts connections until the listener closes.
func (s *Server) serveDoQ(ln *quic.Listener) {
	for {
		conn, err := ln.Accept(s.baseCtx)
		if err != nil {
			if s.baseCtx.Err() == nil && !errors.Is(err, quic.ErrServerClosed) {
				s.logger.Warn("DoQ accept failed", "error", err)
			}
			return
		}
		go s.serveDoQConn(conn)
	}
}

// serveDoQConn accepts streams until the connection dies.
func (s *Server) serveDoQConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(s.baseCtx)
		if err != nil {
			return
		}
		go s.serveDoQStream(conn, stream)
	}
}

// serveDoQStream answers one query on one stream and closes it. Any
// framing or parsing failure closes the stream unanswered, which is
// the RFC 9250 failure mode clients expect.
func (s *Server) serveDoQStream(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()

	raw, err := doq.ReadMessage(stream)
	if err != nil {
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		return
	}

	clientIP := netip.Addr{}
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		clientIP = ap.Addr().Unmap()
	}

	resp := s.core.Resolve(s.baseCtx, req, core.Meta{Proto: "doq", ClientIP: clientIP})

	out, err := resp.Pack()
	if err != nil {
		return
	}
	_ = doq.WriteMessage(stream, out)
}
