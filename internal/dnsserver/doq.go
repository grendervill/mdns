package dnsserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
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
//
// The UDP socket is bound and wrapped in an explicit Transport instead
// of calling quic.ListenAddr: the implicit transport behind ListenAddr
// owns the socket, and closing only the listener leaves a live
// connection holding it, so the next runtime generation could not
// rebind the port. An explicit transport can be closed to drop live
// connections and free the socket.
func (s *Server) startDoQ() error {
	port := s.cfg.Protocols.DoQ.Port

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("doq udp :%d: %w", port, err)
	}

	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(
		&tls.Config{
			GetCertificate: s.certs.GetCertificate,
			NextProtos:     []string{"doq"},
		},
		&quic.Config{MaxIncomingStreams: maxDoQStreams},
	)
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		return fmt.Errorf("doq udp :%d: %w", port, err)
	}

	s.quicUDP = udpConn
	s.quicTr = tr
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
