package dnsserver

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	"mydns/internal/core"
	"mydns/internal/tlscert"
)

// maxDoHRequest caps the request body size: the wire format's own
// limit is 65535 bytes, so 64 KiB covers it with room to spare.
const maxDoHRequest = 64 << 10

// DoH server hardening: this endpoint is internet-facing, so headers
// and idle connections are bounded (Slowloris, connection exhaustion).
const (
	dohReadHeaderTimeout = 5 * time.Second
	dohReadTimeout       = 10 * time.Second
	dohWriteTimeout      = 10 * time.Second
	dohIdleTimeout       = 60 * time.Second
	dohMaxHeaderBytes    = 16 << 10
)

// buildDoHServers builds the HTTPS (HTTP/1.1 + HTTP/2) and HTTP/3
// servers sharing one handler. certs may be nil in tests; when set,
// its GetCertificate signs every handshake. An ACME source makes the
// HTTPS listener also advertise the acme-tls/1 protocol (RFC 8737), so
// a tls-alpn-01 challenge reaches GetCertificate; HTTP/3 keeps its
// QUIC-only protocols.
func buildDoHServers(mux http.Handler, certs tlscert.Source, addr string) (*http.Server, *http3.Server) {
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if certs != nil {
		getCert = certs.GetCertificate
	}

	nextProtos := []string{"h2", "http/1.1"}
	if certs != nil && certs.ACMEALPN() {
		nextProtos = append(nextProtos, "acme-tls/1")
	}

	httpSrv := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: getCert,
			NextProtos:     nextProtos,
		},
		ReadHeaderTimeout: dohReadHeaderTimeout,
		ReadTimeout:       dohReadTimeout,
		WriteTimeout:      dohWriteTimeout,
		IdleTimeout:       dohIdleTimeout,
		MaxHeaderBytes:    dohMaxHeaderBytes,
	}
	h3Srv := &http3.Server{
		Addr:           addr,
		Handler:        mux,
		TLSConfig:      &tls.Config{GetCertificate: getCert},
		IdleTimeout:    dohIdleTimeout,
		MaxHeaderBytes: dohMaxHeaderBytes,
	}
	return httpSrv, h3Srv
}

// startDoH binds the DoH endpoint: HTTPS over TCP (HTTP/1.1 and
// HTTP/2) and HTTP/3 over UDP, both on the same port, sharing one
// handler. The caller must hold s.mu and have set s.baseCtx.
func (s *Server) startDoH() error {
	port := s.cfg.Protocols.DoH.Port

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)

	httpSrv, h3Srv := buildDoHServers(mux, s.certs, fmt.Sprintf(":%d", port))

	ln, err := net.Listen("tcp", httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("doh tcp :%d: %w", port, err)
	}

	s.httpSrv = httpSrv
	s.h3Srv = h3Srv

	go func() {
		if err := httpSrv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Warn("DoH HTTPS listener stopped", "port", port, "error", err)
		}
	}()
	go func() {
		if err := h3Srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Warn("DoH HTTP/3 listener stopped", "port", port, "error", err)
		}
	}()

	s.logger.Info("DoH listening", "port", port)
	return nil
}

// handleDoH implements the RFC 8484 endpoint: POST with the wire
// format as the body, or GET with the base64url ?dns= parameter.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var packed []byte

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "expected Content-Type application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDoHRequest))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "cannot read request body", http.StatusBadRequest)
			return
		}
		packed = body

	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		body, err := base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			http.Error(w, "dns parameter is not base64url", http.StatusBadRequest)
			return
		}
		packed = body

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(packed); err != nil {
		http.Error(w, "body is not a DNS message", http.StatusBadRequest)
		return
	}

	resp := s.core.Resolve(r.Context(), req, core.Meta{
		Proto:    "doh",
		ClientIP: remoteIPFromHTTPAddr(r.RemoteAddr),
	})
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "cannot encode the reply", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(out)
}

// remoteIPFromHTTPAddr parses the "host:port" form used by
// http.Server and http3.Server RemoteAddr fields.
func remoteIPFromHTTPAddr(remoteAddr string) netip.Addr {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
