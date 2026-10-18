package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/tlscert"
)

// startBootstrapDNS starts a UDP DNS server on 127.0.0.1 that answers
// A queries for name with ip, TTL 60, and counts the queries it got.
func startBootstrapDNS(t *testing.T, name, ip string) (*dns.Server, string, *atomic.Int64) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	var calls atomic.Int64
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			calls.Add(1)

			m := new(dns.Msg)
			m.SetReply(req)
			for _, q := range req.Question {
				if q.Qtype != dns.TypeA {
					continue
				}
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(ip).To4(),
				})
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return srv, pc.LocalAddr().String(), &calls
}

// startTCPListener starts a TCP listener on 127.0.0.1 that accepts and
// closes every connection; it returns its address.
func startTCPListener(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	return ln.Addr().String()
}

// dialHostPort dials host:port through r, with a short test deadline.
func dialHostPort(t *testing.T, r *bootstrapResolver, host, port string) (net.Conn, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return r.dialContext(ctx, "tcp", net.JoinHostPort(host, port))
}

// TestBootstrapResolvesAndCaches checks that a hostname is resolved
// through the bootstrap server, that the resolved IP is dialed, and
// that a second dial is served from the cache after the DNS server has
// been stopped.
func TestBootstrapResolvesAndCaches(t *testing.T) {
	srv, dnsAddr, calls := startBootstrapDNS(t, "upstream.test.", "127.0.0.1")
	target := startTCPListener(t)
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", target, err)
	}

	r := newBootstrapResolver([]string{dnsAddr})
	r.timeout = time.Second

	conn, err := dialHostPort(t, r, "upstream.test", port)
	if err != nil {
		t.Fatalf("first dial = %v, want nil", err)
	}
	_ = conn.Close()

	first := calls.Load()
	if first == 0 {
		t.Fatal("bootstrap DNS server got no queries, want at least one")
	}

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("stop DNS server: %v", err)
	}

	conn, err = dialHostPort(t, r, "upstream.test", port)
	if err != nil {
		t.Fatalf("second dial after DNS shutdown = %v, want cache hit", err)
	}
	_ = conn.Close()

	if got := calls.Load(); got != first {
		t.Errorf("DNS queries after cache hit = %d, want still %d", got, first)
	}
}

// TestBootstrapFallsBackToSystem checks that when no bootstrap server
// answers, the resolver falls back to the system resolver: localhost
// resolves and the dial reaches the local listener.
func TestBootstrapFallsBackToSystem(t *testing.T) {
	target := startTCPListener(t)
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", target, err)
	}

	r := newBootstrapResolver([]string{"127.0.0.1:1"})
	r.timeout = 100 * time.Millisecond

	conn, err := dialHostPort(t, r, "localhost", port)
	if err != nil {
		t.Fatalf("dial localhost via system fallback = %v, want nil", err)
	}
	_ = conn.Close()
}

// TestBootstrapNODATAFallsBackToSystem checks that a bootstrap server
// that answers NOERROR without addresses (NODATA) still ends in the
// system fallback, so an upstream on the local network can resolve.
func TestBootstrapNODATAFallsBackToSystem(t *testing.T) {
	// The bootstrap server only knows other.test, so localhost is
	// NODATA for it.
	_, dnsAddr, _ := startBootstrapDNS(t, "other.test.", "127.0.0.1")
	target := startTCPListener(t)
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", target, err)
	}

	r := newBootstrapResolver([]string{dnsAddr})
	r.timeout = time.Second

	conn, err := dialHostPort(t, r, "localhost", port)
	if err != nil {
		t.Fatalf("dial localhost after NODATA = %v, want system fallback", err)
	}
	_ = conn.Close()
}

// TestBootstrapIPLiteralBypassesDNS checks that an IP literal is dialed
// without consulting any resolver, even one with no servers at all.
func TestBootstrapIPLiteralBypassesDNS(t *testing.T) {
	target := startTCPListener(t)

	r := newBootstrapResolver(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := r.dialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("dial IP literal = %v, want nil", err)
	}
	_ = conn.Close()
}

// TestDoHResolvesViaBootstrap checks that the DoH transport resolves
// its URL hostname through the injected bootstrap resolver: the TLS
// server is reached at 127.0.0.1, the SNI still names doh.test, and the
// fake DNS server actually answered.
func TestDoHResolvesViaBootstrap(t *testing.T) {
	_, dnsAddr, dnsCalls := startBootstrapDNS(t, "doh.test.", "127.0.0.1")

	store, err := tlscert.New(config.TLS{Mode: "self-signed"}, "doh.test")
	if err != nil {
		t.Fatalf("tlscert.New() = %v, want nil", err)
	}
	cert, err := store.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate() = %v, want nil", err)
	}

	var sni atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, "unpack", http.StatusBadRequest)
			return
		}

		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(testBootstrapIP).To4(),
		})
		packed, err := reply.Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			sni.Store(hi.ServerName)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", srv.Listener.Addr(), err)
	}

	resolver := newBootstrapResolver([]string{dnsAddr})
	resolver.timeout = time.Second

	tr := newDoHWithResolver(config.UpstreamConfig{
		ID:                 "test",
		Name:               "Test upstream",
		Transport:          "doh",
		Address:            fmt.Sprintf("https://doh.test:%s/dns-query", port),
		InsecureSkipVerify: true,
		Enabled:            true,
	}, resolver)

	resp, err := tr.Exchange(context.Background(), newBootstrapQuery("example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d (%s), want NOERROR", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(resp.Answer))
	}

	if got, _ := sni.Load().(string); got != "doh.test" {
		t.Errorf("TLS SNI = %q, want doh.test", got)
	}
	if dnsCalls.Load() == 0 {
		t.Error("bootstrap DNS server got no queries: the custom dialer was not used")
	}
}

// testBootstrapIP is the A-record answer the DoH test upstream returns.
const testBootstrapIP = "192.0.2.53"

// newBootstrapQuery builds a single-question A query for name.
func newBootstrapQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}
