package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	// Pin a non-loopback nameserver: the host's own resolv.conf must not
	// decide whether this test's fallback runs.
	r.systemNameservers = func() []string { return []string{"192.0.2.53"} }

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
	// Pin a non-loopback nameserver so the loop guard does not depend on
	// the host's resolv.conf (systemd-resolved points at 127.0.0.53).
	r.systemNameservers = func() []string { return []string{"192.0.2.53"} }

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

// startDualStackBootstrapDNS starts a UDP DNS server on 127.0.0.1 that
// answers name with both an A and an AAAA record, so the resolver sees
// the two families in one answer.
func startDualStackBootstrapDNS(t *testing.T, name string) (*dns.Server, string) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			for _, q := range req.Question {
				switch q.Qtype {
				case dns.TypeA:
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("192.0.2.1").To4(),
					})
				case dns.TypeAAAA:
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: net.ParseIP("2001:db8::1"),
					})
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return srv, pc.LocalAddr().String()
}

// TestBootstrapLoopbackSystemFailsFast checks the loop guard: when every
// system nameserver is loopback, the fallback is skipped, the bootstrap
// error propagates at once, and the failure is cached so a second call
// does not query again.
func TestBootstrapLoopbackSystemFailsFast(t *testing.T) {
	r := newBootstrapResolver([]string{"127.0.0.1:1"})
	r.timeout = 100 * time.Millisecond
	r.systemNameservers = func() []string { return []string{"127.0.0.1", "::1"} }

	var systemCalls atomic.Int64
	r.lookupSystem = func(context.Context, string) ([]netip.Addr, error) {
		systemCalls.Add(1)
		return nil, errors.New("the system resolver must not be consulted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < 2; i++ {
		begin := time.Now()
		addrs, err := r.resolveAddr(ctx, "localhost:53")
		if err == nil {
			t.Fatalf("attempt %d: resolveAddr(localhost) = %v, want the bootstrap error", i, addrs)
		}
		if elapsed := time.Since(begin); elapsed > 3*time.Second {
			t.Errorf("attempt %d took %s, want a fast failure", i, elapsed)
		}
	}
	if got := systemCalls.Load(); got != 0 {
		t.Errorf("the system resolver was consulted %d times, want 0 for loopback nameservers", got)
	}
}

// TestBootstrapSuccessSkipsSystemFallback checks that a hostname the
// bootstrap servers resolve never reaches the system resolver.
func TestBootstrapSuccessSkipsSystemFallback(t *testing.T) {
	_, dnsAddr, _ := startBootstrapDNS(t, "upstream.test.", "127.0.0.1")

	r := newBootstrapResolver([]string{dnsAddr})
	r.timeout = time.Second

	var systemCalls atomic.Int64
	r.lookupSystem = func(context.Context, string) ([]netip.Addr, error) {
		systemCalls.Add(1)
		return nil, errors.New("unexpected system lookup")
	}

	addrs, err := r.resolve(context.Background(), "upstream.test")
	if err != nil {
		t.Fatalf("resolve() = %v, want nil", err)
	}
	if len(addrs) != 1 || addrs[0] != "127.0.0.1" {
		t.Errorf("resolve() = %v, want [127.0.0.1]", addrs)
	}
	if got := systemCalls.Load(); got != 0 {
		t.Errorf("the system fallback was consulted %d times, want 0", got)
	}
}

// TestBootstrapIPv4First checks the dial order: an answer carrying both
// families is sorted with IPv4 first, because the sequential dial must
// not sink into a blackholed IPv6 path.
func TestBootstrapIPv4First(t *testing.T) {
	_, dnsAddr := startDualStackBootstrapDNS(t, "dual.test.")

	for i := 0; i < 10; i++ {
		r := newBootstrapResolver([]string{dnsAddr})
		r.timeout = time.Second

		addrs, err := r.resolve(context.Background(), "dual.test")
		if err != nil {
			t.Fatalf("resolve() = %v, want nil", err)
		}
		if len(addrs) != 2 {
			t.Fatalf("resolve() = %v, want two addresses", addrs)
		}
		if addrs[0] != "192.0.2.1" || addrs[1] != "2001:db8::1" {
			t.Fatalf("resolve() order = %v, want IPv4 then IPv6", addrs)
		}
	}
}

// TestPlainResolvesViaBootstrap checks the plain transport with a
// hostname address: the bootstrap resolver maps upstream.test to the
// local fake server, and Exchange succeeds.
func TestPlainResolvesViaBootstrap(t *testing.T) {
	_, dnsAddr, dnsCalls := startBootstrapDNS(t, "upstream.test.", "127.0.0.1")
	_, upstreamAddr, upstreamCalls := startBootstrapDNS(t, "example.com.", "192.0.2.1")

	_, port, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", upstreamAddr, err)
	}

	resolver := newBootstrapResolver([]string{dnsAddr})
	resolver.timeout = time.Second

	tr := newPlainWithResolver(config.UpstreamConfig{
		ID:        "test",
		Name:      "Test upstream",
		Transport: "plain",
		Address:   "upstream.test:" + port,
		Enabled:   true,
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
	if upstreamCalls.Load() == 0 {
		t.Error("the plain upstream got no queries")
	}
	if dnsCalls.Load() == 0 {
		t.Error("the bootstrap DNS server got no queries: the injected resolver was not used")
	}
}
