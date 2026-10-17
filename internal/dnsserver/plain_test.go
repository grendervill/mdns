package dnsserver_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/dnsserver"
	"mydns/internal/qlog"
	"mydns/internal/ratelimit"
	"mydns/internal/routing"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/tlscert"
	"mydns/internal/upstream"
)

// freePort returns a port currently free for UDP on the loopback
// interface. A rare race with another process is acceptable for tests.
func freePort(t *testing.T) int {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() = %v, want nil", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// newFakeUpstream starts a fake upstream answering every A query with
// testIP.
func newFakeUpstream(t *testing.T) (*dnsfake.Fake, *upstream.Upstream) {
	t.Helper()

	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)
	fake.SetHandler(func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		})
		return m
	})

	u, err := upstream.New(config.UpstreamConfig{
		ID: "fake", Name: "fake", Transport: "plain", Address: fake.Addr(), Enabled: true,
	})
	if err != nil {
		t.Fatalf("upstream.New() = %v, want nil", err)
	}
	return fake, u
}

// newTestServer builds a full pipeline (fake upstream, router, cache,
// core, server) with plain DNS enabled on a free port.
func newTestServer(t *testing.T, rps int) (*dnsserver.Server, *dnsfake.Fake, *qlog.Log, int) {
	t.Helper()

	fake, u := newFakeUpstream(t)

	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: port},
	}

	certs, err := tlscert.New(cfg.TLS, cfg.Domain)
	if err != nil {
		t.Fatalf("tlscert.New() = %v, want nil", err)
	}
	limiter, err := ratelimit.New(rps, nil, nil)
	if err != nil {
		t.Fatalf("ratelimit.New() = %v, want nil", err)
	}
	router, err := routing.New([]*upstream.Upstream{u}, cfg.Strategy)
	if err != nil {
		t.Fatalf("routing.New() = %v, want nil", err)
	}
	queryLog, err := qlog.New(100, "", 0)
	if err != nil {
		t.Fatalf("qlog.New() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = queryLog.Close() })

	c := core.New(router, cache.New(100, 0, 86400), queryLog, nil)
	srv := dnsserver.New(cfg, c, certs, limiter, nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
	})

	return srv, fake, queryLog, port
}

// query builds a single-question A query.
func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// TestPlainUDP checks one query over UDP: a NOERROR reply through the
// fake upstream and a log entry marked "udp".
func TestPlainUDP(t *testing.T) {
	_, fake, queryLog, port := newTestServer(t, 100)

	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	resp, _, err := cl.Exchange(query("example.com"), loopback(port))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(resp.Answer))
	}
	if got := fake.Calls(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}

	recent := queryLog.Recent(1)
	if len(recent) != 1 || recent[0].Proto != "udp" {
		t.Errorf("log entry = %+v, want one with proto udp", recent)
	}
}

// TestPlainTCP checks the same over TCP.
func TestPlainTCP(t *testing.T) {
	_, _, queryLog, port := newTestServer(t, 100)

	cl := &dns.Client{Net: "tcp", Timeout: time.Second}
	resp, _, err := cl.Exchange(query("example.com"), loopback(port))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", resp.Rcode)
	}

	recent := queryLog.Recent(1)
	if len(recent) != 1 || recent[0].Proto != "tcp" {
		t.Errorf("log entry = %+v, want one with proto tcp", recent)
	}
}

// TestPlainRateLimitDropsUDP checks that an over-limit UDP request is
// dropped silently: the client sees a timeout.
func TestPlainRateLimitDropsUDP(t *testing.T) {
	_, fake, _, port := newTestServer(t, 1)

	cl := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	addr := loopback(port)

	if _, _, err := cl.Exchange(query("example.com"), addr); err != nil {
		t.Fatalf("Exchange() #1 = %v, want nil", err)
	}
	if _, _, err := cl.Exchange(query("example.com"), addr); err == nil {
		t.Fatalf("Exchange() #2 = nil error, want a timeout (dropped)")
	}
	if got := fake.Calls(); got != 1 {
		t.Errorf("upstream calls = %d, want 1 (second request never forwarded)", got)
	}
}

// TestPlainRateLimitRefusesTCP checks that an over-limit TCP request
// gets a REFUSED reply instead of a silent drop.
func TestPlainRateLimitRefusesTCP(t *testing.T) {
	_, _, _, port := newTestServer(t, 1)

	cl := &dns.Client{Net: "tcp", Timeout: time.Second}
	addr := loopback(port)

	if _, _, err := cl.Exchange(query("example.com"), addr); err != nil {
		t.Fatalf("Exchange() #1 = %v, want nil", err)
	}
	resp, _, err := cl.Exchange(query("example.com"), addr)
	if err != nil {
		t.Fatalf("Exchange() #2 = %v, want a REFUSED reply", err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED", resp.Rcode)
	}
}

// TestShutdownReleasesPorts checks that after Shutdown the port can be
// bound again.
func TestShutdownReleasesPorts(t *testing.T) {
	srv, _, _, port := newTestServer(t, 100)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() = %v, want nil", err)
	}

	pc, err := net.ListenPacket("udp", loopback(port))
	if err != nil {
		t.Fatalf("ListenPacket() after Shutdown = %v, want the port released", err)
	}
	_ = pc.Close()
}

// loopback builds the loopback address for port.
func loopback(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}
