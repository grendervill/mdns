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

// freePort returns a port currently free for both TCP and UDP on the
// loopback interface. A rare race with another process is acceptable
// for tests.
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp) = %v, want nil", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = ln.Close()
		t.Fatalf("ListenPacket(udp :%d) = %v, want nil", port, err)
	}
	_ = pc.Close()
	_ = ln.Close()
	return port
}

// newFakeUpstream starts a fake upstream answering every A query with
// testIP.
func newFakeUpstream(t *testing.T) *dnsfake.Fake {
	t.Helper()
	fake, _ := newFakeUpstreamPair(t, nil)
	return fake
}

// newFakeUpstreamPair starts a fake upstream with handler h (nil means
// the default single testIP answer) and an upstream transport over it.
func newFakeUpstreamPair(t *testing.T, h func(*dns.Msg) *dns.Msg) (*dnsfake.Fake, *upstream.Upstream) {
	t.Helper()

	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)

	if h == nil {
		h = func(req *dns.Msg) *dns.Msg {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, 1),
			})
			return m
		}
	}
	fake.SetHandler(h)

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

	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: port},
	}

	srv, fake, queryLog := testPipeline(t, cfg, rps)
	return srv, fake, queryLog, port
}

// newTestServerHandler is newTestServer with a custom upstream reply
// handler.
func newTestServerHandler(t *testing.T, rps int, h func(*dns.Msg) *dns.Msg) (int, *dnsfake.Fake) {
	t.Helper()

	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: port},
	}

	_, fake, _ := testPipelineHandler(t, cfg, rps, h)
	return port, fake
}

// testPipeline builds the whole stack up to a started server for the
// given config; everything is torn down when the test ends.
func testPipeline(t *testing.T, cfg *config.Config, rps int) (*dnsserver.Server, *dnsfake.Fake, *qlog.Log) {
	t.Helper()
	return testPipelineHandler(t, cfg, rps, nil)
}

// testPipelineHandler is testPipeline with a custom upstream handler.
func testPipelineHandler(t *testing.T, cfg *config.Config, rps int, h func(*dns.Msg) *dns.Msg) (*dnsserver.Server, *dnsfake.Fake, *qlog.Log) {
	t.Helper()

	fake, u := newFakeUpstreamPair(t, h)

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

	return srv, fake, queryLog
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

// bigReply answers with enough A records to exceed a 1232-byte UDP
// response.
func bigReply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	for i := 0; i < 100; i++ {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, byte(i+1)),
		})
	}
	return m
}

// TestPlainUDPTruncatesLargeResponse checks the UDP size policy: a
// large answer is truncated to at most 1232 bytes with the TC bit set,
// so the client knows to retry over TCP.
func TestPlainUDPTruncatesLargeResponse(t *testing.T) {
	port, _ := newTestServerHandler(t, 100, bigReply)

	cl := &dns.Client{Net: "udp", Timeout: time.Second, UDPSize: dns.MaxMsgSize}
	resp, _, err := cl.Exchange(query("example.com"), loopback(port))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if !resp.Truncated {
		t.Errorf("Truncated = false, want true (the answer exceeds 1232 bytes)")
	}
	if len(resp.Answer) == 100 {
		t.Errorf("Answer carries all %d records, want the reply truncated", len(resp.Answer))
	}
	// The wire form is compressed; repack the way the server sent it to
	// measure what actually crossed the socket.
	resp.Compress = true
	if got := resp.Len(); got > 1232 {
		t.Errorf("compressed response Len = %d, want <= 1232", got)
	}
}

// TestPlainTCPKeepsLargeResponse checks that the same answer travels
// complete over TCP: truncation is a UDP-only policy.
func TestPlainTCPKeepsLargeResponse(t *testing.T) {
	port, _ := newTestServerHandler(t, 100, bigReply)

	cl := &dns.Client{Net: "tcp", Timeout: time.Second}
	resp, _, err := cl.Exchange(query("example.com"), loopback(port))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Truncated {
		t.Errorf("Truncated = true, want false (full reply over TCP)")
	}
	if len(resp.Answer) != 100 {
		t.Errorf("Answer has %d records, want all 100", len(resp.Answer))
	}
}

// TestPlainUDPReadsLargeQuery checks that a query larger than the
// 512-byte default receive buffer is still parsed: a padded, EDNS0
// query must resolve rather than time out.
func TestPlainUDPReadsLargeQuery(t *testing.T) {
	_, _, _, port := newTestServer(t, 100)

	q := query("example.com")
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = append(q.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 600)})

	packed, err := q.Pack()
	if err != nil {
		t.Fatalf("Pack() = %v, want nil", err)
	}
	if len(packed) <= 512 {
		t.Fatalf("query is %d bytes; the test needs one over 512", len(packed))
	}

	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	resp, _, err := cl.Exchange(q, loopback(port))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil (query size %d must be readable)", err, len(packed))
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", resp.Rcode)
	}
}

// loopback builds the loopback address for port.
func loopback(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}
