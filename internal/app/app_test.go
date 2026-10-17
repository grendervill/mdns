package app_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/upstream"
)

// discardLogger returns a logger that drops everything.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// freePort returns a port currently free for both TCP and UDP on the
// loopback interface.
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

// loopback builds the loopback address for port.
func loopback(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// newFakeUpstream starts a fake upstream answering every A query with
// 192.0.2.1.
func newFakeUpstream(t *testing.T) *dnsfake.Fake {
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
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.IPv4(192, 0, 2, 1),
		})
		return m
	})
	return fake
}

// testConfig builds a plain-enabled config pointing at the fake.
func testConfig(t *testing.T, fake *dnsfake.Fake, port int) *config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: port},
	}
	cfg.Upstreams = []config.UpstreamConfig{{
		ID:        "fake",
		Name:      "fake",
		Transport: "plain",
		Address:   fake.Addr(),
		Enabled:   true,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
	}
	return cfg
}

// fastMonitor shortens the probing cadence for tests.
func fastMonitor() upstream.MonitorOptions {
	return upstream.MonitorOptions{
		Interval:     50 * time.Millisecond,
		IdleInterval: 50 * time.Millisecond,
		Timeout:      300 * time.Millisecond,
	}
}

// TestAppServesPlain checks the whole wiring: App.Start brings up the
// pipeline and answers a query through the fake upstream.
func TestAppServesPlain(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)

	a, err := app.New(cfg, app.Options{Monitor: fastMonitor()}, discardLogger())
	if err != nil {
		t.Fatalf("app.New() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		if err := a.Stop(sctx); err != nil {
			t.Errorf("Stop() = %v, want nil", err)
		}
	})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	resp, _, err := cl.Exchange(q, loopback(port))
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
}

// TestAppRejectsBadConfig checks that New surfaces config problems.
func TestAppRejectsBadConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "" // invalid
	if _, err := app.New(cfg, app.Options{}, discardLogger()); err == nil {
		t.Fatalf("app.New(invalid) = nil error, want an error")
	}
}
