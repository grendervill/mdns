package app_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/filter"
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

// testOptions returns Options wired for tests: a short temp socket
// path (macOS caps unix socket paths at ~104 bytes, so t.TempDir's
// long test-name paths are unsafe) and a temp config path plus the
// fast monitor.
func testOptions(t *testing.T) app.Options {
	t.Helper()

	sockDir, err := os.MkdirTemp("", "mdns-")
	if err != nil {
		t.Fatalf("MkdirTemp() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	return app.Options{
		Monitor:    fastMonitor(),
		SocketPath: filepath.Join(sockDir, "mdns.sock"),
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}
}

// query builds a single-question A query for name.
func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
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
	cfg.DataDir = t.TempDir() // tests must never touch /var/lib/mdns
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

	a, err := app.New(cfg, testOptions(t), discardLogger())
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

// tlsSkipClient returns an HTTP client trusting self-signed test
// servers.
func tlsSkipClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   3 * time.Second,
	}
}

// TestAppFilterBlocks checks the whole filter wiring: the updater
// fetches the list over TLS, the engine blocks a domain while letting
// others through, and a dead list server keeps the rules working with
// the error visible in the status.
func TestAppFilterBlocks(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "||ads.example.com^\n")
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig(t, fake, port)
	cfg.Filter = config.FilterConfig{
		Enabled: true,
		Mode:    "zero",
		Lists:   []config.FilterList{{ID: "test-list", URL: srv.URL + "/list.txt"}},
	}

	cl := tlsSkipClient()
	opts := testOptions(t)
	opts.FilterClient = cl
	opts.FilterInterval = 50 * time.Millisecond
	a, err := app.New(cfg, opts, discardLogger())
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
		_ = a.Stop(sctx)
	})

	// Wait until the list is applied.
	waitStatus(t, a, func(st []filter.ListStatus) bool {
		return len(st) == 1 && st[0].Applied == 1
	})

	clDNS := &dns.Client{Net: "udp", Timeout: time.Second}

	// A blocked domain.
	resp, _, err := clDNS.Exchange(query("ads.example.com"), loopback(port))
	if err != nil {
		t.Fatalf("blocked Exchange() = %v, want nil", err)
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "0.0.0.0" {
		t.Fatalf("blocked answer = %v, want A 0.0.0.0", resp.Answer)
	}

	// A normal domain still resolves through the fake.
	resp, _, err = clDNS.Exchange(query("example.com"), loopback(port))
	if err != nil {
		t.Fatalf("normal Exchange() = %v, want nil", err)
	}
	aRec, ok = resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "192.0.2.1" {
		t.Fatalf("normal answer = %v, want A 192.0.2.1", resp.Answer)
	}

	// Kill the list server: the error must surface, the rules must stay.
	srv.Close()
	waitStatus(t, a, func(st []filter.ListStatus) bool {
		return len(st) == 1 && st[0].Error != ""
	})
	resp, _, err = clDNS.Exchange(query("ads.example.com"), loopback(port))
	if err != nil {
		t.Fatalf("blocked Exchange() after server death = %v, want nil", err)
	}
	aRec, ok = resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "0.0.0.0" {
		t.Errorf("blocked answer after server death = %v, want A 0.0.0.0 (old rules stay)", resp.Answer)
	}
}

// waitStatus polls the app's filter status until cond holds.
func waitStatus(t *testing.T, a *app.App, cond func([]filter.ListStatus) bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond(a.FilterStatus()) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("filter status condition not met in time; last status: %+v", a.FilterStatus())
}

// TestAppFilterDisabled checks that a disabled filter keeps the old
// behavior and null accessors.
func TestAppFilterDisabled(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port) // Filter disabled by default

	a, err := app.New(cfg, testOptions(t), discardLogger())
	if err != nil {
		t.Fatalf("app.New() = %v, want nil", err)
	}
	if a.Filter() != nil {
		t.Errorf("Filter() = %v, want nil when disabled", a.Filter())
	}
	if a.FilterStatus() != nil {
		t.Errorf("FilterStatus() = %v, want nil when disabled", a.FilterStatus())
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
