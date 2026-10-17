package app_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/transport"
)

// fakeUpstreamIP starts a fake answering A queries with ip after the
// given delay. It also reports how many A queries it answered, which
// excludes the health monitor's NS probes.
func fakeUpstreamIP(t *testing.T, ipv4 [4]byte, delay time.Duration) (*dnsfake.Fake, *atomic.Int64) {
	t.Helper()

	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)

	var aCalls atomic.Int64
	fake.SetHandler(func(req *dns.Msg) *dns.Msg {
		if req.Question[0].Qtype == dns.TypeA {
			aCalls.Add(1)
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3]),
		})
		return m
	})
	return fake, &aCalls
}

// askAllProtocols queries example.com over plain, DoT, DoH and DoQ and
// returns the A answer from each. Every protocol gets a fresh message
// with its own ID, as independent clients do.
func askAllProtocols(t *testing.T, cfg *config.Config) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	newQ := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}

	answers := make([]string, 0, 4)

	// plain
	plain := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := plain.Exchange(newQ(), loopback(cfg.Protocols.Plain.Port))
	if err != nil {
		t.Fatalf("plain Exchange() = %v, want nil", err)
	}
	answers = append(answers, firstA(t, resp))

	// dot, doh, doq through the project's own transports
	for _, tc := range []struct {
		name    string
		address string
	}{
		{"dot", loopback(cfg.Protocols.DoT.Port)},
		{"doh", "https://" + loopback(cfg.Protocols.DoH.Port) + "/dns-query"},
		{"doq", loopback(cfg.Protocols.DoQ.Port)},
	} {
		tr, err := transport.New(config.UpstreamConfig{
			ID:                 "self-" + tc.name,
			Name:               tc.name,
			Transport:          tc.name,
			Address:            tc.address,
			ServerName:         cfg.Domain,
			InsecureSkipVerify: true, // self-signed test certificate
			Enabled:            true,
		})
		if err != nil {
			t.Fatalf("transport.New(%s) = %v, want nil", tc.name, err)
		}
		resp, err := tr.Exchange(ctx, newQ())
		_ = tr.Close()
		if err != nil {
			t.Fatalf("%s Exchange() = %v, want nil", tc.name, err)
		}
		answers = append(answers, firstA(t, resp))
	}
	return answers
}

// firstA extracts the first A answer's address, failing the test when
// the reply is malformed.
func firstA(t *testing.T, resp *dns.Msg) string {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("reply has no answers, want one A record")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer has type %T, want *dns.A", resp.Answer[0])
	}
	return a.A.String()
}

// TestEndToEndAllProtocols proves the design's §7 promises end to end:
// every protocol answers, the fastest upstream wins, answers are
// cached, and a dead upstream fails over to the next one.
func TestEndToEndAllProtocols(t *testing.T) {
	fakeA, aCalls := fakeUpstreamIP(t, [4]byte{192, 0, 2, 1}, 0)
	fakeB, bCalls := fakeUpstreamIP(t, [4]byte{192, 0, 2, 2}, 50*time.Millisecond)

	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: freePort(t)},
		DoT:   config.Protocol{Enabled: true, Port: freePort(t)},
		DoH:   config.Protocol{Enabled: true, Port: freePort(t)},
		DoQ:   config.Protocol{Enabled: true, Port: freePort(t)},
	}
	cfg.Upstreams = []config.UpstreamConfig{
		{ID: "a", Name: "A", Transport: "plain", Address: fakeA.Addr(), Priority: 0, Enabled: true},
		{ID: "b", Name: "B", Transport: "plain", Address: fakeB.Addr(), Priority: 1, Enabled: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
	}

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
		_ = a.Stop(sctx)
	})

	// Let the monitor learn both latencies (A fast, B slow).
	time.Sleep(200 * time.Millisecond)

	// Every protocol answers, fastest upstream A wins.
	for i, got := range askAllProtocols(t, cfg) {
		if got != "192.0.2.1" {
			t.Errorf("protocol #%d answered from %s, want 192.0.2.1 (fastest)", i, got)
		}
	}

	// Repeat: answers come from the cache, the upstream sees no new
	// A queries.
	before := aCalls.Load()
	for i, got := range askAllProtocols(t, cfg) {
		if got != "192.0.2.1" {
			t.Errorf("cached protocol #%d answered from %s, want 192.0.2.1", i, got)
		}
	}
	if after := aCalls.Load(); after != before {
		t.Errorf("upstream A calls went %d -> %d, want no new queries (cache hit)", before, after)
	}

	// Kill A: after the monitor marks it unhealthy and the 1s TTL
	// expires, every protocol must fail over to B.
	fakeA.Close()
	time.Sleep(1200 * time.Millisecond)

	beforeB := bCalls.Load()
	for i, got := range askAllProtocols(t, cfg) {
		if got != "192.0.2.2" {
			t.Errorf("failover protocol #%d answered from %s, want 192.0.2.2 (upstream B)", i, got)
		}
	}
	if afterB := bCalls.Load(); afterB <= beforeB {
		t.Errorf("upstream B calls went %d -> %d, want new queries after failover", beforeB, afterB)
	}
}
