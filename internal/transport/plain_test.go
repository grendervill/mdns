package transport_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/transport"
)

// testIP is the A-record answer the fake upstream returns.
const testIP = "192.0.2.1"

// aRecord builds an A record for name carrying testIP.
func aRecord(name string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(testIP).To4(),
	}
}

// newQuery builds a single-question A query for name.
func newQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// newFakeTransport starts a fresh fake upstream with handler h and a
// plain transport pointed at it; both are closed when the test ends.
func newFakeTransport(t *testing.T, h func(*dns.Msg) *dns.Msg) (transport.Transport, *dnsfake.Fake) {
	t.Helper()

	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)
	fake.SetHandler(h)

	tr, err := transport.New(config.UpstreamConfig{
		ID:        "test",
		Name:      "Test upstream",
		Transport: "plain",
		Address:   fake.Addr(),
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("transport.New(plain) = %v, want nil", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	return tr, fake
}

// TestPlainExchange checks the happy path: one UDP query, one full
// NOERROR reply with the fake's single A answer.
func TestPlainExchange(t *testing.T) {
	tr, fake := newFakeTransport(t, func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, aRecord(req.Question[0].Name))
		return m
	})

	if got := tr.Name(); got != "plain" {
		t.Errorf("Name() = %q, want %q", got, "plain")
	}

	resp, err := tr.Exchange(context.Background(), newQuery("example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d (%s), want NOERROR", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer[0] has type %T, want *dns.A", resp.Answer[0])
	}
	if got := a.A.String(); got != testIP {
		t.Errorf("A = %s, want %s", got, testIP)
	}
	if got := fake.Calls(); got != 1 {
		t.Errorf("fake.Calls() = %d, want 1 (UDP only, no fallback)", got)
	}
}

// TestPlainTruncatedFallsBackToTCP checks the TC-bit fallback: the UDP
// reply is truncated with an empty answer, and the transport must
// return the full answer from the TCP retry.
func TestPlainTruncatedFallsBackToTCP(t *testing.T) {
	var calls atomic.Int64
	tr, fake := newFakeTransport(t, func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		if calls.Add(1) == 1 {
			// The UDP reply: truncated, no answer.
			m.Truncated = true
			return m
		}
		// The TCP retry: the full answer.
		m.Answer = append(m.Answer, aRecord(req.Question[0].Name))
		return m
	})

	resp, err := tr.Exchange(context.Background(), newQuery("example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Truncated {
		t.Errorf("resp.Truncated = true, want false (full reply over TCP)")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1 (full reply over TCP)", len(resp.Answer))
	}
	if got := fake.Calls(); got != 2 {
		t.Errorf("fake.Calls() = %d, want 2 (UDP then TCP fallback)", got)
	}
}

// TestPlainContextTimeout checks that Exchange honors the caller's
// context: an upstream that stays silent past a 100ms deadline must
// produce an error well within a second.
func TestPlainContextTimeout(t *testing.T) {
	tr, _ := newFakeTransport(t, func(req *dns.Msg) *dns.Msg {
		// The upstream never answers within the context's deadline.
		time.Sleep(1 * time.Second)
		m := new(dns.Msg)
		m.SetReply(req)
		return m
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	resp, err := tr.Exchange(ctx, newQuery("example.com"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Exchange() = nil error, want deadline error")
	}
	if resp != nil {
		t.Errorf("Exchange() returned a message, want nil")
	}
	if elapsed >= 1*time.Second {
		t.Errorf("Exchange() returned after %v, want < 1s (deadline 100ms)", elapsed)
	}
}

// TestNewUnsupportedTransport checks that New rejects every transport
// except plain until the dot, doh and doq transports land.
func TestNewUnsupportedTransport(t *testing.T) {
	for _, name := range []string{"dot", "doh", "doq", "tcp", ""} {
		tr, err := transport.New(config.UpstreamConfig{
			ID:        "test",
			Name:      "Test upstream",
			Transport: name,
			Address:   "1.1.1.1:53",
			Enabled:   true,
		})
		if err == nil {
			t.Errorf("New(transport %q) = nil error, want unsupported transport error", name)
		}
		if tr != nil {
			t.Errorf("New(transport %q) = %T, want nil", name, tr)
		}
	}
}
