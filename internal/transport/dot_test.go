package transport_test

import (
	"context"
	"crypto/tls"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/tlscert"
	"mydns/internal/transport"
)

// testDomain is the name the fake DoT server's certificate is issued
// for and the SNI the transport is expected to send.
const testDomain = "dns.example.com"

// selfSigned returns a self-signed certificate for testDomain.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()

	store, err := tlscert.New(config.TLS{Mode: "self-signed"}, testDomain)
	if err != nil {
		t.Fatalf("tlscert.New() = %v, want nil", err)
	}
	cert, err := store.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate() = %v, want nil", err)
	}
	return *cert
}

// newFakeDoT starts a fake DoT upstream answering with aRecord and a
// DoT transport pointed at it; both are closed when the test ends.
func newFakeDoT(t *testing.T, insecure bool) (transport.Transport, *dnsfake.Fake) {
	t.Helper()

	fake, err := dnsfake.NewTLS(selfSigned(t))
	if err != nil {
		t.Fatalf("dnsfake.NewTLS() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)
	fake.SetHandler(func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, aRecord(req.Question[0].Name))
		return m
	})

	tr, err := transport.New(config.UpstreamConfig{
		ID:                 "test",
		Name:               "Test upstream",
		Transport:          "dot",
		Address:            fake.Addr(),
		ServerName:         testDomain,
		InsecureSkipVerify: insecure,
		Enabled:            true,
	})
	if err != nil {
		t.Fatalf("transport.New(dot) = %v, want nil", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	return tr, fake
}

// TestDoTExchange checks the happy path over TLS: one query, one full
// NOERROR reply, the configured SNI in the handshake and the "dot"
// ALPN protocol offered.
func TestDoTExchange(t *testing.T) {
	tr, fake := newFakeDoT(t, true)

	if got := tr.Name(); got != "dot" {
		t.Errorf("Name() = %q, want %q", got, "dot")
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
	if got := fake.Calls(); got != 1 {
		t.Errorf("fake.Calls() = %d, want 1", got)
	}

	hello := fake.LastHello()
	if hello == nil {
		t.Fatalf("fake.LastHello() = nil, want the handshake's ClientHello")
	}
	if hello.ServerName != testDomain {
		t.Errorf("ClientHello ServerName = %q, want %q", hello.ServerName, testDomain)
	}
	if !slices.Contains(hello.ALPN, "dot") {
		t.Errorf("ClientHello ALPN = %v, want it to contain %q", hello.ALPN, "dot")
	}
}

// TestDoTUntrustedCertFails checks that a self-signed certificate is
// rejected when the transport does not skip verification: the error
// must come from the handshake, with no message.
func TestDoTUntrustedCertFails(t *testing.T) {
	tr, _ := newFakeDoT(t, false)

	resp, err := tr.Exchange(context.Background(), newQuery("example.com"))
	if err == nil {
		t.Fatalf("Exchange() = nil error, want certificate verification error")
	}
	if resp != nil {
		t.Errorf("Exchange() returned a message, want nil")
	}
}
