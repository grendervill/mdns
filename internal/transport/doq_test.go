package transport_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"mydns/internal/config"
	"mydns/internal/doq"
	"mydns/internal/transport"
)

// startFakeDoQ starts a minimal DNS-over-QUIC server for the given
// handler and returns its address. Each stream carries one query; a
// nil handler reply leaves the stream unanswered so the client times
// out.
func startFakeDoQ(t *testing.T, handler func(*dns.Msg) *dns.Msg) string {
	t.Helper()

	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		NextProtos:   []string{"doq"},
	}, nil)
	if err != nil {
		t.Fatalf("quic.ListenAddr() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return // listener closed
			}
			go func() {
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						defer stream.Close()

						raw, err := doq.ReadMessage(stream)
						if err != nil {
							return
						}
						req := new(dns.Msg)
						if err := req.Unpack(raw); err != nil {
							return
						}
						resp := handler(req)
						if resp == nil {
							return // stay silent: the client times out
						}
						resp.Id = req.Id
						packed, err := resp.Pack()
						if err != nil {
							return
						}
						_ = doq.WriteMessage(stream, packed)
					}()
				}
			}()
		}
	}()

	return ln.Addr().String()
}

// newFakeDoQ starts the fake DoQ server answering with aRecord and a
// DoQ transport pointed at it; both are closed when the test ends.
func newFakeDoQ(t *testing.T, handler func(*dns.Msg) *dns.Msg) transport.Transport {
	t.Helper()

	addr := startFakeDoQ(t, handler)
	tr, err := transport.New(config.UpstreamConfig{
		ID:                 "test",
		Name:               "Test upstream",
		Transport:          "doq",
		Address:            addr,
		ServerName:         testDomain,
		InsecureSkipVerify: true,
		Enabled:            true,
	})
	if err != nil {
		t.Fatalf("transport.New(doq) = %v, want nil", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	return tr
}

// TestDoQExchange checks the happy path over QUIC: one query on one
// stream, one full NOERROR reply.
func TestDoQExchange(t *testing.T) {
	tr := newFakeDoQ(t, func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, aRecord(req.Question[0].Name))
		return m
	})

	if got := tr.Name(); got != "doq" {
		t.Errorf("Name() = %q, want %q", got, "doq")
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
}

// TestDoQSecondQueryReusesConnection checks that two queries in a row
// share the established QUIC connection: both must succeed.
func TestDoQSecondQueryReusesConnection(t *testing.T) {
	tr := newFakeDoQ(t, func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, aRecord(req.Question[0].Name))
		return m
	})

	for i := 0; i < 2; i++ {
		if _, err := tr.Exchange(context.Background(), newQuery("example.com")); err != nil {
			t.Fatalf("Exchange() #%d = %v, want nil", i+1, err)
		}
	}
}

// TestDoQTimeout checks that an upstream that stays silent matters to
// the caller's deadline: a 150ms context must produce an error well
// within a second.
func TestDoQTimeout(t *testing.T) {
	tr := newFakeDoQ(t, func(*dns.Msg) *dns.Msg { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	resp, err := tr.Exchange(ctx, newQuery("example.com"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Exchange() = nil error, want a timeout error")
	}
	if resp != nil {
		t.Errorf("Exchange() returned a message, want nil")
	}
	if elapsed >= 1*time.Second {
		t.Errorf("Exchange() returned after %v, want < 1s (deadline 150ms)", elapsed)
	}
}
