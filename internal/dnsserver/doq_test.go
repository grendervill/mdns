package dnsserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/qlog"
	"mydns/internal/transport"
)

// newDoQServer builds the pipeline with only DoQ enabled on a free
// port.
func newDoQServer(t *testing.T) (int, *qlog.Log) {
	t.Helper()

	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoQ: config.Protocol{Enabled: true, Port: port},
	}

	_, _, queryLog := testPipeline(t, cfg, 100)
	return port, queryLog
}

// TestDoQ checks one query over DNS-over-QUIC, using the project's own
// DoQ transport as the client: a NOERROR reply through the fake
// upstream and a log entry marked "doq".
func TestDoQ(t *testing.T) {
	port, queryLog := newDoQServer(t)

	tr, err := transport.New(config.UpstreamConfig{
		ID:                 "test",
		Name:               "test",
		Transport:          "doq",
		Address:            loopback(port),
		ServerName:         "mdns.test",
		InsecureSkipVerify: true, // self-signed test certificate
		Enabled:            true,
	})
	if err != nil {
		t.Fatalf("transport.New(doq) = %v, want nil", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := tr.Exchange(ctx, query("example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(resp.Answer))
	}

	recent := queryLog.Recent(1)
	if len(recent) != 1 || recent[0].Proto != "doq" {
		t.Errorf("log entry = %+v, want one with proto doq", recent)
	}
}
