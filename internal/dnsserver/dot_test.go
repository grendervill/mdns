package dnsserver_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/qlog"
)

// newDoTServer builds the pipeline with only DoT enabled on a free
// port.
func newDoTServer(t *testing.T) (int, *qlog.Log) {
	t.Helper()

	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoT: config.Protocol{Enabled: true, Port: port},
	}

	_, _, queryLog := testPipeline(t, cfg, 100)
	return port, queryLog
}

// TestDoT checks one query over DNS-over-TLS: a NOERROR reply through
// the fake upstream and a log entry marked "dot".
func TestDoT(t *testing.T) {
	port, queryLog := newDoTServer(t)

	cl := &dns.Client{
		Net:     "tcp-tls",
		Timeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // self-signed test certificate
			NextProtos:         []string{"dot"},
		},
	}
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

	recent := queryLog.Recent(1)
	if len(recent) != 1 || recent[0].Proto != "dot" {
		t.Errorf("log entry = %+v, want one with proto dot", recent)
	}
}
