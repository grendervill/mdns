package transport_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/transport"
)

// newFakeDoH starts an HTTP/2 test server with handler h and a DoH
// transport pointed at its /dns-query endpoint; both are closed when
// the test ends.
func newFakeDoH(t *testing.T, h http.HandlerFunc) (transport.Transport, *httptest.Server) {
	t.Helper()

	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := transport.New(config.UpstreamConfig{
		ID:                 "test",
		Name:               "Test upstream",
		Transport:          "doh",
		Address:            srv.URL + "/dns-query",
		InsecureSkipVerify: true,
		Enabled:            true,
	})
	if err != nil {
		t.Fatalf("transport.New(doh) = %v, want nil", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	return tr, srv
}

// TestDoHExchange checks the happy path: a POST of the wire-format
// query to the configured path over HTTP/2, answered with a
// wire-format reply.
func TestDoHExchange(t *testing.T) {
	var proto atomic.Int64
	var contentType atomic.Value

	tr, _ := newFakeDoH(t, func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int64(r.ProtoMajor))
		contentType.Store(r.Header.Get("Content-Type"))

		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/dns-query" {
			t.Errorf("path = %s, want /dns-query", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			t.Errorf("unpack query: %v", err)
			http.Error(w, "unpack", http.StatusBadRequest)
			return
		}

		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, aRecord(req.Question[0].Name))
		packed, err := m.Pack()
		if err != nil {
			t.Errorf("pack reply: %v", err)
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	})

	if got := tr.Name(); got != "doh" {
		t.Errorf("Name() = %q, want %q", got, "doh")
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
	if got := proto.Load(); got != 2 {
		t.Errorf("request ProtoMajor = %d, want 2 (HTTP/2)", got)
	}
	if got, _ := contentType.Load().(string); got != "application/dns-message" {
		t.Errorf("request Content-Type = %q, want application/dns-message", got)
	}
}

// TestDoHServerError checks that a non-200 status becomes an error with
// no message.
func TestDoHServerError(t *testing.T) {
	tr, _ := newFakeDoH(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	resp, err := tr.Exchange(context.Background(), newQuery("example.com"))
	if err == nil {
		t.Fatalf("Exchange() = nil error, want status error")
	}
	if resp != nil {
		t.Errorf("Exchange() returned a message, want nil")
	}
}

// TestDoHBadResponseContentType checks that a reply without the DNS
// media type is rejected.
func TestDoHBadResponseContentType(t *testing.T) {
	tr, _ := newFakeDoH(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>wrong</html>"))
	})

	resp, err := tr.Exchange(context.Background(), newQuery("example.com"))
	if err == nil {
		t.Fatalf("Exchange() = nil error, want content type error")
	}
	if resp != nil {
		t.Errorf("Exchange() returned a message, want nil")
	}
}
