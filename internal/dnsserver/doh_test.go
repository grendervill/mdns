package dnsserver_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	"mydns/internal/config"
	"mydns/internal/qlog"
)

// newDoHServer builds the pipeline with only DoH enabled on a free
// port.
func newDoHServer(t *testing.T) (int, *qlog.Log) {
	t.Helper()

	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoH: config.Protocol{Enabled: true, Port: port},
	}

	_, _, queryLog := testPipeline(t, cfg, 100)
	return port, queryLog
}

// dohURL builds the DoH endpoint URL for the test server.
func dohURL(port int, path string) string {
	return fmt.Sprintf("https://127.0.0.1:%d%s", port, path)
}

// newDoHClient builds an HTTP client that trusts the test server's
// self-signed certificate and attempts HTTP/2.
func newDoHClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
}

// postQuery sends packed as a DoH POST with the given content type.
func postQuery(t *testing.T, cl *http.Client, port int, packed []byte, contentType string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, dohURL(port, "/dns-query"), bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("NewRequest() = %v, want nil", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("Do() = %v, want nil", err)
	}
	return resp
}

// readDoHBody decodes a DoH response body into a dns.Msg.
func readDoHBody(t *testing.T, resp *http.Response) *dns.Msg {
	t.Helper()

	if got := resp.Header.Get("Content-Type"); got != "application/dns-message" {
		t.Errorf("response Content-Type = %q, want application/dns-message", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(body) = %v, want nil", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		t.Fatalf("Unpack(body) = %v, want nil", err)
	}
	return m
}

// TestDoHPost checks the happy path: a POST of the wire format over
// HTTP/2 gets the wire format back.
func TestDoHPost(t *testing.T) {
	port, _ := newDoHServer(t)
	cl := newDoHClient()

	packed, err := query("example.com").Pack()
	if err != nil {
		t.Fatalf("Pack() = %v, want nil", err)
	}

	resp := postQuery(t, cl, port, packed, "application/dns-message")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("ProtoMajor = %d, want 2 (HTTP/2)", resp.ProtoMajor)
	}

	m := readDoHBody(t, resp)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("reply = rcode %d with %d answers, want NOERROR with 1", m.Rcode, len(m.Answer))
	}
}

// TestDoHGetBase64URL checks the RFC 8484 GET form: the query travels
// as base64url without padding in the ?dns= parameter.
func TestDoHGetBase64URL(t *testing.T) {
	port, _ := newDoHServer(t)
	cl := newDoHClient()

	packed, err := query("example.com").Pack()
	if err != nil {
		t.Fatalf("Pack() = %v, want nil", err)
	}
	param := base64.RawURLEncoding.EncodeToString(packed) // no padding

	resp, err := cl.Get(dohURL(port, "/dns-query?dns="+param))
	if err != nil {
		t.Fatalf("Get() = %v, want nil", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	m := readDoHBody(t, resp)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("reply = rcode %d with %d answers, want NOERROR with 1", m.Rcode, len(m.Answer))
	}
}

// TestDoHBadContentType checks that a POST without the DNS media type
// is rejected with 415.
func TestDoHBadContentType(t *testing.T) {
	port, _ := newDoHServer(t)
	cl := newDoHClient()

	packed, _ := query("example.com").Pack()
	resp := postQuery(t, cl, port, packed, "text/plain")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
}

// TestDoHTooLarge checks that an oversized POST body is rejected with
// 413, not read into memory.
func TestDoHTooLarge(t *testing.T) {
	port, _ := newDoHServer(t)
	cl := newDoHClient()

	resp := postQuery(t, cl, port, make([]byte, 70<<10), "application/dns-message")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

// TestDoHUnknownPath checks that other paths are 404 for now; the web
// panel will take them over in a later plan.
func TestDoHUnknownPath(t *testing.T) {
	port, _ := newDoHServer(t)
	cl := newDoHClient()

	resp, err := cl.Get(dohURL(port, "/somewhere"))
	if err != nil {
		t.Fatalf("Get() = %v, want nil", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestDoHHTTP3 checks the same POST over HTTP/3.
func TestDoHHTTP3(t *testing.T) {
	port, _ := newDoHServer(t)

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer rt.Close()
	cl := &http.Client{Transport: rt, Timeout: 3 * time.Second}

	packed, err := query("example.com").Pack()
	if err != nil {
		t.Fatalf("Pack() = %v, want nil", err)
	}

	resp := postQuery(t, cl, port, packed, "application/dns-message")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.ProtoMajor != 3 {
		t.Errorf("ProtoMajor = %d, want 3 (HTTP/3)", resp.ProtoMajor)
	}
	m := readDoHBody(t, resp)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("reply = rcode %d with %d answers, want NOERROR with 1", m.Rcode, len(m.Answer))
	}
}
