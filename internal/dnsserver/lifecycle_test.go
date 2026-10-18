package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/qlog"
	"mydns/internal/ratelimit"
	"mydns/internal/routing"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/tlscert"
	"mydns/internal/upstream"
)

// fakeSource is a tlscert.Source whose readiness and ACME ALPN flag the
// tests control, so the deferred TLS lifecycle can be driven directly.
type fakeSource struct {
	mu       sync.Mutex
	ready    bool
	acmeALPN bool
	cert     *tls.Certificate
}

// newFakeSource builds a source holding a real self-signed certificate,
// reporting ready as asked.
func newFakeSource(t *testing.T, ready bool) *fakeSource {
	t.Helper()

	store, err := tlscert.New(config.TLS{Mode: "self-signed"}, "mdns.test")
	if err != nil {
		t.Fatalf("tlscert.New() = %v, want nil", err)
	}
	cert, err := store.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate() = %v, want nil", err)
	}
	return &fakeSource{ready: ready, cert: cert}
}

func (f *fakeSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ready {
		// An ACME manager without a certificate fails the handshake,
		// which is what the eagerly started DoH listener must survive.
		return nil, errors.New("no certificate yet")
	}
	return f.cert, nil
}

func (f *fakeSource) Ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ready
}

// SetReady flips the readiness the server observes.
func (f *fakeSource) SetReady(ready bool) {
	f.mu.Lock()
	f.ready = ready
	f.mu.Unlock()
}

func (f *fakeSource) ACMEALPN() bool { return f.acmeALPN }

func (f *fakeSource) Status() tlscert.Status {
	return tlscert.Status{Mode: "self-signed", State: "ok"}
}

// syncBuffer collects log output written from listener goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// dnsPortMin and dnsPortMax bound the dnsserver tests' port pool. The
// range sits below the OS ephemeral pool (Linux starts at 32768, macOS
// at 49152), so the kernel never hands one of these ports to an
// outbound socket — which is what used to steal a port between freePort
// and the server's bind. The range is disjoint from the app tests' pool
// so the two packages can run side by side under `go test ./...`.
const (
	dnsPortMin = 26000
	dnsPortMax = 31999
)

// portCursor spreads successive allocations across the pool.
var portCursor atomic.Int64

// takenPorts records the ports handed out so far: a test that takes
// several ports before binding any server still gets distinct ones.
var takenPorts = struct {
	sync.Mutex
	taken map[int]bool
}{taken: make(map[int]bool)}

// freePort returns a port free for both TCP and UDP on the wildcard
// address and not yet handed out in this process. Each candidate is
// probed several times in a row, and a port the kernel would hand to an
// outbound socket is never a candidate, so the bind the test performs
// right after does not race.
func freePort(t *testing.T) int {
	t.Helper()

	const rounds = 4
	span := int64(dnsPortMax - dnsPortMin + 1)

	start := dnsPortMin + int(portCursor.Add(1)*7919%span)
	for i := 0; i < int(span); i++ {
		port := dnsPortMin + (start-dnsPortMin+i)%int(span)
		if !takePort(port) {
			continue
		}
		if dnsPortFree(port, rounds) {
			return port
		}
		releasePort(port)
	}
	t.Fatalf("freePort: no free port in %d..%d", dnsPortMin, dnsPortMax)
	return 0
}

// takePort reserves port, reporting false when it is already taken.
func takePort(port int) bool {
	takenPorts.Lock()
	defer takenPorts.Unlock()
	if takenPorts.taken[port] {
		return false
	}
	takenPorts.taken[port] = true
	return true
}

// releasePort gives a reserved port back after a failed probe.
func releasePort(port int) {
	takenPorts.Lock()
	defer takenPorts.Unlock()
	delete(takenPorts.taken, port)
}

// dnsPortFree reports whether port binds for both TCP and UDP on the
// wildcard address, rounds times in a row.
func dnsPortFree(port, rounds int) bool {
	addr := ":" + strconv.Itoa(port)
	for i := 0; i < rounds; i++ {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			_ = ln.Close()
			return false
		}
		_ = pc.Close()
		_ = ln.Close()
	}
	return true
}

// loopback builds the loopback address for port.
func loopback(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// queryMsg builds a single-question A query.
func queryMsg(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// pipeline builds a server over a fake upstream, leaving Start to the
// test so it can drive the TLS lifecycle itself.
func pipeline(t *testing.T, cfg *config.Config, certs tlscert.Source, logger *slog.Logger) (*Server, *dnsfake.Fake) {
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
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		})
		return m
	})

	u, err := upstream.New(config.UpstreamConfig{
		ID: "fake", Name: "fake", Transport: "plain", Address: fake.Addr(), Enabled: true,
	})
	if err != nil {
		t.Fatalf("upstream.New() = %v, want nil", err)
	}
	limiter, err := ratelimit.New(100, nil, nil)
	if err != nil {
		t.Fatalf("ratelimit.New() = %v, want nil", err)
	}
	router, err := routing.New([]*upstream.Upstream{u}, cfg.Strategy)
	if err != nil {
		t.Fatalf("routing.New() = %v, want nil", err)
	}
	queryLog, err := qlog.New(100, "", 0)
	if err != nil {
		t.Fatalf("qlog.New() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = queryLog.Close() })

	c := core.New(router, cache.New(100, 0, 86400), queryLog, nil, "zero", nil)
	return New(cfg, c, certs, limiter, logger), fake
}

// start runs Start and registers the Shutdown cleanup.
func start(t *testing.T, srv *Server) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
	})
}

// dotQuery sends one query over DNS-over-TLS.
func dotQuery(t *testing.T, port int) *dns.Msg {
	t.Helper()

	cl := &dns.Client{
		Net:     "tcp-tls",
		Timeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // self-signed test certificate
			NextProtos:         []string{"dot"},
		},
	}
	resp, _, err := cl.Exchange(queryMsg("example.com"), loopback(port))
	if err != nil {
		t.Fatalf("Exchange(dot :%d) = %v, want nil", port, err)
	}
	return resp
}

// dohClient builds an HTTP client that trusts the test certificate.
func dohClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
}

// wantClosed fails when port accepts a TCP connection.
func wantClosed(t *testing.T, port int, after string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", loopback(port), 300*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Errorf("dial :%d = nil, want the port closed %s", port, after)
	}
}

// TestDeferredTLSStart checks that a source without a certificate lets
// the plain listener run alone: Start serves plain DNS and leaves the
// TLS ports closed until StartTLS brings them up.
func TestDeferredTLSStart(t *testing.T) {
	plainPort, dohPort, dotPort := freePort(t), freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: plainPort},
		DoH:   config.Protocol{Enabled: true, Port: dohPort},
		DoT:   config.Protocol{Enabled: true, Port: dotPort},
	}

	certs := newFakeSource(t, false)
	logs := &syncBuffer{}
	srv, _ := pipeline(t, cfg, certs, slog.New(slog.NewTextHandler(logs, nil)))
	start(t, srv)

	// Plain DNS answers while the certificate is still missing.
	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	resp, _, err := cl.Exchange(queryMsg("example.com"), loopback(plainPort))
	if err != nil {
		t.Fatalf("Exchange(plain) = %v, want nil", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("plain reply = rcode %d with %d answers, want NOERROR with 1", resp.Rcode, len(resp.Answer))
	}

	if srv.TLSStarted() {
		t.Error("TLSStarted() = true after Start with an unready source, want false")
	}
	wantClosed(t, dotPort, "before StartTLS")
	wantClosed(t, dohPort, "before StartTLS")
	if !strings.Contains(logs.String(), "TLS listeners waiting for the certificate") {
		t.Errorf("log = %q, want the deferred-TLS notice", logs.String())
	}

	// Starting TLS without a usable certificate fails without binding.
	if err := srv.StartTLS(); err == nil {
		t.Error("StartTLS() with an unready source = nil, want an error")
	}
	if srv.TLSStarted() {
		t.Error("TLSStarted() = true after a rejected StartTLS, want false")
	}

	// Once the certificate arrives, StartTLS brings the TLS listeners up.
	certs.SetReady(true)
	if err := srv.StartTLS(); err != nil {
		t.Fatalf("StartTLS() = %v, want nil", err)
	}
	if !srv.TLSStarted() {
		t.Error("TLSStarted() = false after StartTLS, want true")
	}

	resp = dotQuery(t, dotPort)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("DoT reply = rcode %d with %d answers, want NOERROR with 1", resp.Rcode, len(resp.Answer))
	}

	hresp, err := dohClient().Get(fmt.Sprintf("https://127.0.0.1:%d/dns-query", dohPort))
	if err != nil {
		t.Fatalf("DoH GET = %v, want nil (the HTTPS listener must be up)", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusBadRequest {
		t.Errorf("DoH GET without ?dns= = %d, want 400 (the listener answered over TLS)", hresp.StatusCode)
	}
}

// TestStartTLSIdempotent checks that repeated StartTLS calls do not
// bind the TLS listeners twice or disturb the running ones.
func TestStartTLSIdempotent(t *testing.T) {
	plainPort, dotPort := freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: plainPort},
		DoT:   config.Protocol{Enabled: true, Port: dotPort},
	}

	certs := newFakeSource(t, true)
	srv, _ := pipeline(t, cfg, certs, nil)
	start(t, srv)

	if !srv.TLSStarted() {
		t.Fatal("TLSStarted() = false after Start with a ready source, want true")
	}
	for i := 1; i <= 3; i++ {
		if err := srv.StartTLS(); err != nil {
			t.Fatalf("StartTLS() #%d = %v, want nil", i, err)
		}
	}

	want := []string{
		fmt.Sprintf("plain:%d", plainPort),
		fmt.Sprintf("dot:%d", dotPort),
	}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() = %v, want %v (no duplicate listeners)", got, want)
	}

	// The single DoT listener survived the repeated calls.
	resp := dotQuery(t, dotPort)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("DoT reply = rcode %d with %d answers, want NOERROR with 1", resp.Rcode, len(resp.Answer))
	}
}

// TestListenersReflectsStart checks that Listeners reports what is
// actually bound: the enabled plain listener after Start and the TLS
// trio only after StartTLS.
func TestListenersReflectsStart(t *testing.T) {
	plainPort, dohPort, dotPort, doqPort := freePort(t), freePort(t), freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: plainPort},
		DoH:   config.Protocol{Enabled: true, Port: dohPort},
		DoT:   config.Protocol{Enabled: true, Port: dotPort},
		DoQ:   config.Protocol{Enabled: true, Port: doqPort},
	}

	certs := newFakeSource(t, false)
	srv, _ := pipeline(t, cfg, certs, nil)

	if got := srv.Listeners(); len(got) != 0 {
		t.Errorf("Listeners() before Start = %v, want none", got)
	}

	start(t, srv)

	want := []string{fmt.Sprintf("plain:%d", plainPort)}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() after Start = %v, want %v", got, want)
	}

	certs.SetReady(true)
	if err := srv.StartTLS(); err != nil {
		t.Fatalf("StartTLS() = %v, want nil", err)
	}

	want = []string{
		fmt.Sprintf("plain:%d", plainPort),
		fmt.Sprintf("doh:%d", dohPort),
		fmt.Sprintf("dot:%d", dotPort),
		fmt.Sprintf("doq:%d", doqPort),
	}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() after StartTLS = %v, want %v", got, want)
	}
}

// TestChallengeHTTP01 checks the ACME HTTP-01 responder: it serves the
// challenge handler on its own plain HTTP port, independently of the
// DNS listeners, and releases the port on stop.
func TestChallengeHTTP01(t *testing.T) {
	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"

	srv, _ := pipeline(t, cfg, newFakeSource(t, false), nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/acme-challenge/x" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "challenge-token")
	})
	if err := srv.StartChallengeHTTP(handler, port); err != nil {
		t.Fatalf("StartChallengeHTTP() = %v, want nil", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.StopChallengeHTTP(ctx)
	})

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/x", port))
	if err != nil {
		t.Fatalf("GET challenge = %v, want nil", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(body) = %v, want nil", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "challenge-token" {
		t.Errorf("challenge response = %d %q, want 200 %q", resp.StatusCode, body, "challenge-token")
	}

	// The responder lives on its own, with no DNS listener started.
	if got := srv.Listeners(); len(got) != 0 {
		t.Errorf("Listeners() = %v, want none (the challenge responder is not a DNS listener)", got)
	}
	if err := srv.StartChallengeHTTP(handler, port); err == nil {
		t.Error("second StartChallengeHTTP() = nil, want an error (already running)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.StopChallengeHTTP(ctx); err != nil {
		t.Fatalf("StopChallengeHTTP() = %v, want nil", err)
	}
	wantClosed(t, port, "after StopChallengeHTTP")

	// Stopping again is a no-op.
	if err := srv.StopChallengeHTTP(ctx); err != nil {
		t.Errorf("second StopChallengeHTTP() = %v, want nil", err)
	}
}

// TestStartTLSRollbackKeepsEagerDoH checks that a failed StartTLS
// rolls back only the listeners that call started: the eagerly
// started DoH listener stays up for later TLS-ALPN challenges.
func TestStartTLSRollbackKeepsEagerDoH(t *testing.T) {
	dohPort, dotPort := freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoH: config.Protocol{Enabled: true, Port: dohPort},
		DoT: config.Protocol{Enabled: true, Port: dotPort},
	}

	certs := newFakeSource(t, false)
	certs.acmeALPN = true
	srv, _ := pipeline(t, cfg, certs, nil)
	srv.alpnPort = dohPort
	start(t, srv)

	// Hold the DoT port so the first listener StartTLS adds cannot bind.
	holder, err := net.Listen("tcp", fmt.Sprintf(":%d", dotPort))
	if err != nil {
		t.Fatalf("Listen(hold :%d) = %v, want nil", dotPort, err)
	}
	defer holder.Close()

	certs.SetReady(true)
	if err := srv.StartTLS(); err == nil {
		t.Fatal("StartTLS() with the DoT port taken = nil, want an error")
	}

	want := []string{fmt.Sprintf("doh:%d", dohPort)}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() after a failed StartTLS = %v, want %v (the eager DoH listener survives)", got, want)
	}
	// The listener still answers over TLS now that a certificate exists.
	hresp, err := dohClient().Get(fmt.Sprintf("https://127.0.0.1:%d/dns-query", dohPort))
	if err != nil {
		t.Fatalf("DoH GET = %v, want nil (the eager listener must still be serving)", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusBadRequest {
		t.Errorf("DoH GET without ?dns= = %d, want 400", hresp.StatusCode)
	}

	// Freeing the port lets the retry complete the group.
	if err := holder.Close(); err != nil {
		t.Fatalf("Close(holder) = %v, want nil", err)
	}
	if err := srv.StartTLS(); err != nil {
		t.Fatalf("StartTLS() retry = %v, want nil", err)
	}
	want = append(want, fmt.Sprintf("dot:%d", dotPort))
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() after the retry = %v, want %v", got, want)
	}
}

// TestStartTLSPartialFailureRollsBack checks that a TLS bind failure
// leaves no half-started TLS listeners behind: the failed group reports
// down and the port it did bind is released for a later retry.
func TestStartTLSPartialFailureRollsBack(t *testing.T) {
	dotPort, dohPort := freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoT: config.Protocol{Enabled: true, Port: dotPort},
		DoH: config.Protocol{Enabled: true, Port: dohPort},
	}

	certs := newFakeSource(t, false)
	srv, _ := pipeline(t, cfg, certs, nil)
	start(t, srv)

	// Hold the DoH port so the second TLS listener cannot bind.
	holder, err := net.Listen("tcp", fmt.Sprintf(":%d", dohPort))
	if err != nil {
		t.Fatalf("Listen(hold :%d) = %v, want nil", dohPort, err)
	}
	defer holder.Close()

	certs.SetReady(true)
	if err := srv.StartTLS(); err == nil {
		t.Fatal("StartTLS() with the DoH port taken = nil, want an error")
	}
	if srv.TLSStarted() {
		t.Error("TLSStarted() = true after a failed StartTLS, want false")
	}
	wantClosed(t, dotPort, "after a rolled-back StartTLS")

	// Freeing the port lets a retry start the whole trio.
	if err := holder.Close(); err != nil {
		t.Fatalf("Close(holder) = %v, want nil", err)
	}
	if err := srv.StartTLS(); err != nil {
		t.Fatalf("StartTLS() retry = %v, want nil", err)
	}
	if !srv.TLSStarted() {
		t.Error("TLSStarted() = false after the retry, want true")
	}
	if resp := dotQuery(t, dotPort); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("DoT reply rcode = %d, want NOERROR", resp.Rcode)
	}
}

// TestShutdownAfterStartNeverLeaksPort pins the dns.Server lifecycle
// race deterministically: Start must return only once the listener is
// actually serving, so an immediate Shutdown cannot see "server not
// started" and leave the listener — and its port — bound. On the old
// code (go s.serve) the serve goroutine often had not set miekg/dns's
// started flag yet, Shutdown refused to close the listener, and the
// next iteration's bind failed with "address already in use".
func TestShutdownAfterStartNeverLeaksPort(t *testing.T) {
	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: port},
	}

	const iterations = 100
	for i := 0; i < iterations; i++ {
		srv, _ := pipeline(t, cfg, newFakeSource(t, true), nil)

		ctx, cancel := context.WithCancel(context.Background())
		if err := srv.Start(ctx); err != nil {
			cancel()
			t.Fatalf("iteration %d: Start() = %v, want nil", i, err)
		}

		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := srv.Shutdown(sctx)
		scancel()
		cancel()
		if err != nil {
			t.Fatalf("iteration %d: Shutdown() = %v, want nil (a race leaves the listener open)", i, err)
		}

		// Both listeners must be gone: rebind the port right away.
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("iteration %d: rebind tcp %s = %v, want nil (a listener leaked)", i, addr, err)
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			_ = ln.Close()
			t.Fatalf("iteration %d: rebind udp %s = %v, want nil (a listener leaked)", i, addr, err)
		}
		_ = pc.Close()
		_ = ln.Close()
	}
}

// quietStdLog mutes the standard logger for a test that deliberately
// provokes an HTTPS handshake error: net/http reports those through
// log.Default, not through the test's slog logger.
func quietStdLog(t *testing.T) {
	t.Helper()

	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// TestNeedsEagerDoH pins the eager-DoH predicate: only an ACME source
// serving TLS-ALPN challenges on the validation port needs the DoH
// listener before a certificate exists.
func TestNeedsEagerDoH(t *testing.T) {
	acme := &fakeSource{acmeALPN: true}
	plain := newFakeSource(t, true) // ACMEALPN false

	doh := func(enabled bool, port int) *config.Config {
		cfg := config.Default()
		cfg.Protocols = config.Protocols{DoH: config.Protocol{Enabled: enabled, Port: port}}
		return cfg
	}

	tests := []struct {
		name  string
		certs tlscert.Source
		cfg   *config.Config
		port  int
		want  bool
	}{
		{"acme source on the ALPN port", acme, doh(true, 443), 443, true},
		{"acme source on another port", acme, doh(true, 8443), 443, false},
		{"plain source on the ALPN port", plain, doh(true, 443), 443, false},
		{"DoH disabled on the ALPN port", acme, doh(false, 443), 443, false},
		{"no certificate source", nil, doh(true, 443), 443, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsEagerDoH(tc.certs, tc.cfg, tc.port); got != tc.want {
				t.Errorf("needsEagerDoH() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEagerDoHOn443ForACME checks R6: in ACME mode the DoH listener on
// the TLS-ALPN port starts before the certificate exists, so the
// challenge handshake can reach GetCertificate. Normal handshakes fail
// until a certificate is issued, and DoT keeps waiting.
func TestEagerDoHOn443ForACME(t *testing.T) {
	dohPort, dotPort := freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoH: config.Protocol{Enabled: true, Port: dohPort},
		DoT: config.Protocol{Enabled: true, Port: dotPort},
	}

	certs := newFakeSource(t, false)
	certs.acmeALPN = true
	logs := &syncBuffer{}
	srv, _ := pipeline(t, cfg, certs, slog.New(slog.NewTextHandler(logs, nil)))
	srv.alpnPort = dohPort // stands in for 443, which tests cannot bind
	start(t, srv)

	// The DoH listener is up although no certificate exists yet.
	conn, err := net.DialTimeout("tcp", loopback(dohPort), time.Second)
	if err != nil {
		t.Fatalf("dial doh :%d = %v, want the eager listener up", dohPort, err)
	}
	_ = conn.Close()

	quietStdLog(t)
	if conn, err := tls.Dial("tcp", loopback(dohPort), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}); err == nil {
		_ = conn.Close()
		t.Error("tls.Dial(doh) = nil, want a handshake error before the certificate exists")
	}

	// Only the eager listener is up; DoT still waits for the certificate.
	want := []string{fmt.Sprintf("doh:%d", dohPort)}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() = %v, want %v", got, want)
	}
	if srv.TLSStarted() {
		t.Error("TLSStarted() = true, want false (DoT still waits for the certificate)")
	}
	wantClosed(t, dotPort, "before StartTLS")
	if !strings.Contains(logs.String(), "DoH listening for ACME TLS-ALPN-01") {
		t.Errorf("log = %q, want the eager-DoH notice", logs.String())
	}
}

// TestStartTLSStartsOnlyMissing checks R6 from the partial state: with
// DoH already up from the eager start, StartTLS brings up only DoT and
// DoQ and later calls are no-ops.
func TestStartTLSStartsOnlyMissing(t *testing.T) {
	dohPort, dotPort, doqPort := freePort(t), freePort(t), freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoH: config.Protocol{Enabled: true, Port: dohPort},
		DoT: config.Protocol{Enabled: true, Port: dotPort},
		DoQ: config.Protocol{Enabled: true, Port: doqPort},
	}

	certs := newFakeSource(t, false)
	certs.acmeALPN = true
	srv, _ := pipeline(t, cfg, certs, nil)
	srv.alpnPort = dohPort
	start(t, srv)

	want := []string{fmt.Sprintf("doh:%d", dohPort)}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Fatalf("Listeners() after Start = %v, want %v (only the eager DoH listener)", got, want)
	}
	if got := srv.TLSStarted(); got {
		t.Errorf("TLSStarted() after Start = %v, want false", got)
	}

	certs.SetReady(true)
	if err := srv.StartTLS(); err != nil {
		t.Fatalf("StartTLS() = %v, want nil", err)
	}

	want = []string{
		fmt.Sprintf("doh:%d", dohPort),
		fmt.Sprintf("dot:%d", dotPort),
		fmt.Sprintf("doq:%d", doqPort),
	}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() after StartTLS = %v, want %v", got, want)
	}
	if !srv.TLSStarted() {
		t.Error("TLSStarted() = false after StartTLS, want true")
	}

	// The eagerly started DoH listener serves normally now.
	hresp, err := dohClient().Get(fmt.Sprintf("https://127.0.0.1:%d/dns-query", dohPort))
	if err != nil {
		t.Fatalf("DoH GET = %v, want nil (the eager listener must be serving)", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusBadRequest {
		t.Errorf("DoH GET without ?dns= = %d, want 400 (the listener answered over TLS)", hresp.StatusCode)
	}

	// A second call is a no-op: no error and no duplicate listeners.
	if err := srv.StartTLS(); err != nil {
		t.Fatalf("second StartTLS() = %v, want nil", err)
	}
	if got := srv.Listeners(); !slices.Equal(got, want) {
		t.Errorf("Listeners() after the second StartTLS = %v, want %v", got, want)
	}
	if resp := dotQuery(t, dotPort); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("DoT reply rcode = %d, want NOERROR", resp.Rcode)
	}
}

// TestDoHACMETLSALPN checks the RFC 8737 wiring end to end: a source
// that asks for it makes the DoH HTTPS listener negotiate acme-tls/1,
// so a TLS-ALPN-01 challenge reaches GetCertificate.
func TestDoHACMETLSALPN(t *testing.T) {
	port := freePort(t)
	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.Protocols = config.Protocols{
		DoH: config.Protocol{Enabled: true, Port: port},
	}

	certs := newFakeSource(t, true)
	certs.acmeALPN = true
	srv, _ := pipeline(t, cfg, certs, nil)
	start(t, srv)

	conn, err := tls.Dial("tcp", loopback(port), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"acme-tls/1"},
	})
	if err != nil {
		t.Fatalf("Dial(acme-tls/1) = %v, want nil", err)
	}
	defer conn.Close()

	if got := conn.ConnectionState().NegotiatedProtocol; got != "acme-tls/1" {
		t.Errorf("NegotiatedProtocol = %q, want acme-tls/1", got)
	}
}
