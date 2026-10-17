package acmecert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mydns/internal/tlscert"
)

// discardLogger returns a logger that drops everything.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// getterFunc adapts a function to the getter seam.
type getterFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)

func (f getterFunc) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return f(hello)
}

// testCertificate returns a certificate whose leaf is issued by
// "Test ACME CA" and expires at notAfter.
func testCertificate(t *testing.T, notAfter time.Time) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() = %v, want nil", err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() = %v, want nil", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test ACME CA"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() = %v, want nil", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() = %v, want nil", err)
	}

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// closed reports whether ch is already closed.
func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestParseEAB(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	encodings := map[string]string{
		"base64url without padding": base64.RawURLEncoding.EncodeToString(key),
		"base64url with padding":    base64.URLEncoding.EncodeToString(key),
		"base64 without padding":    base64.RawStdEncoding.EncodeToString(key),
		"base64 with padding":       base64.StdEncoding.EncodeToString(key),
	}
	for name, encoded := range encodings {
		t.Run(name, func(t *testing.T) {
			eab, err := ParseEAB("kid-1", encoded)
			if err != nil {
				t.Fatalf("ParseEAB(kid-1, %q) = %v, want nil", encoded, err)
			}
			if eab.KID != "kid-1" {
				t.Errorf("KID = %q, want %q", eab.KID, "kid-1")
			}
			if !bytes.Equal(eab.Key, key) {
				t.Errorf("Key = %x, want %x", eab.Key, key)
			}
		})
	}

	t.Run("surrounding whitespace", func(t *testing.T) {
		eab, err := ParseEAB(" kid-1 ", " "+base64.RawURLEncoding.EncodeToString(key)+"\n")
		if err != nil {
			t.Fatalf("ParseEAB() = %v, want nil", err)
		}
		if eab.KID != "kid-1" || !bytes.Equal(eab.Key, key) {
			t.Errorf("ParseEAB() = {KID: %q, Key: %x}, want {kid-1, %x}", eab.KID, eab.Key, key)
		}
	})

	bad := []struct {
		name string
		kid  string
		hmac string
	}{
		{"empty kid", "", base64.RawURLEncoding.EncodeToString(key)},
		{"whitespace kid", "  ", base64.RawURLEncoding.EncodeToString(key)},
		{"empty hmac", "kid-1", ""},
		{"garbage hmac", "kid-1", "!!not base64!!"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseEAB(tc.kid, tc.hmac); err == nil {
				t.Errorf("ParseEAB(%q, %q) = nil error, want an error", tc.kid, tc.hmac)
			}
		})
	}
}

func TestManagerStatusTransitions(t *testing.T) {
	notAfter := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	cert := testCertificate(t, notAfter)

	var fail atomic.Bool
	fail.Store(true)
	g := getterFunc(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if fail.Load() {
			return nil, errors.New("acme: no certificate yet")
		}
		return cert, nil
	})

	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m, err := newWithGetter(g, Options{Domain: "example.com", CacheDir: t.TempDir(), Logger: discardLogger()}, func() time.Time { return at })
	if err != nil {
		t.Fatalf("newWithGetter() = %v, want nil", err)
	}

	got := m.Status()
	if got.Mode != "acme" || got.State != "waiting" {
		t.Errorf("Status() = {Mode: %q, State: %q}, want {acme, waiting}", got.Mode, got.State)
	}
	if !got.LastCheck.IsZero() {
		t.Errorf("LastCheck = %v, want the zero time before the first check", got.LastCheck)
	}
	if m.Ready() {
		t.Error("Ready() = true before the first certificate, want false")
	}
	if closed(m.ReadyChan()) {
		t.Error("ReadyChan() is closed before the first certificate, want open")
	}

	// A failing getter reports the error and keeps the source unready.
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Fatal("GetCertificate() = nil error, want the getter error")
	}
	got = m.Status()
	if got.Mode != "acme" || got.State != "error" {
		t.Errorf("Status() = {Mode: %q, State: %q}, want {acme, error}", got.Mode, got.State)
	}
	if got.Error != "acme: no certificate yet" {
		t.Errorf("Error = %q, want %q", got.Error, "acme: no certificate yet")
	}
	if !got.LastCheck.Equal(at) {
		t.Errorf("LastCheck = %v, want %v", got.LastCheck, at)
	}
	if m.Ready() {
		t.Error("Ready() = true after a failure, want false")
	}
	if closed(m.ReadyChan()) {
		t.Error("ReadyChan() is closed after a failure, want open")
	}

	// A successful getter reports the certificate and closes ReadyChan.
	at = at.Add(time.Minute)
	fail.Store(false)
	gotCert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate() = %v, want nil", err)
	}
	if gotCert != cert {
		t.Error("GetCertificate() did not return the certificate from the source")
	}
	got = m.Status()
	if got.Mode != "acme" || got.State != "ok" {
		t.Errorf("Status() = {Mode: %q, State: %q}, want {acme, ok}", got.Mode, got.State)
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty after a success", got.Error)
	}
	if got.Issuer != "Test ACME CA" {
		t.Errorf("Issuer = %q, want %q", got.Issuer, "Test ACME CA")
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, notAfter)
	}
	if !got.LastCheck.Equal(at) {
		t.Errorf("LastCheck = %v, want %v", got.LastCheck, at)
	}
	if !m.Ready() {
		t.Error("Ready() = false after a certificate, want true")
	}
	if !closed(m.ReadyChan()) {
		t.Error("ReadyChan() is open after a certificate, want closed")
	}

	// A second success must not close ReadyChan twice.
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err != nil {
		t.Fatalf("GetCertificate() = %v, want nil", err)
	}
	if !m.Ready() || !closed(m.ReadyChan()) {
		t.Error("Ready()/ReadyChan() changed after the second certificate")
	}
}

func TestBackoffSchedule(t *testing.T) {
	const min, max = 5 * time.Minute, 6 * time.Hour

	schedule := []time.Duration{
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		80 * time.Minute,
		160 * time.Minute,
		320 * time.Minute,
		6 * time.Hour,
		6 * time.Hour,
		6 * time.Hour,
	}
	for attempt, want := range schedule {
		if got := backoffFor(attempt, min, max, 0.5); got != want {
			t.Errorf("backoffFor(%d, 5m, 6h, 0.5) = %v, want %v", attempt, got, want)
		}
	}

	// The jitter stays within ±20% of the capped backoff.
	for _, rnd := range []float64{0, 0.1, 0.25, 0.75, 0.9, 1} {
		for attempt := range schedule {
			base := min << attempt
			if base <= 0 || base > max {
				base = max
			}
			got := backoffFor(attempt, min, max, rnd)
			lo, hi := base-base/5, base+base/5
			if got < lo || got > hi {
				t.Errorf("backoffFor(%d, 5m, 6h, %v) = %v, want within [%v, %v]", attempt, rnd, got, lo, hi)
			}
		}
	}

	// Zero options fall back to the defaults.
	if got := backoffFor(0, 0, 0, 0.5); got != 5*time.Minute {
		t.Errorf("backoffFor(0, 0, 0, 0.5) = %v, want 5m", got)
	}
	if got := backoffFor(20, 0, 0, 0.5); got != 6*time.Hour {
		t.Errorf("backoffFor(20, 0, 0, 0.5) = %v, want 6h", got)
	}

	// A minimum above the maximum is capped as well.
	if got := backoffFor(0, 10*time.Hour, 6*time.Hour, 0.5); got != 6*time.Hour {
		t.Errorf("backoffFor(0, 10h, 6h, 0.5) = %v, want 6h", got)
	}
}

func TestRunRetriesUntilSuccess(t *testing.T) {
	cert := testCertificate(t, time.Now().Add(90*24*time.Hour))

	var calls atomic.Int32
	g := getterFunc(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if n := calls.Add(1); n <= 2 {
			return nil, fmt.Errorf("acme: attempt %d failed", n)
		}
		return cert, nil
	})

	m, err := newWithGetter(g, Options{
		Domain:     "example.com",
		CacheDir:   t.TempDir(),
		Logger:     discardLogger(),
		BackoffMin: time.Millisecond,
		BackoffMax: 4 * time.Millisecond,
	}, time.Now)
	if err != nil {
		t.Fatalf("newWithGetter() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var states []tlscert.Status
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx, func(st tlscert.Status) {
			mu.Lock()
			defer mu.Unlock()
			states = append(states, st)
		})
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(states)
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}

	mu.Lock()
	collected := append([]tlscert.Status(nil), states...)
	mu.Unlock()
	if len(collected) != 3 {
		t.Fatalf("onState called %d times (%v), want 3 (error, error, ok)", len(collected), collected)
	}
	if collected[0].State != "error" || collected[1].State != "error" {
		t.Errorf("states = [%q %q], want [error error] for the two failures", collected[0].State, collected[1].State)
	}
	last := collected[2]
	if last.State != "ok" {
		t.Errorf("last state = %q, want ok", last.State)
	}
	if last.Issuer != "Test ACME CA" || last.NotAfter.IsZero() {
		t.Errorf("last state = {Issuer: %q, NotAfter: %v}, want the issued certificate", last.Issuer, last.NotAfter)
	}
	if !last.LastCheck.After(collected[0].LastCheck) {
		t.Error("LastCheck did not advance between attempts")
	}

	// After the success Run sleeps for a day: no further fetch happens.
	if got := calls.Load(); got != 3 {
		t.Errorf("getter called %d times, want 3 (a daily check does not run in the test)", got)
	}
	if !m.Ready() {
		t.Error("Ready() = false after the successful attempt, want true")
	}
	if !closed(m.ReadyChan()) {
		t.Error("ReadyChan() is open after the successful attempt, want closed")
	}

	// Cancelling the context ends the daily sleep.
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(states) != 3 {
		t.Errorf("onState called %d times after the cancellation, want 3", len(states))
	}
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("New(Options{}) = nil error, want an error about the missing domain")
	}
	if _, err := New(Options{Domain: "example.com"}); err == nil {
		t.Error("New(Options{Domain: example.com}) = nil error, want an error about the missing cache directory")
	}

	m, err := New(Options{Domain: "example.com", Email: "admin@example.com", CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
	if m.HTTPHandler() == nil {
		t.Error("HTTPHandler() = nil, want the autocert http-01 handler")
	}
	if !m.ACMEALPN() {
		t.Error("ACMEALPN() = false, want true")
	}
	if got := m.Status(); got.Mode != "acme" || got.State != "waiting" {
		t.Errorf("Status() = {Mode: %q, State: %q}, want {acme, waiting}", got.Mode, got.State)
	}
	if m.Ready() {
		t.Error("Ready() = true before the first certificate, want false")
	}
}
