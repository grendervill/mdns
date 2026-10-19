// Package acmecert obtains and renews the server certificate from an
// ACME certificate authority. The Manager implements tlscert.Source, so
// the listeners take it exactly like the static certificate store.
package acmecert

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"mydns/internal/tlscert"
)

const (
	// mode is the status mode of every ACME manager.
	mode = "acme"
	// The status states, mirroring tlscert.Status.State.
	stateWaiting = "waiting"
	stateOK      = "ok"
	stateError   = "error"

	// defaultBackoffMin and defaultBackoffMax bound the retry backoff
	// when Options leaves it unset.
	defaultBackoffMin = 5 * time.Minute
	defaultBackoffMax = 6 * time.Hour

	// checkInterval is how often Run checks a ready certificate.
	checkInterval = 24 * time.Hour
)

// Options configures the ACME certificate manager.
type Options struct {
	Domain             string                       // certificate name and ACME HostPolicy
	Email              string                       // account contact address
	DirectoryURL       string                       // CA directory endpoint
	EAB                *acme.ExternalAccountBinding // required by some CAs (ZeroSSL)
	CacheDir           string                       // <data_dir>/certs/acme
	InsecureSkipVerify bool                         // test ACME servers (pebble); never for production
	Logger             *slog.Logger                 // optional; lifecycle messages only
	BackoffMin         time.Duration                // 0 → 5m
	BackoffMax         time.Duration                // 0 → 6h
}

// validate rejects options the manager cannot work with.
func (o Options) validate() error {
	if o.Domain == "" {
		return errors.New("acmecert: domain is required")
	}
	if o.CacheDir == "" {
		return errors.New("acmecert: cache directory is required")
	}
	return nil
}

// getter is the certificate source the manager drives: the autocert
// manager in production, a stub in tests.
type getter interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Manager obtains the server certificate over ACME and keeps its status
// for the control API. The zero Manager is not usable; build one with
// New.
type Manager struct {
	getter      getter
	httpHandler http.Handler
	domain      string
	log         *slog.Logger
	backoffMin  time.Duration
	backoffMax  time.Duration
	now         func() time.Time

	readyOnce sync.Once
	readyChan chan struct{}

	mu       sync.Mutex
	ready    bool
	status   tlscert.Status
	reported tlscert.Status
}

// newAutocertManager assembles the autocert manager New wraps: the ACME
// stack itself, kept in one place so a test can inspect it.
func newAutocertManager(opts Options) *autocert.Manager {
	client := &acme.Client{DirectoryURL: opts.DirectoryURL}
	if opts.InsecureSkipVerify {
		client.HTTPClient = &http.Client{
			Transport: &http.Transport{
				// Test ACME servers (pebble) serve a certificate that
				// no system root can verify.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(opts.CacheDir),
		HostPolicy: autocert.HostWhitelist(opts.Domain),
		// RenewBefore stays at its zero value on purpose: autocert then
		// renews at the lesser of 30 days or a third of the certificate
		// lifetime — the 30 days the spec asks for on a 90-day
		// certificate, and a safe window on a short-lived one. Setting
		// 30 days explicitly would put every short-lived certificate
		// inside the renewal window on every handshake.
		Client:                 client,
		Email:                  opts.Email,
		ExternalAccountBinding: opts.EAB,
	}
}

// New builds the ACME manager: it issues and caches certificates for
// Domain through DirectoryURL, keeping the account key and the issued
// certificates in CacheDir. InsecureSkipVerify disables the directory
// TLS verification and is meant for test ACME servers only.
func New(opts Options) (*Manager, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	acmeMgr := newAutocertManager(opts)

	m, err := newWithGetter(acmeMgr, opts, time.Now)
	if err != nil {
		return nil, err
	}
	m.httpHandler = acmeMgr.HTTPHandler(http.NotFoundHandler())
	return m, nil
}

// newWithGetter builds a manager on top of a raw certificate getter.
// Only New assembles the autocert and ACME stack; this seam lets the
// tests run the manager without any of it, with a fixed clock.
func newWithGetter(g getter, opts Options, now func() time.Time) (*Manager, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &Manager{
		getter:     g,
		domain:     opts.Domain,
		log:        logger,
		backoffMin: durationOr(opts.BackoffMin, defaultBackoffMin),
		backoffMax: durationOr(opts.BackoffMax, defaultBackoffMax),
		now:        now,
		readyChan:  make(chan struct{}),
		status:     tlscert.Status{Mode: mode, State: stateWaiting},
	}, nil
}

// GetCertificate returns the certificate for the TLS handshake: the
// cached one when autocert holds it, a freshly issued one otherwise.
// The outcome is recorded in Status, except for a CA challenge
// handshake, which carries no certificate the server will ever serve.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		// tls-alpn-01: autocert answers with a temporary challenge
		// certificate, so this says nothing about readiness.
		return m.getter.GetCertificate(hello)
	}

	// A foreign SNI (a scanner, a shared IP, a stale DNS record) says
	// nothing about our certificate: pass the getter's error through but
	// do not record it, or one random handshake would make the daemon
	// report a broken certificate.
	if hello == nil || !strings.EqualFold(hello.ServerName, m.domain) {
		cert, err := m.getter.GetCertificate(hello)
		return cert, err
	}

	cert, _, err := m.fetch(hello)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// fetch asks the getter for a certificate, records the result and
// returns the status it recorded.
func (m *Manager) fetch(hello *tls.ClientHelloInfo) (*tls.Certificate, tlscert.Status, error) {
	cert, err := m.getter.GetCertificate(hello)
	return cert, m.record(cert, err), err
}

// record stores the outcome of a certificate lookup: the issuer and the
// expiry of the leaf on success, the error text otherwise, and the check
// time either way. A failure keeps the last known issuer and expiry, so
// a broken renewal still shows which certificate the server holds. The
// first success makes the source ready.
func (m *Manager) record(cert *tls.Certificate, err error) tlscert.Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.status
	st.Mode = mode
	st.LastCheck = m.now()
	if err != nil {
		st.State = stateError
		st.Error = err.Error()
	} else {
		st.State = stateOK
		st.Error = ""
		if cert != nil && cert.Leaf != nil {
			st.Issuer = cert.Leaf.Issuer.CommonName
			st.NotAfter = cert.Leaf.NotAfter
		}
		m.ready = true
		m.readyOnce.Do(func() { close(m.readyChan) })
	}
	m.status = st
	return st
}

// HTTPHandler serves the ACME http-01 challenge, so a CA can validate
// the domain over port 80; any other request gets 404. New always sets
// it, so a listener started from the ACME manager can serve the
// challenge on the side.
func (m *Manager) HTTPHandler() http.Handler {
	return m.httpHandler
}

// Ready reports whether a certificate has been obtained at least once.
func (m *Manager) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

// ReadyChan is closed when the first certificate arrives; a server can
// wait on it before reporting itself started.
func (m *Manager) ReadyChan() <-chan struct{} {
	return m.readyChan
}

// ACMEALPN reports that the TLS listener must advertise the acme-tls/1
// protocol for the tls-alpn-01 challenge.
func (m *Manager) ACMEALPN() bool {
	return true
}

// Status reports the certificate state for the control API.
func (m *Manager) Status() tlscert.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// clientHello describes the TLS client Run fetches the certificate for:
// a modern ECDSA-capable one. autocert picks the certificate key type
// from the hello (supportsECDSA needs an ECDSA cipher suite and P-256),
// so a bare hello would make it order a second, RSA certificate next to
// the ECDSA one the real clients get. The project issues ECDSA P-256
// certificates only.
func clientHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:      domain,
		SupportedCurves: []tls.CurveID{tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
}

// Run obtains the certificate proactively and then checks it once a
// day. A failed attempt is retried with an exponential backoff and
// ±20% jitter that grows until the first success; every status change
// is passed to onState (which may be nil). Run returns when ctx is done,
// so the caller starts it in a goroutine, once.
func (m *Manager) Run(ctx context.Context, onState func(tlscert.Status)) {
	hello := clientHello(m.domain)
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}

		_, st, err := m.fetch(hello)
		m.notify(onState, st)
		if err == nil {
			attempt = 0
			m.log.Info("acme: certificate ready",
				"domain", m.domain, "issuer", st.Issuer, "not_after", st.NotAfter)
			if !sleep(ctx, checkInterval) {
				return
			}
			continue
		}

		wait := backoffFor(attempt, m.backoffMin, m.backoffMax, rand.Float64())
		attempt++
		m.log.Warn("acme: certificate request failed, retrying",
			"domain", m.domain, "error", err, "retry_in", wait)
		if !sleep(ctx, wait) {
			return
		}
	}
}

// notify passes st to onState when it differs from the previous report.
// The check time alone does not count as a change.
func (m *Manager) notify(onState func(tlscert.Status), st tlscert.Status) {
	if onState == nil {
		return
	}
	m.mu.Lock()
	changed := !sameStatus(m.reported, st)
	m.reported = st
	m.mu.Unlock()
	if changed {
		onState(st)
	}
}

// sameStatus compares two statuses ignoring the check time.
func sameStatus(a, b tlscert.Status) bool {
	return a.Mode == b.Mode &&
		a.State == b.State &&
		a.Issuer == b.Issuer &&
		a.NotAfter.Equal(b.NotAfter) &&
		a.Error == b.Error
}

// backoffFor returns the wait before retry number attempt: Min·2^attempt
// capped at Max, spread by ±20% with rnd in [0, 1] (0.5 means no shift).
// Zero bounds fall back to the defaults.
func backoffFor(attempt int, min, max time.Duration, rnd float64) time.Duration {
	min = durationOr(min, defaultBackoffMin)
	max = durationOr(max, defaultBackoffMax)

	base := min
	for i := 0; i < attempt; i++ {
		if base >= max {
			break
		}
		base *= 2
	}
	if base > max {
		base = max
	}

	if rnd < 0 {
		rnd = 0
	}
	if rnd > 1 {
		rnd = 1
	}
	span := base / 5 // ±20% of the capped backoff
	shift := time.Duration((2*rnd - 1) * float64(span))
	if out := base + shift; out > 0 {
		return out
	}
	return 0
}

// durationOr returns v, or def when v is not positive.
func durationOr(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

// sleep waits for d and reports whether ctx is still alive; a cancelled
// context ends the wait immediately.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// eabEncodings are the base64 alphabets a CA may use for the EAB HMAC.
var eabEncodings = []*base64.Encoding{
	base64.RawURLEncoding,
	base64.URLEncoding,
	base64.RawStdEncoding,
	base64.StdEncoding,
}

// ParseEAB decodes the EAB HMAC from the config: CAs hand the key out as
// base64url or standard base64, with or without padding. The key itself
// is a secret and is never written to the log.
func ParseEAB(kid, hmacB64 string) (*acme.ExternalAccountBinding, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, errors.New("acmecert: eab key id is empty")
	}
	raw := strings.TrimSpace(hmacB64)
	if raw == "" {
		return nil, errors.New("acmecert: eab hmac is empty")
	}

	var decodeErr error
	for _, enc := range eabEncodings {
		key, err := enc.DecodeString(raw)
		if err == nil {
			return &acme.ExternalAccountBinding{KID: kid, Key: key}, nil
		}
		decodeErr = err
	}
	return nil, fmt.Errorf("acmecert: eab hmac is not base64: %w", decodeErr)
}

var _ tlscert.Source = (*Manager)(nil)
