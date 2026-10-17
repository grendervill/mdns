package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/testutil/dnsfake"
	"mydns/internal/tlscert"
)

// tlsConfig builds a plain+DoH config on the given free ports with the
// given TLS section; DoT and DoQ stay off so every test binds only the
// listeners it exercises.
func tlsConfig(t *testing.T, fake *dnsfake.Fake, plainPort, dohPort int, tlsCfg config.TLS) *config.Config {
	t.Helper()

	cfg := testConfig(t, fake, plainPort)
	cfg.Protocols.DoH = config.Protocol{Enabled: true, Port: dohPort}
	cfg.TLS = tlsCfg
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
	}
	return cfg
}

// writeCertPair generates a self-signed P-256 pair for mdns.test and
// writes it as PEM, returning the file paths and the serial number of
// the certificate.
func writeCertPair(t *testing.T, dir string, notAfter time.Time) (certFile, keyFile string, serial *big.Int) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() = %v, want nil", err)
	}
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int() = %v, want nil", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mdns.test"},
		DNSNames:              []string{"mdns.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() = %v, want nil", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey() = %v, want nil", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing %s = %v, want nil", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing %s = %v, want nil", keyFile, err)
	}
	return certFile, keyFile, serial
}

// peerSerial dials the TLS listener on port and returns the serial
// number of the served leaf certificate.
func peerSerial(t *testing.T, port int, serverName string) *big.Int {
	t.Helper()

	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", loopback(port), &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // the test only inspects the served certificate
	})
	if err != nil {
		t.Fatalf("tls.Dial(:%d) = %v, want nil", port, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatalf("handshake on :%d served no certificate", port)
	}
	return certs[0].SerialNumber
}

// TestCertStatusSelfSigned checks that the status carries the
// certificate source state and the listeners the DNS server actually
// started: with a ready self-signed store the DoH listener is up.
func TestCertStatusSelfSigned(t *testing.T) {
	fake := newFakeUpstream(t)
	plainPort := freePort(t)
	dohPort := freePort(t)
	cfg := tlsConfig(t, fake, plainPort, dohPort, config.TLS{Mode: "self-signed"})
	a, _ := startApp(t, cfg)

	st, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() = %v, want nil", err)
	}
	if st.Cert.Mode != "self-signed" {
		t.Errorf("Cert.Mode = %q, want self-signed", st.Cert.Mode)
	}
	if st.Cert.State != "ok" {
		t.Errorf("Cert.State = %q, want ok", st.Cert.State)
	}
	if !slices.Contains(st.Listeners, fmt.Sprintf("doh:%d", dohPort)) {
		t.Errorf("Listeners = %v, want doh:%d", st.Listeners, dohPort)
	}
}

// TestStatusListenersFromServer checks Review Focus R4: the status
// forwards the listeners the DNS server actually started (dnsserver
// order plain, doh), not the config-derived label order (doh, plain).
func TestStatusListenersFromServer(t *testing.T) {
	fake := newFakeUpstream(t)
	plainPort := freePort(t)
	dohPort := freePort(t)
	cfg := tlsConfig(t, fake, plainPort, dohPort, config.TLS{Mode: "self-signed"})
	a, _ := startApp(t, cfg)

	st, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() = %v, want nil", err)
	}

	want := []string{fmt.Sprintf("plain:%d", plainPort), fmt.Sprintf("doh:%d", dohPort)}
	if !slices.Equal(st.Listeners, want) {
		t.Errorf("Listeners = %v, want %v", st.Listeners, want)
	}
}

// TestTLSSwitchSelfSignedToFiles checks the structural switch to a
// file certificate: the DoH listener serves the new pair and the old
// self-signed one is gone, and the change is persisted.
func TestTLSSwitchSelfSignedToFiles(t *testing.T) {
	fake := newFakeUpstream(t)
	plainPort := freePort(t)
	dohPort := freePort(t)
	cfg := tlsConfig(t, fake, plainPort, dohPort, config.TLS{Mode: "self-signed"})
	a, cfgPath := startApp(t, cfg)

	oldSerial := peerSerial(t, dohPort, cfg.Domain)

	certFile, keyFile, wantSerial := writeCertPair(t, t.TempDir(), time.Now().Add(24*time.Hour))

	next := *cfg
	next.TLS = config.TLS{Mode: "files", CertFile: certFile, KeyFile: keyFile}
	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig(files) = %v, want nil", err)
	}

	if got := peerSerial(t, dohPort, cfg.Domain); got.Cmp(wantSerial) != 0 {
		t.Errorf("served serial = %v, want the file certificate %v", got, wantSerial)
	}
	if got := peerSerial(t, dohPort, cfg.Domain); got.Cmp(oldSerial) == 0 {
		t.Errorf("served serial = %v, want it to differ from the old self-signed %v", got, oldSerial)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	if loaded.TLS.Mode != "files" || loaded.TLS.CertFile != certFile {
		t.Errorf("persisted TLS = %+v, want mode files cert_file %q", loaded.TLS, certFile)
	}
}

// TestTLSSwitchInvalidACMERejected checks that an ACME section the
// config rejects changes nothing: the old config, its listeners and
// its certificate keep working.
func TestTLSSwitchInvalidACMERejected(t *testing.T) {
	fake := newFakeUpstream(t)
	plainPort := freePort(t)
	dohPort := freePort(t)
	cfg := tlsConfig(t, fake, plainPort, dohPort, config.TLS{Mode: "self-signed"})
	a, cfgPath := startApp(t, cfg)

	next := *cfg
	// ZeroSSL without the EAB credentials the CA requires.
	next.TLS = config.TLS{Mode: "acme", ACME: config.ACME{Provider: "zerossl", Email: "admin@example.com"}}

	if err := a.UpdateConfig(context.Background(), &next); err == nil {
		t.Fatalf("UpdateConfig(invalid acme) = nil, want a validation error")
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	if loaded.TLS.Mode != "self-signed" {
		t.Errorf("persisted TLS mode = %q, want self-signed", loaded.TLS.Mode)
	}

	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := cl.Exchange(query("example.com"), loopback(plainPort)); err != nil {
		t.Fatalf("Exchange() after the rejected update = %v, want nil", err)
	}

	st, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() = %v, want nil", err)
	}
	if st.Cert.Mode != "self-signed" {
		t.Errorf("Cert.Mode = %q, want self-signed", st.Cert.Mode)
	}
	if !slices.Contains(st.Listeners, fmt.Sprintf("doh:%d", dohPort)) {
		t.Errorf("Listeners = %v, want doh:%d", st.Listeners, dohPort)
	}
}

// TestCertStatusACMEMode checks the ACME branch end to end without a
// CA: the app builds the manager (mode acme, never ok), keeps the TLS
// listeners deferred and does not bind :80, because DoH is configured on
// :443, where the tls-alpn-01 challenge is served. A bogus directory
// makes the manager fail fast against a closed local port.
func TestCertStatusACMEMode(t *testing.T) {
	fake := newFakeUpstream(t)
	plainPort := freePort(t)
	cfg := testConfig(t, fake, plainPort)
	cfg.TLS = config.TLS{Mode: "acme", ACME: config.ACME{
		Provider:           "custom",
		Email:              "admin@example.com",
		DirectoryURL:       "https://127.0.0.1:1/dir",
		InsecureSkipVerify: true,
	}}
	cfg.Protocols.DoH = config.Protocol{Enabled: true, Port: 443}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
	}
	a, _ := startApp(t, cfg)

	st, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() = %v, want nil", err)
	}
	if st.Cert.Mode != "acme" {
		t.Errorf("Cert.Mode = %q, want acme", st.Cert.Mode)
	}
	if st.Cert.State == "ok" {
		t.Errorf("Cert.State = %q, want not ok without a CA", st.Cert.State)
	}
	want := []string{fmt.Sprintf("plain:%d", plainPort)}
	if !slices.Equal(st.Listeners, want) {
		t.Errorf("Listeners = %v, want %v (TLS still waiting)", st.Listeners, want)
	}

	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := cl.Exchange(query("example.com"), loopback(plainPort)); err != nil {
		t.Fatalf("Exchange() in acme mode = %v, want nil (plain keeps serving)", err)
	}
}

// TestCertEventPublished checks that the certificate loop announces the
// source status on the event bus as soon as the runtime starts.
func TestCertEventPublished(t *testing.T) {
	fake := newFakeUpstream(t)
	plainPort := freePort(t)
	dohPort := freePort(t)
	cfg := tlsConfig(t, fake, plainPort, dohPort, config.TLS{Mode: "self-signed"})

	opts := testOptions(t)
	if err := cfg.Save(opts.ConfigPath); err != nil {
		t.Fatalf("cfg.Save() = %v, want nil", err)
	}
	a, err := app.New(cfg, opts, discardLogger())
	if err != nil {
		t.Fatalf("app.New() = %v, want nil", err)
	}

	events, cancelSub := a.Events().Subscribe()
	defer cancelSub()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = a.Stop(sctx)
	})

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("event bus closed before the cert event")
			}
			if ev.Type != "cert" {
				continue
			}
			st, ok := ev.Data.(tlscert.Status)
			if !ok {
				t.Fatalf("cert event data = %T, want tlscert.Status", ev.Data)
			}
			if st.Mode != "self-signed" || st.State != "ok" {
				t.Fatalf("cert event status = %+v, want self-signed/ok", st)
			}
			return
		case <-deadline:
			t.Fatalf("no cert event arrived on the bus")
		}
	}
}
