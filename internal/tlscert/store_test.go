package tlscert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mydns/internal/config"
	"mydns/internal/tlscert"
)

// testDomain is the server domain used across the tests.
const testDomain = "dns.example.com"

// Compile-time proof that the static store satisfies the source
// contract that the ACME manager will implement as well.
var _ tlscert.Source = (*tlscert.Store)(nil)

// writeCertPair generates a fresh self-signed ECDSA P-256 certificate
// for testDomain with a known serial number and writes the certificate
// and key as PEM files. It returns the serial number so the caller can
// check that the loaded certificate is the same one.
func writeCertPair(t *testing.T, certPath, keyPath string) *big.Int {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial := big.NewInt(1234567890)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: testDomain},
		DNSNames:              []string{testDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write %s: %v", keyPath, err)
	}
	return serial
}

func TestSelfSigned(t *testing.T) {
	s, err := tlscert.New(config.TLS{Mode: "self-signed"}, testDomain)
	if err != nil {
		t.Fatalf("New(self-signed) = %v, want nil", err)
	}

	cert, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate(nil) = %v, want nil", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("GetCertificate returned a nil certificate or nil Leaf")
	}

	if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != testDomain {
		t.Errorf("DNSNames = %v, want [%s]", got, testDomain)
	}

	pub, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type %T, want *ecdsa.PublicKey", cert.Leaf.PublicKey)
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("leaf public key curve = %v, want P-256", pub.Curve)
	}
	priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	if priv.Curve != elliptic.P256() {
		t.Errorf("private key curve = %v, want P-256", priv.Curve)
	}

	now := time.Now()
	if !cert.Leaf.NotAfter.After(now) {
		t.Errorf("NotAfter = %v, want in the future (now %v)", cert.Leaf.NotAfter, now)
	}
	if d := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("validity period = %v, want ~90 days", d)
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	serial := writeCertPair(t, certPath, keyPath)

	s, err := tlscert.New(config.TLS{
		Mode:     "files",
		CertFile: certPath,
		KeyFile:  keyPath,
	}, testDomain)
	if err != nil {
		t.Fatalf("New(files) = %v, want nil", err)
	}

	cert, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate(nil) = %v, want nil", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("GetCertificate returned a nil certificate or nil Leaf")
	}

	if cert.Leaf.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("SerialNumber = %v, want %v", cert.Leaf.SerialNumber, serial)
	}
	if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != testDomain {
		t.Errorf("DNSNames = %v, want [%s]", got, testDomain)
	}
}

func TestStoreImplementsSource(t *testing.T) {
	s, err := tlscert.New(config.TLS{Mode: "self-signed"}, testDomain)
	if err != nil {
		t.Fatalf("New(self-signed) = %v, want nil", err)
	}

	var src tlscert.Source = s
	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate(nil) = %v, want nil", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate(nil) returned a nil certificate")
	}
}

func TestStoreStatus(t *testing.T) {
	t.Run("self-signed", func(t *testing.T) {
		s, err := tlscert.New(config.TLS{Mode: "self-signed"}, testDomain)
		if err != nil {
			t.Fatalf("New(self-signed) = %v, want nil", err)
		}
		if !s.Ready() {
			t.Error("Ready() = false, want true")
		}
		if s.ACMEALPN() {
			t.Error("ACMEALPN() = true, want false")
		}

		got := s.Status()
		if got.Mode != "self-signed" {
			t.Errorf("Status().Mode = %q, want self-signed", got.Mode)
		}
		if got.State != "ok" {
			t.Errorf("Status().State = %q, want ok", got.State)
		}
		if got.Error != "" {
			t.Errorf("Status().Error = %q, want empty", got.Error)
		}
		if got.Issuer != testDomain {
			t.Errorf("Status().Issuer = %q, want %q", got.Issuer, testDomain)
		}
		want := time.Now().Add(90 * 24 * time.Hour)
		if d := got.NotAfter.Sub(want); d < -5*time.Minute || d > 5*time.Minute {
			t.Errorf("Status().NotAfter = %v, want ~%v (90 days from now)", got.NotAfter, want)
		}
	})

	t.Run("files", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		writeCertPair(t, certPath, keyPath)

		// The expected issuer and expiry come from the certificate on
		// disk, not from the store.
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("read %s: %v", certPath, err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			t.Fatalf("%s holds no PEM block", certPath)
		}
		want, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse %s: %v", certPath, err)
		}

		s, err := tlscert.New(config.TLS{
			Mode:     "files",
			CertFile: certPath,
			KeyFile:  keyPath,
		}, testDomain)
		if err != nil {
			t.Fatalf("New(files) = %v, want nil", err)
		}
		if !s.Ready() {
			t.Error("Ready() = false, want true")
		}
		if s.ACMEALPN() {
			t.Error("ACMEALPN() = true, want false")
		}

		got := s.Status()
		if got.Mode != "files" {
			t.Errorf("Status().Mode = %q, want files", got.Mode)
		}
		if got.State != "ok" {
			t.Errorf("Status().State = %q, want ok", got.State)
		}
		if got.Issuer != want.Issuer.CommonName {
			t.Errorf("Status().Issuer = %q, want %q", got.Issuer, want.Issuer.CommonName)
		}
		if !got.NotAfter.Equal(want.NotAfter) {
			t.Errorf("Status().NotAfter = %v, want %v", got.NotAfter, want.NotAfter)
		}
	})
}

func TestBadMode(t *testing.T) {
	if _, err := tlscert.New(config.TLS{Mode: "acme"}, testDomain); err == nil {
		t.Fatal("New(mode acme) = nil error, want error")
	}
}
