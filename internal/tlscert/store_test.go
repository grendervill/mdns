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

func TestBadMode(t *testing.T) {
	if _, err := tlscert.New(config.TLS{Mode: "acme"}, testDomain); err == nil {
		t.Fatal("New(mode acme) = nil error, want error")
	}
}
