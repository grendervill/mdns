// Package tlscert provides the server TLS certificate store. The
// certificate pair is either loaded from files or generated
// self-signed in memory, and is handed to the TLS listeners through
// Source — the fixed interface contract that the future ACME manager
// will implement as well.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"mydns/internal/config"
)

// selfSignedValidity is how long a generated self-signed certificate
// stays valid.
const selfSignedValidity = 90 * 24 * time.Hour

// Source provides the server certificate to the TLS listeners; a
// static store and the ACME manager both implement it.
type Source interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Ready() bool    // a usable certificate is available
	ACMEALPN() bool // the 443 listener must advertise acme-tls/1
	Status() Status
}

// Status is a snapshot of the certificate source for the control API
// and the interfaces.
type Status struct {
	Mode      string    `json:"mode"`                // self-signed | files | acme
	State     string    `json:"state"`               // ok | waiting | error
	Issuer    string    `json:"issuer,omitempty"`    // issuer common name
	NotAfter  time.Time `json:"not_after,omitempty"` // leaf expiry
	Error     string    `json:"error,omitempty"`
	LastCheck time.Time `json:"last_check,omitempty"`
}

// Store holds the server certificate. The zero Store is not usable;
// build one with New.
type Store struct {
	mode string
	cert *tls.Certificate
}

// New builds the certificate store from the TLS config. Mode "files"
// loads the pair from CertFile and KeyFile, so a broken or missing pair
// fails at startup, not on the first handshake. Mode "self-signed"
// generates an in-memory ECDSA P-256 certificate with SAN set to
// domain, valid for 90 days. Any other mode is an error.
func New(cfg config.TLS, domain string) (*Store, error) {
	var cert tls.Certificate
	var err error

	switch cfg.Mode {
	case "files":
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load certificate %q and key %q: %w", cfg.CertFile, cfg.KeyFile, err)
		}
	case "self-signed":
		cert, err = selfSigned(domain)
		if err != nil {
			return nil, fmt.Errorf("tls: generate self-signed certificate: %w", err)
		}
	default:
		return nil, fmt.Errorf("tls: unknown mode %q (want files or self-signed)", cfg.Mode)
	}

	return &Store{mode: cfg.Mode, cert: &cert}, nil
}

// GetCertificate returns the stored certificate for every handshake.
// It matches the crypto/tls GetCertificate signature, so the store can
// be assigned to tls.Config.GetCertificate directly; the ClientHelloInfo
// is ignored because one certificate serves every name.
func (s *Store) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cert, nil
}

// Ready reports whether a usable certificate is available. A store
// built by New always holds one.
func (s *Store) Ready() bool {
	return s.cert != nil
}

// ACMEALPN reports whether the 443 listener must advertise the
// acme-tls/1 protocol. The static store never serves ACME challenges.
func (s *Store) ACMEALPN() bool {
	return false
}

// Status reports the stored certificate: the mode the store was built
// with, the issuer common name and the expiry from the leaf. The store
// always holds a usable certificate, so the state is ok.
func (s *Store) Status() Status {
	return Status{
		Mode:     s.mode,
		State:    "ok",
		Issuer:   s.cert.Leaf.Issuer.CommonName,
		NotAfter: s.cert.Leaf.NotAfter,
	}
}

// selfSigned generates a self-signed ECDSA P-256 certificate for
// domain, with the SAN set to domain, valid for selfSignedValidity.
func selfSigned(domain string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ECDSA P-256 key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             now,
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse created certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
