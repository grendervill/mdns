package app

import (
	"testing"

	"mydns/internal/acmecert"
	"mydns/internal/config"
)

// TestReuseACMEManager covers the reuse decision: the manager is bound
// to one domain, one TLS section and one cache directory, so any of
// them changing builds a new one.
func TestReuseACMEManager(t *testing.T) {
	mgr := newTestACMEManager(t)

	acmeTLS := config.TLS{Mode: "acme", ACME: config.ACME{Provider: "custom", DirectoryURL: "https://acme.invalid/dir"}}
	otherTLS := config.TLS{Mode: "acme", ACME: config.ACME{Provider: "letsencrypt", Email: "admin@example.com"}}

	const (
		domain  = "mdns.test"
		dataDir = "/var/lib/mdns"
	)

	cfg := func(domain string, tlsCfg config.TLS, dir string) *config.Config {
		c := config.Default()
		c.Domain = domain
		c.TLS = tlsCfg
		c.DataDir = dir
		return c
	}

	prev := &runtime{acmeMgr: mgr, certDomain: domain, certCfg: acmeTLS, dataDir: dataDir}

	tests := []struct {
		name string
		prev *runtime
		cfg  *config.Config
		want bool
	}{
		{
			name: "same tls, domain and data dir",
			prev: prev,
			cfg:  cfg(domain, acmeTLS, dataDir),
			want: true,
		},
		{
			name: "changed domain",
			prev: prev,
			cfg:  cfg("other.test", acmeTLS, dataDir),
			want: false,
		},
		{
			name: "changed tls",
			prev: prev,
			cfg:  cfg(domain, otherTLS, dataDir),
			want: false,
		},
		{
			name: "changed data dir",
			prev: prev,
			cfg:  cfg(domain, acmeTLS, "/var/lib/other"),
			want: false,
		},
		{
			name: "previous manager missing",
			prev: &runtime{certDomain: domain, certCfg: acmeTLS, dataDir: dataDir},
			cfg:  cfg(domain, acmeTLS, dataDir),
			want: false,
		},
		{
			name: "no previous generation",
			prev: nil,
			cfg:  cfg(domain, acmeTLS, dataDir),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reuseACMEManager(tt.prev, tt.cfg); got != tt.want {
				t.Errorf("reuseACMEManager() = %v, want %v", got, tt.want)
			}
		})
	}
}

// newTestACMEManager builds a manager that is never used: acmecert.New
// performs no network or disk I/O at construction.
func newTestACMEManager(t *testing.T) *acmecert.Manager {
	t.Helper()

	m, err := acmecert.New(acmecert.Options{
		Domain:       "mdns.test",
		DirectoryURL: "https://acme.invalid/dir",
		CacheDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("acmecert.New() = %v, want nil", err)
	}
	return m
}
