package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"mydns/internal/config"
)

// validConfig returns a Default() config with one enabled upstream, so
// that the validation table cases mutate a realistic base.
func validConfig() *config.Config {
	c := config.Default()
	c.Domain = "dns.example.com"
	c.Upstreams = []config.UpstreamConfig{
		{
			ID:        "up1",
			Name:      "Upstream 1",
			Transport: "plain",
			Address:   "1.1.1.1:53",
			Priority:  1,
			Enabled:   true,
		},
	}
	return c
}

func TestDefaultValid(t *testing.T) {
	c := config.Default()

	if err := c.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v, want nil", err)
	}
	if c.Domain == "" {
		t.Errorf("default domain is empty, want a placeholder domain")
	}
	if got := c.Protocols.Plain.Port; got != 53 {
		t.Errorf("plain port = %d, want 53", got)
	}
	if got := c.Protocols.DoH.Port; got != 443 {
		t.Errorf("doh port = %d, want 443", got)
	}
	if got := c.Protocols.DoT.Port; got != 853 {
		t.Errorf("dot port = %d, want 853", got)
	}
	if got := c.Protocols.DoQ.Port; got != 853 {
		t.Errorf("doq port = %d, want 853", got)
	}
	if got := c.Strategy; got != "fastest" {
		t.Errorf("strategy = %q, want %q", got, "fastest")
	}
	if got := c.TLS.Mode; got != "self-signed" {
		t.Errorf("tls mode = %q, want %q", got, "self-signed")
	}
	if got := c.Cache.Size; got != 10000 {
		t.Errorf("cache size = %d, want 10000", got)
	}
	if got := c.Cache.MinTTL; got != 0 {
		t.Errorf("cache min ttl = %d, want 0", got)
	}
	if got := c.Cache.MaxTTL; got != 86400 {
		t.Errorf("cache max ttl = %d, want 86400", got)
	}
	if got := c.Limits.PlainRPSPerIP; got != 50 {
		t.Errorf("plain rps per ip = %d, want 50", got)
	}
	if got := c.Log.MemoryEntries; got != 10000 {
		t.Errorf("log memory entries = %d, want 10000", got)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	// Non-default values everywhere, including the omitempty fields.
	c := config.Default()
	c.Domain = "dns.example.com"
	c.Upstreams = []config.UpstreamConfig{
		{
			ID:                 "cf-dot",
			Name:               "Cloudflare DoT",
			Transport:          "dot",
			Address:            "1.1.1.1:853",
			ServerName:         "cloudflare-dns.com",
			InsecureSkipVerify: true,
			Priority:           2,
			Enabled:            true,
		},
	}
	c.Limits.TrustedCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	c.Log.File = filepath.Join(t.TempDir(), "requests.jsonl")

	path := filepath.Join(t.TempDir(), "config.json")
	if err := c.Save(path); err != nil {
		t.Fatalf("Save(%q) = %v, want nil", path, err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%q) = %v, want nil", path, err)
	}
	if !reflect.DeepEqual(loaded, c) {
		t.Errorf("loaded config does not match saved:\n got %+v\nwant %+v", loaded, c)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", path, err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("config file mode = %v, want %v", got, want)
	}
}

func TestValidateTable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr bool
	}{
		{
			name:    "ok",
			mutate:  func(c *config.Config) {},
			wantErr: false,
		},
		{
			name:    "empty domain",
			mutate:  func(c *config.Config) { c.Domain = "" },
			wantErr: true,
		},
		{
			name:    "domain with scheme",
			mutate:  func(c *config.Config) { c.Domain = "https://dns.example.com" },
			wantErr: true,
		},
		{
			name:    "domain with whitespace",
			mutate:  func(c *config.Config) { c.Domain = "dns.example .com" },
			wantErr: true,
		},
		{
			name:    "unknown strategy",
			mutate:  func(c *config.Config) { c.Strategy = "unknown" },
			wantErr: true,
		},
		{
			name:    "plain port zero",
			mutate:  func(c *config.Config) { c.Protocols.Plain.Port = 0 },
			wantErr: true,
		},
		{
			name:    "doh port too high",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Port = 70000 },
			wantErr: true,
		},
		{
			name: "duplicate upstream id",
			mutate: func(c *config.Config) {
				c.Upstreams = append(c.Upstreams, config.UpstreamConfig{
					ID:        "up1",
					Name:      "Upstream 2",
					Transport: "plain",
					Address:   "8.8.8.8:53",
					Enabled:   true,
				})
			},
			wantErr: true,
		},
		{
			name:    "empty upstream id",
			mutate:  func(c *config.Config) { c.Upstreams[0].ID = "" },
			wantErr: true,
		},
		{
			name:    "unknown transport",
			mutate:  func(c *config.Config) { c.Upstreams[0].Transport = "tcp" },
			wantErr: true,
		},
		{
			name:    "empty address",
			mutate:  func(c *config.Config) { c.Upstreams[0].Address = "" },
			wantErr: true,
		},
		{
			name:    "insecure skip verify on plain transport",
			mutate:  func(c *config.Config) { c.Upstreams[0].InsecureSkipVerify = true },
			wantErr: true,
		},
		{
			name:    "plain address without port",
			mutate:  func(c *config.Config) { c.Upstreams[0].Address = "1.1.1.1" },
			wantErr: true,
		},
		{
			name: "doh address not a URL",
			mutate: func(c *config.Config) {
				c.Upstreams[0].Transport = "doh"
				c.Upstreams[0].Address = "1.1.1.1:443"
			},
			wantErr: true,
		},
		{
			name:    "tls mode acme",
			mutate:  func(c *config.Config) { c.TLS.Mode = "acme" },
			wantErr: true,
		},
		{
			name: "disabled upstream with empty address",
			mutate: func(c *config.Config) {
				c.Upstreams = append(c.Upstreams, config.UpstreamConfig{
					ID:        "up2",
					Name:      "Upstream 2",
					Transport: "plain",
					Address:   "",
					Enabled:   false,
				})
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			err := c.Validate()
			switch {
			case tt.wantErr && err == nil:
				t.Errorf("Validate() = nil, want error")
			case !tt.wantErr && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestLoadMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := config.Load(path); err == nil {
		t.Fatalf("Load(%q) = nil error, want error for a missing file", path)
	}
}

func TestSaveAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	if err := config.Default().Save(path); err != nil {
		t.Fatalf("Save(%q) = %v, want nil", path, err)
	}

	tmps, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmps) != 0 {
		t.Errorf("Save left temp files behind: %v", tmps)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory after Save contains %v, want only [config.json]", names)
	}
}
