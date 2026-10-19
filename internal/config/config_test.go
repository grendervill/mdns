package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	if got := c.Protocols.DoH.Path; got != config.DefaultDoHPath {
		t.Errorf("doh path = %q, want %q", got, config.DefaultDoHPath)
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

func TestFilterDefaults(t *testing.T) {
	c := config.Default()

	if got := c.DataDir; got != "/var/lib/mdns" {
		t.Errorf("data_dir = %q, want %q", got, "/var/lib/mdns")
	}
	f := c.Filter
	if f.Enabled {
		t.Errorf("filter enabled = true, want false by default")
	}
	if f.Mode != "zero" {
		t.Errorf("filter mode = %q, want %q", f.Mode, "zero")
	}
	if f.UpdateIntervalHours != 24 {
		t.Errorf("filter update interval = %d, want 24", f.UpdateIntervalHours)
	}
	if len(f.Lists) != 0 || len(f.UserAllow) != 0 || len(f.UserBlock) != 0 {
		t.Errorf("filter lists/rules = %+v, want empty by default", f)
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
	c.DataDir = "/var/lib/mdns-test"
	c.Filter = config.FilterConfig{
		Enabled:             true,
		Mode:                "nxdomain",
		UpdateIntervalHours: 6,
		Lists: []config.FilterList{
			{ID: "oisd-small"},
			{ID: "custom", URL: "https://lists.example.com/custom.txt"},
		},
		UserAllow: []string{"allowed.example.com"},
		UserBlock: []string{"blocked.example.com"},
	}

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
			name:    "valid custom doh path",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/my-dns._~42" },
			wantErr: false,
		},
		{
			name:    "empty doh path means the default",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "" },
			wantErr: false,
		},
		{
			name:    "doh path without leading slash",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "dns-query" },
			wantErr: true,
		},
		{
			name:    "doh path with whitespace",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/dns query" },
			wantErr: true,
		},
		{
			name:    "doh path dot segment",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/." },
			wantErr: true,
		},
		{
			name:    "doh path dotdot segment",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/.." },
			wantErr: true,
		},
		{
			name:    "path on a non-doh protocol",
			mutate:  func(c *config.Config) { c.Protocols.Plain.Path = "/dns-query" },
			wantErr: true,
		},
		{
			name:    "doh path too long",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/" + strings.Repeat("a", 65) },
			wantErr: true,
		},
		{
			name:    "doh path is just a slash",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/" },
			wantErr: true,
		},
		{
			name:    "doh path collides with login",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/login" },
			wantErr: true,
		},
		{
			name:    "doh path collides with logout",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/logout" },
			wantErr: true,
		},
		{
			name:    "doh path collides with panel",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/panel" },
			wantErr: true,
		},
		{
			name:    "doh path collides with static",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/panel/static" },
			wantErr: true,
		},
		{
			// A later config-validation test for overlaps may add a
			// nested route; the single-segment rule already rejects
			// anything deeper than "/panel".
			name:    "doh path is nested under panel",
			mutate:  func(c *config.Config) { c.Protocols.DoH.Path = "/panel/x" },
			wantErr: true,
		},
		{
			name: "disabled protocol with zero port",
			mutate: func(c *config.Config) {
				c.Protocols.DoQ = config.Protocol{Enabled: false, Port: 0}
			},
			wantErr: false,
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
			// Mode acme is a valid mode, but the empty ACME section
			// names no provider.
			name:    "tls mode acme without provider",
			mutate:  func(c *config.Config) { c.TLS.Mode = "acme" },
			wantErr: true,
		},
		{
			name:    "cache size zero",
			mutate:  func(c *config.Config) { c.Cache.Size = 0 },
			wantErr: true,
		},
		{
			name: "cache min above max",
			mutate: func(c *config.Config) {
				c.Cache.MinTTL = 100
				c.Cache.MaxTTL = 50
			},
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

func TestValidateFilterTable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr bool
	}{
		{
			name:    "filter defaults",
			mutate:  func(c *config.Config) {},
			wantErr: false,
		},
		{
			name: "filter enabled with catalog list",
			mutate: func(c *config.Config) {
				c.Filter.Enabled = true
				c.Filter.Lists = []config.FilterList{{ID: "oisd-small"}}
			},
			wantErr: false,
		},
		{
			name: "manual updates only",
			mutate: func(c *config.Config) {
				c.Filter.UpdateIntervalHours = 0
			},
			wantErr: false,
		},
		{
			name:    "unknown mode",
			mutate:  func(c *config.Config) { c.Filter.Mode = "bogus" },
			wantErr: true,
		},
		{
			name:    "negative interval",
			mutate:  func(c *config.Config) { c.Filter.UpdateIntervalHours = -1 },
			wantErr: true,
		},
		{
			name: "duplicate list ids",
			mutate: func(c *config.Config) {
				c.Filter.Lists = []config.FilterList{{ID: "a"}, {ID: "a"}}
			},
			wantErr: true,
		},
		{
			name: "empty list id",
			mutate: func(c *config.Config) {
				c.Filter.Lists = []config.FilterList{{URL: "https://x/y.txt"}}
			},
			wantErr: true,
		},
		{
			name: "list url not https",
			mutate: func(c *config.Config) {
				c.Filter.Lists = []config.FilterList{{ID: "custom", URL: "http://x/y.txt"}}
			},
			wantErr: true,
		},
		{
			name:    "user rule with space",
			mutate:  func(c *config.Config) { c.Filter.UserBlock = []string{"two words"} },
			wantErr: true,
		},
		{
			name:    "user rule with scheme",
			mutate:  func(c *config.Config) { c.Filter.UserAllow = []string{"https://x.com"} },
			wantErr: true,
		},
		{
			name:    "user rule single label",
			mutate:  func(c *config.Config) { c.Filter.UserBlock = []string{"com"} },
			wantErr: true,
		},
		{
			name:    "user rule with path",
			mutate:  func(c *config.Config) { c.Filter.UserAllow = []string{"x.com/path"} },
			wantErr: true,
		},
		{
			name:    "empty data dir",
			mutate:  func(c *config.Config) { c.DataDir = "" },
			wantErr: true,
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

func TestTLSACMEModeValid(t *testing.T) {
	tests := []struct {
		name string
		acme config.ACME
	}{
		{
			name: "letsencrypt with email",
			acme: config.ACME{Provider: "letsencrypt", Email: "admin@example.com"},
		},
		{
			name: "zerossl with email and eab",
			acme: config.ACME{
				Provider: "zerossl",
				Email:    "admin@example.com",
				EABKeyID: "kid-1",
				EABHMAC:  "c2VjcmV0",
			},
		},
		{
			name: "custom with https url and insecure skip verify",
			acme: config.ACME{
				Provider:           "custom",
				DirectoryURL:       "https://acme.internal.example.com/directory",
				InsecureSkipVerify: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			c.TLS.Mode = "acme"
			c.TLS.ACME = tt.acme

			if err := c.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestTLSACMEModeInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{
			name: "unknown provider",
			mutate: func(c *config.Config) {
				c.TLS.ACME = config.ACME{Provider: "bogus", Email: "admin@example.com"}
			},
		},
		{
			name: "letsencrypt without email",
			mutate: func(c *config.Config) {
				c.TLS.ACME = config.ACME{Provider: "letsencrypt"}
			},
		},
		{
			name: "zerossl without eab",
			mutate: func(c *config.Config) {
				c.TLS.ACME = config.ACME{Provider: "zerossl", Email: "admin@example.com"}
			},
		},
		{
			name: "custom without directory url",
			mutate: func(c *config.Config) {
				c.TLS.ACME = config.ACME{Provider: "custom", Email: "admin@example.com"}
			},
		},
		{
			name: "custom with http directory url",
			mutate: func(c *config.Config) {
				c.TLS.ACME = config.ACME{
					Provider:     "custom",
					Email:        "admin@example.com",
					DirectoryURL: "http://acme.internal.example.com/directory",
				}
			},
		},
		{
			name:   "empty domain",
			mutate: func(c *config.Config) { c.Domain = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			c.TLS.Mode = "acme"
			tt.mutate(c)

			if err := c.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error")
			}
		})
	}
}

func TestACMEDirectoryURL(t *testing.T) {
	tests := []struct {
		name    string
		tls     config.TLS
		want    string
		wantErr bool
	}{
		{
			name: "letsencrypt",
			tls:  config.TLS{ACME: config.ACME{Provider: "letsencrypt"}},
			want: "https://acme-v02.api.letsencrypt.org/directory",
		},
		{
			name: "zerossl",
			tls:  config.TLS{ACME: config.ACME{Provider: "zerossl"}},
			want: "https://acme.zerossl.com/v2/DV90",
		},
		{
			name: "custom",
			tls: config.TLS{ACME: config.ACME{
				Provider:     "custom",
				DirectoryURL: "https://acme.internal.example.com/directory",
			}},
			want: "https://acme.internal.example.com/directory",
		},
		{
			name:    "unknown provider",
			tls:     config.TLS{ACME: config.ACME{Provider: "bogus"}},
			wantErr: true,
		},
		{
			name:    "custom without directory url",
			tls:     config.TLS{ACME: config.ACME{Provider: "custom"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tls.ACMEDirectoryURL()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ACMEDirectoryURL() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ACMEDirectoryURL() = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("ACMEDirectoryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadBackwardCompatDefaults(t *testing.T) {
	// A config written before the filter fields existed: version 1,
	// no data_dir, no filter section. Loading it must fill the new
	// fields with defaults instead of failing validation.
	path := filepath.Join(t.TempDir(), "old.json")
	old := `{
  "version": 1,
  "domain": "dns.example.com",
  "protocols": {
    "plain": {"enabled": false, "port": 0},
    "doh": {"enabled": false, "port": 0},
    "dot": {"enabled": false, "port": 0},
    "doq": {"enabled": false, "port": 0}
  },
  "tls": {"mode": "self-signed"},
  "upstreams": [],
  "strategy": "fastest",
  "cache": {"size": 100, "min_ttl": 0, "max_ttl": 3600},
  "limits": {"plain_rps_per_ip": 10, "trusted_cidrs": []},
  "log": {"memory_entries": 100, "file": "", "max_file_size_bytes": 0}
}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if c.DataDir != "/var/lib/mdns" {
		t.Errorf("DataDir = %q, want the default for old configs", c.DataDir)
	}
	if c.Filter.Mode != "zero" {
		t.Errorf("Filter.Mode = %q, want %q for old configs", c.Filter.Mode, "zero")
	}
	if c.Protocols.DoH.Path != config.DefaultDoHPath {
		t.Errorf("DoH path = %q, want the default %q for old configs", c.Protocols.DoH.Path, config.DefaultDoHPath)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil (old configs must keep loading)", err)
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

func TestPanelDefaults(t *testing.T) {
	c := config.Default()

	if c.Panel.Enabled {
		t.Errorf("panel enabled = true, want false by default")
	}
	if c.Panel.PasswordHash != "" {
		t.Errorf("panel password_hash = %q, want empty by default", c.Panel.PasswordHash)
	}
}

func TestPanelValidation(t *testing.T) {
	validHash := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$mZ1kYXRh"

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr bool
	}{
		{
			name:    "disabled panel without hash",
			mutate:  func(c *config.Config) {},
			wantErr: false,
		},
		{
			name: "enabled panel with valid argon2id hash",
			mutate: func(c *config.Config) {
				c.Panel.Enabled = true
				c.Panel.PasswordHash = validHash
			},
			wantErr: false,
		},
		{
			name:    "enabled panel with empty hash",
			mutate:  func(c *config.Config) { c.Panel.Enabled = true },
			wantErr: true,
		},
		{
			name: "enabled panel with non-argon2id hash",
			mutate: func(c *config.Config) {
				c.Panel.Enabled = true
				c.Panel.PasswordHash = "$2y$10$N9qo8uLOickgx2ZMRZoMye"
			},
			wantErr: true,
		},
		{
			name: "enabled panel with garbage in hash field",
			mutate: func(c *config.Config) {
				c.Panel.Enabled = true
				c.Panel.PasswordHash = "not-a-hash"
			},
			wantErr: true,
		},
		{
			name: "disabled panel ignores garbage in hash field",
			mutate: func(c *config.Config) {
				c.Panel.PasswordHash = "not-a-hash"
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

func TestPanelRoundTrip(t *testing.T) {
	c := validConfig()
	c.Panel = config.PanelConfig{
		Enabled:      true,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$mZ1kYXRh",
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := c.Save(path); err != nil {
		t.Fatalf("Save(%q) = %v, want nil", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"panel"`) {
		t.Errorf("saved JSON has no panel section:\n%s", data)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%q) = %v, want nil", path, err)
	}
	if !reflect.DeepEqual(loaded.Panel, c.Panel) {
		t.Errorf("panel after round-trip = %+v, want %+v", loaded.Panel, c.Panel)
	}
}

// TestTimezoneValidation pins the configurable display zone: a loadable
// IANA name is accepted, an unloadable one is rejected with an error that
// names the field and the zone, and an empty value means "daemon local".
func TestTimezoneValidation(t *testing.T) {
	t.Run("Europe/Moscow is accepted", func(t *testing.T) {
		c := validConfig()
		c.Timezone = "Europe/Moscow"
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil for Europe/Moscow", err)
		}
	})

	t.Run("an unknown zone names the field and the zone", func(t *testing.T) {
		c := validConfig()
		c.Timezone = "Mars/Base"
		err := c.Validate()
		if err == nil {
			t.Fatal("Validate() = nil, want an error for Mars/Base")
		}
		if !strings.Contains(err.Error(), "timezone") {
			t.Errorf("error %q does not name the timezone field", err)
		}
		if !strings.Contains(err.Error(), "Mars/Base") {
			t.Errorf("error %q does not name the rejected zone", err)
		}
	})

	t.Run("empty means the daemon local zone", func(t *testing.T) {
		c := validConfig()
		if c.Timezone != "" {
			t.Fatalf("Default().Timezone = %q, want empty", c.Timezone)
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil with an empty timezone", err)
		}
	})

	t.Run("an old config without the key still validates", func(t *testing.T) {
		// A config written before the timezone field existed: no
		// timezone, no data_dir, no filter section.
		path := filepath.Join(t.TempDir(), "old.json")
		old := `{
  "version": 1,
  "domain": "dns.example.com",
  "tls": {"mode": "self-signed"},
  "strategy": "fastest",
  "cache": {"size": 100, "min_ttl": 0, "max_ttl": 3600},
  "limits": {"plain_rps_per_ip": 10},
  "log": {"memory_entries": 100}
}`
		if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load() = %v, want nil", err)
		}
		if c.Timezone != "" {
			t.Errorf("Timezone = %q, want empty for an old config", c.Timezone)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil (old configs must keep loading)", err)
		}
	})

	t.Run("the zone round-trips through save and load", func(t *testing.T) {
		c := validConfig()
		c.Timezone = "Europe/Moscow"
		path := filepath.Join(t.TempDir(), "config.json")
		if err := c.Save(path); err != nil {
			t.Fatalf("Save() = %v", err)
		}
		loaded, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if loaded.Timezone != "Europe/Moscow" {
			t.Errorf("Timezone after round-trip = %q, want Europe/Moscow", loaded.Timezone)
		}
		if err := loaded.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})
}
