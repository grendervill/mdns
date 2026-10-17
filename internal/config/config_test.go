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
			name:    "tls mode acme",
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
