// Package config defines the JSON configuration schema of the mdns
// server: the config types, the built-in defaults, validation and
// atomic saving.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Protocol enables one listener protocol and selects its port. DoT is
// TCP-only, DoQ is UDP-only; that is decided by the protocol, not config.
type Protocol struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// Protocols groups the listener protocols.
type Protocols struct {
	Plain Protocol `json:"plain"`
	DoH   Protocol `json:"doh"`
	DoT   Protocol `json:"dot"`
	DoQ   Protocol `json:"doq"`
}

// TLS selects how the server certificate is obtained.
type TLS struct {
	Mode     string `json:"mode"` // "files" or "self-signed"
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// UpstreamConfig is one upstream resolver. Address is host:port for
// plain/dot/doq and a full URL for doh. InsecureSkipVerify is allowed
// only for the TLS transports (dot/doh/doq): for upstreams with a
// self-signed certificate, e.g. internal services and tests.
type UpstreamConfig struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Transport          string `json:"transport"`
	Address            string `json:"address"`
	ServerName         string `json:"server_name,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	Priority           int    `json:"priority"`
	Enabled            bool   `json:"enabled"`
}

// Cache configures the in-memory answer cache.
type Cache struct {
	Size   int    `json:"size"`
	MinTTL uint32 `json:"min_ttl"`
	MaxTTL uint32 `json:"max_ttl"`
}

// Limits configures abuse protection for plain DNS. PlainRPSPerIP == 0
// disables the per-IP limit; trusted CIDRs are exempt from it.
type Limits struct {
	PlainRPSPerIP int      `json:"plain_rps_per_ip"`
	TrustedCIDRs  []string `json:"trusted_cidrs"`
}

// LogConfig configures the query log: an in-memory ring buffer and an
// optional JSONL file (empty File = no file) rotated at MaxFileSizeBytes.
type LogConfig struct {
	MemoryEntries    int    `json:"memory_entries"`
	File             string `json:"file"`
	MaxFileSizeBytes int64  `json:"max_file_size_bytes"`
}

// Config is the versioned server configuration, stored as JSON with
// 0600 permissions.
type Config struct {
	Version   int              `json:"version"`
	Domain    string           `json:"domain"`
	Protocols Protocols        `json:"protocols"`
	TLS       TLS              `json:"tls"`
	Upstreams []UpstreamConfig `json:"upstreams"`
	Strategy  string           `json:"strategy"`
	Cache     Cache            `json:"cache"`
	Limits    Limits           `json:"limits"`
	Log       LogConfig        `json:"log"`
}

// strategies is the set of routing strategy names.
var strategies = map[string]bool{
	"fastest":     true,
	"failover":    true,
	"round_robin": true,
	"random":      true,
}

// transports is the set of upstream transport names.
var transports = map[string]bool{
	"plain": true,
	"dot":   true,
	"doh":   true,
	"doq":   true,
}

// tlsTransports is the subset of transports that use TLS and may set
// InsecureSkipVerify.
var tlsTransports = map[string]bool{
	"dot": true,
	"doh": true,
	"doq": true,
}

// Default returns the built-in defaults: all four protocols enabled on
// their standard ports (53, 443, 853, 853), a self-signed certificate,
// the fastest routing strategy, a 10000-entry cache with TTL clamp
// 0..86400, 50 rps per IP on plain DNS and a 10000-entry in-memory
// query log (JSONL file off, rotation at 10 MB). The domain is a
// placeholder; the setup wizard sets the real one.
func Default() *Config {
	return &Config{
		Version: 1,
		Domain:  "mdns.test",
		Protocols: Protocols{
			Plain: Protocol{Enabled: true, Port: 53},
			DoH:   Protocol{Enabled: true, Port: 443},
			DoT:   Protocol{Enabled: true, Port: 853},
			DoQ:   Protocol{Enabled: true, Port: 853},
		},
		TLS:      TLS{Mode: "self-signed"},
		Strategy: "fastest",
		Cache:    Cache{Size: 10000, MinTTL: 0, MaxTTL: 86400},
		Limits:   Limits{PlainRPSPerIP: 50},
		Log:      LogConfig{MemoryEntries: 10000, MaxFileSizeBytes: 10 * 1024 * 1024},
	}
}

// Load reads and parses the JSON config at path. It applies no defaults
// and runs no validation; callers validate what they loaded.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}

// Validate checks the config for consistency: domain shape, port ranges,
// known strategy and TLS mode, and upstream fields. Disabled upstreams
// are exempt from address validation.
func (c *Config) Validate() error {
	if c.Domain == "" {
		return errors.New("domain must not be empty")
	}
	if strings.Contains(c.Domain, "://") {
		return errors.New("domain must not contain a scheme")
	}
	if strings.ContainsAny(c.Domain, " \t\r\n") {
		return errors.New("domain must not contain whitespace")
	}

	for _, p := range []struct {
		name  string
		proto Protocol
	}{
		{"plain", c.Protocols.Plain},
		{"doh", c.Protocols.DoH},
		{"dot", c.Protocols.DoT},
		{"doq", c.Protocols.DoQ},
	} {
		if p.proto.Port < 1 || p.proto.Port > 65535 {
			return fmt.Errorf("protocols.%s: port %d out of range 1-65535", p.name, p.proto.Port)
		}
	}

	if !strategies[c.Strategy] {
		return fmt.Errorf("unknown strategy %q (want one of fastest, failover, round_robin, random)", c.Strategy)
	}

	switch c.TLS.Mode {
	case "files", "self-signed":
	default:
		return fmt.Errorf("tls: unknown mode %q (want files or self-signed)", c.TLS.Mode)
	}

	seen := make(map[string]bool, len(c.Upstreams))
	for i, u := range c.Upstreams {
		if u.ID == "" {
			return fmt.Errorf("upstreams[%d]: id must not be empty", i)
		}
		if seen[u.ID] {
			return fmt.Errorf("upstream %q: duplicate id", u.ID)
		}
		seen[u.ID] = true

		if !transports[u.Transport] {
			return fmt.Errorf("upstream %q: unknown transport %q (want one of plain, dot, doh, doq)", u.ID, u.Transport)
		}
		if u.InsecureSkipVerify && !tlsTransports[u.Transport] {
			return fmt.Errorf("upstream %q: insecure_skip_verify is only allowed for dot, doh or doq", u.ID)
		}
		if !u.Enabled {
			continue
		}
		if err := validateAddress(u.Transport, u.Address); err != nil {
			return fmt.Errorf("upstream %q: %w", u.ID, err)
		}
	}
	return nil
}

// validateAddress checks an upstream address: host:port for plain/dot/doq,
// a full http(s) URL for doh.
func validateAddress(transport, address string) error {
	if address == "" {
		return errors.New("address must not be empty")
	}
	if transport == "doh" {
		u, err := url.Parse(address)
		if err != nil {
			return fmt.Errorf("address %q is not a valid URL: %w", address, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("address %q must be an http or https URL", address)
		}
		if u.Host == "" {
			return fmt.Errorf("address %q must include a host", address)
		}
		return nil
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address %q must be host:port: %w", address, err)
	}
	if host == "" {
		return fmt.Errorf("address %q must include a host", address)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("address %q has invalid port %q (want 1-65535)", address, portStr)
	}
	return nil
}

// Save writes the config to path atomically: the JSON is written to a
// temp file in the same directory, fsynced, renamed over path and the
// result is forced to 0600. Readers never see a partial file, and no
// temp files are left behind on failure.
func (c *Config) Save(path string) (retErr error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config file in %s: %w", dir, err)
	}
	defer func() {
		// After a successful rename the temp file is gone; on failure
		// remove it so no *.tmp leftovers remain.
		tmp.Close() // no-op after a successful close
		if retErr != nil {
			os.Remove(tmp.Name())
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write config %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync config %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod config %s: %w", path, err)
	}
	return nil
}
