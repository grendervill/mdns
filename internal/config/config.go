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
	"regexp"
	"strconv"
	"strings"
	"time"

	"mydns/internal/dnsname"
)

// DefaultDoHPath is the RFC 8484 path the DoH endpoint answers on when
// protocols.doh.path is empty. The panel's routes live under /login,
// /logout and /panel, so the default never shadows them.
const DefaultDoHPath = "/dns-query"

// Protocol enables one listener protocol and selects its port. DoT is
// TCP-only, DoQ is UDP-only; that is decided by the protocol, not config.
// Path is meaningful only for DoH: it is the single URL segment the DoH
// handler is mounted on, an obfuscation that sheds scanner noise, not
// authentication.
type Protocol struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
	// Path is the DoH endpoint path; only protocols.doh uses it, and
	// Validate rejects it on the other protocols.
	Path string `json:"path,omitempty"`
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
	Mode     string `json:"mode"` // "files", "self-signed" or "acme"
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	ACME     ACME   `json:"acme,omitempty"`
}

// ACME configures automatic certificate issuance via the ACME
// protocol. It is used only when the TLS mode is "acme". Provider is
// letsencrypt, zerossl or custom: the first two use their well-known
// directory and require Email (ZeroSSL also requires the EAB
// credentials issued by the CA), while custom requires DirectoryURL.
// InsecureSkipVerify disables the directory TLS check, e.g. for a CA on
// the local network.
type ACME struct {
	Provider           string `json:"provider"` // letsencrypt | zerossl | custom
	Email              string `json:"email,omitempty"`
	DirectoryURL       string `json:"directory_url,omitempty"`
	EABKeyID           string `json:"eab_kid,omitempty"`
	EABHMAC            string `json:"eab_hmac,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// acmeDirectoryURLs maps the built-in CA providers to their ACME
// directory URLs.
var acmeDirectoryURLs = map[string]string{
	"letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
	"zerossl":     "https://acme.zerossl.com/v2/DV90",
}

// ACMEDirectoryURL resolves the provider to its ACME directory URL: the
// built-in CAs map to a fixed URL, custom returns its configured
// DirectoryURL, which must be https.
func (t TLS) ACMEDirectoryURL() (string, error) {
	if dir, ok := acmeDirectoryURLs[t.ACME.Provider]; ok {
		return dir, nil
	}
	if t.ACME.Provider != "custom" {
		return "", fmt.Errorf("tls.acme: unknown provider %q (want letsencrypt, zerossl or custom)", t.ACME.Provider)
	}
	if t.ACME.DirectoryURL == "" {
		return "", errors.New("tls.acme: custom provider requires directory_url")
	}
	u, err := url.Parse(t.ACME.DirectoryURL)
	if err != nil {
		return "", fmt.Errorf("tls.acme: directory_url %q is not valid: %w", t.ACME.DirectoryURL, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("tls.acme: directory_url %q must be an https URL", t.ACME.DirectoryURL)
	}
	return t.ACME.DirectoryURL, nil
}

// validateACME checks the ACME settings: a known provider with a
// usable directory URL (delegated to ACMEDirectoryURL, the single
// source of truth for both) plus the credentials each CA requires —
// a contact email for the public CAs, and the ZeroSSL external
// account binding.
func (t TLS) validateACME() error {
	if _, err := t.ACMEDirectoryURL(); err != nil {
		return err
	}

	switch t.ACME.Provider {
	case "letsencrypt":
		if t.ACME.Email == "" {
			return errors.New("tls.acme: letsencrypt requires email")
		}
	case "zerossl":
		if t.ACME.Email == "" {
			return errors.New("tls.acme: zerossl requires email")
		}
		if t.ACME.EABKeyID == "" || t.ACME.EABHMAC == "" {
			return errors.New("tls.acme: zerossl requires eab_kid and eab_hmac")
		}
	}
	return nil
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

// FilterList is one block-list source. URL is optional: with an empty
// URL the list is looked up in the built-in catalog by ID.
type FilterList struct {
	ID  string `json:"id"`
	URL string `json:"url,omitempty"`
}

// FilterConfig configures the block-list engine: whether it runs, how
// blocked queries are answered, how often lists refresh (0 = manual
// only) and the user's own allow/block rules. A user rule covers the
// domain itself and all of its subdomains.
type FilterConfig struct {
	Enabled             bool         `json:"enabled"`
	Mode                string       `json:"mode"`                  // zero | nxdomain | refused
	UpdateIntervalHours int          `json:"update_interval_hours"` // 0 = manual only
	Lists               []FilterList `json:"lists"`
	UserAllow           []string     `json:"user_allow"`
	UserBlock           []string     `json:"user_block"`
}

// PanelConfig configures the web panel. PasswordHash is the admin
// password stored as an argon2id PHC string and is required when the
// panel is enabled.
type PanelConfig struct {
	Enabled      bool   `json:"enabled"`
	PasswordHash string `json:"password_hash,omitempty"` // argon2id, PHC format
}

// Config is the versioned server configuration, stored as JSON with
// 0600 permissions.
type Config struct {
	Version int    `json:"version"`
	Domain  string `json:"domain"`
	// Timezone is the IANA zone the panel renders query times in. An
	// empty value means the daemon's local zone. It never affects the
	// stored timestamps, only how they are displayed.
	Timezone  string           `json:"timezone,omitempty"`
	Protocols Protocols        `json:"protocols"`
	TLS       TLS              `json:"tls"`
	Upstreams []UpstreamConfig `json:"upstreams"`
	Strategy  string           `json:"strategy"`
	Cache     Cache            `json:"cache"`
	Limits    Limits           `json:"limits"`
	Log       LogConfig        `json:"log"`
	DataDir   string           `json:"data_dir"`
	Filter    FilterConfig     `json:"filter"`
	Panel     PanelConfig      `json:"panel,omitempty"`
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
// 0..86400, 50 rps per IP on plain DNS, a 10000-entry in-memory query
// log (JSONL file off, rotation at 10 MB), data under /var/lib/mdns,
// the filter engine off (dnsserver-style zero answers once enabled) and
// the web panel off. The domain is a placeholder; the setup wizard sets
// the real one.
func Default() *Config {
	return &Config{
		Version: 1,
		Domain:  "mdns.test",
		Protocols: Protocols{
			Plain: Protocol{Enabled: true, Port: 53},
			DoH:   Protocol{Enabled: true, Port: 443, Path: DefaultDoHPath},
			DoT:   Protocol{Enabled: true, Port: 853},
			DoQ:   Protocol{Enabled: true, Port: 853},
		},
		TLS:      TLS{Mode: "self-signed"},
		Strategy: "fastest",
		Cache:    Cache{Size: 10000, MinTTL: 0, MaxTTL: 86400},
		Limits:   Limits{PlainRPSPerIP: 50},
		Log:      LogConfig{MemoryEntries: 10000, MaxFileSizeBytes: 10 * 1024 * 1024},
		DataDir:  "/var/lib/mdns",
		Filter: FilterConfig{
			Mode:                "zero",
			UpdateIntervalHours: 24,
		},
		Panel: PanelConfig{Enabled: false},
	}
}

// Load reads and parses the JSON config at path. It fills the fields
// added after the first schema version with their defaults, so older
// configs keep loading; it runs no validation and leaves everything
// else as written. Callers validate what they loaded.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	return &c, nil
}

// applyDefaults fills the fields introduced after the first config
// version with their defaults, keeping older configs loadable.
func (c *Config) applyDefaults() {
	if c.DataDir == "" {
		c.DataDir = "/var/lib/mdns"
	}
	if c.Filter.Mode == "" {
		c.Filter.Mode = "zero"
	}
	if c.Protocols.DoH.Path == "" {
		c.Protocols.DoH.Path = DefaultDoHPath
	}
}

// DoHPath returns the effective DoH path: the configured value, or the
// default when the config leaves it empty. URL builders and the DoH
// listener both use it, so an empty path and the default behave
// identically.
func (c *Config) DoHPath() string {
	if c.Protocols.DoH.Path == "" {
		return DefaultDoHPath
	}
	return c.Protocols.DoH.Path
}

// Validate checks the config for consistency: domain shape, port ranges,
// known strategy and TLS mode (including the ACME settings when that
// mode is selected), the IANA timezone when one is set, upstream fields,
// data directory, the filter settings and the panel password. Disabled
// upstreams are exempt from address validation, as is the panel password
// when the panel is off.
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

	if c.Timezone != "" {
		if _, err := time.LoadLocation(c.Timezone); err != nil {
			return fmt.Errorf("timezone: cannot load IANA zone %q", c.Timezone)
		}
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
		if p.name != "doh" && p.proto.Path != "" {
			return fmt.Errorf("protocols.%s: path is only valid for doh", p.name)
		}
		if !p.proto.Enabled {
			continue // a disabled protocol's port is irrelevant
		}
		if p.proto.Port < 1 || p.proto.Port > 65535 {
			return fmt.Errorf("protocols.%s: port %d out of range 1-65535", p.name, p.proto.Port)
		}
	}

	if err := validateDoHPath(c.Protocols.DoH.Path); err != nil {
		return err
	}

	if !strategies[c.Strategy] {
		return fmt.Errorf("unknown strategy %q (want one of fastest, failover, round_robin, random)", c.Strategy)
	}

	switch c.TLS.Mode {
	case "files", "self-signed":
	case "acme":
		if err := c.TLS.validateACME(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tls: unknown mode %q (want files, self-signed or acme)", c.TLS.Mode)
	}

	if c.DataDir == "" {
		return errors.New("data_dir must not be empty")
	}

	if c.Cache.Size < 1 {
		return fmt.Errorf("cache: size %d must be at least 1", c.Cache.Size)
	}
	if c.Cache.MinTTL > c.Cache.MaxTTL {
		return fmt.Errorf("cache: min_ttl %d above max_ttl %d", c.Cache.MinTTL, c.Cache.MaxTTL)
	}

	switch c.Filter.Mode {
	case "zero", "nxdomain", "refused":
	default:
		return fmt.Errorf("filter: unknown mode %q (want zero, nxdomain or refused)", c.Filter.Mode)
	}
	if c.Filter.UpdateIntervalHours < 0 {
		return fmt.Errorf("filter: update_interval_hours %d must not be negative", c.Filter.UpdateIntervalHours)
	}

	seenLists := make(map[string]bool, len(c.Filter.Lists))
	for i, l := range c.Filter.Lists {
		if l.ID == "" {
			return fmt.Errorf("filter.lists[%d]: id must not be empty", i)
		}
		if seenLists[l.ID] {
			return fmt.Errorf("filter list %q: duplicate id", l.ID)
		}
		seenLists[l.ID] = true

		if l.URL != "" {
			u, err := url.Parse(l.URL)
			if err != nil {
				return fmt.Errorf("filter list %q: url %q is not valid: %w", l.ID, l.URL, err)
			}
			if u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("filter list %q: url %q must be an https URL", l.ID, l.URL)
			}
		}
	}

	for _, rules := range [][]string{c.Filter.UserAllow, c.Filter.UserBlock} {
		for _, r := range rules {
			if !dnsname.Valid(dnsname.Normalize(r)) {
				return fmt.Errorf("filter rule %q must be a domain with at least two labels", r)
			}
		}
	}

	// The panel password is only meaningful when the panel runs; the
	// full hash verification happens later, at login.
	if c.Panel.Enabled {
		if c.Panel.PasswordHash == "" {
			return errors.New("panel: password_hash must not be empty when the panel is enabled")
		}
		if !strings.HasPrefix(c.Panel.PasswordHash, "$argon2id$") {
			return errors.New("panel: password_hash must be an argon2id PHC hash")
		}
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

// dohPathPattern is the shape of a configurable DoH path: exactly one
// URL segment, so it can neither escape to another route nor carry a
// trailing query.
var dohPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~-]{1,64}$`)

// reservedPanelPaths are the routes the panel owns on the shared DoH
// listener. The DoH path must not shadow them, or a request that should
// reach the panel would be answered as DoH instead.
var reservedPanelPaths = []string{"/login", "/logout", "/panel", "/panel/static"}

// validateDoHPath checks protocols.doh.path: empty means the default, a
// set value must be one URL segment and must not collide with the panel
// routes.
func validateDoHPath(path string) error {
	if path == "" {
		return nil // empty means the default
	}
	if !dohPathPattern.MatchString(path) {
		return fmt.Errorf("protocols.doh: path %q must be one segment like %s", path, DefaultDoHPath)
	}
	if path == "/." || path == "/.." {
		// http.ServeMux would clean these to "/" and the endpoint would
		// never be reachable under the configured path.
		return fmt.Errorf("protocols.doh: path %q must not be \".\" or \"..\"", path)
	}
	for _, reserved := range reservedPanelPaths {
		if path == reserved || strings.HasPrefix(path, reserved+"/") {
			return fmt.Errorf("protocols.doh: path %q collides with the panel route %s", path, reserved)
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
