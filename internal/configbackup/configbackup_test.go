package configbackup_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mydns/internal/config"
	"mydns/internal/configbackup"
)

// testConfig is a valid configuration with an upstream, so a snapshot
// round-trip carries more than the defaults.
func testConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.Domain = "backup.example.test"
	cfg.DataDir = t.TempDir()
	cfg.Upstreams = []config.UpstreamConfig{{
		ID:        "cloudflare",
		Name:      "Cloudflare",
		Transport: "doh",
		Address:   "https://cloudflare-dns.com/dns-query",
		Priority:  0,
		Enabled:   true,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
	}
	return cfg
}

// TestCreateListLoadDelete covers the whole lifecycle: a snapshot is
// listed, loads back with the same content and disappears on delete.
func TestCreateListLoadDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backups")
	cfg := testConfig(t)

	info, err := configbackup.Create(dir, cfg, "before-change")
	if err != nil {
		t.Fatalf("Create() = %v, want nil", err)
	}
	if !strings.HasPrefix(info.Name, "config-") || !strings.HasSuffix(info.Name, "-before-change.json") {
		t.Errorf("name = %q, want config-<timestamp>-before-change.json", info.Name)
	}
	if info.Size <= 0 {
		t.Errorf("size = %d, want a non-empty file", info.Size)
	}

	infos, err := configbackup.List(dir)
	if err != nil {
		t.Fatalf("List() = %v, want nil", err)
	}
	if len(infos) != 1 || infos[0].Name != info.Name {
		t.Fatalf("List() = %+v, want the created snapshot", infos)
	}

	loaded, err := configbackup.Load(dir, info.Name)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if loaded.Domain != cfg.Domain {
		t.Errorf("loaded domain = %q, want %q", loaded.Domain, cfg.Domain)
	}
	if len(loaded.Upstreams) != 1 || loaded.Upstreams[0].Address != cfg.Upstreams[0].Address {
		t.Errorf("loaded upstreams = %+v, want the snapshot's", loaded.Upstreams)
	}
	if loaded.Protocols.DoH.Path != cfg.Protocols.DoH.Path {
		t.Errorf("loaded DoH path = %q, want %q", loaded.Protocols.DoH.Path, cfg.Protocols.DoH.Path)
	}

	if err := configbackup.Delete(dir, info.Name); err != nil {
		t.Fatalf("Delete() = %v, want nil", err)
	}
	infos, err = configbackup.List(dir)
	if err != nil {
		t.Fatalf("List() after delete = %v, want nil", err)
	}
	if len(infos) != 0 {
		t.Errorf("List() after delete = %+v, want empty", infos)
	}
}

// TestCreateRetention keeps at most ten snapshots and prunes the oldest.
func TestCreateRetention(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backups")
	cfg := testConfig(t)

	for i := 0; i < 12; i++ {
		label := "b" + string(rune('a'+i))
		if _, err := configbackup.Create(dir, cfg, label); err != nil {
			t.Fatalf("Create(%q) = %v, want nil", label, err)
		}
	}

	infos, err := configbackup.List(dir)
	if err != nil {
		t.Fatalf("List() = %v, want nil", err)
	}
	if len(infos) != 10 {
		t.Fatalf("List() returned %d snapshots, want 10", len(infos))
	}
	for _, info := range infos {
		if strings.HasSuffix(info.Name, "-ba.json") || strings.HasSuffix(info.Name, "-bb.json") {
			t.Errorf("the oldest snapshot %q survived pruning", info.Name)
		}
	}
	if !strings.HasSuffix(infos[0].Name, "-bl.json") {
		t.Errorf("newest snapshot = %q, want the last created (-bl.json)", infos[0].Name)
	}
}

// TestListMissingDir treats a missing directory as an empty list.
func TestListMissingDir(t *testing.T) {
	infos, err := configbackup.List(filepath.Join(t.TempDir(), "never-created"))
	if err != nil {
		t.Fatalf("List() = %v, want nil", err)
	}
	if len(infos) != 0 {
		t.Errorf("List() = %+v, want empty", infos)
	}
}

// TestLoadMalformed rejects a snapshot that is not valid JSON.
func TestLoadMalformed(t *testing.T) {
	dir := t.TempDir()
	name := "config-20260101-120000.json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configbackup.Load(dir, name); err == nil {
		t.Fatalf("Load(malformed) = nil error, want an error")
	}
}

// TestLoadLegacyDefaults checks the migration path: a config written
// before data_dir, the filter section and the DoH path existed loads
// with those fields defaulted and passes the daemon's validation.
func TestLoadLegacyDefaults(t *testing.T) {
	dir := t.TempDir()
	name := "config-20260101-120000.json"
	legacy := `{
  "version": 1,
  "domain": "legacy.example.test",
  "protocols": {
    "plain": {"enabled": true, "port": 5300},
    "doh": {"enabled": false, "port": 0},
    "dot": {"enabled": false, "port": 0},
    "doq": {"enabled": false, "port": 0}
  },
  "tls": {"mode": "self-signed"},
  "upstreams": [
    {"id": "up1", "name": "Upstream 1", "transport": "plain", "address": "1.1.1.1:53", "priority": 0, "enabled": true}
  ],
  "strategy": "fastest",
  "cache": {"size": 100, "min_ttl": 0, "max_ttl": 3600},
  "limits": {"plain_rps_per_ip": 10, "trusted_cidrs": []},
  "log": {"memory_entries": 100, "file": "", "max_file_size_bytes": 0}
}`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := configbackup.Load(dir, name)
	if err != nil {
		t.Fatalf("Load(legacy) = %v, want nil", err)
	}
	if cfg.DataDir != "/var/lib/mdns" {
		t.Errorf("DataDir = %q, want the default for old configs", cfg.DataDir)
	}
	if cfg.Filter.Mode != "zero" {
		t.Errorf("Filter.Mode = %q, want the default %q", cfg.Filter.Mode, "zero")
	}
	if cfg.Protocols.DoH.Path != config.DefaultDoHPath {
		t.Errorf("DoH path = %q, want the default %q", cfg.Protocols.DoH.Path, config.DefaultDoHPath)
	}
}

// TestPermissions pins the privacy modes: 0700 for the directory and
// 0600 for the snapshot (it carries the panel hash and the ACME EAB).
func TestPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backups")
	info, err := configbackup.Create(dir, testConfig(t), "")
	if err != nil {
		t.Fatalf("Create() = %v, want nil", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(filepath.Join(dir, info.Name))
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("snapshot mode = %o, want 600", got)
	}
}

// TestTraversalRejected refuses names that escape the directory or
// point at something that is not a snapshot file.
func TestTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape.json", "/etc/passwd", `..\escape.json`, "notes.txt", "", ".", "..", "config-20260101-120000.json/../x.json"} {
		_, err := configbackup.Load(dir, name)
		if err == nil {
			t.Errorf("Load(%q) = nil error, want a rejection", name)
		} else if !errors.Is(err, configbackup.ErrInvalidName) {
			t.Errorf("Load(%q) = %v, want ErrInvalidName", name, err)
		}
		err = configbackup.Delete(dir, name)
		if err == nil {
			t.Errorf("Delete(%q) = nil error, want a rejection", name)
		} else if !errors.Is(err, configbackup.ErrInvalidName) {
			t.Errorf("Delete(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

// TestMissingIsNotFound reports a vanished snapshot as ErrNotFound and
// fs.ErrNotExist, so the API can answer 400 while an I/O failure stays
// a 500.
func TestMissingIsNotFound(t *testing.T) {
	dir := t.TempDir()
	name := "config-20260101-120000.json"

	_, err := configbackup.Load(dir, name)
	if !errors.Is(err, configbackup.ErrNotFound) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Load(missing) = %v, want ErrNotFound and fs.ErrNotExist", err)
	}
	err = configbackup.Delete(dir, name)
	if !errors.Is(err, configbackup.ErrNotFound) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Delete(missing) = %v, want ErrNotFound and fs.ErrNotExist", err)
	}
}

// TestMalformedIsInvalid reports bad content as ErrInvalid, not an I/O
// failure.
func TestMalformedIsInvalid(t *testing.T) {
	dir := t.TempDir()
	name := "config-20260101-120000.json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configbackup.Load(dir, name); !errors.Is(err, configbackup.ErrInvalid) {
		t.Errorf("Load(malformed) = %v, want ErrInvalid", err)
	}
}
