package setup_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mydns/internal/config"
	"mydns/internal/setup"
	"mydns/internal/tui"
)

// Backend implements the wizard's environment.
var _ tui.WizardBackend = (*setup.Backend)(nil)

// TestLoadDefaultsWithoutFile checks the first-run path: no config file
// means defaults.
func TestLoadDefaultsWithoutFile(t *testing.T) {
	b := setup.NewLocalBackend(filepath.Join(t.TempDir(), "config.json"))

	cfg, err := b.Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if cfg.Domain != "mdns.test" {
		t.Errorf("default domain = %q, want the placeholder mdns.test", cfg.Domain)
	}
}

// TestSaveLoadRoundtrip checks that Save persists a valid config.
func TestSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	b := setup.NewLocalBackend(path)

	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	cfg.Filter.Enabled = true
	cfg.Filter.Lists = []config.FilterList{{ID: "oisd-small"}}

	if err := b.Save(cfg); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}

	loaded, err := b.Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if loaded.Domain != "dns.example.com" {
		t.Errorf("loaded domain = %q", loaded.Domain)
	}
	if len(loaded.Filter.Lists) != 1 || loaded.Filter.Lists[0].ID != "oisd-small" {
		t.Errorf("loaded lists = %+v", loaded.Filter.Lists)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() = %v, want nil", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("config mode = %v, want %v", got, want)
	}
}

// TestSaveRejectsInvalid checks validation before writing.
func TestSaveRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	b := setup.NewLocalBackend(path)

	cfg := config.Default()
	cfg.Domain = ""

	if err := b.Save(cfg); err == nil {
		t.Fatalf("Save(invalid) = nil, want an error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("config file exists after a rejected save")
	}
}

// TestProbeMeasures checks the backend's probe wiring with a local
// silent address (an immediate connection error is a Result, not a
// panic).
func TestProbeMeasures(t *testing.T) {
	b := setup.NewLocalBackend(filepath.Join(t.TempDir(), "config.json"))

	results := b.Probe(context.Background(), nil)
	if len(results) != 0 {
		t.Errorf("Probe(nil) = %d results, want 0", len(results))
	}
}
