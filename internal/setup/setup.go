// Package setup provides the local wizard environment: reading and
// writing the configuration file directly, before the daemon exists.
package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// Backend implements the wizard backend against the local filesystem.
type Backend struct {
	path string
}

// NewLocalBackend returns a backend writing to configPath.
func NewLocalBackend(configPath string) *Backend {
	return &Backend{path: configPath}
}

// Load reads the existing configuration or returns the defaults when
// none exists yet.
func (b *Backend) Load() (*config.Config, error) {
	cfg, err := config.Load(b.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Default(), nil
		}
		return nil, fmt.Errorf("setup: %w", err)
	}
	return cfg, nil
}

// Save validates and atomically writes the configuration, creating the
// directory when needed.
func (b *Backend) Save(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o755); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if err := cfg.Save(b.path); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	return nil
}

// Providers returns the resolver catalog.
func (b *Backend) Providers() []providers.Provider { return providers.List() }

// Probe measures endpoints like the running daemon would.
func (b *Backend) Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result {
	return probe.Measure(ctx, eps, probe.Options{})
}
