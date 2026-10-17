// Package app wires the whole server from configuration: certificates,
// upstream transports, the health monitor, router, cache, query log
// and the listeners.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/dnsserver"
	"mydns/internal/qlog"
	"mydns/internal/ratelimit"
	"mydns/internal/routing"
	"mydns/internal/tlscert"
	"mydns/internal/upstream"
)

// Options adjust the app for tests; zero values mean production
// defaults.
type Options struct {
	// Monitor tunes the health probing cadence.
	Monitor upstream.MonitorOptions
}

// App is one assembled server instance. Start and Stop are not meant
// to race each other.
type App struct {
	server    *dnsserver.Server
	monitor   *upstream.Monitor
	upstreams []*upstream.Upstream
	queryLog  *qlog.Log
	logger    *slog.Logger
	core      *core.Core

	cancel context.CancelFunc
}

// New validates cfg and builds every component; nothing binds until
// Start.
func New(cfg *config.Config, opts Options, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("app: invalid config: %w", err)
	}

	certs, err := tlscert.New(cfg.TLS, cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("app: certificates: %w", err)
	}

	ups := make([]*upstream.Upstream, 0, len(cfg.Upstreams))
	closeUpstreams := func() {
		for _, u := range ups {
			_ = u.Transport().Close()
		}
	}
	for _, uc := range cfg.Upstreams {
		u, err := upstream.New(uc)
		if err != nil {
			closeUpstreams()
			return nil, fmt.Errorf("app: upstream %q: %w", uc.ID, err)
		}
		ups = append(ups, u)
	}

	router, err := routing.New(ups, cfg.Strategy)
	if err != nil {
		closeUpstreams()
		return nil, fmt.Errorf("app: router: %w", err)
	}

	limiter, err := ratelimit.New(cfg.Limits.PlainRPSPerIP, cfg.Limits.TrustedCIDRs, nil)
	if err != nil {
		closeUpstreams()
		return nil, fmt.Errorf("app: rate limiter: %w", err)
	}

	queryLog, err := qlog.New(cfg.Log.MemoryEntries, cfg.Log.File, cfg.Log.MaxFileSizeBytes)
	if err != nil {
		closeUpstreams()
		return nil, fmt.Errorf("app: query log: %w", err)
	}

	c := core.New(
		router,
		cache.New(cfg.Cache.Size, cfg.Cache.MinTTL, cfg.Cache.MaxTTL),
		queryLog,
		nil, // the filter engine joins here in the next task
		cfg.Filter.Mode,
		logger,
	)

	return &App{
		server:    dnsserver.New(cfg, c, certs, limiter, logger),
		monitor:   upstream.NewMonitor(ups, opts.Monitor, logger),
		upstreams: ups,
		queryLog:  queryLog,
		logger:    logger,
		core:      c,
	}, nil
}

// Start launches the health monitor and binds the listeners; on a
// bind failure the monitor stops and the error returns.
func (a *App) Start(ctx context.Context) error {
	appCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	go a.monitor.Run(appCtx)

	if err := a.server.Start(appCtx); err != nil {
		cancel()
		return err
	}
	return nil
}

// Stop shuts the listeners down, stops the monitor and releases
// resources. It is safe to call after a failed Start.
func (a *App) Stop(ctx context.Context) error {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}

	err := a.server.Shutdown(ctx)
	if cerr := a.queryLog.Close(); err == nil {
		err = cerr
	}
	for _, u := range a.upstreams {
		_ = u.Transport().Close()
	}
	return err
}

// Core exposes the resolve pipeline; tests use it.
func (a *App) Core() *core.Core { return a.core }
