// Package app wires the whole server from configuration: certificates,
// upstream transports, the health monitor, router, cache, query log
// and the listeners.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/dnsserver"
	"mydns/internal/filter"
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
	// FilterClient is the HTTP client for list downloads; nil uses the
	// production client (60s timeout).
	FilterClient *http.Client
	// FilterInterval overrides the configured update interval; 0 keeps
	// the configured one (hours; 0 hours means a single fetch at start).
	FilterInterval time.Duration
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

	filterEngine   *filter.Engine
	updater        *filter.Updater
	filterInterval time.Duration

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

	// The filter engine is optional: off by default, and its failure to
	// load cached data is never fatal (the updater will fetch fresh).
	var filterEngine *filter.Engine
	var updater *filter.Updater
	if cfg.Filter.Enabled {
		filterEngine = filter.NewEngine(filter.EngineOptions{
			UserAllow: cfg.Filter.UserAllow,
			UserBlock: cfg.Filter.UserBlock,
			Logger:    logger,
		})

		specs := make([]filter.ListSpec, 0, len(cfg.Filter.Lists))
		for _, l := range cfg.Filter.Lists {
			u := l.URL
			if u == "" {
				entry, ok := filter.EntryByID(l.ID)
				if !ok {
					closeUpstreams()
					return nil, fmt.Errorf("app: filter list %q is not in the catalog and has no url", l.ID)
				}
				u = entry.URL
			}
			specs = append(specs, filter.ListSpec{ID: l.ID, URL: u})
		}

		updater = filter.NewUpdater(filter.UpdaterOptions{
			Engine:  filterEngine,
			Specs:   specs,
			DataDir: cfg.DataDir,
			Client:  opts.FilterClient,
			Logger:  logger,
		})
		if err := updater.LoadFromDisk(); err != nil {
			logger.Warn("filter: loading cached lists failed", "error", err)
		}
	}

	var coreFilter core.Filter // nil when filtering is off; a typed nil must not enter the interface
	if filterEngine != nil {
		coreFilter = filterEngine
	}

	c := core.New(
		router,
		cache.New(cfg.Cache.Size, cfg.Cache.MinTTL, cfg.Cache.MaxTTL),
		queryLog,
		coreFilter,
		cfg.Filter.Mode,
		logger,
	)

	filterInterval := opts.FilterInterval
	if filterInterval <= 0 {
		filterInterval = time.Duration(cfg.Filter.UpdateIntervalHours) * time.Hour
	}

	return &App{
		server:         dnsserver.New(cfg, c, certs, limiter, logger),
		monitor:        upstream.NewMonitor(ups, opts.Monitor, logger),
		upstreams:      ups,
		queryLog:       queryLog,
		logger:         logger,
		core:           c,
		filterEngine:   filterEngine,
		updater:        updater,
		filterInterval: filterInterval,
	}, nil
}

// Start launches the health monitor and the list updater, then binds
// the listeners; on a bind failure everything stops and the error
// returns.
func (a *App) Start(ctx context.Context) error {
	appCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	go a.monitor.Run(appCtx)
	if a.updater != nil {
		go a.updater.Run(appCtx, a.filterInterval)
	}

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

// Filter exposes the block-list engine; nil when filtering is off.
func (a *App) Filter() *filter.Engine { return a.filterEngine }

// FilterStatus returns the per-list updater status; nil when filtering
// is off.
func (a *App) FilterStatus() []filter.ListStatus {
	if a.updater == nil {
		return nil
	}
	return a.updater.Status()
}
