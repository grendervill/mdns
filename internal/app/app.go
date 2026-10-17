// Package app wires the whole server from configuration: certificates,
// upstream transports, the health monitor, router, cache, query log
// and the listeners. The configuration can be updated at runtime:
// soft changes apply in place, structural ones rebuild the runtime
// with transactional rollback.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
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
	// ConfigPath is where UpdateConfig persists the configuration;
	// updates fail before changing anything when it is empty.
	ConfigPath string
}

// runtime is one assembled generation of the server components.
type runtime struct {
	server    *dnsserver.Server
	monitor   *upstream.Monitor
	upstreams []*upstream.Upstream
	queryLog  *qlog.Log
	core      *core.Core
	router    *routing.Router
	cache     *cache.Cache
	limiter   *ratelimit.Limiter

	filterEngine   *filter.Engine
	updater        *filter.Updater
	specs          []filter.ListSpec
	filterInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
}

// start binds the listeners and starts the background loops.
func (rt *runtime) start(parent context.Context) error {
	rt.ctx, rt.cancel = context.WithCancel(parent)

	go rt.monitor.Run(rt.ctx)
	if rt.updater != nil {
		go rt.updater.Run(rt.ctx, rt.filterInterval)
	}

	if err := rt.server.Start(rt.ctx); err != nil {
		rt.cancel()
		rt.cancel = nil
		return err
	}
	return nil
}

// stop shuts the listeners down and stops the background loops.
func (rt *runtime) stop(ctx context.Context) error {
	if rt.cancel != nil {
		rt.cancel()
		rt.cancel = nil
	}
	return rt.server.Shutdown(ctx)
}

// closeResources releases what outlives one generation: the query log
// (unless keep reuses it) and the upstream transports.
func (rt *runtime) closeResources(keep *runtime) {
	if rt.queryLog != nil && (keep == nil || keep.queryLog != rt.queryLog) {
		_ = rt.queryLog.Close()
	}
	for _, u := range rt.upstreams {
		_ = u.Transport().Close()
	}
}

// App is one assembled server instance. Start, Stop and UpdateConfig
// are safe for sequential use from one goroutine each.
type App struct {
	logger *slog.Logger
	opts   Options

	mu  sync.Mutex
	cfg *config.Config
	rt  *runtime

	appCtx context.Context
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

	rt, err := buildRuntime(cfg, nil, opts, logger)
	if err != nil {
		return nil, err
	}

	cfgCopy := *cfg
	return &App{logger: logger, opts: opts, cfg: &cfgCopy, rt: rt}, nil
}

// Start launches the background loops and binds the listeners; on a
// bind failure everything stops and the error returns.
func (a *App) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	appCtx, cancel := context.WithCancel(ctx)
	a.appCtx, a.cancel = appCtx, cancel
	if err := a.rt.start(appCtx); err != nil {
		cancel()
		a.cancel = nil
		return err
	}
	return nil
}

// Stop shuts the listeners down, stops the background loops and
// releases resources. It is safe to call after a failed Start.
func (a *App) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	err := a.rt.stop(ctx)
	a.rt.closeResources(nil)
	return err
}

// Core exposes the resolve pipeline; tests use it.
func (a *App) Core() *core.Core {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rt.core
}

// Filter exposes the block-list engine; nil when filtering is off.
func (a *App) Filter() *filter.Engine {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rt.filterEngine
}

// FilterStatus returns the per-list updater status; nil when filtering
// is off.
func (a *App) FilterStatus() []filter.ListStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rt.updater == nil {
		return nil
	}
	return a.rt.updater.Status()
}

// Config returns the current configuration.
func (a *App) Config() *config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// UpdateConfig validates, applies and persists a new configuration.
// Soft changes (strategy, cache, limits, filter mode and user rules)
// apply in place; structural changes (domain, TLS, protocols, ports,
// upstreams, log, filter lists) rebuild the runtime. On any failure the
// previous runtime keeps serving and the config file is untouched.
func (a *App) UpdateConfig(ctx context.Context, next *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := next.Validate(); err != nil {
		return fmt.Errorf("app: invalid config: %w", err)
	}
	if a.opts.ConfigPath == "" {
		return fmt.Errorf("app: no config path; cannot persist configuration")
	}

	old := a.cfg
	if !structuralChange(old, next) {
		return a.applySoft(old, next)
	}

	newRT, err := buildRuntime(next, a.rt, a.opts, a.logger)
	if err != nil {
		return err
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldRT := a.rt
	if err := oldRT.stop(stopCtx); err != nil {
		a.logger.Warn("app: stopping the old listeners", "error", err)
	}

	if a.appCtx != nil {
		if err := newRT.start(a.appCtx); err != nil {
			// Roll back to the previous runtime.
			if rerr := oldRT.start(a.appCtx); rerr != nil {
				a.logger.Error("app: rollback failed", "error", rerr)
				return fmt.Errorf("app: applying config: %w (rollback failed: %v)", err, rerr)
			}
			return fmt.Errorf("app: applying config: %w", err)
		}
	}

	if err := next.Save(a.opts.ConfigPath); err != nil {
		if a.appCtx != nil {
			_ = newRT.stop(stopCtx)
			if rerr := oldRT.start(a.appCtx); rerr != nil {
				a.logger.Error("app: rollback after save failure failed", "error", rerr)
			}
		}
		return fmt.Errorf("app: saving config: %w", err)
	}

	a.rt = newRT
	a.cfg = next
	oldRT.closeResources(newRT)
	return nil
}

// applySoft applies the non-structural changes in place, with a roll
// back when persisting fails. The caller must hold a.mu.
func (a *App) applySoft(old, next *config.Config) error {
	rt := a.rt

	if next.Strategy != old.Strategy {
		if err := rt.router.SetStrategy(next.Strategy); err != nil {
			return fmt.Errorf("app: strategy: %w", err)
		}
	}
	if next.Cache != old.Cache {
		rt.cache.SetSize(next.Cache.Size)
		rt.cache.SetLimits(next.Cache.MinTTL, next.Cache.MaxTTL)
	}
	if next.Limits.PlainRPSPerIP != old.Limits.PlainRPSPerIP ||
		!slices.Equal(next.Limits.TrustedCIDRs, old.Limits.TrustedCIDRs) {
		if err := rt.limiter.Reload(next.Limits.PlainRPSPerIP, next.Limits.TrustedCIDRs); err != nil {
			return fmt.Errorf("app: rate limit: %w", err)
		}
	}
	if next.Filter.Mode != old.Filter.Mode {
		rt.core.SetBlockMode(next.Filter.Mode)
	}
	if rt.filterEngine != nil &&
		(!slices.Equal(next.Filter.UserAllow, old.Filter.UserAllow) ||
			!slices.Equal(next.Filter.UserBlock, old.Filter.UserBlock)) {
		rt.filterEngine.SetUserRules(next.Filter.UserAllow, next.Filter.UserBlock)
	}
	if next.Filter.UpdateIntervalHours != old.Filter.UpdateIntervalHours && rt.updater != nil {
		rt.updater.SetInterval(a.filterIntervalFor(next))
		rt.filterInterval = a.filterIntervalFor(next)
	}

	if err := next.Save(a.opts.ConfigPath); err != nil {
		// Roll the applied changes back to the old values.
		_ = rt.router.SetStrategy(old.Strategy)
		rt.cache.SetSize(old.Cache.Size)
		rt.cache.SetLimits(old.Cache.MinTTL, old.Cache.MaxTTL)
		_ = rt.limiter.Reload(old.Limits.PlainRPSPerIP, old.Limits.TrustedCIDRs)
		rt.core.SetBlockMode(old.Filter.Mode)
		if rt.filterEngine != nil {
			rt.filterEngine.SetUserRules(old.Filter.UserAllow, old.Filter.UserBlock)
		}
		if rt.updater != nil {
			rt.updater.SetInterval(a.filterIntervalFor(old))
			rt.filterInterval = a.filterIntervalFor(old)
		}
		return fmt.Errorf("app: saving config: %w", err)
	}

	a.cfg = next
	return nil
}

// structuralChange reports whether applying next needs a runtime
// rebuild; everything else is a soft change.
func structuralChange(old, next *config.Config) bool {
	if old.Domain != next.Domain || old.TLS != next.TLS || old.Protocols != next.Protocols {
		return true
	}
	if !slices.Equal(old.Upstreams, next.Upstreams) {
		return true
	}
	if old.Log != next.Log || old.DataDir != next.DataDir {
		return true
	}
	if old.Filter.Enabled != next.Filter.Enabled || !slices.Equal(old.Filter.Lists, next.Filter.Lists) {
		return true
	}
	return false
}

// filterIntervalFor resolves the effective list update interval.
func (a *App) filterIntervalFor(cfg *config.Config) time.Duration {
	if a.opts.FilterInterval > 0 {
		return a.opts.FilterInterval
	}
	return time.Duration(cfg.Filter.UpdateIntervalHours) * time.Hour
}

// buildRuntime assembles a runtime generation. prev may be nil for the
// first generation; otherwise reusable pieces (the query log, the
// filter engine with its loaded lists) carry over.
func buildRuntime(cfg *config.Config, prev *runtime, opts Options, logger *slog.Logger) (*runtime, error) {
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

	queryLog := (*qlog.Log)(nil)
	if prev != nil && prev.queryLog != nil {
		queryLog = prev.queryLog // carry the journal across generations
	} else {
		queryLog, err = qlog.New(cfg.Log.MemoryEntries, cfg.Log.File, cfg.Log.MaxFileSizeBytes)
		if err != nil {
			closeUpstreams()
			return nil, fmt.Errorf("app: query log: %w", err)
		}
	}

	// The filter engine is optional: off by default, and its failure to
	// load cached data is never fatal (the updater will fetch fresh).
	var filterEngine *filter.Engine
	var updater *filter.Updater
	var specs []filter.ListSpec

	if cfg.Filter.Enabled {
		specs, err = listSpecs(cfg)
		if err != nil {
			closeUpstreams()
			return nil, err
		}

		if prev != nil && prev.filterEngine != nil {
			filterEngine = prev.filterEngine // loaded lists carry over
			filterEngine.SetUserRules(cfg.Filter.UserAllow, cfg.Filter.UserBlock)
		} else {
			filterEngine = filter.NewEngine(filter.EngineOptions{
				UserAllow: cfg.Filter.UserAllow,
				UserBlock: cfg.Filter.UserBlock,
				Logger:    logger,
			})
		}

		if prev != nil && prev.updater != nil && slices.Equal(prev.specs, specs) {
			updater = prev.updater
		} else {
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
	}

	var coreFilter core.Filter // nil when filtering is off; a typed nil must not enter the interface
	if filterEngine != nil {
		coreFilter = filterEngine
	}

	responseCache := cache.New(cfg.Cache.Size, cfg.Cache.MinTTL, cfg.Cache.MaxTTL)

	c := core.New(
		router,
		responseCache,
		queryLog,
		coreFilter,
		cfg.Filter.Mode,
		logger,
	)

	interval := opts.FilterInterval
	if interval <= 0 {
		interval = time.Duration(cfg.Filter.UpdateIntervalHours) * time.Hour
	}

	return &runtime{
		server:         dnsserver.New(cfg, c, certs, limiter, logger),
		monitor:        upstream.NewMonitor(ups, opts.Monitor, logger),
		upstreams:      ups,
		queryLog:       queryLog,
		core:           c,
		router:         router,
		cache:          responseCache,
		limiter:        limiter,
		filterEngine:   filterEngine,
		updater:        updater,
		specs:          specs,
		filterInterval: interval,
	}, nil
}

// listSpecs resolves the configured lists into fetch specs.
func listSpecs(cfg *config.Config) ([]filter.ListSpec, error) {
	specs := make([]filter.ListSpec, 0, len(cfg.Filter.Lists))
	for _, l := range cfg.Filter.Lists {
		u := l.URL
		if u == "" {
			entry, ok := filter.EntryByID(l.ID)
			if !ok {
				return nil, fmt.Errorf("app: filter list %q is not in the catalog and has no url", l.ID)
			}
			u = entry.URL
		}
		specs = append(specs, filter.ListSpec{ID: l.ID, URL: u})
	}
	return specs, nil
}
