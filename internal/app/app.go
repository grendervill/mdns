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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"mydns/internal/acmecert"
	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/core"
	"mydns/internal/dnsserver"
	"mydns/internal/filter"
	"mydns/internal/panel"
	"mydns/internal/qlog"
	"mydns/internal/ratelimit"
	"mydns/internal/routing"
	"mydns/internal/stats"
	"mydns/internal/tlscert"
	"mydns/internal/upstream"
	"mydns/internal/version"
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
	// SocketPath is where the control API listens; empty means
	// /run/mdns/mdns.sock.
	SocketPath string
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

	// certSource provides the TLS certificate; acmeMgr is the same
	// object when the source is the ACME manager. certDomain, certCfg
	// and dataDir scope the manager's reuse across generations: the
	// manager is bound to one domain, TLS section and cache directory.
	// challengeHTTP asks start to bind the ACME HTTP-01 responder on :80.
	certSource    tlscert.Source
	acmeMgr       *acmecert.Manager
	certDomain    string
	certCfg       config.TLS
	challengeHTTP bool

	// logCfg and dataDir scope resource reuse across generations: a
	// changed query-log config or data dir must rebuild its component.
	logCfg  config.LogConfig
	dataDir string

	bus    *api.Bus
	logger *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	// wg tracks the background loops the current generation's start
	// launched, so stop can wait for them: the ACME manager and the
	// filter updater write under the data directory. start replaces it
	// with a fresh group on every generation, so a stop that times out
	// (leaving a parked Wait) can never race a later generation's Add
	// on the same group — the same runtime is restarted on the
	// UpdateConfig rollback paths.
	wg *sync.WaitGroup
}

// goRun starts a tracked background loop. stop waits for every loop
// this way, so a caller that removes the data directory right after
// Stop cannot race the ACME manager or the filter updater writing into
// it. The group is captured at launch so a later generation replacing
// rt.wg cannot complete the wrong group.
func (rt *runtime) goRun(fn func()) {
	wg := rt.wg
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn()
	}()
}

// start binds the listeners and starts the background loops.
func (rt *runtime) start(parent context.Context) error {
	rt.ctx, rt.cancel = context.WithCancel(parent)
	rt.wg = new(sync.WaitGroup)

	rt.goRun(func() { rt.monitor.Run(rt.ctx) })
	if rt.updater != nil {
		rt.goRun(func() { rt.updater.Run(rt.ctx, rt.filterInterval) })
	}

	if err := rt.server.Start(rt.ctx); err != nil {
		rt.cancel()
		rt.cancel = nil
		return err
	}

	if err := rt.startCert(); err != nil {
		_ = rt.stop(context.Background())
		return err
	}
	return nil
}

// startCert wires the certificate lifecycle. In ACME mode the manager
// starts issuing in the background; unless DoH already terminates TLS
// on :443 (where the tls-alpn-01 challenge is served), the HTTP-01
// responder binds :80, as ACME validates by reaching the domain. The
// status loop runs for every source and stops with the runtime context.
func (rt *runtime) startCert() error {
	if rt.acmeMgr != nil {
		if rt.challengeHTTP {
			if err := rt.server.StartChallengeHTTP(rt.acmeMgr.HTTPHandler(), 80); err != nil {
				return fmt.Errorf("app: acme challenge listener: %w", err)
			}
		}
		rt.goRun(func() { rt.acmeMgr.Run(rt.ctx, nil) })
	}
	rt.goRun(func() { rt.certLoop(rt.ctx) })
	return nil
}

// certPollInterval is how often certLoop checks the certificate source.
const certPollInterval = time.Second

// certLoop watches the certificate source: it publishes status changes
// on the event bus and brings the TLS listeners up as soon as the
// source is ready (the ACME manager after its first issuance). The TLS
// listeners are normally already up for a static source, so the
// StartTLS call is a no-op there. It returns when ctx ends.
func (rt *runtime) certLoop(ctx context.Context) {
	ticker := time.NewTicker(certPollInterval)
	defer ticker.Stop()

	var prev tlscert.Status
	first := true
	for {
		st := rt.certSource.Status()
		if first || !sameCertStatus(prev, st) {
			first = false
			prev = st
			if rt.bus != nil {
				rt.bus.Publish(api.Event{Type: "cert", Data: st})
			}
		}

		if rt.certSource.Ready() && !rt.server.TLSStarted() {
			if err := rt.server.StartTLS(); err != nil {
				rt.logger.Warn("app: starting the TLS listeners", "error", err)
			} else {
				rt.logger.Info("app: TLS listeners started", "mode", st.Mode, "issuer", st.Issuer)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sameCertStatus compares two certificate statuses, ignoring the check
// time, which moves on every lookup without a real change.
func sameCertStatus(a, b tlscert.Status) bool {
	return a.Mode == b.Mode &&
		a.State == b.State &&
		a.Issuer == b.Issuer &&
		a.NotAfter.Equal(b.NotAfter) &&
		a.Error == b.Error
}

// stop shuts the listeners down and stops the background loops.
func (rt *runtime) stop(ctx context.Context) error {
	if rt.cancel != nil {
		rt.cancel()
		rt.cancel = nil
	}
	err := rt.server.Shutdown(ctx)

	// Wait for the background loops of this generation. The ACME
	// manager and the filter updater write into the data directory, so a
	// caller that removes it right after Stop (as the tests do) must not
	// race those writes. The wait honours ctx so a stuck loop cannot
	// hang shutdown forever. Wait on the snapshot: start may replace
	// rt.wg for a later generation while this Wait is still parked.
	wg := rt.wg
	if wg != nil {
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	return err
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

	// collector holds the cumulative query statistics. It belongs to
	// the App, not to a runtime generation: the counters cover the
	// whole run of the daemon, so a structural rebuild must not reset
	// them. Every generation's core is pointed at this one collector by
	// wireEvents.
	collector *stats.Collector

	// started is the time the app was constructed, reported as the
	// stats "since". New is where a daemon run begins.
	started time.Time

	bus     *api.Bus
	apiLn   net.Listener
	apiDone chan struct{}

	// panel is the admin web UI, mounted on the DoH listener. It lives
	// for the whole app, not one runtime generation: its sessions and
	// login throttle must survive a configuration rebuild, or applying
	// a settings change would log everybody out.
	panel *panel.Panel

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

	bus := api.NewBus()
	rt, err := buildRuntime(cfg, nil, opts, logger, bus)
	if err != nil {
		return nil, err
	}

	cfgCopy := *cfg
	a := &App{
		logger:    logger,
		opts:      opts,
		cfg:       &cfgCopy,
		rt:        rt,
		bus:       bus,
		collector: stats.NewCollector(),
		started:   time.Now(),
	}
	a.wireEvents(rt)

	a.panel = panel.New(panel.Options{
		Ctrl:    a,
		Version: version.String(),
		Logger:  logger,
		Auth:    a.panelAuth,
	})
	rt.server.SetPanel(a.panel)
	return a, nil
}

// panelAuth reports the panel's live enabled flag and password hash from
// the current configuration. The panel asks on every request, so a
// password change from the panel (Task 9) takes effect without a
// restart. Changing the hash does not revoke the live sessions: a
// browser that is already signed in keeps its cookie until it expires
// or the admin logs out.
func (a *App) panelAuth() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Panel.Enabled, a.cfg.Panel.PasswordHash
}

// Start launches the background loops, binds the listeners and serves
// the control API; on any bind failure everything stops and the error
// returns.
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

	if err := a.startAPI(appCtx); err != nil {
		_ = a.rt.stop(context.Background())
		a.rt.closeResources(nil)
		cancel()
		a.cancel = nil
		return err
	}

	go a.publishUpstreams(appCtx)
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

	// Wait for the control API goroutine so its socket is gone by the
	// time Stop returns.
	if a.apiDone != nil {
		select {
		case <-a.apiDone:
		case <-ctx.Done():
		}
		a.apiDone = nil
		a.apiLn = nil
	}

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

	newRT, err := buildRuntime(next, a.rt, a.opts, a.logger, a.bus)
	if err != nil {
		return err
	}
	// The panel persists across generations; hand it to the freshly
	// built DoH listener before that listener starts.
	newRT.server.SetPanel(a.panel)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldRT := a.rt
	if err := oldRT.stop(stopCtx); err != nil {
		a.logger.Warn("app: stopping the old listeners", "error", err)
	}

	if a.appCtx != nil {
		if err := newRT.start(a.appCtx); err != nil {
			// Roll back to the previous runtime; the half-started one
			// must not leak its transports or a freshly opened log.
			newRT.closeResources(oldRT)
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
		newRT.closeResources(oldRT) // discarded without ever going live
		return fmt.Errorf("app: saving config: %w", err)
	}

	a.rt = newRT
	a.cfg = next
	a.wireEvents(newRT)
	oldRT.closeResources(newRT)
	a.bus.Publish(api.Event{Type: "filter", Data: a.filterSnapshotLocked()})
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
	a.bus.Publish(api.Event{Type: "filter", Data: a.filterSnapshotLocked()})
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
// filter engine with its loaded lists, the ACME manager) carry over.
func buildRuntime(cfg *config.Config, prev *runtime, opts Options, logger *slog.Logger, bus *api.Bus) (*runtime, error) {
	certSource, acmeMgr, err := buildCertSource(cfg, prev, logger)
	if err != nil {
		return nil, err
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
	if prev != nil && prev.queryLog != nil && prev.logCfg == cfg.Log {
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

			// Lists dropped from the config must stop blocking right
			// away instead of lingering until a restart.
			want := make(map[string]struct{}, len(specs))
			for _, s := range specs {
				want[s.ID] = struct{}{}
			}
			for _, st := range filterEngine.Stats().Lists {
				if _, ok := want[st.ID]; !ok {
					filterEngine.RemoveList(st.ID)
				}
			}
		} else {
			filterEngine = filter.NewEngine(filter.EngineOptions{
				UserAllow: cfg.Filter.UserAllow,
				UserBlock: cfg.Filter.UserBlock,
				Logger:    logger,
			})
		}

		if prev != nil && prev.updater != nil && prev.dataDir == cfg.DataDir && slices.Equal(prev.specs, specs) {
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
		server:         dnsserver.New(cfg, c, certSource, limiter, logger),
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
		certSource:     certSource,
		acmeMgr:        acmeMgr,
		certDomain:     cfg.Domain,
		certCfg:        cfg.TLS,
		challengeHTTP:  acmeMgr != nil && !(cfg.Protocols.DoH.Enabled && cfg.Protocols.DoH.Port == 443),
		logCfg:         cfg.Log,
		dataDir:        cfg.DataDir,
		bus:            bus,
		logger:         logger,
	}, nil
}

// buildCertSource assembles the certificate source for a generation: a
// static store for files/self-signed, an ACME manager for acme mode.
// The manager carries over from prev when it still matches the
// configuration (see reuseACMEManager), so a rebuild for another
// section does not restart issuance; a structural certificate change
// builds a new one.
func buildCertSource(cfg *config.Config, prev *runtime, logger *slog.Logger) (tlscert.Source, *acmecert.Manager, error) {
	if cfg.TLS.Mode != "acme" {
		store, err := tlscert.New(cfg.TLS, cfg.Domain)
		if err != nil {
			return nil, nil, fmt.Errorf("app: certificates: %w", err)
		}
		return store, nil, nil
	}

	if reuseACMEManager(prev, cfg) {
		return prev.acmeMgr, prev.acmeMgr, nil
	}

	dir, err := cfg.TLS.ACMEDirectoryURL()
	if err != nil {
		return nil, nil, fmt.Errorf("app: acme: %w", err)
	}

	opts := acmecert.Options{
		Domain:             cfg.Domain,
		Email:              cfg.TLS.ACME.Email,
		DirectoryURL:       dir,
		CacheDir:           filepath.Join(cfg.DataDir, "certs", "acme"),
		InsecureSkipVerify: cfg.TLS.ACME.InsecureSkipVerify,
		Logger:             logger,
	}
	opts.BackoffMin, opts.BackoffMax = acmeBackoffFromEnv()
	if cfg.TLS.ACME.EABKeyID != "" || cfg.TLS.ACME.EABHMAC != "" {
		eab, err := acmecert.ParseEAB(cfg.TLS.ACME.EABKeyID, cfg.TLS.ACME.EABHMAC)
		if err != nil {
			return nil, nil, fmt.Errorf("app: acme: %w", err)
		}
		opts.EAB = eab
	}

	m, err := acmecert.New(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("app: acme: %w", err)
	}
	return m, m, nil
}

// reuseACMEManager reports whether the previous generation's ACME
// manager can serve this configuration. The manager is bound to one
// domain (the ACME HostPolicy and the name it fetches), one TLS section
// and one cache directory, so any of those changing needs a fresh
// manager; the caller has already established that cfg selects acme
// mode.
func reuseACMEManager(prev *runtime, cfg *config.Config) bool {
	if prev == nil || prev.acmeMgr == nil {
		return false
	}
	return prev.certDomain == cfg.Domain && prev.certCfg == cfg.TLS && prev.dataDir == cfg.DataDir
}

// acmeBackoffFromEnv reads the test-only backoff overrides
// MDNS_ACME_BACKOFF_MIN and MDNS_ACME_BACKOFF_MAX (Go duration strings,
// e.g. "5s"). A malformed value is ignored so the manager keeps its
// default, which is what production wants.
func acmeBackoffFromEnv() (min, max time.Duration) {
	min, _ = time.ParseDuration(os.Getenv("MDNS_ACME_BACKOFF_MIN"))
	max, _ = time.ParseDuration(os.Getenv("MDNS_ACME_BACKOFF_MAX"))
	return min, max
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
