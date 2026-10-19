package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/configbackup"
	"mydns/internal/links"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
	"mydns/internal/stats"
	"mydns/internal/upstream"
	"mydns/internal/version"
)

// defaultSocketPath is where the control API listens in production.
const defaultSocketPath = "/run/mdns/mdns.sock"

// upstreamEventInterval paces the live upstream snapshots.
const upstreamEventInterval = time.Second

// Events exposes the live event bus (requests, upstreams, filter).
func (a *App) Events() *api.Bus { return a.bus }

// Status implements api.Controller: the read-only snapshot.
func (a *App) Status(context.Context) (api.Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statusLocked(), nil
}

// statusLocked builds the snapshot. The caller must hold a.mu.
func (a *App) statusLocked() api.Status {
	cfg := a.cfg
	rt := a.rt

	st := api.Status{
		Version:   version.String(),
		Domain:    cfg.Domain,
		Links:     links.Links(cfg),
		Listeners: rt.server.Listeners(),
		Strategy:  cfg.Strategy,
		Upstreams: a.upstreamStatusesLocked(),
		Cache:     rt.cache.Stats(),
		Filter:    a.filterSnapshotLocked(),
		Cert:      rt.certSource.Status(),
	}
	return st
}

// upstreamStatusesLocked snapshots every upstream. The caller must
// hold a.mu.
func (a *App) upstreamStatusesLocked() []api.UpstreamStatus {
	out := make([]api.UpstreamStatus, 0, len(a.rt.upstreams))
	for _, u := range a.rt.upstreams {
		sent, failed := u.Stats()
		out = append(out, api.UpstreamStatus{
			ID:        u.ID,
			Name:      u.Name,
			Transport: u.Transport().Name(),
			Address:   u.Address,
			Enabled:   u.Enabled(),
			Healthy:   u.Status() == upstream.Healthy,
			LatencyMS: float64(u.EWMA().Microseconds()) / 1000,
			Sent:      sent,
			Failed:    failed,
		})
	}
	return out
}

// filterSnapshotLocked snapshots the filter state. The caller must
// hold a.mu.
func (a *App) filterSnapshotLocked() api.FilterSnapshot {
	cfg := a.cfg
	if a.rt.filterEngine == nil {
		return api.FilterSnapshot{Enabled: false, Mode: cfg.Filter.Mode}
	}
	fs := a.rt.filterEngine.Stats()
	return api.FilterSnapshot{
		Enabled:      true,
		Mode:         cfg.Filter.Mode,
		TotalBlocked: fs.TotalBlocked,
		Lists:        fs.Lists,
	}
}

// Providers implements api.Controller.
func (a *App) Providers() []providers.Provider { return providers.List() }

// Probe implements api.Controller.
func (a *App) Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result {
	return probe.Measure(ctx, eps, probe.Options{})
}

// Requests implements api.Controller.
func (a *App) Requests(n int) []qlog.Entry {
	a.mu.Lock()
	queryLog := a.rt.queryLog
	a.mu.Unlock()
	return queryLog.Recent(n)
}

// Stats implements api.Controller: the cumulative query statistics. The
// collector outlives every runtime generation, so the counters cover the
// whole run of the daemon.
func (a *App) Stats() stats.Snapshot { return a.collector.Snapshot() }

// StatsRange returns the query statistics summed over the whole UTC days
// in [from, to] inclusive; a zero bound is open. The panel builds the
// period diagrams from it while the gauges keep the cumulative Snapshot.
func (a *App) StatsRange(from, to time.Time) stats.Snapshot {
	return a.collector.SnapshotRange(from, to)
}

// Started implements api.Controller: the time the app was constructed,
// which the API reports as the stats "since".
func (a *App) Started() time.Time { return a.started }

// RequestsQuery implements api.Controller: one page of filtered history,
// newest first. page is 1-based and per is the page size; both are
// clamped defensively (the API clamps per to [1,500] before calling).
func (a *App) RequestsQuery(q qlog.Query, page, per int) ([]qlog.Entry, int) {
	if page < 1 {
		page = 1
	}
	if per < 1 {
		per = 1
	}

	a.mu.Lock()
	queryLog := a.rt.queryLog
	a.mu.Unlock()
	return queryLog.Query(q, (page-1)*per, per)
}

// FilterUpdate implements api.Controller: a manual list refresh.
func (a *App) FilterUpdate(ctx context.Context, id string) error {
	a.mu.Lock()
	updater := a.rt.updater
	a.mu.Unlock()

	if updater == nil {
		return fmt.Errorf("app: filtering is disabled")
	}

	err := updater.UpdateOne(ctx, id)

	a.mu.Lock()
	snapshot := a.filterSnapshotLocked()
	a.mu.Unlock()
	a.bus.Publish(api.Event{Type: "filter", Data: snapshot})

	return err
}

// backupDir is where the snapshots of one configuration live: a
// "backups" directory under its data directory.
func backupDir(cfg *config.Config) string {
	return filepath.Join(cfg.DataDir, "backups")
}

// backupLabelPreRestore is the label of the undo snapshot a restore
// takes of the configuration it replaces. Automatic pre-change ones are
// labelled "auto", panel-created ones "manual".
const backupLabelPreRestore = "pre-restore"

// CreateConfigBackup stores a snapshot of the current configuration in
// DataDir/backups. The snapshot keeps the daemon's exact on-disk format
// and is migrated and validated when restored.
func (a *App) CreateConfigBackup(label string) error {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	if _, err := configbackup.Create(backupDir(cfg), cfg, label); err != nil {
		return fmt.Errorf("app: creating a config backup: %w", err)
	}
	return nil
}

// ListConfigBackups returns the stored snapshots, newest first.
func (a *App) ListConfigBackups() ([]configbackup.Info, error) {
	a.mu.Lock()
	dir := backupDir(a.cfg)
	a.mu.Unlock()

	infos, err := configbackup.List(dir)
	if err != nil {
		return nil, fmt.Errorf("app: listing config backups: %w", err)
	}
	return infos, nil
}

// RestoreConfigBackup applies a stored snapshot through UpdateConfig,
// so the restore runs the daemon's normal load, migration and
// validation path and is as transactional as any other config change.
// The current config is snapshotted first, which makes the restore
// itself undoable; a snapshot or validation failure leaves the running
// daemon untouched.
func (a *App) RestoreConfigBackup(name string) error {
	a.mu.Lock()
	dir := backupDir(a.cfg)
	a.mu.Unlock()

	restored, err := configbackup.Load(dir, name)
	if err != nil {
		return fmt.Errorf("app: loading config backup: %w", err)
	}
	if err := a.CreateConfigBackup(backupLabelPreRestore); err != nil {
		return err
	}
	return a.updateConfig(context.Background(), restored, false)
}

// DeleteConfigBackup removes one stored snapshot.
func (a *App) DeleteConfigBackup(name string) error {
	a.mu.Lock()
	dir := backupDir(a.cfg)
	a.mu.Unlock()

	if err := configbackup.Delete(dir, name); err != nil {
		return fmt.Errorf("app: deleting config backup: %w", err)
	}
	return nil
}

// wireEvents connects one runtime generation to the event bus and to
// the cumulative statistics. The collector is owned by the App: it is
// deliberately not recreated per generation, so the counters stay
// "since start" across a configuration rebuild.
func (a *App) wireEvents(rt *runtime) {
	if rt.core != nil {
		rt.core.SetObserver(a.collector)
	}
	if rt.queryLog == nil {
		return
	}
	rt.queryLog.SetObserver(func(e qlog.Entry) {
		a.bus.Publish(api.Event{Type: "requests", Data: e})
	})
}

// startAPI binds the control socket and serves the API until ctx ends.
func (a *App) startAPI(ctx context.Context) error {
	socketPath := a.opts.SocketPath
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("app: control socket directory: %w", err)
	}
	// Remove a stale socket left behind by a previous crash.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("app: removing the stale control socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("app: control socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("app: control socket permissions: %w", err)
	}

	srv := api.New(a, a.bus, a.logger, api.ServerOptions{})
	a.apiLn = ln
	a.apiDone = make(chan struct{})

	go func() {
		defer close(a.apiDone)
		if err := srv.Serve(ctx, ln); err != nil {
			a.logger.Warn("app: control API stopped", "error", err)
		}
	}()
	return nil
}

// statsSaveInterval paces the periodic persistence of the statistics
// history. Stop also saves once, so a clean shutdown never loses more
// than this interval of observations.
const statsSaveInterval = 30 * time.Second

// saveStatsLoop persists the cumulative counters and the daily history
// on a ticker until ctx ends. A failed write is logged and the loop
// keeps going: persistence is a convenience, not a correctness
// requirement for the live daemon. It closes done on the way out, so
// Stop can join it before the final Save.
func (a *App) saveStatsLoop(ctx context.Context, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(statsSaveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.collector.Save(a.statsPath); err != nil {
				a.logger.Warn("app: saving the query statistics history", "error", err)
			}
		}
	}
}

// publishUpstreams pushes upstream snapshots to the bus every second
// until ctx ends.
func (a *App) publishUpstreams(ctx context.Context) {
	ticker := time.NewTicker(upstreamEventInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.mu.Lock()
			data := a.upstreamStatusesLocked()
			a.mu.Unlock()
			a.bus.Publish(api.Event{Type: "upstreams", Data: data})
		}
	}
}
