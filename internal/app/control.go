package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"mydns/internal/api"
	"mydns/internal/links"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
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

// wireEvents connects one runtime generation to the event bus.
func (a *App) wireEvents(rt *runtime) {
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
