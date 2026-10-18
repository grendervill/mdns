package app_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
)

// TestAppCollectsStats checks the app wiring: queries served by the
// running pipeline feed the cumulative collector, and a structural
// config rebuild — which replaces the whole runtime — does not reset
// the counters, because they belong to the daemon, not to a generation.
func TestAppCollectsStats(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	a, _ := startApp(t, cfg)

	ask := func(name string) {
		t.Helper()
		cl := &dns.Client{Net: "udp", Timeout: time.Second}
		if _, _, err := cl.Exchange(query(name), loopback(port)); err != nil {
			t.Fatalf("Exchange(%s) = %v, want nil", name, err)
		}
	}

	ask("one.example.com") // forwarded to the fake upstream
	ask("one.example.com") // ...then served from the cache
	ask("two.example.com") // forwarded

	snap := a.Stats()
	if snap.Total != 3 {
		t.Fatalf("Total before the update = %d, want 3", snap.Total)
	}
	if snap.Outcomes["upstream"] != 2 || snap.Outcomes["cached"] != 1 {
		t.Errorf("Outcomes before the update = %v, want 2 upstream and 1 cached", snap.Outcomes)
	}
	if snap.Upstreams["fake"] != 2 {
		t.Errorf("Upstreams before the update = %v, want the fake counted twice", snap.Upstreams)
	}
	if snap.Protos["udp"] != 3 {
		t.Errorf("Protos before the update = %v, want udp counted 3 times", snap.Protos)
	}

	// A log change is structural: UpdateConfig swaps in a new runtime
	// with a fresh cache and core. The counters must carry over.
	next := *cfg
	next.Log.MemoryEntries = cfg.Log.MemoryEntries + 1
	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	ask("one.example.com") // the rebuilt cache is cold: forwarded again

	snap = a.Stats()
	if snap.Total != 4 {
		t.Errorf("Total after the update = %d, want 4 (counters survive a rebuild)", snap.Total)
	}
	if snap.Upstreams["fake"] != 3 {
		t.Errorf("Upstreams after the update = %v, want the fake counted 3 times", snap.Upstreams)
	}
}

// TestAppStatsPersistAcrossRestart checks the file wiring end to end:
// the history is saved on Stop and reloaded by a fresh App over the same
// data directory, so the counters survive a daemon restart.
func TestAppStatsPersistAcrossRestart(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("cfg.Save() = %v, want nil", err)
	}

	ask := func(name string) {
		t.Helper()
		cl := &dns.Client{Net: "udp", Timeout: time.Second}
		if _, _, err := cl.Exchange(query(name), loopback(port)); err != nil {
			t.Fatalf("Exchange(%s) = %v, want nil", name, err)
		}
	}

	// First run: serve two queries, then Stop persists the history.
	opts := testOptions(t)
	opts.ConfigPath = cfgPath
	a, err := app.New(cfg, opts, discardLogger())
	if err != nil {
		t.Fatalf("app.New() = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := a.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start() = %v, want nil", err)
	}
	ask("one.example.com")
	ask("two.example.com")

	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := a.Stop(sctx); err != nil {
		scancel()
		cancel()
		t.Fatalf("Stop() = %v, want nil", err)
	}
	scancel()
	cancel()

	// Second run over the same data directory: the counters carried over.
	opts2 := testOptions(t)
	opts2.ConfigPath = cfgPath
	a2, err := app.New(cfg, opts2, discardLogger())
	if err != nil {
		t.Fatalf("app.New() on restart = %v, want nil", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	if err := a2.Start(ctx2); err != nil {
		cancel2()
		t.Fatalf("Start() on restart = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = a2.Stop(sctx)
		cancel2()
	})

	if got := a2.Stats().Total; got != 2 {
		t.Errorf("Total after restart = %d, want 2 (history must survive)", got)
	}
	if got := a2.StatsRange(time.Time{}, time.Time{}).Total; got != 2 {
		t.Errorf("range Total after restart = %d, want 2", got)
	}
}
