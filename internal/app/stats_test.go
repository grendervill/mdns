package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
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

	snap := a.CollectorForTests().Snapshot()
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

	snap = a.CollectorForTests().Snapshot()
	if snap.Total != 4 {
		t.Errorf("Total after the update = %d, want 4 (counters survive a rebuild)", snap.Total)
	}
	if snap.Upstreams["fake"] != 3 {
		t.Errorf("Upstreams after the update = %v, want the fake counted 3 times", snap.Upstreams)
	}
}
