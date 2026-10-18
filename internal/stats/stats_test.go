package stats

import (
	"fmt"
	"sync"
	"testing"

	"mydns/internal/qlog"
)

// otherBucketLabel pins the literal the snapshot must use for the
// overflow row: the panel renders it verbatim.
const otherBucketLabel = "остальные"

// assertCounts compares a counter map and reports every difference.
func assertCounts(t *testing.T, name string, got, want map[string]uint64) {
	t.Helper()

	if len(got) != len(want) {
		t.Errorf("%s size = %d (%v), want %d (%v)", name, len(got), got, len(want), want)
		return
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s[%q] = %d, want %d", name, k, got[k], w)
		}
	}
}

// TestCollectorOutcomes pins the classification rule that ruling R7
// deliberately duplicates from qlog's unexported helper: a blocked
// request stays blocked even when it also hit the cache or an upstream,
// a cache hit outranks an upstream answer, an entry with no source at
// all is an error, and the rcode is never consulted.
func TestCollectorOutcomes(t *testing.T) {
	c := NewCollector()

	for _, e := range []qlog.Entry{
		{Blocked: true},
		{Blocked: true, CacheHit: true},
		{Blocked: true, Upstream: "u1"},
		{CacheHit: true},
		{CacheHit: true, Upstream: "u1"},
		{Upstream: "u1"},
		{Upstream: "u1", Rcode: 2}, // the rcode does not demote an upstream answer
		{Rcode: 2},                 // typically a SERVFAIL resolved by nobody
		{},                         // a zero entry is an error too
	} {
		c.Observe(e)
	}

	snap := c.Snapshot()
	if snap.Total != 9 {
		t.Fatalf("Total = %d, want 9", snap.Total)
	}
	assertCounts(t, "Outcomes", snap.Outcomes, map[string]uint64{
		"blocked":  3,
		"cached":   2,
		"upstream": 2,
		"error":    2,
	})
}

// TestCollectorSnapshotEmpty checks the shape of a snapshot taken
// before any query: zeroed totals, the four outcome keys already
// present (the panel renders one diagram per outcome), and non-nil
// collections so the API marshals {} and [] instead of null.
func TestCollectorSnapshotEmpty(t *testing.T) {
	snap := NewCollector().Snapshot()

	if snap.Total != 0 {
		t.Errorf("Total = %d, want 0", snap.Total)
	}
	assertCounts(t, "Outcomes", snap.Outcomes, map[string]uint64{
		"blocked": 0, "cached": 0, "upstream": 0, "error": 0,
	})
	if snap.Protos == nil || snap.Upstreams == nil || snap.Clients == nil {
		t.Fatalf("empty snapshot has nil collections: %+v", snap)
	}
	if len(snap.Protos) != 0 || len(snap.Upstreams) != 0 || len(snap.Clients) != 0 {
		t.Errorf("empty snapshot is not empty: %+v", snap)
	}
}

// TestCollectorProtosUpstreams checks the protocol and upstream
// counters; an entry without a protocol, client or upstream must not
// create an empty-key row.
func TestCollectorProtosUpstreams(t *testing.T) {
	c := NewCollector()
	c.Observe(qlog.Entry{Proto: "udp", Upstream: "u1", ClientIP: "1.1.1.1"})
	c.Observe(qlog.Entry{Proto: "udp", Upstream: "u2", ClientIP: "1.1.1.1"})
	c.Observe(qlog.Entry{Proto: "doh", Upstream: "u1", ClientIP: "1.1.1.1"})
	c.Observe(qlog.Entry{}) // a malformed request: no proto, no client, no upstream

	snap := c.Snapshot()
	assertCounts(t, "Protos", snap.Protos, map[string]uint64{"udp": 2, "doh": 1})
	assertCounts(t, "Upstreams", snap.Upstreams, map[string]uint64{"u1": 2, "u2": 1})
	if len(snap.Clients) != 1 || snap.Clients[0].IP != "1.1.1.1" || snap.Clients[0].Count != 3 {
		t.Errorf("Clients = %+v, want one row 1.1.1.1 with 3", snap.Clients)
	}
}

// TestCollectorTopClients checks the top list: 25 clients with counts
// 1..25 become the 20 busiest rows, sorted descending, plus the
// overflow bucket carrying the sum of the five dropped counts.
func TestCollectorTopClients(t *testing.T) {
	c := NewCollector()

	for i := 1; i <= 25; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		for j := 0; j < i; j++ {
			c.Observe(qlog.Entry{ClientIP: ip, Proto: "udp"})
		}
	}

	snap := c.Snapshot()
	if snap.Total != 325 { // 1+2+...+25
		t.Fatalf("Total = %d, want 325", snap.Total)
	}

	clients := snap.Clients
	if len(clients) != 21 {
		t.Fatalf("len(Clients) = %d, want 21 (top-20 + %q)", len(clients), otherBucketLabel)
	}
	for i := 0; i < 20; i++ {
		wantIP := fmt.Sprintf("10.0.0.%d", 25-i)
		wantCount := uint64(25 - i)
		if clients[i].IP != wantIP || clients[i].Count != wantCount {
			t.Errorf("Clients[%d] = %+v, want {%s %d}", i, clients[i], wantIP, wantCount)
		}
		if i > 0 && clients[i-1].Count < clients[i].Count {
			t.Errorf("Clients not sorted descending at %d: %d before %d", i, clients[i-1].Count, clients[i].Count)
		}
	}

	last := clients[20]
	if last.IP != otherBucketLabel {
		t.Fatalf("last row = %+v, want the %q bucket", last, otherBucketLabel)
	}
	if want := uint64(1 + 2 + 3 + 4 + 5); last.Count != want {
		t.Errorf("%q = %d, want %d (the sum of the dropped counts)", otherBucketLabel, last.Count, want)
	}

	var sum uint64
	for _, cl := range clients {
		sum += cl.Count
	}
	if sum != snap.Total {
		t.Errorf("client counts sum to %d, want the total %d", sum, snap.Total)
	}
}

// TestCollectorCap checks the memory bound: more distinct addresses
// than the cap neither grow the client map nor lose a single query —
// everything beyond the cap lands in the overflow bucket, including
// later repeats of an unknown address. The snapshot's bucket row is the
// sum of every count outside the top-20, so it carries both the
// untracked addresses and the tracked tail.
func TestCollectorCap(t *testing.T) {
	const unique = 5000
	c := NewCollector()

	for i := 0; i < unique; i++ {
		c.Observe(qlog.Entry{ClientIP: fmt.Sprintf("10.0.%d.%d", i/256, i%256)})
	}

	if got := len(c.clients); got != maxClients {
		t.Fatalf("tracked clients = %d, want the cap %d", got, maxClients)
	}
	if got, want := c.overflow, uint64(unique-maxClients); got != want {
		t.Fatalf("overflow = %d, want %d (addresses beyond the cap)", got, want)
	}

	snap := c.Snapshot()
	if snap.Total != unique {
		t.Errorf("Total = %d, want %d", snap.Total, unique)
	}
	if len(snap.Clients) != topClients+1 {
		t.Fatalf("len(Clients) = %d, want %d (top-20 + %q)", len(snap.Clients), topClients+1, otherBucketLabel)
	}
	// Everything but the 20 busiest single-hit addresses is aggregated.
	if got, want := snap.Clients[topClients].Count, uint64(unique-topClients); got != want {
		t.Errorf("%q = %d, want %d", otherBucketLabel, got, want)
	}

	// An address first seen after the cap is full is never tracked: its
	// repeats only grow the overflow counter.
	for j := 0; j < 10; j++ {
		c.Observe(qlog.Entry{ClientIP: "10.9.9.9"})
	}
	if got := len(c.clients); got != maxClients {
		t.Errorf("tracked clients after repeats = %d, want the cap %d", got, maxClients)
	}
	if got, want := c.overflow, uint64(unique-maxClients+10); got != want {
		t.Errorf("overflow after repeats = %d, want %d", got, want)
	}

	snap = c.Snapshot()
	if snap.Total != unique+10 {
		t.Errorf("Total after repeats = %d, want %d", snap.Total, unique+10)
	}
	for i, cl := range snap.Clients[:topClients] {
		if cl.Count != 1 {
			t.Errorf("Clients[%d] = %+v, want the untracked address to be absent from the top list", i, cl)
		}
	}
	if got, want := snap.Clients[topClients].Count, uint64(unique+10-topClients); got != want {
		t.Errorf("%q after repeats = %d, want %d", otherBucketLabel, got, want)
	}

	var sum uint64
	for _, cl := range snap.Clients {
		sum += cl.Count
	}
	if sum != snap.Total {
		t.Errorf("client counts sum to %d, want the total %d", sum, snap.Total)
	}
}

// TestCollectorConcurrent exercises the counters from several
// goroutines; run under -race it pins the locking.
func TestCollectorConcurrent(t *testing.T) {
	const workers, per = 8, 500
	c := NewCollector()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.Observe(qlog.Entry{
					ClientIP: fmt.Sprintf("10.%d.%d.%d", w, i/256, i%256),
					Proto:    "udp",
					Upstream: "u1",
				})
			}
		}(w)
	}
	wg.Wait()

	snap := c.Snapshot()
	const total = workers * per
	if snap.Total != total {
		t.Fatalf("Total = %d, want %d", snap.Total, total)
	}
	assertCounts(t, "Outcomes", snap.Outcomes, map[string]uint64{
		"blocked": 0, "cached": 0, "upstream": total, "error": 0,
	})
	assertCounts(t, "Protos", snap.Protos, map[string]uint64{"udp": total})
	assertCounts(t, "Upstreams", snap.Upstreams, map[string]uint64{"u1": total})

	var sum uint64
	for _, cl := range snap.Clients {
		sum += cl.Count
	}
	if sum != total {
		t.Errorf("client counts sum to %d, want %d", sum, total)
	}
}

// TestCollectorSnapshotIsCopy checks that mutating a snapshot cannot
// corrupt the collector.
func TestCollectorSnapshotIsCopy(t *testing.T) {
	c := NewCollector()
	c.Observe(qlog.Entry{Proto: "udp", ClientIP: "1.1.1.1"})

	first := c.Snapshot()
	first.Outcomes["cached"] = 99
	first.Protos["tcp"] = 99
	first.Clients[0].Count = 99

	second := c.Snapshot()
	if second.Outcomes["cached"] != 0 || second.Protos["tcp"] != 0 {
		t.Errorf("snapshot aliases the collector: %+v", second)
	}
	if second.Clients[0].Count != 1 {
		t.Errorf("Clients = %+v, want the untouched count 1", second.Clients)
	}
}
