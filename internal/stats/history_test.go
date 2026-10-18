package stats

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"mydns/internal/qlog"
)

// dayAt builds a mid-day UTC timestamp for a calendar date, so a bucket
// key is unambiguous.
func dayAt(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 12, 0, 0, 0, time.UTC)
}

// observeOn folds one entry into the collector as if the clock read day.
func observeOn(c *Collector, day time.Time, e qlog.Entry) {
	c.now = func() time.Time { return day }
	c.Observe(e)
}

// TestCollectorDayRollover checks that Observe fills both the
// cumulative counters and the bucket of its UTC day, and that crossing
// midnight starts a new bucket.
func TestCollectorDayRollover(t *testing.T) {
	c := NewCollector()
	day1 := time.Date(2026, 1, 1, 23, 30, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 0, 30, 0, 0, time.UTC)

	observeOn(c, day1, qlog.Entry{Upstream: "u", Proto: "udp", ClientIP: "10.0.0.1"})
	observeOn(c, day1, qlog.Entry{CacheHit: true, Proto: "udp"})
	observeOn(c, day2, qlog.Entry{Blocked: true, Proto: "tcp"})

	if got := c.SnapshotRange(day1, day1).Total; got != 2 {
		t.Errorf("day1 total = %d, want 2", got)
	}
	if got := c.SnapshotRange(day2, day2).Total; got != 1 {
		t.Errorf("day2 total = %d, want 1", got)
	}
	if got := c.SnapshotRange(day1, day2).Total; got != 3 {
		t.Errorf("two-day total = %d, want 3", got)
	}
	if got := c.Snapshot().Total; got != 3 {
		t.Errorf("cumulative total = %d, want 3", got)
	}
}

// TestCollectorSnapshotRangeBounds checks the whole-day sums, the open
// bounds and the reversed range.
func TestCollectorSnapshotRangeBounds(t *testing.T) {
	c := NewCollector()
	d1, d2, d3 := dayAt(2026, 3, 1), dayAt(2026, 3, 2), dayAt(2026, 3, 3)
	observeOn(c, d1, qlog.Entry{Upstream: "u1", Proto: "udp"})
	observeOn(c, d2, qlog.Entry{Upstream: "u2", Proto: "doh"})
	observeOn(c, d3, qlog.Entry{Blocked: true, Proto: "tcp"})

	mid := c.SnapshotRange(d2, d2)
	if mid.Total != 1 || mid.Upstreams["u2"] != 1 || mid.Protos["doh"] != 1 {
		t.Errorf("middle day = %+v, want only the u2/doh query", mid)
	}

	if got := c.SnapshotRange(time.Time{}, d2).Total; got != 2 {
		t.Errorf("open from bound total = %d, want 2", got)
	}
	if got := c.SnapshotRange(d2, time.Time{}).Total; got != 2 {
		t.Errorf("open to bound total = %d, want 2", got)
	}
	if got := c.SnapshotRange(time.Time{}, time.Time{}).Total; got != 3 {
		t.Errorf("both bounds open total = %d, want 3", got)
	}

	rev := c.SnapshotRange(d3, d1)
	if rev.Total != 0 {
		t.Errorf("reversed range total = %d, want 0", rev.Total)
	}
	for _, name := range outcomeNames {
		if _, ok := rev.Outcomes[name]; !ok {
			t.Errorf("reversed range is missing outcome %q", name)
		}
	}
}

// TestCollectorDayClientOverflow checks the per-day client cap and the
// merge across days into the top-20 plus the "остальные" row.
func TestCollectorDayClientOverflow(t *testing.T) {
	c := NewCollector()
	day := dayAt(2026, 5, 5)
	c.now = func() time.Time { return day }
	for i := 0; i < 300; i++ {
		c.Observe(qlog.Entry{Upstream: "u", Proto: "udp", ClientIP: fmt.Sprintf("10.0.0.%d", i)})
	}

	one := c.SnapshotRange(day, day)
	if one.Total != 300 {
		t.Fatalf("day total = %d, want 300", one.Total)
	}
	if len(one.Clients) != topClients+1 {
		t.Fatalf("client rows = %d, want %d (top-20 plus остальные)", len(one.Clients), topClients+1)
	}
	last := one.Clients[len(one.Clients)-1]
	if last.IP != otherBucket {
		t.Fatalf("last client row = %q, want %q", last.IP, otherBucket)
	}
	// 256 tracked once, 44 overflowed; the 236 tracked past the top-20
	// fold into остальные too: 236 + 44 = 280.
	if last.Count != 280 {
		t.Errorf("остальные count = %d, want 280", last.Count)
	}
	if sum := clientSum(one); sum != 300 {
		t.Errorf("client counts sum = %d, want 300", sum)
	}

	// A second day repeats one address: the range merges it.
	day2 := dayAt(2026, 5, 6)
	c.now = func() time.Time { return day2 }
	c.Observe(qlog.Entry{Upstream: "u", Proto: "udp", ClientIP: "10.0.0.0"})

	both := c.SnapshotRange(day, day2)
	if both.Total != 301 {
		t.Fatalf("two-day total = %d, want 301", both.Total)
	}
	if len(both.Clients) == 0 || both.Clients[0].IP != "10.0.0.0" || both.Clients[0].Count != 2 {
		t.Errorf("merged top client = %+v, want 10.0.0.0 counted twice", both.Clients)
	}
	if sum := clientSum(both); sum != 301 {
		t.Errorf("merged client counts sum = %d, want 301", sum)
	}
}

// clientSum adds every rendered client row.
func clientSum(sn Snapshot) uint64 {
	var sum uint64
	for _, cl := range sn.Clients {
		sum += cl.Count
	}
	return sum
}

// TestCollectorRetention checks that a rollover prunes the buckets past
// the HistoryDays window.
func TestCollectorRetention(t *testing.T) {
	c := NewCollector()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	oldest := now.AddDate(0, 0, -HistoryDays)
	for i := 0; i <= HistoryDays; i++ { // 401 buckets: oldest .. now
		date := oldest.AddDate(0, 0, i).Format(dayDate)
		c.days[date] = newDayStats(date)
		c.days[date].Total = 1
	}
	if len(c.days) != HistoryDays+1 {
		t.Fatalf("prepared buckets = %d, want %d", len(c.days), HistoryDays+1)
	}

	// Rolling to a new day prunes the two oldest buckets.
	c.now = func() time.Time { return now.AddDate(0, 0, 1) }
	c.Observe(qlog.Entry{Upstream: "u", Proto: "udp"})

	if len(c.days) != HistoryDays {
		t.Errorf("retained buckets = %d, want %d", len(c.days), HistoryDays)
	}
	if _, ok := c.days[oldest.Format(dayDate)]; ok {
		t.Error("the oldest bucket survived the prune")
	}
}

// TestCollectorSaveLoad checks the file round-trip: cumulative counters
// and every range survive, the file is 0600, no temp file is left, a
// missing file is fine and a wrong version is refused.
func TestCollectorSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	c := NewCollector()
	now := time.Now().UTC()
	d1 := now.AddDate(0, 0, -1)
	c.now = func() time.Time { return d1 }
	c.Observe(qlog.Entry{Upstream: "u1", Proto: "udp", ClientIP: "10.0.0.1"})
	c.Observe(qlog.Entry{CacheHit: true, Proto: "doh", ClientIP: "10.0.0.2"})
	c.now = func() time.Time { return now }
	c.Observe(qlog.Entry{Blocked: true, Proto: "tcp", ClientIP: "10.0.0.1"})

	if err := c.Save(path); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}
	if err := c.Save(""); err != nil {
		t.Errorf("Save(\"\") = %v, want nil", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file left behind: %v", err)
	}

	loaded := NewCollector()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if !reflect.DeepEqual(loaded.Snapshot(), c.Snapshot()) {
		t.Errorf("cumulative snapshot after Load = %+v, want %+v", loaded.Snapshot(), c.Snapshot())
	}
	if !reflect.DeepEqual(loaded.SnapshotRange(time.Time{}, time.Time{}), c.SnapshotRange(time.Time{}, time.Time{})) {
		t.Error("full range after Load differs from the saved one")
	}
	if !reflect.DeepEqual(loaded.SnapshotRange(d1, d1), c.SnapshotRange(d1, d1)) {
		t.Error("day range after Load differs from the saved one")
	}

	if err := NewCollector().Load(filepath.Join(dir, "absent.json")); err != nil {
		t.Errorf("Load() of a missing file = %v, want nil", err)
	}
	if err := NewCollector().Load(""); err != nil {
		t.Errorf("Load(\"\") = %v, want nil", err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatalf("writing the bad file: %v", err)
	}
	if err := NewCollector().Load(bad); err == nil {
		t.Error("Load() of a wrong version returned nil, want an error")
	}
}

// TestCollectorLoadKeepsFullCumulativeClients checks that a restore
// keeps the whole cumulative client map, not only the snapshot's top-20.
func TestCollectorLoadKeepsFullCumulativeClients(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	c := NewCollector()
	for i := 0; i < 25; i++ {
		c.Observe(qlog.Entry{Upstream: "u", Proto: "udp", ClientIP: fmt.Sprintf("10.1.0.%d", i)})
	}
	if err := c.Save(path); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}

	loaded := NewCollector()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if len(loaded.clients) != 25 {
		t.Errorf("restored cumulative clients = %d, want 25 (the full map)", len(loaded.clients))
	}
}

// TestCollectorConcurrentObserveAndRange exercises the one mutex under
// the race detector: observers and range readers share the collector.
func TestCollectorConcurrentObserveAndRange(t *testing.T) {
	c := NewCollector()
	day := time.Now().UTC()
	c.now = func() time.Time { return day }

	var writers sync.WaitGroup
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < 250; i++ {
				c.Observe(qlog.Entry{Upstream: "u", Proto: "udp", ClientIP: fmt.Sprintf("10.0.%d.%d", w, i)})
			}
		}(w)
	}

	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = c.SnapshotRange(day, day)
				_ = c.Snapshot()
			}
		}
	}()

	writers.Wait()
	close(stop)
	reader.Wait()

	if got := c.Snapshot().Total; got != 1000 {
		t.Errorf("total after the concurrent run = %d, want 1000", got)
	}
}

// TestCollectorSaveSkipsUnchanged checks the ticker guard: an unchanged
// collector is a no-op, and a new observation makes Save write again.
func TestCollectorSaveSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	c := NewCollector()
	c.Observe(qlog.Entry{Upstream: "u", Proto: "udp"})
	if err := c.Save(path); err != nil {
		t.Fatalf("first Save() = %v, want nil", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the saved file: %v", err)
	}
	if err := c.Save(path); err != nil {
		t.Fatalf("Save() of an unchanged collector = %v, want nil", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Save() rewrote an unchanged collector: %v", err)
	}

	c.Observe(qlog.Entry{Blocked: true, Proto: "tcp"})
	if err := c.Save(path); err != nil {
		t.Fatalf("Save() after a new observation = %v, want nil", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Save() did not write after a new observation: %v", err)
	}
}

// TestCollectorConcurrentSave checks that two Saves racing on one path
// use distinct temp files: neither fails with ENOENT and no temp file is
// left behind.
func TestCollectorConcurrentSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	first := NewCollector()
	first.Observe(qlog.Entry{Upstream: "u1", Proto: "udp"})
	second := NewCollector()
	second.Observe(qlog.Entry{CacheHit: true, Proto: "doh"})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, c := range []*Collector{first, second} {
		wg.Add(1)
		go func(c *Collector) {
			defer wg.Done()
			errs <- c.Save(path)
		}(c)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Save() = %v, want nil", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.Name() != "stats.json" {
			t.Errorf("leftover file after concurrent Save: %s", e.Name())
		}
	}

	loaded := NewCollector()
	if err := loaded.Load(path); err != nil {
		t.Errorf("Load() of the racing file = %v, want nil", err)
	}
}
