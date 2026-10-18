// Daily history: alongside the cumulative counters the collector keeps
// one bucket per UTC day, so the panel can show "за период" totals and
// diagrams without the cumulative "since start" block losing its
// meaning. The buckets are bounded (HistoryDays) and persisted to a
// JSON file under the data directory, so a restart keeps the history.
package stats

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"mydns/internal/qlog"
)

// HistoryDays is how many daily buckets the collector keeps. Four
// hundred days cover a year plus a margin, so a "12 месяцев" range is
// always whole.
const HistoryDays = 400

// dayMaxClients caps the distinct client addresses tracked inside one
// day. It is lower than the cumulative maxClients: a per-day map times
// HistoryDays buckets would otherwise grow without bound, and within a
// single day only the busy tail matters.
const dayMaxClients = 256

// dayStats is one UTC day bucket and also the shape the history file
// stores both the daily list and the cumulative counters in.
type dayStats struct {
	Date      string            `json:"date"`
	Total     uint64            `json:"total"`
	Outcomes  map[string]uint64 `json:"outcomes,omitempty"`
	Protos    map[string]uint64 `json:"protos,omitempty"`
	Upstreams map[string]uint64 `json:"upstreams,omitempty"`
	Clients   map[string]uint64 `json:"clients,omitempty"`
	Overflow  uint64            `json:"overflow,omitempty"`
}

// dayDate is the key format of a bucket: a whole UTC calendar day.
const dayDate = "2006-01-02"

// newDayStats returns an empty bucket for date with non-nil maps.
func newDayStats(date string) *dayStats {
	return &dayStats{
		Date:      date,
		Outcomes:  make(map[string]uint64, len(outcomeNames)),
		Protos:    make(map[string]uint64),
		Upstreams: make(map[string]uint64),
		Clients:   make(map[string]uint64),
	}
}

// observeDayLocked folds one observation into its day bucket, creating
// the bucket — and pruning the expired ones — on the first observation
// of a new day. The caller must hold the lock; o is the precomputed
// outcome class.
func (c *Collector) observeDayLocked(date string, e qlog.Entry, o string) {
	d, ok := c.days[date]
	if !ok {
		// A new day rolls the window forward: drop what fell out.
		c.pruneLocked(c.clock())
		d = newDayStats(date)
		c.days[date] = d
	}

	d.Total++
	d.Outcomes[o]++

	if e.Proto != "" {
		d.Protos[e.Proto]++
	}
	if e.Upstream != "" {
		d.Upstreams[e.Upstream]++
	}
	if e.ClientIP == "" {
		return
	}
	if _, ok := d.Clients[e.ClientIP]; ok {
		d.Clients[e.ClientIP]++
	} else if len(d.Clients) >= dayMaxClients {
		d.Overflow++
	} else {
		d.Clients[e.ClientIP] = 1
	}
}

// pruneLocked drops the buckets older than HistoryDays relative to ref.
// Date keys are ISO calendar days, so a plain string compare orders
// them. The caller must hold the lock.
func (c *Collector) pruneLocked(ref time.Time) {
	if len(c.days) == 0 {
		return
	}
	cutoff := ref.UTC().AddDate(0, 0, -(HistoryDays - 1)).Format(dayDate)
	for date := range c.days {
		if date < cutoff {
			delete(c.days, date)
		}
	}
}

// SnapshotRange sums the whole UTC days whose date keys fall in
// [from, to] inclusive. A zero from or to is an open bound; a reversed
// range (from after to) is empty. The result mirrors Snapshot: the four
// outcome keys are always present and the client table is the top-20
// over the range followed, when anything overflowed or was folded, by
// the "остальные" row.
func (c *Collector) SnapshotRange(from, to time.Time) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snap := Snapshot{
		Outcomes:  make(map[string]uint64, len(outcomeNames)),
		Protos:    make(map[string]uint64),
		Upstreams: make(map[string]uint64),
	}
	for _, name := range outcomeNames {
		snap.Outcomes[name] = 0
	}

	hasFrom := !from.IsZero()
	hasTo := !to.IsZero()
	if hasFrom && hasTo && from.After(to) {
		return snap
	}

	var fromKey, toKey string
	if hasFrom {
		fromKey = from.UTC().Format(dayDate)
	}
	if hasTo {
		toKey = to.UTC().Format(dayDate)
	}

	clients := make(map[string]uint64, dayMaxClients)
	var overflow uint64
	for date, d := range c.days {
		if hasFrom && date < fromKey {
			continue
		}
		if hasTo && date > toKey {
			continue
		}
		snap.Total += d.Total
		for k, v := range d.Outcomes {
			snap.Outcomes[k] += v
		}
		for k, v := range d.Protos {
			snap.Protos[k] += v
		}
		for k, v := range d.Upstreams {
			snap.Upstreams[k] += v
		}
		overflow += d.Overflow
		for ip, n := range d.Clients {
			clients[ip] += n
		}
	}

	list := make([]ClientCount, 0, len(clients))
	for ip, n := range clients {
		list = append(list, ClientCount{IP: ip, Count: n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].IP < list[j].IP
	})
	if len(list) > topClients {
		for _, cl := range list[topClients:] {
			overflow += cl.Count
		}
		list = list[:topClients]
	}
	if overflow > 0 {
		list = append(list, ClientCount{IP: otherBucket, Count: overflow})
	}
	snap.Clients = list

	return snap
}

// statsFileVersion is the layout version of the persisted history. A
// file with any other version is refused rather than misread.
const statsFileVersion = 1

// statsFile is the on-disk shape: the cumulative counters together with
// every daily bucket. Older buckets are pruned before they are written.
type statsFile struct {
	Version    int        `json:"version"`
	SavedAt    time.Time  `json:"saved_at"`
	Cumulative dayStats   `json:"cumulative"`
	Days       []dayStats `json:"days"`
}

// cloneMap copies a count map, always returning a non-nil map so a
// loaded collector never has nil counter maps.
func cloneMap(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// copyDayStats copies one bucket off the collector.
func copyDayStats(d *dayStats) dayStats {
	return dayStats{
		Date:      d.Date,
		Total:     d.Total,
		Outcomes:  cloneMap(d.Outcomes),
		Protos:    cloneMap(d.Protos),
		Upstreams: cloneMap(d.Upstreams),
		Clients:   cloneMap(d.Clients),
		Overflow:  d.Overflow,
	}
}

// cumulativeLocked copies the cumulative counters into the file shape.
// The caller must hold the lock.
func (c *Collector) cumulativeLocked() dayStats {
	return dayStats{
		Total:     c.total,
		Outcomes:  cloneMap(c.outcomes),
		Protos:    cloneMap(c.protos),
		Upstreams: cloneMap(c.upstreams),
		Clients:   cloneMap(c.clients),
		Overflow:  c.overflow,
	}
}

// Save writes the cumulative counters and the daily history to path as
// JSON. An empty path is a no-op, as is an unchanged collector: the
// 30 s ticker must not rewrite a file nothing has touched. The write is
// atomic: a uniquely named temp file in the same directory, synced,
// then renamed. The data directory is never created here — the
// installer owns it — so a missing directory is an error the caller logs
// and survives.
func (c *Collector) Save(path string) error {
	if path == "" {
		return nil
	}

	c.mu.Lock()
	if c.gen == c.savedGen {
		c.mu.Unlock()
		return nil
	}
	file := statsFile{
		Version:    statsFileVersion,
		SavedAt:    c.clock().UTC(),
		Cumulative: c.cumulativeLocked(),
		Days:       make([]dayStats, 0, len(c.days)),
	}
	for _, d := range c.days {
		file.Days = append(file.Days, copyDayStats(d))
	}
	gen := c.gen
	c.mu.Unlock()

	sort.Slice(file.Days, func(i, j int) bool { return file.Days[i].Date < file.Days[j].Date })

	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("stats: encoding history: %w", err)
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("stats: creating the history temp file: %w", err)
	}
	tmp := f.Name()
	fail := func(op string, err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("stats: %s: %w", op, err)
	}

	if _, err := f.Write(data); err != nil {
		return fail("writing history", err)
	}
	if err := f.Sync(); err != nil {
		return fail("syncing history", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("stats: closing history: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("stats: replacing history: %w", err)
	}

	// Record the generation only when nothing was observed while we
	// wrote, so a ticker that skips an unchanged collector cannot lose
	// an update.
	c.mu.Lock()
	if c.gen == gen {
		c.savedGen = gen
	}
	c.mu.Unlock()
	return nil
}

// Load restores the cumulative counters and the daily history from
// path. A missing file is not an error (the first run has none); a
// wrong version is. Buckets outside the retention window are pruned.
func (c *Collector) Load(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stats: reading history: %w", err)
	}

	var file statsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("stats: decoding history: %w", err)
	}
	if file.Version != statsFileVersion {
		return fmt.Errorf("stats: unsupported history version %d", file.Version)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.total = file.Cumulative.Total
	c.outcomes = cloneMap(file.Cumulative.Outcomes)
	c.protos = cloneMap(file.Cumulative.Protos)
	c.upstreams = cloneMap(file.Cumulative.Upstreams)
	c.clients = cloneMap(file.Cumulative.Clients)
	c.overflow = file.Cumulative.Overflow

	c.days = make(map[string]*dayStats, len(file.Days))
	for i := range file.Days {
		d := file.Days[i]
		if d.Date == "" {
			continue
		}
		c.days[d.Date] = &dayStats{
			Date:      d.Date,
			Total:     d.Total,
			Outcomes:  cloneMap(d.Outcomes),
			Protos:    cloneMap(d.Protos),
			Upstreams: cloneMap(d.Upstreams),
			Clients:   cloneMap(d.Clients),
			Overflow:  d.Overflow,
		}
	}
	c.pruneLocked(c.clock())
	return nil
}
