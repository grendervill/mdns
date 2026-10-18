// Package stats keeps cumulative counters of the resolved queries:
// the outcome mix, the protocols, which upstream answered, and the
// busiest clients. The counters cover the whole run of the daemon (they
// are not a window over the query log's ring), so the panel can report
// exact "since start" totals without memory growing with traffic. The
// client list is the one exception to "exact": it is bounded, and every
// address beyond the bound is folded into one overflow row.
package stats

import (
	"sort"
	"sync"

	"mydns/internal/qlog"
)

// These are the outcome names the API and the panel speak.
const (
	outcomeBlocked  = "blocked"
	outcomeCached   = "cached"
	outcomeUpstream = "upstream"
	outcomeError    = "error"
)

// outcomeNames fixes both the presence and the order of the four
// outcome keys in every snapshot: the panel renders one diagram per
// outcome, so a missing key would mean a missing diagram rather than a
// zero one.
var outcomeNames = [...]string{outcomeBlocked, outcomeCached, outcomeUpstream, outcomeError}

// otherBucket is the snapshot row that aggregates every client outside
// the top list, so the client table stays bounded while the counts keep
// summing to the total. It is Russian because the panel renders it
// verbatim.
const otherBucket = "остальные"

// topClients is how many client addresses one snapshot carries besides
// the overflow row.
const topClients = 20

// maxClients caps the tracked client addresses. Beyond it a new
// address is only counted in the overflow row: a busy daemon meets
// many more distinct clients than a map should hold for its lifetime,
// and the tail matters only in aggregate.
const maxClients = 4096

// Collector accumulates the counters. It is safe for concurrent use.
//
// A single mutex guards every counter: the maps cannot be updated
// atomically, and the observed rate (tens of thousands of queries per
// second, versus a handful of map writes under a lock per query) leaves
// the critical section far from contended.
type Collector struct {
	mu        sync.Mutex
	total     uint64
	outcomes  map[string]uint64
	protos    map[string]uint64
	upstreams map[string]uint64
	clients   map[string]uint64
	// overflow counts every observation of a client that is not
	// tracked (see maxClients); Snapshot folds it into otherBucket.
	overflow uint64
}

// NewCollector returns an empty collector.
func NewCollector() *Collector {
	return &Collector{
		outcomes:  make(map[string]uint64, len(outcomeNames)),
		protos:    make(map[string]uint64, 6),
		upstreams: make(map[string]uint64, 4),
		clients:   make(map[string]uint64, 64),
	}
}

// Observe folds one entry into the counters. It is the callback the
// core pipeline runs for every resolved request (core.Observer), on the
// same path that appends to the query log.
func (c *Collector) Observe(e qlog.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.total++
	c.outcomes[outcome(e)]++

	// An empty field means "not applicable" (a malformed request has no
	// question, a blocked or cached answer has no upstream), so it must
	// not become a key of its own.
	if e.Proto != "" {
		c.protos[e.Proto]++
	}
	if e.Upstream != "" {
		c.upstreams[e.Upstream]++
	}
	if e.ClientIP == "" {
		return
	}

	if _, ok := c.clients[e.ClientIP]; ok {
		c.clients[e.ClientIP]++
		return
	}
	if len(c.clients) >= maxClients {
		c.overflow++
		return
	}
	c.clients[e.ClientIP] = 1
}

// Snapshot is a cumulative view of everything the collector has seen.
// The maps and the slice are copies and never alias the collector.
type Snapshot struct {
	Total     uint64            `json:"total"`
	Outcomes  map[string]uint64 `json:"outcomes"`  // cached | blocked | upstream | error
	Protos    map[string]uint64 `json:"protos"`    // udp | tcp | doh | dot | doq
	Upstreams map[string]uint64 `json:"upstreams"` // upstream ID -> answered
	Clients   []ClientCount     `json:"clients"`   // top-20 + "остальные"
}

// ClientCount is one row of the client table.
type ClientCount struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

// Snapshot copies the counters. The outcome map always carries the four
// outcome keys; the client table holds the 20 busiest addresses sorted
// by count (descending, ties by address) followed, when anything
// overflowed, by the "остальные" row with the sum of all the remaining
// counts.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snap := Snapshot{
		Total:     c.total,
		Outcomes:  make(map[string]uint64, len(outcomeNames)),
		Protos:    make(map[string]uint64, len(c.protos)),
		Upstreams: make(map[string]uint64, len(c.upstreams)),
	}
	for _, name := range outcomeNames {
		snap.Outcomes[name] = c.outcomes[name]
	}
	for proto, n := range c.protos {
		snap.Protos[proto] = n
	}
	for id, n := range c.upstreams {
		snap.Upstreams[id] = n
	}

	clients := make([]ClientCount, 0, len(c.clients)+1)
	for ip, n := range c.clients {
		clients = append(clients, ClientCount{IP: ip, Count: n})
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Count != clients[j].Count {
			return clients[i].Count > clients[j].Count
		}
		return clients[i].IP < clients[j].IP
	})

	overflow := c.overflow
	if len(clients) > topClients {
		for _, cl := range clients[topClients:] {
			overflow += cl.Count
		}
		clients = clients[:topClients]
	}
	if overflow > 0 {
		clients = append(clients, ClientCount{IP: otherBucket, Count: overflow})
	}
	snap.Clients = clients

	return snap
}

// outcome classifies one entry the same way qlog's unexported helper
// does: blocked → cached → upstream → error. The order matters: a
// blocked request stays blocked even when a cached answer was served, a
// cache hit outranks an upstream lookup, and an entry with no source at
// all failed (for example, every upstream was down and the answer was
// SERVFAIL). The rcode is deliberately not consulted, so an upstream
// answer with an error rcode still counts as upstream.
//
// Ruling R7 of docs/superpowers/plans/2026-10-18-mdns-panel.md accepts
// this duplication instead of sharing code with the qlog package; the
// tests keep both copies on the same rule.
func outcome(e qlog.Entry) string {
	switch {
	case e.Blocked:
		return outcomeBlocked
	case e.CacheHit:
		return outcomeCached
	case e.Upstream != "":
		return outcomeUpstream
	default:
		return outcomeError
	}
}
