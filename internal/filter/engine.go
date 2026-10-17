package filter

import (
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

	"mydns/internal/dnsname"
)

// topDomainsLimit bounds the distinct domains the top tracker keeps;
// beyond it, new domains are ignored so memory cannot grow unbounded.
const topDomainsLimit = 4096

// topDomainsReturned caps the Top list in Stats.
const topDomainsReturned = 50

// CompiledList is a parsed list ready to install into the engine.
type CompiledList struct {
	ID     string
	URL    string
	Block  []string
	Except []string
}

// EngineOptions configure a new engine.
type EngineOptions struct {
	UserAllow []string
	UserBlock []string
	Logger    *slog.Logger
}

// index is one immutable snapshot compiled from the user rules and all
// installed lists. A check never touches mutable state.
type index struct {
	userAllow  suffixSet[struct{}]
	userBlock  suffixSet[struct{}]
	listExcept suffixSet[struct{}]
	listBlock  suffixSet[string] // domain → list ID
}

// check answers one normalized name with the design's rule order.
func (i *index) check(name string) (bool, string) {
	lbl := dnsname.Labels(name)
	if len(lbl) == 0 {
		return false, ""
	}
	if _, ok := i.userAllow.value(lbl); ok {
		return false, ""
	}
	if _, ok := i.userBlock.value(lbl); ok {
		return true, "user"
	}
	if _, ok := i.listExcept.value(lbl); ok {
		return false, ""
	}
	if source, ok := i.listBlock.value(lbl); ok {
		return true, source
	}
	return false, ""
}

// Engine is safe for concurrent use.
type Engine struct {
	logger *slog.Logger

	mu        sync.Mutex
	userAllow []string
	userBlock []string
	lists     map[string]CompiledList
	hits      map[string]*atomic.Uint64 // outside the replaced list data: counters survive updates
	order     []string                  // install order: source priority and Stats order
	idx       atomic.Pointer[index]

	totalBlocked atomic.Uint64

	topMu sync.Mutex
	top   map[string]uint64
}

// NewEngine builds an engine with the user rules in place and no lists
// installed.
func NewEngine(opts EngineOptions) *Engine {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	e := &Engine{
		logger:    logger,
		userAllow: opts.UserAllow,
		userBlock: opts.UserBlock,
		lists:     make(map[string]CompiledList),
		hits:      make(map[string]*atomic.Uint64),
		top:       make(map[string]uint64),
	}
	e.rebuildLocked()
	return e
}

// SetList installs or replaces a list and atomically republishes the
// index; queries in flight keep using the previous snapshot. Hit
// counters belong to the list identity, not to one snapshot of its
// rules, so they survive refreshes.
func (e *Engine) SetList(l CompiledList) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.lists[l.ID]; !exists {
		e.order = append(e.order, l.ID)
		e.hits[l.ID] = &atomic.Uint64{}
	}
	e.lists[l.ID] = l
	e.rebuildLocked()

	e.logger.Debug("filter list installed", "id", l.ID, "block", len(l.Block), "except", len(l.Except))
}

// RemoveList drops a list and republishes the index.
func (e *Engine) RemoveList(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.lists[id]; !exists {
		return
	}
	delete(e.lists, id)
	delete(e.hits, id)
	for i, oid := range e.order {
		if oid == id {
			e.order = append(e.order[:i], e.order[i+1:]...)
			break
		}
	}
	e.rebuildLocked()
}

// Check applies the rule priorities to a query name and reports
// whether it must be blocked and by what ("user" or a list ID).
func (e *Engine) Check(qname string) (bool, string) {
	idx := e.idx.Load()
	if idx == nil {
		return false, ""
	}

	name := dnsname.Normalize(qname)
	blocked, source := idx.check(name)
	if !blocked {
		return false, ""
	}

	e.totalBlocked.Add(1)
	e.countTop(name)
	if source != "user" {
		e.mu.Lock()
		h := e.hits[source]
		e.mu.Unlock()
		if h != nil {
			h.Add(1)
		}
	}
	return true, source
}

// countTop tracks the most frequently blocked domains.
func (e *Engine) countTop(name string) {
	e.topMu.Lock()
	defer e.topMu.Unlock()

	if count, ok := e.top[name]; ok {
		e.top[name] = count + 1
		return
	}
	if len(e.top) < topDomainsLimit {
		e.top[name] = 1
	}
}

// ListStat is one list's rule counts and hits.
type ListStat struct {
	ID     string
	Block  int
	Except int
	Hits   uint64
}

// DomainCount is one entry of the top blocked domains.
type DomainCount struct {
	Domain string
	Count  uint64
}

// Stats is an engine snapshot for the live views.
type Stats struct {
	TotalBlocked uint64
	Lists        []ListStat // install order
	Top          []DomainCount
}

// Stats returns the current counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	lists := make([]ListStat, 0, len(e.order))
	for _, id := range e.order {
		l, ok := e.lists[id]
		if !ok {
			continue
		}
		var hits uint64
		if h := e.hits[id]; h != nil {
			hits = h.Load()
		}
		lists = append(lists, ListStat{
			ID:     id,
			Block:  len(l.Block),
			Except: len(l.Except),
			Hits:   hits,
		})
	}
	e.mu.Unlock()

	e.topMu.Lock()
	top := make([]DomainCount, 0, len(e.top))
	for d, n := range e.top {
		top = append(top, DomainCount{Domain: d, Count: n})
	}
	e.topMu.Unlock()

	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Domain < top[j].Domain
	})
	if len(top) > topDomainsReturned {
		top = top[:topDomainsReturned]
	}

	return Stats{
		TotalBlocked: e.totalBlocked.Load(),
		Lists:        lists,
		Top:          top,
	}
}

// rebuildLocked compiles a fresh index snapshot. The caller must hold
// e.mu.
func (e *Engine) rebuildLocked() {
	idx := &index{
		userAllow:  suffixSet[struct{}]{},
		userBlock:  suffixSet[struct{}]{},
		listExcept: suffixSet[struct{}]{},
		listBlock:  suffixSet[string]{},
	}
	for _, d := range e.userAllow {
		idx.userAllow.add(d, struct{}{})
	}
	for _, d := range e.userBlock {
		idx.userBlock.add(d, struct{}{})
	}
	for _, id := range e.order {
		if l, ok := e.lists[id]; ok {
			for _, d := range l.Except {
				idx.listExcept.add(d, struct{}{})
			}
		}
	}
	for _, id := range e.order {
		if l, ok := e.lists[id]; ok {
			for _, d := range l.Block {
				name := dnsname.Normalize(d)
				if name == "" {
					continue
				}
				if _, exists := idx.listBlock[name]; !exists {
					idx.listBlock[name] = id // first list in install order wins
				}
			}
		}
	}
	e.idx.Store(idx)
}
