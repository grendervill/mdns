// Package routing picks the upstream that answers each query: a
// strategy orders the candidates, and the router walks that order,
// failing over on transport errors and SERVFAIL.
package routing

import (
	"fmt"
	"math/rand"
	"sort"
	"sync/atomic"

	"mydns/internal/upstream"
)

// Strategy orders the candidate upstreams. The first entry is the
// primary choice; healthy upstreams come before unhealthy ones.
type Strategy interface {
	Order(ups []*upstream.Upstream) []*upstream.Upstream
}

// NewStrategy returns the strategy with the given name: "fastest",
// "failover", "round_robin" or "random".
func NewStrategy(name string) (Strategy, error) {
	switch name {
	case "fastest":
		return fastest{}, nil
	case "failover":
		return failover{}, nil
	case "round_robin":
		return newRoundRobin(), nil
	case "random":
		return random{}, nil
	default:
		return nil, fmt.Errorf("unknown strategy %q", name)
	}
}

// splitEnabled partitions the enabled upstreams into healthy and
// unhealthy halves. Unhealthy ones are never dropped: they stay as the
// last-resort candidates.
func splitEnabled(ups []*upstream.Upstream) (healthy, unhealthy []*upstream.Upstream) {
	for _, u := range ups {
		if !u.Enabled() {
			continue
		}
		if u.Status() == upstream.Healthy {
			healthy = append(healthy, u)
		} else {
			unhealthy = append(unhealthy, u)
		}
	}
	return healthy, unhealthy
}

// fastest orders healthy upstreams by their EWMA latency.
type fastest struct{}

func (fastest) Order(ups []*upstream.Upstream) []*upstream.Upstream {
	healthy, unhealthy := splitEnabled(ups)
	sort.SliceStable(healthy, func(i, j int) bool {
		return healthy[i].EWMA() < healthy[j].EWMA()
	})
	return append(healthy, unhealthy...)
}

// failover orders upstreams by their configured priority.
type failover struct{}

func (failover) Order(ups []*upstream.Upstream) []*upstream.Upstream {
	healthy, unhealthy := splitEnabled(ups)
	byPriority := func(list []*upstream.Upstream) {
		sort.SliceStable(list, func(i, j int) bool {
			return list[i].Priority < list[j].Priority
		})
	}
	byPriority(healthy)
	byPriority(unhealthy)
	return append(healthy, unhealthy...)
}

// roundRobin rotates the healthy upstreams one step per call.
type roundRobin struct {
	next atomic.Uint64
}

func newRoundRobin() *roundRobin { return &roundRobin{} }

func (r *roundRobin) Order(ups []*upstream.Upstream) []*upstream.Upstream {
	healthy, unhealthy := splitEnabled(ups)
	if len(healthy) == 0 {
		return unhealthy
	}

	k := int((r.next.Add(1) - 1) % uint64(len(healthy)))
	rotated := append(healthy[k:], healthy[:k]...)
	return append(rotated, unhealthy...)
}

// random shuffles the healthy upstreams uniformly.
type random struct{}

func (random) Order(ups []*upstream.Upstream) []*upstream.Upstream {
	healthy, unhealthy := splitEnabled(ups)
	rand.Shuffle(len(healthy), func(i, j int) {
		healthy[i], healthy[j] = healthy[j], healthy[i]
	})
	return append(healthy, unhealthy...)
}
