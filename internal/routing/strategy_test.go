package routing_test

import (
	"testing"
	"time"

	"mydns/internal/config"
	"mydns/internal/routing"
	"mydns/internal/testutil/scripted"
	"mydns/internal/upstream"
)

// newUpstream builds an enabled upstream with the given id, priority
// and EWMA. An unhealthy upstream is produced with three failed probes.
func newUpstream(t *testing.T, id string, priority int, ewma time.Duration, healthy bool) *upstream.Upstream {
	t.Helper()

	u := upstream.NewWithTransport(config.UpstreamConfig{
		ID:        id,
		Name:      id,
		Transport: "plain",
		Address:   "127.0.0.1:53",
		Priority:  priority,
		Enabled:   true,
	}, scripted.New())

	if healthy {
		u.ObserveProbe(true, ewma)
	} else {
		for i := 0; i < 3; i++ {
			u.ObserveProbe(false, 0)
		}
	}
	return u
}

// ids returns the ordered upstream ids for easy assertions.
func ids(ups []*upstream.Upstream) []string {
	out := make([]string, len(ups))
	for i, u := range ups {
		out[i] = u.ID
	}
	return out
}

// noopStrategy keeps TestUnknownStrategyError honest about types.
var _ routing.Strategy = mustStrategy("fastest")

func mustStrategy(name string) routing.Strategy {
	s, err := routing.NewStrategy(name)
	if err != nil {
		panic(err)
	}
	return s
}

// TestFastestOrder checks that fastest sorts healthy upstreams by EWMA.
func TestFastestOrder(t *testing.T) {
	a := newUpstream(t, "a", 0, 30*time.Millisecond, true)
	b := newUpstream(t, "b", 0, 5*time.Millisecond, true)
	c := newUpstream(t, "c", 0, 10*time.Millisecond, true)

	st, err := routing.NewStrategy("fastest")
	if err != nil {
		t.Fatalf("NewStrategy(fastest) = %v, want nil", err)
	}

	got := ids(st.Order([]*upstream.Upstream{a, b, c}))
	want := []string{"b", "c", "a"}
	if len(got) != len(want) {
		t.Fatalf("Order() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Order() = %v, want %v", got, want)
		}
	}
}

// TestFastestPutsUnhealthyLast checks that a healthy upstream outranks
// an unhealthy one regardless of EWMA.
func TestFastestPutsUnhealthyLast(t *testing.T) {
	healthy := newUpstream(t, "healthy", 0, 30*time.Millisecond, true)
	sick := newUpstream(t, "sick", 0, 0, false)

	st := mustStrategy("fastest")
	got := ids(st.Order([]*upstream.Upstream{sick, healthy}))
	if got[0] != "healthy" || got[1] != "sick" {
		t.Errorf("Order() = %v, want [healthy sick]", got)
	}
}

// TestFailoverOrder checks that failover sorts by the configured
// priority.
func TestFailoverOrder(t *testing.T) {
	a := newUpstream(t, "a", 2, 0, true)
	b := newUpstream(t, "b", 0, 0, true)
	c := newUpstream(t, "c", 1, 0, true)

	st := mustStrategy("failover")
	got := ids(st.Order([]*upstream.Upstream{a, b, c}))
	if got[0] != "b" || got[1] != "c" || got[2] != "a" {
		t.Errorf("Order() = %v, want [b c a]", got)
	}
}

// TestRoundRobinRotates checks the round-robin rotation.
func TestRoundRobinRotates(t *testing.T) {
	a := newUpstream(t, "a", 0, 0, true)
	b := newUpstream(t, "b", 0, 0, true)

	st := mustStrategy("round_robin")
	want := [][]string{{"a", "b"}, {"b", "a"}, {"a", "b"}, {"b", "a"}}
	for i, w := range want {
		got := ids(st.Order([]*upstream.Upstream{a, b}))
		if got[0] != w[0] || got[1] != w[1] {
			t.Fatalf("Order() #%d = %v, want %v", i+1, got, w)
		}
	}
}

// TestRandomIsPermutation checks that random returns a permutation of
// the healthy upstreams and that the order varies.
func TestRandomIsPermutation(t *testing.T) {
	a := newUpstream(t, "a", 0, 0, true)
	b := newUpstream(t, "b", 0, 0, true)
	c := newUpstream(t, "c", 0, 0, true)
	set := []*upstream.Upstream{a, b, c}

	st := mustStrategy("random")
	firsts := map[string]bool{}
	for i := 0; i < 100; i++ {
		got := st.Order(set)
		if len(got) != 3 {
			t.Fatalf("Order() length = %d, want 3", len(got))
		}
		seen := map[string]bool{}
		for _, u := range got {
			seen[u.ID] = true
		}
		if !seen["a"] || !seen["b"] || !seen["c"] {
			t.Fatalf("Order() = %v, want a permutation of [a b c]", ids(got))
		}
		firsts[got[0].ID] = true
	}
	if len(firsts) < 2 {
		t.Errorf("first element over 100 random orders = %v, want at least two distinct", firsts)
	}
}

// TestDisabledExcluded checks that disabled upstreams never appear in
// the order.
func TestDisabledExcluded(t *testing.T) {
	a := newUpstream(t, "a", 0, 0, true)
	off := upstream.NewWithTransport(config.UpstreamConfig{
		ID: "off", Name: "off", Transport: "plain", Address: "127.0.0.1:53", Enabled: false,
	}, scripted.New())

	for _, name := range []string{"fastest", "failover", "round_robin", "random"} {
		got := ids(mustStrategy(name).Order([]*upstream.Upstream{a, off}))
		if len(got) != 1 || got[0] != "a" {
			t.Errorf("%s Order() = %v, want [a]", name, got)
		}
	}
}

// TestUnknownStrategyError checks that an unknown strategy name is
// rejected.
func TestUnknownStrategyError(t *testing.T) {
	if st, err := routing.NewStrategy("bogus"); err == nil || st != nil {
		t.Errorf("NewStrategy(bogus) = (%v, %v), want (nil, error)", st, err)
	}
}
