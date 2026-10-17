package filter_test

import (
	"sync"
	"testing"

	"mydns/internal/filter"
)

// TestCheckPriorities checks the design's rule order: user allow above
// everything, then user block, then list exceptions, then list rules.
func TestCheckPriorities(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{
		UserAllow: []string{"x.com"},
		UserBlock: []string{"x.com", "blocked-by-user.com"},
	})
	e.SetList(filter.CompiledList{
		ID:     "l1",
		Block:  []string{"x.com", "blocked-by-user.com", "ads.com"},
		Except: []string{"ads.com", "blocked-by-user.com"},
	})

	checks := []struct {
		name    string
		blocked bool
		source  string
	}{
		{"x.com", false, ""},                  // user allow beats user block and the list
		{"sub.x.com", false, ""},              // ... and covers subdomains
		{"blocked-by-user.com", true, "user"}, // user block beats the list exception
		{"ads.com", false, ""},                // list exception beats the list rule
		{"other.com", false, ""},              // not covered at all
	}

	for _, c := range checks {
		blocked, source := e.Check(c.name)
		if blocked != c.blocked || source != c.source {
			t.Errorf("Check(%q) = (%v, %q), want (%v, %q)", c.name, blocked, source, c.blocked, c.source)
		}
	}
}

// TestCheckSuffix checks that a rule for a domain covers subdomains.
func TestCheckSuffix(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"ads.example.com"}})

	checks := []struct {
		name    string
		blocked bool
	}{
		{"ads.example.com", true},
		{"sub.ads.example.com", true},
		{"example.com", false},
	}
	for _, c := range checks {
		if blocked, _ := e.Check(c.name); blocked != c.blocked {
			t.Errorf("Check(%q) = %v, want %v", c.name, blocked, c.blocked)
		}
	}
}

// TestCheckSource checks that the most specific rule names its list.
func TestCheckSource(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "outer", Block: []string{"a.com"}})
	e.SetList(filter.CompiledList{ID: "inner", Block: []string{"b.a.com"}})

	if _, source := e.Check("b.a.com"); source != "inner" {
		t.Errorf("Check(b.a.com) source = %q, want inner (more specific)", source)
	}
	if _, source := e.Check("x.a.com"); source != "outer" {
		t.Errorf("Check(x.a.com) source = %q, want outer", source)
	}
}

// TestSetListReplaces checks that re-installing a list swaps its rules.
func TestSetListReplaces(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"a.com"}})
	if blocked, _ := e.Check("a.com"); !blocked {
		t.Fatalf("Check(a.com) = false, want true after SetList")
	}

	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"b.com"}})
	if blocked, _ := e.Check("a.com"); blocked {
		t.Errorf("Check(a.com) = true, want false after replacement")
	}
	if blocked, _ := e.Check("b.com"); !blocked {
		t.Errorf("Check(b.com) = false, want true after replacement")
	}
}

// TestRemoveList checks that removing a list drops its rules.
func TestRemoveList(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"a.com"}})
	e.RemoveList("l1")

	if blocked, _ := e.Check("a.com"); blocked {
		t.Errorf("Check(a.com) = true, want false after RemoveList")
	}
	if got := e.Stats().Lists; len(got) != 0 {
		t.Errorf("Stats().Lists = %v, want empty after RemoveList", got)
	}
}

// TestStatsCounters checks totals, per-list hits and the top domains.
func TestStatsCounters(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"a.com", "c.com"}})
	e.SetList(filter.CompiledList{ID: "l2", Block: []string{"b.com"}})

	e.Check("a.com")
	e.Check("a.com")
	e.Check("b.com")
	e.Check("ok.com") // not blocked

	st := e.Stats()
	if st.TotalBlocked != 3 {
		t.Errorf("TotalBlocked = %d, want 3", st.TotalBlocked)
	}
	if len(st.Lists) != 2 {
		t.Fatalf("len(Lists) = %d, want 2", len(st.Lists))
	}
	l1, l2 := st.Lists[0], st.Lists[1]
	if l1.ID != "l1" || l1.Block != 2 || l1.Except != 0 || l1.Hits != 2 {
		t.Errorf("l1 stat = %+v, want ID l1, Block 2, Except 0, Hits 2", l1)
	}
	if l2.ID != "l2" || l2.Block != 1 || l2.Hits != 1 {
		t.Errorf("l2 stat = %+v, want ID l2, Block 1, Hits 1", l2)
	}
	if len(st.Top) != 2 {
		t.Fatalf("len(Top) = %d, want 2", len(st.Top))
	}
	if st.Top[0].Domain != "a.com" || st.Top[0].Count != 2 {
		t.Errorf("Top[0] = %+v, want a.com with 2", st.Top[0])
	}
}

// TestHitsSurviveListReplacement checks that per-list hit counters
// keep accumulating across list updates, where the rules are replaced
// but the list identity stays.
func TestHitsSurviveListReplacement(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"a.com"}})
	e.Check("a.com")

	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"b.com"}}) // daily refresh

	st := e.Stats()
	if len(st.Lists) != 1 {
		t.Fatalf("len(Lists) = %d, want 1", len(st.Lists))
	}
	if st.Lists[0].Hits != 1 {
		t.Errorf("Hits after replacement = %d, want 1 (counters survive updates)", st.Lists[0].Hits)
	}
}

// TestSetUserRules checks live replacement of the user's own rules.
func TestSetUserRules(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"ads.example.com"}})

	if blocked, _ := e.Check("ads.example.com"); !blocked {
		t.Fatalf("Check(ads.example.com) = false, want the list rule")
	}

	e.SetUserRules(nil, []string{"ads.example.com"})
	if blocked, source := e.Check("ads.example.com"); !blocked || source != "user" {
		t.Errorf("after user block = (%v, %q), want (true, user)", blocked, source)
	}

	e.SetUserRules([]string{"ads.example.com"}, nil)
	if blocked, _ := e.Check("ads.example.com"); blocked {
		t.Errorf("after user allow = true, want false")
	}

	e.SetUserRules(nil, nil)
	if blocked, source := e.Check("ads.example.com"); !blocked || source != "l1" {
		t.Errorf("after clearing rules = (%v, %q), want (true, l1)", blocked, source)
	}
}

// TestCheckConcurrentReload exercises concurrent checks while the
// index is swapped: the point is the race detector, not the outcome.
func TestCheckConcurrentReload(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "seed", Block: []string{"seed.example.com"}})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				e.Check("seed.example.com")
				e.Check("other.example.com")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			e.SetList(filter.CompiledList{ID: "seed", Block: []string{"seed.example.com"}})
		}
	}()
	wg.Wait()

	if blocked, _ := e.Check("seed.example.com"); !blocked {
		t.Errorf("Check(seed.example.com) = false after reload churn, want true")
	}
}

// TestCheckNormalization checks that a mixed-case rule and an FQDN
// query still match.
func TestCheckNormalization(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	e.SetList(filter.CompiledList{ID: "l1", Block: []string{"Example.COM"}})

	if blocked, source := e.Check("ADS.example.com."); !blocked || source != "l1" {
		t.Errorf("Check(ADS.example.com.) = (%v, %q), want (true, l1)", blocked, source)
	}
}
