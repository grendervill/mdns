package app_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/filter"
)

// TestUpdateConfigDropsRemovedList checks that a list removed from the
// config stops blocking right after the update instead of lingering
// until a daemon restart.
func TestUpdateConfigDropsRemovedList(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)

	goneSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "||gone.example.com^\n")
	}))
	t.Cleanup(goneSrv.Close)
	staysSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "||stays.example.com^\n")
	}))
	t.Cleanup(staysSrv.Close)

	cfg.DataDir = t.TempDir()
	cfg.Filter = config.FilterConfig{
		Enabled: true,
		Mode:    "zero",
		Lists: []config.FilterList{
			{ID: "list-a", URL: goneSrv.URL + "/list.txt"},
			{ID: "list-b", URL: staysSrv.URL + "/list.txt"},
		},
	}

	opts := testOptions(t)
	opts.FilterClient = tlsSkipClient()
	opts.FilterInterval = 50 * time.Millisecond
	a, err := app.New(cfg, opts, discardLogger())
	if err != nil {
		t.Fatalf("app.New() = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = a.Stop(sctx)
	})

	waitStatus(t, a, func(st []filter.ListStatus) bool {
		return len(st) == 2 && st[0].Applied == 1 && st[1].Applied == 1
	})

	ask := func(name string) string {
		t.Helper()
		cl := &dns.Client{Net: "udp", Timeout: time.Second}
		resp, _, err := cl.Exchange(query(name), loopback(port))
		if err != nil {
			t.Fatalf("Exchange(%s) = %v, want nil", name, err)
		}
		if len(resp.Answer) == 0 {
			return ""
		}
		if aRec, ok := resp.Answer[0].(*dns.A); ok {
			return aRec.A.String()
		}
		return resp.Answer[0].String()
	}

	if got := ask("gone.example.com"); got != "0.0.0.0" {
		t.Fatalf("gone.example.com before the update = %s, want blocked 0.0.0.0", got)
	}
	if got := ask("stays.example.com"); got != "0.0.0.0" {
		t.Fatalf("stays.example.com before the update = %s, want blocked 0.0.0.0", got)
	}

	next := *cfg
	next.Filter.Lists = []config.FilterList{{ID: "list-b", URL: staysSrv.URL + "/list.txt"}}
	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	if got := ask("gone.example.com"); got == "0.0.0.0" {
		t.Errorf("gone.example.com = %s after removing list-a, want it resolved upstream", got)
	}
	if got := ask("stays.example.com"); got != "0.0.0.0" {
		t.Errorf("stays.example.com = %s, want it still blocked by list-b", got)
	}
	for _, st := range a.FilterStatus() {
		if st.ID == "list-a" {
			t.Errorf("list-a still present in the filter status")
		}
	}
}

// TestUpdateConfigLogChangeRebuilds checks that changing the query-log
// settings actually rebuilds the journal: its new memory cap applies
// right away instead of silently keeping the old log.
func TestUpdateConfigLogChangeRebuilds(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	cfg.Log.MemoryEntries = 100
	a, _ := startApp(t, cfg)

	fill := func(prefix string) {
		t.Helper()
		cl := &dns.Client{Net: "udp", Timeout: time.Second}
		for i := 0; i < 3; i++ {
			if _, _, err := cl.Exchange(query(fmt.Sprintf("%s%d.example.com", prefix, i)), loopback(port)); err != nil {
				t.Fatalf("Exchange(%s%d) = %v, want nil", prefix, i, err)
			}
		}
	}

	fill("before")
	if got := len(a.Requests(50)); got != 3 {
		t.Fatalf("journal entries before the update = %d, want 3", got)
	}

	next := *cfg
	next.Log.MemoryEntries = 1
	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	fill("after")
	if got := len(a.Requests(50)); got != 1 {
		t.Errorf("journal entries after the log change = %d, want 1 (the new memory cap)", got)
	}
}
