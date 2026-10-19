package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mydns/internal/app"
	"mydns/internal/config"
)

// TestUpdateConfigQuiescesSharedUpdater pins the structural swap's
// quiesce step: the filter updater carries over into the next
// generation when the lists and the data dir are unchanged, so the
// previous generation's Run has to have returned before the new one
// launches another. A fetch a swap cancels mid-flight must therefore
// not surface as a list error in the live status.
func TestUpdateConfigQuiescesSharedUpdater(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)

	// The list server holds every fetch open until its client goes
	// away, so the swap always cancels one mid-flight.
	fetching := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case fetching <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	cfg.Filter = config.FilterConfig{
		Enabled: true,
		Mode:    "zero",
		Lists:   []config.FilterList{{ID: "slow", URL: srv.URL + "/list.txt"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
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

	// Wait until the first fetch is actually in flight.
	select {
	case <-fetching:
	case <-time.After(2 * time.Second):
		t.Fatal("the list server never saw the initial fetch")
	}

	// A structural change that keeps the same ports and the same list,
	// so the updater is reused across the swap.
	fake2 := newFakeUpstream(t)
	next := *cfg
	next.Upstreams = []config.UpstreamConfig{
		cfg.Upstreams[0],
		{ID: "fake2", Name: "fake2", Transport: "plain", Address: fake2.Addr(), Enabled: true},
	}

	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	if got := len(a.Config().Upstreams); got != 2 {
		t.Errorf("live config carries %d upstreams, want the new 2", got)
	}

	// The status must stay clean: neither the aborted fetch's outcome
	// nor a later one from the retired generation may land an error.
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		for _, st := range a.FilterStatus() {
			if st.Error != "" {
				t.Errorf("list %s: Error = %q after the swap, want empty", st.ID, st.Error)
			}
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}
