package app_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/filter"
)

// TestFilterEndToEndAllProtocols proves the design's promise that
// filtering is identical for every protocol and client: the same
// blocked, excepted, user-allowed and user-blocked names behave the
// same over plain DNS, DoT, DoH and DoQ, and blocked names never reach
// the upstream.
func TestFilterEndToEndAllProtocols(t *testing.T) {
	fake, aCalls := fakeUpstreamIP(t, [4]byte{192, 0, 2, 1}, 0)

	var listRequests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		listRequests.Add(1)
		fmt.Fprint(w, "||ads.example.com^\n||allowed.example.com^\n@@||good.ads.example.com^\n")
	}))
	t.Cleanup(srv.Close)

	cfg := config.Default()
	cfg.Domain = "mdns.test"
	cfg.DataDir = t.TempDir()
	cfg.Protocols = config.Protocols{
		Plain: config.Protocol{Enabled: true, Port: freePort(t)},
		DoT:   config.Protocol{Enabled: true, Port: freePort(t)},
		DoH:   config.Protocol{Enabled: true, Port: freePort(t)},
		DoQ:   config.Protocol{Enabled: true, Port: freePort(t)},
	}
	cfg.Upstreams = []config.UpstreamConfig{
		{ID: "a", Name: "A", Transport: "plain", Address: fake.Addr(), Priority: 0, Enabled: true},
	}
	cfg.Filter = config.FilterConfig{
		Enabled:   true,
		Mode:      "zero",
		Lists:     []config.FilterList{{ID: "e2e", URL: srv.URL + "/list.txt"}},
		UserAllow: []string{"allowed.example.com"},
		UserBlock: []string{"manual.example.com"},
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

	waitStatus(t, a, func(st []filter.ListStatus) bool {
		return len(st) == 1 && st[0].Applied == 3
	})

	check := func(name, want string) {
		t.Helper()
		before := aCalls.Load()
		for i, got := range askAllProtocols(t, cfg, name) {
			if got != want {
				t.Errorf("%s over protocol #%d: got %s, want %s", name, i, got, want)
			}
		}
		if want == "0.0.0.0" {
			if after := aCalls.Load(); after != before {
				t.Errorf("%s: upstream answered %d queries for a blocked name", name, after-before)
			}
		}
	}

	check("ads.example.com", "0.0.0.0")        // blocked by the list
	check("good.ads.example.com", "192.0.2.1") // @@ exception inside the list
	check("allowed.example.com", "192.0.2.1")  // user allow beats the list rule
	check("manual.example.com", "0.0.0.0")     // user block
	check("ads.example.com", "0.0.0.0")        // repeat: blocks are not cached away

	if got := listRequests.Load(); got == 0 {
		t.Errorf("list server saw no requests")
	}
}
