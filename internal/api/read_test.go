package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
)

// discardLogger returns a logger that drops everything.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeController scripts the API's controller dependency.
type fakeController struct {
	status       api.Status
	statusErr    error
	cfg          *config.Config
	catalog      []providers.Provider
	lastRequests int
	lastProbe    []providers.Endpoint
	lastFilterID string
	lastConfig   *config.Config
	updateErr    error
}

func (f *fakeController) Status(context.Context) (api.Status, error) {
	return f.status, f.statusErr
}
func (f *fakeController) Config() *config.Config { return f.cfg }
func (f *fakeController) UpdateConfig(_ context.Context, c *config.Config) error {
	f.lastConfig = c
	return f.updateErr
}
func (f *fakeController) Providers() []providers.Provider { return f.catalog }
func (f *fakeController) Probe(_ context.Context, eps []providers.Endpoint) []probe.Result {
	f.lastProbe = eps
	return nil
}
func (f *fakeController) Requests(n int) []qlog.Entry {
	f.lastRequests = n
	return make([]qlog.Entry, n)
}
func (f *fakeController) FilterStatus() []filter.ListStatus { return nil }
func (f *fakeController) FilterUpdate(_ context.Context, id string) error {
	f.lastFilterID = id
	return nil
}

// newTestServer builds an API server over the fake with a live test
// HTTP server around it.
func newTestServer(t *testing.T, ctl *fakeController) *httptest.Server {
	t.Helper()
	srv := api.New(ctl, discardLogger(), api.ServerOptions{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// getJSON fetches path and decodes the JSON into v, returning the
// status code.
func getJSON(t *testing.T, ts *httptest.Server, path string, v any) int {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s = %v, want nil", path, err)
	}
	defer resp.Body.Close()
	if v != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

// TestStatusJSON checks the status snapshot round-trips.
func TestStatusJSON(t *testing.T) {
	ctl := &fakeController{
		status: api.Status{
			Version:   "test",
			Domain:    "dns.example.com",
			Strategy:  "fastest",
			Listeners: []string{"plain:53", "doh:443"},
			Upstreams: []api.UpstreamStatus{{
				ID: "cf", Name: "Cloudflare", Transport: "plain", Address: "1.1.1.1:53",
				Enabled: true, Healthy: true, LatencyMS: 12.5, Sent: 10, Failed: 1,
			}},
			Cache:  cache.Stats{Hits: 3, Misses: 4, Size: 7},
			Filter: api.FilterSnapshot{Enabled: true, Mode: "zero", TotalBlocked: 42},
		},
	}

	ts := newTestServer(t, ctl)
	var got api.Status
	if code := getJSON(t, ts, "/api/v1/status", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}

	if got.Domain != "dns.example.com" || got.Strategy != "fastest" {
		t.Errorf("status = %+v, want domain and strategy", got)
	}
	if len(got.Upstreams) != 1 || got.Upstreams[0].LatencyMS != 12.5 || !got.Upstreams[0].Healthy {
		t.Errorf("upstreams = %+v, want the scripted one", got.Upstreams)
	}
	if got.Cache.Hits != 3 || got.Filter.TotalBlocked != 42 {
		t.Errorf("cache/filter = %+v / %+v, want the scripted values", got.Cache, got.Filter)
	}
}

// TestConfigJSON checks the config endpoint returns the current config.
func TestConfigJSON(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	ctl := &fakeController{cfg: cfg}

	ts := newTestServer(t, ctl)
	var got config.Config
	if code := getJSON(t, ts, "/api/v1/config", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if got.Domain != "dns.example.com" {
		t.Errorf("config.Domain = %q, want dns.example.com", got.Domain)
	}
}

// TestProvidersJSON checks the catalog endpoint.
func TestProvidersJSON(t *testing.T) {
	ctl := &fakeController{catalog: providers.List()}

	ts := newTestServer(t, ctl)
	var got []providers.Provider
	if code := getJSON(t, ts, "/api/v1/providers", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if len(got) != len(providers.List()) {
		t.Errorf("providers count = %d, want %d", len(got), len(providers.List()))
	}
}

// TestRequestsLimit checks the n parameter: default 200, capped at
// 10000.
func TestRequestsLimit(t *testing.T) {
	ctl := &fakeController{}
	ts := newTestServer(t, ctl)

	var entries []qlog.Entry
	if code := getJSON(t, ts, "/api/v1/requests", &entries); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastRequests != 200 {
		t.Errorf("default n = %d, want 200", ctl.lastRequests)
	}

	if code := getJSON(t, ts, "/api/v1/requests?n=5", &entries); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastRequests != 5 {
		t.Errorf("n=5 → %d, want 5", ctl.lastRequests)
	}

	if code := getJSON(t, ts, "/api/v1/requests?n=999999", &entries); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastRequests != 10000 {
		t.Errorf("n=999999 → %d, want the 10000 cap", ctl.lastRequests)
	}
}

// TestFilterStatusJSON checks the filter status endpoint.
func TestFilterStatusJSON(t *testing.T) {
	ctl := &fakeController{}
	ts := newTestServer(t, ctl)

	var got []filter.ListStatus
	if code := getJSON(t, ts, "/api/v1/filter/status", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
}

// TestUnknownPath404 checks unknown routes.
func TestUnknownPath404(t *testing.T) {
	ts := newTestServer(t, &fakeController{})
	if code := getJSON(t, ts, "/api/v1/nope", nil); code != http.StatusNotFound {
		t.Errorf("status code = %d, want 404", code)
	}
}

// TestMethodNotAllowed405 checks wrong methods on known routes.
func TestMethodNotAllowed405(t *testing.T) {
	ts := newTestServer(t, &fakeController{})
	resp, err := http.Post(ts.URL+"/api/v1/status", "application/json", nil)
	if err != nil {
		t.Fatalf("POST = %v, want nil", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want 405", resp.StatusCode)
	}
}
