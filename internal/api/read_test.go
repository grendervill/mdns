package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
	"mydns/internal/stats"
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
	probeFn      func(context.Context, []providers.Endpoint) []probe.Result
	lastFilterID string
	lastConfig   *config.Config
	updateErr    error

	stats   stats.Snapshot
	started time.Time

	lastQuery qlog.Query
	lastPage  int
	lastPer   int
	queryFn   func(q qlog.Query, page, per int) ([]qlog.Entry, int)
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
func (f *fakeController) Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result {
	f.lastProbe = eps
	if f.probeFn != nil {
		return f.probeFn(ctx, eps)
	}
	return nil
}
func (f *fakeController) Requests(n int) []qlog.Entry {
	f.lastRequests = n
	return make([]qlog.Entry, n)
}
func (f *fakeController) Stats() stats.Snapshot { return f.stats }
func (f *fakeController) Started() time.Time    { return f.started }
func (f *fakeController) RequestsQuery(q qlog.Query, page, per int) ([]qlog.Entry, int) {
	f.lastQuery, f.lastPage, f.lastPer = q, page, per
	if f.queryFn != nil {
		return f.queryFn(q, page, per)
	}
	return nil, 0
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
	srv := api.New(ctl, api.NewBus(), discardLogger(), api.ServerOptions{})
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

// TestStatsJSON checks /stats returns the cumulative snapshot together
// with the daemon start time.
func TestStatsJSON(t *testing.T) {
	since := time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)
	ctl := &fakeController{
		stats: stats.Snapshot{
			Total: 7,
			Outcomes: map[string]uint64{
				"blocked": 2, "cached": 3, "upstream": 2, "error": 0,
			},
			Protos:    map[string]uint64{"udp": 5, "doh": 2},
			Upstreams: map[string]uint64{"cf": 2},
			Clients:   []stats.ClientCount{{IP: "10.0.0.1", Count: 4}},
		},
		started: since,
	}

	ts := newTestServer(t, ctl)
	var got api.StatsResponse
	if code := getJSON(t, ts, "/api/v1/stats", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}

	if got.Total != 7 {
		t.Errorf("Total = %d, want 7", got.Total)
	}
	if got.Outcomes["blocked"] != 2 || got.Outcomes["cached"] != 3 {
		t.Errorf("Outcomes = %v, want blocked=2 cached=3", got.Outcomes)
	}
	if got.Protos["udp"] != 5 || got.Protos["doh"] != 2 {
		t.Errorf("Protos = %v, want udp=5 doh=2", got.Protos)
	}
	if got.Upstreams["cf"] != 2 {
		t.Errorf("Upstreams = %v, want cf=2", got.Upstreams)
	}
	if len(got.Clients) != 1 || got.Clients[0].IP != "10.0.0.1" || got.Clients[0].Count != 4 {
		t.Errorf("Clients = %+v, want the scripted row", got.Clients)
	}
	if !got.Since.Equal(since) {
		t.Errorf("Since = %v, want %v", got.Since, since)
	}
}

// TestRequestsPaged checks the paged shape: parameters reach the
// controller, the page/per echo back and pages is ceil(total/per).
func TestRequestsPaged(t *testing.T) {
	scripted := []qlog.Entry{
		{QName: "a.example.com.", Blocked: true},
		{QName: "b.example.com.", Blocked: true},
	}
	ctl := &fakeController{
		queryFn: func(qlog.Query, int, int) ([]qlog.Entry, int) { return scripted, 250 },
	}

	ts := newTestServer(t, ctl)
	path := "/api/v1/requests?page=2&per=50&q=example&outcome=blocked" +
		"&proto=udp&client=10.0.0.1&upstream=cf"
	var got api.RequestsPage
	if code := getJSON(t, ts, path, &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}

	want := qlog.Query{
		Search: "example", Outcome: "blocked", Proto: "udp",
		Client: "10.0.0.1", Upstream: "cf",
	}
	if ctl.lastQuery != want {
		t.Errorf("query = %+v, want %+v", ctl.lastQuery, want)
	}
	if ctl.lastPage != 2 || ctl.lastPer != 50 {
		t.Errorf("page/per = %d/%d, want 2/50", ctl.lastPage, ctl.lastPer)
	}
	if got.Total != 250 || got.Page != 2 || got.Per != 50 || got.Pages != 5 {
		t.Errorf("shape = total %d page %d per %d pages %d, want 250/2/50/5",
			got.Total, got.Page, got.Per, got.Pages)
	}
	if len(got.Entries) != 2 || got.Entries[0].QName != "a.example.com." {
		t.Errorf("entries = %+v, want the scripted page", got.Entries)
	}
}

// TestRequestsPagedDefaults checks the paged clamps: page below 1
// becomes 1, per above 500 becomes 500, and a filter parameter alone
// switches on the paged shape.
func TestRequestsPagedDefaults(t *testing.T) {
	ctl := &fakeController{
		queryFn: func(qlog.Query, int, int) ([]qlog.Entry, int) { return nil, 0 },
	}

	ts := newTestServer(t, ctl)
	var got api.RequestsPage
	if code := getJSON(t, ts, "/api/v1/requests?page=0&per=100000", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastPage != 1 || ctl.lastPer != 500 {
		t.Errorf("page/per = %d/%d, want 1/500", ctl.lastPage, ctl.lastPer)
	}
	if got.Page != 1 || got.Per != 500 {
		t.Errorf("echo = page %d per %d, want 1/500", got.Page, got.Per)
	}
	if got.Pages != 1 {
		t.Errorf("Pages = %d, want 1 for an empty result", got.Pages)
	}

	// An empty page must serialize as [] rather than null.
	resp, err := http.Get(ts.URL + "/api/v1/requests?page=1")
	if err != nil {
		t.Fatalf("GET requests = %v, want nil", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(raw), `"entries":[]`) {
		t.Errorf("empty page body = %s, want entries:[]", raw)
	}

	// A lone filter parameter selects the paged shape with defaults.
	if code := getJSON(t, ts, "/api/v1/requests?q=ads", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastPage != 1 || ctl.lastPer != 100 {
		t.Errorf("default page/per = %d/%d, want 1/100", ctl.lastPage, ctl.lastPer)
	}
	if ctl.lastQuery.Search != "ads" {
		t.Errorf("filter = %+v, want search ads", ctl.lastQuery)
	}

	// page/per are the paged trigger too: n must not be honoured.
	if code := getJSON(t, ts, "/api/v1/requests?n=5&page=1", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastRequests != 0 {
		t.Errorf("legacy Requests called with n=%d in paged mode, want 0", ctl.lastRequests)
	}
}

// TestRequestsUnknownOutcome checks an unrecognised outcome name is
// treated as no filter rather than rejected.
func TestRequestsUnknownOutcome(t *testing.T) {
	ctl := &fakeController{
		queryFn: func(qlog.Query, int, int) ([]qlog.Entry, int) { return nil, 0 },
	}

	ts := newTestServer(t, ctl)
	var got api.RequestsPage
	if code := getJSON(t, ts, "/api/v1/requests?outcome=bogus", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if ctl.lastQuery.Outcome != "" {
		t.Errorf("outcome = %q, want an empty filter", ctl.lastQuery.Outcome)
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
