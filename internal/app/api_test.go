package app_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/api"
	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/qlog"
)

// unixClient returns an HTTP client talking to the unix socket.
func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 3 * time.Second,
	}
}

// unixStreamClient is unixClient without the overall timeout, for SSE.
func unixStreamClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// startAppAPI starts an app with a temp control socket and the given
// config persisted; the app and the socket path are returned.
func startAppAPI(t *testing.T, cfg *config.Config) (*app.App, string) {
	t.Helper()

	opts := testOptions(t)
	if err := cfg.Save(opts.ConfigPath); err != nil {
		t.Fatalf("cfg.Save() = %v, want nil", err)
	}

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

	return a, opts.SocketPath
}

// TestAppServesAPI checks the control API on the daemon socket.
func TestAppServesAPI(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	_, sock := startAppAPI(t, cfg)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/api/v1/status")
	if err != nil {
		t.Fatalf("GET status = %v, want nil", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want 200", resp.StatusCode)
	}

	var st api.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Domain != cfg.Domain {
		t.Errorf("domain = %q, want %q", st.Domain, cfg.Domain)
	}
	if len(st.Upstreams) != 1 {
		t.Fatalf("upstreams = %d, want 1", len(st.Upstreams))
	}
	if st.Upstreams[0].Address != fake.Addr() {
		t.Errorf("upstream address = %q, want %q", st.Upstreams[0].Address, fake.Addr())
	}
	if len(st.Links) == 0 {
		t.Errorf("links = empty, want the enabled protocols")
	}
	if len(st.Listeners) == 0 {
		t.Errorf("listeners = empty, want the enabled listeners")
	}
}

// TestAppAPIEvents checks the SSE stream end to end: a DNS query shows
// up as a requests event.
func TestAppAPIEvents(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	_, sock := startAppAPI(t, cfg)

	cl := unixStreamClient(sock)
	resp, err := cl.Get("http://unix/api/v1/events")
	if err != nil {
		t.Fatalf("GET events = %v, want nil", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	lines := make(chan string, 200)
	go func() {
		defer close(lines)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	// Make a DNS query over the running server.
	dnsCl := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := dnsCl.Exchange(query("example.com"), loopback(port)); err != nil {
		t.Fatalf("DNS Exchange() = %v, want nil", err)
	}

	deadline := time.After(4 * time.Second)
	seenType := false
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("stream ended before the request event")
			}
			if strings.Contains(line, "event: requests") {
				seenType = true
			}
			if seenType && strings.Contains(line, "example.com.") {
				return // the request event arrived
			}
		case <-deadline:
			t.Fatalf("request event did not arrive on the stream")
		}
	}
}

// TestAppFilterUpdateViaAPI checks the manual list refresh over the
// API, including the unknown-list error.
func TestAppFilterUpdateViaAPI(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "||ads.example.com^\n")
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig(t, fake, port)
	cfg.Filter = config.FilterConfig{
		Enabled: true,
		Mode:    "zero",
		Lists:   []config.FilterList{{ID: "test-list", URL: srv.URL + "/list.txt"}},
	}

	opts := testOptions(t)
	opts.FilterClient = tlsSkipClient()
	opts.FilterInterval = 50 * time.Millisecond
	if err := cfg.Save(opts.ConfigPath); err != nil {
		t.Fatalf("cfg.Save() = %v, want nil", err)
	}
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
		return len(st) == 1 && st[0].Applied == 1
	})

	cl := unixClient(opts.SocketPath)

	body, _ := json.Marshal(map[string]string{"id": "test-list"})
	resp, err := cl.Post("http://unix/api/v1/filter/update", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST filter/update = %v, want nil", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want 200", resp.StatusCode)
	}

	body, _ = json.Marshal(map[string]string{"id": "nope"})
	resp, err = cl.Post("http://unix/api/v1/filter/update", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST filter/update (unknown) = %v, want nil", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("unknown list status code = %d, want 500", resp.StatusCode)
	}
}

// TestAppStatsAndPagedRequests checks the stats and history endpoints
// end to end over the daemon socket: real queries feed the cumulative
// counters, and the filtered history view pages over them.
func TestAppStatsAndPagedRequests(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	cfg.Filter = config.FilterConfig{
		Enabled:   true,
		Mode:      "zero",
		UserBlock: []string{"blocked.example.com"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate() = %v, want nil", err)
	}
	_, sock := startAppAPI(t, cfg)

	ask := func(name string) {
		t.Helper()
		cl := &dns.Client{Net: "udp", Timeout: time.Second}
		if _, _, err := cl.Exchange(query(name), loopback(port)); err != nil {
			t.Fatalf("Exchange(%s) = %v, want nil", name, err)
		}
	}
	ask("one.example.com") // forwarded upstream
	ask("one.example.com") // ...then served from the cache
	for i := 0; i < 5; i++ {
		ask("blocked.example.com") // filtered, never cached
	}

	cl := unixClient(sock)

	var st api.StatsResponse
	getJSONUnix(t, cl, "/api/v1/stats", &st)
	if st.Total != 7 {
		t.Errorf("stats total = %d, want 7", st.Total)
	}
	if st.Outcomes["blocked"] != 5 || st.Outcomes["cached"] != 1 || st.Outcomes["upstream"] != 1 {
		t.Errorf("stats outcomes = %v, want blocked=5 cached=1 upstream=1", st.Outcomes)
	}
	if st.Upstreams["fake"] != 1 {
		t.Errorf("stats upstreams = %v, want fake=1", st.Upstreams)
	}
	if st.Since.IsZero() || st.Since.After(time.Now()) {
		t.Errorf("stats since = %v, want a real past start time", st.Since)
	}

	var page api.RequestsPage
	getJSONUnix(t, cl, "/api/v1/requests?outcome=blocked&per=2&page=2", &page)
	if page.Total != 5 || page.Pages != 3 || page.Page != 2 || page.Per != 2 {
		t.Errorf("page shape = total %d pages %d page %d per %d, want 5/3/2/2",
			page.Total, page.Pages, page.Page, page.Per)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("page entries = %d, want 2", len(page.Entries))
	}
	for _, e := range page.Entries {
		if !e.Blocked || e.QName != "blocked.example.com." {
			t.Errorf("entry = %+v, want a blocked.example.com. block", e)
		}
	}

	var legacy []qlog.Entry
	getJSONUnix(t, cl, "/api/v1/requests?n=3", &legacy)
	if len(legacy) != 3 {
		t.Errorf("legacy entries = %d, want 3", len(legacy))
	}
}

// getJSONUnix fetches path over the unix-socket client and decodes the
// JSON body, failing the test on a non-200 response.
func getJSONUnix(t *testing.T, cl *http.Client, path string, v any) {
	t.Helper()
	resp, err := cl.Get("http://unix" + path)
	if err != nil {
		t.Fatalf("GET %s = %v, want nil", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// TestAppStopClosesSocket checks the socket is gone once Stop returns.
func TestAppStopClosesSocket(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	a, sock := startAppAPI(t, cfg)

	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	if err := a.Stop(sctx); err != nil {
		t.Fatalf("Stop() = %v, want nil", err)
	}

	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket still exists after Stop: %v", err)
	}
}
