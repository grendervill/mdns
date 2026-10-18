package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/auth"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/qlog"
	"mydns/internal/stats"
	"mydns/internal/tlscert"
)

// errFakeApply is the scripted failure a manageCtrl returns from
// UpdateConfig or FilterUpdate in the failure-path tests.
var errFakeApply = errors.New("fake apply failure")

// authVerify is a shorthand for auth.Verify in the password test.
func authVerify(hash, pw string) bool { return auth.Verify(hash, pw) }

// tlscertStatus builds a certificate snapshot with the shipped fields.
func tlscertStatus(_ *testing.T, mode, state, issuer, notAfter, errText string) tlscert.Status {
	s := tlscert.Status{Mode: mode, State: state, Issuer: issuer, Error: errText}
	if notAfter != "" {
		s.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		s.LastCheck = time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC)
	}
	return s
}

// manageHash is a syntactically valid argon2id PHC string. The management
// tests never sign in, so it only has to satisfy config.Validate's
// "panel enabled needs a hash" rule; the password-change test asserts on
// the real hash the panel mints.
const manageHash = "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// manageCtrl is a scripted daemon for the management pages. It records
// every configuration it is handed and every list refresh, so a test can
// assert exactly what a page sent. UpdateConfig validates the config the
// way the real app does, then honours a scripted failure.
type manageCtrl struct {
	mu sync.Mutex

	cfg   *config.Config
	st    api.Status
	lists []filter.ListStatus

	updates   []*config.Config
	updateErr error

	refreshes  []string
	refreshErr error

	// refreshPanic makes FilterUpdate panic with this value, standing in
	// for a controller bug that would otherwise crash the daemon.
	refreshPanic any

	// refreshStarted receives the id of every FilterUpdate call before
	// the call blocks on refreshGate, so a test can observe a background
	// refresh while it is still in flight.
	refreshStarted chan string
	refreshGate    <-chan struct{}

	started time.Time
}

func (c *manageCtrl) Config() *config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func (c *manageCtrl) Status(context.Context) (api.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st, nil
}

// UpdateConfig validates first, exactly like app.UpdateConfig, so an
// invalid form reaches the page as a real error even without a daemon.
func (c *manageCtrl) UpdateConfig(_ context.Context, next *config.Config) error {
	if err := next.Validate(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.updateErr != nil {
		return c.updateErr
	}
	c.updates = append(c.updates, next)
	c.cfg = next
	return nil
}

func (c *manageCtrl) Stats() stats.Snapshot { return stats.Snapshot{} }

func (c *manageCtrl) StatsRange(time.Time, time.Time) stats.Snapshot { return stats.Snapshot{} }

func (c *manageCtrl) Requests(int) []qlog.Entry { return nil }

func (c *manageCtrl) RequestsQuery(qlog.Query, int, int) ([]qlog.Entry, int) { return nil, 0 }

func (c *manageCtrl) FilterStatus() []filter.ListStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lists
}

func (c *manageCtrl) FilterUpdate(_ context.Context, id string) error {
	if c.refreshStarted != nil {
		c.refreshStarted <- id
	}
	if c.refreshGate != nil {
		<-c.refreshGate
	}
	if c.refreshPanic != nil {
		panic(c.refreshPanic)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshErr != nil {
		return c.refreshErr
	}
	c.refreshes = append(c.refreshes, id)
	return nil
}

func (c *manageCtrl) Started() time.Time { return c.started }

// sent returns the configs UpdateConfig accepted, oldest first.
func (c *manageCtrl) sent() []*config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*config.Config(nil), c.updates...)
}

// refreshed returns the list IDs FilterUpdate was asked for.
func (c *manageCtrl) refreshed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.refreshes...)
}

// manageConfig is a valid config with the panel on, so a management
// form can round-trip through config.Validate.
func manageConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.Domain = "dns.example.test"
	cfg.Panel = config.PanelConfig{Enabled: true, PasswordHash: manageHash}
	return cfg
}

// manageUpstreams is the two-upstream fixture: one live, one off.
func manageUpstreams(cfg *config.Config) {
	cfg.Upstreams = []config.UpstreamConfig{
		{ID: "cloudflare", Name: "Cloudflare", Transport: "doh", Address: "https://cloudflare-dns.com/dns-query", Priority: 0, Enabled: true},
		{ID: "quad9", Name: "Quad9", Transport: "doq", Address: "dns.quad9.net:853", Priority: 1, Enabled: false},
	}
}

// managePOST posts a form to a panel page with a fresh session and the
// matching CSRF token. It does not follow redirects, so the caller sees
// the 303 and its Location.
func managePOST(t *testing.T, p *Panel, srv *httptest.Server, path string, form url.Values) (*http.Response, string) {
	t.Helper()

	token, err := p.sessions.Create()
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set(csrfField, p.csrfToken(sessionCSRFBinding(token)))

	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})

	return doManage(t, srv, req)
}

// rawPOST posts with a valid session but no CSRF token, for the
// rejection check.
func rawPOST(t *testing.T, p *Panel, srv *httptest.Server, path string, form url.Values) (*http.Response, string) {
	t.Helper()

	token, err := p.sessions.Create()
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	return doManage(t, srv, req)
}

// doManage performs a request with a redirect-refusing client and drains
// the body.
func doManage(t *testing.T, srv *httptest.Server, req *http.Request) (*http.Response, string) {
	t.Helper()

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", req.URL.Path, err)
	}
	return resp, string(body)
}

// wantRedirect asserts a 303 to exactly want.
func wantRedirect(t *testing.T, resp *http.Response, want string) {
	t.Helper()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// managePanel mounts a panel over ctrl with the version the status tests
// use, so the maintenance page has something to render.
func managePanel(t *testing.T, ctrl *manageCtrl) (*Panel, *httptest.Server) {
	t.Helper()
	return statusPanel(t, ctrl)
}

// ---- upstreams ---------------------------------------------------

// TestUpstreamsPage checks the table: both upstreams, the live state
// from Status, the per-row flip control and the priority editor.
func TestUpstreamsPage(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	ctrl := &manageCtrl{
		cfg: cfg,
		st: api.Status{Upstreams: []api.UpstreamStatus{
			{ID: "cloudflare", Name: "Cloudflare", Transport: "doh", Address: "https://cloudflare-dns.com/dns-query", Enabled: true, Healthy: true, LatencyMS: 21, Sent: 98, Failed: 2},
			{ID: "quad9", Name: "Quad9", Transport: "doq", Address: "dns.quad9.net:853", Enabled: false},
		}},
	}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/upstreams")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/upstreams = %d, want 200\n%s", code, body)
	}

	wants := []string{
		"Upstream’ы",
		"стратегия", "fastest",
		"Cloudflare", "Quad9",
		"doh", "https://cloudflare-dns.com/dns-query",
		"здоров", "выключен",
		"21 мс", "98 %",
		`name="prio.cloudflare" value="0"`,
		`name="prio.quad9" value="1"`,
		`action="/panel/upstreams/priority"`,
		`formaction="/panel/upstreams/toggle"`,
		`name="id" value="cloudflare"`,
		`name="id" value="quad9"`,
		"Выключить", "Включить",
		"Сохранить порядок",
		` class="on" aria-current="page" href="/panel/upstreams"`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("upstreams page is missing %q", want)
		}
	}
	assertNoInlineAssets(t, body)
}

// TestUpstreamToggle checks the soft flip: the whole config goes to
// UpdateConfig with exactly one flag changed.
func TestUpstreamToggle(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	original := cfg
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/upstreams/toggle", url.Values{"id": {"quad9"}})
	wantRedirect(t, resp, "/panel/upstreams?ok=upstream")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	got := sent[0]

	if !got.Upstreams[1].Enabled {
		t.Error("quad9 was not enabled")
	}
	if !got.Upstreams[0].Enabled || got.Upstreams[0].Address != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("the other upstream changed: %+v", got.Upstreams[0])
	}
	// The whole config travels, not a patch.
	if got.Domain != cfg.Domain || got.Strategy != cfg.Strategy || got.Cache != cfg.Cache || got.Panel.PasswordHash != manageHash {
		t.Errorf("the full config did not travel:\n%+v", got)
	}
	if len(got.Upstreams) != 2 {
		t.Errorf("upstreams = %d, want the full list of 2", len(got.Upstreams))
	}

	// The page edits a copy: the config it read from the daemon is
	// untouched, so a rejected apply cannot have changed anything.
	if original.Upstreams[1].Enabled {
		t.Error("the page mutated the live config in place instead of sending a copy")
	}
	if got == original {
		t.Error("the page sent the live config pointer instead of a copy")
	}
}

// TestUpstreamToggleFailure checks the failure path: the page re-renders
// with the error and never claims the change landed.
func TestUpstreamToggleFailure(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	ctrl := &manageCtrl{cfg: cfg, updateErr: errFakeApply}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/upstreams/toggle", url.Values{"id": {"quad9"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, errFakeApply.Error()) {
		t.Errorf("the page does not show the failure %q", errFakeApply)
	}
	if strings.Contains(body, "upstream переключён") || strings.Contains(body, `class="flash"`) {
		t.Error("the page claims the toggle succeeded after a failure")
	}
	if len(ctrl.sent()) != 0 {
		t.Error("a failed toggle was recorded as applied")
	}
}

// TestUpstreamPriority saves the whole priority column at once.
func TestUpstreamPriority(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/upstreams/priority", url.Values{
		"prio.cloudflare": {"2"},
		"prio.quad9":      {"0"},
	})
	wantRedirect(t, resp, "/panel/upstreams?ok=priority")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	if got := sent[0].Upstreams[0].Priority; got != 2 {
		t.Errorf("cloudflare priority = %d, want 2", got)
	}
	if got := sent[0].Upstreams[1].Priority; got != 0 {
		t.Errorf("quad9 priority = %d, want 0", got)
	}
	if sent[0].Upstreams[0].Enabled != cfg.Upstreams[0].Enabled {
		t.Error("the priority save changed the enabled flags")
	}
}

// TestUpstreamStrategy saves each of the four strategies and rejects an
// unknown one.
func TestUpstreamStrategy(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	for i, strategy := range []string{"fastest", "failover", "round_robin", "random"} {
		resp, body := managePOST(t, p, srv, "/panel/upstreams/strategy", url.Values{"strategy": {strategy}})
		wantRedirect(t, resp, "/panel/upstreams?ok=strategy")
		if got := ctrl.sent(); len(got) != i+1 {
			t.Fatalf("UpdateConfig called %d times, want %d\n%s", len(got), i+1, body)
		}
	}
	sent := ctrl.sent()
	if sent[3].Strategy != "random" {
		t.Errorf("strategy = %q, want random", sent[3].Strategy)
	}
	if len(sent[3].Upstreams) != 2 {
		t.Error("the strategy save dropped the upstreams")
	}

	t.Run("unknown strategy", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/upstreams/strategy", url.Values{"strategy": {"bogus"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "bogus") {
			t.Error("the page does not name the rejected strategy")
		}
		if len(ctrl.sent()) != 4 {
			t.Error("an unknown strategy reached UpdateConfig")
		}
	})
}

// TestUpstreamAddCatalog adds provider endpoints from the catalog,
// picks a unique ID and rejects a duplicate address.
func TestUpstreamAddCatalog(t *testing.T) {
	cfg := manageConfig(t) // no upstreams yet
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/upstreams/add", url.Values{"provider": {"cloudflare|doh"}})
	wantRedirect(t, resp, "/panel/upstreams?ok=upstream")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	got := sent[0].Upstreams
	if len(got) != 1 {
		t.Fatalf("upstreams = %d, want 1", len(got))
	}
	u := got[0]
	if u.ID != "cloudflare" || u.Transport != "doh" || u.Address != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("added upstream = %+v, want Cloudflare DoH", u)
	}
	if !u.Enabled || u.Priority != 0 {
		t.Errorf("added upstream enabled/priority = %v/%d, want true/0", u.Enabled, u.Priority)
	}

	// A second transport of the same provider gets a suffixed, unique ID.
	resp, _ = managePOST(t, p, srv, "/panel/upstreams/add", url.Values{"provider": {"cloudflare|plain"}})
	wantRedirect(t, resp, "/panel/upstreams?ok=upstream")
	sent = ctrl.sent()
	if len(sent) != 2 || len(sent[1].Upstreams) != 2 {
		t.Fatalf("second add: %d configs, %d upstreams", len(sent), len(sent[1].Upstreams))
	}
	if second := sent[1].Upstreams[1]; second.ID != "cloudflare-plain" || second.Priority != 1 {
		t.Errorf("second upstream = %+v, want id cloudflare-plain with priority 1", second)
	}

	t.Run("duplicate endpoint", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/upstreams/add", url.Values{"provider": {"cloudflare|doh"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "уже добавлен") {
			t.Errorf("the duplicate message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 2 {
			t.Error("a duplicate endpoint reached UpdateConfig")
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/upstreams/add", url.Values{"provider": {"nope|doh"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if len(ctrl.sent()) != 2 {
			t.Error("an unknown provider reached UpdateConfig")
		}
	})
}

// TestUpstreamCustom stores a hand-written upstream and validates its
// fields.
func TestUpstreamCustom(t *testing.T) {
	cfg := manageConfig(t)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/upstreams/custom", url.Values{
		"id": {"my-dns"}, "name": {"My DNS"}, "transport": {"dot"},
		"address": {"10.0.0.1:853"}, "server_name": {"dns.internal"}, "priority": {"5"},
	})
	wantRedirect(t, resp, "/panel/upstreams?ok=upstream")

	sent := ctrl.sent()
	if len(sent) != 1 || len(sent[0].Upstreams) != 1 {
		t.Fatalf("UpdateConfig calls/upstreams = %d/%v\n%s", len(sent), sent, body)
	}
	u := sent[0].Upstreams[0]
	if u.ID != "my-dns" || u.Name != "My DNS" || u.Transport != "dot" || u.Address != "10.0.0.1:853" ||
		u.ServerName != "dns.internal" || u.Priority != 5 || !u.Enabled {
		t.Errorf("custom upstream = %+v", u)
	}

	t.Run("derived id and default priority", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/upstreams/custom", url.Values{
			"transport": {"plain"}, "address": {"1.1.1.1:53"},
		})
		wantRedirect(t, resp, "/panel/upstreams?ok=upstream")
		got := ctrl.sent()
		if len(got) != 2 || len(got[1].Upstreams) != 2 {
			t.Fatalf("second custom: %d configs", len(got))
		}
		second := got[1].Upstreams[1]
		if second.ID != "1-1-1-1" {
			t.Errorf("derived id = %q, want 1-1-1-1", second.ID)
		}
		if second.Priority != 6 {
			t.Errorf("default priority = %d, want max+1 = 6", second.Priority)
		}
		if second.Name != "1-1-1-1" {
			t.Errorf("default name = %q, want the id", second.Name)
		}
	})

	t.Run("empty address", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/upstreams/custom", url.Values{
			"id": {"x"}, "transport": {"plain"}, "address": {"  "},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "адрес") {
			t.Error("the missing-address message is absent")
		}
	})

	t.Run("unknown transport", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/upstreams/custom", url.Values{
			"id": {"x"}, "transport": {"bogus"}, "address": {"1.1.1.1:53"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("duplicate id", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/upstreams/custom", url.Values{
			"id": {"my-dns"}, "transport": {"plain"}, "address": {"2.2.2.2:53"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if len(ctrl.sent()) != 2 {
			t.Error("a duplicate id reached UpdateConfig")
		}
	})
}

// TestUpstreamRemove refuses to remove the last enabled upstream and
// removes any other.
func TestUpstreamRemove(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg) // cloudflare enabled, quad9 disabled
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/upstreams/remove", url.Values{"id": {"cloudflare"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("removing the last enabled upstream = %d, want 400\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "последн") {
		t.Errorf("the last-upstream message is missing:\n%s", body)
	}
	if len(ctrl.sent()) != 0 {
		t.Error("a refused removal reached UpdateConfig")
	}

	resp, _ = managePOST(t, p, srv, "/panel/upstreams/remove", url.Values{"id": {"quad9"}})
	wantRedirect(t, resp, "/panel/upstreams?ok=upstream")
	sent := ctrl.sent()
	if len(sent) != 1 || len(sent[0].Upstreams) != 1 || sent[0].Upstreams[0].ID != "cloudflare" {
		t.Errorf("after removing quad9: %v", sent)
	}

	t.Run("unknown id", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/upstreams/remove", url.Values{"id": {"nope"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// TestEndpointOptions checks the catalog picker: non-empty, unique
// values, and a Cloudflare DoH entry.
func TestEndpointOptions(t *testing.T) {
	opts := endpointOptions()
	if len(opts) == 0 {
		t.Fatal("endpointOptions is empty")
	}
	seen := make(map[string]bool, len(opts))
	foundCloudflare := false
	for _, o := range opts {
		if seen[o.Value] {
			t.Errorf("duplicate endpoint option %q", o.Value)
		}
		seen[o.Value] = true
		if o.Value == "cloudflare|doh" &&
			strings.Contains(o.Label, "Cloudflare") &&
			strings.Contains(o.Label, "DoH") &&
			strings.Contains(o.Label, "https://cloudflare-dns.com/dns-query") {
			foundCloudflare = true
		}
	}
	if !foundCloudflare {
		t.Error("the Cloudflare DoH entry is missing")
	}
}

// ---- filters -----------------------------------------------------

// manageFilterConfig is a config with the filter engine on. It carries
// no list so a test can add one without failing the built-in catalog
// lookup (the panel never resolves list URLs).
func manageFilters(cfg *config.Config) {
	cfg.Filter.Enabled = true
	cfg.Filter.Mode = "nxdomain"
	cfg.Filter.UserAllow = []string{"good.example.com"}
	cfg.Filter.UserBlock = []string{"ads.example.com"}
}

// TestFiltersPage checks the lists table, the mode radios and the user
// rules, plus the disabled note.
func TestFiltersPage(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	// The table is driven by the config, so both lists the status reports
	// are also configured; their state columns come from the status.
	cfg.Filter.Lists = []config.FilterList{{ID: "oisd"}, {ID: "user"}}
	ctrl := &manageCtrl{
		cfg: cfg,
		st:  api.Status{Filter: api.FilterSnapshot{Enabled: true, Mode: "nxdomain", TotalBlocked: 12481}},
		lists: []filter.ListStatus{
			{ID: "oisd", URL: "https://example.test/oisd.txt", UpdatedAt: time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC), Applied: 101_000, Skipped: 42},
			{ID: "user", Error: "fetch failed"},
		},
	}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/filters")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/filters = %d, want 200\n%s", code, body)
	}

	wants := []string{
		"Фильтры",
		"Списки", "oisd", "user",
		"101 000", "42",
		"18.10 09:30:00",
		"ок", "ошибка",
		`action="/panel/filters/refresh"`,
		"Обновить", "Обновить все",
		`name="id" value=""`,
		`action="/panel/filters/mode"`,
		`name="mode" value="zero"`, `name="mode" value="nxdomain"`, `name="mode" value="refused"`,
		`value="nxdomain" checked`,
		"12 481",
		"Разрешённые", "Заблокированные",
		"good.example.com", "ads.example.com",
		`action="/panel/filters/rules/add"`,
		`action="/panel/filters/rules/remove"`,
		`name="kind"`,
		` class="on" aria-current="page" href="/panel/filters"`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("filters page is missing %q", want)
		}
	}

	t.Run("disabled filter", func(t *testing.T) {
		off := manageConfig(t)
		c := &manageCtrl{cfg: off}
		p2, srv2 := managePanel(t, c)
		code, body := authedGET(t, p2, srv2, "/panel/filters")
		if code != http.StatusOK {
			t.Fatalf("GET /panel/filters = %d, want 200", code)
		}
		if !strings.Contains(body, "Фильтрация выключена") {
			t.Error("the disabled filter note is missing")
		}
		if !strings.Contains(body, "Списки не заданы") {
			t.Error("the empty-lists note is missing")
		}
	})
}

// TestFiltersListsTable checks the lists table is built from the config,
// not only from the updater's live status: a just-configured list the
// updater has not reported yet still renders with a placeholder state and
// its refresh control, a status the config carries wins over the
// placeholder, and a status the config no longer carries is not shown.
func TestFiltersListsTable(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	cfg.Filter.Lists = []config.FilterList{{ID: "adguard-base"}, {ID: "oisd"}}
	ctrl := &manageCtrl{
		cfg: cfg,
		lists: []filter.ListStatus{
			{ID: "oisd", URL: "https://example.test/oisd.txt", UpdatedAt: time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC), Applied: 101_000, Skipped: 42},
			{ID: "stale-list", URL: "https://example.test/gone.txt"},
		},
	}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/filters")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/filters = %d, want 200\n%s", code, body)
	}
	wants := []string{
		"adguard-base",
		"не загружен",
		`name="id" value="adguard-base">Обновить`,
		"101 000", "18.10 09:30:00",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("filters page is missing %q", want)
		}
	}
	if strings.Contains(body, "stale-list") {
		t.Error("the table shows a status entry the config no longer carries")
	}
	if strings.Contains(body, "Списки не заданы") {
		t.Error("the empty-lists note is shown while lists are configured")
	}
}

// TestFiltersRefresh checks the single-flight asynchronous refresh: the
// POST returns at once, a second one while the update is in flight is
// refused with a banner, and the background goroutine eventually
// completes with the id the first POST asked for. The gate keeps the
// goroutine blocked for as long as the assertions need; every wait is
// bounded so a regression fails instead of hanging the suite.
func TestFiltersRefresh(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	started := make(chan string, 2)
	gate := make(chan struct{})
	ctrl := &manageCtrl{cfg: cfg, refreshStarted: started, refreshGate: gate}
	p, srv := managePanel(t, ctrl)
	// Bound this test's requests: if the handler regressed to running the
	// download synchronously, the first POST fails fast instead of hanging
	// until the go test timeout.
	srv.Client().Timeout = 5 * time.Second

	begin := time.Now()
	resp, body := managePOST(t, p, srv, "/panel/filters/refresh", url.Values{"id": {"oisd"}})
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("the refresh POST took %s; it must return without waiting for the download", elapsed)
	}
	wantRedirect(t, resp, "/panel/filters?ok=lists")

	select {
	case id := <-started:
		if id != "oisd" {
			t.Errorf("FilterUpdate id = %q, want oisd", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the background FilterUpdate did not start")
	}

	resp, body = managePOST(t, p, srv, "/panel/filters/refresh", url.Values{"id": {""}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second refresh while one runs = %d, want 409\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "обновление уже идёт") {
		t.Errorf("the second POST does not show «обновление уже идёт»:\n%s", body)
	}

	code, page := authedGET(t, p, srv, "/panel/filters?ok=lists")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/filters?ok=lists = %d, want 200", code)
	}
	if !strings.Contains(page, "обновление запущено") {
		t.Errorf("the success banner «обновление запущено» is missing:\n%s", page)
	}

	close(gate)
	waitFor(t, "the first refresh to complete", func() bool { return len(ctrl.refreshed()) == 1 })
	if got := ctrl.refreshed(); got[0] != "oisd" {
		t.Errorf("completed refresh = %q, want [oisd]", got)
	}
	waitFor(t, "the single-flight flag to clear", func() bool { return !p.refresh.isRunning() })

	// The single-list path is the same path; a later POST (id "") must
	// start a fresh background refresh once the first one finished.
	resp, _ = managePOST(t, p, srv, "/panel/filters/refresh", url.Values{"id": {""}})
	wantRedirect(t, resp, "/panel/filters?ok=lists")
	waitFor(t, "the all-lists refresh to complete", func() bool { return len(ctrl.refreshed()) == 2 })
	if got := ctrl.refreshed(); got[1] != "" {
		t.Errorf("completed refresh = %q, want [oisd \"\"]", got)
	}
	select {
	case id := <-started:
		if id != "" {
			t.Errorf("second FilterUpdate id = %q, want the empty all-lists id", id)
		}
	case <-time.After(2 * time.Second):
		t.Error("the second background FilterUpdate did not start")
	}
}

// TestFiltersRefreshPanic checks that a panicking updater cannot take the
// daemon down: the POST still redirects, the process keeps serving, and
// the single-flight flag clears so later refreshes are accepted.
func TestFiltersRefreshPanic(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	ctrl := &manageCtrl{cfg: cfg, refreshPanic: "boom", refreshStarted: make(chan string, 1)}
	p, srv := managePanel(t, ctrl)

	resp, _ := managePOST(t, p, srv, "/panel/filters/refresh", url.Values{"id": {"oisd"}})
	wantRedirect(t, resp, "/panel/filters?ok=lists")

	// The panicking updater really ran (the message is sent before the
	// panic); without recovery this goroutine would take the process down.
	select {
	case id := <-ctrl.refreshStarted:
		if id != "oisd" {
			t.Errorf("FilterUpdate id = %q, want oisd", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the background FilterUpdate did not start")
	}

	waitFor(t, "the single-flight flag to clear after the panic", func() bool {
		return !p.refresh.isRunning()
	})

	// The recover kept the process alive: the panel still answers.
	code, page := authedGET(t, p, srv, "/panel/filters?ok=lists")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/filters?ok=lists after the panic = %d, want 200\n%s", code, page)
	}
	if !strings.Contains(page, "обновление запущено") {
		t.Errorf("the success banner «обновление запущено» is missing after the panic:\n%s", page)
	}
	if got := ctrl.refreshed(); len(got) != 0 {
		t.Errorf("a panicking FilterUpdate recorded %q, want nothing", got)
	}
}

// waitFor polls cond until it reports true or a short deadline expires.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestFilterMode sends the whole config with a new block mode.
func TestFilterMode(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/filters/mode", url.Values{"mode": {"refused"}})
	wantRedirect(t, resp, "/panel/filters?ok=mode")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	if sent[0].Filter.Mode != "refused" {
		t.Errorf("Filter.Mode = %q, want refused", sent[0].Filter.Mode)
	}
	if !sent[0].Filter.Enabled || len(sent[0].Filter.UserBlock) != 1 {
		t.Error("the mode change dropped other filter settings")
	}

	t.Run("unknown mode is rejected", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/filters/mode", url.Values{"mode": {"nonsense"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "nonsense") {
			t.Error("the page does not name the rejected mode")
		}
		if len(ctrl.sent()) != 1 {
			t.Error("an unknown mode was sent to UpdateConfig")
		}
	})
}

// TestFilterRules adds and removes one rule in the right list.
func TestFilterRules(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	// Add an allow rule; it is normalized and lands in UserAllow.
	resp, body := managePOST(t, p, srv, "/panel/filters/rules/add", url.Values{
		"kind": {"allow"}, "domain": {"Extra.Example.COM."},
	})
	wantRedirect(t, resp, "/panel/filters?ok=rule")
	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	if got := sent[0].Filter.UserAllow; len(got) != 2 || got[1] != "extra.example.com" {
		t.Errorf("UserAllow = %q, want [good.example.com extra.example.com]", got)
	}
	if got := sent[0].Filter.UserBlock; len(got) != 1 || got[0] != "ads.example.com" {
		t.Errorf("UserBlock = %q, want it untouched", got)
	}

	// Remove an allow rule; only that list shrinks.
	resp, _ = managePOST(t, p, srv, "/panel/filters/rules/remove", url.Values{
		"kind": {"allow"}, "domain": {"good.example.com"},
	})
	wantRedirect(t, resp, "/panel/filters?ok=rule")
	sent = ctrl.sent()
	if len(sent) != 2 {
		t.Fatalf("UpdateConfig called %d times, want 2", len(sent))
	}
	if got := sent[1].Filter.UserAllow; len(got) != 1 || got[0] != "extra.example.com" {
		t.Errorf("UserAllow = %q, want [extra.example.com]", got)
	}
	if got := sent[1].Filter.UserBlock; len(got) != 1 {
		t.Errorf("UserBlock = %q, want it untouched", got)
	}

	t.Run("empty domain", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/filters/rules/add", url.Values{
			"kind": {"block"}, "domain": {"  "},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "Укажите домен") {
			t.Errorf("the empty-domain message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 2 {
			t.Error("an empty domain reached UpdateConfig")
		}
	})

	t.Run("single-label domain", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/filters/rules/add", url.Values{
			"kind": {"block"}, "domain": {"localhost"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "localhost") {
			t.Error("the rejected domain is not echoed")
		}
		if len(ctrl.sent()) != 2 {
			t.Error("a single-label domain reached UpdateConfig")
		}
	})
}

// TestFilterListAdd covers the catalog add and the custom list add,
// including the rejected forms.
func TestFilterListAdd(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg) // filter on, no lists
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	// A ready-made catalog list is stored with an empty URL.
	resp, body := managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{"id": {"oisd-small"}})
	wantRedirect(t, resp, "/panel/filters?ok=list")
	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	if got := sent[0].Filter.Lists; len(got) != 1 || got[0].ID != "oisd-small" || got[0].URL != "" {
		t.Errorf("lists = %+v, want [{oisd-small }]", got)
	}
	if !sent[0].Filter.Enabled {
		t.Error("adding a list silently changed the filter enabled flag")
	}

	// A custom list is stored with its slug and URL.
	resp, _ = managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{
		"custom_id": {"my-list"}, "custom_url": {"https://example.test/hosts.txt"},
	})
	wantRedirect(t, resp, "/panel/filters?ok=list")
	sent = ctrl.sent()
	if len(sent) != 2 {
		t.Fatalf("UpdateConfig called %d times, want 2", len(sent))
	}
	if got := sent[1].Filter.Lists; len(got) != 2 || got[1].ID != "my-list" || got[1].URL != "https://example.test/hosts.txt" {
		t.Errorf("lists = %+v, want the custom list appended", got)
	}

	t.Run("duplicate catalog add", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{"id": {"oisd-small"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "уже добавлен") {
			t.Errorf("the duplicate message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 2 {
			t.Error("a duplicate catalog list reached UpdateConfig")
		}
	})

	t.Run("unknown catalog id", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{"id": {"no-such-list"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if len(ctrl.sent()) != 2 {
			t.Error("an unknown catalog id reached UpdateConfig")
		}
	})

	t.Run("http url rejected", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{
			"custom_id": {"plain-http"}, "custom_url": {"http://example.test/hosts.txt"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "https") {
			t.Error("the https-required message is missing")
		}
		if len(ctrl.sent()) != 2 {
			t.Error("an http list reach UpdateConfig")
		}
	})

	t.Run("empty url rejected", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{
			"custom_id": {"no-url"}, "custom_url": {""},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("bad slug rejected", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/filters/lists/add", url.Values{
			"custom_id": {"Bad_Slug"}, "custom_url": {"https://example.test/hosts.txt"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "ID списка") {
			t.Error("the slug message is missing")
		}
		if len(ctrl.sent()) != 2 {
			t.Error("a bad slug reached UpdateConfig")
		}
	})
}

// TestFilterListRemove drops one list only.
func TestFilterListRemove(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	cfg.Filter.Lists = []config.FilterList{
		{ID: "oisd-small"},
		{ID: "hagezi-pro"},
		{ID: "my-list", URL: "https://example.test/hosts.txt"},
	}
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/filters/lists/remove", url.Values{"id": {"hagezi-pro"}})
	wantRedirect(t, resp, "/panel/filters?ok=list")
	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	got := sent[0].Filter.Lists
	if len(got) != 2 || got[0].ID != "oisd-small" || got[1].ID != "my-list" {
		t.Errorf("lists = %+v, want oisd-small and my-list", got)
	}

	t.Run("unknown id", func(t *testing.T) {
		resp, _ := managePOST(t, p, srv, "/panel/filters/lists/remove", url.Values{"id": {"no-such"}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if len(ctrl.sent()) != 1 {
			t.Error("an unknown list id reached UpdateConfig")
		}
	})
}

// TestFiltersCatalogPage checks the ready-made list section renders the
// catalog with the Russian category and the added state.
func TestFiltersCatalogPage(t *testing.T) {
	cfg := manageConfig(t)
	manageFilters(cfg)
	cfg.Filter.Lists = []config.FilterList{{ID: "oisd-small"}}
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/filters")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/filters = %d, want 200\n%s", code, body)
	}
	wants := []string{
		"Готовые списки",
		"реклама и трекеры", "комбинированные",
		`action="/panel/filters/lists/add"`,
		`action="/panel/filters/lists/remove"`,
		`value="adguard-dns-filter"`,
		"OISD Small",
		"Убрать", "Добавить",
		"Свой список",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("filters page is missing %q", want)
		}
	}
	assertNoInlineAssets(t, body)

	t.Run("disabled disables the buttons", func(t *testing.T) {
		off := manageConfig(t) // filter off
		c := &manageCtrl{cfg: off}
		p2, srv2 := managePanel(t, c)
		_, body := authedGET(t, p2, srv2, "/panel/filters")
		if !strings.Contains(body, " disabled") {
			t.Error("the catalog buttons are not disabled while filtering is off")
		}
		if !strings.Contains(body, "Фильтрация выключена") {
			t.Error("the disabled hint is missing")
		}
	})
}

// ---- settings ----------------------------------------------------

// validSettingsForm is a complete, valid settings submission.
func validSettingsForm() url.Values {
	return url.Values{
		"domain":                       {"dns.example.test"},
		"plain.enabled":                {"on"},
		"plain.port":                   {"53"},
		"doh.enabled":                  {"on"},
		"doh.port":                     {"443"},
		"dot.enabled":                  {"on"},
		"dot.port":                     {"853"},
		"doq.enabled":                  {"on"},
		"doq.port":                     {"853"},
		"strategy":                     {"fastest"},
		"cache.size":                   {"10000"},
		"cache.min_ttl":                {"0"},
		"cache.max_ttl":                {"86400"},
		"limits.plain_rps_per_ip":      {"50"},
		"filter.enabled":               {"on"},
		"filter.update_interval_hours": {"24"},
	}
}

// TestSettingsPage renders the form from the live config.
func TestSettingsPage(t *testing.T) {
	cfg := manageConfig(t)
	cfg.Filter.Enabled = true
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/settings")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/settings = %d, want 200\n%s", code, body)
	}

	wants := []string{
		"Настройки",
		`action="/panel/settings"`,
		`name="domain" value="dns.example.test"`,
		`name="plain.enabled" checked`,
		`name="plain.port" value="53"`,
		`name="doh.port" value="443"`,
		`name="dot.port" value="853"`,
		`name="doq.port" value="853"`,
		`name="strategy"`,
		`value="fastest" selected`,
		`name="timezone" value=""`,
		`name="cache.size" value="10000"`,
		`name="cache.min_ttl" value="0"`,
		`name="cache.max_ttl" value="86400"`,
		`name="limits.plain_rps_per_ip" value="50"`,
		`name="filter.enabled" checked`,
		`name="filter.update_interval_hours" value="24"`,
		"Применить",
		`action="/panel/settings/password"`,
		"Сменить пароль",
		`name="password"`, `name="password2"`,
		` class="on" aria-current="page" href="/panel/settings"`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	assertNoInlineAssets(t, body)
}

// TestSettingsTimezone checks the settings form's «Часовой пояс» field: a
// valid IANA zone persists, the form shows the stored zone and its
// datalist, and a bad zone re-renders with the error while the live
// config stays unchanged.
func TestSettingsTimezone(t *testing.T) {
	t.Run("a valid zone is saved", func(t *testing.T) {
		cfg := manageConfig(t)
		ctrl := &manageCtrl{cfg: cfg}
		p, srv := managePanel(t, ctrl)

		form := validSettingsForm()
		form.Set("timezone", "Europe/Moscow")
		resp, body := managePOST(t, p, srv, "/panel/settings", form)
		wantRedirect(t, resp, "/panel/settings?ok=settings")

		sent := ctrl.sent()
		if len(sent) != 1 {
			t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
		}
		if sent[0].Timezone != "Europe/Moscow" {
			t.Errorf("saved Timezone = %q, want Europe/Moscow", sent[0].Timezone)
		}
	})

	t.Run("the form shows the stored zone and datalist", func(t *testing.T) {
		cfg := manageConfig(t)
		cfg.Timezone = "Asia/Almaty"
		p, srv := managePanel(t, &manageCtrl{cfg: cfg})

		code, body := authedGET(t, p, srv, "/panel/settings")
		if code != http.StatusOK {
			t.Fatalf("GET /panel/settings = %d, want 200", code)
		}
		for _, want := range []string{
			`name="timezone" value="Asia/Almaty"`,
			`id="tz-zones"`,
			`value="Europe/Moscow"`,
			`value="UTC"`,
			"IANA-зона, пусто — системная",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("the settings page is missing %q", want)
			}
		}
	})

	t.Run("an unknown zone is rejected and changes nothing", func(t *testing.T) {
		cfg := manageConfig(t)
		ctrl := &manageCtrl{cfg: cfg}
		p, srv := managePanel(t, ctrl)

		form := validSettingsForm()
		form.Set("timezone", "Mars/Base")
		resp, body := managePOST(t, p, srv, "/panel/settings", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "timezone") || !strings.Contains(body, "Mars/Base") {
			t.Errorf("the re-rendered page does not report the bad zone:\n%s", body)
		}
		if !strings.Contains(body, `name="timezone" value="Mars/Base"`) {
			t.Error("the form does not echo the rejected value")
		}
		if len(ctrl.sent()) != 0 {
			t.Error("UpdateConfig ran for a config Validate rejects")
		}
		if ctrl.cfg.Timezone != "" {
			t.Errorf("live config timezone = %q, want it unchanged", ctrl.cfg.Timezone)
		}
	})
}

// TestSettingsApply sends the edited values in the full config.
func TestSettingsApply(t *testing.T) {
	cfg := manageConfig(t)
	cfg.Limits.TrustedCIDRs = []string{"10.0.0.0/8"}
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	form := validSettingsForm()
	form.Set("domain", "new.example.test")
	form.Set("strategy", "failover")
	form.Set("cache.size", "20000")
	form.Set("plain.port", "5533")
	form.Del("doq.enabled") // the checkbox was cleared

	resp, body := managePOST(t, p, srv, "/panel/settings", form)
	wantRedirect(t, resp, "/panel/settings?ok=settings")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	got := sent[0]
	if got.Domain != "new.example.test" || got.Strategy != "failover" {
		t.Errorf("domain/strategy = %q/%q, want new.example.test/failover", got.Domain, got.Strategy)
	}
	if got.Cache.Size != 20000 {
		t.Errorf("cache size = %d, want 20000", got.Cache.Size)
	}
	if got.Protocols.Plain.Port != 5533 {
		t.Errorf("plain port = %d, want 5533", got.Protocols.Plain.Port)
	}
	if got.Protocols.DoQ.Enabled {
		t.Error("doq was not disabled by the cleared checkbox")
	}
	if got.Panel.PasswordHash != manageHash {
		t.Error("the apply dropped the panel password hash")
	}
	if len(got.Limits.TrustedCIDRs) != 1 || got.Limits.TrustedCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("trusted CIDRs = %q, want [10.0.0.0/8] (the apply must preserve fields the form does not edit)",
			got.Limits.TrustedCIDRs)
	}

	t.Run("success banner", func(t *testing.T) {
		code, body := authedGET(t, p, srv, "/panel/settings?ok=settings")
		if code != http.StatusOK {
			t.Fatalf("GET /panel/settings?ok=settings = %d, want 200", code)
		}
		if !strings.Contains(body, "применено") {
			t.Errorf("the success banner «применено» is missing:\n%s", body)
		}
	})
}

// TestSettingsInvalid checks that a rejected apply re-renders the form
// with the error and the values the admin typed.
func TestSettingsInvalid(t *testing.T) {
	cfg := manageConfig(t)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	t.Run("port 0", func(t *testing.T) {
		form := validSettingsForm()
		form.Set("domain", "typed.example.test")
		form.Set("plain.port", "0")

		resp, body := managePOST(t, p, srv, "/panel/settings", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "port 0 out of range") {
			t.Errorf("the validation error is missing:\n%s", body)
		}
		// The submitted values survive the re-render.
		if !strings.Contains(body, `name="plain.port" value="0"`) {
			t.Error("the submitted port was not preserved")
		}
		if !strings.Contains(body, `name="domain" value="typed.example.test"`) {
			t.Error("the submitted domain was not preserved")
		}
		if len(ctrl.sent()) != 0 {
			t.Error("an invalid config was applied")
		}
	})

	t.Run("unknown strategy", func(t *testing.T) {
		form := validSettingsForm()
		form.Set("strategy", "bogus")

		resp, body := managePOST(t, p, srv, "/panel/settings", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "unknown strategy") {
			t.Errorf("the validation error is missing:\n%s", body)
		}
		if !strings.Contains(body, `value="bogus" selected`) {
			t.Errorf("the submitted strategy was not preserved:\n%s", body)
		}
		if len(ctrl.sent()) != 0 {
			t.Error("an invalid config was applied")
		}
	})

	t.Run("non-numeric port", func(t *testing.T) {
		form := validSettingsForm()
		form.Set("doh.port", "https")

		resp, body := managePOST(t, p, srv, "/panel/settings", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "ожидается число") {
			t.Errorf("the parse error is missing:\n%s", body)
		}
	})
}

// TestPasswordChange hashes the new password and stores only the hash.
func TestPasswordChange(t *testing.T) {
	cfg := manageConfig(t)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	const newPassword = "a much better password"
	resp, body := managePOST(t, p, srv, "/panel/settings/password", url.Values{
		"password": {newPassword}, "password2": {newPassword},
	})
	wantRedirect(t, resp, "/panel/settings?ok=password")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	hash := sent[0].Panel.PasswordHash
	if hash == newPassword || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("stored password = %q, want an argon2id hash of the plaintext", hash)
	}
	if !authVerify(hash, newPassword) {
		t.Error("the stored hash does not verify the submitted password")
	}
	if authVerify(hash, "not the password") {
		t.Error("the stored hash verifies a wrong password")
	}
	if !sent[0].Panel.Enabled {
		t.Error("the password change disabled the panel")
	}

	t.Run("too short", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/settings/password", url.Values{
			"password": {"short"}, "password2": {"short"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "8") {
			t.Errorf("the minimum-length message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 1 {
			t.Error("a too-short password was applied")
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/settings/password", url.Values{
			"password": {"a much better password"}, "password2": {"a much better passwore"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "не совпадают") {
			t.Errorf("the mismatch message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 1 {
			t.Error("a mismatched password was applied")
		}
	})

	t.Run("four Cyrillic runes are too short", func(t *testing.T) {
		// "тест" is four runes but eight bytes: a byte-length check
		// would wrongly accept it, the shared rune-count validator
		// rejects it.
		resp, body := managePOST(t, p, srv, "/panel/settings/password", url.Values{
			"password": {"тест"}, "password2": {"тест"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (4 runes, 8 bytes)\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "не короче") {
			t.Errorf("the minimum-length message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 1 {
			t.Error("a 4-rune Cyrillic password was applied")
		}
	})

	t.Run("padded password is rejected", func(t *testing.T) {
		resp, body := managePOST(t, p, srv, "/panel/settings/password", url.Values{
			"password": {" pw "}, "password2": {" pw "},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400\n%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "пробел") {
			t.Errorf("the whitespace message is missing:\n%s", body)
		}
		if len(ctrl.sent()) != 1 {
			t.Error("a padded password was applied")
		}
	})

	t.Run("eight-character password is accepted", func(t *testing.T) {
		const eight = "12345678"
		resp, body := managePOST(t, p, srv, "/panel/settings/password", url.Values{
			"password": {eight}, "password2": {eight},
		})
		wantRedirect(t, resp, "/panel/settings?ok=password")

		sent := ctrl.sent()
		if len(sent) != 2 {
			t.Fatalf("UpdateConfig called %d times, want 2\n%s", len(sent), body)
		}
		if hash := sent[1].Panel.PasswordHash; !authVerify(hash, eight) {
			t.Errorf("stored hash %q does not verify the eight-character password", hash)
		}
	})
}

// ---- certificate -------------------------------------------------

// TestCertPage renders the certificate block from Status and the TLS
// mode from the config.
func TestCertPage(t *testing.T) {
	cfg := manageConfig(t)
	cfg.TLS = config.TLS{
		Mode: "acme",
		ACME: config.ACME{Provider: "letsencrypt", Email: "admin@example.test"},
	}
	ctrl := &manageCtrl{
		cfg: cfg,
		st:  api.Status{Cert: tlscertStatus(t, "acme", "ok", "Let's Encrypt", "2027-01-15T12:00:00Z", "")},
	}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/cert")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/cert = %d, want 200\n%s", code, body)
	}

	wants := []string{
		"Сертификат", "Действует", "Let&#39;s Encrypt", "15.01.2027",
		"acme", "letsencrypt", "admin@example.test",
		"mdns setup",
		` class="on" aria-current="page" href="/panel/cert"`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("cert page is missing %q", want)
		}
	}

	t.Run("error state", func(t *testing.T) {
		badCfg := manageConfig(t)
		c := &manageCtrl{cfg: badCfg, st: api.Status{Cert: tlscertStatus(t, "acme", "error", "", "", "dns-01 challenge failed")}}
		p2, srv2 := managePanel(t, c)
		_, body := authedGET(t, p2, srv2, "/panel/cert")
		if !strings.Contains(body, "Ошибка") || !strings.Contains(body, "dns-01 challenge failed") {
			t.Errorf("the certificate error is not rendered:\n%s", body)
		}
	})
}

// ---- maintenance -------------------------------------------------

// TestMaintenancePage renders the version, the uptime and both actions.
func TestMaintenancePage(t *testing.T) {
	cfg := manageConfig(t)
	ctrl := &manageCtrl{cfg: cfg, started: time.Now().Add(-50 * time.Hour)}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/maintenance")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/maintenance = %d, want 200\n%s", code, body)
	}

	wants := []string{
		"Обслуживание", "v-test", "2 дня",
		`href="/panel/maintenance/config.json"`, "Скачать конфиг",
		`action="/panel/maintenance/reapply"`, "Применить конфиг заново",
		"хэш пароля", "EAB",
		` class="on" aria-current="page" href="/panel/maintenance"`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("maintenance page is missing %q", want)
		}
	}
}

// TestConfigDownload streams the config as a pretty JSON attachment.
func TestConfigDownload(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	manageFilters(cfg)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/maintenance/config.json")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/maintenance/config.json = %d, want 200", code)
	}

	var got config.Config
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("the download is not JSON: %v\n%s", err, body)
	}
	if got.Domain != cfg.Domain || got.Panel.PasswordHash != cfg.Panel.PasswordHash {
		t.Errorf("the download does not carry the live config: %+v", got)
	}
	if len(got.Upstreams) != 2 || len(got.Filter.UserBlock) != 1 {
		t.Error("the download dropped the parts of the config the panel never touches")
	}
	if !strings.Contains(body, "{\n  \"version\"") {
		t.Errorf("the JSON is not indented:\n%s", body[:min(len(body), 120)])
	}
}

// TestReapply sends the current config back through UpdateConfig.
func TestReapply(t *testing.T) {
	cfg := manageConfig(t)
	original := cfg
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := managePOST(t, p, srv, "/panel/maintenance/reapply", nil)
	wantRedirect(t, resp, "/panel/maintenance?ok=reapply")

	sent := ctrl.sent()
	if len(sent) != 1 {
		t.Fatalf("UpdateConfig called %d times, want 1\n%s", len(sent), body)
	}
	if sent[0].Domain != cfg.Domain || sent[0].Strategy != cfg.Strategy {
		t.Errorf("the reapplied config differs: %+v", sent[0])
	}
	// The page hands over a copy, so the daemon's config is not aliased.
	if sent[0] == original {
		t.Error("the reapply passed the live config pointer instead of a copy")
	}
}

// ---- cross-cutting ------------------------------------------------

// TestManagePagesSharedShell walks the five new pages: each renders the
// full rail and keeps the strict CSP promise (no inline style/script).
func TestManagePagesSharedShell(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	manageFilters(cfg)
	ctrl := &manageCtrl{
		cfg: cfg,
		st: api.Status{
			Filter: api.FilterSnapshot{Enabled: true, Mode: "zero"},
			Cert:   tlscertStatus(t, "self-signed", "ok", "mdns self-signed", "2027-01-15T12:00:00Z", ""),
		},
	}
	p, srv := managePanel(t, ctrl)

	pages := []string{"/panel/upstreams", "/panel/filters", "/panel/settings", "/panel/cert", "/panel/maintenance"}
	rail := []string{
		`href="/panel/"`, `href="/panel/history"`, `href="/panel/upstreams"`,
		`href="/panel/filters"`, `href="/panel/cert"`, `href="/panel/settings"`,
		`href="/panel/maintenance"`, `action="/logout"`,
	}
	for _, path := range pages {
		code, body := authedGET(t, p, srv, path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200\n%s", path, code, body)
			continue
		}
		for _, want := range rail {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing the rail entry %q", path, want)
			}
		}
		if n := strings.Count(body, `aria-current="page"`); n != 1 {
			t.Errorf("%s marks %d rail entries active, want 1", path, n)
		}
		assertNoInlineAssets(t, body)
	}
}

// TestManageCSRFRejected spot-checks the token gate on a brand-new route.
func TestManageCSRFRejected(t *testing.T) {
	cfg := manageConfig(t)
	manageUpstreams(cfg)
	ctrl := &manageCtrl{cfg: cfg}
	p, srv := managePanel(t, ctrl)

	resp, body := rawPOST(t, p, srv, "/panel/upstreams/toggle", url.Values{"id": {"quad9"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /panel/upstreams/toggle without a token = %d, want 403\n%s", resp.StatusCode, body)
	}
	if len(ctrl.sent()) != 0 {
		t.Error("a CSRF-less request changed the config")
	}
}

// assertNoInlineAssets fails when a page carries an inline style or a
// script element, which the panel's CSP forbids.
func assertNoInlineAssets(t *testing.T, body string) {
	t.Helper()

	if strings.Contains(body, "style=") {
		t.Error(`page carries an inline style="…" attribute (forbidden by the CSP)`)
	}
	if strings.Contains(body, "<style") {
		t.Error("page carries an inline <style> element (forbidden by the CSP)")
	}
	if strings.Contains(body, "<script>") {
		t.Error("page carries an inline <script> element (forbidden by the CSP)")
	}
}
