package panel

import (
	"bufio"
	"context"
	"fmt"
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
	"mydns/internal/links"
	"mydns/internal/qlog"
	"mydns/internal/stats"
	"mydns/internal/tlscert"
)

// statusCtrl is a scripted daemon: it returns one fixed status and one
// fixed statistics snapshot, and it serves a small recent-query list
// for the feed's backfill.
type statusCtrl struct {
	cfg    *config.Config
	st     api.Status
	sn     stats.Snapshot
	recent []qlog.Entry
}

func (c *statusCtrl) Config() *config.Config { return c.cfg }

func (c *statusCtrl) Status(context.Context) (api.Status, error) { return c.st, nil }

func (c *statusCtrl) Stats() stats.Snapshot { return c.sn }

// Requests returns the newest n entries, oldest first — the contract the
// real daemon has (qlog.Log.Recent).
func (c *statusCtrl) Requests(n int) []qlog.Entry {
	if n > len(c.recent) {
		n = len(c.recent)
	}
	if n <= 0 {
		return nil
	}
	return c.recent[len(c.recent)-n:]
}

// quietLogger drops every log line.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// statusPanel mounts a panel on a plain test server. The tests sign in
// by minting a session directly, so they exercise the page, not the
// login flow (that is panel_test.go's job).
func statusPanel(t *testing.T, ctrl Controller) (*Panel, *httptest.Server) {
	t.Helper()
	return statusPanelBus(t, ctrl, nil)
}

// statusPanelBus is statusPanel with a live event bus.
func statusPanelBus(t *testing.T, ctrl Controller, bus *api.Bus) (*Panel, *httptest.Server) {
	t.Helper()

	p := New(Options{
		Enabled:      true,
		PasswordHash: "unused: these tests mint a session directly",
		Version:      "v-test",
		Logger:       quietLogger(),
		Ctrl:         ctrl,
		Bus:          bus,
	})

	mux := http.NewServeMux()
	p.Mount(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return p, srv
}

// authedGET requests path with a fresh valid session cookie and returns
// the status and the drained body.
func authedGET(t *testing.T, p *Panel, srv *httptest.Server, path string) (int, string) {
	t.Helper()

	resp := authedRequest(t, p, srv, path)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

// authedRequest requests path with a fresh valid session cookie and
// returns the live response, for streaming endpoints.
func authedRequest(t *testing.T, p *Panel, srv *httptest.Server, path string) *http.Response {
	t.Helper()

	token, err := p.sessions.Create()
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// mockupStatus is the scripted daemon behind TestStatusRenders. The
// statistics deliberately repeat the approved mockup's 74 / 19 / 6.7 /
// 0.3 split (740 + 190 + 67 + 3 = 1000), so the page can be compared
// against the mockup's figure.
func mockupStatus() *statusCtrl {
	return &statusCtrl{
		cfg: &config.Config{Domain: "dns.example.test"},
		st: api.Status{
			Version: "v9",
			Links: []links.Link{
				{Proto: "doh", Title: "DoH (DNS-over-HTTPS)", URI: "https://dns.example.test/dns-query"},
				{Proto: "plain", Title: "Обычный DNS (для роутеров)", URI: "dns.example.test:53"},
			},
			Cache: cache.Stats{Hits: 96, Misses: 4, Size: 71208},
			Upstreams: []api.UpstreamStatus{
				{ID: "cloudflare", Name: "Cloudflare", Healthy: true, LatencyMS: 21.4},
				{ID: "quad9", Name: "Quad9", Healthy: true, LatencyMS: 28},
				{ID: "google", Name: "Google", Healthy: false, LatencyMS: 5},
			},
			Cert: tlscert.Status{
				Mode:     "acme",
				State:    "ok",
				Issuer:   "Let's Encrypt",
				NotAfter: time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC),
			},
		},
		sn: stats.Snapshot{
			Total: 1000,
			Outcomes: map[string]uint64{
				"cached": 740, "upstream": 190, "blocked": 67, "error": 3,
			},
			Protos:    map[string]uint64{"udp": 610, "doh": 220, "dot": 100, "doq": 70},
			Upstreams: map[string]uint64{"cloudflare": 580, "quad9": 250, "google": 170},
			Clients: []stats.ClientCount{
				{IP: "192.168.1.12", Count: 410},
				{IP: "остальные", Count: 590},
			},
		},
		recent: []qlog.Entry{
			{QName: "api.github.com.", QType: 1, Proto: "udp", Upstream: "cloudflare", LatencyMS: 21},
			{QName: "ads.doubleclick.net.", QType: 1, Proto: "udp", Blocked: true, BlockSource: "oisd"},
			{QName: "cdn.jsdelivr.net.", QType: 1, Proto: "doh", CacheHit: true},
		},
	}
}

// TestStatusRenders checks the whole status screen: every section of the
// approved mockup is present, the donuts carry the mockup's segment
// geometry and click-through links, and the page keeps the strict CSP
// promise (no inline styles).
func TestStatusRenders(t *testing.T) {
	p, srv := statusPanel(t, mockupStatus())

	code, body := authedGET(t, p, srv, "/panel/")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/ = %d, want 200\n%s", code, body)
	}

	sections := []string{
		"Статус", "Запросов всего", "Кеш", "Заблокировано", "Лучший upstream",
		"Куда идут запросы", "Ответы", "Протоколы", "Кто ответил (upstream’ы)", "Клиенты",
		"Живая лента", "Адреса для устройств", "Сертификат", "Действует",
	}
	for _, want := range sections {
		if !strings.Contains(body, want) {
			t.Errorf("status page is missing %q", want)
		}
	}

	// The mockup's dasharrays and offsets, straight from its figure:
	// slice starts are 0, 74, 93 and 99.7 percent, so the offsets are
	// 25 minus each of those.
	geometry := []string{
		`stroke-dasharray="74 26"`, `stroke-dashoffset="25"`,
		`stroke-dasharray="19 81"`, `stroke-dashoffset="-49"`,
		`stroke-dasharray="6.7 93.3"`, `stroke-dashoffset="-68"`,
		`stroke-dasharray="0.3 99.7"`, `stroke-dashoffset="-74.7"`,
	}
	for _, want := range geometry {
		if !strings.Contains(body, want) {
			t.Errorf("donut geometry is missing %q", want)
		}
	}

	links := []string{
		`href="/panel/history?outcome=cached"`,
		`href="/panel/history?outcome=upstream"`,
		`href="/panel/history?outcome=blocked"`,
		`href="/panel/history?outcome=error"`,
		`href="/panel/history?proto=udp"`,
		`href="/panel/history?upstream=cloudflare"`,
		`href="/panel/history?client=192.168.1.12"`,
	}
	for _, want := range links {
		if !strings.Contains(body, want) {
			t.Errorf("donut is missing its history link %q", want)
		}
	}

	labels := []string{
		`data-label="кеш"`, `data-value="74 % · 740"`,
		`data-label="udp (обычный)"`, `data-label="Cloudflare"`, `data-label="192.168.1.12"`,
		`data-label="остальные"`,
	}
	for _, want := range labels {
		if !strings.Contains(body, want) {
			t.Errorf("donut is missing %q", want)
		}
	}

	// Gauges: the mockup's wording and the scripted numbers.
	gauges := []string{"1 000", "96 %", "71 208 записей", "67", "6,7 %", "21 мс"}
	for _, want := range gauges {
		if !strings.Contains(body, want) {
			t.Errorf("gauge area is missing %q", want)
		}
	}

	// Device links and the certificate block.
	if !strings.Contains(body, "https://dns.example.test/dns-query") {
		t.Error("device links are missing the DoH address")
	}
	if !strings.Contains(body, "dns.example.test:53") {
		t.Error("device links are missing the plain DNS address")
	}
	if !strings.Contains(body, "Let&#39;s Encrypt") {
		t.Error("certificate block is missing the issuer")
	}
	if !strings.Contains(body, "15.01.2027") {
		t.Error("certificate block is missing the expiry")
	}

	// The feed is backfilled from Requests, newest first.
	feedRows := strings.Count(body, `class="q"`)
	if feedRows != 3 {
		t.Errorf("feed has %d rows, want 3 (the backfilled ones)", feedRows)
	}
	if i, j := strings.Index(body, "cdn.jsdelivr.net."), strings.Index(body, "api.github.com."); i < 0 || j < 0 || i > j {
		t.Errorf("feed order: newest (cdn.jsdelivr.net.) must precede oldest (api.github.com.)")
	}

	// Strict CSP: no inline styles, no inline scripts.
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

// TestDonutMath pins the segment geometry to the mockup: dasharray is
// "pct 100-pct" and dashoffset is 25 - cumulative start percent, so the
// first segment starts at the top. The 74/19/6.7/0.3 case is the
// mockup's "Ответы" figure; the single 100 % case is a full ring.
func TestDonutMath(t *testing.T) {
	t.Run("mockup 74/19/6.7/0.3", func(t *testing.T) {
		// 740 + 190 + 67 + 3 = 1000 exactly repeats the mockup's split.
		got := donut([]share{{Value: 740}, {Value: 190}, {Value: 67}, {Value: 3}})
		want := []arc{
			{Offset: 25, Dash: 74, Gap: 26},
			{Offset: -49, Dash: 19, Gap: 81},
			{Offset: -68, Dash: 6.7, Gap: 93.3},
			{Offset: -74.7, Dash: 0.3, Gap: 99.7},
		}
		if len(got) != len(want) {
			t.Fatalf("donut() returned %d arcs, want %d", len(got), len(want))
		}
		var sum float64
		for i := range want {
			if !closeEnough(got[i].Dash, want[i].Dash) {
				t.Errorf("arc %d dash = %v, want %v", i, got[i].Dash, want[i].Dash)
			}
			if !closeEnough(got[i].Gap, want[i].Gap) {
				t.Errorf("arc %d gap = %v, want %v", i, got[i].Gap, want[i].Gap)
			}
			if !closeEnough(got[i].Offset, want[i].Offset) {
				t.Errorf("arc %d offset = %v, want %v", i, got[i].Offset, want[i].Offset)
			}
			sum += got[i].Dash
		}
		if sum < 99.9 || sum > 100.1 {
			t.Errorf("share sum = %v, want 100±0.1", sum)
		}
	})

	t.Run("a single full ring", func(t *testing.T) {
		got := donut([]share{{Value: 5}})
		if len(got) != 1 {
			t.Fatalf("donut() returned %d arcs, want 1", len(got))
		}
		if got[0] != (arc{Offset: 25, Dash: 100, Gap: 0}) {
			t.Errorf("single arc = %+v, want {25 100 0}", got[0])
		}
	})
}

// closeEnough compares two rounded percentages.
func closeEnough(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }

// TestStatusFeedBuffer checks the server-side rolling buffer and the
// event stream's snapshot frame.
func TestStatusFeedBuffer(t *testing.T) {
	t.Run("the buffer keeps the newest 30", func(t *testing.T) {
		f := newFeed(feedSize)
		for i := 0; i < 100; i++ {
			f.push(qlog.Entry{QName: fmt.Sprintf("q%03d.", i)})
		}
		snap := f.snapshot()
		if len(snap) != feedSize {
			t.Fatalf("buffer len = %d, want %d", len(snap), feedSize)
		}
		if snap[0].QName != "q099." {
			t.Errorf("newest entry = %q, want q099.", snap[0].QName)
		}
		if snap[feedSize-1].QName != "q070." {
			t.Errorf("oldest kept entry = %q, want q070.", snap[feedSize-1].QName)
		}
	})

	t.Run("the snapshot frame carries the backfill", func(t *testing.T) {
		ctrl := mockupStatus()
		p, srv := statusPanel(t, ctrl)

		resp := authedRequest(t, p, srv, "/panel/events")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /panel/events = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
			t.Fatalf("Content-Type = %q, want text/event-stream", ct)
		}

		events := readSSE(t, resp.Body, 2)
		if len(events) < 2 {
			t.Fatalf("read %d events, want at least 2 (ping, snapshot)", len(events))
		}
		if events[0].name != "ping" {
			t.Errorf("first event = %q, want ping", events[0].name)
		}
		if events[1].name != "snapshot" {
			t.Fatalf("second event = %q, want snapshot", events[1].name)
		}
		for _, qname := range []string{"api.github.com.", "ads.doubleclick.net.", "cdn.jsdelivr.net."} {
			if !strings.Contains(events[1].data, qname) {
				t.Errorf("snapshot frame is missing %q: %s", qname, events[1].data)
			}
		}
		if !strings.Contains(events[1].data, `class="q"`) {
			t.Errorf("snapshot frame is not feed-row HTML: %s", events[1].data)
		}
		if strings.ContainsAny(events[1].data, "\n\r") {
			t.Errorf("snapshot frame contains a raw newline, which would split the SSE data: %q", events[1].data)
		}
	})
}

// sseEvent is one parsed Server-Sent Event.
type sseEvent struct {
	name string
	data string
}

// readSSE reads until it has collected want complete events.
func readSSE(t *testing.T, r io.Reader, want int) []sseEvent {
	t.Helper()

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	var (
		events []sseEvent
		cur    sseEvent
	)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.name != "" {
				events = append(events, cur)
				cur = sseEvent{}
			}
			if len(events) >= want {
				return events
			}
		case strings.HasPrefix(line, "event: "):
			cur.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
		}
	}
	return events
}

// nextSSE reads one event from br, failing when none arrives in time.
func nextSSE(t *testing.T, br *bufio.Reader) sseEvent {
	t.Helper()

	type result struct {
		event sseEvent
		err   error
	}
	done := make(chan result, 1)
	go func() {
		var cur sseEvent
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				done <- result{err: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				if cur.name != "" {
					done <- result{event: cur}
					return
				}
			case strings.HasPrefix(line, "event: "):
				cur.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				cur.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("reading the event stream: %v", r.err)
		}
		return r.event
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for an event")
		return sseEvent{}
	}
}

// TestStatusLiveRow checks the stream's live end to end: with a bus
// wired, a query published after the snapshot arrives as a row frame.
func TestStatusLiveRow(t *testing.T) {
	bus := api.NewBus()
	p, srv := statusPanelBus(t, mockupStatus(), bus)

	resp := authedRequest(t, p, srv, "/panel/events")
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	if got := nextSSE(t, br); got.name != "ping" {
		t.Fatalf("first event = %q, want ping", got.name)
	}
	if got := nextSSE(t, br); got.name != "snapshot" {
		t.Fatalf("second event = %q, want snapshot", got.name)
	}

	bus.Publish(api.Event{Type: "requests", Data: qlog.Entry{
		Time: time.Now(), QName: "live.test.", QType: 1, Proto: "udp",
		Upstream: "cloudflare", LatencyMS: 9,
	}})

	row := nextSSE(t, br)
	if row.name != "row" {
		t.Fatalf("event after the publish = %q, want row", row.name)
	}
	for _, want := range []string{"live.test.", `class="q"`, `class="tag ok"`, "9 мс · cloudflare"} {
		if !strings.Contains(row.data, want) {
			t.Errorf("row frame is missing %q: %s", want, row.data)
		}
	}
}

// TestStaticAssetsForCSP pins the two static-asset promises behind the
// strict CSP: app.js stops htmx from injecting its indicator <style>,
// and app.css carries the rules htmx would have injected.
func TestStaticAssetsForCSP(t *testing.T) {
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("reading app.js: %v", err)
	}
	if !strings.Contains(string(js), "includeIndicatorStyles = false") {
		t.Error("app.js does not disable htmx's injected indicator styles")
	}

	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("reading app.css: %v", err)
	}
	for _, want := range []string{".htmx-indicator", ".htmx-request"} {
		if !strings.Contains(string(css), want) {
			t.Errorf("app.css is missing the htmx indicator rule %q", want)
		}
	}
}

// TestGaugeFormats checks the derived gauge values: the best upstream is
// the fastest healthy one, the cache share rounds the way the mockup
// shows it, and the client overflow bucket survives into the diagram.
func TestGaugeFormats(t *testing.T) {
	t.Run("best upstream is the fastest healthy one", func(t *testing.T) {
		ups := []api.UpstreamStatus{
			{ID: "a", Name: "Slow", Healthy: true, LatencyMS: 40},
			{ID: "b", Name: "Fast", Healthy: true, LatencyMS: 12.6},
			{ID: "c", Name: "Down but quick", Healthy: false, LatencyMS: 3},
		}
		best, ok := bestUpstream(ups)
		if !ok {
			t.Fatal("bestUpstream() found nothing, want the healthy Fast")
		}
		if best.Name != "Fast" {
			t.Errorf("best upstream = %q, want Fast (an unhealthy one must not win)", best.Name)
		}

		if _, ok := bestUpstream([]api.UpstreamStatus{{ID: "x", Healthy: false, LatencyMS: 1}}); ok {
			t.Error("bestUpstream() reported an upstream with none healthy")
		}
	})

	t.Run("cache share rounds", func(t *testing.T) {
		pct, ok := cacheHitPercent(cache.Stats{Hits: 96, Misses: 4})
		if !ok || formatPercent(pct) != "96" {
			t.Errorf("cacheHitPercent(96/4) = %v ok=%v, want 96", pct, ok)
		}
		pct, ok = cacheHitPercent(cache.Stats{Hits: 9641, Misses: 359})
		if !ok || formatPercent(pct) != "96,4" {
			t.Errorf("cacheHitPercent(9641/10000) = %v, want 96,4", pct)
		}
		if _, ok := cacheHitPercent(cache.Stats{}); ok {
			t.Error("cacheHitPercent() with no lookups should not report a share")
		}
	})

	t.Run("the overflow client bucket renders", func(t *testing.T) {
		shares := clientShares(stats.Snapshot{
			Clients: []stats.ClientCount{
				{IP: "192.168.1.12", Count: 410},
				{IP: "остальные", Count: 590},
			},
		})
		if len(shares) != 2 || shares[1].Label != "остальные" {
			t.Fatalf("clientShares() = %+v, want the overflow bucket as the second share", shares)
		}
		if shares[1].Href != "" {
			t.Errorf("the overflow bucket must not link to a client filter, got %q", shares[1].Href)
		}
		if shares[0].Href != "/panel/history?client=192.168.1.12" {
			t.Errorf("client share href = %q", shares[0].Href)
		}

		// And it reaches the page.
		p, srv := statusPanel(t, mockupStatus())
		_, body := authedGET(t, p, srv, "/panel/")
		if !strings.Contains(body, "остальные") {
			t.Error("status page does not render the client overflow bucket")
		}
	})
}
