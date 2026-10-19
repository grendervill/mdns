package panel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/configbackup"
	"mydns/internal/filter"
	"mydns/internal/links"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
	"mydns/internal/stats"
	"mydns/internal/tlscert"
)

// statusCtrl is a scripted daemon: it returns one fixed status and one
// fixed statistics snapshot, and it serves a small recent-query list
// for the feed's backfill. The cumulative Snapshot and the range
// snapshot are separate fields so a test can tell which one a page
// used; the range call is remembered for the period tests.
type statusCtrl struct {
	cfg     *config.Config
	st      api.Status
	sn      stats.Snapshot
	rangeSn stats.Snapshot
	recent  []qlog.Entry

	mu       sync.Mutex
	lastFrom time.Time
	lastTo   time.Time
	rangeN   int
}

func (c *statusCtrl) Config() *config.Config { return c.cfg }

// UpdateConfig is a no-op: the status tests render, they do not write.
func (c *statusCtrl) UpdateConfig(context.Context, *config.Config) error { return nil }

func (c *statusCtrl) Status(context.Context) (api.Status, error) { return c.st, nil }

func (c *statusCtrl) Stats() stats.Snapshot { return c.sn }

func (c *statusCtrl) StatsRange(from, to time.Time) stats.Snapshot {
	c.mu.Lock()
	c.lastFrom, c.lastTo = from, to
	c.rangeN++
	c.mu.Unlock()
	return c.rangeSn
}

// lastRange is the from/to of the most recent StatsRange call.
func (c *statusCtrl) lastRange() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastFrom, c.lastTo
}

func (c *statusCtrl) Started() time.Time { return time.Time{} }

func (c *statusCtrl) FilterStatus() []filter.ListStatus { return nil }

func (c *statusCtrl) FilterUpdate(context.Context, string) error { return nil }

func (c *statusCtrl) Probe(context.Context, []providers.Endpoint) []probe.Result { return nil }

func (c *statusCtrl) CreateConfigBackup(string) error { return nil }

func (c *statusCtrl) ListConfigBackups() ([]configbackup.Info, error) { return nil, nil }

func (c *statusCtrl) RestoreConfigBackup(string) error { return nil }

func (c *statusCtrl) DeleteConfigBackup(string) error { return nil }

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

// RequestsQuery is unused by the status tests; it exists to satisfy the
// Controller interface.
func (c *statusCtrl) RequestsQuery(qlog.Query, int, int) ([]qlog.Entry, int) {
	return nil, 0
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
// against the mockup's figure. The range snapshot repeats it too, so
// the default 30-day period draws the same figure the mockup does.
func mockupStatus() *statusCtrl {
	ctrl := &statusCtrl{
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
	ctrl.rangeSn = ctrl.sn
	return ctrl
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
	if !strings.Contains(body, `<div id="stats-block">`) {
		t.Error("the statistics are not wrapped in #stats-block (the poller's target)")
	}

	// The mockup's dasharrays and offsets, straight from its figure:
	// slice starts are 0, 74, 93 and 99.7 percent, so the offsets are
	// 25 minus each of those. The 48-unit viewBox keeps the 14-wide
	// stroke (16 on hover) around r=15.9 inside the box instead of
	// clipping the rings into octagons.
	geometry := []string{
		`viewBox="0 0 48 48"`, `cx="24" cy="24"`, `r="15.9"`,
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

// TestStatusFeedTimezone checks that the live feed renders a query's time
// in the configured IANA zone (Europe/Moscow is UTC+3 all year, so no DST
// edge is involved) and that the stored Entry.Time keeps its own zone.
func TestStatusFeedTimezone(t *testing.T) {
	// 2026-01-02 12:00:00 UTC is 15:00:00 in Moscow (UTC+3, no DST).
	noon := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	stored := qlog.Entry{Time: noon, QName: "noon.example.", QType: 1, Proto: "udp", Upstream: "cloudflare", LatencyMS: 5}
	feedTime := regexp.MustCompile(`<span class="t">\d{2}:\d{2}:\d{2}</span>`)

	t.Run("Europe/Moscow shifts the feed to 15:00:00", func(t *testing.T) {
		ctrl := &statusCtrl{
			cfg:    &config.Config{Domain: "dns.example.test", Timezone: "Europe/Moscow"},
			recent: []qlog.Entry{stored},
		}
		p, srv := statusPanel(t, ctrl)

		code, body := authedGET(t, p, srv, "/panel/")
		if code != http.StatusOK {
			t.Fatalf("GET /panel/ = %d, want 200\n%s", code, body)
		}
		if !strings.Contains(body, `<span class="t">15:00:00</span>`) {
			t.Errorf("feed does not render 12:00 UTC as 15:00:00 in Europe/Moscow:\n%s", body)
		}
		if !stored.Time.Equal(noon) || stored.Time.Location() != time.UTC {
			t.Error("the displayed zone changed the stored Entry.Time")
		}
	})

	for _, tt := range []struct {
		name string
		zone string
	}{
		{"an empty zone falls back to local", ""},
		{"an unknown stored zone falls back to local", "Mars/Base"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &statusCtrl{
				cfg:    &config.Config{Domain: "dns.example.test", Timezone: tt.zone},
				recent: []qlog.Entry{stored},
			}
			p, srv := statusPanel(t, ctrl)

			code, body := authedGET(t, p, srv, "/panel/")
			if code != http.StatusOK {
				t.Fatalf("GET /panel/ = %d, want 200 (must not panic)", code)
			}
			// The process zone is unknown here, so only the shape is
			// asserted; the test never mutates time.Local.
			if !feedTime.MatchString(body) {
				t.Errorf("feed row time is not HH:MM:SS:\n%s", body)
			}
		})
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

// TestEventsEndStreams checks that EndStreams ends a live SSE handler:
// http.Server.Shutdown does not cancel handler contexts, so without the
// signal an open stream would hold the listener until the stop timeout.
// A fresh request after EndStreams must still stream, because the signal
// is replaced for the next runtime generation.
func TestEventsEndStreams(t *testing.T) {
	p, srv := statusPanelBus(t, mockupStatus(), api.NewBus())

	resp := authedRequest(t, p, srv, "/panel/events")
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	if got := nextSSE(t, br); got.name != "ping" {
		t.Fatalf("first event = %q, want ping", got.name)
	}
	if got := nextSSE(t, br); got.name != "snapshot" {
		t.Fatalf("second event = %q, want snapshot", got.name)
	}

	// The handler must return as soon as EndStreams fires, well under
	// the 5 s stop timeout the app uses. EOF on the body means it did.
	p.EndStreams()
	drained := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, br)
		drained <- err
	}()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("draining the ended stream: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stream handler did not return within 2s of EndStreams")
	}

	// The channel was replaced, so a connection from the next
	// generation still streams.
	resp2 := authedRequest(t, p, srv, "/panel/events")
	defer resp2.Body.Close()

	br2 := bufio.NewReader(resp2.Body)
	if got := nextSSE(t, br2); got.name != "ping" {
		t.Fatalf("event on the fresh stream = %q, want ping", got.name)
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

// periodCtrl is a daemon whose cumulative and range snapshots differ, so
// a test can tell which one a page used: the cumulative total is 1000
// with a 74/19/6.7/0.3 outcome split, the range total is 40 with a 75 %
// cached share.
func periodCtrl() *statusCtrl {
	return &statusCtrl{
		cfg: &config.Config{Domain: "dns.example.test"},
		sn: stats.Snapshot{
			Total:     1000,
			Outcomes:  map[string]uint64{"cached": 740, "upstream": 190, "blocked": 67, "error": 3},
			Protos:    map[string]uint64{"udp": 1000},
			Upstreams: map[string]uint64{"u": 1000},
		},
		rangeSn: stats.Snapshot{
			Total:     40,
			Outcomes:  map[string]uint64{"cached": 30, "upstream": 5, "blocked": 4, "error": 1},
			Protos:    map[string]uint64{"udp": 40},
			Upstreams: map[string]uint64{"u": 40},
		},
	}
}

// TestStatusPeriodDefault checks the default period: the four gauges
// keep the cumulative counters while the donuts and the period line
// follow the range snapshot.
func TestStatusPeriodDefault(t *testing.T) {
	p, srv := statusPanel(t, periodCtrl())

	code, body := authedGET(t, p, srv, "/panel/")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/ = %d, want 200", code)
	}

	if !strings.Contains(body, `<option value="30" selected>Месяц</option>`) {
		t.Error("the default period is not the selected month")
	}
	if !strings.Contains(body, "За период (Месяц): всего 40 · кеш 30 · блок 4 · ошибки 1") {
		t.Errorf("the period line does not use the range snapshot:\n%s", body)
	}
	if !strings.Contains(body, "1 000") {
		t.Error("the gauges must keep the cumulative total")
	}
	if !strings.Contains(body, `data-value="75 % · 30"`) {
		t.Errorf("the donuts do not use the range snapshot:\n%s", body)
	}
	if strings.Contains(body, `data-value="74 % · 740"`) {
		t.Error("the donuts leaked the cumulative snapshot")
	}
}

// TestStatusPeriodFixed checks a fixed choice: its label, its data and
// the range window the page asked the controller for.
func TestStatusPeriodFixed(t *testing.T) {
	ctrl := periodCtrl()
	p, srv := statusPanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/?period=365")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/?period=365 = %d, want 200", code)
	}
	if !strings.Contains(body, `<option value="365" selected>12 месяцев</option>`) {
		t.Error("the 12-month option is not selected")
	}
	if !strings.Contains(body, "период: 12 месяцев") {
		t.Error("the heading does not carry the period label")
	}
	if !strings.Contains(body, `data-value="75 % · 30"`) {
		t.Errorf("the donuts do not use the range snapshot:\n%s", body)
	}
	// The gauges stay all-time regardless of the period.
	if !strings.Contains(body, "1 000") {
		t.Error("the gauges changed with the period")
	}

	from, to := ctrl.lastRange()
	if from.IsZero() || to.IsZero() || !to.After(from) {
		t.Fatalf("StatsRange(%v, %v): want an ordered, non-zero window", from, to)
	}
	if span := to.Sub(from); span < 350*24*time.Hour || span > 370*24*time.Hour {
		t.Errorf("12-month window span = %v, want about a year", span)
	}
}

// TestStatusPeriodCustomForwardsDates checks that a custom range parses
// both dates and forwards them to StatsRange.
func TestStatusPeriodCustomForwardsDates(t *testing.T) {
	ctrl := periodCtrl()
	p, srv := statusPanel(t, ctrl)

	now := time.Now().UTC()
	fromDate := now.AddDate(0, 0, -10)
	toDate := now.AddDate(0, 0, -1)
	fromText := fromDate.Format("2006-01-02")
	toText := toDate.Format("2006-01-02")

	code, body := authedGET(t, p, srv, "/panel/?period=custom&from="+fromText+"&to="+toText)
	if code != http.StatusOK {
		t.Fatalf("custom GET = %d, want 200", code)
	}
	if !strings.Contains(body, `<option value="custom" selected>Своё</option>`) {
		t.Error("the custom option is not selected")
	}
	if !strings.Contains(body, `name="from" value="`+fromText+`"`) ||
		!strings.Contains(body, `name="to" value="`+toText+`"`) {
		t.Error("the date inputs do not echo the request")
	}

	gotFrom, gotTo := ctrl.lastRange()
	wantFrom := time.Date(fromDate.Year(), fromDate.Month(), fromDate.Day(), 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(toDate.Year(), toDate.Month(), toDate.Day(), 0, 0, 0, 0, time.UTC)
	if !gotFrom.Equal(wantFrom) || !gotTo.Equal(wantTo) {
		t.Errorf("StatsRange got (%v, %v), want (%v, %v)", gotFrom, gotTo, wantFrom, wantTo)
	}
}

// TestStatusPeriodReversedFallsBack checks that a reversed custom range
// is refused: the page shows the month with a notice.
func TestStatusPeriodReversedFallsBack(t *testing.T) {
	ctrl := periodCtrl()
	p, srv := statusPanel(t, ctrl)

	now := time.Now().UTC()
	fromText := now.Format("2006-01-02")
	toText := now.AddDate(0, 0, -5).Format("2006-01-02")

	code, body := authedGET(t, p, srv, "/panel/?period=custom&from="+fromText+"&to="+toText)
	if code != http.StatusOK {
		t.Fatalf("reversed GET = %d, want 200", code)
	}
	if !strings.Contains(body, `<option value="30" selected>Месяц</option>`) {
		t.Error("a reversed range did not fall back to the month")
	}
	if !strings.Contains(body, "Начало периода позже конца") {
		t.Errorf("the page does not carry the fallback notice:\n%s", body)
	}
}

// TestStatusPeriodEmptyHistory checks that a daemon with no history
// still renders the period line with zeros and does not error.
func TestStatusPeriodEmptyHistory(t *testing.T) {
	p, srv := statusPanel(t, &statusCtrl{cfg: &config.Config{Domain: "dns.example.test"}})

	code, body := authedGET(t, p, srv, "/panel/")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/ with no history = %d, want 200", code)
	}
	if !strings.Contains(body, "За период (Месяц): всего 0 · кеш 0 · блок 0 · ошибки 0") {
		t.Errorf("the empty period line is missing:\n%s", body)
	}
}

// TestStatusPeriodForm checks the selector markup: the six choices in
// their fixed order («Сегодня» first) and the two date inputs, in one GET
// form.
func TestStatusPeriodForm(t *testing.T) {
	p, srv := statusPanel(t, mockupStatus())

	_, body := authedGET(t, p, srv, "/panel/")
	for _, want := range []string{
		`action="/panel/"`,
		`name="period"`,
		`name="from"`,
		`name="to"`,
		`type="date"`,
		`>Сегодня</option>`,
		`>Месяц</option>`,
		`>3 месяца</option>`,
		`>6 месяцев</option>`,
		`>12 месяцев</option>`,
		`>Своё</option>`,
		`Показать`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the period form is missing %q", want)
		}
	}

	if i, j := strings.Index(body, `value="today"`), strings.Index(body, `value="30"`); i < 0 || j < 0 || i > j {
		t.Errorf("«Сегодня» is not the first period option (today at %d, month at %d)", i, j)
	}
}

// TestStatusStatsFragment checks the polled fragment: the same gauges,
// period summary and donuts as the page for the same query, with the
// no-store/nosniff headers and without the selector or the live feed.
func TestStatusStatsFragment(t *testing.T) {
	ctrl := periodCtrl()
	p, srv := statusPanel(t, ctrl)

	resp := authedRequest(t, p, srv, "/panel/stats?period=365")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/stats = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the fragment: %v", err)
	}
	body := string(raw)

	for _, want := range []string{
		`class="gauges"`,
		"Запросов всего",
		"1 000",
		`За период (12 месяцев): всего 40 · кеш 30 · блок 4 · ошибки 1`,
		`class="piefold"`,
		`data-value="75 % · 30"`,
		`href="/panel/history?outcome=cached"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the fragment is missing %q", want)
		}
	}

	for _, unwanted := range []string{
		`action="/panel/"`,
		`name="period"`,
		`id="stats-block"`,
		`id="feed"`,
		"Живая лента",
		"<form",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the fragment must not carry %q", unwanted)
		}
	}

	from, to := ctrl.lastRange()
	if from.IsZero() || to.IsZero() || !to.After(from) {
		t.Fatalf("StatsRange(%v, %v): want an ordered, non-zero window", from, to)
	}
}

// TestStatusPeriodToday checks the new first window: the parser resolves
// it to the current UTC calendar day, and both the page and the fragment
// honour it.
func TestStatusPeriodToday(t *testing.T) {
	now := time.Date(2026, 10, 18, 23, 30, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodGet, "/panel/?period=today", nil)
	sel := parsePeriod(req, now)

	wantDay := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	if sel.Period != "today" || sel.Label != "Сегодня" {
		t.Fatalf("parsePeriod(today) = %q/%q, want today/Сегодня", sel.Period, sel.Label)
	}
	if !sel.From.Equal(wantDay) || !sel.To.Equal(wantDay) {
		t.Errorf("today range = (%v, %v), want (%v, %v)", sel.From, sel.To, wantDay, wantDay)
	}
	if sel.FromText != "2026-10-18" || sel.ToText != "2026-10-18" {
		t.Errorf("today text = (%q, %q), want 2026-10-18 twice", sel.FromText, sel.ToText)
	}

	ctrl := periodCtrl()
	p, srv := statusPanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/?period=today")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/?period=today = %d, want 200", code)
	}
	for _, want := range []string{
		`<option value="today" selected>Сегодня</option>`,
		"период: Сегодня",
		"За период (Сегодня): всего 40 · кеш 30 · блок 4 · ошибки 1",
		`data-value="75 % · 30"`,
		`name="from" value="` + time.Now().UTC().Format("2006-01-02") + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the today page is missing %q", want)
		}
	}

	utc := time.Now().UTC()
	today := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	from, to := ctrl.lastRange()
	if !from.Equal(today) || !to.Equal(today) {
		t.Errorf("StatsRange got (%v, %v), want today (%v, %v)", from, to, today, today)
	}

	code, frag := authedGET(t, p, srv, "/panel/stats?period=today")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/stats?period=today = %d, want 200", code)
	}
	if !strings.Contains(frag, "За период (Сегодня)") || !strings.Contains(frag, `data-value="75 % · 30"`) {
		t.Errorf("the today fragment does not honour the period:\n%s", frag)
	}
	if strings.Contains(frag, `name="period"`) {
		t.Error("the today fragment carries the period selector")
	}
}

// TestStatusPeriodCustomBoundary checks the retention cutoff: a range of
// exactly 400 whole days is accepted, one day longer falls back to the
// month with the «длиннее 400 дней» notice.
func TestStatusPeriodCustomBoundary(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	day := func(d time.Time) string { return d.UTC().Format("2006-01-02") }

	boundary := now.Add(-stats.HistoryDays * 24 * time.Hour)
	req := httptest.NewRequest(http.MethodGet,
		"/panel/?period=custom&from="+day(boundary)+"&to="+day(now), nil)
	sel := parsePeriod(req, now)
	if sel.Period != "custom" || sel.Notice != "" {
		t.Errorf("a 400-day window = %q/%q, want an accepted custom range", sel.Period, sel.Notice)
	}

	older := boundary.AddDate(0, 0, -1)
	req = httptest.NewRequest(http.MethodGet,
		"/panel/?period=custom&from="+day(older)+"&to="+day(now), nil)
	sel = parsePeriod(req, now)
	if sel.Period != defaultPeriod || !strings.Contains(sel.Notice, "длиннее 400 дней") {
		t.Errorf("a 401-day window = %q/%q, want the month fallback", sel.Period, sel.Notice)
	}
}
