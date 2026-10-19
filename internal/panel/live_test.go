package panel

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/qlog"
)

// TestLiveRingBounds pins the live ring's bound and order: after more
// pushes than it holds, exactly liveFeedSize entries survive, newest
// first, and the oldest ones are gone.
func TestLiveRingBounds(t *testing.T) {
	f := newFeed(liveFeedSize)
	for i := 0; i < 120; i++ {
		f.push(qlog.Entry{QName: fmt.Sprintf("q%03d.", i)})
	}

	snap := f.snapshot()
	if len(snap) != liveFeedSize {
		t.Fatalf("buffer len = %d, want %d", len(snap), liveFeedSize)
	}
	if snap[0].QName != "q119." {
		t.Errorf("newest entry = %q, want q119.", snap[0].QName)
	}
	if snap[liveFeedSize-1].QName != "q020." {
		t.Errorf("oldest kept entry = %q, want q020.", snap[liveFeedSize-1].QName)
	}
}

// TestLiveRingSeedOnlyWhenEmpty checks that the backfill runs once: a
// live push that arrives first must never be overwritten by a seed, and
// repeating the seed must not duplicate rows.
func TestLiveRingSeedOnlyWhenEmpty(t *testing.T) {
	oldestFirst := []qlog.Entry{{QName: "old."}, {QName: "new."}}

	f := newFeed(liveFeedSize)
	f.seed(oldestFirst)
	snap := f.snapshot()
	if len(snap) != 2 || snap[0].QName != "new." || snap[1].QName != "old." {
		t.Fatalf("seeded snapshot = %+v, want newest first new., old.", snap)
	}

	f.push(qlog.Entry{QName: "live."})
	f.seed(oldestFirst)

	snap = f.snapshot()
	if len(snap) != 3 {
		t.Fatalf("buffer len after a repeated seed = %d, want 3", len(snap))
	}
	if snap[0].QName != "live." {
		t.Errorf("newest entry = %q, want the live push", snap[0].QName)
	}

	// A seed larger than the ring is clamped, not trusted.
	big := make([]qlog.Entry, liveFeedSize+10)
	for i := range big {
		big[i].QName = fmt.Sprintf("seed%03d.", i)
	}
	g := newFeed(liveFeedSize)
	g.seed(big)
	if got := len(g.snapshot()); got != liveFeedSize {
		t.Errorf("a seeded buffer holds %d rows, want %d", got, liveFeedSize)
	}
}

// liveCtrl returns a daemon with three scripted rows (oldest first): an
// upstream answer, a hostile blocked qname and a cache hit. Moscow is
// UTC+3 all year, so the stored noon renders as 15:00.
func liveCtrl() *statusCtrl {
	return &statusCtrl{
		cfg: &config.Config{Domain: "dns.example.test", Timezone: "Europe/Moscow"},
		recent: []qlog.Entry{
			{
				Time:     time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
				ClientIP: "192.168.1.9", Proto: "udp", QName: "api.example.", QType: 1,
				Rcode: 0, Upstream: "cloudflare", LatencyMS: 21,
			},
			{
				Time:     time.Date(2026, 1, 2, 12, 0, 1, 0, time.UTC),
				ClientIP: "10.0.0.7", Proto: "doh", QName: `<script>alert(1)</script>.`, QType: 28,
				Rcode: 3, Blocked: true, BlockSource: "oisd",
			},
			{
				Time:     time.Date(2026, 1, 2, 12, 0, 2, 0, time.UTC),
				ClientIP: "10.0.0.8", Proto: "dot", QName: "cdn.example.", QType: 5,
				Rcode: 0, CacheHit: true,
			},
		},
	}
}

// TestLivePageRendersSnapshot checks the server-rendered table: every
// promised column, the configured timezone, the outcome classification
// and, above all, that a hostile qname is escaped into text.
func TestLivePageRendersSnapshot(t *testing.T) {
	p, srv := statusPanel(t, liveCtrl())

	code, body := authedGET(t, p, srv, "/panel/live")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/live = %d, want 200\n%s", code, body)
	}

	for _, want := range []string{
		"Живой экран",
		"время", "клиент", "протокол", "имя · тип", "результат", "источник", "задержка", "rcode",
		"15:00:02", "cdn.example.", "CNAME", "кеш",
		"10.0.0.7", "oisd", "блок", "NXDOMAIN",
		"192.168.1.9", "cloudflare", "21 мс", "NOERROR",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("live page is missing %q", want)
		}
	}

	// The hostile name arrives as text, never as markup.
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("live page rendered the hostile qname as a script element")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;.") {
		t.Errorf("live page does not carry the escaped hostile qname:\n%s", body)
	}

	// Newest first: the cache hit precedes the blocked row, which
	// precedes the upstream answer.
	iNew, iBlock, iOld := strings.Index(body, "cdn.example."),
		strings.Index(body, "alert(1)"), strings.Index(body, "api.example.")
	if iNew < 0 || iBlock < 0 || iOld < 0 || !(iNew < iBlock && iBlock < iOld) {
		t.Errorf("live table order: newest (cdn.example.) must precede the blocked row, then api.example.")
	}

	// One header row and three data rows.
	if got := strings.Count(body, "<tr>"); got != 4 {
		t.Errorf("live table has %d <tr> elements, want 4 (header plus three rows)", got)
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

// TestLiveEmptyPage checks the placeholder: an empty ring renders the
// same line live.js restores when a snapshot is empty.
func TestLiveEmptyPage(t *testing.T) {
	p, srv := statusPanel(t, &statusCtrl{cfg: &config.Config{Domain: "dns.example.test"}})

	code, body := authedGET(t, p, srv, "/panel/live")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/live = %d, want 200", code)
	}
	if !strings.Contains(body, `<tr class="empty"><td colspan="8">Пока нет запросов</td></tr>`) {
		t.Errorf("empty live table is missing its placeholder:\n%s", body)
	}
}

// TestLiveStream covers the stream end to end: the snapshot frame holds
// the seeded rows as <tr> fragments, a publish becomes a row frame, and
// EndStreams ends the handler promptly.
func TestLiveStream(t *testing.T) {
	bus := api.NewBus()
	p, srv := statusPanelBus(t, liveCtrl(), bus)

	resp := authedRequest(t, p, srv, "/panel/live/events")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/live/events = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	br := bufio.NewReader(resp.Body)
	if got := nextSSE(t, br); got.name != "ping" {
		t.Fatalf("first event = %q, want ping", got.name)
	}
	snapshot := nextSSE(t, br)
	if snapshot.name != "snapshot" {
		t.Fatalf("second event = %q, want snapshot", snapshot.name)
	}
	for _, want := range []string{"<tr>", "cdn.example.", "api.example.", "CNAME"} {
		if !strings.Contains(snapshot.data, want) {
			t.Errorf("snapshot frame is missing %q: %s", want, snapshot.data)
		}
	}
	if strings.ContainsAny(snapshot.data, "\n\r") {
		t.Errorf("snapshot frame contains a raw newline: %q", snapshot.data)
	}

	bus.Publish(api.Event{Type: "requests", Data: qlog.Entry{
		Time: time.Now(), ClientIP: "10.1.2.3", QName: "live.test.", QType: 1, Rcode: 0,
		Proto: "tcp", Upstream: "quad9", LatencyMS: 9,
	}})

	row := nextSSE(t, br)
	if row.name != "row" {
		t.Fatalf("event after the publish = %q, want row", row.name)
	}
	for _, want := range []string{
		"<tr>", "10.1.2.3", "live.test.", "quad9", "9 мс", "NOERROR", `<span class="tag ok">ok</span>`,
	} {
		if !strings.Contains(row.data, want) {
			t.Errorf("row frame is missing %q: %s", want, row.data)
		}
	}

	// EndStreams must end this handler, not leave it holding the
	// listener until the stop timeout.
	p.EndStreams()
	drained := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, br)
		drained <- err
	}()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("draining the ended live stream: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the live stream handler did not return within 2s of EndStreams")
	}
}
