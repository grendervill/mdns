package panel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/qlog"
	"mydns/internal/stats"
)

// historyCtrl is a scripted daemon whose history is a real qlog ring, so
// the page exercises the same filter and paging semantics the API has.
// It also remembers the last query it was asked for, so the tests can
// assert what the page passed through.
type historyCtrl struct {
	cfg  *config.Config
	ring *qlog.Log

	mu    sync.Mutex
	last  qlog.Query
	page  int
	per   int
	calls int
}

// newHistoryCtrl builds a controller holding entries (oldest first).
func newHistoryCtrl(t *testing.T, entries ...qlog.Entry) *historyCtrl {
	t.Helper()

	ring, err := qlog.New(len(entries)+1, "", 0)
	if err != nil {
		t.Fatalf("qlog.New: %v", err)
	}
	for _, e := range entries {
		ring.Add(e)
	}
	t.Cleanup(func() { _ = ring.Close() })

	return &historyCtrl{
		cfg:  &config.Config{Domain: "dns.example.test", Log: config.LogConfig{MemoryEntries: 10000}},
		ring: ring,
	}
}

func (c *historyCtrl) Config() *config.Config { return c.cfg }

// UpdateConfig is a no-op: the history tests read, they do not write.
func (c *historyCtrl) UpdateConfig(context.Context, *config.Config) error { return nil }

func (c *historyCtrl) Status(context.Context) (api.Status, error) { return api.Status{}, nil }

func (c *historyCtrl) Stats() stats.Snapshot { return stats.Snapshot{} }

func (c *historyCtrl) StatsRange(time.Time, time.Time) stats.Snapshot { return stats.Snapshot{} }

func (c *historyCtrl) Started() time.Time { return time.Time{} }

func (c *historyCtrl) FilterStatus() []filter.ListStatus { return nil }

func (c *historyCtrl) FilterUpdate(context.Context, string) error { return nil }

func (c *historyCtrl) Requests(n int) []qlog.Entry { return c.ring.Recent(n) }

func (c *historyCtrl) RequestsQuery(q qlog.Query, page, per int) ([]qlog.Entry, int) {
	c.mu.Lock()
	c.last, c.page, c.per = q, page, per
	c.calls++
	c.mu.Unlock()

	if page < 1 {
		page = 1
	}
	if per < 1 {
		per = 1
	}
	return c.ring.Query(q, (page-1)*per, per)
}

// lastOffset is the ring offset the page last asked for.
func (c *historyCtrl) lastOffset() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return (c.page - 1) * c.per
}

// lastSearch is the free-text term of the last query.
func (c *historyCtrl) lastSearch() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last.Search
}

// queryCalls counts the RequestsQuery calls; the CSV export walks the
// ring in several pages, the HTML page in one.
func (c *historyCtrl) queryCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// historyBase is the timestamp of the oldest scripted entry.
var historyBase = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// mixedHistory is a small record with one normal answer, two blocked
// requests and a cache hit — one of each state the row helper knows.
func mixedHistory() []qlog.Entry {
	return []qlog.Entry{
		{Time: historyBase, QName: "api.github.com.", QType: 1, Proto: "udp", Rcode: 0,
			ClientIP: "192.168.1.12", Upstream: "cloudflare", LatencyMS: 21},
		{Time: historyBase.Add(time.Second), QName: "ads.doubleclick.net.", QType: 1, Proto: "udp", Rcode: 0,
			ClientIP: "192.168.1.31", Blocked: true, BlockSource: "oisd"},
		{Time: historyBase.Add(2 * time.Second), QName: "cdn.jsdelivr.net.", QType: 1, Proto: "doh", Rcode: 0,
			ClientIP: "192.168.1.12", CacheHit: true},
		{Time: historyBase.Add(3 * time.Second), QName: "tracker.adsrv.net.", QType: 28, Proto: "dot", Rcode: 0,
			ClientIP: "192.168.1.44", Blocked: true, BlockSource: "adguard"},
	}
}

// historyEntries builds n consecutive queries, oldest first, named so
// their order is easy to assert (q000 … qNNN).
func historyEntries(n int) []qlog.Entry {
	entries := make([]qlog.Entry, n)
	for i := range entries {
		entries[i] = qlog.Entry{
			Time:      historyBase.Add(time.Duration(i) * time.Second),
			QName:     fmt.Sprintf("q%03d.example.", i),
			QType:     1,
			Proto:     "udp",
			Rcode:     0,
			ClientIP:  "192.168.1.12",
			Upstream:  "cloudflare",
			LatencyMS: float64(i),
		}
	}
	return entries
}

// countRows counts the feed-style rows the history page rendered.
func countRows(body string) int { return strings.Count(body, `class="q"`) }

// TestHistoryPage checks the filtered screen: a blocked filter shows only
// blocked rows, the total comes from the controller, and the page carries
// the components of the approved frame.
func TestHistoryPage(t *testing.T) {
	ctrl := newHistoryCtrl(t, mixedHistory()...)
	p, srv := statusPanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/history?outcome=blocked")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history = %d, want 200\n%s", code, body)
	}

	for _, want := range []string{"ads.doubleclick.net.", "tracker.adsrv.net."} {
		if !strings.Contains(body, want) {
			t.Errorf("blocked page is missing %q", want)
		}
	}
	for _, notWant := range []string{"api.github.com.", "cdn.jsdelivr.net."} {
		if strings.Contains(body, notWant) {
			t.Errorf("blocked page must not show %q", notWant)
		}
	}
	if n := countRows(body); n != 2 {
		t.Errorf("blocked page has %d rows, want 2", n)
	}

	// The pager: total from the controller, one page of a hundred.
	for _, want := range []string{
		"История запросов",
		"Найдено <b>2</b>",
		"страница <b>1</b> из <b>1</b>",
		"по 100 на страницу",
		"автообновление выключено",
		"в памяти: <b>10 000</b>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("history page is missing %q", want)
		}
	}

	// The active filter is a chip, the outcome is in the head, and the
	// rail marks «Запросы» active.
	if !strings.Contains(body, `class="chip"`) || !strings.Contains(body, "заблокировано") {
		t.Error("history page does not show the active filter as a chip")
	}
	if !strings.Contains(body, `class="tag block"`) {
		t.Error("history page does not render the blocked row tag")
	}
	if !strings.Contains(body, `aria-current="page" href="/panel/history"`) {
		t.Error("the rail does not mark «Запросы» active")
	}
	if strings.Contains(body, `href="/panel/history.csv"`) {
		t.Error("the CSV link must carry the filter parameters")
	}
	if !strings.Contains(body, `href="/panel/history.csv?outcome=blocked"`) {
		t.Error("the CSV link does not carry the active outcome filter")
	}

	// The shared feed row helper supplies the row: time, name, proto,
	// tag, latency. The hover title carries the record type and rcode.
	if !strings.Contains(body, `class="ms"`) || !strings.Contains(body, `class="tag block"`) {
		t.Error("history rows do not use the shared feed row markup")
	}
	if !strings.Contains(body, `title="tracker.adsrv.net. AAAA · NOERROR"`) {
		t.Errorf("row title is missing the record type and rcode:\n%s", body)
	}
}

// TestHistorySearch checks the free-text box: the term reaches qlog
// verbatim and the page shows the case-insensitive matches.
func TestHistorySearch(t *testing.T) {
	ctrl := newHistoryCtrl(t, mixedHistory()...)
	p, srv := statusPanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/history?q=GitHub")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history?q=GitHub = %d, want 200\n%s", code, body)
	}

	if got := ctrl.lastSearch(); got != "GitHub" {
		t.Errorf("qlog.Query.Search = %q, want the term passed through verbatim", got)
	}
	if !strings.Contains(body, "api.github.com.") {
		t.Error("search page is missing the case-insensitive match")
	}
	if strings.Contains(body, "ads.doubleclick.net.") {
		t.Error("search page shows a row that does not match")
	}
	if !strings.Contains(body, `value="GitHub"`) {
		t.Error("the search box does not echo the term")
	}
}

// TestHistoryPagination checks the paging contract: page 2 asks for
// offset 100, pages do not overlap and run newest first, a page past the
// end clamps to the last one, and the edge controls are disabled.
func TestHistoryPagination(t *testing.T) {
	ctrl := newHistoryCtrl(t, historyEntries(150)...)
	p, srv := statusPanel(t, ctrl)

	code, page1 := authedGET(t, p, srv, "/panel/history")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history = %d, want 200\n%s", code, page1)
	}
	if n := countRows(page1); n != 100 {
		t.Errorf("page 1 has %d rows, want 100", n)
	}
	if !strings.Contains(page1, "страница <b>1</b> из <b>2</b>") {
		t.Error("page 1 does not report two pages")
	}

	code, page2 := authedGET(t, p, srv, "/panel/history?page=2")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history?page=2 = %d, want 200\n%s", code, page2)
	}
	if got := ctrl.lastOffset(); got != 100 {
		t.Errorf("page 2 requested offset %d, want 100", got)
	}
	if got := ctrl.queryCalls(); got != 2 {
		t.Errorf("nice request count = %d, want 2 (one per page)", got)
	}
	if n := countRows(page2); n != 50 {
		t.Errorf("page 2 has %d rows, want 50", n)
	}
	if !strings.Contains(page2, "страница <b>2</b> из <b>2</b>") {
		t.Error("page 2 does not report two pages")
	}

	// Newest first, and the two pages do not share a row.
	if i, j := strings.Index(page1, "q149.example."), strings.Index(page1, "q050.example."); i < 0 || j < 0 || i > j {
		t.Errorf("page 1 order: newest (q149) must precede oldest (q050)")
	}
	if i, j := strings.Index(page2, "q049.example."), strings.Index(page2, "q000.example."); i < 0 || j < 0 || i > j {
		t.Errorf("page 2 order: newest (q049) must precede oldest (q000)")
	}
	for _, name := range []string{"q149.example.", "q050.example."} {
		if strings.Contains(page2, name) {
			t.Errorf("page 2 overlaps page 1 with %q", name)
		}
	}

	// Edge controls: back is disabled on page 1, forward on page 2, and
	// neither links past the range.
	if !strings.Contains(page1, `aria-disabled="true">← назад`) {
		t.Error("page 1 does not disable «назад»")
	}
	if strings.Contains(page1, `href="/panel/history?page=0"`) {
		t.Error("page 1 links to page 0")
	}
	if !strings.Contains(page1, `href="/panel/history?page=2"`) {
		t.Error("page 1 does not link forward to page 2")
	}
	if !strings.Contains(page2, `aria-disabled="true">вперёд →`) {
		t.Error("page 2 does not disable «вперёд»")
	}
	if strings.Contains(page2, `href="/panel/history?page=3"`) {
		t.Error("page 2 links past the last page")
	}

	// A page past the end clamps to the last and is shown as such.
	code, clamped := authedGET(t, p, srv, "/panel/history?page=99")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history?page=99 = %d, want 200\n%s", code, clamped)
	}
	if !strings.Contains(clamped, "страница <b>2</b> из <b>2</b>") {
		t.Error("an out-of-range page is not clamped to the last one")
	}
	if n := countRows(clamped); n != 50 {
		t.Errorf("clamped page has %d rows, want the 50 of page 2", n)
	}
}

// TestHistoryCSV checks the export: a UTF-8 BOM, the header, CRLF line
// endings, RFC4180 quoting of delimiters and quotes, and every matching
// row rather than just the visible page.
func TestHistoryCSV(t *testing.T) {
	entries := historyEntries(1050)
	entries = append(entries, qlog.Entry{
		Time: historyBase.Add(2000 * time.Second), QName: `weird,name".example.`, QType: 16,
		Proto: "udp", Rcode: 0, ClientIP: "10.0.0.1", Upstream: "quad9", LatencyMS: 5,
	})
	ctrl := newHistoryCtrl(t, entries...)
	p, srv := statusPanel(t, ctrl)

	resp := authedRequest(t, p, srv, "/panel/history.csv")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/history.csv = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the CSV: %v", err)
	}
	body := string(data)

	if !strings.HasPrefix(body, "\ufeff") {
		t.Error("the export does not start with a UTF-8 BOM")
	}
	lines := strings.Split(strings.TrimSuffix(body, "\r\n"), "\r\n")
	if len(lines) != 1052 {
		t.Fatalf("the export has %d lines, want 1052 (header plus 1051 rows)", len(lines))
	}
	wantHeader := "\ufeff" + strings.Join(historyCSVHeader, ";")
	if lines[0] != wantHeader {
		t.Errorf("CSV header = %q, want %q", lines[0], wantHeader)
	}
	if wantHeader != "\ufeffвремя;протокол;домен;тип;результат;источник;клиент;мс" {
		t.Errorf("the header wording changed: %q", wantHeader)
	}

	// All matching rows, not just the first page of 100: both ends of
	// the ring reached the file.
	for _, want := range []string{"q000.example.", "q1049.example."} {
		if !strings.Contains(body, want) {
			t.Errorf("the export is missing %q (it exported only a page)", want)
		}
	}
	if got := ctrl.queryCalls(); got != 3 {
		t.Errorf("the export walked the ring in %d calls, want 3 (1051 rows / 500)", got)
	}

	// RFC4180: a field with a delimiter or a quote is quoted, the inner
	// quotes are doubled.
	if !strings.Contains(body, `"weird,name"".example."`) {
		t.Errorf("the export does not quote and double the comma/quote field:\n%s", body)
	}
	// CRLF is the only line break.
	if !strings.Contains(body, "\r\n") {
		t.Error("the export does not use CRLF")
	}
	if strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\n") {
		t.Error("the export contains a bare LF")
	}
}

// TestHistoryTimezone checks that the history table and the CSV export
// render query times in the configured zone, and that the stored
// timestamps keep the zone they were logged in.
func TestHistoryTimezone(t *testing.T) {
	// 2026-01-02 12:00:00 UTC is 15:00:00 in Moscow (UTC+3, no DST).
	noon := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	entry := qlog.Entry{Time: noon, QName: "noon.example.", QType: 1, Proto: "udp", Rcode: 0,
		ClientIP: "192.168.1.12", Upstream: "cloudflare", LatencyMS: 5}

	ctrl := newHistoryCtrl(t, entry)
	ctrl.cfg.Timezone = "Europe/Moscow"
	p, srv := statusPanel(t, ctrl)

	t.Run("the table shows Moscow time", func(t *testing.T) {
		code, body := authedGET(t, p, srv, "/panel/history")
		if code != http.StatusOK {
			t.Fatalf("GET /panel/history = %d, want 200\n%s", code, body)
		}
		if !strings.Contains(body, `<span class="t">15:00:00</span>`) {
			t.Errorf("history row does not render 12:00 UTC as 15:00:00:\n%s", body)
		}
	})

	t.Run("the CSV exports Moscow time", func(t *testing.T) {
		resp := authedRequest(t, p, srv, "/panel/history.csv")
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading the CSV: %v", err)
		}
		want := "2026-01-02 15:00:00;udp;noon.example.;A;ответ upstream;cloudflare;192.168.1.12;5"
		if !strings.Contains(strings.TrimPrefix(string(data), "\ufeff"), want) {
			t.Errorf("the CSV does not export Moscow time:\nwant %q\n got %s", want, data)
		}
	})

	if !entry.Time.Equal(noon) || entry.Time.Location() != time.UTC {
		t.Error("the displayed zone changed the stored Entry.Time")
	}
}

// TestHistoryChip checks that a chip's × removes exactly its own filter
// and keeps the others and the search term.
func TestHistoryChip(t *testing.T) {
	ctrl := newHistoryCtrl(t, mixedHistory()...)
	p, srv := statusPanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/history?outcome=blocked&proto=udp&q=ads")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history = %d, want 200\n%s", code, body)
	}

	if n := strings.Count(body, `class="chip"`); n != 2 {
		t.Fatalf("the page shows %d chips, want 2 (outcome and proto)", n)
	}
	if n := strings.Count(body, `class="x"`); n != 2 {
		t.Fatalf("the page shows %d remove links, want 2", n)
	}

	// Removing the outcome keeps the protocol and the search term. The
	// separators are HTML-escaped in the attribute, hence "&amp;".
	if !strings.Contains(body, `href="/panel/history?proto=udp&amp;q=ads"`) {
		t.Errorf("removing the outcome does not keep the other filter and the search")
	}
	// Removing the protocol keeps the outcome and the search term.
	if !strings.Contains(body, `href="/panel/history?outcome=blocked&amp;q=ads"`) {
		t.Errorf("removing the protocol does not keep the other filter and the search")
	}
	if !strings.Contains(body, `<b>заблокировано</b>`) {
		t.Error("the outcome chip does not label the filter")
	}
	if !strings.Contains(body, `<b>udp (обычный)</b>`) {
		t.Error("the protocol chip does not label the filter")
	}

	// Removing a filter resets to page 1: the chip links carry no page.
	if strings.Contains(body, `href="/panel/history?proto=udp&q=ads&page=`) {
		t.Error("a chip link does not reset the page")
	}
}

// TestHistoryEscaping checks that user-controlled text is never markup:
// the query name reaches the table escaped and the CSV as a quoted,
// RFC4180-escaped field.
func TestHistoryEscaping(t *testing.T) {
	evil := `<script>alert("x")</script>.example.`
	ctrl := newHistoryCtrl(t, qlog.Entry{
		Time: historyBase, QName: evil, QType: 1, Proto: "udp", Rcode: 0,
		ClientIP: `192.168.1.12"><script>`, Blocked: true, BlockSource: `oisd;<script>`,
	})
	p, srv := statusPanel(t, ctrl)

	code, body := authedGET(t, p, srv, "/panel/history")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/history = %d, want 200\n%s", code, body)
	}
	if strings.Contains(body, "<script>") {
		t.Error("the table rendered a raw <script> from a query name")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the table does not show the escaped query name")
	}
	if !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "oisd;") {
		t.Error("the block source is not rendered")
	}

	resp := authedRequest(t, p, srv, "/panel/history.csv")
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the CSV: %v", err)
	}
	csv := string(data)
	if !strings.Contains(csv, `"<script>alert(""x"")</script>.example."`) {
		t.Errorf("the query name is not quoted with doubled quotes:\n%s", csv)
	}
	if !strings.Contains(csv, `"oisd;<script>"`) {
		t.Errorf("the block source with a semicolon is not quoted:\n%s", csv)
	}
	if !strings.Contains(csv, `"192.168.1.12""><script>"`) {
		t.Errorf("the client IP with a quote is not escaped:\n%s", csv)
	}
}

// TestHistoryCSVFormulaInjection checks the export's second escaping
// rule: a cell that begins with a spreadsheet formula character is
// prefix'd with a single quote, so Excel, LibreOffice and Numbers show
// the text instead of evaluating it. Any DNS client chooses the query
// name, so a cell like "=cmd|' /C calc'!A0…" is reachable and must never
// be executable.
func TestHistoryCSVFormulaInjection(t *testing.T) {
	ctrl := newHistoryCtrl(t,
		qlog.Entry{Time: historyBase, QName: `=cmd|' /C calc'!A0.evil.example.`, QType: 1, Proto: "udp", Rcode: 0,
			ClientIP: "192.168.1.12", Blocked: true, BlockSource: "ads"},
		qlog.Entry{Time: historyBase.Add(time.Second), QName: `+1234567890.evil.example.`, QType: 1, Proto: "udp", Rcode: 0,
			ClientIP: "192.168.1.12", Upstream: "cloudflare"},
		qlog.Entry{Time: historyBase.Add(2 * time.Second), QName: `-2+3.evil.example.`, QType: 1, Proto: "udp", Rcode: 0,
			ClientIP: "192.168.1.12", CacheHit: true},
		qlog.Entry{Time: historyBase.Add(3 * time.Second), QName: `@SUM(1).evil.example.`, QType: 1, Proto: "udp", Rcode: 0,
			ClientIP: "192.168.1.12", Upstream: "quad9"},
	)
	p, srv := statusPanel(t, ctrl)

	resp := authedRequest(t, p, srv, "/panel/history.csv")
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the CSV: %v", err)
	}
	csv := string(data)

	// Each formula-shaped cell reaches the file as text, with the
	// neutralizing single quote in front.
	for _, want := range []string{
		`'=cmd|' /C calc'!A0.evil.example.`,
		`'+1234567890.evil.example.`,
		`'-2+3.evil.example.`,
		`'@SUM(1).evil.example.`,
	} {
		if !strings.Contains(csv, want) {
			t.Errorf("the export does not neutralize the formula cell %q:\n%s", want, csv)
		}
	}

	// No cell may begin with a bare formula character. Every data line
	// is время;протокол;домен;…, so the domain (the third field) is
	// always preceded by ";" — a bare ";" plus a formula character means
	// the neutering was skipped.
	for _, bare := range []string{";=cmd", ";+1234567890", ";-2+3", ";@SUM"} {
		if strings.Contains(csv, bare) {
			t.Errorf("the export leaks a bare formula cell %q:\n%s", bare, csv)
		}
	}
}
