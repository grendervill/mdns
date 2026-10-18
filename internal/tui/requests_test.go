package tui

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/qlog"
)

// step applies one message to the model and returns it.
func step(m Model, msg tea.Msg) Model {
	updated, _ := m.Update(msg)
	return updated.(Model)
}

// key builds a runes key message.
func key(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

// requestEvent builds a requests event.
func requestEvent(e qlog.Entry) eventMsg {
	return eventMsg{e: api.Event{Type: "requests", Data: e}}
}

// TestRequestsFeed checks the live feed, the pause toggle and the
// resume toggle.
func TestRequestsFeed(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})

	for i := 0; i < 3; i++ {
		m = step(m, requestEvent(qlog.Entry{QName: fmt.Sprintf("d%d.example.com.", i), Proto: "udp"}))
	}
	if view := m.View(); !strings.Contains(view, "d2.example.com.") {
		t.Fatalf("View() misses the newest request:\n%s", view)
	}

	// Pause: new events must not append.
	m = step(m, key(' '))
	m = step(m, requestEvent(qlog.Entry{QName: "paused.example.com.", Proto: "udp"}))
	if view := m.View(); strings.Contains(view, "paused.example.com.") {
		t.Fatalf("paused feed still appended:\n%s", view)
	}

	// Resume.
	m = step(m, key(' '))
	m = step(m, requestEvent(qlog.Entry{QName: "resumed.example.com.", Proto: "udp"}))
	if view := m.View(); !strings.Contains(view, "resumed.example.com.") {
		t.Fatalf("feed did not resume:\n%s", view)
	}
}

// TestRequestsCap checks the 500-entry buffer.
func TestRequestsCap(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})

	for i := 0; i < 600; i++ {
		m = step(m, requestEvent(qlog.Entry{QName: fmt.Sprintf("d%d.example.com.", i), Proto: "udp"}))
	}
	if got := len(m.requests); got != requestsCap {
		t.Fatalf("buffer = %d entries, want %d", got, requestsCap)
	}
	if m.requests[0].QName != "d100.example.com." {
		t.Errorf("oldest entry = %q, want d100.example.com.", m.requests[0].QName)
	}
}

// TestRequestsClear checks the x key.
func TestRequestsClear(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})
	m = step(m, requestEvent(qlog.Entry{QName: "a.example.com.", Proto: "udp"}))

	m = step(m, key('x'))
	if got := len(m.requests); got != 0 {
		t.Errorf("buffer after x = %d entries, want 0", got)
	}
}

// TestBlockedMarked checks that blocked entries show their source.
func TestBlockedMarked(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})
	m = step(m, requestEvent(qlog.Entry{
		QName: "ads.example.com.", Proto: "udp", Blocked: true, BlockSource: "oisd-small",
	}))

	view := m.View()
	if !strings.Contains(view, "БЛОК") || !strings.Contains(view, "oisd-small") {
		t.Errorf("View() does not mark the blocked entry with its source:\n%s", view)
	}
}

// TestRequestsClientColumn checks that the feed renders the client
// address and names the column.
func TestRequestsClientColumn(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})
	m = step(m, requestEvent(qlog.Entry{
		QName: "a.example.com.", Proto: "udp", ClientIP: "192.168.1.50",
	}))

	view := m.View()
	for _, want := range []string{"клиент", "192.168.1.50", "a.example.com."} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q:\n%s", want, view)
		}
	}
}

// TestRequestsFilter checks the f-key feed filter: it narrows live and
// backfilled rows, keeps a cancelled edit and clears on Esc.
func TestRequestsFilter(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})
	m = step(m, requestEvent(qlog.Entry{QName: "ads.example.com.", Proto: "udp", ClientIP: "10.0.0.1"}))
	m = step(m, requestEvent(qlog.Entry{QName: "safe.example.com.", Proto: "dot", ClientIP: "10.0.0.2"}))

	// f opens the filter input; Enter commits the typed substring.
	m = step(m, key('f'))
	if !m.inputActive || m.inputMode != inputRequestsFilter {
		t.Fatalf("f did not open the feed filter input (active=%v mode=%v)", m.inputActive, m.inputMode)
	}
	m = typeText(m, "ads")
	m = step(m, enterKey())

	if m.requestsFilter != "ads" {
		t.Fatalf("requestsFilter = %q, want ads", m.requestsFilter)
	}
	view := m.View()
	if !strings.Contains(view, "Фильтр: «ads» · найдено 1 из 2") {
		t.Errorf("View() misses the filter note:\n%s", view)
	}
	if !strings.Contains(view, "ads.example.com.") {
		t.Errorf("View() dropped a matching row:\n%s", view)
	}
	if strings.Contains(view, "safe.example.com.") {
		t.Errorf("View() kept a row the filter excludes:\n%s", view)
	}

	// A live append that does not match stays buffered but hidden.
	m = step(m, requestEvent(qlog.Entry{QName: "other.example.com.", Proto: "tcp"}))
	if len(m.requests) != 3 {
		t.Fatalf("buffer = %d entries, want the row kept", len(m.requests))
	}
	if strings.Contains(m.View(), "other.example.com.") {
		t.Errorf("a non-matching live row leaked into the view:\n%s", m.View())
	}

	// The filter also matches the client address; re-opening the input
	// prefills the current value.
	m = step(m, key('f'))
	if m.input != "ads" {
		t.Fatalf("the filter input prefilled %q, want the current filter", m.input)
	}
	for range m.input {
		m = step(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = typeText(m, "10.0.0.2")
	m = step(m, enterKey())
	view = m.View()
	if !strings.Contains(view, "safe.example.com.") || strings.Contains(view, "ads.example.com.") {
		t.Errorf("the client filter did not narrow the feed:\n%s", view)
	}

	// Back to the domain filter: the backfill respects it too.
	m = step(m, key('f'))
	for range m.input {
		m = step(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = typeText(m, "ads")
	m = step(m, enterKey())
	m = step(m, requestsLoadedMsg{entries: []qlog.Entry{
		{QName: "ads2.example.com.", Proto: "udp"},
		{QName: "nodomain.example.net.", Proto: "udp"},
	}})
	view = m.View()
	if !strings.Contains(view, "ads2.example.com.") {
		t.Errorf("the filtered backfill dropped a matching row:\n%s", view)
	}
	if strings.Contains(view, "nodomain.example.net.") {
		t.Errorf("the filtered backfill kept a non-matching row:\n%s", view)
	}

	// Esc inside the input keeps the previous filter, unlike Enter.
	m = step(m, key('f'))
	m = typeText(m, "zzz")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.requestsFilter != "ads" {
		t.Errorf("esc in the input changed the filter to %q, want the previous ads", m.requestsFilter)
	}
	if !strings.Contains(m.View(), "ads2.example.com.") {
		t.Errorf("the cancelled edit dropped the filter:\n%s", m.View())
	}

	// Committing an empty value clears the filter.
	m = step(m, key('f'))
	for range m.input {
		m = step(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = step(m, enterKey())
	if m.requestsFilter != "" {
		t.Fatalf("an empty filter commit left %q", m.requestsFilter)
	}
	view = m.View()
	for _, want := range []string{"ads2.example.com.", "nodomain.example.net."} {
		if !strings.Contains(view, want) {
			t.Errorf("an empty filter commit did not restore %q:\n%s", want, view)
		}
	}

	// Esc on the screen also clears the filter.
	m = step(m, key('f'))
	m = typeText(m, "ads")
	m = step(m, enterKey())
	if m.requestsFilter != "ads" {
		t.Fatalf("requestsFilter = %q, want the filter re-applied before the esc check", m.requestsFilter)
	}
	m = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.requestsFilter != "" {
		t.Fatalf("esc on the requests screen left the filter %q", m.requestsFilter)
	}
	view = m.View()
	for _, want := range []string{"ads2.example.com.", "nodomain.example.net."} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q after clearing the filter:\n%s", want, view)
		}
	}
}

// TestRequestsFilterPromptVisible checks that the filter prompt stays on
// screen while its result set is empty, so typing is never blind.
func TestRequestsFilterPromptVisible(t *testing.T) {
	// Empty journal.
	m := New(&stubClient{}, Options{Initial: "requests"})
	m = step(m, key('f'))
	m = typeText(m, "abc")
	view := m.View()
	if !strings.Contains(view, "Фильтр ленты (домен/клиент/upstream/прото): abc▏") {
		t.Errorf("View() misses the prompt on an empty journal:\n%s", view)
	}
	if !strings.Contains(view, "Запросов пока нет.") {
		t.Errorf("View() misses the empty-journal note:\n%s", view)
	}

	// A committed filter that matches nothing: re-opening it keeps both
	// the prompt and the no-match note visible.
	m = New(&stubClient{}, Options{Initial: "requests"})
	m = step(m, requestEvent(qlog.Entry{QName: "a.example.com.", Proto: "udp"}))
	m = step(m, key('f'))
	m = typeText(m, "zzz")
	m = step(m, enterKey())
	if view := m.View(); !strings.Contains(view, "Нет запросов по фильтру «zzz»") {
		t.Fatalf("View() misses the no-match note:\n%s", view)
	}

	m = step(m, key('f'))
	m = typeText(m, "!")
	view = m.View()
	if !strings.Contains(view, "Фильтр ленты (домен/клиент/upstream/прото): zzz!▏") {
		t.Errorf("View() misses the prompt while editing a no-match filter:\n%s", view)
	}
	if !strings.Contains(view, "Нет запросов по фильтру «zzz»") {
		t.Errorf("View() dropped the no-match note while editing:\n%s", view)
	}
}

// TestRequestsRowWidth checks the journal table against its width
// budget: every row and the header stay within 113 columns.
func TestRequestsRowWidth(t *testing.T) {
	const budget = 113

	m := New(&stubClient{}, Options{Initial: "requests"})
	entries := []qlog.Entry{
		{
			QName: strings.Repeat("very-long-label.", 8) + "example.com.", Proto: "dot",
			ClientIP: "2001:db8::1234:5678:9abc:def0", Upstream: strings.Repeat("upstream", 6),
			LatencyMS: 1234.5,
		},
		{
			QName: "ads.example.com.", Proto: "udp", ClientIP: "192.168.100.200",
			Blocked: true, BlockSource: strings.Repeat("block-list", 5),
		},
		{QName: "cached.example.com.", Proto: "doh", ClientIP: "10.0.0.1", CacheHit: true},
	}

	for _, e := range entries {
		if line := m.requestLine(e); utf8.RuneCountInString(line) > budget {
			t.Errorf("row is %d columns, want <= %d: %q", utf8.RuneCountInString(line), budget, line)
		}
		m = step(m, requestEvent(e))
	}
	if got := utf8.RuneCountInString(requestsHeader()); got != budget {
		t.Errorf("header is %d columns, want %d", got, budget)
	}

	for _, line := range strings.Split(m.View(), "\n") {
		if strings.Contains(line, "example.com.") && utf8.RuneCountInString(line) > budget {
			t.Errorf("rendered row is %d columns, want <= %d: %q", utf8.RuneCountInString(line), budget, line)
		}
	}
}

func TestUpstreamsView(t *testing.T) {
	st := sampleStatus()
	st.Upstreams = append(st.Upstreams, api.UpstreamStatus{
		ID: "q9", Name: "Quad9", Transport: "doq", Address: "9.9.9.9:853",
		Enabled: true, Healthy: false, LatencyMS: 5000, Sent: 100, Failed: 7,
	})

	m := New(&stubClient{}, Options{Initial: "upstreams"})
	m = step(m, statusLoadedMsg{st: st})

	view := m.View()
	for _, want := range []string{"Cloudflare", "1.1.1.1:53", "12.5", "Quad9", "сбой", "100", "7"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q:\n%s", want, view)
		}
	}
}

// TestRequestsBackfill checks that entering the requests screen loads
// the recent journal from the daemon instead of starting empty.
func TestRequestsBackfill(t *testing.T) {
	sc := &stubClient{requestEntries: []qlog.Entry{
		{QName: "one.example.com.", Proto: "udp"},
		{QName: "two.example.com.", Proto: "dot"},
	}}
	m := New(sc, Options{})

	updated, cmd := m.Update(key('3')) // switch to the requests screen
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("entering the requests screen returned no load command")
	}
	m = step(m, cmd())

	if view := m.View(); !strings.Contains(view, "two.example.com.") {
		t.Errorf("View() misses the backfilled journal:\n%s", view)
	}
}

// TestRequestsScrollStops checks that scrolling up cannot run past the
// oldest entry into a blank view.
func TestRequestsScrollStops(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "requests"})
	for i := 0; i < 3; i++ {
		m = step(m, requestEvent(qlog.Entry{QName: fmt.Sprintf("d%d.example.com.", i), Proto: "udp"}))
	}

	for i := 0; i < 6; i++ {
		m = step(m, key('k'))
	}
	if got, want := m.requestsScroll, len(m.requests)-1; got != want {
		t.Fatalf("requestsScroll = %d, want it capped at %d", got, want)
	}
	if view := m.View(); !strings.Contains(view, "d0.example.com.") {
		t.Errorf("View() is blank at full scroll:\n%s", view)
	}
}
