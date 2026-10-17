package tui

import (
	"fmt"
	"strings"
	"testing"

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

// TestUpstreamsView checks the detailed upstream table.
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
