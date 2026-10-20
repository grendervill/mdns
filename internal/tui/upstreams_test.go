package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// upstreamCfgWith builds a default config carrying the given upstreams.
func upstreamCfgWith(ups ...config.UpstreamConfig) *config.Config {
	cfg := config.Default()
	cfg.Upstreams = ups
	return cfg
}

// upstreamModel builds the upstreams screen over sc with cfg loaded.
func upstreamModel(sc *stubClient, cfg *config.Config) Model {
	m := New(sc, Options{Initial: "upstreams"})
	return step(m, upstreamConfigLoadedMsg{cfg: cfg})
}

// spaceKey is the enabled-toggle key.
func spaceKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeySpace} }

// TestUpstreamCatalogAdd checks the provider picker: the add carries the
// panel's ID/priority rules, a duplicate endpoint is refused without an
// update, and the add shows up after the config reload.
func TestUpstreamCatalogAdd(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	if m.screen != screenUpstreamCatalog {
		t.Fatalf("screen = %v, want the catalog picker", m.screen)
	}
	m = drainCmd(t, m, cmd)

	view := m.View()
	for _, want := range []string{"Cloudflare", "DoH", "https://cloudflare-dns.com/dns-query"} {
		if !strings.Contains(view, want) {
			t.Errorf("catalog View() misses %q:\n%s", want, view)
		}
	}

	// The first entry is Cloudflare's DoH endpoint.
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	got := sc.updates[0].Upstreams
	if len(got) != 1 {
		t.Fatalf("upstreams = %+v, want one added endpoint", got)
	}
	up := got[0]
	if up.ID != "cloudflare" {
		t.Errorf("id = %q, want cloudflare (the free provider id)", up.ID)
	}
	if up.Transport != "doh" || up.Address != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("added %s %s, want the Cloudflare DoH endpoint", up.Transport, up.Address)
	}
	if up.Priority != 0 {
		t.Errorf("priority = %d, want 0 (max+1 over an empty list)", up.Priority)
	}
	if !up.Enabled {
		t.Errorf("the added upstream is not enabled")
	}

	// The reload that follows the apply shows the endpoint as present.
	if !strings.Contains(m.View(), "добавлен") {
		t.Errorf("catalog View() does not mark the added endpoint:\n%s", m.View())
	}

	// The same endpoint cannot be added twice: the second Enter changes
	// nothing and reports the duplicate.
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d after a duplicate, want 1", len(sc.updates))
	}
	if m.upstreamErr == nil || !strings.Contains(m.upstreamErr.Error(), "уже добавлен") {
		t.Errorf("duplicate add error = %v, want an «уже добавлен» note", m.upstreamErr)
	}
}

// TestUpstreamCatalogUniqueID checks the ID fallback: a second endpoint
// of the same provider gets provider-transport.
func TestUpstreamCatalogUniqueID(t *testing.T) {
	cfg := upstreamCfgWith(config.UpstreamConfig{ID: "cloudflare", Enabled: true, Transport: "doh", Address: "https://cloudflare-dns.com/dns-query"})
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	m = step(m, key('a'))
	// The picker's second row is Cloudflare's DoT endpoint.
	m = step(m, key('j'))
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	got := sc.updates[0].Upstreams
	if len(got) != 2 || got[1].ID != "cloudflare-dot" || got[1].Priority != 1 {
		t.Errorf("second upstream = %+v, want id cloudflare-dot with priority 1", got)
	}
}

// TestUpstreamCustomForm checks the custom form: a valid upstream is
// validated and applied, an invalid address surfaces the validation
// error without touching the config, and Esc leaves the config alone.
func TestUpstreamCustomForm(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	updated, cmd := m.Update(key('c'))
	m = updated.(Model)
	if m.screen != screenUpstreamForm {
		t.Fatalf("screen = %v, want the custom form", m.screen)
	}
	if cmd != nil {
		t.Fatalf("c returned a command, want none")
	}
	if m.upstreamForm.Transport != "plain" {
		t.Errorf("default transport = %q, want plain", m.upstreamForm.Transport)
	}

	// Address: field 3.
	m = step(m, key('j'))
	m = step(m, key('j'))
	m = step(m, key('j'))
	updated, _ = m.Update(enterKey())
	m = updated.(Model)
	m = typeText(m, "9.9.9.9:53")
	updated, _ = m.Update(enterKey())
	m = updated.(Model)

	// Priority: field 5.
	m = step(m, key('j'))
	m = step(m, key('j'))
	updated, _ = m.Update(enterKey())
	m = updated.(Model)
	m = typeText(m, "5")
	updated, _ = m.Update(enterKey())
	m = updated.(Model)

	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	if m.screen != screenUpstreams {
		t.Errorf("screen = %v after applying, want upstreams", m.screen)
	}
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	got := sc.updates[0].Upstreams
	if len(got) != 1 {
		t.Fatalf("upstreams = %+v, want one", got)
	}
	up := got[0]
	if up.ID != "9-9-9-9" {
		t.Errorf("derived id = %q, want 9-9-9-9", up.ID)
	}
	if up.Address != "9.9.9.9:53" || up.Priority != 5 || !up.Enabled || up.Transport != "plain" {
		t.Errorf("added upstream = %+v, want a plain 9.9.9.9:53 with priority 5", up)
	}
}

// TestUpstreamCustomFormValidationError checks that config.Validate
// rejects a bad address in place and the config never leaves the TUI.
func TestUpstreamCustomFormValidationError(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	m = step(m, key('c'))
	m = step(m, key('j'))
	m = step(m, key('j'))
	m = step(m, key('j'))
	updated, _ := m.Update(enterKey())
	m = updated.(Model)
	m = typeText(m, "not-an-address")
	updated, _ = m.Update(enterKey())
	m = updated.(Model)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	if cmd != nil {
		t.Fatalf("ctrl+s returned a command after a validation failure")
	}
	if m.screen != screenUpstreamForm {
		t.Errorf("screen = %v after a validation failure, want the form", m.screen)
	}
	if m.upstreamFormErr == nil {
		t.Fatalf("upstreamFormErr = nil, want the validation error")
	}
	if !strings.Contains(m.View(), "host:port") {
		t.Errorf("form View() misses the validation error:\n%s", m.View())
	}
	if len(sc.updates) != 0 {
		t.Errorf("UpdateConfig calls = %d, want 0 for an invalid address", len(sc.updates))
	}
}

// TestUpstreamCustomFormEsc checks that Esc after edits cancels without
// touching the config.
func TestUpstreamCustomFormEsc(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	m = step(m, key('c'))
	m = step(m, key('j')) // the name field
	updated, _ := m.Update(enterKey())
	m = updated.(Model)
	m = typeText(m, "My resolver")
	updated, _ = m.Update(enterKey())
	m = updated.(Model)

	m = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != screenUpstreams {
		t.Fatalf("esc left the form on %v, want the upstreams screen", m.screen)
	}
	if len(sc.updates) != 0 {
		t.Errorf("UpdateConfig calls = %d after esc, want 0", len(sc.updates))
	}
}

// TestUpstreamToggleAndRemove checks the last-enabled guard for space and
// d, then both actions with two enabled upstreams.
func TestUpstreamToggleAndRemove(t *testing.T) {
	one := upstreamCfgWith(config.UpstreamConfig{ID: "a", Enabled: true, Transport: "plain", Address: "1.1.1.1:53"})
	sc := &stubClient{cfg: one}
	m := upstreamModel(sc, one)

	updated, cmd := m.Update(spaceKey())
	m = updated.(Model)
	if cmd != nil || len(sc.updates) != 0 {
		t.Fatalf("space disabled the last enabled upstream (cmd=%v, updates=%d)", cmd, len(sc.updates))
	}
	if m.upstreamErr == nil || !strings.Contains(m.upstreamErr.Error(), "последний") {
		t.Errorf("last-enabled note = %v, want a refusal", m.upstreamErr)
	}

	updated, cmd = m.Update(key('d'))
	m = updated.(Model)
	if cmd != nil || len(sc.updates) != 0 {
		t.Fatalf("d removed the last enabled upstream (cmd=%v, updates=%d)", cmd, len(sc.updates))
	}
	if m.upstreamErr == nil || !strings.Contains(m.upstreamErr.Error(), "последний") {
		t.Errorf("remove-last note = %v, want a refusal", m.upstreamErr)
	}

	// With two enabled upstreams both actions work.
	two := upstreamCfgWith(
		config.UpstreamConfig{ID: "a", Enabled: true, Transport: "plain", Address: "1.1.1.1:53"},
		config.UpstreamConfig{ID: "b", Enabled: true, Transport: "plain", Address: "8.8.8.8:53"},
	)
	sc = &stubClient{cfg: two}
	m = upstreamModel(sc, two)

	updated, cmd = m.Update(spaceKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 || sc.updates[0].Upstreams[0].Enabled {
		t.Fatalf("space did not disable the first upstream: %+v", sc.updates)
	}

	m = upstreamModel(sc, sc.cfg)
	updated, cmd = m.Update(key('d'))
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 2 {
		t.Fatalf("UpdateConfig calls = %d, want 2", len(sc.updates))
	}
	got := sc.updates[1].Upstreams
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("upstreams after d = %+v, want just b", got)
	}
}

// TestUpstreamPriorityAndStrategy checks the p and s round-trips.
func TestUpstreamPriorityAndStrategy(t *testing.T) {
	cfg := upstreamCfgWith(config.UpstreamConfig{ID: "a", Enabled: true, Transport: "plain", Address: "1.1.1.1:53", Priority: 2})
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	updated, cmd := m.Update(key('p'))
	m = updated.(Model)
	if !m.inputActive || m.inputMode != inputUpstreamPriority {
		t.Fatalf("p did not open the priority input")
	}
	if m.input != "" {
		t.Errorf("priority input prefilled with %q, want empty", m.input)
	}
	if !strings.Contains(m.View(), "сейчас 2") {
		t.Errorf("View() does not show the current priority in the prompt:\n%s", m.View())
	}
	m = typeText(m, "7")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 || sc.updates[0].Upstreams[0].Priority != 7 {
		t.Fatalf("priority update = %+v, want 7", sc.updates)
	}

	// An empty submit cancels without touching the config.
	updated, cmd = m.Update(key('p'))
	m = updated.(Model)
	if !m.inputActive || m.input != "" {
		t.Fatalf("reopened priority input is active=%v value=%q, want active and empty", m.inputActive, m.input)
	}
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if cmd != nil || len(sc.updates) != 1 {
		t.Errorf("an empty priority submit applied a change (cmd=%v, updates=%d)", cmd != nil, len(sc.updates))
	}

	// The strategy picker starts on the current value and applies the
	// highlighted one with Enter.
	m = upstreamModel(sc, sc.cfg)
	updated, cmd = m.Update(key('s'))
	m = updated.(Model)
	if cmd != nil {
		t.Fatalf("s returned a command, want the strategy picker")
	}
	if m.screen != screenStrategyPicker {
		t.Fatalf("screen = %v, want the strategy picker", m.screen)
	}
	if !strings.Contains(m.View(), "сейчас") {
		t.Errorf("strategy picker View() does not mark the current strategy:\n%s", m.View())
	}
	m = step(m, key('j')) // fastest → failover
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if m.screen != screenUpstreams {
		t.Errorf("screen = %v after Enter, want upstreams", m.screen)
	}
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 2 || sc.updates[1].Strategy != "failover" {
		t.Fatalf("strategy update = %+v, want failover", sc.updates)
	}
	if !strings.Contains(m.View(), "failover") {
		t.Errorf("upstreams View() does not show the new strategy:\n%s", m.View())
	}
}

// TestUpstreamProbe checks the t key: the result is rendered for success
// and both failure shapes, and the config is never updated.
func TestUpstreamProbe(t *testing.T) {
	cfg := upstreamCfgWith(config.UpstreamConfig{ID: "a", Name: "A", Enabled: true, Transport: "plain", Address: "1.1.1.1:53"})

	t.Run("success", func(t *testing.T) {
		sc := &stubClient{cfg: cfg, probeResults: []probe.Result{{
			Endpoint: providers.Endpoint{Transport: "plain", Address: "1.1.1.1:53"},
			Latency:  2500 * time.Millisecond,
			Rcode:    "NOERROR",
		}}}
		m := upstreamModel(sc, cfg)

		updated, cmd := m.Update(key('t'))
		m = updated.(Model)
		if cmd == nil {
			t.Fatalf("t returned no probe command")
		}
		m = step(m, cmd())

		if !strings.Contains(m.View(), "Отвечает: 2500.0 мс, rcode NOERROR") {
			t.Errorf("View() misses the probe result:\n%s", m.View())
		}
		if len(sc.updates) != 0 {
			t.Errorf("probe called UpdateConfig %d times, want 0", len(sc.updates))
		}
	})

	t.Run("unexpected reply", func(t *testing.T) {
		sc := &stubClient{cfg: cfg, probeResults: []probe.Result{{
			Endpoint: providers.Endpoint{Transport: "plain", Address: "1.1.1.1:53"},
			Err:      "unexpected reply: SERVFAIL",
		}}}
		m := upstreamModel(sc, cfg)

		updated, cmd := m.Update(key('t'))
		m = updated.(Model)
		m = step(m, cmd())

		if !strings.Contains(m.View(), "Ответил ошибкой: SERVFAIL") {
			t.Errorf("View() misses the failure result:\n%s", m.View())
		}
		if len(sc.updates) != 0 {
			t.Errorf("probe called UpdateConfig %d times, want 0", len(sc.updates))
		}
	})

	t.Run("no answer", func(t *testing.T) {
		sc := &stubClient{cfg: cfg, probeResults: []probe.Result{{
			Endpoint: providers.Endpoint{Transport: "plain", Address: "1.1.1.1:53"},
			Err:      "connection refused",
		}}}
		m := upstreamModel(sc, cfg)

		updated, cmd := m.Update(key('t'))
		m = updated.(Model)
		m = step(m, cmd())

		if !strings.Contains(m.View(), "Нет ответа: connection refused") {
			t.Errorf("View() misses the no-answer result:\n%s", m.View())
		}
		if len(sc.updates) != 0 {
			t.Errorf("probe called UpdateConfig %d times, want 0", len(sc.updates))
		}
	})
}

// TestUpstreamCatalogDetails checks the right pane carries the trust
// rating and source, and that an added endpoint gains the duplicate
// marker; Esc returns without touching the config.
func TestUpstreamCatalogDetails(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	view := m.View()
	for _, want := range []string{"Cloudflare", "Доверие:", "Privacy Guides", "Обезличенные данные"} {
		if !strings.Contains(view, want) {
			t.Errorf("catalog View() misses %q:\n%s", want, view)
		}
	}

	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if !strings.Contains(m.View(), "Дубль:") {
		t.Errorf("catalog View() misses the duplicate marker after the add:\n%s", m.View())
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != screenUpstreams {
		t.Errorf("esc left the catalog on %v, want upstreams", m.screen)
	}
	if len(sc.updates) != 1 {
		t.Errorf("UpdateConfig calls = %d, want 1 (esc must not add)", len(sc.updates))
	}
}

// TestTransportPicker checks that Enter on the transport field opens the
// list, Enter sets the form value and nothing is applied before ctrl+s.
func TestTransportPicker(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)

	m = step(m, key('c'))
	m = step(m, key('j'))
	m = step(m, key('j')) // the transport field

	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if cmd != nil {
		t.Fatalf("enter on the transport field returned a command")
	}
	if m.screen != screenTransportPicker {
		t.Fatalf("screen = %v, want the transport picker", m.screen)
	}
	if !strings.Contains(m.View(), "сейчас") || !strings.Contains(m.View(), "host:port") {
		t.Errorf("transport picker View() misses the current marker or the address format:\n%s", m.View())
	}

	m = step(m, key('j'))
	m = step(m, key('j')) // plain → doh
	if !strings.Contains(m.View(), "https-URL") {
		t.Errorf("transport picker View() misses the DoH note:\n%s", m.View())
	}
	updated, _ = m.Update(enterKey())
	m = updated.(Model)
	if m.screen != screenUpstreamForm {
		t.Errorf("screen = %v after Enter, want the form", m.screen)
	}
	if m.upstreamForm.Transport != "doh" {
		t.Errorf("form transport = %q, want doh", m.upstreamForm.Transport)
	}
	if len(sc.updates) != 0 {
		t.Errorf("the transport picker applied the config before ctrl+s")
	}

	// Esc from the picker keeps the form value.
	m = step(m, enterKey())
	m = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != screenUpstreamForm {
		t.Errorf("esc left the picker on %v, want the form", m.screen)
	}
	if m.upstreamForm.Transport != "doh" {
		t.Errorf("esc reset the transport to %q, want doh", m.upstreamForm.Transport)
	}
}

// TestUpstreamsFooterAndHelp checks the new keys are discoverable.
func TestUpstreamsFooterAndHelp(t *testing.T) {
	cfg := upstreamCfgWith(config.UpstreamConfig{ID: "a", Enabled: true, Transport: "plain", Address: "1.1.1.1:53"})
	m := upstreamModel(&stubClient{cfg: cfg}, cfg)
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	view := m.View()
	for _, want := range []string{"Стратегия", "space — вкл/выкл", "d — удалить", "p — приоритет", "s — стратегия", "t — проверить", "a — каталог", "c — свой upstream"} {
		if !strings.Contains(view, want) {
			t.Errorf("upstreams View() misses %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "пауза ленты") {
		t.Errorf("the upstreams footer advertises the feed's pause key:\n%s", view)
	}

	m = step(m, key('?'))
	help := m.View()
	for _, want := range []string{"Upstream'ы (экран 4)", "каталог провайдеров", "свой upstream", "проверить выбранный"} {
		if !strings.Contains(help, want) {
			t.Errorf("help View() misses %q:\n%s", want, help)
		}
	}
}

// TestUpstreamsEmptyState checks that an empty upstream list still shows
// the way out and an error instead of a silent blank screen.
func TestUpstreamsEmptyState(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)
	m.upstreamErr = errors.New("демон недоступен")

	view := m.View()
	for _, want := range []string{"a откроет каталог", "c добавит свой", "демон недоступен"} {
		if !strings.Contains(view, want) {
			t.Errorf("empty upstreams View() misses %q:\n%s", want, view)
		}
	}
}
