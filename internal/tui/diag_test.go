package tui

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/probe"
	"mydns/internal/tlscert"
)

// checkLine returns the view line naming the given check, or "".
func checkLine(view, name string) string {
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, name+":") {
			return line
		}
	}
	return ""
}

// diagStatus is the all-good status the diagnostics tests render: one
// listener, matching the config, and an issued certificate.
func diagStatus() api.Status {
	st := sampleStatus()
	st.Listeners = []string{"plain:53"}
	st.Cert = tlscert.Status{Mode: "self-signed", State: "ok", Issuer: "self-signed", NotAfter: certExpiry}
	return st
}

// diagConfig is the all-good config: plain DNS only (so the listener
// check matches the status), one enabled upstream and one list.
func diagConfig() *config.Config {
	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	cfg.Protocols = config.Protocols{Plain: config.Protocol{Enabled: true, Port: 53}}
	cfg.Upstreams = []config.UpstreamConfig{{
		ID: "cf", Name: "Cloudflare", Transport: "plain", Address: "1.1.1.1:53", Enabled: true,
	}}
	cfg.Filter.Enabled = true
	cfg.Filter.Lists = []config.FilterList{{ID: "oisd-small"}}
	return cfg
}

// diagClient is a fake client for the diagnostics tests.
func diagClient() *stubClient {
	return &stubClient{
		status:      diagStatus(),
		cfg:         diagConfig(),
		filterLists: []filter.ListStatus{{ID: "oisd-small", Applied: 100}},
	}
}

// openDiag switches to tab 7 and applies the load command.
func openDiag(t *testing.T, sc *stubClient) Model {
	t.Helper()
	m := New(sc, Options{})
	updated, cmd := m.Update(key('7'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("tab 7 returned no command")
	}
	return step(m, cmd())
}

// TestDiagScreen checks the diagnostic lines for a healthy daemon, a
// certificate error and a failed upstream probe.
func TestDiagScreen(t *testing.T) {
	t.Run("all good", func(t *testing.T) {
		m := openDiag(t, diagClient())

		view := m.View()
		for _, want := range []string{
			"Диагностика",
			"✓ Конфигурация: валидна, домен dns.example.com",
			"✓ Порты: слушает: plain:53",
			"✓ Сертификат: ok, self-signed",
			"✓ Upstream'ы: лучший — Cloudflare, 10.0 ms",
			"✓ Списки фильтра: правил 100, списков 1",
			"✓ Версия: mdns test · домен dns.example.com",
		} {
			if !strings.Contains(view, want) {
				t.Errorf("View() misses %q:\n%s", want, view)
			}
		}
		if strings.Contains(view, "\n✗") || strings.Contains(view, "\n! ") {
			t.Errorf("View() has warnings on a healthy daemon:\n%s", view)
		}
	})

	t.Run("certificate error", func(t *testing.T) {
		sc := diagClient()
		sc.status.Cert = tlscert.Status{Mode: "acme", State: "error", Error: "acme: no account"}

		view := openDiag(t, sc).View()
		if !strings.Contains(view, "✗ Сертификат: ошибка — acme: no account") {
			t.Errorf("View() misses the certificate failure line:\n%s", view)
		}
	})

	t.Run("certificate error is one short line", func(t *testing.T) {
		sc := diagClient()
		sc.status.Cert = tlscert.Status{
			Mode:  "acme",
			State: "error",
			Error: "acme: first line\nsecond line with a stack trace that must not be rendered",
		}

		view := openDiag(t, sc).View()
		if !strings.Contains(view, "✗ Сертификат: ошибка — acme: first line") {
			t.Errorf("View() misses the sanitized certificate line:\n%s", view)
		}
		if strings.Contains(view, "second line") {
			t.Errorf("View() rendered a multi-line certificate error:\n%s", view)
		}

		sc.status.Cert.Error = strings.Repeat("x", 200)
		view = openDiag(t, sc).View()
		if !strings.Contains(view, "…") {
			t.Errorf("View() did not truncate a long certificate error:\n%s", view)
		}
		if line := checkLine(view, "Сертификат"); utf8.RuneCountInString(line) > 70 {
			t.Errorf("certificate line is %d columns wide: %q", utf8.RuneCountInString(line), line)
		}
	})

	t.Run("all protocols disabled", func(t *testing.T) {
		sc := diagClient()
		cfg := diagConfig()
		cfg.Protocols = config.Protocols{}
		sc.cfg = cfg
		sc.status.Listeners = nil

		view := openDiag(t, sc).View()
		if !strings.Contains(view, "✓ Порты: все протоколы выключены") {
			t.Errorf("View() misses the all-disabled ports line:\n%s", view)
		}
		if strings.Contains(view, "ни об одном листенере") {
			t.Errorf("View() warns about missing listeners with every protocol off:\n%s", view)
		}
	})

	t.Run("probe failure", func(t *testing.T) {
		sc := diagClient()
		sc.probeResults = []probe.Result{{Err: "dial tcp 1.1.1.1:53: i/o timeout"}}

		view := openDiag(t, sc).View()
		if !strings.Contains(view, "! Upstream «Cloudflare»: 1.1.1.1:53 — dial tcp 1.1.1.1:53: i/o timeout") {
			t.Errorf("View() misses the upstream warning line:\n%s", view)
		}
		if strings.Contains(view, "лучший —") {
			t.Errorf("View() reports a best upstream although the ping failed:\n%s", view)
		}
	})

	t.Run("filter list error", func(t *testing.T) {
		sc := diagClient()
		sc.filterLists = []filter.ListStatus{{ID: "oisd-small", Error: "connection refused"}}

		view := openDiag(t, sc).View()
		if !strings.Contains(view, "! Список «oisd-small»: connection refused") {
			t.Errorf("View() misses the list failure line:\n%s", view)
		}
	})

	t.Run("daemon down", func(t *testing.T) {
		sc := &stubClient{statusErr: errors.New("connection refused"), configErr: errors.New("connection refused")}

		view := openDiag(t, sc).View()
		if !strings.Contains(view, "✗ Конфигурация: connection refused") {
			t.Errorf("View() misses the config failure line:\n%s", view)
		}
		if !strings.Contains(view, "! Сертификат: демон не запущен") {
			t.Errorf("View() misses the offline certificate warning:\n%s", view)
		}
	})
}

// TestDiagNav checks the diagnostics tab and the ? help overlay: ? does
// not change the selected tab and Esc returns to it.
func TestDiagNav(t *testing.T) {
	sc := diagClient()
	m := New(sc, Options{})

	updated, cmd := m.Update(key('7'))
	m = updated.(Model)
	if m.screen != screenDiag {
		t.Fatalf("tab 7 opened %v, want diag", m.screen)
	}
	if cmd == nil {
		t.Fatalf("tab 7 returned no load command")
	}
	m = step(m, cmd())

	updated, _ = m.Update(key('?'))
	m = updated.(Model)
	if m.screen != screenHelp {
		t.Fatalf("? opened %v, want help", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "горячие клавиши") {
		t.Errorf("the help overlay misses its title:\n%s", view)
	}
	if !strings.Contains(view, "7 Диагностика") {
		t.Errorf("the help overlay lost the tab bar:\n%s", view)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != screenDiag {
		t.Errorf("esc from help returned to %v, want diag", m.screen)
	}

	// A digit also leaves the overlay.
	updated, _ = m.Update(key('?'))
	m = updated.(Model)
	if m.screen != screenHelp {
		t.Fatalf("? reopened %v, want help", m.screen)
	}
	updated, _ = m.Update(key('1'))
	m = updated.(Model)
	if m.screen != screenStatus {
		t.Errorf("digit from help opened %v, want status", m.screen)
	}
}
