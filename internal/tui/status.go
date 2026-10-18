package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"mydns/internal/api"
)

// Styles shared by the views.
var (
	titleStyle     = lipgloss.NewStyle().Bold(true)
	dimStyle       = lipgloss.NewStyle().Faint(true)
	okStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	activeTabStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	tabStyle       = lipgloss.NewStyle().Faint(true)
)

// statusView renders the main screen.
func (m *Model) statusView() string {
	if m.statusErr != nil {
		return m.offlineView()
	}
	if m.status.Domain == "" {
		return dimStyle.Render("Загрузка…") + "\n"
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("mdns " + m.status.Version + " · " + m.status.Domain))
	b.WriteString("\n")

	if len(m.status.Listeners) > 0 {
		b.WriteString(dimStyle.Render("Слушает: " + strings.Join(m.status.Listeners, ", ")))
		b.WriteString("\n")
	}
	b.WriteString(dimStyle.Render("Стратегия: " + m.status.Strategy))
	b.WriteString("\n")
	if line := m.certLine(); line != "" {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if len(m.status.Links) > 0 {
		b.WriteString(titleStyle.Render("Ссылки для устройств"))
		b.WriteString("\n")
		for _, l := range m.status.Links {
			b.WriteString(fmt.Sprintf("  %-28s %s\n", dimStyle.Render(l.Title), l.URI))
		}
		b.WriteString("\n")
	}

	if len(m.status.Upstreams) > 0 {
		b.WriteString(titleStyle.Render("Upstream'ы"))
		b.WriteString("\n")
		for _, u := range m.status.Upstreams {
			b.WriteString(fmt.Sprintf("  %-22s %-6s %-22s %8s  %s\n",
				u.Name, u.Transport, u.Address,
				formatLatency(u.LatencyMS), healthLabel(u)))
		}
		b.WriteString("\n")
	}

	b.WriteString(titleStyle.Render("Кеш"))
	b.WriteString(fmt.Sprintf("  попадания %d · промахи %d · записей %d\n",
		m.status.Cache.Hits, m.status.Cache.Misses, m.status.Cache.Size))

	b.WriteString(titleStyle.Render("Фильтр"))
	if m.status.Filter.Enabled {
		b.WriteString(fmt.Sprintf("  включён · режим %s · заблокировано %d\n",
			m.status.Filter.Mode, m.status.Filter.TotalBlocked))
		for _, l := range m.status.Filter.Lists {
			b.WriteString(fmt.Sprintf("  %-24s правил %d · попаданий %d\n", l.ID, l.Block, l.Hits))
		}
	} else {
		b.WriteString("  выключен\n")
	}

	return b.String()
}

// certLine renders the certificate state line, empty when the daemon
// reports no certificate information at all (an older daemon).
func (m *Model) certLine() string {
	c := m.status.Cert
	if c.Mode == "" {
		return ""
	}

	switch c.State {
	case "ok":
		name := c.Issuer
		if name == "" {
			name = c.Mode
		}
		return okStyle.Render(fmt.Sprintf("Сертификат: %s, истекает %s",
			name, c.NotAfter.Format("02.01.2006")))
	case "waiting":
		return warnStyle.Render("Сертификат: ожидание выпуска…")
	case "error":
		return errStyle.Render("Сертификат: ошибка — " + c.Error)
	}
	return ""
}

// offlineView renders the daemon-unavailable state.
func (m *Model) offlineView() string {
	var b strings.Builder
	b.WriteString(errStyle.Render("Демон недоступен: " + m.statusErr.Error()))
	b.WriteString("\n\n")
	b.WriteString("Что можно сделать:\n")
	b.WriteString("  r         — попробовать переподключиться\n")
	b.WriteString("  mdns setup — первичная настройка, если демон ещё не запускался\n")
	return b.String()
}

// formatLatency renders a latency in milliseconds.
func formatLatency(ms float64) string {
	return fmt.Sprintf("%.1f ms", ms)
}

// healthLabel names an upstream's state.
func healthLabel(u api.UpstreamStatus) string {
	switch {
	case !u.Enabled:
		return dimStyle.Render("выключен")
	case u.Healthy:
		return okStyle.Render("здоров")
	default:
		return warnStyle.Render("сбой")
	}
}
