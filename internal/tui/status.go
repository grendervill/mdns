package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"mydns/internal/api"
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

	title := "mdns"
	if version := versionLabel(m.status.Version); version != "" {
		title += " " + version
	}
	b.WriteString(titleStyle.Render(title + " · " + m.status.Domain))
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

	width := m.pickerContentWidth()
	narrow := m.width > 0 && width < 90

	if len(m.status.Links) > 0 {
		b.WriteString(titleStyle.Render("Ссылки для устройств"))
		b.WriteString("\n")
		for _, l := range m.status.Links {
			if narrow {
				b.WriteString(narrowLinkLine(l.Title, l.URI, width))
			} else {
				b.WriteString(fmt.Sprintf("  %-28s %s\n", dimStyle.Render(l.Title), l.URI))
			}
		}
		b.WriteString("\n")
	}

	if len(m.status.Upstreams) > 0 {
		b.WriteString(titleStyle.Render("Upstream'ы"))
		b.WriteString("\n")
		for _, u := range m.status.Upstreams {
			if narrow {
				b.WriteString(narrowUpstreamLine(u, width))
			} else {
				b.WriteString(fmt.Sprintf("  %-22s %-6s %-22s %8s  %s\n",
					u.Name, u.Transport, u.Address,
					formatLatency(u.LatencyMS), healthLabel(u)))
			}
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

// narrowLinkLine renders one device link on a single row, trimming the
// title and the URI instead of letting lipgloss wrap them.
func narrowLinkLine(title, uri string, width int) string {
	const titleCol = 24
	title = truncate(title, titleCol)
	uriWidth := width - 2 - titleCol - 1
	if uriWidth < 8 {
		uriWidth = 8
	}
	uri = truncate(uri, uriWidth)
	padding := strings.Repeat(" ", titleCol-len([]rune(title)))
	return "  " + dimStyle.Render(title) + padding + " " + uri + "\n"
}

// narrowUpstreamLine packs one upstream into a single row at narrow
// widths: name, transport, a truncated address, latency and state.
func narrowUpstreamLine(u api.UpstreamStatus, width int) string {
	const (
		nameCol      = 18
		transportCol = 6
	)
	latency := formatLatency(u.LatencyMS)
	state := healthLabel(u)
	used := 2 + nameCol + 1 + transportCol + 1 + 1 + len([]rune(latency)) + 2 + lipgloss.Width(state)
	addressWidth := width - used
	if addressWidth < 8 {
		addressWidth = 8
	}
	name := truncate(u.Name, nameCol)
	transport := truncate(u.Transport, transportCol)
	address := truncate(u.Address, addressWidth)
	return fmt.Sprintf("  %-*s %-*s %-*s %*s  %s\n",
		nameCol, name, transportCol, transport, addressWidth, address,
		len([]rune(latency)), latency, state)
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
