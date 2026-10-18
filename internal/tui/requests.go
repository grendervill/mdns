package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/miekg/dns"

	"mydns/internal/qlog"
)

// requestsCap is the requests screen buffer size.
const requestsCap = 500

// loadRequests fetches the recent query journal.
func loadRequests(c Client) tea.Cmd {
	return func() tea.Msg {
		entries, err := c.Requests(context.Background(), requestsCap)
		return requestsLoadedMsg{entries: entries, err: err}
	}
}

// requestsView renders the live query journal.
func (m *Model) requestsView() string {
	var b strings.Builder

	shown := m.filteredRequests()

	if m.requestsPaused {
		b.WriteString(warnStyle.Render("Лента на паузе (пробел — продолжить)") + "\n")
	}
	if m.requestsFilter != "" {
		b.WriteString(dimStyle.Render(fmt.Sprintf("Фильтр: «%s» · найдено %d из %d · f — изменить · esc — сбросить", m.requestsFilter, len(shown), len(m.requests))))
		b.WriteString("\n")
	}
	if m.requestsPaused || m.requestsFilter != "" {
		b.WriteString("\n")
	}

	if len(m.requests) == 0 {
		b.WriteString(dimStyle.Render("Запросов пока нет.") + "\n")
		m.writeRequestsInput(&b)
		return b.String()
	}
	if len(shown) == 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("Нет запросов по фильтру «%s» (esc — сбросить).", m.requestsFilter)) + "\n")
		m.writeRequestsInput(&b)
		return b.String()
	}

	b.WriteString(dimStyle.Render(requestsHeader()))
	b.WriteString("\n")

	// Show the last lines that fit; scroll counts lines up from the
	// newest entry.
	limit := len(shown)
	if m.height > 4 && limit > m.height-4 {
		limit = m.height - 4
	}
	end := len(shown) - m.requestsScroll
	if end < 0 {
		end = 0
	}
	start := end - limit
	if start < 0 {
		start = 0
	}

	for _, e := range shown[start:end] {
		b.WriteString(m.requestLine(e))
		b.WriteString("\n")
	}

	if m.requestsScroll > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("… прокрутка вверх на %d строк (↓ — вниз)", m.requestsScroll)))
		b.WriteString("\n")
	}

	m.writeRequestsInput(&b)
	return b.String()
}

// writeRequestsInput appends the feed filter prompt while it is open.
// It runs on every render path, so the line stays visible even when
// the active filter matches nothing.
func (m *Model) writeRequestsInput(b *strings.Builder) {
	if !m.inputActive || m.inputMode != inputRequestsFilter {
		return
	}
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("Фильтр ленты (домен/клиент/upstream/прото): ") + m.input + "▏")
	b.WriteString("\n")
}

// Column widths of the journal table: time, protocol, client, domain,
// type, result, source and latency. The total stays inside a
// 120-column terminal.
const (
	colProto  = 5
	colClient = 18
	colDomain = 24
	colType   = 5
	colResult = 17
	colOrigin = 20
	colMS     = 6
)

// requestsHeader renders the column captions.
func requestsHeader() string {
	return fmt.Sprintf("%-8s  %-*s  %-*s  %-*s %-*s %-*s %-*s %*s",
		"время", colProto, "прото", colClient, "клиент", colDomain, "домен",
		colType, "тип", colResult, "результат", colOrigin, "источник", colMS, "мс")
}

// filteredRequests returns the entries matching the feed filter.
func (m *Model) filteredRequests() []qlog.Entry {
	if m.requestsFilter == "" {
		return m.requests
	}
	needle := strings.ToLower(m.requestsFilter)
	out := make([]qlog.Entry, 0, len(m.requests))
	for _, e := range m.requests {
		if entryMatches(e, needle) {
			out = append(out, e)
		}
	}
	return out
}

// entryMatches reports whether an entry matches the filter: a
// case-insensitive substring of the domain, client IP, upstream ID or
// protocol.
func entryMatches(e qlog.Entry, needle string) bool {
	for _, field := range []string{e.QName, e.ClientIP, e.Upstream, e.Proto} {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

// requestLine formats one journal entry.
func (m *Model) requestLine(e qlog.Entry) string {
	qtype := dns.TypeToString[e.QType]
	if qtype == "" {
		qtype = fmt.Sprintf("%d", e.QType)
	}

	result := dns.RcodeToString[e.Rcode]
	if result == "" {
		result = fmt.Sprintf("rcode %d", e.Rcode)
	}

	origin := ""
	switch {
	case e.Blocked:
		origin = errStyle.Render("БЛОК(" + e.BlockSource + ")")
	case e.CacheHit:
		origin = okStyle.Render("кеш")
	default:
		origin = e.Upstream
		if origin == "" {
			origin = "—"
		}
	}

	client := e.ClientIP
	if client == "" {
		client = "—"
	}

	return fmt.Sprintf("%s  %-*s  %-*s  %-*s %-*s %-*s %-*s %*.1f",
		e.Time.Format(time.TimeOnly),
		colProto, e.Proto,
		colClient, truncate(client, colClient),
		colDomain, truncate(e.QName, colDomain),
		colType, qtype,
		colResult, result,
		colOrigin, truncate(origin, colOrigin),
		colMS, e.LatencyMS,
	)
}

// upstreamsView renders the detailed upstream table.
func (m *Model) upstreamsView() string {
	if len(m.status.Upstreams) == 0 {
		return dimStyle.Render("Данные об upstream'ах появятся после подключения к демону.") + "\n"
	}

	var b strings.Builder
	b.WriteString(dimStyle.Render("id           имя                   прот   адрес                  задержка    состояние  отправлено/ошибки"))
	b.WriteString("\n")

	for _, u := range m.status.Upstreams {
		sent := fmt.Sprintf("%d/%d", u.Sent, u.Failed)
		b.WriteString(fmt.Sprintf("%-12s %-21s %-6s %-22s %-11s %-10s %s\n",
			truncate(u.ID, 12),
			truncate(u.Name, 21),
			u.Transport,
			truncate(u.Address, 22),
			formatLatency(u.LatencyMS),
			healthLabel(u),
			sent,
		))
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Стратегия: " + m.status.Strategy))
	b.WriteString("\n")
	return b.String()
}

// truncate shortens s to at most n runes, adding an ellipsis.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 1 {
		return string(runes[:n])
	}
	return string(runes[:n-1]) + "…"
}
