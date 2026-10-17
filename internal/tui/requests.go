package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/qlog"
)

// requestsCap is the requests screen buffer size.
const requestsCap = 500

// requestsView renders the live query journal.
func (m *Model) requestsView() string {
	var b strings.Builder

	if m.requestsPaused {
		b.WriteString(warnStyle.Render("Лента на паузе (пробел — продолжить)") + "\n\n")
	}

	if len(m.requests) == 0 {
		b.WriteString(dimStyle.Render("Запросов пока нет.") + "\n")
		return b.String()
	}

	b.WriteString(dimStyle.Render("время     прото  домен                              тип   результат        источник             мс"))
	b.WriteString("\n")

	// Show the last lines that fit; scroll counts lines up from the
	// newest entry.
	limit := len(m.requests)
	if m.height > 4 && limit > m.height-4 {
		limit = m.height - 4
	}
	end := len(m.requests) - m.requestsScroll
	if end < 0 {
		end = 0
	}
	start := end - limit
	if start < 0 {
		start = 0
	}

	for _, e := range m.requests[start:end] {
		b.WriteString(m.requestLine(e))
		b.WriteString("\n")
	}

	if m.requestsScroll > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("… прокрутка вверх на %d строк (↓ — вниз)", m.requestsScroll)))
		b.WriteString("\n")
	}
	return b.String()
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

	return fmt.Sprintf("%s  %-5s  %-34s %-5s %-17s %-20s %6.1f",
		e.Time.Format(time.TimeOnly),
		e.Proto,
		truncate(e.QName, 34),
		qtype,
		result,
		truncate(origin, 20),
		e.LatencyMS,
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
