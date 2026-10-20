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

// requestsView renders the live query journal newest first: the newest
// entry sits directly under the header, and scrolling up (k) skips
// entries from the newest end.
func (m *Model) requestsView() string {
	var b strings.Builder

	shown := m.filteredRequests()

	var note strings.Builder
	if m.requestsPaused {
		note.WriteString(warnStyle.Render("Лента на паузе (пробел — продолжить)") + "\n")
	}
	if m.requestsFilter != "" {
		note.WriteString(dimStyle.Render(fmt.Sprintf("Фильтр: «%s» · найдено %d из %d · f — изменить · esc — сбросить", m.requestsFilter, len(shown), len(m.requests))))
		note.WriteString("\n")
	}
	if m.requestsPaused || m.requestsFilter != "" {
		note.WriteString("\n")
	}

	if len(m.requests) == 0 {
		b.WriteString(note.String())
		b.WriteString(dimStyle.Render("Запросов пока нет.") + "\n")
		m.writeRequestsInput(&b)
		return b.String()
	}
	if len(shown) == 0 {
		b.WriteString(note.String())
		b.WriteString(dimStyle.Render(fmt.Sprintf("Нет запросов по фильтру «%s» (esc — сбросить).", m.requestsFilter)) + "\n")
		m.writeRequestsInput(&b)
		return b.String()
	}

	b.WriteString(note.String())

	// Reserve the lines that stay pinned above and below the rows: the
	// column header, the scroll note and the filter prompt. The rows use
	// whatever the body has left, so the shell never clips the newest
	// entries (and with them the header) off the top.
	fixed := len(contentLines(note.String())) + 1
	if m.inputActive && m.inputMode == inputRequestsFilter {
		fixed += 2
	}
	limit := len(shown)
	if height := m.contentHeight(); height > 0 {
		limit = height - fixed
		if m.requestsScroll > 0 && limit > 1 {
			limit-- // the scroll note takes one row
		}
		if limit < 0 {
			limit = 0
		}
		if limit > len(shown) {
			limit = len(shown)
		}
	}

	b.WriteString(dimStyle.Render(m.requestsHeader()))
	b.WriteString("\n")

	// Newest first: index len-1 is the newest entry and requestsScroll
	// counts how many of the newest rows the reader has scrolled past.
	for i := 0; i < limit; i++ {
		idx := len(shown) - 1 - m.requestsScroll - i
		if idx < 0 {
			break
		}
		b.WriteString(m.requestLine(shown[idx]))
		b.WriteString("\n")
	}

	if m.requestsScroll > 0 && limit > 0 {
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

// Column widths of the journal table. The client, domain and source
// columns share the rest of the content pane, so the whole row always
// fits the pane width: at 120 columns one entry is exactly one line.
const (
	colTime   = 8
	colProto  = 5
	colType   = 5
	colResult = 9
	colMS     = 7
	// requestsSeparators is the fixed cost of the gaps between the eight
	// columns: 2+2+2+1+1+1+1 cells.
	requestsSeparators = 10
)

// requestsColumnWidths splits the content width between the three
// variable columns; the fixed columns and the gaps are charged first.
func requestsColumnWidths(content int) (client, domain, source int) {
	rest := content - (colTime + colProto + colType + colResult + colMS + requestsSeparators)
	if rest < 3 {
		rest = 3
	}
	client = rest * 30 / 100
	domain = rest * 42 / 100
	source = rest - client - domain
	if client < 1 {
		client = 1
	}
	if domain < 1 {
		domain = 1
	}
	if source < 1 {
		source = 1
	}
	return client, domain, source
}

// requestsHeader renders the column captions for the current width.
func (m *Model) requestsHeader() string {
	client, domain, source := requestsColumnWidths(m.pickerContentWidth())
	return cell("время", colTime, false) + "  " +
		cell("прото", colProto, false) + "  " +
		cell("клиент", client, false) + "  " +
		cell("домен", domain, false) + " " +
		cell("тип", colType, false) + " " +
		cell("результат", colResult, false) + " " +
		cell("источник", source, false) + " " +
		cell("мс", colMS, true)
}

// cell pads text to exactly width display cells, optionally right
// aligned. Wide runes are measured in cells, never in runes.
func cell(text string, width int, right bool) string {
	text = truncate(text, width)
	if right {
		if pad := width - displayWidth(text); pad > 0 {
			return strings.Repeat(" ", pad) + text
		}
		return text
	}
	return padCells(text, width)
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

// requestLine formats one journal entry into a single row that fits the
// content pane.
func (m *Model) requestLine(e qlog.Entry) string {
	qtype := dns.TypeToString[e.QType]
	if qtype == "" {
		qtype = fmt.Sprintf("%d", e.QType)
	}

	result := dns.RcodeToString[e.Rcode]
	if result == "" {
		result = fmt.Sprintf("rcode %d", e.Rcode)
	}

	origin, originText := "", ""
	switch {
	case e.Blocked:
		origin, originText = "БЛОК("+e.BlockSource+")", errStyle.Render("БЛОК("+e.BlockSource+")")
	case e.CacheHit:
		origin, originText = "кеш", okStyle.Render("кеш")
	default:
		origin = e.Upstream
		if origin == "" {
			origin = "—"
		}
		originText = origin
	}

	client := e.ClientIP
	if client == "" {
		client = "—"
	}

	clientWidth, domainWidth, originWidth := requestsColumnWidths(m.pickerContentWidth())
	return cell(e.Time.Format(time.TimeOnly), colTime, false) + "  " +
		cell(e.Proto, colProto, false) + "  " +
		cell(client, clientWidth, false) + "  " +
		cell(e.QName, domainWidth, false) + " " +
		cell(qtype, colType, false) + " " +
		cell(result, colResult, false) + " " +
		trimCell(originText, origin, originWidth) + " " +
		cell(fmt.Sprintf("%.1f", e.LatencyMS), colMS, true)
}

// trimCell truncates the plain form for the width budget and returns the
// matching styled form, padded to the same width.
func trimCell(styled, plain string, width int) string {
	if displayWidth(plain) <= width {
		return curatedStyle(styled, plain, width)
	}
	trimmed := truncate(plain, width)
	if trimmed == plain {
		return curatedStyle(styled, plain, width)
	}
	// A truncated styled value drops its styling: the escaped string
	// cannot be sliced safely, and the plain prefix is unambiguous.
	return padCells(trimmed, width)
}

// curatedStyle pads a styled string to the column width, using the plain
// text only for the cell count.
func curatedStyle(styled, plain string, width int) string {
	if pad := width - displayWidth(plain); pad > 0 {
		return styled + strings.Repeat(" ", pad)
	}
	return styled
}
