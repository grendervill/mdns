// History screen: the filtered, paged view of the daemon's in-memory
// query ring. It is deliberately not live — no SSE, no auto-refresh —
// so every filter, page and search is a plain full-page navigation and
// the page works with scripting off. The CSV export streams exactly the
// same filter over every matching row, not just the visible page.
package panel

import (
	"bufio"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"mydns/internal/qlog"
)

const (
	// historyPath and historyCSVPath are the two views of the same
	// filtered history: the HTML page and its export.
	historyPath    = "/panel/history"
	historyCSVPath = "/panel/history.csv"

	// historyPerPage is the page size of the history screen. The mockup
	// reads "по 100 на страницу", so it is a constant and never a URL
	// parameter: a caller cannot ask for a different page size.
	historyPerPage = 100

	// csvPageSize is the page size the export walks the ring with. It is
	// qlog's own page maximum (500), so a whole export costs as few
	// round trips as the query log allows.
	csvPageSize = 500

	// csvMaxRows bounds one export. The live ring is the real cap; this
	// only stops a controller that never reports it has run out.
	csvMaxRows = 1_000_000
)

// historyCSVHeader is the export's first row, in the table's column
// order. The delimiter is ';' because the file is Russian and Excel's
// Russian locale splits on semicolons.
var historyCSVHeader = []string{"время", "протокол", "домен", "тип", "результат", "источник", "клиент", "мс"}

// historyParams is the filter state parsed from a history URL. Search
// is the free-text box; the four named filters are exact matches.
type historyParams struct {
	Search   string
	Outcome  string
	Proto    string
	Client   string
	Upstream string
	Page     int
}

// parseHistory reads the filter parameters of a history request. An
// unknown outcome is dropped (the API's ?outcome= behaves the same), a
// missing or malformed page is 1. Nothing is rejected: the screen only
// reads.
func parseHistory(r *http.Request) historyParams {
	v := r.URL.Query()
	return historyParams{
		Search:   v.Get("q"),
		Outcome:  historyOutcome(v.Get("outcome")),
		Proto:    v.Get("proto"),
		Client:   v.Get("client"),
		Upstream: v.Get("upstream"),
		Page:     positiveAtoi(v.Get("page"), 1),
	}
}

// historyOutcome validates an outcome name. An unknown value means "no
// filter" rather than an empty page, so a stale link never lies.
func historyOutcome(raw string) string {
	switch raw {
	case "cached", "blocked", "upstream", "error":
		return raw
	default:
		return ""
	}
}

// positiveAtoi parses a 1-based number, falling back to def.
func positiveAtoi(raw string, def int) int {
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return def
	}
	return v
}

// query turns the parsed filters into the qlog query the controller
// consumes.
func (p historyParams) query() qlog.Query {
	return qlog.Query{
		Search:   p.Search,
		Outcome:  p.Outcome,
		Proto:    p.Proto,
		Client:   p.Client,
		Upstream: p.Upstream,
	}
}

// values returns the URL parameters of a link. Empty filters are
// dropped and page 1 is the canonical absence of a page, so every link
// has exactly one spelling.
func (p historyParams) values() url.Values {
	v := url.Values{}
	if p.Search != "" {
		v.Set("q", p.Search)
	}
	if p.Outcome != "" {
		v.Set("outcome", p.Outcome)
	}
	if p.Proto != "" {
		v.Set("proto", p.Proto)
	}
	if p.Client != "" {
		v.Set("client", p.Client)
	}
	if p.Upstream != "" {
		v.Set("upstream", p.Upstream)
	}
	if p.Page > 1 {
		v.Set("page", strconv.Itoa(p.Page))
	}
	return v
}

// href builds a link to path carrying exactly this filter state.
func (p historyParams) href(path string) string {
	if enc := p.values().Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

// historyChip is one active filter as a removable chip: its label, the
// query parameter it stands for, and the link that removes exactly that
// one filter and keeps the rest (back on page 1).
type historyChip struct {
	Param  string
	Value  string
	Label  string
	Remove string
}

// chips lists the active filters in the mockup's order: outcome,
// protocol, client, upstream.
func (p historyParams) chips() []historyChip {
	chips := make([]historyChip, 0, 4)
	add := func(param, value, label string) {
		if value == "" {
			return
		}
		gone := p
		switch param {
		case "outcome":
			gone.Outcome = ""
		case "proto":
			gone.Proto = ""
		case "client":
			gone.Client = ""
		case "upstream":
			gone.Upstream = ""
		}
		gone.Page = 1
		chips = append(chips, historyChip{
			Param:  param,
			Value:  value,
			Label:  label,
			Remove: gone.href(historyPath),
		})
	}
	// The chip values are the raw filter values, so the remove link
	// round-trips the URL exactly; only the label is prose.
	add("outcome", p.Outcome, historyOutcomeLabel(p.Outcome))
	add("proto", p.Proto, protoLabel(p.Proto))
	add("client", p.Client, p.Client)
	add("upstream", p.Upstream, p.Upstream)
	return chips
}

// historyOutcomeLabel is the Russian word for an outcome. It is shared
// by the chip and by the export's "результат" column, so the page and
// the file name the same states the same way.
func historyOutcomeLabel(outcome string) string {
	switch outcome {
	case "cached":
		return "кеш"
	case "blocked":
		return "заблокировано"
	case "upstream":
		return "ответ upstream"
	case "error":
		return "ошибки"
	default:
		return outcome
	}
}

// historyOutcomeOf classifies one entry the way qlog does. The rule is
// duplicated on purpose (see the plan's R7): the panel and qlog are
// separate packages and must not share this small classifier. Order
// matters: blocked beats cache, cache beats upstream, and no source at
// all is an error.
func historyOutcomeOf(e qlog.Entry) string {
	switch {
	case e.Blocked:
		return "blocked"
	case e.CacheHit:
		return "cached"
	case e.Upstream != "":
		return "upstream"
	default:
		return "error"
	}
}

// historyResult is the export's "результат" cell.
func historyResult(e qlog.Entry) string {
	return historyOutcomeLabel(historyOutcomeOf(e))
}

// historySource is the export's "источник" cell: the block list, the
// upstream ID, or empty for a cache hit.
func historySource(e qlog.Entry) string {
	switch {
	case e.Blocked:
		return e.BlockSource
	case e.CacheHit:
		return ""
	default:
		return e.Upstream
	}
}

// historyCSVRecord renders one entry as a CSV row.
func historyCSVRecord(e qlog.Entry) []string {
	qtype := dns.TypeToString[e.QType]
	if qtype == "" {
		qtype = "TYPE" + strconv.Itoa(int(e.QType))
	}
	return []string{
		e.Time.Format("2006-01-02 15:04:05"),
		e.Proto,
		e.QName,
		qtype,
		historyResult(e),
		historySource(e),
		e.ClientIP,
		strconv.FormatFloat(math.Round(e.LatencyMS), 'f', -1, 64),
	}
}

// historyPages is ceil(total/per), at least 1, so an empty result still
// reports a valid first page and the pager never reads "страница 1 из 0".
func historyPages(total, per int) int {
	if per < 1 {
		per = 1
	}
	n := (total + per - 1) / per
	if n < 1 {
		n = 1
	}
	return n
}

// historyView is the whole history page.
type historyView struct {
	Domain string
	CSRF   string
	Nav    string

	// MemoryEntries is the ring's capacity from the daemon config, shown
	// in the topline the way the mockup does ("в памяти: 10 000").
	MemoryEntries string

	Query         string
	Chips         []historyChip
	FilterSummary string
	CSVHref       string

	Rows  []rowView
	Total string
	Page  int
	Pages int
	// PerPage is the fixed page size shown in the pager.
	PerPage int

	// PrevHref and NextHref are empty at the edges, which the template
	// renders as a disabled control.
	PrevHref string
	NextHref string
}

// handleHistory renders the filtered history page.
func (p *Panel) handleHistory(w http.ResponseWriter, r *http.Request) {
	params := parseHistory(r)

	view := historyView{
		CSRF:    p.csrfToken(sessionCSRFBinding(p.sessionToken(r))),
		Nav:     "history",
		Query:   params.Search,
		PerPage: historyPerPage,
	}

	total := 0
	if p.ctrl != nil {
		if cfg := p.ctrl.Config(); cfg != nil {
			view.Domain = cfg.Domain
			if cfg.Log.MemoryEntries > 0 {
				view.MemoryEntries = formatCount(uint64(cfg.Log.MemoryEntries))
			}
		}

		entries, n := p.ctrl.RequestsQuery(params.query(), params.Page, historyPerPage)
		total = n
		pages := historyPages(total, historyPerPage)

		// A page past the end is clamped to the last one and shown as
		// such, rather than rendering an empty table.
		if params.Page > pages {
			params.Page = pages
			entries, _ = p.ctrl.RequestsQuery(params.query(), params.Page, historyPerPage)
		}

		view.Rows = rowsFor(entries)
		view.Page, view.Pages = params.Page, pages
		if params.Page > 1 {
			prev := params
			prev.Page = params.Page - 1
			view.PrevHref = prev.href(historyPath)
		}
		if params.Page < pages {
			next := params
			next.Page = params.Page + 1
			view.NextHref = next.href(historyPath)
		}
	} else {
		view.Page, view.Pages = 1, 1
	}

	view.Total = formatCount(uint64(total))
	view.Chips = params.chips()
	view.FilterSummary = chipSummary(view.Chips)
	view.CSVHref = params.href(historyCSVPath)

	p.render(w, http.StatusOK, "history", view)
}

// handleHistoryCSV streams every row matching the current filter as
// RFC4180 CSV. It walks the ring in csvPageSize pages, so it exports the
// whole match set rather than the current page. A UTF-8 byte-order mark
// leads the file and the fields are separated by ';', so Excel opens the
// Russian text with the right encoding and columns.
func (p *Panel) handleHistoryCSV(w http.ResponseWriter, r *http.Request) {
	// An export can stream for longer than the listener's 10 s write
	// timeout on a slow link; the response must not be cut halfway.
	clearWriteDeadline(w)

	params := parseHistory(r)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="mdns-history.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The export is as private as the page it mirrors.
	w.Header().Set("Cache-Control", "no-store")

	bw := bufio.NewWriter(w)
	// The BOM is written as a Go escape so the source file stays plain
	// UTF-8; Excel uses it to detect the encoding.
	bw.WriteString("\ufeff")
	writeCSVRecord(bw, historyCSVHeader)

	if p.ctrl != nil {
		q := params.query()
		collected := 0
		for page := 1; collected < csvMaxRows; page++ {
			entries, total := p.ctrl.RequestsQuery(q, page, csvPageSize)
			for _, e := range entries {
				writeCSVRecord(bw, historyCSVRecord(e))
			}
			collected += len(entries)
			if len(entries) == 0 || collected >= total {
				break
			}
		}
	}

	_ = bw.Flush()
}

// writeCSVRecord writes one CRLF-terminated record.
func writeCSVRecord(bw *bufio.Writer, fields []string) {
	for i, f := range fields {
		if i > 0 {
			bw.WriteByte(';')
		}
		bw.WriteString(csvField(f))
	}
	bw.WriteString("\r\n")
}

// csvField renders one CSV cell. Every column goes through it, so both
// promises below hold for all of them.
//
// First, spreadsheet formula injection is neutralized: a cell whose text
// begins with '=', '+', '-', '@', a tab or a carriage return is prefix'd
// with a single quote (OWASP's guidance), so Excel, LibreOffice and
// Numbers show it as text instead of evaluating it as a formula. The
// query name is attacker-chosen — any DNS client picks it — so a cell
// like "=cmd|' /C calc'!A0.attacker.example." must never be executable.
//
// Then the field is quoted for RFC4180 when it needs it: the delimiter
// is ';', so a field is quoted when it contains a semicolon, a quote, a
// newline — or a plain comma, which is not strictly required with a
// semicolon delimiter but keeps the file readable by tools that assume
// commas.
func csvField(s string) string {
	if strings.IndexAny(s, "=+-@\t\r") == 0 {
		s = "'" + s
	}
	if strings.ContainsAny(s, ";,\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// chipSummary is the prose the head shows for the active filters.
func chipSummary(chips []historyChip) string {
	labels := make([]string, len(chips))
	for i, c := range chips {
		labels[i] = c.Label
	}
	return strings.Join(labels, ", ")
}
