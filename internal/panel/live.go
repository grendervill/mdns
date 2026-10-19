// Live screen: the newest requests as a table plus a Server-Sent Events
// stream. The page carries a server-rendered snapshot, so it is useful
// with scripting off, and live.js only prepends the streamed rows. The
// ring is separate from the status feed: it is larger (100 entries) and
// its rows are richer, but it shares the status feed's bus subscription.
package panel

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/qlog"
)

// liveFeedSize bounds the live screen's ring. The table shows the newest
// 100 requests, newest first; the same bound is enforced in live.js.
const liveFeedSize = 100

// liveView is the whole live page.
type liveView struct {
	Domain string
	CSRF   string
	Nav    string // the rail entry to mark active ("live")
	Rows   []liveRowView
}

// liveRowView is one row of the live table. Unlike the compact status
// feed it spells out every column the screen promises: the client, the
// record type, the source and the response code.
type liveRowView struct {
	Time    string // HH:MM:SS in the configured zone
	Client  string
	Proto   string
	Name    string
	Type    string
	Tag     string // ok | cache | block | err
	TagText string
	Source  string
	Latency string
	Rcode   string
}

// liveRowViewFor renders one query record. The outcome classification is
// the history screen's (historyOutcomeOf), so the two views cannot
// disagree about what a row is; only the presentation is wider here.
func liveRowViewFor(e qlog.Entry, loc *time.Location) liveRowView {
	v := liveRowView{
		Time:    e.Time.In(loc).Format("15:04:05"),
		Client:  e.ClientIP,
		Proto:   e.Proto,
		Name:    e.QName,
		Type:    qtypeName(e.QType),
		Latency: liveLatency(e),
		Rcode:   rcodeName(e.Rcode),
	}

	switch historyOutcomeOf(e) {
	case "blocked":
		v.Tag, v.TagText = "block", "блок"
	case "cached":
		v.Tag, v.TagText = "cache", "кеш"
	case "upstream":
		v.Tag, v.TagText = "ok", "ok"
	default:
		v.Tag, v.TagText = "err", "ошибка"
	}

	// historySource is empty for a cache hit; the table still needs a
	// glyph in that cell.
	v.Source = historySource(e)
	if v.Source == "" {
		v.Source = "—"
	}
	return v
}

// liveLatency is the latency cell. A blocked query never reached an
// upstream, so it reports zero the way the compact feed does; a missing
// measurement stays an em dash.
func liveLatency(e qlog.Entry) string {
	switch {
	case e.Blocked:
		return "0 мс"
	case e.LatencyMS > 0:
		return formatMS(e.LatencyMS)
	default:
		return "—"
	}
}

// qtypeName spells out a record type, falling back to the RFC 3597
// spelling for a type the DNS library does not know.
func qtypeName(qtype uint16) string {
	if name := dns.TypeToString[qtype]; name != "" {
		return name
	}
	return "TYPE" + strconv.Itoa(int(qtype))
}

// rcodeName spells out a response code, falling back to its number.
func rcodeName(rcode int) string {
	if name := dns.RcodeToString[rcode]; name != "" {
		return name
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// liveRows renders the ring's rows, newest first.
func (p *Panel) liveRows() []liveRowView {
	entries := p.live.snapshot()
	rows := make([]liveRowView, len(entries))
	loc := p.location()
	for i, e := range entries {
		rows[i] = liveRowViewFor(e, loc)
	}
	return rows
}

// handleLive renders the server-side snapshot of the live ring.
func (p *Panel) handleLive(w http.ResponseWriter, r *http.Request) {
	view := liveView{
		CSRF: p.csrfToken(sessionCSRFBinding(p.sessionToken(r))),
		Nav:  "live",
	}
	if p.ctrl != nil {
		if cfg := p.ctrl.Config(); cfg != nil {
			view.Domain = cfg.Domain
		}
	}
	view.Rows = p.liveRows()

	p.render(w, http.StatusOK, "live", view)
}

// handleLiveEvents streams the live ring: one snapshot frame with the
// current <tr> fragments, then one row frame per new query. It shares
// the status stream's headers, write-deadline handling and ping cadence.
func (p *Panel) handleLiveEvents(w http.ResponseWriter, r *http.Request) {
	p.stream(w, r, p.liveHTML, p.liveRowHTML)
}

// liveHTML renders the whole ring as table rows.
func (p *Panel) liveHTML() string {
	return p.renderLiveRows(p.liveRows())
}

// liveRowHTML renders one query as a table row.
func (p *Panel) liveRowHTML(e qlog.Entry) string {
	return p.renderLiveRows([]liveRowView{liveRowViewFor(e, p.location())})
}

// renderLiveRows executes the live_row fragment for each row. A
// rendering error drops the row rather than the stream; the templates
// are fixed, so this is a "cannot happen" guard, not a code path.
func (p *Panel) renderLiveRows(rows []liveRowView) string {
	var buf strings.Builder
	for _, row := range rows {
		if err := templates["live"].ExecuteTemplate(&buf, "live_row", row); err != nil {
			p.logger.Warn("panel: rendering a live row", "error", err)
		}
	}
	return buf.String()
}
