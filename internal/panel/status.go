// Status screen: the panel's landing page. It renders the gauges, the
// four query-distribution diagrams and the last queries from an
// in-memory rolling buffer, and it serves the live feed's Server-Sent
// Event stream. Everything is server-rendered HTML; the only client
// script positions the chart tooltip and appends streamed rows.
package panel

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/qlog"
	"mydns/internal/stats"
)

const (
	// feedSize is how many queries the live feed keeps. The mockup's
	// "последние 30" is a product decision: enough to watch traffic,
	// little enough that the DOM stays small under load. The bound is
	// enforced on both sides (here and in app.js).
	feedSize = 30

	// maxDonutSegments caps how many slices one diagram draws before the
	// tail is folded into "прочие". The mockup shows four; twenty thin
	// slices would be unreadable and would bury the legend.
	maxDonutSegments = 6

	// otherClientsLabel mirrors stats' overflow row ("остальные", see
	// stats.otherBucket). The panel spells it out because that package
	// keeps the constant unexported.
	otherClientsLabel = "остальные"
)

// feed is the rolling buffer behind the live feed. It keeps the newest
// feedSize entries, newest first, and is shared by every SSE client, so
// a late subscriber still sees the recent traffic. It is safe for
// concurrent use.
type feed struct {
	mu    sync.Mutex
	rows  []qlog.Entry
	limit int
}

// newFeed returns an empty buffer holding at most limit entries.
func newFeed(limit int) *feed {
	if limit < 1 {
		limit = 1
	}
	return &feed{limit: limit}
}

// push prepends one entry, dropping the oldest when the buffer is full.
func (f *feed) push(e qlog.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rows := make([]qlog.Entry, 0, f.limit)
	rows = append(rows, e)
	rows = append(rows, f.rows...)
	if len(rows) > f.limit {
		rows = rows[:f.limit]
	}
	f.rows = rows
}

// seed fills an empty buffer from the daemon's query log. entries are
// oldest first (qlog.Log.Recent); the buffer keeps them newest first.
// It is a no-op once live events have arrived, so a live push never
// loses to the backfill.
func (f *feed) seed(entries []qlog.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.rows) > 0 {
		return
	}
	rows := make([]qlog.Entry, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		rows = append(rows, entries[i])
	}
	if len(rows) > f.limit {
		rows = rows[:f.limit]
	}
	f.rows = rows
}

// snapshot returns a copy of the buffer, newest first.
func (f *feed) snapshot() []qlog.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]qlog.Entry, len(f.rows))
	copy(out, f.rows)
	return out
}

// share is one candidate slice of a diagram: a label, a count, the
// history filter it links to (empty for a slice that must not link) and
// the palette slot it draws with.
type share struct {
	Label string
	Value uint64
	Href  string
	Slot  int
}

// arc is the geometry of one slice. Dash and Gap are the two numbers of
// the stroke-dasharray (pct and 100-pct); Offset places the slice's
// start so the first one begins at the top of the ring.
type arc struct {
	Offset float64
	Dash   float64
	Gap    float64
}

// donut turns counts into ring geometry with the mockup's convention:
// dasharray = "pct 100-pct" and dashoffset = 25 - cumulative start
// percent, so the first slice begins at the top of the ring. Every
// slice rounds to one decimal on its own; the drawn sum can therefore
// drift from 100 by a fraction of a percent, which shows as a sub-pixel
// seam rather than a wrong figure. Compensating the drift in one slice
// would make that slice quietly lie about its size instead.
func donut(shares []share) []arc {
	var total uint64
	for _, s := range shares {
		total += s.Value
	}

	arcs := make([]arc, len(shares))
	if total == 0 {
		// No queries yet: every slice is empty and the ring shows only
		// its track.
		for i := range arcs {
			arcs[i] = arc{Offset: 25, Dash: 0, Gap: 100}
		}
		return arcs
	}

	cumulative := 0.0
	for i, s := range shares {
		pct := round1(float64(s.Value) / float64(total) * 100)
		arcs[i] = arc{
			Offset: round1(25 - cumulative),
			Dash:   pct,
			Gap:    round1(100 - pct),
		}
		cumulative = round1(cumulative + pct)
	}
	return arcs
}

// round1 rounds to one decimal, the precision the diagram prints.
func round1(v float64) float64 { return math.Round(v*10) / 10 }

// segmentView is one rendered slice: the arc geometry plus what the
// hover label and the link need.
type segmentView struct {
	Label     string
	ValueText string
	Percent   string
	Href      string
	Slot      int
	Dash      float64
	Gap       float64
	Offset    float64
}

// donutView is one rendered diagram.
type donutView struct {
	Title    string
	Segments []segmentView
}

// buildDonut zips shares with their geometry, folding everything past
// maxDonutSegments into one "прочие" slice.
func buildDonut(title string, shares []share) donutView {
	if len(shares) > maxDonutSegments {
		var rest uint64
		for _, s := range shares[maxDonutSegments-1:] {
			rest += s.Value
		}
		folded := make([]share, 0, maxDonutSegments)
		folded = append(folded, shares[:maxDonutSegments-1]...)
		folded = append(folded, share{Label: "прочие", Value: rest, Slot: 3})
		shares = folded
	}

	var total uint64
	for _, s := range shares {
		total += s.Value
	}

	arcs := donut(shares)
	view := donutView{Title: title, Segments: make([]segmentView, len(shares))}
	for i, s := range shares {
		var pct float64
		if total > 0 {
			pct = round1(float64(s.Value) / float64(total) * 100)
		}
		view.Segments[i] = segmentView{
			Label:     s.Label,
			Percent:   formatPercent(pct),
			ValueText: formatPercent(pct) + " % · " + formatCount(s.Value),
			Href:      s.Href,
			Slot:      s.Slot,
			Dash:      arcs[i].Dash,
			Gap:       arcs[i].Gap,
			Offset:    arcs[i].Offset,
		}
	}
	return view
}

// outcomeShares builds the "Ответы" diagram in the mockup's order
// (cached, upstream, blocked, error) so its palette slots match the
// approved colours (copper, green, red, yellow).
func outcomeShares(sn stats.Snapshot) []share {
	ordered := []struct {
		key   string
		label string
		slot  int
	}{
		{"cached", "кеш", 0},
		{"upstream", "ответ upstream", 1},
		{"blocked", "заблокировано", 5},
		{"error", "ошибки", 2},
	}
	shares := make([]share, 0, len(ordered))
	for _, o := range ordered {
		shares = append(shares, share{
			Label: o.label,
			Value: sn.Outcomes[o.key],
			Href:  historyHref("outcome", o.key),
			Slot:  o.slot,
		})
	}
	return shares
}

// protoShares builds the "Протоколы" diagram, busiest first.
func protoShares(sn stats.Snapshot) []share {
	keys := sortedKeys(sn.Protos)
	shares := make([]share, 0, len(keys))
	for i, proto := range keys {
		shares = append(shares, share{
			Label: protoLabel(proto),
			Value: sn.Protos[proto],
			Href:  historyHref("proto", proto),
			Slot:  i,
		})
	}
	return shares
}

// upstreamShares builds the "Кто ответил" diagram, busiest first. The
// status snapshot supplies display names; a missing name falls back to
// the upstream ID.
func upstreamShares(sn stats.Snapshot, st api.Status) []share {
	names := make(map[string]string, len(st.Upstreams))
	for _, u := range st.Upstreams {
		if u.Name != "" {
			names[u.ID] = u.Name
		}
	}

	keys := sortedKeys(sn.Upstreams)
	shares := make([]share, 0, len(keys))
	for i, id := range keys {
		label := id
		if name, ok := names[id]; ok {
			label = name
		}
		shares = append(shares, share{
			Label: label,
			Value: sn.Upstreams[id],
			Href:  historyHref("upstream", id),
			Slot:  i,
		})
	}
	return shares
}

// clientShares builds the "Клиенты" diagram. The stats snapshot is
// already ordered (busiest first, the overflow row last), so the order
// is preserved; only the overflow row has no history filter to link to
// (an exact client IP is what the history accepts).
func clientShares(sn stats.Snapshot) []share {
	shares := make([]share, 0, len(sn.Clients))
	for i, c := range sn.Clients {
		href := historyHref("client", c.IP)
		if c.IP == otherClientsLabel {
			href = ""
		}
		shares = append(shares, share{Label: c.IP, Value: c.Count, Href: href, Slot: i})
	}
	return shares
}

// sortedKeys returns the keys of a count map, busiest first, ties by
// name, so a diagram does not reshuffle between two equal values.
func sortedKeys(counts map[string]uint64) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// historyHref builds a link into the history page with one filter set.
// The page parses the same parameter names qlog's Query uses (Task 8).
func historyHref(param, value string) string {
	return historyPath + "?" + url.Values{param: {value}}.Encode()
}

// protoLabel spells out the transports the way the mockup's legend
// does; every other name is already readable.
func protoLabel(proto string) string {
	switch proto {
	case "udp", "tcp":
		return proto + " (обычный)"
	default:
		return proto
	}
}

// rowView is one live-feed row.
type rowView struct {
	Time    string
	QName   string
	Title   string // qname plus the record type, for the hover title
	Proto   string
	Tag     string // ok | cache | block | err
	TagText string
	Detail  string // latency and source, or "—"
}

// rowViewFor renders one query record the way the mockup's feed does:
// the tag carries the outcome and the last cell the latency and the
// source (upstream ID, block-list name, or nothing for a cache hit).
// The history page renders the same row through this helper, so the
// two screens can never drift apart. The time is shown in loc, which the
// panel loads from its live config; the entry itself is untouched.
func rowViewFor(e qlog.Entry, loc *time.Location) rowView {
	rv := rowView{
		Time:  e.Time.In(loc).Format("15:04:05"),
		QName: e.QName,
		Proto: e.Proto,
		Title: queryTitle(e),
	}

	latency := "—"
	if e.LatencyMS > 0 {
		latency = formatMS(e.LatencyMS)
	}

	switch {
	case e.Blocked:
		rv.Tag, rv.TagText = "block", "блок"
		if e.BlockSource != "" {
			rv.Detail = "0 мс · " + e.BlockSource
		} else {
			rv.Detail = "0 мс"
		}
	case e.CacheHit:
		rv.Tag, rv.TagText, rv.Detail = "cache", "кеш", "—"
	case e.Upstream != "":
		rv.Tag, rv.TagText, rv.Detail = "ok", "ok", latency+" · "+e.Upstream
	default:
		rv.Tag, rv.TagText, rv.Detail = "err", "ошибка", latency
	}
	return rv
}

// queryTitle is the hover title of one query row. The feed and the
// history table have no column for the record type or the response
// code, so both live here: the name, the type, then the rcode.
func queryTitle(e qlog.Entry) string {
	title := strings.TrimSpace(e.QName + " " + dns.TypeToString[e.QType])
	if rc := dns.RcodeToString[e.Rcode]; rc != "" {
		if title != "" {
			title += " · "
		}
		title += rc
	}
	return title
}

// rowsFor renders entries through the shared feed row helper. Both the
// live feed and the history table use it, in the panel's configured zone.
func rowsFor(entries []qlog.Entry, loc *time.Location) []rowView {
	rows := make([]rowView, len(entries))
	for i, e := range entries {
		rows[i] = rowViewFor(e, loc)
	}
	return rows
}

// linkView is one device connection string. URI is a template.URL
// because the daemon builds the addresses (tls://, quic://, a bare
// host:port) — schemes html/template's default filter would reject —
// from the admin's own configuration, which is trusted input here.
type linkView struct {
	Title string
	URI   template.URL
}

// certView is the certificate block. Show is false when the daemon
// reports no certificate information at all.
type certView struct {
	Show   bool
	State  string // ok | waiting | error
	Label  string
	Detail string
}

// statusView is the whole status page.
type statusView struct {
	Domain  string
	Version string
	CSRF    string
	Nav     string // the rail entry to mark active ("status")

	Total          string
	CachePercent   string
	CacheEntries   string
	Blocked        string
	BlockedPercent string
	BestLatency    string
	BestName       string

	// Period selector state. The four gauges above stay all-time; the
	// donuts and the period summary render the selected range.
	PeriodOptions []periodOption
	PeriodFrom    string
	PeriodTo      string
	PeriodLabel   string
	PeriodNotice  string
	PeriodSummary string

	Donuts []donutView
	Feed   []rowView
	Links  []linkView
	Cert   certView
}

// periodOption is one entry of the period selector.
type periodOption struct {
	Value    string
	Label    string
	Selected bool
}

// handleStatus renders the status screen.
func (p *Panel) handleStatus(w http.ResponseWriter, r *http.Request) {
	view := statusView{
		Version: p.version,
		CSRF:    p.csrfToken(sessionCSRFBinding(p.sessionToken(r))),
		Nav:     "status",
	}

	sel := parsePeriod(r, time.Now())

	var (
		st      api.Status
		sn      stats.Snapshot
		rangeSn stats.Snapshot
	)
	if p.ctrl != nil {
		if cfg := p.ctrl.Config(); cfg != nil {
			view.Domain = cfg.Domain
		}
		got, err := p.ctrl.Status(r.Context())
		if err != nil {
			// The page still renders; the gauges show nothing rather
			// than stale numbers.
			p.logger.Warn("panel: reading the daemon status", "error", err)
		} else {
			st = got
		}
		sn = p.ctrl.Stats()
		rangeSn = p.ctrl.StatsRange(sel.From, sel.To)
	}

	fillGauges(&view, st, sn)
	fillDonuts(&view, st, rangeSn)
	fillPeriod(&view, sel, rangeSn)
	fillLinks(&view, st)
	fillCert(&view, st)
	view.Feed = p.feedRows()

	p.render(w, http.StatusOK, "status", view)
}

// defaultPeriod is the period choice shown when the query is missing or
// invalid. Everything that cannot be understood falls back to it.
const defaultPeriod = "30"

// periodOrder fixes the selector order; periodLabels names each choice
// in Russian. The custom choice parses the two date fields instead of a
// fixed length.
var periodOrder = [...]string{"30", "90", "180", "365", "custom"}

var periodLabels = map[string]string{
	"30":     "Месяц",
	"90":     "3 месяца",
	"180":    "6 месяцев",
	"365":    "12 месяцев",
	"custom": "Своё",
}

// periodDays maps the fixed choices to their length in whole calendar
// days, counting today.
var periodDays = map[string]int{
	"30":  30,
	"90":  90,
	"180": 180,
	"365": 365,
}

// periodSelection is a resolved period request: the range the donuts sum
// over, the echo for the date inputs and an optional notice when the
// request was clamped or rejected.
type periodSelection struct {
	Period   string
	From     time.Time
	To       time.Time
	FromText string
	ToText   string
	Label    string
	Notice   string
}

// parsePeriod resolves the period query into a whole-UTC-day range. An
// unknown choice is the default month. A custom range must carry two
// valid dates, must not be reversed and must fit the retention window;
// otherwise it falls back to the month with a short notice. Future
// dates clamp to now.
func parsePeriod(r *http.Request, now time.Time) periodSelection {
	q := r.URL.Query()
	period := q.Get("period")
	if _, ok := periodLabels[period]; !ok {
		period = defaultPeriod
	}

	if period == "custom" {
		from, errFrom := parseDay(q.Get("from"))
		to, errTo := parseDay(q.Get("to"))
		if errFrom != nil || errTo != nil {
			return periodFallback(now, "Укажите обе даты в формате ГГГГ-ММ-ДД")
		}
		if to.After(now) {
			to = now
		}
		if from.After(now) {
			from = now
		}
		if from.After(to) {
			return periodFallback(now, "Начало периода позже конца — показан месяц")
		}
		cutoff := now.AddDate(0, 0, -(stats.HistoryDays - 1))
		if from.Before(cutoff) {
			return periodFallback(now, "Период длиннее 400 дней — показан месяц")
		}
		return periodSelection{
			Period:   "custom",
			From:     from,
			To:       to,
			FromText: from.UTC().Format("2006-01-02"),
			ToText:   to.UTC().Format("2006-01-02"),
			Label:    periodLabels["custom"],
		}
	}

	days := periodDays[period]
	from := now.AddDate(0, 0, -(days - 1))
	return periodSelection{
		Period:   period,
		From:     from,
		To:       now,
		FromText: from.UTC().Format("2006-01-02"),
		ToText:   now.UTC().Format("2006-01-02"),
		Label:    periodLabels[period],
	}
}

// periodFallback builds the default month with a notice.
func periodFallback(now time.Time, notice string) periodSelection {
	days := periodDays[defaultPeriod]
	from := now.AddDate(0, 0, -(days - 1))
	return periodSelection{
		Period:   defaultPeriod,
		From:     from,
		To:       now,
		FromText: from.UTC().Format("2006-01-02"),
		ToText:   now.UTC().Format("2006-01-02"),
		Label:    periodLabels[defaultPeriod],
		Notice:   notice,
	}
}

// parseDay parses one calendar date from the URL, in UTC so the day
// boundaries match the collector's UTC buckets.
func parseDay(raw string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02", raw, time.UTC)
}

// fillPeriod fills the selector state and the period totals line. The
// totals come from the range snapshot, so they always match the donuts.
func fillPeriod(view *statusView, sel periodSelection, sn stats.Snapshot) {
	view.PeriodOptions = make([]periodOption, 0, len(periodOrder))
	for _, v := range periodOrder {
		view.PeriodOptions = append(view.PeriodOptions, periodOption{
			Value:    v,
			Label:    periodLabels[v],
			Selected: v == sel.Period,
		})
	}
	view.PeriodFrom = sel.FromText
	view.PeriodTo = sel.ToText
	view.PeriodLabel = sel.Label
	view.PeriodNotice = sel.Notice
	view.PeriodSummary = "всего " + formatCount(sn.Total) +
		" · кеш " + formatCount(sn.Outcomes["cached"]) +
		" · блок " + formatCount(sn.Outcomes["blocked"]) +
		" · ошибки " + formatCount(sn.Outcomes["error"])
}

// fillGauges fills the four counters above the diagrams.
func fillGauges(view *statusView, st api.Status, sn stats.Snapshot) {
	view.Total = formatCount(sn.Total)

	if pct, ok := cacheHitPercent(st.Cache); ok {
		view.CachePercent = formatPercent(pct) + " %"
	} else {
		view.CachePercent = "—"
	}
	if st.Cache.Size > 0 {
		view.CacheEntries = formatCount(uint64(st.Cache.Size)) + " записей"
	}

	blocked := sn.Outcomes["blocked"]
	view.Blocked = formatCount(blocked)
	if sn.Total > 0 {
		view.BlockedPercent = formatPercent(float64(blocked)/float64(sn.Total)*100) + " %"
	}

	if best, ok := bestUpstream(st.Upstreams); ok {
		view.BestLatency = formatMS(best.LatencyMS)
		view.BestName = best.Name
		if view.BestName == "" {
			view.BestName = best.ID
		}
	} else {
		view.BestLatency = "—"
	}
}

// fillDonuts fills the four diagrams from the period snapshot, so they
// follow the selector while the gauges stay all-time.
func fillDonuts(view *statusView, st api.Status, sn stats.Snapshot) {
	view.Donuts = []donutView{
		buildDonut("Ответы", outcomeShares(sn)),
		buildDonut("Протоколы", protoShares(sn)),
		buildDonut("Кто ответил (upstream’ы)", upstreamShares(sn, st)),
		buildDonut("Клиенты", clientShares(sn)),
	}
}

// fillLinks fills the device-address block.
func fillLinks(view *statusView, st api.Status) {
	links := make([]linkView, 0, len(st.Links))
	for _, l := range st.Links {
		links = append(links, linkView{Title: l.Title, URI: template.URL(l.URI)})
	}
	view.Links = links
}

// fillCert fills the certificate block with the TUI's wording, so both
// interfaces describe one certificate state the same way.
func fillCert(view *statusView, st api.Status) {
	c := st.Cert
	if c.Mode == "" {
		return
	}

	view.Cert.Show = true
	class, label, known := certStateLabel(c.State)
	if !known {
		// An unknown state keeps the old rendering: the state word as
		// the tag class and the mode as the label.
		view.Cert.State = c.State
		view.Cert.Label = c.Mode
		return
	}
	view.Cert.State, view.Cert.Label = class, label

	name := c.Issuer
	if name == "" {
		name = c.Mode
	}
	switch c.State {
	case "ok":
		view.Cert.Detail = name + " · истекает " + c.NotAfter.Format("02.01.2006")
	case "waiting":
		view.Cert.Detail = "ожидание выпуска…"
	case "error":
		view.Cert.Detail = "ошибка — " + c.Error
	}
}

// certStateLabel maps a certificate state to the tag class and the
// Russian word both the status page and the certificate page show, so
// the two screens cannot describe one state differently.
func certStateLabel(state string) (class, label string, known bool) {
	switch state {
	case "ok":
		return "ok", "Действует", true
	case "waiting":
		return "waiting", "Ожидает", true
	case "error":
		return "error", "Ошибка", true
	default:
		return state, state, false
	}
}

// feedRows renders the buffer's rows, newest first.
func (p *Panel) feedRows() []rowView {
	return rowsFor(p.feed.snapshot(), p.location())
}

// handleEvents streams the live feed as Server-Sent Events, behind the
// session cookie (never a URL token). It sends an immediate ping so a
// client can tell "connected" from "waiting", then a snapshot frame
// with the buffer's current rows, then one row frame per new query.
func (p *Panel) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// The DoH listener sets a 10s write timeout for its hardening, but a
	// stream outlives it. Clear the per-connection write deadline for
	// this request so the pings keep flowing; the request context still
	// ends the loop when the client goes away.
	clearWriteDeadline(w)

	w.WriteHeader(http.StatusOK)

	if !writeSSE(w, flusher, "ping", "{}") {
		return
	}
	if !writeSSE(w, flusher, "snapshot", p.feedHTML()) {
		return
	}

	var events <-chan api.Event
	if p.bus != nil {
		ch, cancel := p.bus.Subscribe()
		defer cancel()
		events = ch
	}

	ticker := time.NewTicker(p.pingInterval)
	defer ticker.Stop()

	// EndStreams closes this when the runtime behind the panel stops;
	// Shutdown does not cancel r.Context(), so without it the handler
	// would block the stop until its timeout.
	done := p.streamDone()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			if e.Type != "requests" {
				continue
			}
			entry, ok := e.Data.(qlog.Entry)
			if !ok {
				continue
			}
			if !writeSSE(w, flusher, "row", p.rowHTML(entry)) {
				return
			}
		case <-ticker.C:
			if !writeSSE(w, flusher, "ping", "{}") {
				return
			}
		}
	}
}

// writeSSE writes one event frame; it reports false when the client is
// gone. The payload is one HTML fragment with no newline (the row
// templates are single-line), so it never needs splitting across data
// lines; a stray newline would end the frame early, so it is folded to
// a space defensively.
func writeSSE(w http.ResponseWriter, flusher http.Flusher, event, payload string) bool {
	payload = strings.NewReplacer("\n", " ", "\r", " ").Replace(payload)
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// feedHTML renders the whole buffer as feed rows.
func (p *Panel) feedHTML() string {
	return p.renderRows(p.feedRows())
}

// rowHTML renders one query as a feed row.
func (p *Panel) rowHTML(e qlog.Entry) string {
	return p.renderRows([]rowView{rowViewFor(e, p.location())})
}

// renderRows executes the feed_row fragment for each row. A rendering
// error drops the row rather than the stream; the templates are fixed,
// so this is a "cannot happen" guard, not a code path.
func (p *Panel) renderRows(rows []rowView) string {
	var buf bytes.Buffer
	for _, row := range rows {
		if err := templates["status"].ExecuteTemplate(&buf, "feed_row", row); err != nil {
			p.logger.Warn("panel: rendering a feed row", "error", err)
		}
	}
	return buf.String()
}

// cacheHitPercent is the share of cacheable lookups that hit, or false
// when nothing looked the cache up yet (the gauge then shows "—" rather
// than a misleading 0 %).
func cacheHitPercent(c cache.Stats) (float64, bool) {
	lookups := c.Hits + c.Misses
	if lookups == 0 {
		return 0, false
	}
	return float64(c.Hits) / float64(lookups) * 100, true
}

// bestUpstream is the fastest upstream the daemon currently reports as
// healthy, which is the one the router is expected to prefer.
func bestUpstream(upstreams []api.UpstreamStatus) (api.UpstreamStatus, bool) {
	var (
		best  api.UpstreamStatus
		found bool
	)
	for _, u := range upstreams {
		if !u.Healthy {
			continue
		}
		if !found || u.LatencyMS < best.LatencyMS {
			best, found = u, true
		}
	}
	return best, found
}

// formatCount groups a count with spaces, the way the mockup writes
// "184 921".
func formatCount(n uint64) string {
	digits := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, d := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(d)
	}
	return b.String()
}

// formatPercent prints a percentage the mockup's way: a comma decimal
// separator and no trailing ",0" ("74", "6,7", "96,4").
func formatPercent(p float64) string {
	return strings.ReplaceAll(strconv.FormatFloat(round1(p), 'f', -1, 64), ".", ",")
}

// formatMS prints a latency rounded to whole milliseconds.
func formatMS(ms float64) string {
	return strconv.FormatFloat(math.Round(ms), 'f', -1, 64) + " мс"
}
