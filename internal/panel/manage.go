// Management screens: upstreams, filters, settings, certificate and
// maintenance. Every mutation loads the live configuration, edits a
// private copy and hands the whole thing to UpdateConfig, which is
// transactional in the daemon — a rejected change leaves the running
// daemon untouched and the page re-renders the form with the error.
// The pages carry no script: they are plain forms with a redirect after
// a successful POST, the same server-rendered approach as the history
// screen, so the strict CSP holds.
package panel

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"mydns/internal/api"
	"mydns/internal/auth"
	"mydns/internal/config"
	"mydns/internal/dnsname"
	"mydns/internal/filter"
	"mydns/internal/providers"
	"mydns/internal/tlscert"
)

// The management screens are addressed by these paths; every redirect
// after a successful POST returns to the page it came from.
const (
	upstreamsPath   = "/panel/upstreams"
	filtersPath     = "/panel/filters"
	settingsPath    = "/panel/settings"
	maintenancePath = "/panel/maintenance"
)

// filterRefresh is the single-flight state of the block-list update.
// The DoH listener has a 10 s write timeout, while «обновить все» may
// download dozens of lists for up to a minute each, so the POST only
// starts the work and returns; a second POST while it runs is refused
// rather than queued (two concurrent updaters would race on one list).
type filterRefresh struct {
	mu      sync.Mutex
	running bool
}

// start launches fn in the background unless a refresh is already
// running. It reports false when the caller found one in flight. The
// background work uses context.Background(): it must not inherit the
// request context, which the listener cancels after its write deadline.
func (f *filterRefresh) start(fn func()) bool {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return false
	}
	f.running = true
	f.mu.Unlock()

	go func() {
		defer func() {
			f.mu.Lock()
			f.running = false
			f.mu.Unlock()
		}()
		fn()
	}()
	return true
}

// isRunning reports whether a refresh is in flight (tests and pages).
func (f *filterRefresh) isRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

// errNoDaemon is what a management page reports when the panel is
// mounted without a daemon behind it (a test that only exercises the
// shell).
var errNoDaemon = errors.New("панель не подключена к демону")

// manageNotice is the result banner of a management page: an error left
// by a rejected submission, or a short confirmation shown after a
// successful POST redirects back to the page.
type manageNotice struct {
	Error string
	OK    string
}

// okMessage maps the ?ok= key of a redirect to the banner it shows. An
// unknown key shows nothing, so a hand-written URL cannot make the page
// claim a change that never happened.
func okMessage(key string) string {
	switch key {
	case "upstream":
		return "upstream переключён"
	case "upstream-added":
		return "upstream добавлен"
	case "upstream-removed":
		return "upstream удалён"
	case "strategy":
		return "стратегия сохранена"
	case "priority":
		return "порядок сохранён"
	case "lists":
		return "обновление запущено"
	case "list-added":
		return "список добавлен"
	case "list-removed":
		return "список удалён"
	case "mode":
		return "режим применён"
	case "rule":
		return "правило применено"
	case "settings":
		return "применено"
	case "password":
		return "пароль изменён"
	case "reapply":
		return "конфиг применён заново"
	case "backup-created":
		return "резервная копия создана"
	case "backup-restored":
		return "конфигурация восстановлена из копии"
	case "backup-deleted":
		return "резервная копия удалена"
	default:
		return ""
	}
}

// notice reads the confirmation banner of a page request.
func notice(r *http.Request) manageNotice {
	return manageNotice{OK: okMessage(r.URL.Query().Get("ok"))}
}

// cloneConfig copies a configuration deeply enough for a form to edit it
// without touching the live one: every slice the panel can change is
// cloned, and every other field is a value. Config() hands out the
// daemon's live pointer, so mutating it in place would change the daemon
// even when UpdateConfig later rejects the change.
func cloneConfig(cfg *config.Config) *config.Config {
	out := *cfg
	out.Upstreams = append([]config.UpstreamConfig(nil), cfg.Upstreams...)
	out.Limits.TrustedCIDRs = append([]string(nil), cfg.Limits.TrustedCIDRs...)
	out.Filter.Lists = append([]config.FilterList(nil), cfg.Filter.Lists...)
	out.Filter.UserAllow = append([]string(nil), cfg.Filter.UserAllow...)
	out.Filter.UserBlock = append([]string(nil), cfg.Filter.UserBlock...)
	return &out
}

// currentConfig returns the daemon's configuration, or nil when the
// panel has no daemon.
func (p *Panel) currentConfig() *config.Config {
	if p.ctrl == nil {
		return nil
	}
	return p.ctrl.Config()
}

// pageDomain is the domain shown in the rail brand; empty without a
// daemon.
func (p *Panel) pageDomain() string {
	if cfg := p.currentConfig(); cfg != nil {
		return cfg.Domain
	}
	return ""
}

// manageCSRF is the CSRF token for the current session, the value every
// management form carries.
func (p *Panel) manageCSRF(r *http.Request) string {
	return p.csrfToken(sessionCSRFBinding(p.sessionToken(r)))
}

// finishApply hands next to the daemon and either redirects to okHref or
// re-renders the page with the failure. render fills the page with the
// error banner; the caller's form values are already in its closure.
func (p *Panel) finishApply(w http.ResponseWriter, r *http.Request, next *config.Config, okHref string, render func(status int, n manageNotice)) {
	if err := p.applyConfig(r, next); err != nil {
		p.logger.Warn("panel: applying a management change", "error", err)
		render(http.StatusBadRequest, manageNotice{Error: err.Error()})
		return
	}
	http.Redirect(w, r, okHref, http.StatusSeeOther)
}

// applyConfig validates, applies and persists next through the daemon.
func (p *Panel) applyConfig(r *http.Request, next *config.Config) error {
	if p.ctrl == nil {
		return errNoDaemon
	}
	return p.ctrl.UpdateConfig(r.Context(), next)
}

// statusSnapshot reads the daemon status, tolerating a failure: the page
// still renders, its live columns just read «—».
func (p *Panel) statusSnapshot(r *http.Request) api.Status {
	if p.ctrl == nil {
		return api.Status{}
	}
	st, err := p.ctrl.Status(r.Context())
	if err != nil {
		p.logger.Warn("panel: reading the daemon status", "error", err)
		return api.Status{}
	}
	return st
}

// ---- upstreams ----------------------------------------------------

// upstreamRow is one line of the upstreams table: the configured fields
// plus the live state when the daemon reports the upstream.
type upstreamRow struct {
	ID        string
	Name      string
	Transport string
	Address   string
	Priority  int
	Action    string // the flip button's label

	StateClass string
	StateText  string
	Latency    string
	Answered   string
	Errors     string

	// TrustClass and TrustLabel describe the catalog provider this
	// upstream was added from; empty when the ID matches no provider.
	TrustClass string
	TrustLabel string
}

// endpointOption is one reachable provider endpoint in the catalog
// picker. Value is the "providerID|transport" pair the add form posts;
// Label is the human-readable provider, transport and address.
type endpointOption struct {
	Value string
	Label string
}

// trustRow is one line of the provider trust table: the provider name,
// the badge class and label, the note and the cited source.
type trustRow struct {
	Provider   string
	Class      string
	Label      string
	Note       string
	SourceName string
	SourceURL  string
}

// trustTagClass maps a trust level to its badge class, the same classes
// the tables use for health: ok, warn and muted.
func trustTagClass(level string) string {
	switch level {
	case providers.TrustRecommended:
		return "ok"
	case providers.TrustLimited:
		return "warn"
	default:
		return "muted"
	}
}

// providerTrustRows builds the trust table from the provider catalog, in
// the catalog's stable order, one row per provider.
func providerTrustRows() []trustRow {
	list := providers.List()
	out := make([]trustRow, 0, len(list))
	for _, p := range list {
		out = append(out, trustRow{
			Provider:   p.Name,
			Class:      trustTagClass(p.Trust.Level),
			Label:      p.Trust.Label,
			Note:       p.Trust.Note,
			SourceName: p.Trust.SourceName,
			SourceURL:  p.Trust.SourceURL,
		})
	}
	return out
}

// upstreamsView is the whole upstreams page.
type upstreamsView struct {
	manageNotice
	Domain          string
	CSRF            string
	Nav             string
	Strategy        string
	StrategyOptions []strategyOption
	Endpoints       []endpointOption
	Upstreams       []upstreamRow
	TrustProviders  []trustRow

	// Custom-form state, echoed so a rejected or probed submission does
	// not make the operator retype the upstream.
	FormID         string
	FormName       string
	FormTransport  string
	FormAddress    string
	FormServerName string
	FormPriority   string
}

// upstreamForm is the state of the custom-upstream form.
type upstreamForm struct {
	ID         string
	Name       string
	Transport  string
	Address    string
	ServerName string
	Priority   string
}

// upstreamFormFromRequest reads the custom form's fields.
func upstreamFormFromRequest(r *http.Request) upstreamForm {
	return upstreamForm{
		ID:         strings.TrimSpace(r.PostFormValue("id")),
		Name:       strings.TrimSpace(r.PostFormValue("name")),
		Transport:  strings.TrimSpace(r.PostFormValue("transport")),
		Address:    strings.TrimSpace(r.PostFormValue("address")),
		ServerName: strings.TrimSpace(r.PostFormValue("server_name")),
		Priority:   strings.TrimSpace(r.PostFormValue("priority")),
	}
}

// upstreamRowFor renders one upstream: the config supplies the identity
// and the enabled flag, the status the live health and counters.
func upstreamRowFor(u config.UpstreamConfig, live api.UpstreamStatus) upstreamRow {
	row := upstreamRow{
		ID:        u.ID,
		Name:      u.Name,
		Transport: u.Transport,
		Address:   u.Address,
		Priority:  u.Priority,
		Action:    "Включить",
		Latency:   "—",
		Answered:  "—",
		Errors:    "—",
	}
	if row.Name == "" {
		row.Name = u.ID
	}

	switch {
	case !u.Enabled:
		row.StateText = "выключен"
	case live.Healthy:
		row.StateClass, row.StateText = "ok", "здоров"
	default:
		row.StateClass, row.StateText = "err", "сбой"
	}

	if u.Enabled {
		row.Action = "Выключить"
		if live.Healthy && live.LatencyMS > 0 {
			row.Latency = formatMS(live.LatencyMS)
		}
		if total := live.Sent + live.Failed; total > 0 {
			row.Answered = formatPercent(float64(live.Sent)/float64(total)*100) + " %"
			row.Errors = formatPercent(float64(live.Failed)/float64(total)*100) + " %"
		}
	}
	return row
}

// handleUpstreams renders the upstreams screen.
func (p *Panel) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	p.renderUpstreams(w, r, http.StatusOK, notice(r))
}

// renderUpstreams renders the page from the live config and status.
func (p *Panel) renderUpstreams(w http.ResponseWriter, r *http.Request, status int, n manageNotice) {
	p.renderUpstreamsForm(w, r, status, n, upstreamForm{})
}

// renderUpstreamsForm renders the page with an explicit custom-form
// state, so a rejected or probed submission can echo what was typed.
func (p *Panel) renderUpstreamsForm(w http.ResponseWriter, r *http.Request, status int, n manageNotice, form upstreamForm) {
	view := upstreamsView{
		manageNotice:   n,
		Domain:         p.pageDomain(),
		CSRF:           p.manageCSRF(r),
		Nav:            "upstreams",
		Endpoints:      endpointOptions(),
		TrustProviders: providerTrustRows(),
		FormID:         form.ID,
		FormName:       form.Name,
		FormTransport:  form.Transport,
		FormAddress:    form.Address,
		FormServerName: form.ServerName,
		FormPriority:   form.Priority,
	}

	strategy := ""
	cfg := p.currentConfig()
	if cfg != nil {
		strategy = cfg.Strategy
		view.Strategy = strategy
		st := p.statusSnapshot(r)
		live := make(map[string]api.UpstreamStatus, len(st.Upstreams))
		for _, u := range st.Upstreams {
			live[u.ID] = u
		}
		view.Upstreams = make([]upstreamRow, 0, len(cfg.Upstreams))
		for _, u := range cfg.Upstreams {
			row := upstreamRowFor(u, live[u.ID])
			// A configured upstream that came from the catalog carries
			// its provider's trust badge; a hand-written one matches no
			// provider and stays bare.
			if trust, ok := providers.TrustForUpstream(u.ID); ok {
				row.TrustClass = trustTagClass(trust.Level)
				row.TrustLabel = trust.Label
			}
			view.Upstreams = append(view.Upstreams, row)
		}
	}
	view.StrategyOptions = strategyOptions(strategy)

	p.render(w, status, "upstreams", view)
}

// endpointOptions builds the catalog picker from the provider catalog,
// one entry per provider and transport (the first endpoint of each, in
// the catalog's DoH, DoT, DoQ, plain order), so every option value is
// unique and the order is stable.
func endpointOptions() []endpointOption {
	var out []endpointOption
	for _, prov := range providers.List() {
		seen := make(map[string]bool)
		for _, e := range prov.AllEndpoints() {
			if seen[e.Transport] {
				continue
			}
			seen[e.Transport] = true
			out = append(out, endpointOption{
				Value: prov.ID + "|" + e.Transport,
				Label: fmt.Sprintf("%s — %s · %s", prov.Name, transportLabel(e.Transport), e.Address),
			})
		}
	}
	return out
}

// transportLabel is the prose name of an upstream transport.
func transportLabel(transport string) string {
	switch transport {
	case "doh":
		return "DoH"
	case "dot":
		return "DoT"
	case "doq":
		return "DoQ"
	default:
		return "plain"
	}
}

// validStrategy reports whether name is one of the routing strategies
// the config accepts.
func validStrategy(name string) bool {
	for _, s := range strategies {
		if s.value == name {
			return true
		}
	}
	return false
}

// knownTransport reports whether transport is one of the upstream
// transports the config accepts.
func knownTransport(transport string) bool {
	for _, f := range protocolFields {
		if f.field == transport {
			return true
		}
	}
	return false
}

// nextPriority is one past the highest existing priority, so a new
// upstream sorts last under the failover strategy. An empty list yields 0.
func nextPriority(upstreams []config.UpstreamConfig) int {
	highest := -1
	for _, u := range upstreams {
		if u.Priority > highest {
			highest = u.Priority
		}
	}
	return highest + 1
}

// uniqueUpstreamID picks a free ID for a new upstream: the provider ID
// when it is free, then provider-transport, then a numbered suffix.
func uniqueUpstreamID(upstreams []config.UpstreamConfig, providerID, transport string) string {
	taken := make(map[string]bool, len(upstreams))
	for _, u := range upstreams {
		taken[u.ID] = true
	}
	if !taken[providerID] {
		return providerID
	}
	candidate := providerID + "-" + transport
	if !taken[candidate] {
		return candidate
	}
	for i := 2; ; i++ {
		candidate = fmt.Sprintf("%s-%s-%d", providerID, transport, i)
		if !taken[candidate] {
			return candidate
		}
	}
}

// upstreamIDFromAddress derives a slug ID from an upstream address when
// the custom form leaves the ID empty: the URL host for DoH, the host of
// a host:port for the other transports.
func upstreamIDFromAddress(address string) string {
	host := address
	if u, err := url.Parse(address); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	slug := slugID(host)
	if slug == "" {
		slug = "upstream"
	}
	return slug
}

// slugID lowercases s and keeps only [a-z0-9], turning every other run
// of characters into a single dash; leading and trailing dashes go.
func slugID(s string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			if pendingDash && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingDash = false
			b.WriteRune(r)
		default:
			pendingDash = true
		}
	}
	return b.String()
}

// handleUpstreamToggle flips one upstream's enabled flag. The whole
// config travels to UpdateConfig, which is what makes the daemon rebuild
// (or, for a soft change, reapply) atomically.
func (p *Panel) handleUpstreamToggle(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	id := strings.TrimSpace(r.PostFormValue("id"))
	next := cloneConfig(cfg)
	idx := -1
	for i := range next.Upstreams {
		if next.Upstreams[i].ID != id {
			continue
		}
		idx = i
		break
	}
	if idx < 0 {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "upstream не найден: " + id})
		return
	}

	// Disabling the last enabled upstream would leave the daemon with
	// nothing to forward to, exactly like removing it.
	if next.Upstreams[idx].Enabled {
		enabled := 0
		for _, u := range next.Upstreams {
			if u.Enabled {
				enabled++
			}
		}
		if enabled <= 1 {
			p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{
				Error: "нельзя выключить последний включённый upstream — демону будет некуда пересылать запросы",
			})
			return
		}
	}
	next.Upstreams[idx].Enabled = !next.Upstreams[idx].Enabled

	p.finishApply(w, r, next, upstreamsPath+"?ok=upstream", func(status int, n manageNotice) {
		p.renderUpstreams(w, r, status, n)
	})
}

// handleUpstreamPriority saves the whole priority column at once, which
// is the order a failover strategy walks.
func (p *Panel) handleUpstreamPriority(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	next := cloneConfig(cfg)
	for i := range next.Upstreams {
		raw := strings.TrimSpace(r.PostFormValue("prio." + next.Upstreams[i].ID))
		if raw == "" {
			continue // a field the form did not carry keeps its value
		}
		priority, err := strconv.Atoi(raw)
		if err != nil || priority < 0 {
			p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{
				Error: fmt.Sprintf("приоритет для «%s»: ожидается целое число не меньше нуля", next.Upstreams[i].ID),
			})
			return
		}
		next.Upstreams[i].Priority = priority
	}

	p.finishApply(w, r, next, upstreamsPath+"?ok=priority", func(status int, n manageNotice) {
		p.renderUpstreams(w, r, status, n)
	})
}

// handleUpstreamStrategy saves the routing strategy chosen on the
// upstreams page. The known set is shared with the settings page, so the
// two cannot disagree.
func (p *Panel) handleUpstreamStrategy(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	strategy := strings.TrimSpace(r.PostFormValue("strategy"))
	if !validStrategy(strategy) {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "неизвестная стратегия: " + strategy})
		return
	}

	next := cloneConfig(cfg)
	next.Strategy = strategy
	p.finishApply(w, r, next, upstreamsPath+"?ok=strategy", func(status int, n manageNotice) {
		p.renderUpstreams(w, r, status, n)
	})
}

// handleUpstreamAdd adds one provider endpoint from the catalog. The
// posted provider value is "providerID|transport"; the first endpoint of
// that provider and transport supplies the address.
func (p *Panel) handleUpstreamAdd(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	providerID, transport, ok := strings.Cut(strings.TrimSpace(r.PostFormValue("provider")), "|")
	prov, found := providers.ByID(providerID)
	if !ok || providerID == "" || transport == "" || !found {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "выберите провайдера и транспорт"})
		return
	}

	endpoint, found := providers.Endpoint{}, false
	for _, e := range prov.AllEndpoints() {
		if e.Transport == transport {
			endpoint, found = e, true
			break
		}
	}
	if !found {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{
			Error: fmt.Sprintf("у провайдера «%s» нет транспорта %s", prov.Name, transport),
		})
		return
	}

	next := cloneConfig(cfg)
	for _, u := range next.Upstreams {
		if u.Transport == endpoint.Transport && u.Address == endpoint.Address {
			p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{
				Error: "этот upstream уже добавлен: " + endpoint.Address,
			})
			return
		}
	}

	up := endpoint.UpstreamConfig(uniqueUpstreamID(next.Upstreams, prov.ID, endpoint.Transport), prov.Name)
	up.Priority = nextPriority(next.Upstreams)
	next.Upstreams = append(next.Upstreams, up)

	p.finishApply(w, r, next, upstreamsPath+"?ok=upstream-added", func(status int, n manageNotice) {
		p.renderUpstreams(w, r, status, n)
	})
}

// handleUpstreamCustom adds an upstream the admin types in. The ID is
// optional (derived from the address host when empty); everything
// semantic — the transport, the address shape — is left to
// config.Validate, which UpdateConfig runs, so the page and the daemon
// cannot disagree.
func (p *Panel) handleUpstreamCustom(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	id := strings.TrimSpace(r.PostFormValue("id"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	transport := strings.TrimSpace(r.PostFormValue("transport"))
	address := strings.TrimSpace(r.PostFormValue("address"))
	serverName := strings.TrimSpace(r.PostFormValue("server_name"))
	rawPriority := strings.TrimSpace(r.PostFormValue("priority"))

	if address == "" {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "укажите адрес upstream"})
		return
	}
	if !knownTransport(transport) {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "неизвестный транспорт: " + transport})
		return
	}

	next := cloneConfig(cfg)
	if id == "" {
		id = uniqueUpstreamID(next.Upstreams, upstreamIDFromAddress(address), transport)
	} else {
		for _, u := range next.Upstreams {
			if u.ID == id {
				p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "upstream с таким ID уже есть: " + id})
				return
			}
		}
	}

	priority := nextPriority(next.Upstreams)
	if rawPriority != "" {
		n, err := strconv.Atoi(rawPriority)
		if err != nil || n < 0 {
			p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "приоритет: ожидается целое число не меньше нуля"})
			return
		}
		priority = n
	}

	if name == "" {
		name = id
	}
	next.Upstreams = append(next.Upstreams, config.UpstreamConfig{
		ID:         id,
		Name:       name,
		Transport:  transport,
		Address:    address,
		ServerName: serverName,
		Priority:   priority,
		Enabled:    true,
	})

	p.finishApply(w, r, next, upstreamsPath+"?ok=upstream-added", func(status int, n manageNotice) {
		p.renderUpstreams(w, r, status, n)
	})
}

// probeBudget bounds one upstream probe. The DoH listener's write
// timeout is 10 s, so 5 s leaves room to render the result.
const probeBudget = 5 * time.Second

// handleUpstreamProbe checks one hand-written upstream without saving
// it. It never touches the config: the operator sees the latency (or
// the failure) and can still press «Добавить upstream» afterwards, since
// an upstream may legitimately be down at configuration time.
func (p *Panel) handleUpstreamProbe(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	form := upstreamFormFromRequest(r)
	ep, err := probeEndpoint(form)
	if err != nil {
		p.renderUpstreamsForm(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()}, form)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeBudget)
	defer cancel()
	results := p.ctrl.Probe(ctx, []providers.Endpoint{ep})

	var n manageNotice
	switch {
	case len(results) == 0:
		n.Error = "Нет ответа: проверка не дала результата"
	case results[0].Err != "":
		n.Error = "Нет ответа: " + results[0].Err
	default:
		rcode := results[0].Rcode
		if rcode == "" {
			rcode = "NOERROR"
		}
		latency := formatMS(float64(results[0].Latency) / float64(time.Millisecond))
		n.OK = fmt.Sprintf("Отвечает: %s, rcode %s", latency, rcode)
	}
	p.renderUpstreamsForm(w, r, http.StatusOK, n, form)
}

// probeEndpoint turns the custom form into the single endpoint to probe.
// It rejects an empty or unknown transport and an empty address before
// the controller is called, so a malformed form never starts a probe.
func probeEndpoint(form upstreamForm) (providers.Endpoint, error) {
	if form.Transport == "" {
		return providers.Endpoint{}, errors.New("выберите транспорт")
	}
	if !knownTransport(form.Transport) {
		return providers.Endpoint{}, fmt.Errorf("неизвестный транспорт: %s", form.Transport)
	}
	if form.Address == "" {
		return providers.Endpoint{}, errors.New("укажите адрес upstream")
	}
	return providers.Endpoint{
		Transport:  form.Transport,
		Address:    form.Address,
		ServerName: form.ServerName,
	}, nil
}

// handleUpstreamRemove drops one upstream. Removing the last enabled one
// is refused: the daemon would have nothing to forward to.
func (p *Panel) handleUpstreamRemove(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	id := strings.TrimSpace(r.PostFormValue("id"))
	next := cloneConfig(cfg)
	idx := -1
	for i := range next.Upstreams {
		if next.Upstreams[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{Error: "upstream не найден: " + id})
		return
	}

	enabled := 0
	for _, u := range next.Upstreams {
		if u.Enabled {
			enabled++
		}
	}
	if next.Upstreams[idx].Enabled && enabled <= 1 {
		p.renderUpstreams(w, r, http.StatusBadRequest, manageNotice{
			Error: "нельзя удалить последний включённый upstream — демону будет некуда пересылать запросы",
		})
		return
	}

	next.Upstreams = append(next.Upstreams[:idx], next.Upstreams[idx+1:]...)
	p.finishApply(w, r, next, upstreamsPath+"?ok=upstream-removed", func(status int, n manageNotice) {
		p.renderUpstreams(w, r, status, n)
	})
}

// ---- filters ------------------------------------------------------

// filterListRow is one line of the block-list table.
type filterListRow struct {
	ID         string
	Rules      string
	Skipped    string
	Updated    string
	Title      string // the full error, kept in the row's tooltip
	StateClass string
	StateText  string
}

// filterModeOption is one block-mode radio.
type filterModeOption struct {
	Value   string
	Label   string
	Checked bool
}

// filterModes is the fixed set of block modes, in the order the engine
// documents them (filter.config: zero | nxdomain | refused).
var filterModes = []struct{ value, label string }{
	{"zero", "zero (0.0.0.0 / ::)"},
	{"nxdomain", "nxdomain (несуществующий домен)"},
	{"refused", "refused (отказ)"},
}

// filterModeOptions marks the current mode.
func filterModeOptions(current string) []filterModeOption {
	opts := make([]filterModeOption, 0, len(filterModes))
	for _, m := range filterModes {
		opts = append(opts, filterModeOption{Value: m.value, Label: m.label, Checked: m.value == current})
	}
	return opts
}

// filterModeLabel is the short prose name of a mode, shared by the mode
// radios and the topline.
func filterModeLabel(mode string) string {
	for _, m := range filterModes {
		if m.value == mode {
			return m.label
		}
	}
	return mode
}

// validFilterMode reports whether mode is one the engine accepts.
func validFilterMode(mode string) bool {
	for _, m := range filterModes {
		if m.value == mode {
			return true
		}
	}
	return false
}

// filtersForm is the state of the filters page's forms, echoed back when
// a submission is rejected so the admin does not retype it: the add-rule
// fields plus the custom-list ID and URL.
type filtersForm struct {
	Domain string
	Kind   string

	CustomID  string
	CustomURL string
}

// catalogRow is one entry of the ready-made list catalog on the filters
// page: the catalog metadata, the Russian category label and whether the
// daemon already configures the list.
type catalogRow struct {
	ID          string
	Name        string
	Category    string
	Description string
	Added       bool
}

// filtersView is the whole filters page.
type filtersView struct {
	manageNotice
	Domain string
	CSRF   string
	Nav    string

	Enabled      bool
	ModeLabel    string
	TotalBlocked string

	Lists   []filterListRow
	Catalog []catalogRow
	Modes   []filterModeOption

	Allow []string
	Block []string

	AddDomain string
	AddKind   string

	CustomID  string
	CustomURL string
}

// handleFilters renders the filters screen.
func (p *Panel) handleFilters(w http.ResponseWriter, r *http.Request) {
	p.renderFilters(w, r, http.StatusOK, notice(r), filtersForm{Kind: "block"})
}

// renderFilters renders the page with the current config, the catalog,
// the engine's per-list status and the form state.
func (p *Panel) renderFilters(w http.ResponseWriter, r *http.Request, status int, n manageNotice, form filtersForm) {
	view := filtersView{
		manageNotice: n,
		Domain:       p.pageDomain(),
		CSRF:         p.manageCSRF(r),
		Nav:          "filters",
		AddDomain:    form.Domain,
		AddKind:      form.Kind,
		CustomID:     form.CustomID,
		CustomURL:    form.CustomURL,
	}

	loc := p.location()
	cfg := p.currentConfig()
	mode := "zero"
	added := make(map[string]bool)
	if cfg != nil {
		view.Enabled = cfg.Filter.Enabled
		mode = cfg.Filter.Mode
		view.Allow = cfg.Filter.UserAllow
		view.Block = cfg.Filter.UserBlock
		for _, l := range cfg.Filter.Lists {
			added[l.ID] = true
		}
	}
	view.ModeLabel = filterModeLabel(mode)
	view.Modes = filterModeOptions(mode)
	for _, e := range filter.Catalog() {
		view.Catalog = append(view.Catalog, catalogRow{
			ID:          e.ID,
			Name:        e.Name,
			Category:    listCategoryLabel(e.Category),
			Description: e.Description,
			Added:       added[e.ID],
		})
	}

	// The table shows the configured lists, in config order, so a list the
	// updater has not reported yet (a fresh addition, or a daemon that is
	// not there) still appears with a placeholder state and its refresh
	// control. A status entry the config no longer carries is stale and is
	// dropped, and a status the config does carry wins over the placeholder.
	live := make(map[string]filter.ListStatus)
	if p.ctrl != nil {
		if st := p.statusSnapshot(r); st.Filter.TotalBlocked > 0 {
			view.TotalBlocked = formatCount(st.Filter.TotalBlocked)
		}
		for _, l := range p.ctrl.FilterStatus() {
			live[l.ID] = l
		}
	}
	if cfg != nil {
		view.Lists = make([]filterListRow, 0, len(cfg.Filter.Lists))
		for _, l := range cfg.Filter.Lists {
			if st, ok := live[l.ID]; ok {
				view.Lists = append(view.Lists, filterListRowFor(st, loc))
				continue
			}
			view.Lists = append(view.Lists, filterListRow{
				ID:         l.ID,
				Rules:      formatCount(0),
				Skipped:    formatCount(0),
				Updated:    "—",
				StateClass: "warn",
				StateText:  "не загружен",
			})
		}
	}

	p.render(w, status, "filters", view)
}

// listCategoryLabel is the Russian label of a catalog category.
func listCategoryLabel(category string) string {
	switch category {
	case "ads":
		return "реклама и трекеры"
	case "combined":
		return "комбинированные"
	case "regional":
		return "региональные"
	default:
		return category
	}
}

// hasFilterList reports whether id is already configured.
func hasFilterList(lists []config.FilterList, id string) bool {
	for _, l := range lists {
		if l.ID == id {
			return true
		}
	}
	return false
}

// validListSlug reports whether id is a usable custom-list ID: a
// lowercase slug [a-z0-9][a-z0-9-]{0,47}.
func validListSlug(id string) bool {
	if id == "" || len(id) > 48 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// handleFilterListAdd appends a ready-made catalog list (id) or a custom
// list (custom_id + custom_url) to the block-list configuration. An
// empty URL marks a catalog list, which the engine resolves by ID.
func (p *Panel) handleFilterListAdd(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, filtersForm{Kind: "block"})
		return
	}

	form := filtersForm{
		Kind:      "block",
		CustomID:  strings.TrimSpace(r.PostFormValue("custom_id")),
		CustomURL: strings.TrimSpace(r.PostFormValue("custom_url")),
	}
	id := strings.TrimSpace(r.PostFormValue("id"))

	next := cloneConfig(cfg)
	var list config.FilterList
	if id != "" {
		if _, ok := filter.EntryByID(id); !ok {
			p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "неизвестный список: " + id}, form)
			return
		}
		if hasFilterList(next.Filter.Lists, id) {
			p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "список уже добавлен: " + id}, form)
			return
		}
		list = config.FilterList{ID: id}
	} else {
		if !validListSlug(form.CustomID) {
			p.renderFilters(w, r, http.StatusBadRequest, manageNotice{
				Error: "ID списка: строчные латинские буквы, цифры и дефис, до 48 символов",
			}, form)
			return
		}
		if hasFilterList(next.Filter.Lists, form.CustomID) {
			p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "список уже добавлен: " + form.CustomID}, form)
			return
		}
		u, err := url.Parse(form.CustomURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "URL списка должен быть https-ссылкой с хостом"}, form)
			return
		}
		list = config.FilterList{ID: form.CustomID, URL: form.CustomURL}
	}

	next.Filter.Lists = append(next.Filter.Lists, list)
	p.finishApply(w, r, next, filtersPath+"?ok=list-added", func(status int, n manageNotice) {
		p.renderFilters(w, r, status, n, form)
	})
}

// handleFilterListRemove drops one configured list and nothing else.
func (p *Panel) handleFilterListRemove(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, filtersForm{Kind: "block"})
		return
	}

	id := strings.TrimSpace(r.PostFormValue("id"))
	next := cloneConfig(cfg)
	if !hasFilterList(next.Filter.Lists, id) {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "список не найден: " + id}, filtersForm{Kind: "block"})
		return
	}
	kept := make([]config.FilterList, 0, len(next.Filter.Lists))
	for _, l := range next.Filter.Lists {
		if l.ID != id {
			kept = append(kept, l)
		}
	}
	next.Filter.Lists = kept

	p.finishApply(w, r, next, filtersPath+"?ok=list-removed", func(status int, n manageNotice) {
		p.renderFilters(w, r, status, n, filtersForm{Kind: "block"})
	})
}

// filterListRowFor renders one list's live state. The update time is
// shown in loc, the panel's configured zone, like every other time.
func filterListRowFor(l filter.ListStatus, loc *time.Location) filterListRow {
	row := filterListRow{
		ID:      l.ID,
		Rules:   formatCount(uint64(l.Applied)),
		Skipped: formatCount(uint64(l.Skipped)),
		Updated: "—",
	}
	if !l.UpdatedAt.IsZero() {
		row.Updated = l.UpdatedAt.In(loc).Format("02.01 15:04:05")
	}

	switch {
	case l.Error != "":
		row.StateClass, row.StateText, row.Title = "err", "ошибка", l.Error
	case l.UpdatedAt.IsZero():
		row.StateClass, row.StateText = "warn", "не загружен"
	default:
		row.StateClass, row.StateText = "ok", "ок"
	}
	return row
}

// handleFiltersRefresh starts reloading one block list, or every list
// when the posted id is empty. The work runs in the background: the DoH
// listener's 10 s write timeout would otherwise truncate the response
// and cancel the update mid-loop, leaving some lists refreshed and some
// not. The POST redirects at once with «обновление запущено»; a second
// POST while the update runs is refused with a banner.
func (p *Panel) handleFiltersRefresh(w http.ResponseWriter, r *http.Request) {
	if p.ctrl == nil {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, filtersForm{Kind: "block"})
		return
	}
	// With filtering off there is no engine to update: claiming a refresh
	// started would be a lie the next page load contradicts.
	if cfg := p.currentConfig(); cfg == nil || !cfg.Filter.Enabled {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "фильтрация выключена"}, filtersForm{Kind: "block"})
		return
	}

	id := strings.TrimSpace(r.PostFormValue("id"))
	started := p.refresh.start(func() {
		// The update runs outside net/http's per-request recover, so a
		// panicking controller would otherwise take the daemon down.
		// Recover first (innermost defer) so the single-flight reset
		// registered by start still runs after the panic is contained.
		defer func() {
			if r := recover(); r != nil {
				p.logger.Error("panel: block list refresh panicked",
					"id", id, "panic", r, "stack", string(debug.Stack()))
			}
		}()
		if err := p.ctrl.FilterUpdate(context.Background(), id); err != nil {
			p.logger.Warn("panel: refreshing block lists", "id", id, "error", err)
			return
		}
		p.logger.Info("panel: block lists refreshed", "id", id)
	})
	if !started {
		p.renderFilters(w, r, http.StatusConflict,
			manageNotice{Error: "обновление уже идёт"}, filtersForm{Kind: "block"})
		return
	}
	http.Redirect(w, r, filtersPath+"?ok=lists", http.StatusSeeOther)
}

// handleFilterMode switches the block mode through the whole config.
func (p *Panel) handleFilterMode(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, filtersForm{Kind: "block"})
		return
	}

	mode := strings.TrimSpace(r.PostFormValue("mode"))
	if !validFilterMode(mode) {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "неизвестный режим блокировки: " + mode}, filtersForm{Kind: "block"})
		return
	}

	next := cloneConfig(cfg)
	next.Filter.Mode = mode
	p.finishApply(w, r, next, filtersPath+"?ok=mode", func(status int, n manageNotice) {
		p.renderFilters(w, r, status, n, filtersForm{Kind: "block"})
	})
}

// handleFilterRuleAdd appends one user rule to the allow or block list.
func (p *Panel) handleFilterRuleAdd(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, filtersForm{Kind: "block"})
		return
	}

	kind := r.PostFormValue("kind")
	raw := strings.TrimSpace(r.PostFormValue("domain"))
	form := filtersForm{Domain: raw, Kind: kind}
	if kind != "allow" && kind != "block" {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "неизвестный тип правила: " + kind}, form)
		return
	}
	domain := dnsname.Normalize(raw)
	if domain == "" {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "Укажите домен"}, form)
		return
	}
	if !dnsname.Valid(domain) {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{
			Error: fmt.Sprintf("«%s» — не домен: нужно минимум две метки, только буквы, цифры и дефис", raw),
		}, form)
		return
	}

	next := cloneConfig(cfg)
	if kind == "allow" {
		next.Filter.UserAllow = appendRule(next.Filter.UserAllow, domain)
	} else {
		next.Filter.UserBlock = appendRule(next.Filter.UserBlock, domain)
	}

	p.finishApply(w, r, next, filtersPath+"?ok=rule", func(status int, n manageNotice) {
		p.renderFilters(w, r, status, n, form)
	})
}

// handleFilterRuleRemove drops one user rule from its list.
func (p *Panel) handleFilterRuleRemove(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, filtersForm{Kind: "block"})
		return
	}

	kind := r.PostFormValue("kind")
	domain := dnsname.Normalize(strings.TrimSpace(r.PostFormValue("domain")))
	form := filtersForm{Domain: domain, Kind: kind}
	if kind != "allow" && kind != "block" {
		p.renderFilters(w, r, http.StatusBadRequest, manageNotice{Error: "неизвестный тип правила: " + kind}, form)
		return
	}

	next := cloneConfig(cfg)
	if kind == "allow" {
		next.Filter.UserAllow = deleteRule(next.Filter.UserAllow, domain)
	} else {
		next.Filter.UserBlock = deleteRule(next.Filter.UserBlock, domain)
	}

	p.finishApply(w, r, next, filtersPath+"?ok=rule", func(status int, n manageNotice) {
		p.renderFilters(w, r, status, n, form)
	})
}

// appendRule adds domain unless it is already present, so a double
// submission cannot store the same rule twice.
func appendRule(rules []string, domain string) []string {
	for _, r := range rules {
		if r == domain {
			return rules
		}
	}
	return append(rules, domain)
}

// deleteRule removes every occurrence of domain. It builds a fresh
// slice instead of filtering in place, so it never mutates the argument:
// the caller's clone and the daemon's own slice stay untouched even if
// this helper is reused beyond the current form flow.
func deleteRule(rules []string, domain string) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if r != domain {
			out = append(out, r)
		}
	}
	return out
}

// ---- settings -----------------------------------------------------

// protocolField names one listener protocol and its form prefix.
type protocolField struct {
	field string
	label string
}

// protocolFields is the fixed protocol list of the settings form.
var protocolFields = []protocolField{
	{"plain", "Обычный DNS (UDP/TCP)"},
	{"doh", "DoH (HTTPS)"},
	{"dot", "DoT (TLS)"},
	{"doq", "DoQ (QUIC)"},
}

// protocolRow is one protocol's controls in the form.
type protocolRow struct {
	Field   string
	Label   string
	Enabled bool
	Port    string
}

// strategyOption is one routing strategy in the select. A strategy the
// config validation rejects (an admin typed it into the file) is
// preserved as an extra option so a rejected save does not silently
// rewrite it.
type strategyOption struct {
	Value    string
	Label    string
	Selected bool
}

// strategies is the set routing knows, with the prose the mockup uses.
var strategies = []struct{ value, label string }{
	{"fastest", "fastest — по задержке"},
	{"failover", "failover — по приоритету"},
	{"round_robin", "round_robin — по кругу"},
	{"random", "random — случайно"},
}

// strategyOptions marks the current strategy, appending an unknown one.
func strategyOptions(current string) []strategyOption {
	opts := make([]strategyOption, 0, len(strategies)+1)
	known := false
	for _, s := range strategies {
		if s.value == current {
			known = true
		}
		opts = append(opts, strategyOption{Value: s.value, Label: s.label, Selected: s.value == current})
	}
	if current != "" && !known {
		opts = append([]strategyOption{{Value: current, Label: current + " (неизвестная)", Selected: true}}, opts...)
	}
	return opts
}

// settingsView is the whole settings page. Its string fields hold what
// the form shows, which on a rejected submission is what the admin
// typed, not what the daemon stores.
type settingsView struct {
	manageNotice
	Domain string
	CSRF   string
	Nav    string

	FormDomain   string
	FormTimezone string
	DoHPath      string
	Strategies   []strategyOption

	Protocols []protocolRow

	CacheSize      string
	CacheMinTTL    string
	CacheMaxTTL    string
	PlainRPS       string
	FilterEnabled  bool
	FilterInterval string
}

// settingsFromConfig fills the form from the live configuration.
func settingsFromConfig(cfg *config.Config) settingsView {
	view := settingsView{
		FormDomain:     cfg.Domain,
		FormTimezone:   cfg.Timezone,
		DoHPath:        cfg.DoHPath(),
		CacheSize:      strconv.Itoa(cfg.Cache.Size),
		CacheMinTTL:    strconv.FormatUint(uint64(cfg.Cache.MinTTL), 10),
		CacheMaxTTL:    strconv.FormatUint(uint64(cfg.Cache.MaxTTL), 10),
		PlainRPS:       strconv.Itoa(cfg.Limits.PlainRPSPerIP),
		FilterEnabled:  cfg.Filter.Enabled,
		FilterInterval: strconv.Itoa(cfg.Filter.UpdateIntervalHours),
	}
	protocols := map[string]config.Protocol{
		"plain": cfg.Protocols.Plain,
		"doh":   cfg.Protocols.DoH,
		"dot":   cfg.Protocols.DoT,
		"doq":   cfg.Protocols.DoQ,
	}
	for _, f := range protocolFields {
		p := protocols[f.field]
		view.Protocols = append(view.Protocols, protocolRow{
			Field: f.field, Label: f.label, Enabled: p.Enabled, Port: strconv.Itoa(p.Port),
		})
	}
	view.Strategies = strategyOptions(cfg.Strategy)
	return view
}

// settingsFromForm fills the form from a submission, so a rejected save
// shows the values the admin typed.
func settingsFromForm(r *http.Request) settingsView {
	view := settingsView{
		FormDomain:     r.PostFormValue("domain"),
		FormTimezone:   strings.TrimSpace(r.PostFormValue("timezone")),
		DoHPath:        strings.TrimSpace(r.PostFormValue("doh.path")),
		Strategies:     strategyOptions(strings.TrimSpace(r.PostFormValue("strategy"))),
		CacheSize:      strings.TrimSpace(r.PostFormValue("cache.size")),
		CacheMinTTL:    strings.TrimSpace(r.PostFormValue("cache.min_ttl")),
		CacheMaxTTL:    strings.TrimSpace(r.PostFormValue("cache.max_ttl")),
		PlainRPS:       strings.TrimSpace(r.PostFormValue("limits.plain_rps_per_ip")),
		FilterEnabled:  r.PostFormValue("filter.enabled") != "",
		FilterInterval: strings.TrimSpace(r.PostFormValue("filter.update_interval_hours")),
	}
	for _, f := range protocolFields {
		view.Protocols = append(view.Protocols, protocolRow{
			Field:   f.field,
			Label:   f.label,
			Enabled: r.PostFormValue(f.field+".enabled") != "",
			Port:    strings.TrimSpace(r.PostFormValue(f.field + ".port")),
		})
	}
	return view
}

// handleSettings renders the settings screen.
func (p *Panel) handleSettings(w http.ResponseWriter, r *http.Request) {
	var view settingsView
	if cfg := p.currentConfig(); cfg != nil {
		view = settingsFromConfig(cfg)
	}
	p.renderSettings(w, r, http.StatusOK, notice(r), view)
}

// renderSettings renders the page with the given form state.
func (p *Panel) renderSettings(w http.ResponseWriter, r *http.Request, status int, n manageNotice, view settingsView) {
	view.manageNotice = n
	view.Domain = p.pageDomain()
	view.CSRF = p.manageCSRF(r)
	view.Nav = "settings"
	p.render(w, status, "settings", view)
}

// handleSettingsApply rewrites the editable configuration fields and
// hands the full config to UpdateConfig.
func (p *Panel) handleSettingsApply(w http.ResponseWriter, r *http.Request) {
	// A structural change rebuilds listeners and can take seconds; the
	// 10 s listener write timeout would cut the response after the
	// daemon already applied the config. Accept a client-side timeout
	// instead of a truncated server answer.
	clearWriteDeadline(w)

	cfg := p.currentConfig()
	if cfg == nil {
		p.renderSettings(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, settingsFromForm(r))
		return
	}

	// «Сгенерировать» only proposes a fresh path: it re-renders the form
	// with a random value and touches no config. Only a later «Применить»
	// saves it, so a generate cannot change the running daemon.
	if r.PostFormValue("generate") == "doh-path" {
		view := settingsFromForm(r)
		view.DoHPath = generateDoHPath()
		p.renderSettings(w, r, http.StatusOK, manageNotice{}, view)
		return
	}

	view := settingsFromForm(r)
	next := cloneConfig(cfg)
	if err := applySettingsForm(next, r); err != nil {
		p.renderSettings(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()}, view)
		return
	}
	p.finishApply(w, r, next, settingsPath+"?ok=settings", func(status int, n manageNotice) {
		p.renderSettings(w, r, status, n, view)
	})
}

// applySettingsForm parses the settings form onto next. Parsing failures
// (a non-numeric port) are reported here; everything semantic — port
// ranges, known strategy, TTL order — is left to config.Validate, which
// UpdateConfig runs, so the page and the daemon cannot disagree.
func applySettingsForm(next *config.Config, r *http.Request) error {
	domain := strings.TrimSpace(r.PostFormValue("domain"))
	if domain == "" {
		return errors.New("домен не может быть пустым")
	}
	next.Domain = domain

	// The timezone is left unvalidated here: an unknown IANA zone is a
	// semantic error config.Validate reports, so the page and the daemon
	// cannot disagree.
	next.Timezone = strings.TrimSpace(r.PostFormValue("timezone"))

	for _, f := range protocolFields {
		port, err := formInt(r, f.field+".port")
		if err != nil {
			return fmt.Errorf("порт %s: %w", f.label, err)
		}
		setProtocol(next, f.field, r.PostFormValue(f.field+".enabled") != "", port)
	}

	// setProtocol rebuilds the DoH protocol value, so the path is set
	// after the loop: an empty value means the default and is left as is.
	next.Protocols.DoH.Path = strings.TrimSpace(r.PostFormValue("doh.path"))

	next.Strategy = strings.TrimSpace(r.PostFormValue("strategy"))

	size, err := formInt(r, "cache.size")
	if err != nil {
		return fmt.Errorf("размер кеша: %w", err)
	}
	next.Cache.Size = size

	minTTL, err := formUint32(r, "cache.min_ttl")
	if err != nil {
		return fmt.Errorf("кеш: min TTL: %w", err)
	}
	maxTTL, err := formUint32(r, "cache.max_ttl")
	if err != nil {
		return fmt.Errorf("кеш: max TTL: %w", err)
	}
	next.Cache.MinTTL, next.Cache.MaxTTL = minTTL, maxTTL

	rps, err := formInt(r, "limits.plain_rps_per_ip")
	if err != nil {
		return fmt.Errorf("лимит запросов на IP: %w", err)
	}
	next.Limits.PlainRPSPerIP = rps

	next.Filter.Enabled = r.PostFormValue("filter.enabled") != ""
	interval, err := formInt(r, "filter.update_interval_hours")
	if err != nil {
		return fmt.Errorf("интервал обновления списков: %w", err)
	}
	next.Filter.UpdateIntervalHours = interval
	return nil
}

// setProtocol writes one protocol row.
func setProtocol(cfg *config.Config, field string, enabled bool, port int) {
	p := config.Protocol{Enabled: enabled, Port: port}
	switch field {
	case "plain":
		cfg.Protocols.Plain = p
	case "doh":
		cfg.Protocols.DoH = p
	case "dot":
		cfg.Protocols.DoT = p
	case "doq":
		cfg.Protocols.DoQ = p
	}
}

// generateDoHPath returns a fresh random DoH path: "/" plus 12 lowercase
// hex characters. It is obfuscation that sheds scanner noise, not a
// secret, so hex is enough and stays easy to read out.
func generateDoHPath() string {
	return "/" + hex.EncodeToString(mustRandom(6))
}

// formInt parses a required integer form field.
func formInt(r *http.Request, field string) (int, error) {
	raw := strings.TrimSpace(r.PostFormValue(field))
	if raw == "" {
		return 0, errors.New("ожидается число")
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("ожидается число")
	}
	return n, nil
}

// formUint32 parses a required unsigned form field.
func formUint32(r *http.Request, field string) (uint32, error) {
	raw := strings.TrimSpace(r.PostFormValue(field))
	if raw == "" {
		return 0, errors.New("ожидается целое число")
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, errors.New("ожидается целое число не меньше нуля")
	}
	return uint32(n), nil
}

// handlePasswordChange hashes the new panel password and stores only the
// hash. The live sessions are deliberately left alone (Options.Auth
// documents that), so the admin stays signed in in the tab they used.
func (p *Panel) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		p.renderSettings(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()}, settingsView{})
		return
	}

	view := settingsFromConfig(cfg)
	fail := func(msg string) {
		p.renderSettings(w, r, http.StatusBadRequest, manageNotice{Error: msg}, view)
	}

	password := r.PostFormValue("password")
	if err := auth.ValidatePassword(password); err != nil {
		// Same shared rule and wording as the setup wizard: at least
		// auth.MinPasswordLen runes and no leading/trailing whitespace.
		switch {
		case errors.Is(err, auth.ErrPasswordWhitespace):
			fail("пароль не должен начинаться или заканчиваться пробелом")
		case errors.Is(err, auth.ErrPasswordTooShort):
			fail(fmt.Sprintf("пароль должен быть не короче %d символов", auth.MinPasswordLen))
		default:
			fail(err.Error())
		}
		return
	}
	if password != r.PostFormValue("password2") {
		fail("пароли не совпадают")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		p.logger.Error("panel: hashing the new password", "error", err)
		fail("не удалось захешировать пароль")
		return
	}

	next := cloneConfig(cfg)
	next.Panel.PasswordHash = hash
	p.finishApply(w, r, next, settingsPath+"?ok=password", func(status int, n manageNotice) {
		p.renderSettings(w, r, status, n, view)
	})
}

// ---- certificate --------------------------------------------------

// certPageView is the read-only certificate page: the live state from the
// daemon plus the TLS mode the config selects.
type certPageView struct {
	manageNotice
	Domain string
	CSRF   string
	Nav    string

	Show       bool
	StateClass string
	StateText  string
	Issuer     string
	NotAfter   string
	LastCheck  string
	Error      string

	TLSMode       string
	CertFile      string
	KeyFile       string
	ACMEProvider  string
	ACMEEmail     string
	ACMEDirectory string
}

// handleCert renders the certificate page.
func (p *Panel) handleCert(w http.ResponseWriter, r *http.Request) {
	view := certPageView{
		manageNotice: notice(r),
		Domain:       p.pageDomain(),
		CSRF:         p.manageCSRF(r),
		Nav:          "cert",
	}

	if cfg := p.currentConfig(); cfg != nil {
		view.TLSMode = cfg.TLS.Mode
		view.CertFile = cfg.TLS.CertFile
		view.KeyFile = cfg.TLS.KeyFile
		view.ACMEProvider = cfg.TLS.ACME.Provider
		view.ACMEEmail = cfg.TLS.ACME.Email
		if dir, err := cfg.TLS.ACMEDirectoryURL(); err == nil {
			view.ACMEDirectory = dir
		}
	}

	fillCertView(&view, p.statusSnapshot(r).Cert)
	p.render(w, http.StatusOK, "cert", view)
}

// fillCertView copies the certificate snapshot into the page. It shares
// certStateLabel with the status page, so both name a state the same way.
func fillCertView(view *certPageView, c tlscert.Status) {
	if c.Mode == "" {
		view.StateText = "нет данных"
		return
	}

	view.Show = true
	view.Issuer = c.Issuer
	view.Error = c.Error
	class, label, known := certStateLabel(c.State)
	if !known {
		view.StateClass, view.StateText = c.State, c.Mode
	} else {
		view.StateClass, view.StateText = class, label
	}
	if !c.NotAfter.IsZero() {
		view.NotAfter = c.NotAfter.Format("02.01.2006")
	}
	if !c.LastCheck.IsZero() {
		view.LastCheck = c.LastCheck.Format("02.01.2006 15:04:05")
	}
}

// ---- maintenance --------------------------------------------------

// backupRow is one snapshot in the maintenance table, with its time and
// size already formatted for display.
type backupRow struct {
	Name string
	When string
	Size string
}

// maintenanceView is the maintenance page.
type maintenanceView struct {
	manageNotice
	Domain  string
	CSRF    string
	Nav     string
	Version string
	Uptime  string
	Started string

	Backups []backupRow
}

// handleMaintenance renders the maintenance screen.
func (p *Panel) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	p.renderMaintenance(w, r, http.StatusOK, notice(r))
}

// renderMaintenance renders the page.
func (p *Panel) renderMaintenance(w http.ResponseWriter, r *http.Request, status int, n manageNotice) {
	view := maintenanceView{
		manageNotice: n,
		Domain:       p.pageDomain(),
		CSRF:         p.manageCSRF(r),
		Nav:          "maintenance",
		Version:      p.version,
	}
	if p.ctrl != nil {
		if started := p.ctrl.Started(); !started.IsZero() {
			view.Started = started.In(p.location()).Format("02.01.2006 15:04:05")
			view.Uptime = formatUptime(time.Since(started))
		}
		infos, err := p.ctrl.ListConfigBackups()
		switch {
		case err != nil:
			p.logger.Warn("panel: listing the config backups", "error", err)
			if n.Error == "" {
				n.Error = "не удалось прочитать резервные копии: " + err.Error()
			}
		default:
			loc := p.location()
			view.Backups = make([]backupRow, 0, len(infos))
			for _, info := range infos {
				view.Backups = append(view.Backups, backupRow{
					Name: info.Name,
					When: info.ModTime.In(loc).Format("02.01.2006 15:04:05"),
					Size: formatSize(info.Size),
				})
			}
		}
	}
	view.manageNotice = n
	p.render(w, status, "maintenance", view)
}

// handleBackupCreate stores a manual snapshot of the live config.
func (p *Panel) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if p.ctrl == nil {
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	if err := p.ctrl.CreateConfigBackup("manual"); err != nil {
		p.logger.Warn("panel: creating a config backup", "error", err)
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()})
		return
	}
	http.Redirect(w, r, maintenancePath+"?ok=backup-created", http.StatusSeeOther)
}

// backupExists reports whether name is one of the stored snapshots. The
// list is the gate for restore and delete, so a hand-written name can
// never address a file the page did not show.
func (p *Panel) backupExists(name string) (bool, error) {
	if p.ctrl == nil {
		return false, errNoDaemon
	}
	infos, err := p.ctrl.ListConfigBackups()
	if err != nil {
		return false, err
	}
	for _, info := range infos {
		if info.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// handleBackupRestore applies one snapshot through the daemon's normal
// config load, migration and UpdateConfig path. A restore that fails
// validation re-renders the page with the error and leaves the running
// daemon untouched.
func (p *Panel) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	// A restore may rebuild the listeners, which outlives the DoH
	// listener's write timeout.
	clearWriteDeadline(w)

	name := strings.TrimSpace(r.PostFormValue("name"))
	ok, err := p.backupExists(name)
	if err != nil {
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()})
		return
	}
	if !ok {
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: "копия не найдена: " + name})
		return
	}

	if err := p.ctrl.RestoreConfigBackup(name); err != nil {
		p.logger.Warn("panel: restoring a config backup", "name", name, "error", err)
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()})
		return
	}
	http.Redirect(w, r, maintenancePath+"?ok=backup-restored", http.StatusSeeOther)
}

// handleBackupDelete removes one snapshot. The name must be one the page
// listed, so a hand-written path cannot reach outside the backups
// directory.
func (p *Panel) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	ok, err := p.backupExists(name)
	if err != nil {
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()})
		return
	}
	if !ok {
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: "копия не найдена: " + name})
		return
	}

	if err := p.ctrl.DeleteConfigBackup(name); err != nil {
		p.logger.Warn("panel: deleting a config backup", "name", name, "error", err)
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: err.Error()})
		return
	}
	http.Redirect(w, r, maintenancePath+"?ok=backup-deleted", http.StatusSeeOther)
}

// formatSize renders a snapshot size in the largest unit that keeps it
// readable.
func formatSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d Б", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f КБ", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f МБ", float64(n)/(1024*1024))
	}
}

// handleConfigDownload streams the live configuration as a pretty JSON
// attachment. The file carries the panel password hash and the ACME EAB
// HMAC — the page says so, and the response is no-store.
func (p *Panel) handleConfigDownload(w http.ResponseWriter, r *http.Request) {
	cfg := p.currentConfig()
	if cfg == nil {
		http.Error(w, errNoDaemon.Error(), http.StatusServiceUnavailable)
		return
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		p.logger.Error("panel: serializing the config", "error", err)
		http.Error(w, "не удалось сериализовать конфигурацию", http.StatusInternalServerError)
		return
	}
	data = append(data, '\n')

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="mdns-config.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		p.logger.Warn("panel: writing the config download", "error", err)
	}
}

// handleReapply pushes the current configuration back through
// UpdateConfig: a soft reapply, the web twin of the TUI's "apply again".
func (p *Panel) handleReapply(w http.ResponseWriter, r *http.Request) {
	// Same reason as handleSettingsApply: a reapply may rebuild the
	// daemon's listeners, which outlives the listener's write timeout.
	clearWriteDeadline(w)

	cfg := p.currentConfig()
	if cfg == nil {
		p.renderMaintenance(w, r, http.StatusBadRequest, manageNotice{Error: errNoDaemon.Error()})
		return
	}

	next := cloneConfig(cfg)
	p.finishApply(w, r, next, maintenancePath+"?ok=reapply", func(status int, n manageNotice) {
		p.renderMaintenance(w, r, status, n)
	})
}

// formatUptime renders a duration the mockup's way: "3 дня 4 ч", falling
// back to hours and minutes for a young process.
func formatUptime(d time.Duration) string {
	if d < time.Minute {
		return "меньше минуты"
	}
	days := int(d / (24 * time.Hour))
	hours := int(d/time.Hour) % 24
	minutes := int(d/time.Minute) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d %s %d ч", days, pluralDays(days), hours)
	case hours > 0:
		return fmt.Sprintf("%d ч %d мин", hours, minutes)
	default:
		return fmt.Sprintf("%d мин", minutes)
	}
}

// pluralDays is the Russian plural of "день".
func pluralDays(n int) string {
	switch {
	case n%10 == 1 && n%100 != 11:
		return "день"
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 10 || n%100 >= 20):
		return "дня"
	default:
		return "дней"
	}
}
