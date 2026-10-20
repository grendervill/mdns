package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// upstreamProbeBudget bounds one probe from the TUI, matching the web
// panel: the daemon's DoH listener write timeout is 10 s, so 5 s leaves
// room to render the result.
const upstreamProbeBudget = 5 * time.Second

// upstreamTransports is the order the custom form cycles transports in.
var upstreamTransports = []string{"plain", "dot", "doh", "doq"}

// upstreamFormField indexes name the editable fields of the custom
// upstream form, in the order they are rendered.
const (
	upstreamFormID = iota
	upstreamFormName
	upstreamFormTransport
	upstreamFormAddress
	upstreamFormServerName
	upstreamFormPriority
)

// upstreamFormFields are the form's field labels, one per index above.
var upstreamFormFields = []string{
	"ID (пусто — из адреса)",
	"Название",
	"Транспорт",
	"Адрес",
	"ServerName (для DoT/DoQ по IP)",
	"Приоритет",
}

// upstreamFormState carries every field the custom form edits.
type upstreamFormState struct {
	ID         string
	Name       string
	Transport  string
	Address    string
	ServerName string
	Priority   string
}

// value returns the field at index i.
func (f upstreamFormState) value(i int) string {
	switch i {
	case upstreamFormID:
		return f.ID
	case upstreamFormName:
		return f.Name
	case upstreamFormTransport:
		return f.Transport
	case upstreamFormAddress:
		return f.Address
	case upstreamFormServerName:
		return f.ServerName
	case upstreamFormPriority:
		return f.Priority
	}
	return ""
}

// setValue writes the field at index i.
func (f *upstreamFormState) setValue(i int, v string) {
	switch i {
	case upstreamFormID:
		f.ID = v
	case upstreamFormName:
		f.Name = v
	case upstreamFormTransport:
		f.Transport = v
	case upstreamFormAddress:
		f.Address = v
	case upstreamFormServerName:
		f.ServerName = v
	case upstreamFormPriority:
		f.Priority = v
	}
}

// isUpstreamScreen reports whether s is one of the upstreams screens
// that render the live config.
func isUpstreamScreen(s screen) bool {
	return s == screenUpstreams || s == screenUpstreamCatalog || s == screenUpstreamForm
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

// nextUpstreamTransport cycles the transport forwards.
func nextUpstreamTransport(t string) string {
	for i, x := range upstreamTransports {
		if x == t {
			return upstreamTransports[(i+1)%len(upstreamTransports)]
		}
	}
	return upstreamTransports[0]
}

// prevUpstreamTransport cycles the transport backwards.
func prevUpstreamTransport(t string) string {
	for i, x := range upstreamTransports {
		if x == t {
			return upstreamTransports[(i-1+len(upstreamTransports))%len(upstreamTransports)]
		}
	}
	return upstreamTransports[0]
}

// uniqueUpstreamID picks a free ID for a new upstream, with the same
// rule as the web panel: the provider ID when it is free, then
// provider-transport, then a numbered suffix.
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

// nextUpstreamPriority is one past the highest existing priority, so a
// new upstream sorts last under the failover strategy.
func nextUpstreamPriority(upstreams []config.UpstreamConfig) int {
	highest := -1
	for _, u := range upstreams {
		if u.Priority > highest {
			highest = u.Priority
		}
	}
	return highest + 1
}

// upstreamIDFromAddress derives a slug ID from an upstream address when
// the custom form leaves the ID empty: the URL host for DoH, the host of
// a host:port otherwise.
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

// upstreamCatalogEntry is one row of the provider endpoint picker.
type upstreamCatalogEntry struct {
	provider string // provider ID, the ID stem of a new upstream
	name     string // provider display name
	end      providers.Endpoint
	trust    providers.Trust
}

// upstreamCatalogEntries lists every endpoint of every provider, in the
// catalog's stable order (providers as-is, endpoints DoH/DoT/DoQ/plain).
func upstreamCatalogEntries() []upstreamCatalogEntry {
	var out []upstreamCatalogEntry
	for _, p := range providers.List() {
		for _, e := range p.AllEndpoints() {
			out = append(out, upstreamCatalogEntry{provider: p.ID, name: p.Name, end: e, trust: p.Trust})
		}
	}
	return out
}

// loadUpstreamConfig fetches the live configuration for upstream edits.
func loadUpstreamConfig(c Client) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		return upstreamConfigLoadedMsg{cfg: cfg, err: err}
	}
}

// applyUpstreamCfg sends the edited upstream configuration and keeps the
// local copy in step until the daemon reload lands.
func (m Model) applyUpstreamCfg(next *config.Config) (tea.Model, tea.Cmd) {
	m.upstreamCfg = next
	m.upstreamErr = nil
	return m, applySettingsCmd(m.client, cloneConfig(next))
}

// upstreamRow is one rendered upstream line: the identity and flags from
// the config, the live health and counters from the status snapshot.
type upstreamRow struct {
	id        string
	name      string
	transport string
	address   string
	priority  int
	enabled   bool
	live      api.UpstreamStatus
	hasLive   bool
}

// upstreamRows builds the table: from the live config when it is loaded
// (the source of truth for ids, priority and the enabled flag) joined
// with the status snapshot, or straight from the status before the
// config arrives.
func (m *Model) upstreamRows() []upstreamRow {
	if m.upstreamCfg == nil {
		out := make([]upstreamRow, 0, len(m.status.Upstreams))
		for _, u := range m.status.Upstreams {
			out = append(out, upstreamRow{
				id: u.ID, name: u.Name, transport: u.Transport, address: u.Address,
				enabled: u.Enabled, live: u, hasLive: true,
			})
		}
		return out
	}

	live := make(map[string]api.UpstreamStatus, len(m.status.Upstreams))
	for _, u := range m.status.Upstreams {
		live[u.ID] = u
	}
	out := make([]upstreamRow, 0, len(m.upstreamCfg.Upstreams))
	for _, u := range m.upstreamCfg.Upstreams {
		row := upstreamRow{
			id: u.ID, name: u.Name, transport: u.Transport, address: u.Address,
			priority: u.Priority, enabled: u.Enabled,
		}
		if s, ok := live[u.ID]; ok {
			row.live, row.hasLive = s, true
			if row.name == "" {
				row.name = s.Name
			}
		}
		if row.name == "" {
			row.name = u.ID
		}
		out = append(out, row)
	}
	return out
}

// selectedUpstreamRow returns the row under the cursor, if any.
func (m *Model) selectedUpstreamRow() (upstreamRow, bool) {
	rows := m.upstreamRows()
	if m.upstreamCursor < 0 || m.upstreamCursor >= len(rows) {
		return upstreamRow{}, false
	}
	return rows[m.upstreamCursor], true
}

// upstreamConfigIndex returns the position of id in the live config.
func (m *Model) upstreamConfigIndex(id string) int {
	if m.upstreamCfg == nil {
		return -1
	}
	for i, u := range m.upstreamCfg.Upstreams {
		if u.ID == id {
			return i
		}
	}
	return -1
}

// enabledUpstreamCount counts the enabled upstreams of the live config.
func enabledUpstreamCount(cfg *config.Config) int {
	n := 0
	for _, u := range cfg.Upstreams {
		if u.Enabled {
			n++
		}
	}
	return n
}

// toggleSelectedUpstream flips the enabled flag of the row under the
// cursor, refusing to disable the last enabled upstream.
func (m Model) toggleSelectedUpstream() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	row, ok := m.selectedUpstreamRow()
	if !ok {
		m.upstreamErr = errors.New("upstream не выбран")
		return m, nil
	}
	idx := m.upstreamConfigIndex(row.id)
	if idx < 0 {
		m.upstreamErr = fmt.Errorf("upstream не найден: %s", row.id)
		return m, nil
	}
	if m.upstreamCfg.Upstreams[idx].Enabled && enabledUpstreamCount(m.upstreamCfg) <= 1 {
		m.upstreamErr = errors.New("нельзя выключить последний включённый upstream — демону будет некуда пересылать запросы")
		return m, nil
	}
	next := cloneConfig(m.upstreamCfg)
	next.Upstreams[idx].Enabled = !next.Upstreams[idx].Enabled
	return m.applyUpstreamCfg(next)
}

// removeSelectedUpstream drops the row under the cursor, refusing to
// remove the last enabled upstream.
func (m Model) removeSelectedUpstream() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	row, ok := m.selectedUpstreamRow()
	if !ok {
		m.upstreamErr = errors.New("upstream не выбран")
		return m, nil
	}
	idx := m.upstreamConfigIndex(row.id)
	if idx < 0 {
		m.upstreamErr = fmt.Errorf("upstream не найден: %s", row.id)
		return m, nil
	}
	if m.upstreamCfg.Upstreams[idx].Enabled && enabledUpstreamCount(m.upstreamCfg) <= 1 {
		m.upstreamErr = errors.New("нельзя удалить последний включённый upstream — демону будет некуда пересылать запросы")
		return m, nil
	}
	next := cloneConfig(m.upstreamCfg)
	next.Upstreams = append(next.Upstreams[:idx], next.Upstreams[idx+1:]...)
	if m.upstreamCursor >= len(next.Upstreams) && m.upstreamCursor > 0 {
		m.upstreamCursor--
	}
	return m.applyUpstreamCfg(next)
}

// startUpstreamPriority opens the priority input on the selected row.
// The input starts empty so typing appends; the current value is shown
// in the prompt instead.
func (m Model) startUpstreamPriority() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	_, ok := m.selectedUpstreamRow()
	if !ok {
		m.upstreamErr = errors.New("upstream не выбран")
		return m, nil
	}
	m.upstreamErr = nil
	m.inputActive = true
	m.inputMode = inputUpstreamPriority
	m.input = ""
	return m, nil
}

// commitUpstreamPriority parses the typed priority and applies it; an
// empty submit cancels.
func (m Model) commitUpstreamPriority() (tea.Model, tea.Cmd) {
	raw := strings.TrimSpace(m.input)
	m.inputActive = false
	m.input = ""
	if raw == "" {
		return m, nil // cancelled
	}
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	row, ok := m.selectedUpstreamRow()
	if !ok {
		m.upstreamErr = errors.New("upstream не выбран")
		return m, nil
	}
	priority, err := strconv.Atoi(raw)
	if err != nil || priority < 0 {
		m.upstreamErr = errors.New("приоритет: ожидается целое число не меньше нуля")
		return m, nil
	}
	idx := m.upstreamConfigIndex(row.id)
	if idx < 0 {
		m.upstreamErr = fmt.Errorf("upstream не найден: %s", row.id)
		return m, nil
	}
	if m.upstreamCfg.Upstreams[idx].Priority == priority {
		m.upstreamErr = nil
		return m, nil // nothing changed
	}
	next := cloneConfig(m.upstreamCfg)
	next.Upstreams[idx].Priority = priority
	return m.applyUpstreamCfg(next)
}

// probeSelectedUpstream probes the row under the cursor without touching
// the config.
func (m Model) probeSelectedUpstream() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	row, ok := m.selectedUpstreamRow()
	if !ok {
		m.upstreamErr = errors.New("upstream не выбран")
		return m, nil
	}
	idx := m.upstreamConfigIndex(row.id)
	if idx < 0 {
		m.upstreamErr = fmt.Errorf("upstream не найден: %s", row.id)
		return m, nil
	}
	u := m.upstreamCfg.Upstreams[idx]
	ep := providers.Endpoint{Transport: u.Transport, Address: u.Address, ServerName: u.ServerName}
	m.upstreamErr = nil
	return m, probeUpstreamCmd(m.client, u.ID, ep)
}

// probeUpstreamCmd runs one probe and renders its outcome; it never
// mutates the configuration.
func probeUpstreamCmd(c Client, id string, ep providers.Endpoint) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), upstreamProbeBudget)
		defer cancel()

		results, err := c.Probe(ctx, []providers.Endpoint{ep})
		if err != nil {
			return upstreamProbedMsg{id: id, result: "Нет ответа: " + err.Error()}
		}
		if len(results) == 0 {
			return upstreamProbedMsg{id: id, result: "Нет ответа: проверка не дала результата"}
		}
		return upstreamProbedMsg{id: id, result: renderProbeResult(results[0])}
	}
}

// renderProbeResult turns one probe result into the Russian line the
// upstreams screen shows.
func renderProbeResult(r probe.Result) string {
	switch {
	case r.Err != "":
		if rest, ok := strings.CutPrefix(r.Err, "unexpected reply: "); ok {
			return "Ответил ошибкой: " + rest
		}
		return "Нет ответа: " + r.Err
	default:
		rcode := r.Rcode
		if rcode == "" {
			rcode = "NOERROR"
		}
		ms := float64(r.Latency) / float64(time.Millisecond)
		return fmt.Sprintf("Отвечает: %.1f мс, rcode %s", ms, rcode)
	}
}

// addCatalogEndpoint adds the highlighted provider endpoint and applies
// the config, rejecting an endpoint that is already configured.
func (m Model) addCatalogEndpoint() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	entries := upstreamCatalogEntries()
	if m.picker.cursor < 0 || m.picker.cursor >= len(entries) {
		return m, nil
	}
	e := entries[m.picker.cursor]

	next := cloneConfig(m.upstreamCfg)
	for _, u := range next.Upstreams {
		if u.Transport == e.end.Transport && u.Address == e.end.Address {
			m.upstreamErr = fmt.Errorf("этот upstream уже добавлен: %s", e.end.Address)
			return m, nil
		}
	}

	up := e.end.UpstreamConfig(uniqueUpstreamID(next.Upstreams, e.provider, e.end.Transport), e.name)
	up.Priority = nextUpstreamPriority(next.Upstreams)
	next.Upstreams = append(next.Upstreams, up)
	return m.applyUpstreamCfg(next)
}

// startUpstreamForm opens the custom-upstream form with a fresh state.
func (m Model) startUpstreamForm() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	m.screen = screenUpstreamForm
	m.upstreamFormField = 0
	m.upstreamFormErr = nil
	m.upstreamErr = nil
	m.upstreamForm = upstreamFormState{
		Transport: "plain",
		Priority:  strconv.Itoa(nextUpstreamPriority(m.upstreamCfg.Upstreams)),
	}
	return m, nil
}

// commitUpstreamFormField writes the typed value into the focused form
// field; an empty value keeps the field as it was.
func (m Model) commitUpstreamFormField() (tea.Model, tea.Cmd) {
	i := m.upstreamFormField
	value := strings.TrimSpace(m.input)
	m.inputActive = false
	m.input = ""
	if value == "" {
		m.upstreamFormErr = nil
		return m, nil
	}
	if i == upstreamFormPriority {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			m.upstreamFormErr = errors.New("приоритет: ожидается целое число не меньше нуля")
			return m, nil
		}
	}
	m.upstreamForm.setValue(i, value)
	m.upstreamFormErr = nil
	return m, nil
}

// applyUpstreamForm validates the form through config.Validate and
// applies it; a validation error is shown in place and the config is
// left untouched.
func (m Model) applyUpstreamForm() (tea.Model, tea.Cmd) {
	if m.upstreamCfg == nil {
		m.upstreamFormErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}

	form := m.upstreamForm
	next := cloneConfig(m.upstreamCfg)

	id := strings.TrimSpace(form.ID)
	if id == "" {
		id = uniqueUpstreamID(next.Upstreams, upstreamIDFromAddress(form.Address), form.Transport)
	} else {
		for _, u := range next.Upstreams {
			if u.ID == id {
				m.upstreamFormErr = fmt.Errorf("upstream с таким ID уже есть: %s", id)
				return m, nil
			}
		}
	}

	priority := nextUpstreamPriority(next.Upstreams)
	if raw := strings.TrimSpace(form.Priority); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			m.upstreamFormErr = errors.New("приоритет: ожидается целое число не меньше нуля")
			return m, nil
		}
		priority = n
	}

	name := strings.TrimSpace(form.Name)
	if name == "" {
		name = id
	}
	next.Upstreams = append(next.Upstreams, config.UpstreamConfig{
		ID:         id,
		Name:       name,
		Transport:  form.Transport,
		Address:    strings.TrimSpace(form.Address),
		ServerName: strings.TrimSpace(form.ServerName),
		Priority:   priority,
		Enabled:    true,
	})

	if err := next.Validate(); err != nil {
		m.upstreamFormErr = err
		return m, nil // the config is untouched
	}

	m.screen = screenUpstreams
	m.upstreamFormErr = nil
	m.upstreamErr = nil
	return m.applyUpstreamCfg(next)
}

// upstreamsView renders the detailed upstream table with the row actions.
func (m *Model) upstreamsView() string {
	rows := m.upstreamRows()
	if len(rows) == 0 {
		var b strings.Builder
		b.WriteString(dimStyle.Render("Upstream'ы не настроены — a откроет каталог провайдеров, c добавит свой") + "\n")
		if m.upstreamErr != nil {
			b.WriteString("\n" + errStyle.Render(m.upstreamErr.Error()) + "\n")
		}
		return b.String()
	}

	var b strings.Builder
	strategy := m.status.Strategy
	if m.upstreamCfg != nil && m.upstreamCfg.Strategy != "" {
		strategy = m.upstreamCfg.Strategy
	}
	b.WriteString(titleStyle.Render("Стратегия: " + strategy))
	b.WriteString(dimStyle.Render("  (s — выбрать из списка)"))
	b.WriteString("\n\n")

	b.WriteString(dimStyle.Render("  id           имя                   прот   адрес                  прио задержка    состояние  отправлено/ошибки"))
	b.WriteString("\n")

	for i, row := range rows {
		marker := "  "
		if i == m.upstreamCursor {
			marker = "> "
		}
		live := row.live
		live.Enabled = row.enabled
		if !row.hasLive {
			live.LatencyMS = 0
		}
		sent := "—"
		if row.hasLive {
			sent = fmt.Sprintf("%d/%d", row.live.Sent, row.live.Failed)
		}
		line := fmt.Sprintf("%s%-12s %-21s %-6s %-22s %-4d %-11s %-10s %s",
			marker,
			truncate(row.id, 12),
			truncate(row.name, 21),
			row.transport,
			truncate(row.address, 22),
			row.priority,
			formatLatency(live.LatencyMS),
			healthLabel(live),
			sent,
		)
		if i == m.upstreamCursor {
			line = activeTabStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.probeUpstream != "" && m.probeResult != "" {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("Проверка "+m.probeUpstream+": ") + m.probeResult)
		b.WriteString("\n")
	}

	if m.upstreamErr != nil {
		b.WriteString("\n" + errStyle.Render(m.upstreamErr.Error()) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("space — вкл/выкл · d — удалить · p — приоритет · s — стратегия · t — проверить"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("a — каталог провайдеров · c — свой upstream · j/k — выбор"))
	b.WriteString("\n")

	if m.inputActive && m.inputMode == inputUpstreamPriority {
		b.WriteString("\n")
		hint := ""
		if row, ok := m.selectedUpstreamRow(); ok {
			hint = fmt.Sprintf(" (сейчас %d, пусто — отмена)", row.priority)
		}
		b.WriteString(titleStyle.Render("Приоритет"+hint+": ") + m.input + "▏")
		b.WriteString("\n")
	}
	return b.String()
}

// upstreamCatalogView renders the provider endpoint picker.
func (m *Model) upstreamCatalogView() string {
	m.upstreamCatalogPicker()
	out := m.pickerView(&m.picker)
	if m.upstreamErr != nil {
		out += "\n" + errStyle.Render(m.upstreamErr.Error())
	}
	return out
}

// openUpstreamCatalog opens the provider picker on its first row.
func (m *Model) openUpstreamCatalog() {
	m.pickerReturn = screenUpstreams
	m.picker = picker{title: "Каталог провайдеров"}
	m.upstreamCatalogPicker()
	m.upstreamErr = nil
	m.screen = screenUpstreamCatalog
	m.settleRail()
}

// upstreamCatalogPicker refreshes the picker rows from the live config,
// keeping the cursor.
func (m *Model) upstreamCatalogPicker() {
	entries := upstreamCatalogEntries()
	items := make([]pickerItem, 0, len(entries))
	for _, e := range entries {
		installed := m.upstreamConfigured(e.end)
		status := ""
		if installed {
			status = "добавлен"
		}

		details := []string{
			e.name,
			"Провайдер: " + e.name + " (" + e.provider + ")",
			"Транспорт: " + transportLabel(e.end.Transport) + " (" + e.end.Transport + ")",
			"Адрес: " + e.end.Address,
		}
		if e.end.ServerName != "" {
			details = append(details, "ServerName: "+e.end.ServerName)
		}
		details = append(details, "")
		if e.trust.Label != "" {
			details = append(details, "Доверие: "+e.trust.Label)
		} else {
			details = append(details, "Доверие: нет данных")
		}
		if e.trust.Note != "" {
			details = append(details, e.trust.Note)
		}
		if e.trust.SourceURL != "" {
			details = append(details, "Источник: "+e.trust.SourceName+" — "+e.trust.SourceURL)
		}
		if installed {
			details = append(details,
				"",
				"Дубль: этот транспорт и адрес уже добавлены —",
				"повторный enter будет отклонён.")
		}
		label := e.name + " — " + transportLabel(e.end.Transport) + " · " + e.end.Address
		items = append(items, pickerItem{Label: label, Status: status, Details: details})
	}
	m.picker.setItems(items)
}

// upstreamConfigured reports whether the endpoint is already added.
func (m *Model) upstreamConfigured(ep providers.Endpoint) bool {
	if m.upstreamCfg == nil {
		return false
	}
	for _, u := range m.upstreamCfg.Upstreams {
		if u.Transport == ep.Transport && u.Address == ep.Address {
			return true
		}
	}
	return false
}

// strategyPickerView renders the routing-strategy picker.
func (m *Model) strategyPickerView() string {
	m.strategyPickerItems()
	return m.pickerView(&m.picker)
}

// openStrategyPicker opens the strategy list on the current value.
func (m Model) openStrategyPicker() (tea.Model, tea.Cmd) {
	m.pickerReturn = m.screen
	if m.pickerReturn != screenSettings {
		m.pickerReturn = screenUpstreams
	}
	cfg := m.strategyConfig()
	if cfg == nil {
		if m.pickerReturn == screenSettings {
			m.settingsErr = errors.New("конфигурация ещё не загружена")
			return m, loadConfig(m.client)
		}
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	m.picker = picker{title: "Стратегия маршрутизации"}
	m.strategyPickerItems()
	current := cfg.Strategy
	if current == "" {
		current = m.status.Strategy
	}
	for i, name := range strategyNames {
		if name == current {
			m.picker.cursor = i
		}
	}
	m.screen = screenStrategyPicker
	m.settleRail()
	return m, nil
}

// strategyConfig returns the config the strategy picker edits.
func (m *Model) strategyConfig() *config.Config {
	if m.pickerReturn == screenSettings {
		return m.settingsCfg
	}
	return m.upstreamCfg
}

// strategyPickerItems fills the strategy rows and marks the current one.
func (m *Model) strategyPickerItems() {
	current := ""
	if cfg := m.strategyConfig(); cfg != nil {
		current = cfg.Strategy
	}
	if current == "" {
		current = m.status.Strategy
	}
	items := make([]pickerItem, 0, len(strategyNames))
	for _, name := range strategyNames {
		status := ""
		if name == current {
			status = "сейчас"
		}
		items = append(items, pickerItem{
			Label:   name,
			Status:  status,
			Details: strategyDetails(name),
		})
	}
	m.picker.setItems(items)
}

// strategyDetails explains one routing strategy.
func strategyDetails(name string) []string {
	switch name {
	case "failover":
		return []string{
			"Отказоустойчивость: запросы идут к первому здоровому upstream'у по приоритету (p), остальные ждут в резерве.",
			"Предсказуемый порядок; при сбое — переключение на следующий.",
		}
	case "round_robin":
		return []string{
			"По кругу распределяет запросы между здоровыми upstream'ами.",
			"Ровная нагрузка без учёта задержки.",
		}
	case "random":
		return []string{
			"Выбирает случайный здоровый upstream.",
			"Простое распределение нагрузки без измерений.",
		}
	default:
		return []string{
			"Самый быстрый: выбирает upstream по измеренным задержкам и состоянию здоровья (t — проверить вручную).",
			"Подходит для повседневного использования.",
		}
	}
}

// applyStrategyPick applies the highlighted strategy and returns to the
// screen the picker was opened from.
func (m Model) applyStrategyPick() (tea.Model, tea.Cmd) {
	if m.picker.cursor < 0 || m.picker.cursor >= len(strategyNames) {
		return m, nil
	}
	strategy := strategyNames[m.picker.cursor]

	if m.pickerReturn == screenSettings {
		m.screen = screenSettings
		m.settleRail()
		if m.settingsCfg == nil {
			m.settingsErr = errors.New("конфигурация ещё не загружена")
			return m, loadConfig(m.client)
		}
		// Stage the choice like the timezone picker: ctrl+s applies it.
		next := cloneConfig(m.settingsCfg)
		next.Strategy = strategy
		m.settingsCfg = next
		m.settingsErr = nil
		return m, nil
	}

	m.screen = screenUpstreams
	m.settleRail()
	if m.upstreamCfg == nil {
		m.upstreamErr = errors.New("конфигурация ещё не загружена")
		return m, loadUpstreamConfig(m.client)
	}
	next := cloneConfig(m.upstreamCfg)
	next.Strategy = strategy
	m.upstreamErr = nil
	return m.applyUpstreamCfg(next)
}

// transportPickerView renders the transport picker of the custom form.
func (m *Model) transportPickerView() string {
	m.transportPickerItems()
	return m.pickerView(&m.picker)
}

// openTransportPicker opens the transport list on the form's value.
func (m Model) openTransportPicker() (tea.Model, tea.Cmd) {
	m.pickerReturn = screenUpstreamForm
	m.picker = picker{title: "Транспорт upstream"}
	m.transportPickerItems()
	for i, t := range upstreamTransports {
		if t == m.upstreamForm.Transport {
			m.picker.cursor = i
		}
	}
	m.screen = screenTransportPicker
	m.settleRail()
	return m, nil
}

// transportPickerItems fills the transport rows.
func (m *Model) transportPickerItems() {
	items := make([]pickerItem, 0, len(upstreamTransports))
	for _, t := range upstreamTransports {
		status := ""
		if t == m.upstreamForm.Transport {
			status = "сейчас"
		}
		items = append(items, pickerItem{
			Label:   transportLabel(t),
			Status:  status,
			Details: transportDetails(t),
		})
	}
	m.picker.setItems(items)
}

// transportDetails describes the address format of one transport.
func transportDetails(transport string) []string {
	switch transport {
	case "dot":
		return []string{
			"DNS-over-TLS: адрес host:port, обычно :853.",
			"Шифрование TLS; для адреса по IP задайте ServerName —",
			"он уходит в SNI и проверяется по сертификату.",
		}
	case "doh":
		return []string{
			"DNS-over-HTTPS: адрес — https-URL, например",
			"https://dns.example.com/dns-query.",
			"ServerName не нужен: имя берётся из URL.",
		}
	case "doq":
		return []string{
			"DNS-over-QUIC: адрес host:port, обычно :853.",
			"QUIC + TLS; для адреса по IP задайте ServerName,",
			"он нужен для проверки сертификата.",
		}
	default:
		return []string{
			"Обычный DNS: адрес host:port, например 1.1.1.1:53.",
			"Без шифрования; подходит для локальных резолверов.",
		}
	}
}

// applyTransportPick writes the highlighted transport into the form and
// returns; the config is untouched until ctrl+s.
func (m Model) applyTransportPick() (tea.Model, tea.Cmd) {
	if m.picker.cursor < 0 || m.picker.cursor >= len(upstreamTransports) {
		return m, nil
	}
	m.upstreamForm.Transport = upstreamTransports[m.picker.cursor]
	m.screen = screenUpstreamForm
	m.settleRail()
	return m, nil
}

// upstreamFormView renders the custom-upstream form.
func (m *Model) upstreamFormView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Новый upstream"))
	b.WriteString(dimStyle.Render("  (j/k — поля, enter — изменить/сменить транспорт, ctrl+s — применить, esc — отмена)") + "\n\n")

	for i, name := range upstreamFormFields {
		marker := "  "
		if i == m.upstreamFormField {
			marker = "> "
		}
		value := m.upstreamForm.value(i)
		if value == "" {
			value = dimStyle.Render("—")
		}
		line := fmt.Sprintf("%s%-36s %s", marker, name, value)
		if i == m.upstreamFormField {
			line = activeTabStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.inputActive && m.inputMode == inputUpstreamFormField {
		b.WriteString("\n")
		b.WriteString(titleStyle.Render(upstreamFormFields[m.upstreamFormField]+": ") + m.input + "▏")
		b.WriteString("\n")
	}

	if m.upstreamFormErr != nil {
		b.WriteString("\n")
		b.WriteString(errStyle.Render("Ошибка: " + m.upstreamFormErr.Error()))
		b.WriteString("\n")
	}
	return b.String()
}
