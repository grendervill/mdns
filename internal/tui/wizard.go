package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/links"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// stage is one wizard step.
type stage int

const (
	stageDomain stage = iota
	stageTLS
	stageProtocols
	stageProviders
	stageStrategy
	stageFilters
	stageSummary
)

// stageNames labels the steps for the header.
var stageNames = []string{
	"Домен",
	"Сертификат",
	"Протоколы и порты",
	"DNS-провайдеры",
	"Стратегия",
	"Фильтрация",
	"Итог",
}

// WizardBackend is the environment the wizard works against: the local
// setup backend before the first run, or the daemon API from the TUI.
type WizardBackend interface {
	Load() (*config.Config, error)
	Save(cfg *config.Config) error
	Providers() []providers.Provider
	Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result
}

// probeTarget pairs a provider with the endpoint being probed.
type probeTarget struct {
	id       string
	endpoint providers.Endpoint
}

// wizardRow is one row of the providers list (a section header or a
// provider).
type wizardRow struct {
	header   string
	provider *providers.Provider
}

// wizardProbeMsg carries fresh probe results by provider ID.
type wizardProbeMsg struct{ byID map[string]probe.Result }

// wizardProbeTickMsg re-runs the probes.
type wizardProbeTickMsg struct{}

// WizardModel is the setup wizard.
type WizardModel struct {
	backend   WizardBackend
	providers []providers.Provider

	cfg    *config.Config
	stage  stage
	cursor int

	selected  map[string]bool
	transport map[string]string
	probes    map[string]probe.Result

	inputActive bool
	inputTarget string
	input       string

	width, height int
	err           error
	saved         bool
}

// NewWizard loads the current configuration and starts at step one.
func NewWizard(b WizardBackend) (WizardModel, error) {
	cfg, err := b.Load()
	if err != nil {
		return WizardModel{}, err
	}

	w := WizardModel{
		backend:   b,
		providers: b.Providers(),
		cfg:       cloneConfig(cfg),
		selected:  make(map[string]bool),
		transport: make(map[string]string),
		probes:    make(map[string]probe.Result),
	}
	w.stage = stageDomain
	w.inputActive = true
	w.inputTarget = "domain"
	w.input = ""
	return w, nil
}

// Saved reports whether the configuration was written.
func (w *WizardModel) Saved() bool { return w.saved }

// Summary renders the closing summary, links included.
func (w *WizardModel) Summary() string {
	var b strings.Builder

	b.WriteString("Готово! Настройка сохранена.\n\n")
	b.WriteString("Домен: " + w.cfg.Domain + "\n")
	b.WriteString("Сертификат: " + w.cfg.TLS.Mode + "\n")

	b.WriteString("Протоколы: ")
	protos := make([]string, 0, 4)
	for _, p := range []struct {
		name string
		on   bool
		port int
	}{
		{"plain", w.cfg.Protocols.Plain.Enabled, w.cfg.Protocols.Plain.Port},
		{"DoH", w.cfg.Protocols.DoH.Enabled, w.cfg.Protocols.DoH.Port},
		{"DoT", w.cfg.Protocols.DoT.Enabled, w.cfg.Protocols.DoT.Port},
		{"DoQ", w.cfg.Protocols.DoQ.Enabled, w.cfg.Protocols.DoQ.Port},
	} {
		if p.on {
			protos = append(protos, fmt.Sprintf("%s:%d", p.name, p.port))
		}
	}
	b.WriteString(strings.Join(protos, ", ") + "\n")

	b.WriteString("Провайдеры:\n")
	for _, u := range w.cfg.Upstreams {
		b.WriteString(fmt.Sprintf("  %s (%s) — %s\n", u.Name, u.Transport, u.Address))
	}
	b.WriteString("Стратегия: " + w.cfg.Strategy + "\n")
	if w.cfg.Filter.Enabled {
		b.WriteString(fmt.Sprintf("Фильтрация: включена, списков %d\n", len(w.cfg.Filter.Lists)))
	} else {
		b.WriteString("Фильтрация: выключена\n")
	}

	b.WriteString("\nСсылки для устройств:\n")
	for _, l := range links.Links(w.cfg) {
		b.WriteString(fmt.Sprintf("  %s — %s\n", l.Title, l.URI))
	}
	return b.String()
}

// Init implements tea.Model.
func (w WizardModel) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (w WizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		w.width, w.height = msg.Width, msg.Height
		return w, nil

	case wizardProbeMsg:
		for id, r := range msg.byID {
			w.probes[id] = r
		}
		if w.stage == stageProviders {
			return w, tea.Tick(time.Second, func(time.Time) tea.Msg { return wizardProbeTickMsg{} })
		}
		return w, nil

	case wizardProbeTickMsg:
		if w.stage != stageProviders {
			return w, nil
		}
		return w, wizardProbeCmd(w.backend, w.probeTargets())

	case tea.KeyMsg:
		return w.handleKey(msg)
	}
	return w, nil
}

// handleKey processes one key press.
func (w WizardModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if w.inputActive {
		return w.handleInputKey(msg)
	}

	switch msg.String() {
	case "ctrl+c":
		return w, tea.Quit
	case "esc":
		if w.stage > stageDomain {
			return w, w.enterStage(w.stage - 1)
		}
		return w, nil
	case "n":
		if w.stage < stageSummary {
			return w, w.enterStage(w.stage + 1)
		}
		return w, nil
	}

	switch w.stage {
	case stageDomain:
		if msg.String() == "enter" {
			w.inputActive = true
			w.inputTarget = "domain"
			w.input = w.cfg.Domain
		}

	case stageTLS:
		switch msg.String() {
		case "j", "down":
			if w.cursor < 1 {
				w.cursor++
			}
		case "k", "up":
			if w.cursor > 0 {
				w.cursor--
			}
		case "enter":
			w.err = nil
			if w.cursor == 0 {
				w.cfg.TLS = config.TLS{Mode: "self-signed"}
				return w, nil
			}
			w.cfg.TLS = config.TLS{Mode: "files"}
			w.openInput("cert", "")
		}

	case stageProtocols:
		switch msg.String() {
		case "j", "down":
			if w.cursor < 3 {
				w.cursor++
			}
		case "k", "up":
			if w.cursor > 0 {
				w.cursor--
			}
		case "enter":
			w.toggleProtocol()
		case "p":
			name := protocolNames[w.cursor]
			w.openInput("port:"+name, "")
		}

	case stageProviders:
		switch msg.String() {
		case "j", "down":
			w.moveProviderCursor(1)
		case "k", "up":
			w.moveProviderCursor(-1)
		case "enter":
			if p := w.currentProvider(); p != nil {
				w.selected[p.ID] = !w.selected[p.ID]
				if w.selected[p.ID] && w.transport[p.ID] == "" {
					w.transport[p.ID] = defaultTransportOf(*p)
				}
			}
		case "t":
			if p := w.currentProvider(); p != nil {
				w.cycleTransport(*p)
			}
		}

	case stageStrategy:
		switch msg.String() {
		case "j", "down":
			if w.cursor < len(strategyNames)-1 {
				w.cursor++
			}
		case "k", "up":
			if w.cursor > 0 {
				w.cursor--
			}
		case "enter":
			w.cfg.Strategy = strategyNames[w.cursor]
		}

	case stageFilters:
		switch msg.String() {
		case "j", "down":
			if w.cursor < len(filterPresetNames)-1 {
				w.cursor++
			}
		case "k", "up":
			if w.cursor > 0 {
				w.cursor--
			}
		case "enter":
			w.applyFilterPreset()
		}

	case stageSummary:
		if msg.String() == "enter" {
			return w.save()
		}
	}
	return w, nil
}

// handleInputKey processes keys while an input is open.
func (w WizardModel) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		w.inputActive = false
		w.input = ""
		return w, nil
	case tea.KeyEnter:
		return w.commitInput()
	case tea.KeyBackspace:
		runes := []rune(w.input)
		if len(runes) > 0 {
			w.input = string(runes[:len(runes)-1])
		}
		return w, nil
	case tea.KeySpace:
		w.input += " "
		return w, nil
	case tea.KeyRunes:
		w.input += string(msg.Runes)
		return w, nil
	}
	return w, nil
}

// openInput starts an input line.
func (w *WizardModel) openInput(target, prefill string) {
	w.inputActive = true
	w.inputTarget = target
	w.input = prefill
}

// enterStage switches steps and arms the step's behaviour.
func (w *WizardModel) enterStage(s stage) tea.Cmd {
	w.stage = s
	w.cursor = 0
	w.inputActive = false
	w.err = nil

	if s == stageProviders {
		w.moveProviderCursor(1) // skip the first section header
		return wizardProbeCmd(w.backend, w.probeTargets())
	}
	return nil
}

// commitInput applies the open input line.
func (w WizardModel) commitInput() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(w.input)

	switch {
	case w.inputTarget == "domain":
		if value == "" {
			w.err = errors.New("домен не может быть пустым")
			return w, nil
		}
		if strings.Contains(value, "://") || strings.ContainsAny(value, " \t/") {
			w.err = errors.New("домен без схемы и без пути, например dns.example.com")
			return w, nil
		}
		w.cfg.Domain = value
		w.inputActive = false
		w.input = ""
		w.err = nil
		return w, w.enterStage(stageTLS)

	case w.inputTarget == "cert":
		if value == "" {
			w.err = errors.New("путь к сертификату не может быть пустым")
			return w, nil
		}
		w.cfg.TLS.CertFile = value
		w.openInput("key", "")
		return w, nil

	case w.inputTarget == "key":
		if value == "" {
			w.err = errors.New("путь к ключу не может быть пустым")
			return w, nil
		}
		w.cfg.TLS.KeyFile = value
		w.inputActive = false
		w.input = ""
		return w, w.enterStage(stageProtocols)

	case strings.HasPrefix(w.inputTarget, "port:"):
		name := strings.TrimPrefix(w.inputTarget, "port:")
		port := defaultPort(name)
		if value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 65535 {
				w.err = fmt.Errorf("порт %q: нужно число 1-65535", value)
				return w, nil
			}
			port = n
		}
		w.setPort(name, port)
		w.inputActive = false
		w.input = ""
		w.err = nil
		return w, nil
	}

	w.inputActive = false
	return w, nil
}

// protocolNames maps the protocols row order to names.
var protocolNames = []string{"plain", "doh", "dot", "doq"}

// defaultPort returns the standard port of a protocol.
func defaultPort(name string) int {
	switch name {
	case "plain":
		return 53
	case "doh":
		return 443
	default:
		return 853
	}
}

// setPort writes a protocol's port by name.
func (w *WizardModel) setPort(name string, port int) {
	switch name {
	case "plain":
		w.cfg.Protocols.Plain.Port = port
	case "doh":
		w.cfg.Protocols.DoH.Port = port
	case "dot":
		w.cfg.Protocols.DoT.Port = port
	case "doq":
		w.cfg.Protocols.DoQ.Port = port
	}
}

// toggleProtocol flips the protocol under the cursor.
func (w *WizardModel) toggleProtocol() {
	switch protocolNames[w.cursor] {
	case "plain":
		w.cfg.Protocols.Plain.Enabled = !w.cfg.Protocols.Plain.Enabled
	case "doh":
		w.cfg.Protocols.DoH.Enabled = !w.cfg.Protocols.DoH.Enabled
	case "dot":
		w.cfg.Protocols.DoT.Enabled = !w.cfg.Protocols.DoT.Enabled
	case "doq":
		w.cfg.Protocols.DoQ.Enabled = !w.cfg.Protocols.DoQ.Enabled
	}
}

// strategyNames is the strategy chooser's order.
var strategyNames = []string{"fastest", "failover", "round_robin", "random"}

// filterPresetNames is the filter presets' order.
var filterPresetNames = []string{"Выключено", "Базовый", "Строгий", "Свой набор"}

// applyFilterPreset applies the selected filter preset.
func (w *WizardModel) applyFilterPreset() {
	switch w.cursor {
	case 0:
		w.cfg.Filter.Enabled = false
		w.cfg.Filter.Lists = nil
	case 1:
		w.cfg.Filter.Enabled = true
		w.cfg.Filter.Lists = presetLists("basic")
	case 2:
		w.cfg.Filter.Enabled = true
		w.cfg.Filter.Lists = presetLists("strict")
	case 3:
		w.cfg.Filter.Enabled = true
		w.cfg.Filter.Lists = nil
	}
}

// presetLists converts a catalog preset into config lists.
func presetLists(name string) []config.FilterList {
	ids, ok := filter.Preset(name)
	if !ok {
		return nil
	}
	out := make([]config.FilterList, 0, len(ids))
	for _, id := range ids {
		out = append(out, config.FilterList{ID: id})
	}
	return out
}

// providerRows flattens sections and providers for the list.
func (w *WizardModel) providerRows() []wizardRow {
	var rows []wizardRow
	rows = append(rows, wizardRow{header: "Без фильтров"})
	for i := range w.providers {
		if w.providers[i].Section == providers.SectionPlain {
			rows = append(rows, wizardRow{provider: &w.providers[i]})
		}
	}
	rows = append(rows, wizardRow{header: "С фильтрами"})
	for i := range w.providers {
		if w.providers[i].Section == providers.SectionBlocking {
			rows = append(rows, wizardRow{provider: &w.providers[i]})
		}
	}
	return rows
}

// currentProvider returns the provider under the cursor, if any.
func (w *WizardModel) currentProvider() *providers.Provider {
	rows := w.providerRows()
	if w.cursor < 0 || w.cursor >= len(rows) {
		return nil
	}
	return rows[w.cursor].provider
}

// moveProviderCursor moves the cursor, skipping section headers.
func (w *WizardModel) moveProviderCursor(delta int) {
	rows := w.providerRows()
	next := w.cursor
	for {
		next += delta
		if next < 0 || next >= len(rows) {
			return
		}
		if rows[next].provider != nil {
			w.cursor = next
			return
		}
	}
}

// defaultTransportOf picks the preferred transport of a provider.
func defaultTransportOf(p providers.Provider) string {
	for _, pref := range []string{"doh", "dot", "doq", "plain"} {
		for _, e := range p.AllEndpoints() {
			if e.Transport == pref {
				return pref
			}
		}
	}
	return "plain"
}

// cycleTransport moves to the next available transport.
func (w *WizardModel) cycleTransport(p providers.Provider) {
	available := make([]string, 0, 4)
	for _, pref := range []string{"doh", "dot", "doq", "plain"} {
		for _, e := range p.AllEndpoints() {
			if e.Transport == pref {
				available = append(available, pref)
				break
			}
		}
	}
	if len(available) == 0 {
		return
	}

	cur := w.transport[p.ID]
	if cur == "" {
		cur = defaultTransportOf(p)
	}
	for i, t := range available {
		if t == cur {
			w.transport[p.ID] = available[(i+1)%len(available)]
			return
		}
	}
	w.transport[p.ID] = available[0]
}

// pickEndpoint returns the endpoint of the provider for a transport.
func pickEndpoint(p providers.Provider, transport string) (providers.Endpoint, bool) {
	for _, e := range p.AllEndpoints() {
		if e.Transport == transport {
			return e, true
		}
	}
	if eps := p.AllEndpoints(); len(eps) > 0 {
		return eps[0], true
	}
	return providers.Endpoint{}, false
}

// probeTargets builds the list of endpoints to probe.
func (w *WizardModel) probeTargets() []probeTarget {
	targets := make([]probeTarget, 0, len(w.providers))
	for _, p := range w.providers {
		tr := w.transport[p.ID]
		if tr == "" {
			tr = defaultTransportOf(p)
		}
		if ep, ok := pickEndpoint(p, tr); ok {
			targets = append(targets, probeTarget{id: p.ID, endpoint: ep})
		}
	}
	return targets
}

// wizardProbeCmd measures the targets and reports them by provider ID.
func wizardProbeCmd(b WizardBackend, targets []probeTarget) tea.Cmd {
	return func() tea.Msg {
		eps := make([]providers.Endpoint, len(targets))
		for i, t := range targets {
			eps[i] = t.endpoint
		}
		results := b.Probe(context.Background(), eps)

		byID := make(map[string]probe.Result, len(targets))
		for i, t := range targets {
			if i < len(results) {
				byID[t.id] = results[i]
			}
		}
		return wizardProbeMsg{byID: byID}
	}
}

// buildUpstreams converts the selection into upstream configs.
func (w *WizardModel) buildUpstreams() []config.UpstreamConfig {
	var ups []config.UpstreamConfig
	prio := 0
	for _, p := range w.providers {
		if !w.selected[p.ID] {
			continue
		}
		tr := w.transport[p.ID]
		if tr == "" {
			tr = defaultTransportOf(p)
		}
		ep, ok := pickEndpoint(p, tr)
		if !ok {
			continue
		}
		uc := ep.UpstreamConfig(p.ID, p.Name)
		uc.Priority = prio
		prio++
		ups = append(ups, uc)
	}
	return ups
}

// save validates and writes the configuration.
func (w WizardModel) save() (tea.Model, tea.Cmd) {
	w.cfg.Upstreams = w.buildUpstreams()
	if len(w.cfg.Upstreams) == 0 {
		w.err = errors.New("выберите хотя бы одного DNS-провайдера")
		return w, nil
	}
	if err := w.cfg.Validate(); err != nil {
		w.err = err
		return w, nil
	}
	if err := w.backend.Save(w.cfg); err != nil {
		w.err = err
		return w, nil
	}
	w.saved = true
	return w, tea.Quit
}

// View implements tea.Model.
func (w WizardModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(fmt.Sprintf("Мастер настройки — шаг %d/7: %s", int(w.stage)+1, stageNames[w.stage])))
	b.WriteString("\n\n")

	switch w.stage {
	case stageDomain:
		b.WriteString("Введите домен, привязанный к этому серверу (A-запись уже должна указывать на него).\n")
	case stageTLS:
		b.WriteString("Как выпускать TLS-сертификат?\n\n")
		options := []string{
			"Самоподписанный (быстрый старт; устройствам нужно доверие)",
			"Свои файлы сертификата (cert + key)",
		}
		for i, opt := range options {
			marker := "  "
			if i == w.cursor {
				marker = "> "
			}
			b.WriteString(marker + opt + "\n")
		}
		b.WriteString("\n" + dimStyle.Render("Let's Encrypt появится в следующем обновлении (план ACME)."))
		b.WriteString("\n")
	case stageProtocols:
		b.WriteString("Протоколы и порты (enter — вкл/выкл, p — порт):\n\n")
		for i, name := range protocolNames {
			marker := "  "
			if i == w.cursor {
				marker = "> "
			}
			state := "выкл"
			port := 0
			switch name {
			case "plain":
				state, port = onOff(w.cfg.Protocols.Plain.Enabled), w.cfg.Protocols.Plain.Port
			case "doh":
				state, port = onOff(w.cfg.Protocols.DoH.Enabled), w.cfg.Protocols.DoH.Port
			case "dot":
				state, port = onOff(w.cfg.Protocols.DoT.Enabled), w.cfg.Protocols.DoT.Port
			case "doq":
				state, port = onOff(w.cfg.Protocols.DoQ.Enabled), w.cfg.Protocols.DoQ.Port
			}
			b.WriteString(fmt.Sprintf("%s%-6s %-5s порт %d\n", marker, name, state, port))
		}
	case stageProviders:
		b.WriteString("Выберите провайдеров (enter — вкл/выкл, t — протокол обращения):\n\n")
		for i, row := range w.providerRows() {
			if row.provider == nil {
				b.WriteString("\n" + dimStyle.Render(row.header) + "\n")
				continue
			}
			marker := "  "
			if i == w.cursor {
				marker = "> "
			}
			checked := "[ ]"
			if w.selected[row.provider.ID] {
				checked = "[x]"
			}
			tr := w.transport[row.provider.ID]
			if tr == "" {
				tr = defaultTransportOf(*row.provider)
			}
			lat := "…"
			if r, ok := w.probes[row.provider.ID]; ok {
				if r.Err != "" {
					lat = "недоступен"
				} else {
					lat = formatLatency(float64(r.Latency.Microseconds()) / 1000)
				}
			}
			b.WriteString(fmt.Sprintf("%s%s %-24s %-6s %s\n", marker, checked, row.provider.Name, tr, lat))
		}
	case stageStrategy:
		b.WriteString("Как выбирать провайдера для каждого запроса?\n\n")
		for i, name := range strategyNames {
			marker := "  "
			if i == w.cursor {
				marker = "> "
			}
			note := ""
			switch name {
			case "fastest":
				note = "— самый быстрый (рекомендуется)"
			case "failover":
				note = "— по порядку с переходом при сбое"
			case "round_robin":
				note = "— по кругу"
			case "random":
				note = "— случайно"
			}
			b.WriteString(fmt.Sprintf("%s%-12s %s\n", marker, name, note))
		}
	case stageFilters:
		b.WriteString("Фильтрация рекламы и трекеров (настраивается подробно позже):\n\n")
		for i, name := range filterPresetNames {
			marker := "  "
			if i == w.cursor {
				marker = "> "
			}
			b.WriteString(marker + name + "\n")
		}
	case stageSummary:
		b.WriteString("Проверьте настройки:\n\n")
		b.WriteString(fmt.Sprintf("  Домен: %s\n", w.cfg.Domain))
		b.WriteString(fmt.Sprintf("  TLS: %s\n", w.cfg.TLS.Mode))
		b.WriteString(fmt.Sprintf("  Стратегия: %s\n", w.cfg.Strategy))
		b.WriteString(fmt.Sprintf("  Фильтрация: %v (%d списков)\n", w.cfg.Filter.Enabled, len(w.cfg.Filter.Lists)))
		b.WriteString("  Провайдеры:\n")
		for _, u := range w.buildUpstreams() {
			b.WriteString(fmt.Sprintf("    %s (%s) — %s\n", u.Name, u.Transport, u.Address))
		}
		preview := cloneConfig(w.cfg)
		preview.Upstreams = w.buildUpstreams()
		b.WriteString("\n")
		for _, l := range links.Links(preview) {
			b.WriteString(fmt.Sprintf("  %-28s %s\n", l.Title, l.URI))
		}
		b.WriteString("\n" + titleStyle.Render("enter — сохранить и выйти"))
	}

	if w.inputActive {
		b.WriteString("\n")
		b.WriteString(titleStyle.Render(inputPrompt(w.inputTarget)) + " " + w.input + "▏")
		b.WriteString("\n")
	}
	if w.err != nil {
		b.WriteString("\n")
		b.WriteString(errStyle.Render("Ошибка: " + w.err.Error()))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("enter — выбор · n — далее · esc — назад · ctrl+c — выход"))
	return b.String()
}

// inputPrompt names the open input.
func inputPrompt(target string) string {
	switch {
	case target == "domain":
		return "Домен:"
	case target == "cert":
		return "Путь к сертификату (PEM):"
	case target == "key":
		return "Путь к ключу (PEM):"
	case strings.HasPrefix(target, "port:"):
		name := strings.TrimPrefix(target, "port:")
		return fmt.Sprintf("Порт для %s (Enter — стандартный %d):", name, defaultPort(name))
	}
	return "Значение:"
}

// onOff renders a boolean as Russian text.
func onOff(v bool) string {
	if v {
		return "вкл"
	}
	return "выкл"
}

// Run starts the wizard in the alternate screen.
func (w WizardModel) Run() error {
	_, err := tea.NewProgram(w, tea.WithAltScreen()).Run()
	return err
}
