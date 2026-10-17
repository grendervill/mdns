package tui

import (
	"context"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/qlog"
	"mydns/internal/tlscert"
)

// screen identifies one top-level view.
type screen int

const (
	screenStatus screen = iota
	screenWizard
	screenRequests
	screenUpstreams
	screenFilters
	screenSettings
	screenHelp
)

// screenTabs is the navigation order; digits 1-7 select these.
var screenTabs = []struct {
	name   string
	screen screen
}{
	{"Статус", screenStatus},
	{"Визард", screenWizard},
	{"Запросы", screenRequests},
	{"Upstream'ы", screenUpstreams},
	{"Фильтры", screenFilters},
	{"Настройки", screenSettings},
	{"Помощь", screenHelp},
}

// Options configure the model.
type Options struct {
	// Initial names the starting screen ("status", "requests", ...);
	// empty means status.
	Initial string
}

// Model is the root bubbletea model of the TUI.
type Model struct {
	client Client
	opts   Options

	screen screen
	width  int
	height int

	status    api.Status
	statusErr error

	events <-chan api.Event

	requests       []qlog.Entry
	requestsPaused bool
	requestsScroll int

	filterLists  []filter.ListStatus
	filterCursor int
	filterErr    error

	settingsCfg    *config.Config
	settingsCursor int
	settingsErr    error

	inputActive bool
	inputMode   inputMode
	inputField  int
	input       string

	wizard        *WizardModel
	wizardLoading bool
	wizardNote    string

	ctx    context.Context
	cancel context.CancelFunc
}

// New builds the TUI model over the given client.
func New(c Client, opts Options) Model {
	ctx, cancel := context.WithCancel(context.Background())
	m := Model{client: c, opts: opts, ctx: ctx, cancel: cancel}
	m.screen = parseScreen(opts.Initial)
	return m
}

// parseScreen maps an initial screen name; unknown names mean status.
func parseScreen(name string) screen {
	switch strings.ToLower(name) {
	case "wizard", "визард":
		return screenWizard
	case "requests", "запросы":
		return screenRequests
	case "upstreams", "upstream":
		return screenUpstreams
	case "filters", "фильтры":
		return screenFilters
	case "settings", "настройки":
		return screenSettings
	case "help", "помощь":
		return screenHelp
	default:
		return screenStatus
	}
}

// Message types shared across the model files.
type (
	statusLoadedMsg struct {
		st  api.Status
		err error
	}
	eventsReadyMsg struct {
		ch  <-chan api.Event
		err error
	}
	eventMsg        struct{ e api.Event }
	eventsClosedMsg struct{}

	filterLoadedMsg struct {
		lists []filter.ListStatus
		err   error
	}
	filterUpdatedMsg struct{ err error }

	configLoadedMsg struct {
		cfg *config.Config
		err error
	}
	configAppliedMsg struct{ err error }

	requestsLoadedMsg struct {
		entries []qlog.Entry
		err     error
	}

	// eventsRetryMsg re-opens the event stream after eventsRetryDelay.
	eventsRetryMsg struct{}
)

// fetchStatus loads the status snapshot.
func fetchStatus(c Client) tea.Cmd {
	return func() tea.Msg {
		st, err := c.Status(context.Background())
		return statusLoadedMsg{st: st, err: err}
	}
}

// subscribe opens the live event stream.
func subscribe(c Client, ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		ch, err := c.Events(ctx)
		return eventsReadyMsg{ch: ch, err: err}
	}
}

// waitEvents reads one event from the stream.
func waitEvents(ch <-chan api.Event) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return eventsClosedMsg{}
		}
		return eventMsg{e: e}
	}
}

// eventsRetryDelay is the pause before re-opening the event stream.
var eventsRetryDelay = 2 * time.Second

// resubscribe schedules a new subscribe attempt after a pause, so a
// daemon restart or a dropped socket heals without a TUI restart.
func resubscribe() tea.Cmd {
	return tea.Tick(eventsRetryDelay, func(time.Time) tea.Msg { return eventsRetryMsg{} })
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(fetchStatus(m.client), subscribe(m.client, m.ctx))
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// The embedded wizard owns keys while its tab is active; its probes
	// keep refreshing even when the user looks at other screens.
	if m.wizard != nil {
		switch msg := msg.(type) {
		case tea.WindowSizeMsg:
			m.width, m.height = msg.Width, msg.Height
			return m.forwardToWizard(msg)

		case wizardProbeMsg, wizardProbeTickMsg:
			if m.screen == screenWizard {
				return m.forwardToWizard(msg)
			}
			// Parked on another screen: the chain dies here and
			// re-entering the wizard restarts it.

		case tea.KeyMsg:
			if m.screen == screenWizard {
				s := msg.String()
				if !m.wizard.inputActive && (s == "q" || isScreenDigit(s)) {
					break // navigation and quit stay global
				}
				return m.forwardToWizard(msg)
			}
		}
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case wizardOpenedMsg:
		m.wizardLoading = false
		if msg.err != nil {
			m.wizardNote = "Не удалось открыть мастер: " + msg.err.Error()
			return m, nil
		}
		m.wizard = &msg.w
		return m, nil

	case wizardDoneMsg:
		m.wizard = nil
		if !msg.saved {
			m.wizardNote = "Мастер закрыт без сохранения — настройки не изменены."
			return m, nil
		}
		m.wizardNote = "Мастер: настройки сохранены и применены."
		m.settingsCfg = nil // the settings screen reloads the fresh config
		m.screen = screenStatus
		return m, fetchStatus(m.client)

	case statusLoadedMsg:
		if msg.err != nil {
			m.statusErr = msg.err
		} else {
			m.status = msg.st
			m.statusErr = nil
		}
		return m, nil

	case eventsReadyMsg:
		if msg.err != nil {
			return m, resubscribe() // the daemon may come back
		}
		m.events = msg.ch
		return m, waitEvents(msg.ch)

	case eventMsg:
		m.applyEvent(msg.e)
		if m.events != nil {
			return m, waitEvents(m.events)
		}
		return m, nil

	case eventsClosedMsg:
		m.events = nil
		return m, resubscribe()

	case eventsRetryMsg:
		return m, subscribe(m.client, m.ctx)

	case filterLoadedMsg:
		m.filterLists = msg.lists
		m.filterErr = msg.err
		if m.filterCursor >= len(m.filterLists) {
			m.filterCursor = 0
		}
		return m, nil

	case filterUpdatedMsg:
		return m.applyFilterUpdateResult(msg.err)

	case configLoadedMsg:
		m.settingsCfg = msg.cfg
		m.settingsErr = msg.err
		return m, nil

	case configAppliedMsg:
		if msg.err != nil {
			m.settingsErr = msg.err
			m.filterErr = msg.err
			return m, nil
		}
		m.settingsErr = nil
		m.filterErr = nil
		return m, fetchStatus(m.client)

	case requestsLoadedMsg:
		if msg.err == nil {
			m.requests = msg.entries
			if len(m.requests) > requestsCap {
				m.requests = m.requests[len(m.requests)-requestsCap:]
			}
			m.requestsScroll = 0 // follow the newest entry
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// refreshCmd reloads the data of the active screen.
func (m Model) refreshCmd() tea.Cmd {
	cmds := []tea.Cmd{fetchStatus(m.client)}
	switch m.screen {
	case screenFilters:
		cmds = append(cmds, loadFilterStatus(m.client))
	case screenSettings:
		cmds = append(cmds, loadConfig(m.client))
	case screenRequests:
		cmds = append(cmds, loadRequests(m.client))
	}
	return tea.Batch(cmds...)
}

// lazyLoadCmd loads the screen's data on first visit.
func (m Model) lazyLoadCmd() tea.Cmd {
	switch m.screen {
	case screenFilters:
		if m.filterLists == nil {
			return loadFilterStatus(m.client)
		}
	case screenSettings:
		if m.settingsCfg == nil {
			return loadConfig(m.client)
		}
	case screenRequests:
		if m.requests == nil {
			return loadRequests(m.client)
		}
	}
	return nil
}

// handleKey processes one key press.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.inputActive {
		return m.handleInputKey(msg)
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.cancel()
		return m, tea.Quit
	case "r":
		return m, m.refreshCmd()
	case "1", "2", "3", "4", "5", "6", "7":
		idx := int(msg.String()[0] - '1')
		m.screen = screenTabs[idx].screen
		if m.screen == screenWizard {
			return m.openWizard()
		}
		return m, m.lazyLoadCmd()
	}

	switch m.screen {
	case screenRequests:
		switch msg.String() {
		case " ":
			m.requestsPaused = !m.requestsPaused
		case "x":
			m.requests = nil
			m.requestsScroll = 0
		case "up", "k":
			if m.requestsScroll < len(m.requests)-1 {
				m.requestsScroll++
			}
		case "down", "j":
			if m.requestsScroll > 0 {
				m.requestsScroll--
			}
		}

	case screenFilters:
		fields := m.filterLists
		switch msg.String() {
		case "j", "down":
			if m.filterCursor < len(fields)-1 {
				m.filterCursor++
			}
		case "k", "up":
			if m.filterCursor > 0 {
				m.filterCursor--
			}
		case "enter":
			if len(fields) > 0 {
				return m, filterUpdateCmd(m.client, fields[m.filterCursor].ID)
			}
		case "u":
			return m, filterUpdateCmd(m.client, "")
		case "m":
			next := nextBlockMode(m.status.Filter.Mode)
			m.status.Filter.Mode = next // optimistic until the reload lands
			return m, applyModeCmd(m.client, next)
		case "a":
			m.inputActive = true
			m.inputMode = inputRule
			m.input = ""
		}

	case screenSettings:
		switch msg.String() {
		case "j", "down":
			if m.settingsCfg != nil && m.settingsCursor < len(m.settingsFields())-1 {
				m.settingsCursor++
			}
		case "k", "up":
			if m.settingsCursor > 0 {
				m.settingsCursor--
			}
		case "enter":
			if m.settingsCfg == nil {
				return m, m.lazyLoadCmd()
			}
			f := m.settingsFields()[m.settingsCursor]
			if f.toggle != nil {
				f.toggle(m.settingsCfg)
				return m, nil
			}
			m.inputActive = true
			m.inputMode = inputSettingsField
			m.inputField = m.settingsCursor
			m.input = ""
		case "ctrl+s":
			if m.settingsCfg == nil {
				return m, nil
			}
			return m, applySettingsCmd(m.client, cloneConfig(m.settingsCfg))
		case "w":
			return m.openWizard()
		}
	}
	return m, nil
}

// openWizard opens (or re-shows) the embedded wizard over the control
// API.
func (m Model) openWizard() (tea.Model, tea.Cmd) {
	m.screen = screenWizard
	if m.wizard != nil {
		return m, m.wizard.restartProbes() // resume the pings if parked
	}
	if m.wizardLoading {
		return m, nil
	}
	m.wizardNote = ""
	m.wizardLoading = true
	return m, openWizardCmd(m.client)
}

// forwardToWizard hands a message to the embedded wizard.
func (m Model) forwardToWizard(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.wizard.Update(msg)
	wm := updated.(WizardModel)
	m.wizard = &wm
	return m, cmd
}

// isScreenDigit reports whether s selects a screen tab (1-7).
func isScreenDigit(s string) bool {
	return len(s) == 1 && s[0] >= '1' && s[0] <= '7'
}

// handleInputKey processes keys while an input line is open.
func (m Model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyCtrlC {
		m.cancel()
		return m, tea.Quit
	}

	switch msg.Type {
	case tea.KeyEsc:
		m.inputActive = false
		m.input = ""
		return m, nil
	case tea.KeyEnter:
		return m.commitInput()
	case tea.KeyBackspace:
		runes := []rune(m.input)
		if len(runes) > 0 {
			m.input = string(runes[:len(runes)-1])
		}
		return m, nil
	case tea.KeySpace:
		m.input += " "
		return m, nil
	case tea.KeyRunes:
		m.input += string(msg.Runes)
		return m, nil
	}
	return m, nil
}

// commitInput applies the open input line.
func (m Model) commitInput() (tea.Model, tea.Cmd) {
	switch m.inputMode {
	case inputRule:
		return m.commitRule()
	case inputSettingsField:
		m.inputActive = false
		field := m.settingsFields()[m.inputField]
		err := commitSettingsField(field, m.settingsCfg, m.input)
		m.input = ""
		if err != nil {
			m.settingsErr = err
		} else {
			m.settingsErr = nil
		}
		return m, nil
	}
	m.inputActive = false
	return m, nil
}

// applyEvent folds one live event into the model.
func (m *Model) applyEvent(e api.Event) {
	switch data := e.Data.(type) {
	case []api.UpstreamStatus:
		m.status.Upstreams = data
	case api.FilterSnapshot:
		m.status.Filter = data
	case qlog.Entry:
		if m.requestsPaused {
			return
		}
		m.requests = append(m.requests, data)
		if len(m.requests) > requestsCap {
			m.requests = m.requests[1:]
		}
		m.requestsScroll = 0 // follow the tail
	case tlscert.Status:
		m.status.Cert = data
	}
}

// View implements tea.Model.
func (m Model) View() string {
	// The embedded wizard takes the whole screen (it has its own header
	// and footer).
	if m.screen == screenWizard && m.wizard != nil {
		return m.wizard.View()
	}

	var b strings.Builder
	b.WriteString(m.tabsView())
	b.WriteString("\n\n")

	switch m.screen {
	case screenStatus:
		b.WriteString(m.statusView())
	case screenWizard:
		b.WriteString(m.wizardView())
	case screenRequests:
		b.WriteString(m.requestsView())
	case screenUpstreams:
		b.WriteString(m.upstreamsView())
	case screenFilters:
		b.WriteString(m.filtersView())
	case screenSettings:
		b.WriteString(m.settingsView())
	case screenHelp:
		b.WriteString(m.helpView())
	default:
		b.WriteString(dimStyle.Render("Этот экран появится в следующем обновлении."))
		b.WriteString("\n")
	}

	if m.wizardNote != "" {
		b.WriteString("\n")
		b.WriteString(titleStyle.Render(m.wizardNote))
	}

	if m.width > 0 {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("q — выход · r — обновить · пробел — пауза ленты · x — очистить · ↑↓ — прокрутка"))
	}
	return b.String()
}

// tabsView renders the top navigation bar.
func (m Model) tabsView() string {
	parts := make([]string, 0, len(screenTabs))
	for i, tab := range screenTabs {
		label := itoa(i+1) + " " + tab.name
		if tab.screen == m.screen {
			parts = append(parts, activeTabStyle.Render(label))
		} else {
			parts = append(parts, tabStyle.Render(label))
		}
	}
	return strings.Join(parts, "  ")
}

// helpView is the shortcut reference.
func (m *Model) helpView() string {
	lines := []string{
		titleStyle.Render("mdns — горячие клавиши"),
		"",
		"  1-7   переключение экранов",
		"  r     перечитать данные с демона",
		"  q     выход",
		"",
		dimStyle.Render("Все настройки выполняются в TUI и в веб-панели одинаково:"),
		dimStyle.Render("источник правды один — демон."),
	}
	return strings.Join(lines, "\n") + "\n"
}

// Run starts the bubbletea program in the alternate screen.
func (m Model) Run() error {
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

// itoa is a tiny int-to-string helper for the tab labels.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
