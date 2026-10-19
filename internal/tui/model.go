package tui

import (
	"context"
	"errors"
	"fmt"
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
	screenDiag
	screenMaintenance
	// screenFilterCatalog is the list picker opened from the filters
	// screen; it is not a tab.
	screenFilterCatalog
	// screenUpstreamCatalog is the provider-endpoint picker opened from
	// the upstreams screen; it is not a tab.
	screenUpstreamCatalog
	// screenUpstreamForm is the custom-upstream form opened from the
	// upstreams screen; it is not a tab.
	screenUpstreamForm
	// screenHelp is not a tab: the ? key opens it as an overlay and
	// Esc (or any digit) leaves it.
	screenHelp
)

// screenTabs is the navigation order; digits 1-8 select these.
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
	{"Диагностика", screenDiag},
	{"Обслуживание", screenMaintenance},
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

	// helpReturn is the screen the ? overlay was opened from.
	helpReturn screen

	status    api.Status
	statusErr error

	events <-chan api.Event

	requests       []qlog.Entry
	requestsPaused bool
	requestsScroll int
	requestsFilter string

	diagChecks []diagCheck
	diagLoaded bool

	filterLists  []filter.ListStatus
	filterCursor int
	filterErr    error
	// filterCfg is the live configuration the filter edits work on; it
	// is reloaded whenever the screen is entered.
	filterCfg     *config.Config
	catalogCursor int
	// filterNewID carries the custom-list ID from the first input step
	// to the URL step.
	filterNewID string

	settingsCfg    *config.Config
	settingsCursor int
	settingsErr    error

	// upstreamCfg is the live configuration the upstream edits work on;
	// it is reloaded whenever the upstreams screens are entered.
	upstreamCfg    *config.Config
	upstreamCursor int
	upstreamErr    error

	// upstreamCatalogCursor is the highlighted row of the provider
	// endpoint picker.
	upstreamCatalogCursor int

	// upstreamForm is the state of the custom-upstream form, carrying
	// every typed field until ctrl+s applies it.
	upstreamForm      upstreamFormState
	upstreamFormField int
	upstreamFormErr   error

	// probeUpstream/probeResult hold the last probe's target and its
	// rendered outcome, shown under the table.
	probeUpstream string
	probeResult   string

	// Backups screen state: the stored snapshots, the live config
	// (needed for the display timezone and the panel password change)
	// and the feedback lines.
	backups         []BackupInfo
	backupsLoaded   bool
	backupsErr      error
	backupCursor    int
	maintenanceCfg  *config.Config
	maintenanceNote string
	maintenanceErr  error
	passwordFirst   string
	passwordPending bool

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
	case "diag", "диагностика":
		return screenDiag
	case "maintenance", "обслуживание":
		return screenMaintenance
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
	filterConfigLoadedMsg struct {
		cfg *config.Config
		err error
	}
	filterUpdatedMsg struct{ err error }

	configLoadedMsg struct {
		cfg *config.Config
		err error
	}
	configAppliedMsg struct{ err error }

	// upstreamConfigLoadedMsg carries the live config for upstream edits.
	upstreamConfigLoadedMsg struct {
		cfg *config.Config
		err error
	}
	// upstreamProbedMsg carries one upstream probe's rendered outcome.
	upstreamProbedMsg struct {
		id     string
		result string
	}

	requestsLoadedMsg struct {
		entries []qlog.Entry
		err     error
	}

	// eventsRetryMsg re-opens the event stream after eventsRetryDelay.
	eventsRetryMsg struct{}

	// backupsLoadedMsg carries the stored config snapshots.
	backupsLoadedMsg struct {
		backups []BackupInfo
		err     error
	}
	// backupDoneMsg reports one create/restore/delete mutation.
	backupDoneMsg struct {
		action string
		name   string
		err    error
	}
	// maintenanceConfigMsg carries the live config for the display
	// timezone and the panel password change.
	maintenanceConfigMsg struct {
		cfg *config.Config
		err error
	}
	// passwordHashedMsg carries the result of the slow argon2 hash.
	passwordHashedMsg struct {
		hash string
		err  error
	}
	// passwordChangedMsg reports the config write that stores the hash.
	passwordChangedMsg struct {
		cfg *config.Config
		err error
	}
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
	return tea.Batch(fetchStatus(m.client), subscribe(m.client, m.ctx), m.lazyLoadCmd())
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

	case filterConfigLoadedMsg:
		if msg.err != nil {
			m.filterErr = msg.err
			return m, nil
		}
		m.filterCfg = msg.cfg
		m.filterErr = nil
		if rows := m.filterRows(); len(rows) > 0 && m.filterCursor >= len(rows) {
			m.filterCursor = len(rows) - 1
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
			m.upstreamErr = msg.err
			m.upstreamFormErr = msg.err
			// The daemon refused the change: reload the live config so
			// the filter screens never edit a rejected copy.
			if m.screen == screenFilters || m.screen == screenFilterCatalog {
				return m, loadFilterConfig(m.client)
			}
			if isUpstreamScreen(m.screen) {
				return m, loadUpstreamConfig(m.client)
			}
			return m, nil
		}
		m.settingsErr = nil
		m.filterErr = nil
		m.upstreamErr = nil
		m.upstreamFormErr = nil
		cmds := []tea.Cmd{fetchStatus(m.client)}
		if m.screen == screenFilters || m.screen == screenFilterCatalog {
			cmds = append(cmds, filterConfigLoadCmd(m.client))
		}
		if isUpstreamScreen(m.screen) {
			cmds = append(cmds, loadUpstreamConfig(m.client))
		}
		return m, tea.Batch(cmds...)

	case upstreamConfigLoadedMsg:
		if msg.err != nil {
			m.upstreamErr = msg.err
			return m, nil
		}
		m.upstreamCfg = msg.cfg
		m.upstreamErr = nil
		if m.upstreamCursor >= len(m.upstreamRows()) && m.upstreamCursor > 0 {
			m.upstreamCursor = len(m.upstreamRows()) - 1
		}
		return m, nil

	case upstreamProbedMsg:
		m.probeUpstream = msg.id
		m.probeResult = msg.result
		return m, nil

	case requestsLoadedMsg:
		if msg.err == nil {
			m.requests = msg.entries
			if len(m.requests) > requestsCap {
				m.requests = m.requests[len(m.requests)-requestsCap:]
			}
			m.requestsScroll = 0 // follow the newest entry
		}
		return m, nil

	case diagLoadedMsg:
		m.diagChecks = buildDiagChecks(msg)
		m.diagLoaded = true
		return m, nil

	case backupsLoadedMsg:
		m.backupsLoaded = true
		m.backupsErr = msg.err
		if msg.err == nil {
			m.backups = sortBackups(msg.backups)
			switch {
			case len(m.backups) == 0:
				// Never leave the cursor at -1: an empty reload (the
				// last snapshot was deleted elsewhere) returns it to
				// the first row the next create will occupy.
				m.backupCursor = 0
			case m.backupCursor >= len(m.backups):
				m.backupCursor = len(m.backups) - 1
			}
		}
		return m, nil

	case backupDoneMsg:
		if msg.err != nil {
			m.maintenanceNote = ""
			m.maintenanceErr = msg.err
			return m, nil
		}
		m.maintenanceErr = nil
		cmds := []tea.Cmd{loadBackups(m.client)}
		switch msg.action {
		case "create":
			m.maintenanceNote = "Резервная копия создана."
		case "restore":
			m.maintenanceNote = "Конфигурация восстановлена из копии " + msg.name + "."
			// Restore rewrites the whole config, the panel state
			// included: re-read it before the next password change.
			m.maintenanceCfg = nil
			m.settingsCfg = nil
			cmds = append(cmds, loadMaintenanceConfig(m.client))
		case "delete":
			m.maintenanceNote = "Резервная копия удалена."
		}
		return m, tea.Batch(cmds...)

	case maintenanceConfigMsg:
		if msg.err != nil {
			m.maintenanceErr = msg.err
			m.passwordPending = false
			return m, nil
		}
		m.maintenanceCfg = msg.cfg
		if !m.passwordPending {
			return m, nil
		}
		m.passwordPending = false
		if msg.cfg == nil || !msg.cfg.Panel.Enabled {
			m.maintenanceErr = errPanelDisabled
			return m, nil
		}
		return m.openPasswordPrompt(), nil

	case passwordHashedMsg:
		if msg.err != nil {
			m.maintenanceErr = fmt.Errorf("не удалось захэшировать пароль: %w", msg.err)
			return m, nil
		}
		if m.maintenanceCfg == nil {
			m.maintenanceErr = errors.New("конфигурация не загружена — повторите смену пароля")
			return m, nil
		}
		next := cloneConfig(m.maintenanceCfg)
		next.Panel.PasswordHash = msg.hash
		return m, applyPasswordCmd(m.client, next)

	case passwordChangedMsg:
		if msg.err != nil {
			m.maintenanceNote = ""
			m.maintenanceErr = fmt.Errorf("не удалось применить пароль: %w", msg.err)
			return m, nil
		}
		m.maintenanceCfg = msg.cfg
		m.maintenanceErr = nil
		m.maintenanceNote = "Готово: пароль изменён."
		m.settingsCfg = nil // the settings screen re-reads the new hash
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
		cmds = append(cmds, loadFilterStatus(m.client), loadFilterConfig(m.client))
	case screenFilterCatalog:
		cmds = append(cmds, loadFilterConfig(m.client))
	case screenUpstreams, screenUpstreamCatalog:
		cmds = append(cmds, loadUpstreamConfig(m.client))
	case screenSettings:
		cmds = append(cmds, loadConfig(m.client))
	case screenRequests:
		cmds = append(cmds, loadRequests(m.client))
	case screenDiag:
		cmds = append(cmds, loadDiag(m.client))
	case screenMaintenance:
		cmds = append(cmds, loadBackups(m.client), loadMaintenanceConfig(m.client))
	}
	return tea.Batch(cmds...)
}

// lazyLoadCmd loads the screen's data on first visit.
func (m Model) lazyLoadCmd() tea.Cmd {
	switch m.screen {
	case screenFilters:
		// Always reload the live config: the edits must never work on a
		// stale copy.
		return tea.Batch(loadFilterStatus(m.client), loadFilterConfig(m.client))
	case screenSettings:
		if m.settingsCfg == nil {
			return loadConfig(m.client)
		}
	case screenUpstreams, screenUpstreamCatalog:
		// Always reload the live config: the edits must never work on a
		// stale copy.
		return loadUpstreamConfig(m.client)
	case screenRequests:
		if m.requests == nil {
			return loadRequests(m.client)
		}
	case screenDiag:
		if !m.diagLoaded {
			return loadDiag(m.client)
		}
	case screenMaintenance:
		return tea.Batch(loadBackups(m.client), loadMaintenanceConfig(m.client))
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
		// On the filters screen r adds a user rule, mirroring the web
		// panel; everywhere else it refreshes the screen.
		if m.screen == screenFilters {
			m.inputActive = true
			m.inputMode = inputRule
			m.input = ""
			return m, nil
		}
		return m, m.refreshCmd()
	case "?":
		if m.screen != screenHelp {
			m.helpReturn = m.screen
		}
		m.screen = screenHelp
		return m, nil
	case "1", "2", "3", "4", "5", "6", "7", "8":
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
		case "f":
			m.inputActive = true
			m.inputMode = inputRequestsFilter
			m.input = m.requestsFilter // editing an existing filter
		case "esc":
			// Outside an input line Esc clears the feed filter; inside
			// it (handleInputKey) Esc keeps the previous value.
			m.requestsFilter = ""
			m.requestsScroll = 0
		case "up", "k":
			if m.requestsScroll < len(m.filteredRequests())-1 {
				m.requestsScroll++
			}
		case "down", "j":
			if m.requestsScroll > 0 {
				m.requestsScroll--
			}
		}

	case screenFilters:
		fields := m.filterRows()
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
			if len(fields) > 0 && m.filterCursor < len(fields) {
				return m, filterUpdateCmd(m.client, fields[m.filterCursor].id)
			}
		case "u":
			return m, filterUpdateCmd(m.client, "")
		case "m":
			next := nextBlockMode(m.status.Filter.Mode)
			m.status.Filter.Mode = next // optimistic until the reload lands
			return m, applyModeCmd(m.client, next)
		case "a":
			m.screen = screenFilterCatalog
			m.catalogCursor = 0
			m.filterErr = nil
			return m, loadFilterConfig(m.client)
		case "c":
			return m.startCustomList()
		case "d":
			return m.removeSelectedFilterList()
		case "e":
			return m.toggleFilterEnabled()
		}

	case screenFilterCatalog:
		switch msg.String() {
		case "j", "down":
			if m.catalogCursor < len(filter.Catalog())-1 {
				m.catalogCursor++
			}
		case "k", "up":
			if m.catalogCursor > 0 {
				m.catalogCursor--
			}
		case "enter":
			return m.toggleCatalogList()
		case "esc":
			m.screen = screenFilters
			m.filterErr = nil
		}

	case screenUpstreams:
		switch msg.String() {
		case "j", "down":
			if m.upstreamCursor < len(m.upstreamRows())-1 {
				m.upstreamCursor++
			}
		case "k", "up":
			if m.upstreamCursor > 0 {
				m.upstreamCursor--
			}
		case " ", "space":
			return m.toggleSelectedUpstream()
		case "d":
			return m.removeSelectedUpstream()
		case "p":
			return m.startUpstreamPriority()
		case "s":
			return m.cycleUpstreamStrategy()
		case "t":
			return m.probeSelectedUpstream()
		case "a":
			m.screen = screenUpstreamCatalog
			m.upstreamCatalogCursor = 0
			m.upstreamErr = nil
			return m, loadUpstreamConfig(m.client)
		case "c":
			return m.startUpstreamForm()
		}

	case screenUpstreamCatalog:
		entries := upstreamCatalogEntries()
		switch msg.String() {
		case "j", "down":
			if m.upstreamCatalogCursor < len(entries)-1 {
				m.upstreamCatalogCursor++
			}
		case "k", "up":
			if m.upstreamCatalogCursor > 0 {
				m.upstreamCatalogCursor--
			}
		case "enter":
			return m.addCatalogEndpoint()
		case "esc":
			m.screen = screenUpstreams
			m.upstreamErr = nil
		}

	case screenUpstreamForm:
		switch msg.String() {
		case "j", "down":
			if m.upstreamFormField < len(upstreamFormFields)-1 {
				m.upstreamFormField++
			}
		case "k", "up":
			if m.upstreamFormField > 0 {
				m.upstreamFormField--
			}
		case "enter":
			if m.upstreamFormField == upstreamFormTransport {
				m.upstreamForm.Transport = nextUpstreamTransport(m.upstreamForm.Transport)
				return m, nil
			}
			m.inputActive = true
			m.inputMode = inputUpstreamFormField
			m.inputField = m.upstreamFormField
			m.input = ""
		case "left", "right":
			if m.upstreamFormField == upstreamFormTransport {
				if msg.String() == "left" {
					m.upstreamForm.Transport = prevUpstreamTransport(m.upstreamForm.Transport)
				} else {
					m.upstreamForm.Transport = nextUpstreamTransport(m.upstreamForm.Transport)
				}
			}
		case "ctrl+s":
			return m.applyUpstreamForm()
		case "esc":
			m.screen = screenUpstreams
			m.upstreamFormErr = nil
			m.upstreamErr = nil
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

	case screenMaintenance:
		switch msg.String() {
		case "j", "down":
			if m.backupCursor < len(m.backups)-1 {
				m.backupCursor++
			}
		case "k", "up":
			if m.backupCursor > 0 {
				m.backupCursor--
			}
		case "c":
			m.maintenanceErr = nil
			m.maintenanceNote = ""
			return m, createBackupCmd(m.client, "manual")
		case "enter":
			return m.restoreSelectedBackup()
		case "d":
			return m.deleteSelectedBackup()
		case "p":
			return m.startPasswordChange()
		}

	case screenHelp:
		if msg.String() == "esc" {
			m.screen = m.helpReturn
			if m.screen == screenHelp {
				m.screen = screenStatus
			}
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

// isScreenDigit reports whether s selects a screen tab (1-8).
func isScreenDigit(s string) bool {
	return len(s) == 1 && s[0] >= '1' && s[0] <= '8'
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
		m.inputMode = inputNone
		m.filterNewID = ""
		// Cancelling either password prompt drops the pair and the
		// error of the abandoned attempt.
		m.passwordFirst = ""
		if m.screen == screenMaintenance {
			m.maintenanceErr = nil
		}
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
	case inputRequestsFilter:
		m.inputActive = false
		m.requestsFilter = strings.TrimSpace(m.input)
		m.input = ""
		m.requestsScroll = 0
		return m, nil
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
	case inputFilterListID:
		return m.commitFilterListID()
	case inputFilterListURL:
		return m.commitFilterListURL()
	case inputUpstreamFormField:
		return m.commitUpstreamFormField()
	case inputUpstreamPriority:
		return m.commitUpstreamPriority()
	case inputMaintenancePassword:
		return m.commitMaintenancePassword()
	case inputMaintenanceConfirm:
		return m.commitMaintenanceConfirm()
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
	case screenUpstreamCatalog:
		b.WriteString(m.upstreamCatalogView())
	case screenUpstreamForm:
		b.WriteString(m.upstreamFormView())
	case screenFilters:
		b.WriteString(m.filtersView())
	case screenFilterCatalog:
		b.WriteString(m.catalogView())
	case screenSettings:
		b.WriteString(m.settingsView())
	case screenDiag:
		b.WriteString(m.diagView())
	case screenMaintenance:
		b.WriteString(m.maintenanceView())
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
		b.WriteString(dimStyle.Render(m.footerText()))
	}
	return b.String()
}

// footerText is the per-screen key reference. Each line names only keys
// that actually work on that screen; the feed's space/x hints therefore
// never leak onto another screen.
func (m Model) footerText() string {
	// While an input line or a prompt owns the keys, the destructive
	// screen keys do not work: advertise only the two that do.
	if m.inputActive {
		return "enter — подтвердить · esc — отмена"
	}
	switch m.screen {
	case screenRequests:
		return "q — выход · r — обновить · ? — помощь · пробел — пауза ленты · x — очистить · ↑↓ — прокрутка"
	case screenFilters:
		return "q — выход · r — правило · enter/u — обновить · ? — помощь · ↑↓ — прокрутка"
	case screenUpstreams:
		return "space — вкл/выкл · d — удалить · p — приоритет · s — стратегия · t — проверить · a — каталог · c — свой · j/k — выбор · ? — помощь"
	case screenUpstreamForm:
		return "j/k — поля · enter — изменить/сменить транспорт · ctrl+s — применить · esc — отмена"
	case screenUpstreamCatalog, screenFilterCatalog:
		return "j/k — выбор · enter — добавить/удалить · esc — назад · ? — помощь"
	case screenSettings:
		return "q — выход · r — обновить · enter — изменить · ctrl+s — применить · ? — помощь"
	case screenMaintenance:
		return "j/k — выбор · c — создать · enter — восстановить · d — удалить · p — пароль панели · r — обновить · ? — помощь"
	default:
		return "q — выход · r — обновить · ? — помощь"
	}
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

// helpView is the shortcut reference, shown by the ? overflow screen.
func (m *Model) helpView() string {
	lines := []string{
		titleStyle.Render("mdns — горячие клавиши"),
		"",
		"  1-8   переключение экранов (7 — Диагностика, 8 — Обслуживание)",
		"  r     перечитать данные с демона",
		"  f     фильтр ленты «Запросы» (Enter — применить, esc — отменить)",
		"  esc   сбросить фильтр ленты / выйти из справки",
		"  пробел пауза ленты запросов",
		"  x     очистить ленту запросов",
		"  ↑↓    прокрутка ленты",
		"",
		titleStyle.Render("Фильтры (экран 5)"),
		"  a     каталог списков (enter — добавить/удалить, esc — назад)",
		"  c     свой список: ID, затем https-URL",
		"  d     удалить выбранный список",
		"  e     включить или выключить фильтрацию",
		"  r     добавить правило (block домен / allow домен)",
		"  u     обновить все списки · enter — выбранный",
		"",
		titleStyle.Render("Upstream'ы (экран 4)"),
		"  a     каталог провайдеров (enter — добавить, esc — назад)",
		"  c     свой upstream: ID, название, транспорт, адрес, SNI, приоритет",
		"  пробел включить/выключить выбранный (последний включённый не выключается)",
		"  d     удалить выбранный upstream · p — приоритет · s — стратегия",
		"  t     проверить выбранный upstream (probe)",
		"",
		titleStyle.Render("Обслуживание (экран 8)"),
		"  j/k   выбор копии · enter — восстановить · d — удалить",
		"  c     создать резервную копию (метка manual)",
		"  p     сменить пароль веб-панели (два скрытых ввода, esc — отмена)",
		dimStyle.Render("  Восстановление заменяет конфигурацию целиком, снапшот создаётся автоматически"),
		"",
		titleStyle.Render("Настройки (экран 6)"),
		"  enter — изменить поле, ctrl+s — применить",
		dimStyle.Render("  Часовой пояс: IANA-зона, напр. Europe/Moscow, Europe/London, UTC (пусто — системная)"),
		"  ?     эта справка",
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
