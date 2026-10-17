package tui

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
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
	// SocketPath is only used for display; the client carries the real
	// connection.
	SocketPath string
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

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(fetchStatus(m.client), subscribe(m.client, m.ctx))
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

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
			return m, nil // the status screen already reports daemon errors
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
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// handleKey processes one key press.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.cancel()
		return m, tea.Quit
	case "r":
		return m, fetchStatus(m.client)
	case "1", "2", "3", "4", "5", "6", "7":
		idx := int(msg.String()[0] - '1')
		m.screen = screenTabs[idx].screen
	}
	return m, nil
}

// applyEvent folds one live event into the model.
func (m *Model) applyEvent(e api.Event) {
	switch data := e.Data.(type) {
	case []api.UpstreamStatus:
		m.status.Upstreams = data
	case api.FilterSnapshot:
		m.status.Filter = data
	}
	// qlog.Entry events feed the requests screen (next task).
}

// View implements tea.Model.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(m.tabsView())
	b.WriteString("\n\n")

	switch m.screen {
	case screenStatus:
		b.WriteString(m.statusView())
	case screenHelp:
		b.WriteString(m.helpView())
	default:
		b.WriteString(dimStyle.Render("Этот экран появится в следующем обновлении."))
		b.WriteString("\n")
	}

	if m.width > 0 {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("q — выход · r — обновить · 1-7 — экраны"))
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
