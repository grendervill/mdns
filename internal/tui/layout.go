package tui

import (
	"math"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Palette: the single source of the TUI colours.
var (
	colorAccent = lipgloss.Color("215") // copper
	colorMuted  = lipgloss.Color("245")
	colorOK     = lipgloss.Color("42")
	colorWarn   = lipgloss.Color("214")
	colorErr    = lipgloss.Color("196")
	colorBorder = lipgloss.Color("238")
	colorRailBg = lipgloss.Color("236")
)

// Shell metrics.
const (
	// railBreakpoint is the narrowest terminal that shows the left rail;
	// below it the numeric tab line is the fallback.
	railBreakpoint = 64
	// railWidth is the full width of the navigation rail including the
	// marker column.
	railWidth = 20
	// railFrames bounds the transition: 6 frames at 20 ms = 120 ms.
	railFrames = 6
)

// railFrameDelay is the pause between marker frames; tests may shorten
// it, production keeps the fast 20 ms cadence.
var railFrameDelay = 20 * time.Millisecond

// Styles shared by the views.
var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	dimStyle   = lipgloss.NewStyle().Faint(true)

	okStyle   = lipgloss.NewStyle().Foreground(colorOK)
	warnStyle = lipgloss.NewStyle().Foreground(colorWarn)
	errStyle  = lipgloss.NewStyle().Foreground(colorErr)

	// activeTabStyle marks the selected row in lists; the rail has its
	// own background style below.
	activeTabStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	tabStyle       = lipgloss.NewStyle().Foreground(colorMuted)

	headerBrandStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	headerMetaStyle  = lipgloss.NewStyle().Foreground(colorMuted)

	railItemStyle   = lipgloss.NewStyle().Foreground(colorMuted).Width(railWidth - 2)
	railActiveStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Background(colorRailBg).Width(railWidth - 2)
	railMarkerStyle = lipgloss.NewStyle().Foreground(colorAccent)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	footerStyle = lipgloss.NewStyle().Foreground(colorMuted)
)

// railAnim is the sliding-marker state: the marker eases from the row
// of the previous screen to the row of the new one.
type railAnim struct {
	from   int
	to     int
	frame  int
	active bool
}

// railTickMsg advances the marker by one frame.
type railTickMsg struct{}

// railVisible reports whether the terminal is wide enough for the rail.
func (m Model) railVisible() bool {
	return m.width >= railBreakpoint
}

// railIndex maps a screen to its rail row. Child screens and the help
// overlay stay on the tab they belong to, so the rail never goes blank.
func (m Model) railIndex(s screen) int {
	switch s {
	case screenFilterCatalog, screenModePicker:
		s = screenFilters
	case screenUpstreamCatalog, screenUpstreamForm, screenTransportPicker:
		s = screenUpstreams
	case screenStrategyPicker:
		s = m.pickerReturn
		if s != screenSettings {
			s = screenUpstreams
		}
	case screenTimezonePicker:
		s = screenSettings
	case screenHelp:
		s = m.helpReturn
		if s == screenHelp {
			s = screenStatus
		}
		return m.railIndex(s)
	}
	for i, tab := range screenTabs {
		if tab.screen == s {
			return i
		}
	}
	return 0
}

// switchScreen changes the top-level screen and starts the marker
// transition when the rail is visible and motion is enabled.
func (m *Model) switchScreen(s screen) tea.Cmd {
	from := m.railMarkerRow()
	m.screen = s
	to := m.railIndex(s)
	if !m.railVisible() || m.opts.DisableAnimations || from == to {
		m.settleRail()
		return nil
	}
	m.anim = railAnim{from: from, to: to, active: true}
	return m.railTickCmd()
}

// settleRail snaps the marker to the active screen without motion.
func (m *Model) settleRail() {
	idx := m.railIndex(m.screen)
	m.anim = railAnim{from: idx, to: idx}
}

// railTickCmd schedules the next marker frame.
func (m Model) railTickCmd() tea.Cmd {
	return tea.Tick(railFrameDelay, func(time.Time) tea.Msg { return railTickMsg{} })
}

// advanceRail folds one tick into the marker state and reports whether
// another frame is still needed.
func (m *Model) advanceRail() bool {
	if !m.anim.active {
		return false
	}
	m.anim.frame++
	if m.anim.frame >= railFrames {
		m.anim.frame = railFrames
		m.anim.from = m.anim.to
		m.anim.active = false
		return false
	}
	return true
}

// railMarkerRow is the row the copper marker currently sits on. While
// the text highlight moves immediately, the marker eases out towards
// the target row.
func (m Model) railMarkerRow() int {
	target := m.railIndex(m.screen)
	if !m.anim.active || !m.railVisible() {
		return target
	}
	if m.anim.frame >= railFrames {
		return m.anim.to
	}
	t := float64(m.anim.frame) / float64(railFrames)
	eased := 1 - math.Pow(1-t, 3) // ease-out cubic: fast start, soft stop
	row := m.anim.from + int(math.Round(float64(m.anim.to-m.anim.from)*eased))
	if row < 0 {
		return 0
	}
	if row >= len(screenTabs) {
		return len(screenTabs) - 1
	}
	return row
}

// railView renders the eight tabs with numbers and the sliding marker.
func (m Model) railView() string {
	marker := m.railMarkerRow()
	active := m.railIndex(m.screen)
	lines := make([]string, 0, len(screenTabs))
	for i, tab := range screenTabs {
		prefix := " "
		if i == marker {
			prefix = railMarkerStyle.Render("▌")
		}
		label := itoa(i+1) + " " + tab.name
		if i == active {
			lines = append(lines, prefix+" "+railActiveStyle.Render(label))
		} else {
			lines = append(lines, prefix+" "+railItemStyle.Render(label))
		}
	}
	return strings.Join(lines, "\n")
}

// headerDomain prefers the live status and falls back to a loaded
// configuration while the daemon is still answering.
func (m Model) headerDomain() string {
	if m.status.Domain != "" {
		return m.status.Domain
	}
	if m.settingsCfg != nil && m.settingsCfg.Domain != "" {
		return m.settingsCfg.Domain
	}
	if m.maintenanceCfg != nil && m.maintenanceCfg.Domain != "" {
		return m.maintenanceCfg.Domain
	}
	if m.upstreamCfg != nil && m.upstreamCfg.Domain != "" {
		return m.upstreamCfg.Domain
	}
	return "…"
}

// headerStatus is the muted connection/version note on the right.
func (m Model) headerStatus() string {
	if m.statusErr != nil {
		return "нет связи"
	}
	if m.status.Domain == "" && m.status.Version == "" {
		return ""
	}
	if m.status.Version != "" {
		return "v" + m.status.Version + " · подключено"
	}
	return "подключено"
}

// headerView renders the brand, domain and the optional status note.
func (m Model) headerView() string {
	brand := "mdns"
	meta := " · " + m.headerDomain()
	right := m.headerStatus()

	if m.width > 0 {
		// Leave room for the right note; drop it when it cannot fit.
		maxLeft := m.width
		if rw := lipgloss.Width(right); right != "" && rw+1 < maxLeft {
			maxLeft -= rw + 1
		}
		if maxLeft <= len([]rune(brand)) {
			meta = ""
		} else if len([]rune(brand))+len([]rune(meta)) > maxLeft {
			meta = truncate(meta, maxLeft-len([]rune(brand)))
		}
	}

	left := headerBrandStyle.Render(brand) + headerMetaStyle.Render(meta)
	if m.width <= 0 || right == "" {
		return left
	}
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return left
	}
	return left + strings.Repeat(" ", gap) + headerMetaStyle.Render(right)
}

// paneView frames the active screen in the content pane, truncating
// lines that no longer fit beside the rail.
func (m Model) paneView(content string) string {
	inner := m.width - railWidth - 1 - paneStyle.GetHorizontalFrameSize()
	if inner < 1 {
		inner = 1
	}
	content = strings.TrimRight(content, "\n")
	// Keep the pane at least as tall as the rail so the frame never ends
	// halfway down the navigation column.
	if lines := strings.Count(content, "\n") + 1; lines < len(screenTabs) {
		content += strings.Repeat("\n", len(screenTabs)-lines)
	}
	body := lipgloss.NewStyle().Width(inner).MaxWidth(inner).Render(content)
	return paneStyle.Render(body)
}

// footerLine prefixes the per-screen keys with the rail hint.
func (m Model) footerLine() string {
	text := m.footerText()
	if !m.inputActive {
		text = "1–8 — разделы · " + text
	}
	if m.width > 0 {
		text = truncate(text, m.width)
	}
	return text
}

// shellView composes header, navigation, content and footer.
func (m Model) shellView(content string) string {
	var b strings.Builder
	b.WriteString(m.headerView())
	b.WriteString("\n\n")

	if m.railVisible() {
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, m.railView(), " ", m.paneView(content)))
	} else {
		// Narrow terminals keep the original numeric tab line.
		b.WriteString(m.tabsView())
		b.WriteString("\n\n")
		b.WriteString(content)
	}

	if m.width > 0 {
		b.WriteString("\n")
		b.WriteString(footerStyle.Render(m.footerLine()))
	}
	return b.String()
}
