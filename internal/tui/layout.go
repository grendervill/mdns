package tui

import (
	"math"
	"strconv"
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
	// fullRailBreakpoint is where the rail widens from the two-letter
	// compact form to the full tab names.
	fullRailBreakpoint = 100
	// railWidth is the full width of the navigation rail including the
	// marker column.
	railWidth = 20
	// compactRailWidth is the width of the rail with numbers and
	// two-letter labels: marker, space and a four-column label.
	compactRailWidth = 6
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

	// compact rail styles: the same palette over the four-column label.
	compactRailItemStyle   = lipgloss.NewStyle().Foreground(colorMuted).Width(compactRailWidth - 2)
	compactRailActiveStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Background(colorRailBg).Width(compactRailWidth - 2)

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
	// scheduled records that a tick is already in flight; the Update
	// wrapper starts the clock for animations begun outside switchScreen
	// (back-navigation and the wizard) without double-scheduling.
	scheduled bool
}

// railTickMsg advances the marker by one frame.
type railTickMsg struct{}

// railVisible reports whether the terminal is wide enough for the rail.
func (m Model) railVisible() bool {
	return m.width >= railBreakpoint
}

// railCompact reports whether the rail shows numbers and two-letter
// labels instead of the full tab names.
func (m Model) railCompact() bool {
	return m.width >= railBreakpoint && m.width < fullRailBreakpoint
}

// railColumnWidth is the width the rail reserves beside the content;
// pickerContentWidth and paneView share it so the two-pane breakpoint
// matches the real content width.
func (m Model) railColumnWidth() int {
	if m.railCompact() {
		return compactRailWidth
	}
	return railWidth
}

// railIndex maps a screen to its rail row. Child screens and the help
// overlay stay on the tab they belong to, so the rail never goes blank.
func (m Model) railIndex(s screen) int {
	switch s {
	case screenFilterCatalog, screenModePicker, screenUserRules:
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
	m.anim = railAnim{from: from, to: to, active: true, scheduled: true}
	return m.railTickCmd()
}

// settleRail moves the marker to the active screen, animating when the
// rail is visible and motion is enabled. It returns the next tick so a
// back-navigation or wizard transition eases exactly like a digit jump;
// with animations disabled (tests) it snaps and returns nil.
func (m *Model) settleRail() tea.Cmd {
	return m.railTo(m.railIndex(m.screen), m.railMarkerRow())
}

// railTo eases the marker from the given row to to, or snaps when the
// rail is hidden, motion is off, or the row does not change.
func (m *Model) railTo(to, from int) tea.Cmd {
	if !m.railVisible() || m.opts.DisableAnimations || from == to {
		m.anim = railAnim{from: to, to: to}
		return nil
	}
	m.anim = railAnim{from: from, to: to, active: true}
	return m.railTickCmd()
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
		m.anim.scheduled = false
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
// Between railBreakpoint and fullRailBreakpoint the labels shrink to
// two letters, so an 80-column terminal keeps 69 content columns.
func (m Model) railView() string {
	marker := m.railMarkerRow()
	active := m.railIndex(m.screen)
	itemStyle, activeStyle, width := railItemStyle, railActiveStyle, railWidth
	if m.railCompact() {
		itemStyle, activeStyle, width = compactRailItemStyle, compactRailActiveStyle, compactRailWidth
	}
	lines := make([]string, 0, len(screenTabs))
	for i, tab := range screenTabs {
		prefix := " "
		if i == marker {
			prefix = railMarkerStyle.Render("▌")
		}
		name := tab.name
		if m.railCompact() {
			name = tab.short
		}
		label := strconv.Itoa(i+1) + " " + name
		if w := lipgloss.Width(label); w < width-2 {
			label += strings.Repeat(" ", width-2-w)
		}
		if i == active {
			lines = append(lines, prefix+" "+activeStyle.Render(label))
		} else {
			lines = append(lines, prefix+" "+itemStyle.Render(label))
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
		return versionLabel(m.status.Version) + " · подключено"
	}
	return "подключено"
}

// versionLabel formats a daemon version with exactly one leading v, so
// the header and the maintenance screen never print "vv…".
func versionLabel(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	if strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V") {
		return version
	}
	return "v" + version
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

// paneInnerWidth is the number of display columns inside the content
// pane. The shell wraps the body to this width before measuring it, so
// the viewport counts painted rows rather than logical ones.
func (m Model) paneInnerWidth() int {
	if m.width <= 0 {
		return 0
	}
	if m.railVisible() {
		inner := m.width - m.railColumnWidth() - 1 - paneStyle.GetHorizontalFrameSize()
		if inner < 1 {
			inner = 1
		}
		return inner
	}
	return m.width
}

// wrapContent pane-wraps the body at the real content width. Every
// height measurement in the shell runs on this wrapped form.
func (m Model) wrapContent(content string) string {
	width := m.paneInnerWidth()
	if width <= 0 {
		return content
	}
	return lipgloss.NewStyle().Width(width).MaxWidth(width).Render(content)
}

// bodyLines is the active screen rendered, wrapped and split into the
// display rows the viewport scrolls through.
func (m Model) bodyLines() []string {
	return contentLines(m.wrapContent(m.viewContent()))
}

// contentHeight is the body height the shell can give the content; zero
// means the terminal size is unknown.
func (m Model) contentHeight() int {
	if m.height <= 0 {
		return 0
	}
	height, _, _ := m.contentViewport(0)
	return height
}

// paneView frames the active screen in the content pane, truncating
// lines that no longer fit beside the rail.
func (m Model) paneView(body string) string {
	inner := m.paneInnerWidth()
	if inner < 1 {
		inner = 1
	}
	body = lipgloss.NewStyle().Width(inner).MaxWidth(inner).Render(body)
	return paneStyle.Render(body)
}

// shellChromeHeight is the number of rows the pinned chrome occupies:
// the header and its blank line, the footer, and the pane border or the
// narrow tab line.
func (m Model) shellChromeHeight() int {
	rows := 2 // header + blank line
	if m.width > 0 {
		rows++ // footer
	}
	if m.railVisible() {
		rows += paneStyle.GetVerticalFrameSize()
	} else {
		rows += strings.Count(m.tabsView(), "\n") + 2 // tabs + blank line
	}
	return rows
}

// contentViewport returns the visible body height, the clamped offset
// and whether the content needs scrolling. A zero height means the
// terminal size is unknown, so the whole content is rendered. The caller
// wraps the content first, so lines are painted rows.
func (m Model) contentViewport(lines int) (height, offset int, overflow bool) {
	if m.height <= 0 {
		return 0, 0, false
	}
	height = m.height - m.shellChromeHeight()
	if height < 0 {
		height = 0
	}
	overflow = lines > height
	if overflow {
		if height > 2 {
			// The scroll hint takes one more footer row.
			height--
		} else {
			// At extreme heights a hidden hint is better than an
			// overflowing frame: clip the body and advertise nothing.
			overflow = false
		}
	}
	offset = m.contentOffset
	if offset < 0 {
		offset = 0
	}
	if max := lines - height; offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}
	return height, offset, overflow
}

// contentLines splits rendered content into display rows.
func contentLines(content string) []string {
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

// clampContentOffset keeps the stored offset inside the current body.
func (m *Model) clampContentOffset() {
	if m.screen == screenWizard && m.wizard != nil {
		m.contentOffset = 0
		return
	}
	_, offset, _ := m.contentViewport(len(m.bodyLines()))
	m.contentOffset = offset
}

// scrollContent moves the body by one page; it is a no-op when the
// content already fits.
func (m Model) scrollContent(dir int) Model {
	lines := m.bodyLines()
	height, offset, overflow := m.contentViewport(len(lines))
	if !overflow || height < 1 {
		return m
	}
	offset += dir * height
	if max := len(lines) - height; offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}
	m.contentOffset = offset
	return m
}

// truncateFooter shortens a key line at a " · " boundary, falling back
// to a character truncation only when even the first entry is too long.
func truncateFooter(text string, width int) string {
	if width <= 0 || lipgloss.Width(text) <= width {
		return text
	}
	parts := strings.Split(text, " · ")
	out := ""
	for _, part := range parts {
		candidate := part
		if out != "" {
			candidate = out + " · " + part
		}
		if lipgloss.Width(candidate)+2 > width {
			break
		}
		out = candidate
	}
	if out != "" {
		return out + " …"
	}
	return truncate(text, width)
}

// footerLine prefixes the per-screen keys with the rail hint.
func (m Model) footerLine() string {
	text := m.footerText()
	if !m.inputActive {
		text = "1–8 — разделы · " + text
	}
	if m.width > 0 {
		text = truncateFooter(text, m.width)
	}
	return text
}

// shellView composes header, navigation, content and footer. The header,
// rail and footer stay pinned; only the body is clipped to the viewport.
// The content is wrapped before it is measured, so a wrapped line counts
// as a row and the header can never be pushed off the terminal.
func (m Model) shellView(content string) string {
	content = m.wrapContent(content)
	lines := contentLines(content)
	height, offset, overflow := m.contentViewport(len(lines))
	switch {
	case height > 0:
		end := offset + height
		if end > len(lines) {
			end = len(lines)
		}
		lines = lines[offset:end]
	case m.height > 0:
		lines = nil
	}
	// Keep the pane at least as tall as the rail when the window allows
	// it, so the frame never ends halfway down the navigation column.
	if m.railVisible() && (height == 0 || height >= len(screenTabs)) {
		for len(lines) < len(screenTabs) {
			lines = append(lines, "")
		}
	}
	body := strings.Join(lines, "\n")

	var b strings.Builder
	b.WriteString(m.headerView())
	b.WriteString("\n\n")

	if m.railVisible() {
		pane := m.paneView(body)
		rail := m.railView()
		// A very short terminal can leave the pane shorter than the
		// eight-row rail; clip the rail rather than overflow.
		if paneRows := len(contentLines(pane)); paneRows < len(contentLines(rail)) {
			railLines := contentLines(rail)
			rail = strings.Join(railLines[:paneRows], "\n")
		}
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, rail, " ", pane))
	} else {
		// Narrow terminals keep the original numeric tab line.
		b.WriteString(m.tabsView())
		b.WriteString("\n\n")
		if m.width > 0 {
			body = lipgloss.NewStyle().MaxWidth(m.width).Render(body)
		}
		b.WriteString(body)
	}

	if m.width > 0 {
		b.WriteString("\n")
		b.WriteString(footerStyle.Render(m.footerLine()))
		if overflow {
			b.WriteString("\n")
			b.WriteString(footerStyle.Render(truncateFooter("PgUp/PgDn — прокрутка", m.width)))
		}
	}
	view := b.String()
	// Last-resort guard for terminals below the minimum chrome height:
	// the first m.height rows win, the header always stays on top.
	if m.height > 0 {
		rows := contentLines(view)
		if len(rows) > m.height {
			view = strings.Join(rows[:m.height], "\n")
		}
	}
	return view
}
