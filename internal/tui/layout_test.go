package tui

import (
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/links"
	"mydns/internal/qlog"
)

// shellModel builds a loaded status model at the given terminal size
// with motion disabled, so the layout assertions are deterministic.
func shellModel(t *testing.T, width, height int) Model {
	t.Helper()
	m := New(&stubClient{status: sampleStatus()}, Options{DisableAnimations: true})
	m = step(m, statusLoadedMsg{st: sampleStatus()})
	m = step(m, tea.WindowSizeMsg{Width: width, Height: height})
	return m
}

// TestRailShowsAllTabsAndOneMarker checks the wide shell: every tab is
// present in the rail and exactly one marker is drawn.
func TestRailShowsAllTabsAndOneMarker(t *testing.T) {
	m := shellModel(t, 120, 40)

	view := m.View()
	for _, tab := range screenTabs {
		if !strings.Contains(view, tab.name) {
			t.Errorf("rail misses tab %q:\n%s", tab.name, view)
		}
	}
	if n := strings.Count(view, "▌"); n != 1 {
		t.Errorf("rail markers = %d, want exactly 1:\n%s", n, view)
	}
	if rows := strings.Count(m.railView(), "\n") + 1; rows != len(screenTabs) {
		t.Errorf("rail rows = %d, want %d", rows, len(screenTabs))
	}
}

// TestCompactRailShowsAbbreviations checks the 64-99 column mode: the
// rail shrinks to numbers and two-letter labels, leaves 69 content
// columns at 80 and still draws exactly one marker.
func TestCompactRailShowsAbbreviations(t *testing.T) {
	m := shellModel(t, 80, 24)

	rail := m.railView()
	for _, tab := range screenTabs {
		if !strings.Contains(rail, tab.short) {
			t.Errorf("compact rail misses the abbreviation %q:\n%s", tab.short, rail)
		}
		if strings.Contains(rail, tab.name) {
			t.Errorf("compact rail still carries the full name %q:\n%s", tab.name, rail)
		}
	}
	for i, line := range strings.Split(rail, "\n") {
		if w := lipgloss.Width(line); w != compactRailWidth {
			t.Errorf("rail row %d width = %d, want %d: %q", i, w, compactRailWidth, line)
		}
	}
	if n := strings.Count(m.View(), "▌"); n != 1 {
		t.Errorf("compact rail markers = %d, want exactly 1:\n%s", n, m.View())
	}
	if got := m.pickerContentWidth(); got != 69 {
		t.Errorf("content width at 80 = %d, want 69", got)
	}
	if m.railColumnWidth() != compactRailWidth {
		t.Errorf("railColumnWidth = %d, want %d", m.railColumnWidth(), compactRailWidth)
	}
}

// TestCompactRailMarkerAnimates checks the marker transition also runs
// in the compact rail and lands on the target row.
func TestCompactRailMarkerAnimates(t *testing.T) {
	m := New(&stubClient{status: sampleStatus()}, Options{})
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})

	updated, _ := m.Update(key('4'))
	m = updated.(Model)
	if !m.anim.active {
		t.Fatalf("the compact rail did not start the marker animation")
	}
	last := -1
	for frame := 0; frame < railFrames; frame++ {
		updated, cmd := m.Update(railTickMsg{})
		m = updated.(Model)
		row := m.railMarkerRow()
		if row < last {
			t.Errorf("marker moved backwards: %d then %d", last, row)
		}
		last = row
		if frame == railFrames-1 && cmd != nil {
			t.Errorf("the last frame scheduled another tick")
		}
	}
	if m.anim.active {
		t.Errorf("animation is still active after %d frames", railFrames)
	}
	if got := m.railMarkerRow(); got != 3 {
		t.Errorf("marker row = %d, want the upstreams row 3", got)
	}
	if n := strings.Count(m.View(), "▌"); n != 1 {
		t.Errorf("compact rail markers = %d, want 1 after animation", n)
	}
}

// TestNarrowTerminalFallsBackToTabLine checks the width < 64 fallback:
// one numeric line with every tab and no rail marker.
func TestNarrowTerminalFallsBackToTabLine(t *testing.T) {
	m := shellModel(t, 50, 20)

	view := m.View()
	if strings.Contains(view, "▌") || strings.Contains(view, "╭") {
		t.Errorf("narrow view still renders the rail or pane:\n%s", view)
	}
	if !strings.Contains(view, "1 Статус") {
		t.Fatalf("narrow view misses the numeric tab line:\n%s", view)
	}
	for _, tab := range screenTabs {
		if !strings.Contains(view, tab.name) {
			t.Errorf("fallback tabs miss %q:\n%s", tab.name, view)
		}
	}
}

// TestSmallTerminalViewDoesNotPanic guards the 40x12 minimum.
func TestSmallTerminalViewDoesNotPanic(t *testing.T) {
	m := shellModel(t, 40, 12)
	if view := m.View(); view == "" {
		t.Errorf("View() is empty at 40x12")
	}
}

// TestDigitSwitchesScreenWithRail checks that digits still navigate and
// the marker follows the target.
func TestDigitSwitchesScreenWithRail(t *testing.T) {
	m := shellModel(t, 120, 40)

	m = step(m, key('4'))
	if m.screen != screenUpstreams {
		t.Fatalf("screen = %v, want upstreams", m.screen)
	}
	if got := m.railMarkerRow(); got != 3 {
		t.Errorf("marker row = %d, want 3", got)
	}
	if n := strings.Count(m.View(), "▌"); n != 1 {
		t.Errorf("rail markers = %d, want 1 after navigation", n)
	}
}

// TestMarkerAnimationAdvancesAndStops checks the tick-driven transition:
// it moves for six frames, then stops at the target.
func TestMarkerAnimationAdvancesAndStops(t *testing.T) {
	m := New(&stubClient{status: sampleStatus()}, Options{})
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	updated, _ := m.Update(key('3'))
	m = updated.(Model)
	if !m.anim.active {
		t.Fatalf("switching screens did not start the marker animation")
	}
	if m.anim.from != 0 || m.anim.to != 2 {
		t.Errorf("animation from/to = %d/%d, want 0/2", m.anim.from, m.anim.to)
	}

	last := -1
	for frame := 0; frame < railFrames; frame++ {
		updated, cmd := m.Update(railTickMsg{})
		m = updated.(Model)
		row := m.railMarkerRow()
		if row < last {
			t.Errorf("marker moved backwards: %d then %d", last, row)
		}
		last = row
		if frame < railFrames-1 && cmd == nil {
			t.Errorf("frame %d scheduled no next tick", frame)
		}
		if frame == railFrames-1 && cmd != nil {
			t.Errorf("the last frame scheduled another tick")
		}
	}
	if m.anim.active {
		t.Errorf("animation is still active after %d frames", railFrames)
	}
	if got := m.railMarkerRow(); got != 2 {
		t.Errorf("marker row = %d, want the requests row 2", got)
	}
}

// TestMarkerAnimationRetargets checks a switch during motion starts from
// the marker's current row instead of jumping.
func TestMarkerAnimationRetargets(t *testing.T) {
	m := New(&stubClient{status: sampleStatus()}, Options{})
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	m = step(m, key('3'))
	m = step(m, railTickMsg{})
	row := m.railMarkerRow()
	if row == 0 || row == 2 {
		t.Fatalf("marker did not move mid-animation: row = %d", row)
	}

	m = step(m, key('6'))
	if !m.anim.active {
		t.Fatalf("retarget stopped the animation")
	}
	if m.anim.from != row || m.anim.to != 5 {
		t.Errorf("retarget from/to = %d/%d, want %d/5", m.anim.from, m.anim.to, row)
	}
}

// TestDisableAnimationsSnapsMarker checks the deterministic test option.
func TestDisableAnimationsSnapsMarker(t *testing.T) {
	m := shellModel(t, 120, 40)

	m = step(m, key('5'))
	if m.anim.active {
		t.Errorf("animation ran with DisableAnimations set")
	}
	if got := m.railMarkerRow(); got != 4 {
		t.Errorf("marker row = %d, want 4", got)
	}
}

// TestHelpListsRailHint checks the overlay documents the rail keys.
func TestHelpListsRailHint(t *testing.T) {
	m := shellModel(t, 120, 40)
	m = step(m, key('?'))

	view := m.View()
	if !strings.Contains(view, "1–8 — разделы") {
		t.Errorf("help overlay misses the rail hint:\n%s", view)
	}
	for _, want := range []string{"сменить пароль", "каталог провайдеров", "свой список"} {
		if !strings.Contains(view, want) {
			t.Errorf("help overlay lost the management key %q:\n%s", want, view)
		}
	}
}

// TestShellFitsTerminalWidth checks no line overflows 120 or 80 columns
// once the rail and pane are in place.
func TestShellFitsTerminalWidth(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {80, 24}} {
		m := shellModel(t, size[0], size[1])
		for _, tab := range screenTabs {
			m.screen = tab.screen
			m.settleRail()
			for _, line := range strings.Split(m.View(), "\n") {
				if w := lipgloss.Width(line); w > size[0] {
					t.Errorf("%dx%d %s: line width %d > %d: %q",
						size[0], size[1], tab.name, w, size[0], line)
				}
			}
		}
	}
}

// fullStatus is a status screen taller than an 80x24 terminal.
func fullStatus() api.Status {
	st := sampleStatus()
	for i := 0; i < 14; i++ {
		st.Upstreams = append(st.Upstreams, api.UpstreamStatus{
			ID:        "up" + strconv.Itoa(i),
			Name:      "Provider " + strconv.Itoa(i),
			Transport: "plain",
			Address:   "198.51.100." + strconv.Itoa(i) + ":53",
			Enabled:   true,
			Healthy:   i%2 == 0,
			LatencyMS: float64(10 + i),
		})
	}
	return st
}

// TestShortTerminalKeepsChromeAndFits pins the whole shell to the
// terminal: the header, rail and footer never scroll off, and the body
// is clipped instead.
func TestShortTerminalKeepsChromeAndFits(t *testing.T) {
	m := New(&stubClient{status: fullStatus()}, Options{DisableAnimations: true})
	m = step(m, statusLoadedMsg{st: fullStatus()})
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})

	view := m.View()
	lines := strings.Split(view, "\n")
	if len(lines) > 24 {
		t.Errorf("view has %d lines, want at most 24:\n%s", len(lines), view)
	}
	if !strings.HasPrefix(lines[0], "mdns") {
		t.Errorf("the header scrolled off the first row: %q", lines[0])
	}
	// At 80 columns the rail is compact, so the active tab is "1 Ст".
	if !strings.Contains(view, "1 Ст") {
		t.Errorf("the rail lost the active tab:\n%s", view)
	}
	for _, tab := range screenTabs {
		if !strings.Contains(view, tab.short) {
			t.Errorf("the rail lost %q:\n%s", tab.short, view)
		}
	}
	if !strings.Contains(view, "PgUp/PgDn — прокрутка") {
		t.Errorf("the overflowing body has no scroll hint:\n%s", view)
	}
}

// TestContentScrollKeys checks PgUp/PgDn move the body a page, clamp at
// the edges and reset when the screen changes.
func TestContentScrollKeys(t *testing.T) {
	m := New(&stubClient{status: fullStatus()}, Options{DisableAnimations: true})
	m = step(m, statusLoadedMsg{st: fullStatus()})
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})

	if m.contentOffset != 0 {
		t.Fatalf("initial offset = %d, want 0", m.contentOffset)
	}
	m = step(m, tea.KeyMsg{Type: tea.KeyPgDown})
	if m.contentOffset == 0 {
		t.Fatalf("PgDn did not advance the offset")
	}
	paged := m.contentOffset
	m = step(m, tea.KeyMsg{Type: tea.KeyPgUp})
	if m.contentOffset != 0 {
		t.Errorf("PgUp offset = %d, want 0", m.contentOffset)
	}

	// Ctrl+D/Ctrl+U mirror the page keys.
	m = step(m, tea.KeyMsg{Type: tea.KeyCtrlD})
	if m.contentOffset != paged {
		t.Errorf("ctrl+d offset = %d, want %d", m.contentOffset, paged)
	}
	m = step(m, tea.KeyMsg{Type: tea.KeyCtrlU})
	if m.contentOffset != 0 {
		t.Errorf("ctrl+u offset = %d, want 0", m.contentOffset)
	}

	// Repeated PgDn stops at the last page.
	lines := m.bodyLines()
	height, _, overflow := m.contentViewport(len(lines))
	if !overflow {
		t.Fatalf("the test status does not overflow")
	}
	max := len(lines) - height
	for i := 0; i < 20; i++ {
		m = step(m, tea.KeyMsg{Type: tea.KeyPgDown})
	}
	if m.contentOffset != max {
		t.Errorf("clamped offset = %d, want %d", m.contentOffset, max)
	}

	// A screen switch clears the offset.
	m = step(m, key('5'))
	if m.contentOffset != 0 {
		t.Errorf("offset = %d after switching screens, want 0", m.contentOffset)
	}
}

// TestContentOffsetClampsOnResize checks a grown terminal drops a stale
// offset instead of leaving the user on a blank page.
func TestContentOffsetClampsOnResize(t *testing.T) {
	m := New(&stubClient{status: fullStatus()}, Options{DisableAnimations: true})
	m = step(m, statusLoadedMsg{st: fullStatus()})
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m.contentOffset = 999

	m = step(m, tea.WindowSizeMsg{Width: 200, Height: 80})
	if m.contentOffset != 0 {
		t.Errorf("offset = %d after growing the terminal, want 0", m.contentOffset)
	}
}

// TestShortScreenHasNoScrollHint checks a body that fits advertises no
// scrolling and ignores the page keys.
func TestShortScreenHasNoScrollHint(t *testing.T) {
	m := shellModel(t, 120, 40)
	if strings.Contains(m.View(), "PgUp/PgDn — прокрутка") {
		t.Errorf("a fitting body shows the scroll hint:\n%s", m.View())
	}
	m = step(m, tea.KeyMsg{Type: tea.KeyPgDown})
	if m.contentOffset != 0 {
		t.Errorf("PgDn moved a fitting body to offset %d", m.contentOffset)
	}
}

// TestStatusNarrowKeepsOneLinePerUpstream checks that an 80-column
// status truncates a long address and link instead of wrapping them.
func TestStatusNarrowKeepsOneLinePerUpstream(t *testing.T) {
	const longAddress = "resolver-with-a-very-long-name.example.net:853"
	const longLink = "https://dns.example.com/dns-query?device=living-room-tv&token=abcdef"

	st := sampleStatus()
	st.Upstreams = []api.UpstreamStatus{{
		ID: "long", Name: "Cloudflare", Transport: "dot", Address: longAddress,
		Enabled: true, Healthy: true, LatencyMS: 12.5, Sent: 10,
	}}
	st.Links = []links.Link{{Proto: "doh", Title: "DoH для большого телевизора в гостиной", URI: longLink}}

	m := New(&stubClient{status: st}, Options{DisableAnimations: true})
	m = step(m, statusLoadedMsg{st: st})
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})

	view := m.View()
	if strings.Contains(view, longAddress) || strings.Contains(view, longLink) {
		t.Errorf("a narrow status still contains the untruncated value:\n%s", view)
	}

	content := strings.TrimRight(m.statusView(), "\n")
	lines := strings.Split(content, "\n")
	width := m.pickerContentWidth()
	for i, line := range lines {
		if w := lipgloss.Width(line); w > width {
			t.Errorf("status line %d width = %d > %d: %q", i, w, width, line)
		}
		if !strings.Contains(line, "Cloudflare") {
			continue
		}
		if i+1 < len(lines) && lines[i+1] != "" {
			t.Errorf("the long address wrapped onto a second line: %q", lines[i+1])
		}
	}
}

// assertShellFits fails when View() is taller than the terminal or the
// header is not its first line.
func assertShellFits(t *testing.T, m Model, width, height int) {
	t.Helper()
	lines := strings.Split(m.View(), "\n")
	if len(lines) > height {
		t.Errorf("%dx%d: View() has %d lines, want at most %d:\n%s", width, height, len(lines), height, m.View())
	}
	if !strings.HasPrefix(lines[0], "mdns") {
		t.Errorf("%dx%d: the header is not the first line: %q", width, height, lines[0])
	}
}

// TestEveryScreenFitsTerminalHeight is the generic guard against layout
// drift: every tab fits its terminal after the body is pane-wrapped and
// keeps the header pinned.
func TestEveryScreenFitsTerminalHeight(t *testing.T) {
	screens := []screen{
		screenStatus, screenRequests, screenUpstreams,
		screenSettings, screenHelp, screenMaintenance, screenDiag,
	}
	for _, size := range [][2]int{{80, 24}, {100, 30}} {
		width, height := size[0], size[1]
		m := shellModel(t, width, height)
		cfg := config.Default()
		m = step(m, configLoadedMsg{cfg: cfg})
		m = step(m, filterConfigLoadedMsg{cfg: cfg})
		m = step(m, maintenanceConfigMsg{cfg: cfg})
		m = step(m, backupsLoadedMsg{backups: []BackupInfo{{Name: "snap-1.json"}, {Name: "snap-2.json"}}})
		m = step(m, diagLoadedMsg{status: fullStatus(), cfg: cfg})
		entries := make([]qlog.Entry, 0, 60)
		for i := 0; i < 60; i++ {
			entries = append(entries, qlog.Entry{
				QName: strconv.Itoa(i) + ".example.com.", Proto: "udp",
				ClientIP: "192.168.1.10", LatencyMS: 12.5,
			})
		}
		m = step(m, requestsLoadedMsg{entries: entries})

		for _, sc := range screens {
			m.screen = sc
			m.contentOffset = 0
			m.settleRail()
			assertShellFits(t, m, width, height)
		}
	}
}

// TestSmallTerminalViewFits checks the 40x12 fallback no longer spills
// past the terminal.
func TestSmallTerminalViewFits(t *testing.T) {
	m := shellModel(t, 40, 12)
	assertShellFits(t, m, 40, 12)
}

// countRailTickCmds runs the batch members and counts the commands that
// produce a rail tick. It is only used by the one-chain guard.
func countRailTickCmds(t *testing.T, cmd tea.Cmd) int {
	t.Helper()
	if cmd == nil {
		return 0
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		if _, tick := msg.(railTickMsg); tick {
			return 1
		}
		return 0
	}
	n := 0
	for _, member := range batch {
		if member == nil {
			continue
		}
		if _, tick := member().(railTickMsg); tick {
			n++
		}
	}
	return n
}

// TestWizardTransitionSchedulesOneTick pins the single marker tick chain:
// openWizard returns railTo's tick, so Update must not schedule a second
// one for the same transition.
func TestWizardTransitionSchedulesOneTick(t *testing.T) {
	old := railFrameDelay
	railFrameDelay = time.Millisecond
	defer func() { railFrameDelay = old }()

	m := New(&stubClient{status: sampleStatus()}, Options{})
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	updated, cmd := m.Update(key('2'))
	m = updated.(Model)
	if m.screen != screenWizard {
		t.Fatalf("2 opened %v, want the wizard", m.screen)
	}
	if !m.anim.active || !m.anim.scheduled {
		t.Fatalf("animation = %+v, want active with a tick in flight", m.anim)
	}
	if got := countRailTickCmds(t, cmd); got != 1 {
		t.Errorf("the wizard transition scheduled %d tick chains, want exactly 1", got)
	}
}

// TestBackNavigationAnimatesMarker checks settleRail starts the marker
// transition (opening the wizard leaves the status row) instead of
// snapping, and the tick chain still stops on the target row.
func TestBackNavigationAnimatesMarker(t *testing.T) {
	m := New(&stubClient{status: sampleStatus()}, Options{})
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	updated, cmd := m.Update(key('2'))
	m = updated.(Model)
	if m.screen != screenWizard {
		t.Fatalf("2 opened %v, want the wizard", m.screen)
	}
	if !m.anim.active || m.anim.from != 0 || m.anim.to != 1 {
		t.Fatalf("settleRail animation = %+v, want 0→1 and active", m.anim)
	}
	if cmd == nil {
		t.Fatalf("the wizard transition scheduled no command")
	}
	if !m.anim.scheduled {
		t.Errorf("the marker animation has no tick in flight")
	}
	for frame := 0; frame < railFrames; frame++ {
		m = step(m, railTickMsg{})
	}
	if m.anim.active {
		t.Errorf("the marker animation is still active after %d frames", railFrames)
	}
	if got := m.railMarkerRow(); got != 1 {
		t.Errorf("marker row = %d, want the wizard row 1", got)
	}
}
