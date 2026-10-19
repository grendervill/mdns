package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
