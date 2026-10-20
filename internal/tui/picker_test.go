package tui

import (
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// pickerFixture builds a picker with three distinct rows.
func pickerFixture() picker {
	return picker{
		title: "Тест",
		items: []pickerItem{
			{Label: "первый", Status: "сейчас", Details: []string{"Описание первого элемента."}},
			{Label: "второй", Status: "установлен", Details: []string{"Описание второго элемента."}},
			{Label: "третий", Details: []string{"Описание третьего элемента."}},
		},
	}
}

// TestPickerNavigationChangesDetails checks that moving the cursor swaps
// the right pane's details.
func TestPickerNavigationChangesDetails(t *testing.T) {
	p := pickerFixture()

	view := p.Render(40, 40, 8)
	if !strings.Contains(view, "Описание первого") {
		t.Fatalf("Render() misses the first details:\n%s", view)
	}

	p.moveDown()
	view = p.Render(40, 40, 8)
	if !strings.Contains(view, "Описание второго") {
		t.Errorf("Render() after j misses the second details:\n%s", view)
	}
	if strings.Contains(view, "Описание первого") {
		t.Errorf("Render() still shows the first details after j:\n%s", view)
	}

	p.moveUp()
	p.moveUp() // clamped at the first row
	if p.cursor != 0 {
		t.Errorf("cursor = %d after moving past the top, want 0", p.cursor)
	}
	if _, ok := p.selected(); !ok {
		t.Errorf("selected() reports no row")
	}
}

// TestPickerScrollWindow checks that a long list scrolls around the
// cursor and shows both scroll indicators.
func TestPickerScrollWindow(t *testing.T) {
	items := make([]pickerItem, 30)
	for i := range items {
		items[i] = pickerItem{
			Label:   "строка-" + strconv.Itoa(i),
			Details: []string{"детали " + strconv.Itoa(i)},
		}
	}
	p := picker{title: "Длинный", items: items, cursor: 20}

	view := p.Render(40, 40, 6)
	if !strings.Contains(view, "↑ ещё") {
		t.Errorf("Render() misses the top scroll indicator:\n%s", view)
	}
	if !strings.Contains(view, "↓ ещё") {
		t.Errorf("Render() misses the bottom scroll indicator:\n%s", view)
	}
	if !strings.Contains(view, "строка-20") || !strings.Contains(view, "детали 20") {
		t.Errorf("Render() misses the selected row or its details:\n%s", view)
	}
	if strings.Contains(view, "строка-0 ") || strings.Contains(view, "строка-29") {
		t.Errorf("Render() shows rows outside the scroll window:\n%s", view)
	}
}

// TestPickerTwoPaneAt80Columns checks the shell at 80 columns: the
// compact rail leaves 69 content columns, so the picker keeps the list
// and the details side by side instead of stacking.
func TestPickerTwoPaneAt80Columns(t *testing.T) {
	cfg := upstreamCfgWith()
	m := upstreamModel(&stubClient{cfg: cfg}, cfg)
	m = step(m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m = step(m, key('s'))

	if m.screen != screenStrategyPicker {
		t.Fatalf("s opened %v, want the strategy picker", m.screen)
	}
	if got := m.pickerContentWidth(); got != 69 {
		t.Fatalf("picker content width = %d, want 69", got)
	}
	if left, right := pickerPaneWidths(69); left+right+1 != 69 {
		t.Errorf("pane widths %d+%d+1 != 69", left, right)
	}

	view := m.View()
	top := 0
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "╭") {
			top++
		}
	}
	if top != 2 {
		t.Errorf("80-column view draws %d top-border lines, want 2 (shell pane + two-pane picker):\n%s", top, view)
	}
	for _, line := range strings.Split(view, "\n") {
		if w := lipgloss.Width(line); w > 80 {
			t.Errorf("line width %d > 80: %q", w, line)
		}
	}
}

// TestPickerNarrowStacks checks the <68 column layout: the list sits
// above the details instead of beside them.
func TestPickerNarrowStacks(t *testing.T) {
	p := pickerFixture()

	wide := p.Render(40, 40, 8)
	stacked := p.Render(30, 30, 8)

	wideLines := 0
	for _, line := range strings.Split(wide, "\n") {
		if strings.Contains(line, "╭") {
			wideLines++
		}
	}
	if wideLines != 1 {
		t.Errorf("wide layout draws %d top-border lines, want 1 (side by side)", wideLines)
	}
	topLines := 0
	for _, line := range strings.Split(stacked, "\n") {
		if strings.Contains(line, "╭") {
			topLines++
		}
	}
	if topLines != 2 {
		t.Errorf("narrow layout draws %d top-border lines, want 2 (list above details):\n%s", topLines, stacked)
	}
	if !strings.Contains(stacked, "первый") || !strings.Contains(stacked, "Описание первого") {
		t.Errorf("stacked layout loses the row or its details:\n%s", stacked)
	}
	if !strings.Contains(stacked, pickerHint) {
		t.Errorf("stacked layout loses the hint line:\n%s", stacked)
	}
}

// TestPickerLongDetailsWrap checks that hostile details wrap without a
// panic and never overflow the pane.
func TestPickerLongDetailsWrap(t *testing.T) {
	long := strings.Repeat("оченьдлинноесловобезпробелов", 12) + " " +
		strings.Repeat("текст с пробелами ", 20)
	p := picker{
		title: "Длинные детали",
		items: []pickerItem{{Label: strings.Repeat("этикетка", 30), Details: []string{long, "", long}}},
	}

	view := p.Render(14, 15, 6)
	if view == "" {
		t.Fatalf("Render() is empty")
	}
	for _, line := range strings.Split(view, "\n") {
		if w := lipgloss.Width(line); w > 30 {
			t.Errorf("line width %d > 30: %q", w, line)
		}
	}
}

// TestPickerEnterEscCallbacks checks that a picker screen routes Enter
// and Esc back through the model: strategy Enter applies and returns,
// Esc cancels without a config write.
func TestPickerEnterEscCallbacks(t *testing.T) {
	cfg := upstreamCfgWith()
	sc := &stubClient{cfg: cfg}
	m := upstreamModel(sc, cfg)
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	// Esc leaves the picker and keeps the config untouched.
	m = step(m, key('s'))
	if m.screen != screenStrategyPicker {
		t.Fatalf("s opened %v, want the strategy picker", m.screen)
	}
	m = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != screenUpstreams {
		t.Errorf("esc left the picker on %v, want upstreams", m.screen)
	}
	if len(sc.updates) != 0 {
		t.Errorf("esc called UpdateConfig %d times, want 0", len(sc.updates))
	}

	// Enter applies the selected strategy and returns.
	m = step(m, key('s'))
	m = step(m, key('j'))
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if m.screen != screenUpstreams {
		t.Errorf("enter left the picker on %v, want upstreams", m.screen)
	}
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 || sc.updates[0].Strategy != "failover" {
		t.Errorf("updates = %+v, want one failover write", sc.updates)
	}
}

// TestPickerCJKWidths checks a wide-rune label never pushes a picker row
// past the pane at content widths 75 and 90: every line fits, the
// borders stay on one line and the shell height is respected.
func TestPickerCJKWidths(t *testing.T) {
	for _, size := range [][2]int{{100, 30}, {115, 30}} {
		width, height := size[0], size[1]
		m := New(&stubClient{}, Options{DisableAnimations: true})
		m = step(m, tea.WindowSizeMsg{Width: width, Height: height})
		m.picker = picker{
			title: "Провайдеры",
			items: []pickerItem{
				{Label: "AdGuard Chinese (中文)", Status: "сейчас", Details: []string{"Китайский фильтр AdGuard: 中文 домены."}},
				{Label: "Cloudflare (безопасный)", Details: []string{"Обычный резолвер."}},
			},
		}
		m.screen = screenStrategyPicker
		m.settleRail()

		if got := m.pickerContentWidth(); got != width-25 {
			t.Fatalf("%dx%d: content width = %d, want %d", width, height, got, width-25)
		}
		view := m.View()
		for _, line := range strings.Split(view, "\n") {
			if w := lipgloss.Width(line); w > width {
				t.Errorf("%dx%d: line width %d > %d: %q", width, height, w, width, line)
			}
			if strings.Count(line, "╭") != strings.Count(line, "╮") {
				t.Errorf("%dx%d: unbalanced top border: %q", width, height, line)
			}
			if strings.Count(line, "╰") != strings.Count(line, "╯") {
				t.Errorf("%dx%d: unbalanced bottom border: %q", width, height, line)
			}
		}
		if n := strings.Count(view, "\n") + 1; n > height {
			t.Errorf("%dx%d: View() has %d lines, want at most %d", width, height, n, height)
		}
		if !strings.Contains(view, pickerHint) {
			t.Errorf("%dx%d: the picker hint is clipped:\n%s", width, height, view)
		}
		if !strings.Contains(view, "╰") {
			t.Errorf("%dx%d: the picker bottom border is clipped:\n%s", width, height, view)
		}
	}
}

// TestPickerFitsBodyHeight checks the picker hint and bottom border are
// visible at 120x40 and 80x24: the panes no longer overshoot the body.
func TestPickerFitsBodyHeight(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {80, 24}} {
		cfg := upstreamCfgWith()
		m := upstreamModel(&stubClient{cfg: cfg}, cfg)
		m = step(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = step(m, key('s'))

		view := m.View()
		if !strings.Contains(view, pickerHint) {
			t.Errorf("%dx%d: the picker hint is clipped:\n%s", size[0], size[1], view)
		}
		if !strings.Contains(view, "╰") {
			t.Errorf("%dx%d: the picker bottom border is clipped:\n%s", size[0], size[1], view)
		}
		if n := strings.Count(view, "\n") + 1; n > size[1] {
			t.Errorf("%dx%d: View() has %d lines, want at most %d", size[0], size[1], n, size[1])
		}
	}
}
