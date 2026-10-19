package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// pickerItem is one choice of a two-pane picker: the row text, a short
// state note («установлен», «сейчас», «дубль») and the detail lines the
// right pane shows for the selected row.
type pickerItem struct {
	Label   string
	Status  string
	Details []string
}

// picker is the shared two-pane enumeration view. It holds no bubbletea
// commands: the screen that owns it decides what Enter and Esc mean, so
// every list in the TUI renders and scrolls the same way.
type picker struct {
	title  string
	items  []pickerItem
	cursor int
	offset int
}

// pickerHint is the bottom key line shared by every picker.
const pickerHint = "j/k — выбор · enter — выбрать · esc — назад"

// pickerStackWidth is the content width below which the list and the
// details stack vertically instead of sitting side by side.
const pickerStackWidth = 72

// pickerSelectedStyle marks the highlighted row of a picker.
var pickerSelectedStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(colorAccent).
	Background(colorRailBg)

// setItems replaces the rows and keeps the cursor in range.
func (p *picker) setItems(items []pickerItem) {
	p.items = items
	p.clamp()
}

// clamp keeps the cursor and the scroll offset inside the item list.
func (p *picker) clamp() {
	n := len(p.items)
	if n == 0 {
		p.cursor, p.offset = 0, 0
		return
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= n {
		p.cursor = n - 1
	}
	if p.offset < 0 {
		p.offset = 0
	}
	if p.offset >= n {
		p.offset = n - 1
	}
}

// moveDown moves the cursor one row down.
func (p *picker) moveDown() {
	if p.cursor < len(p.items)-1 {
		p.cursor++
	}
}

// moveUp moves the cursor one row up.
func (p *picker) moveUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

// selected returns the row under the cursor.
func (p *picker) selected() (pickerItem, bool) {
	if p.cursor < 0 || p.cursor >= len(p.items) {
		return pickerItem{}, false
	}
	return p.items[p.cursor], true
}

// visible computes the item window for a pane of total lines height. It
// reserves one line for each scroll indicator and always keeps the
// cursor inside the window.
func (p *picker) visible(height int) (start, rows int, topMore, bottomMore bool) {
	n := len(p.items)
	if height < 1 {
		height = 1
	}
	if n == 0 {
		return 0, 0, false, false
	}
	p.clamp()
	start = p.offset

	// Iterate a few times: reserving an indicator can push the cursor
	// out, and moving the window can add or remove an indicator.
	for i := 0; i < 4; i++ {
		rows = height
		topMore = start > 0
		bottomMore = start+rows < n
		if topMore {
			rows--
		}
		if bottomMore {
			rows--
		}
		if rows < 1 {
			rows = 1
		}
		if p.cursor < start {
			start = p.cursor
			continue
		}
		if p.cursor >= start+rows {
			start = p.cursor - rows + 1
			continue
		}
		break
	}
	if start < 0 {
		start = 0
	}
	if start > n-1 {
		start = n - 1
	}
	p.offset = start

	rows = height
	topMore = start > 0
	if topMore {
		rows--
	}
	bottomMore = start+rows < n
	if bottomMore {
		rows--
	}
	if rows < 1 {
		rows = 1
	}
	if start+rows > n {
		rows = n - start
		bottomMore = false
	}
	return start, rows, topMore, bottomMore
}

// Render draws the picker. leftWidth and rightWidth are the full pane
// widths including borders; height is the content height of a pane.
// Below pickerStackWidth the list is placed above the details.
func (p *picker) Render(leftWidth, rightWidth, height int) string {
	if leftWidth < 8 {
		leftWidth = 8
	}
	if rightWidth < 8 {
		rightWidth = 8
	}
	if height < 3 {
		height = 3
	}

	var b strings.Builder
	if p.title != "" {
		b.WriteString(titleStyle.Render(p.title))
		b.WriteString("\n")
	}

	total := leftWidth + rightWidth + 1
	if total < pickerStackWidth {
		// Narrow terminals: the same data, list above the details.
		listHeight := height / 2
		if listHeight < 3 {
			listHeight = 3
		}
		if listHeight > 8 {
			listHeight = 8
		}
		detailHeight := height - listHeight
		if detailHeight < 3 {
			detailHeight = 3
		}
		b.WriteString(p.listPane(total, listHeight))
		b.WriteString("\n")
		b.WriteString(p.detailPane(total, detailHeight))
	} else {
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
			p.listPane(leftWidth, height), " ", p.detailPane(rightWidth, height)))
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(truncate(pickerHint, total)))
	return b.String()
}

// listPane renders the scrolling item list with rounded borders.
func (p *picker) listPane(width, height int) string {
	inner := width - paneStyle.GetHorizontalFrameSize()
	if inner < 1 {
		inner = 1
	}
	if height < 1 {
		height = 1
	}

	lines := make([]string, 0, height)
	if len(p.items) == 0 {
		lines = append(lines, dimStyle.Render("Список пуст"))
	} else {
		start, rows, topMore, bottomMore := p.visible(height)
		if topMore {
			lines = append(lines, dimStyle.Render("↑ ещё "+itoa(start)))
		}
		end := start + rows
		for i := start; i < end; i++ {
			lines = append(lines, p.row(i, inner))
		}
		if bottomMore && len(lines) < height {
			lines = append(lines, dimStyle.Render("↓ ещё "+itoa(len(p.items)-end)))
		}
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	return paneStyle.Render(strings.Join(lines, "\n"))
}

// row renders one list row: marker, truncated label and a right-aligned
// muted status. The selected row is highlighted as a whole.
func (p *picker) row(i, width int) string {
	it := p.items[i]
	marker := "  "
	if i == p.cursor {
		marker = "▸ "
	}
	status := it.Status

	labelWidth := width - lipgloss.Width(marker)
	if status != "" {
		labelWidth -= lipgloss.Width(status) + 1
	}
	if labelWidth < 1 {
		labelWidth = 1
	}
	label := truncate(it.Label, labelWidth)
	padding := labelWidth - lipgloss.Width(label)
	if padding < 0 {
		padding = 0
	}

	plain := marker + label + strings.Repeat(" ", padding)
	if i == p.cursor {
		if status != "" {
			plain += " " + status
		}
		return pickerSelectedStyle.Render(plain)
	}
	if status != "" {
		return plain + " " + dimStyle.Render(status)
	}
	return plain
}

// detailPane renders the details of the selected row, wrapped to the
// pane width; long content is cut to the pane height.
func (p *picker) detailPane(width, height int) string {
	inner := width - paneStyle.GetHorizontalFrameSize()
	if inner < 1 {
		inner = 1
	}
	if height < 1 {
		height = 1
	}

	lines := make([]string, 0, height)
	item, ok := p.selected()
	if !ok {
		lines = append(lines, dimStyle.Render("Нет выбора"))
	} else {
		for _, detail := range item.Details {
			lines = append(lines, wrapText(detail, inner)...)
		}
	}
	if len(lines) == 0 {
		lines = append(lines, dimStyle.Render("Нет описания"))
	}
	if len(lines) > height {
		lines = lines[:height]
		if height > 0 {
			lines[height-1] = dimStyle.Render("…")
		}
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return paneStyle.Render(strings.Join(lines, "\n"))
}

// wrapText breaks plain text into lines of at most width runes. Long
// words are split; empty paragraphs stay as blank lines.
func wrapText(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	for _, para := range strings.Split(text, "\n") {
		if para == "" {
			out = append(out, "")
			continue
		}
		line := ""
		for _, word := range strings.Fields(para) {
			for len([]rune(word)) > width {
				if line != "" {
					out = append(out, line)
					line = ""
				}
				runes := []rune(word)
				out = append(out, string(runes[:width]))
				word = string(runes[width:])
			}
			if word == "" {
				continue
			}
			switch {
			case line == "":
				line = word
			case len([]rune(line))+1+len([]rune(word)) <= width:
				line += " " + word
			default:
				out = append(out, line)
				line = word
			}
		}
		out = append(out, line)
	}
	return out
}

// pickerContentWidth is the width available inside the shell's pane.
func (m Model) pickerContentWidth() int {
	if m.width <= 0 {
		return 100
	}
	if m.railVisible() {
		w := m.width - railWidth - 1 - paneStyle.GetHorizontalFrameSize()
		if w < 20 {
			w = 20
		}
		return w
	}
	return m.width
}

// pickerContentHeight is the body height available to a picker.
func (m Model) pickerContentHeight() int {
	if m.height <= 0 {
		return 24
	}
	h := m.height - 8 // header, footer, pane borders and the hint line
	if h < 5 {
		h = 5
	}
	return h
}

// pickerPaneWidths splits the content width: the list gets about 40%,
// clamped to 24..48 columns, the details take the rest.
func pickerPaneWidths(content int) (left, right int) {
	left = content * 2 / 5
	if left < 24 {
		left = 24
	}
	if left > 48 {
		left = 48
	}
	right = content - left - 1
	if right < 8 {
		right = 8
	}
	return left, right
}

// pickerView renders p at the shell's current size.
func (m *Model) pickerView(p *picker) string {
	left, right := pickerPaneWidths(m.pickerContentWidth())
	return p.Render(left, right, m.pickerContentHeight())
}
