package tui

import (
	"strings"

	"github.com/mattn/go-runewidth"
)

// displayWidth is the number of terminal cells s occupies. Wide CJK
// runes count as two cells, combining marks as zero, so every width
// budget in the TUI matches what the terminal actually paints.
func displayWidth(s string) int {
	return runewidth.StringWidth(s)
}

// truncate shortens s to at most n display cells, adding an ellipsis.
// It never splits a wide rune in half: a two-cell rune that does not fit
// is dropped, so the result is never wider than n.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if displayWidth(s) <= n {
		return s
	}
	limit := n - 1 // leave one cell for the ellipsis
	if limit <= 0 {
		return "…"
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := runewidth.RuneWidth(r)
		if used+w > limit {
			break
		}
		b.WriteRune(r)
		used += w
	}
	return b.String() + "…"
}

// padCells right-pads s with spaces to exactly width display cells. A
// string wider than width is returned unchanged; callers truncate first.
func padCells(s string, width int) string {
	if w := displayWidth(s); w < width {
		return s + strings.Repeat(" ", width-w)
	}
	return s
}
