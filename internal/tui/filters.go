package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// inputMode tells what the open input line edits.
type inputMode int

const (
	inputNone inputMode = iota
	inputRule
	inputSettingsField
	inputRequestsFilter
)

// nextBlockMode cycles the block mode.
func nextBlockMode(mode string) string {
	switch mode {
	case "zero":
		return "nxdomain"
	case "nxdomain":
		return "refused"
	default:
		return "zero"
	}
}

// modeLabel renders a block mode.
func modeLabel(mode string) string {
	switch mode {
	case "nxdomain":
		return "nxdomain (несуществующий домен)"
	case "refused":
		return "refused (отказ)"
	default:
		return "zero (0.0.0.0 / ::)"
	}
}

// loadFilterStatus fetches the per-list statuses.
func loadFilterStatus(c Client) tea.Cmd {
	return func() tea.Msg {
		lists, err := c.FilterStatus(context.Background())
		return filterLoadedMsg{lists: lists, err: err}
	}
}

// filterUpdateCmd refreshes one list or all of them.
func filterUpdateCmd(c Client, id string) tea.Cmd {
	return func() tea.Msg {
		return filterUpdatedMsg{err: c.FilterUpdate(context.Background(), id)}
	}
}

// applyModeCmd sends the whole config with a new block mode.
func applyModeCmd(c Client, mode string) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		if err != nil {
			return configAppliedMsg{err: err}
		}
		cfg.Filter.Mode = mode
		return configAppliedMsg{err: c.UpdateConfig(context.Background(), cfg)}
	}
}

// addUserRuleCmd appends one user rule and applies the config.
func addUserRuleCmd(c Client, kind, domain string) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		if err != nil {
			return configAppliedMsg{err: err}
		}
		if kind == "allow" {
			cfg.Filter.UserAllow = append(cfg.Filter.UserAllow, domain)
		} else {
			cfg.Filter.UserBlock = append(cfg.Filter.UserBlock, domain)
		}
		return configAppliedMsg{err: c.UpdateConfig(context.Background(), cfg)}
	}
}

// filtersView renders the block-list screen.
func (m *Model) filtersView() string {
	var b strings.Builder

	if m.status.Filter.Enabled {
		b.WriteString(fmt.Sprintf("Режим блокировки: %s  (m — переключить)\n", modeLabel(m.status.Filter.Mode)))
		b.WriteString(fmt.Sprintf("Заблокировано всего: %d\n\n", m.status.Filter.TotalBlocked))
	} else {
		b.WriteString(warnStyle.Render("Фильтрация выключена — включите её в «Настройках» или визарде") + "\n\n")
	}

	if len(m.filterLists) == 0 {
		b.WriteString(dimStyle.Render("Списки не загружены (r — обновить)") + "\n")
	} else {
		b.WriteString(dimStyle.Render("  список                 правил      пропуск  обновлён          статус"))
		b.WriteString("\n")
		for i, l := range m.filterLists {
			marker := "  "
			if i == m.filterCursor {
				marker = "> "
			}
			state := okStyle.Render("ок")
			if l.Error != "" {
				state = errStyle.Render("ошибка: " + truncate(l.Error, 44))
			}
			updated := "—"
			if !l.UpdatedAt.IsZero() {
				updated = l.UpdatedAt.Format("02.01 15:04:05")
			}
			b.WriteString(fmt.Sprintf("%s%-22s %-11d %-8d %-17s %s\n",
				marker, truncate(l.ID, 22), l.Applied, l.Skipped, updated, state))
		}
	}

	if m.filterErr != nil {
		b.WriteString("\n" + errStyle.Render(m.filterErr.Error()) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("enter — обновить список · u — обновить все · m — режим блокировки · a — добавить правило"))
	b.WriteString("\n")

	if m.inputActive && m.inputMode == inputRule {
		b.WriteString("\n")
		b.WriteString(titleStyle.Render("Правило (block домен / allow домен): ") + m.input + "▏")
		b.WriteString("\n")
	}
	return b.String()
}

// commitRule parses and applies the rule input.
func (m Model) commitRule() (tea.Model, tea.Cmd) {
	text := strings.TrimSpace(m.input)
	m.input = ""
	m.inputActive = false

	if text == "" {
		return m, nil
	}

	parts := strings.Fields(text)
	if len(parts) != 2 || (parts[0] != "block" && parts[0] != "allow") {
		m.filterErr = errors.New("формат правила: block домен или allow домен")
		return m, nil
	}

	m.filterErr = nil
	return m, addUserRuleCmd(m.client, parts[0], parts[1])
}

// applyFilterUpdateResult reloads the statuses after a manual update.
func (m Model) applyFilterUpdateResult(err error) (tea.Model, tea.Cmd) {
	m.filterErr = err
	return m, loadFilterStatus(m.client)
}
