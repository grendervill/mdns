package tui

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
	"mydns/internal/filter"
)

// inputMode tells what the open input line edits.
type inputMode int

const (
	inputNone inputMode = iota
	inputRule
	inputSettingsField
	inputRequestsFilter
	inputFilterListID
	inputFilterListURL
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

// loadFilterConfig fetches the live configuration for filter edits.
func loadFilterConfig(c Client) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		return filterConfigLoadedMsg{cfg: cfg, err: err}
	}
}

// hasFilterList reports whether id is already configured.
func hasFilterList(lists []config.FilterList, id string) bool {
	for _, l := range lists {
		if l.ID == id {
			return true
		}
	}
	return false
}

// filterListIndex returns the position of id in lists, or -1.
func filterListIndex(lists []config.FilterList, id string) int {
	for i, l := range lists {
		if l.ID == id {
			return i
		}
	}
	return -1
}

// validCustomListID checks the ID of a custom list: non-empty and free
// of whitespace and slashes.
func validCustomListID(id string) error {
	if id == "" {
		return errors.New("ID списка не может быть пустым")
	}
	if strings.ContainsAny(id, " \t\r\n/") {
		return fmt.Errorf("недопустимый ID списка %q", id)
	}
	return nil
}

// validHTTPSListURL checks that raw is an absolute https URL with a host.
func validHTTPSListURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("URL списка должен быть https-ссылкой с хостом")
	}
	return nil
}

// filterConfigLoadCmd refreshes the filters screen after a successful
// config change: the status, the list states and the live config.
func filterConfigLoadCmd(c Client) tea.Cmd {
	return tea.Batch(loadFilterStatus(c), loadFilterConfig(c))
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

	enabled := m.status.Filter.Enabled
	mode := m.status.Filter.Mode
	configured := -1 // unknown until the live config arrives
	if m.filterCfg != nil {
		enabled = m.filterCfg.Filter.Enabled
		if m.filterCfg.Filter.Mode != "" {
			mode = m.filterCfg.Filter.Mode
		}
		configured = len(m.filterCfg.Filter.Lists)
	}

	if enabled {
		b.WriteString(fmt.Sprintf("Режим блокировки: %s  (m — переключить)\n", modeLabel(mode)))
		b.WriteString(fmt.Sprintf("Заблокировано всего: %d\n", m.status.Filter.TotalBlocked))
	} else {
		b.WriteString(warnStyle.Render("Фильтрация выключена — e включает её из этого экрана") + "\n")
	}
	if configured >= 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("Настроено списков: %d", configured)) + "\n")
	}
	b.WriteString("\n")

	if len(m.filterLists) == 0 {
		b.WriteString(dimStyle.Render("Списки не загружены (перезайдите на экран: 5)") + "\n")
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
	b.WriteString(dimStyle.Render("enter — обновить список · u — обновить все · m — режим блокировки") + "\n")
	b.WriteString(dimStyle.Render("a — каталог · c — свой список · d — удалить · e — вкл/выкл · r — правило") + "\n")

	if m.inputActive {
		switch m.inputMode {
		case inputRule:
			b.WriteString("\n")
			b.WriteString(titleStyle.Render("Правило (block домен / allow домен): ") + m.input + "▏")
			b.WriteString("\n")
		case inputFilterListID:
			b.WriteString("\n")
			b.WriteString(titleStyle.Render("ID нового списка: ") + m.input + "▏")
			b.WriteString("\n")
		case inputFilterListURL:
			b.WriteString("\n")
			b.WriteString(dimStyle.Render("ID: "+m.filterNewID) + "\n")
			b.WriteString(titleStyle.Render("URL нового списка (https): ") + m.input + "▏")
			b.WriteString("\n")
		}
	}
	return b.String()
}

// catalogView renders the built-in list picker.
func (m *Model) catalogView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Каталог списков"))
	b.WriteString(dimStyle.Render("  (j/k — выбор, enter — добавить/удалить, esc — назад)") + "\n\n")

	entries := filter.Catalog()
	if m.filterCfg == nil {
		b.WriteString(dimStyle.Render("Конфигурация загружается…") + "\n")
		return b.String()
	}

	b.WriteString(dimStyle.Render(fmt.Sprintf("  %-24s %-26s %-16s %s", "ID", "название", "категория", "статус")))
	b.WriteString("\n")
	for i, e := range entries {
		marker := "  "
		if i == m.catalogCursor {
			marker = "> "
		}
		state := dimStyle.Render("нет")
		if hasFilterList(m.filterCfg.Filter.Lists, e.ID) {
			state = okStyle.Render("установлен")
		}
		line := fmt.Sprintf("%s%-24s %-26s %-16s %s",
			marker, truncate(e.ID, 24), truncate(e.Name, 26), catalogCategoryLabel(e.Category), state)
		if i == m.catalogCursor {
			line = activeTabStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.filterErr != nil {
		b.WriteString("\n" + errStyle.Render(m.filterErr.Error()) + "\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("enter — добавить или удалить список · esc — вернуться к фильтрам"))
	b.WriteString("\n")
	return b.String()
}

// catalogCategoryLabel renders a catalog category in Russian.
func catalogCategoryLabel(category string) string {
	switch category {
	case "ads":
		return "реклама"
	case "combined":
		return "комбинированные"
	case "regional":
		return "региональные"
	default:
		return category
	}
}

// applyFilterCfg sends the edited filter configuration and keeps the
// local copy in step until the daemon reload lands.
func (m Model) applyFilterCfg(next *config.Config) (tea.Model, tea.Cmd) {
	m.filterCfg = next
	m.filterErr = nil
	return m, applySettingsCmd(m.client, cloneConfig(next))
}

// toggleCatalogList adds the highlighted catalog list or removes it.
func (m Model) toggleCatalogList() (tea.Model, tea.Cmd) {
	entries := filter.Catalog()
	if m.filterCfg == nil || m.catalogCursor >= len(entries) {
		return m, nil
	}
	id := entries[m.catalogCursor].ID
	next := cloneConfig(m.filterCfg)
	if i := filterListIndex(next.Filter.Lists, id); i >= 0 {
		next.Filter.Lists = append(next.Filter.Lists[:i], next.Filter.Lists[i+1:]...)
	} else {
		next.Filter.Lists = append(next.Filter.Lists, config.FilterList{ID: id})
	}
	return m.applyFilterCfg(next)
}

// removeSelectedFilterList drops the list under the status cursor.
func (m Model) removeSelectedFilterList() (tea.Model, tea.Cmd) {
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	id := ""
	if len(m.filterLists) > 0 && m.filterCursor < len(m.filterLists) {
		id = m.filterLists[m.filterCursor].ID
	} else if m.filterCursor < len(m.filterCfg.Filter.Lists) {
		id = m.filterCfg.Filter.Lists[m.filterCursor].ID
	}
	if id == "" {
		m.filterErr = errors.New("список не выбран")
		return m, nil
	}
	next := cloneConfig(m.filterCfg)
	i := filterListIndex(next.Filter.Lists, id)
	if i < 0 {
		m.filterErr = fmt.Errorf("список не найден в конфигурации: %s", id)
		return m, nil
	}
	next.Filter.Lists = append(next.Filter.Lists[:i], next.Filter.Lists[i+1:]...)
	if m.filterCursor >= len(next.Filter.Lists) && m.filterCursor > 0 {
		m.filterCursor--
	}
	return m.applyFilterCfg(next)
}

// toggleFilterEnabled flips cfg.Filter.Enabled and applies it.
func (m Model) toggleFilterEnabled() (tea.Model, tea.Cmd) {
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	next := cloneConfig(m.filterCfg)
	next.Filter.Enabled = !next.Filter.Enabled
	m.status.Filter.Enabled = next.Filter.Enabled // optimistic until the reload
	return m.applyFilterCfg(next)
}

// startCustomList opens the first step of the custom-list input.
func (m Model) startCustomList() (tea.Model, tea.Cmd) {
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	m.filterErr = nil
	m.filterNewID = ""
	m.input = ""
	m.inputActive = true
	m.inputMode = inputFilterListID
	return m, nil
}

// commitFilterListID validates the ID and moves on to the URL step.
func (m Model) commitFilterListID() (tea.Model, tea.Cmd) {
	id := strings.TrimSpace(m.input)
	if err := validCustomListID(id); err != nil {
		m.filterErr = err
		return m, nil // stay in the flow with the typed text
	}
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, nil
	}
	if hasFilterList(m.filterCfg.Filter.Lists, id) {
		m.filterErr = fmt.Errorf("список уже добавлен: %s", id)
		return m, nil
	}
	m.filterNewID = id
	m.input = ""
	m.inputMode = inputFilterListURL
	m.filterErr = nil
	return m, nil
}

// commitFilterListURL appends the custom list and applies the config.
func (m Model) commitFilterListURL() (tea.Model, tea.Cmd) {
	raw := strings.TrimSpace(m.input)
	if err := validHTTPSListURL(raw); err != nil {
		m.filterErr = err
		return m, nil // stay in the flow with the typed text
	}
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, nil
	}
	next := cloneConfig(m.filterCfg)
	next.Filter.Lists = append(next.Filter.Lists, config.FilterList{ID: m.filterNewID, URL: raw})
	m.input = ""
	m.inputActive = false
	m.inputMode = inputNone
	m.filterNewID = ""
	return m.applyFilterCfg(next)
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
