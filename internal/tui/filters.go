package tui

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
	// inputUpstreamFormField edits the focused field of the custom
	// upstream form.
	inputUpstreamFormField
	// inputUpstreamPriority edits the priority of the selected upstream.
	inputUpstreamPriority
	// inputMaintenancePassword and inputMaintenanceConfirm edit the
	// panel password pair on the maintenance screen. Both are secrets.
	inputMaintenancePassword
	inputMaintenanceConfirm
)

// blockModes is the order of the block-mode picker.
var blockModes = []string{"zero", "nxdomain", "refused"}

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

// loadFilterConfigKeepErr reloads the live config but preserves the error
// the caller already set: a rejected write must stay visible after the
// fresh copy arrives (and the rejected copy must be replaced).
func loadFilterConfigKeepErr(c Client) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		return filterConfigLoadedMsg{cfg: cfg, err: err, keepErr: true}
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

// filterRow is one visible line of the filters table: the live status
// when the updater has reported, or just the configured list before the
// first status arrives. Every key acts on the selected visible row, so
// the screen can never delete a list it does not show.
type filterRow struct {
	id   string
	url  string
	live *filter.ListStatus
}

// filterRows returns the rows the screen renders: the statuses when
// they exist, otherwise the lists from the live config (filtering may be
// disabled, and then the updater reports none).
func (m *Model) filterRows() []filterRow {
	if len(m.filterLists) > 0 {
		rows := make([]filterRow, len(m.filterLists))
		for i := range m.filterLists {
			rows[i] = filterRow{
				id:   m.filterLists[i].ID,
				url:  m.filterLists[i].URL,
				live: &m.filterLists[i],
			}
		}
		return rows
	}
	if m.filterCfg == nil {
		return nil
	}
	rows := make([]filterRow, 0, len(m.filterCfg.Filter.Lists))
	for _, l := range m.filterCfg.Filter.Lists {
		rows = append(rows, filterRow{id: l.ID, url: l.URL})
	}
	return rows
}

// selectedFilterRow returns the row under the cursor, if any.
func (m *Model) selectedFilterRow() (filterRow, bool) {
	rows := m.filterRows()
	if m.filterCursor < 0 || m.filterCursor >= len(rows) {
		return filterRow{}, false
	}
	return rows[m.filterCursor], true
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

	rows := m.filterRows()
	if len(rows) == 0 {
		switch {
		case m.filterErr != nil && m.filterCfg == nil:
			b.WriteString(errStyle.Render("Не удалось загрузить списки: "+truncate(m.filterErr.Error(), 70)) + "\n")
		case m.filterCfg == nil && len(m.filterLists) == 0:
			b.WriteString(dimStyle.Render("Списки загружаются…") + "\n")
		default:
			// An honest empty state: nothing is configured, and these
			// are the keys that change that.
			b.WriteString(dimStyle.Render("Списков нет — a откроет каталог, c добавит свой") + "\n")
		}
	} else {
		b.WriteString(dimStyle.Render("  список                 правил      пропуск  обновлён          статус"))
		b.WriteString("\n")
		for i, row := range rows {
			marker := "  "
			if i == m.filterCursor {
				marker = "> "
			}
			applied, skipped, updated := "—", "—", "—"
			state := dimStyle.Render("не загружен")
			if row.live != nil {
				applied = fmt.Sprintf("%d", row.live.Applied)
				skipped = fmt.Sprintf("%d", row.live.Skipped)
				state = okStyle.Render("ок")
				if row.live.Error != "" {
					state = errStyle.Render("ошибка: " + truncate(row.live.Error, 44))
				}
				if !row.live.UpdatedAt.IsZero() {
					updated = row.live.UpdatedAt.Format("02.01 15:04:05")
				}
			}
			b.WriteString(fmt.Sprintf("%s%-22s %-11s %-8s %-17s %s\n",
				marker, truncate(row.id, 22), applied, skipped, updated, state))
			if row.url != "" {
				b.WriteString("   " + dimStyle.Render(truncate(row.url, 72)) + "\n")
			}
		}
	}

	if m.filterErr != nil {
		b.WriteString("\n" + errStyle.Render(m.filterErr.Error()) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("enter — обновить список · u — обновить все · m — режим блокировки") + "\n")
	b.WriteString(dimStyle.Render("a — каталог · c — свой список · d — удалить · x — правила · e — вкл/выкл · r — правило") + "\n")

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

// catalogView renders the built-in list picker. A config load failure
// gets a small error screen instead of a picker that cannot be trusted;
// a rejected action keeps the picker and pins its error above it.
func (m *Model) catalogView() string {
	m.filterCatalogPicker()
	if m.filterErr == nil {
		return m.pickerView(&m.picker)
	}
	if m.filterCfg == nil {
		return m.filterConfigErrorView()
	}
	return m.pickerViewWithNote(&m.picker, m.filterErr.Error())
}

// filterConfigErrorView renders the catalog's config-loading failure on
// its own, so the text is visible without scrolling.
func (m *Model) filterConfigErrorView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Каталог списков") + "\n\n")
	b.WriteString(errStyle.Render("Не удалось загрузить конфигурацию фильтра:") + "\n")
	for _, line := range wrapText(m.filterErr.Error(), m.pickerContentWidth()) {
		b.WriteString(errStyle.Render(line) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("esc — назад") + "\n")
	return b.String()
}

// openFilterCatalog opens the catalog picker on its first row.
func (m *Model) openFilterCatalog() {
	m.pickerReturn = screenFilters
	m.picker = picker{title: "Каталог списков"}
	m.filterCatalogPicker()
	m.filterErr = nil
	m.screen = screenFilterCatalog
	m.settleRail()
}

// filterCatalogPicker refreshes the picker rows from the live config and
// the last status snapshot, keeping the cursor.
func (m *Model) filterCatalogPicker() {
	entries := filter.Catalog()
	items := make([]pickerItem, 0, len(entries))
	for _, e := range entries {
		installed := m.filterCfg != nil && hasFilterList(m.filterCfg.Filter.Lists, e.ID)
		status := "нет"
		if installed {
			status = "установлен"
		}
		details := []string{
			e.Name + " (" + e.ID + ")",
			"Категория: " + catalogCategoryLabel(e.Category),
			e.Description,
			"URL: " + e.URL,
		}
		if installed {
			details = append(details, "Статус: установлен — enter уберёт список.")
		} else {
			details = append(details, "Статус: не установлен — enter добавит список.")
		}
		if live := m.filterStatusByID(e.ID); live != nil {
			applied, skipped := strconv.Itoa(live.Applied), strconv.Itoa(live.Skipped)
			details = append(details, "Правил: применено "+applied+" · пропущено "+skipped)
			if live.Error != "" {
				details = append(details, "Ошибка: "+live.Error)
			}
		}
		details = append(details,
			"",
			"Косметические правила (скрытие элементов) на уровне DNS игнорируются —",
			"применяются только доменные правила списка.")
		items = append(items, pickerItem{Label: e.Name, Status: status, Details: details})
	}
	m.picker.setItems(items)
}

// filterStatusByID returns the live status of one list, if reported.
func (m *Model) filterStatusByID(id string) *filter.ListStatus {
	for i := range m.filterLists {
		if m.filterLists[i].ID == id {
			return &m.filterLists[i]
		}
	}
	return nil
}

// userRule is one allow/block entry of the live config; index is its
// position in the matching slice.
type userRule struct {
	kind   string // "allow" or "block"
	index  int
	domain string
}

// userRuleRows lists the user rules in render order: allow rules first,
// then block rules.
func (m *Model) userRuleRows() []userRule {
	if m.filterCfg == nil {
		return nil
	}
	out := make([]userRule, 0, len(m.filterCfg.Filter.UserAllow)+len(m.filterCfg.Filter.UserBlock))
	for i, d := range m.filterCfg.Filter.UserAllow {
		out = append(out, userRule{kind: "allow", index: i, domain: d})
	}
	for i, d := range m.filterCfg.Filter.UserBlock {
		out = append(out, userRule{kind: "block", index: i, domain: d})
	}
	return out
}

// userRulesView renders the user-rule picker, with a failed deletion's
// error pinned above the rows so Esc cannot hide it unseen.
func (m *Model) userRulesView() string {
	m.userRulesPicker()
	if m.filterErr == nil {
		return m.pickerView(&m.picker)
	}
	return m.pickerViewWithNote(&m.picker, m.filterErr.Error())
}

// openUserRules opens the allow/block rule list on the filters screen.
func (m Model) openUserRules() (tea.Model, tea.Cmd) {
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	m.pickerReturn = screenFilters
	m.picker = picker{title: "Правила пользователя"}
	m.userRulesPicker()
	m.filterErr = nil
	m.screen = screenUserRules
	m.settleRail()
	return m, nil
}

// userRulesPicker fills the rows; every row's details name the action
// Enter performs so a delete is never blind.
func (m *Model) userRulesPicker() {
	rows := m.userRuleRows()
	items := make([]pickerItem, 0, len(rows))
	for _, r := range rows {
		label := r.kind + " " + r.domain
		status := ""
		details := []string{
			"Тип: " + r.kind + " (правило пользователя)",
			"Домен: " + r.domain,
			"",
			"enter — удалить это правило и применить конфигурацию.",
			"Списки фильтра не затрагиваются.",
		}
		items = append(items, pickerItem{Label: label, Status: status, Details: details})
	}
	m.picker.setItems(items)
}

// deleteSelectedUserRule removes the rule under the cursor from the live
// config copy and applies it. Duplicates are deleted one at a time by
// their exact index.
func (m Model) deleteSelectedUserRule() (tea.Model, tea.Cmd) {
	rows := m.userRuleRows()
	if m.picker.cursor < 0 || m.picker.cursor >= len(rows) {
		return m, nil
	}
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	row := rows[m.picker.cursor]
	next := cloneConfig(m.filterCfg)
	if row.kind == "allow" {
		next.Filter.UserAllow = append(next.Filter.UserAllow[:row.index], next.Filter.UserAllow[row.index+1:]...)
	} else {
		next.Filter.UserBlock = append(next.Filter.UserBlock[:row.index], next.Filter.UserBlock[row.index+1:]...)
	}
	m.filterErr = nil
	return m.applyFilterCfg(next)
}

// modePickerView renders the block-mode picker.
func (m *Model) modePickerView() string {
	m.modePickerItems()
	return m.pickerView(&m.picker)
}

// openModePicker opens the block-mode list on the current mode.
func (m Model) openModePicker() (tea.Model, tea.Cmd) {
	m.pickerReturn = screenFilters
	m.picker = picker{title: "Режим блокировки"}
	m.modePickerItems()
	for i, mode := range blockModes {
		if mode == m.currentBlockMode() {
			m.picker.cursor = i
		}
	}
	m.filterErr = nil
	m.screen = screenModePicker
	m.settleRail()
	return m, nil
}

// modePickerItems fills the block-mode rows.
func (m *Model) modePickerItems() {
	items := make([]pickerItem, 0, len(blockModes))
	for _, mode := range blockModes {
		status := ""
		if mode == m.currentBlockMode() {
			status = "сейчас"
		}
		items = append(items, pickerItem{
			Label:   mode,
			Status:  status,
			Details: modeDetails(mode),
		})
	}
	m.picker.setItems(items)
}

// currentBlockMode prefers the live config over the status snapshot.
func (m *Model) currentBlockMode() string {
	if m.filterCfg != nil && m.filterCfg.Filter.Mode != "" {
		return m.filterCfg.Filter.Mode
	}
	if m.status.Filter.Mode != "" {
		return m.status.Filter.Mode
	}
	return blockModes[0]
}

// modeDetails explains the DNS answer a blocked client receives.
func modeDetails(mode string) []string {
	switch mode {
	case "nxdomain":
		return []string{
			"Клиент получает NXDOMAIN — «такого домена не существует».",
			"Блокировка выглядит как ошибка в имени, а не как пустой ответ.",
		}
	case "refused":
		return []string{
			"Клиент получает REFUSED — сервер отказался отвечать.",
			"Некоторые приложения показывают ошибку сети вместо пустой страницы.",
		}
	default:
		return []string{
			"Клиент получает 0.0.0.0 (IPv4) или :: (IPv6).",
			"Соединение не устанавливается, страница выглядит пустой.",
		}
	}
}

// applyModePick applies the highlighted block mode and returns to the
// filters screen.
func (m Model) applyModePick() (tea.Model, tea.Cmd) {
	it, ok := m.picker.selected()
	if !ok {
		return m, nil
	}
	mode := it.Label
	m.screen = screenFilters
	m.settleRail()
	m.status.Filter.Mode = mode // optimistic until the reload lands
	if m.filterCfg != nil {
		next := cloneConfig(m.filterCfg)
		next.Filter.Mode = mode
		m.filterCfg = next
	}
	m.filterErr = nil
	return m, applyModeCmd(m.client, mode)
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
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	if m.picker.cursor < 0 || m.picker.cursor >= len(entries) {
		return m, nil
	}
	id := entries[m.picker.cursor].ID
	next := cloneConfig(m.filterCfg)
	if i := filterListIndex(next.Filter.Lists, id); i >= 0 {
		next.Filter.Lists = append(next.Filter.Lists[:i], next.Filter.Lists[i+1:]...)
	} else {
		next.Filter.Lists = append(next.Filter.Lists, config.FilterList{ID: id})
	}
	return m.applyFilterCfg(next)
}

// removeSelectedFilterList drops the list under the cursor. It refuses
// when no row is visible: a delete must never resolve an invisible list
// from the config by index.
func (m Model) removeSelectedFilterList() (tea.Model, tea.Cmd) {
	row, ok := m.selectedFilterRow()
	if !ok {
		m.filterErr = errors.New("список не выбран")
		return m, nil
	}
	if m.filterCfg == nil {
		m.filterErr = errors.New("конфигурация ещё не загружена")
		return m, loadFilterConfig(m.client)
	}
	id := row.id
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
