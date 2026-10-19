package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
	"mydns/internal/filter"
)

// filterListsMsg builds a filterLoadedMsg with two list statuses.
func filterListsMsg() filterLoadedMsg {
	return filterLoadedMsg{lists: []filter.ListStatus{
		{ID: "oisd-small", URL: "https://small.oisd.nl/", Applied: 56754, Skipped: 3},
		{ID: "broken-list", URL: "https://x/list.txt", Error: "connection refused"},
	}}
}

// enterKey is the shared enter key message.
func enterKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }

// typeText feeds r as individual rune keys.
func typeText(m Model, s string) Model {
	for _, r := range s {
		m = step(m, key(r))
	}
	return m
}

// TestFiltersView checks the list table renders statuses and errors.
func TestFiltersView(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "filters"})
	m = step(m, filterListsMsg())
	m = step(m, statusLoadedMsg{st: sampleStatus()})

	view := m.View()
	for _, want := range []string{"oisd-small", "56754", "broken-list", "connection refused"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "каталог") || !strings.Contains(view, "свой список") {
		t.Errorf("View() misses the new filter keys:\n%s", view)
	}
}

// drainCmd runs a command and folds every message it produces (batches
// included) into the model.
func drainCmd(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	if cmd == nil {
		return m
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			m = drainCmd(t, m, c)
		}
		return m
	}
	return step(m, msg)
}

// moveToSettingsField walks the cursor to the named settings field.
func moveToSettingsField(t *testing.T, m Model, name string) Model {
	t.Helper()
	for i := 0; i < len(m.settingsFields()); i++ {
		if m.settingsFields()[m.settingsCursor].name == name {
			return m
		}
		m = step(m, key('j'))
	}
	t.Fatalf("settings field %q not found", name)
	return m
}

// editSettingsField opens the named field, types value (nothing when
// empty) and commits it.
func editSettingsField(t *testing.T, m Model, name, value string) Model {
	t.Helper()
	m = moveToSettingsField(t, m, name)
	m = step(m, enterKey())
	if !m.inputActive {
		t.Fatalf("enter on %q did not open the input", name)
	}
	m = typeText(m, value)
	updated, _ := m.Update(enterKey())
	return updated.(Model)
}

// pickTimezone opens the timezone picker from the settings screen,
// selects the named row and confirms it.
func pickTimezone(t *testing.T, m Model, label string) Model {
	t.Helper()
	if m.screen != screenTimezonePicker {
		m = moveToSettingsField(t, m, timezoneFieldName)
		m = step(m, enterKey())
	}
	if m.screen != screenTimezonePicker {
		t.Fatalf("enter on the timezone field opened %v, want the timezone picker", m.screen)
	}
	found := false
	for i, c := range timezoneChoices {
		if c.label == label {
			m.picker.cursor = i
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("timezone choice %q not found", label)
	}
	updated, cmd := m.Update(enterKey())
	if cmd != nil {
		t.Errorf("staging timezone %q returned a command", label)
	}
	return updated.(Model)
}

// TestFilterManualUpdate checks that enter refreshes the list under the
// cursor.
func TestFilterManualUpdate(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterListsMsg())

	m = step(m, key('j')) // cursor to the second list
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("enter returned no command")
	}
	_ = cmd()

	if len(sc.filters) != 1 || sc.filters[0] != "broken-list" {
		t.Errorf("FilterUpdate calls = %v, want [broken-list]", sc.filters)
	}
}

// TestFilterUpdateAll checks the u key.
func TestFilterUpdateAll(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterListsMsg())

	updated, cmd := m.Update(key('u'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("u returned no command")
	}
	_ = cmd()

	if len(sc.filters) != 1 || sc.filters[0] != "" {
		t.Errorf("FilterUpdate calls = %v, want one call with an empty id", sc.filters)
	}
}

// TestFilterModeToggle checks that m opens the mode picker, the current
// mode is marked, and Enter applies the highlighted mode.
func TestFilterModeToggle(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, statusLoadedMsg{st: sampleStatus()}) // mode zero

	updated, cmd := m.Update(key('m'))
	m = updated.(Model)
	if cmd != nil {
		t.Fatalf("m returned a command, want the picker screen")
	}
	if m.screen != screenModePicker {
		t.Fatalf("screen = %v, want the mode picker", m.screen)
	}
	if !strings.Contains(m.View(), "сейчас") || !strings.Contains(m.View(), "0.0.0.0") {
		t.Errorf("mode picker View() misses the marker or the explanation:\n%s", m.View())
	}

	m = step(m, key('j')) // zero → nxdomain
	if !strings.Contains(m.View(), "NXDOMAIN") {
		t.Errorf("mode picker View() misses the NXDOMAIN explanation:\n%s", m.View())
	}
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if m.screen != screenFilters {
		t.Errorf("screen = %v after Enter, want filters", m.screen)
	}
	if cmd == nil {
		t.Fatalf("Enter returned no command")
	}
	_ = cmd()

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Filter.Mode; got != "nxdomain" {
		t.Errorf("sent filter.mode = %q, want nxdomain", got)
	}
	if !strings.Contains(m.View(), "nxdomain") {
		t.Errorf("View() does not show the new mode:\n%s", m.View())
	}
}

// TestUserRuleAdd checks the r-key rule input for both block and allow.
func TestUserRuleAdd(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, statusLoadedMsg{st: sampleStatus()})

	m = step(m, key('r'))
	m = typeText(m, "block ads.example.com")
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("enter after the rule returned no command")
	}
	_ = cmd()

	m = step(m, key('r'))
	m = typeText(m, "allow safe.example.com")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	_ = cmd()

	if len(sc.updates) != 2 {
		t.Fatalf("UpdateConfig calls = %d, want 2", len(sc.updates))
	}
	if got := sc.updates[0].Filter.UserBlock; len(got) != 1 || got[0] != "ads.example.com" {
		t.Errorf("user_block after block rule = %v, want [ads.example.com]", got)
	}
	if got := sc.updates[1].Filter.UserAllow; len(got) != 1 || got[0] != "safe.example.com" {
		t.Errorf("user_allow after allow rule = %v, want [safe.example.com]", got)
	}
}

// TestSettingsApply checks that editing a field and ctrl+s sends the
// updated config.
func TestSettingsApply(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "settings"})
	m = step(m, configLoadedMsg{cfg: config.Default()})

	// Move to the strategy field.
	for i := 0; i < len(m.settingsFields()); i++ {
		if m.settingsFields()[m.settingsCursor].name == "Стратегия" {
			break
		}
		m = step(m, key('j'))
	}
	m = step(m, enterKey())
	if !m.inputActive {
		t.Fatalf("enter did not open the input")
	}
	m = typeText(m, "random")
	updated, _ := m.Update(enterKey())
	m = updated.(Model)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("ctrl+s returned no command")
	}
	_ = cmd()

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Strategy; got != "random" {
		t.Errorf("sent strategy = %q, want random", got)
	}
}

// TestSettingsApplyError checks that an apply failure surfaces without
// losing the edited values.
func TestSettingsApplyError(t *testing.T) {
	sc := &stubClient{updateErr: errors.New("boom: invalid domain")}
	m := New(sc, Options{Initial: "settings"})
	m = step(m, configLoadedMsg{cfg: config.Default()})

	for m.settingsFields()[m.settingsCursor].name != "Домен" {
		m = step(m, key('j'))
	}
	m = step(m, enterKey())
	m = typeText(m, "new.example.com")
	updated, _ := m.Update(enterKey())
	m = updated.(Model)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("ctrl+s returned no command")
	}
	msg, ok := cmd().(configAppliedMsg)
	if !ok {
		t.Fatalf("ctrl+s command produced %T, want configAppliedMsg", cmd())
	}
	m = step(m, msg)

	if m.settingsErr == nil {
		t.Fatalf("settingsErr = nil after a failed apply")
	}
	if !strings.Contains(m.View(), "boom") {
		t.Errorf("View() misses the error text:\n%s", m.View())
	}
	if got := m.settingsCfg.Domain; got != "new.example.com" {
		t.Errorf("edited domain = %q, want it kept after the failure", got)
	}
}

// TestSettingsNewFieldRoundTrip checks the timezone (including the
// empty/system value), the DoH path and the list refresh interval.
func TestSettingsNewFieldRoundTrip(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "settings"})
	m = step(m, configLoadedMsg{cfg: config.Default()})

	if !strings.Contains(m.View(), "Europe/Moscow, Europe/London, UTC") {
		t.Errorf("the timezone hint is missing:\n%s", m.View())
	}

	m = pickTimezone(t, m, "Europe/Moscow")
	if got := m.settingsCfg.Timezone; got != "Europe/Moscow" {
		t.Errorf("timezone = %q, want Europe/Moscow", got)
	}
	m = pickTimezone(t, m, "системный")
	if got := m.settingsCfg.Timezone; got != "" {
		t.Errorf("timezone = %q, want it cleared to the system zone", got)
	}
	m = editSettingsField(t, m, "Путь DoH", "/doh")
	if got := m.settingsCfg.Protocols.DoH.Path; got != "/doh" {
		t.Errorf("doh path = %q, want /doh", got)
	}
	// An empty path is valid: the daemon falls back to /dns-query.
	m = editSettingsField(t, m, "Путь DoH", "")
	if got := m.settingsCfg.Protocols.DoH.Path; got != "" {
		t.Errorf("doh path = %q, want it cleared to the /dns-query default", got)
	}
	m = editSettingsField(t, m, "Интервал обновления списков, ч", "6")
	if got := m.settingsCfg.Filter.UpdateIntervalHours; got != 6 {
		t.Errorf("interval = %d, want 6", got)
	}

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	got := sc.updates[0]
	if got.Timezone != "" {
		t.Errorf("sent timezone = %q, want empty", got.Timezone)
	}
	if got.Protocols.DoH.Path != "" {
		t.Errorf("sent doh path = %q, want empty (the /dns-query default)", got.Protocols.DoH.Path)
	}
	if got.Filter.UpdateIntervalHours != 6 {
		t.Errorf("sent interval = %d, want 6", got.Filter.UpdateIntervalHours)
	}
}

// TestSettingsNewFieldApplyError checks that a rejected timezone is
// surfaced by the daemon and the edited value is kept.
func TestSettingsNewFieldApplyError(t *testing.T) {
	sc := &stubClient{updateErr: errors.New(`timezone: cannot load IANA zone "Mars/Base"`)}
	m := New(sc, Options{Initial: "settings"})
	m = step(m, configLoadedMsg{cfg: config.Default()})

	m = pickTimezone(t, m, "Своё…")
	if !m.inputActive || m.inputMode != inputSettingsField {
		t.Fatalf("«Своё…» did not open the free-text timezone input")
	}
	m = typeText(m, "Mars/Base")
	updated, _ := m.Update(enterKey())
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	if m.settingsErr == nil {
		t.Fatalf("settingsErr = nil after a rejected timezone")
	}
	if !strings.Contains(m.View(), "IANA") {
		t.Errorf("View() misses the daemon error:\n%s", m.View())
	}
	if got := m.settingsCfg.Timezone; got != "Mars/Base" {
		t.Errorf("timezone = %q, want it kept after the failure", got)
	}
}

// TestFilterCatalogToggle checks the catalog picker: installed markers
// from the live config, Enter adding a {ID} entry and removing it again.
func TestFilterCatalogToggle(t *testing.T) {
	cfg := config.Default()
	cfg.Filter.Lists = []config.FilterList{{ID: "oisd-full"}}
	sc := &stubClient{cfg: cfg}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterConfigLoadedMsg{cfg: cfg})

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	if m.screen != screenFilterCatalog {
		t.Fatalf("screen = %v, want the catalog picker", m.screen)
	}
	m = drainCmd(t, m, cmd)

	view := m.View()
	for _, want := range []string{"adguard-dns-filter", "AdGuard DNS filter", "реклама", "установлен"} {
		if !strings.Contains(view, want) {
			t.Errorf("catalog View() misses %q:\n%s", want, view)
		}
	}

	m = step(m, key('j'))
	if m.picker.cursor != 1 {
		t.Errorf("j moved the cursor to %d, want 1", m.picker.cursor)
	}
	m = step(m, key('k'))
	if m.picker.cursor != 0 {
		t.Errorf("k moved the cursor to %d, want 0", m.picker.cursor)
	}

	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	got := sc.updates[0].Filter.Lists
	if len(got) != 2 || got[0].ID != "oisd-full" || got[1].ID != "adguard-dns-filter" || got[1].URL != "" {
		t.Errorf("lists after the add = %+v, want oisd-full then adguard-dns-filter with no URL", got)
	}

	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 2 {
		t.Fatalf("UpdateConfig calls = %d, want 2", len(sc.updates))
	}
	got = sc.updates[1].Filter.Lists
	if len(got) != 1 || got[0].ID != "oisd-full" {
		t.Errorf("lists after the second Enter = %+v, want just oisd-full", got)
	}

	m = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != screenFilters {
		t.Errorf("esc left the picker on %v, want the filters screen", m.screen)
	}
}

// TestFilterCatalogDetails checks the right pane: category, description,
// URL, the applied/skipped counters and the DNS-level cosmetic note.
func TestFilterCatalogDetails(t *testing.T) {
	cfg := config.Default()
	sc := &stubClient{cfg: cfg}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterConfigLoadedMsg{cfg: cfg})
	m = step(m, filterLoadedMsg{lists: []filter.ListStatus{{
		ID: "adguard-dns-filter", Applied: 123, Skipped: 4,
	}}})
	m = step(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	m = drainCmd(t, m, cmd)

	view := m.View()
	for _, want := range []string{
		"реклама", "AdGuard's DNS-tuned", "https://adguardteam.github.io",
		"применено 123", "пропущено 4", "Косметические", "не установлен",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("catalog View() misses %q:\n%s", want, view)
		}
	}

	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Filter.Lists; len(got) != 1 || got[0].ID != "adguard-dns-filter" {
		t.Errorf("lists after Enter = %+v, want adguard-dns-filter installed", got)
	}
}

// TestSettingsStrategyPicker checks that s on Settings opens the strategy
// list, marks the current value and applies the chosen one.
func TestSettingsStrategyPicker(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "settings"})
	m = step(m, configLoadedMsg{cfg: config.Default()})

	m = step(m, key('s'))
	if m.screen != screenStrategyPicker {
		t.Fatalf("screen = %v, want the strategy picker", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "сейчас") || !strings.Contains(view, "fastest") {
		t.Errorf("strategy picker View() misses the current marker:\n%s", view)
	}

	m = step(m, key('j'))
	m = step(m, key('j'))
	m = step(m, key('j')) // fastest → random
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if m.screen != screenSettings {
		t.Errorf("screen = %v after Enter, want settings", m.screen)
	}
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 || sc.updates[0].Strategy != "random" {
		t.Fatalf("updates = %+v, want one random strategy write", sc.updates)
	}
}

// TestTimezonePickerStages checks that the zone list stages the value
// without a config write, that the details show a real local time, and
// that «Своё…» reuses the free-text input.
func TestTimezonePickerStages(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "settings"})
	m = step(m, configLoadedMsg{cfg: config.Default()})

	m = moveToSettingsField(t, m, timezoneFieldName)
	m = step(m, enterKey())
	if m.screen != screenTimezonePicker {
		t.Fatalf("screen = %v, want the timezone picker", m.screen)
	}
	view := m.View()
	for _, want := range []string{"Сейчас:", "UTC+", "системный"} {
		if !strings.Contains(view, want) {
			t.Errorf("timezone picker View() misses %q:\n%s", want, view)
		}
	}

	m = pickTimezone(t, m, "UTC")
	if got := m.settingsCfg.Timezone; got != "UTC" {
		t.Errorf("staged timezone = %q, want UTC", got)
	}
	if len(sc.updates) != 0 {
		t.Fatalf("timezone staging called UpdateConfig %d times, want 0", len(sc.updates))
	}

	// UTC is now current and its detail is a UTC+00:00 clock.
	m = moveToSettingsField(t, m, timezoneFieldName)
	m = step(m, enterKey())
	view = m.View()
	if !strings.Contains(view, "UTC+00:00") {
		t.Errorf("UTC detail misses the zero offset:\n%s", view)
	}

	m = pickTimezone(t, m, "Своё…")
	if !m.inputActive || m.inputMode != inputSettingsField {
		t.Fatalf("«Своё…» did not open the free-text input")
	}
	m = typeText(m, "Europe/Paris")
	updated, _ := m.Update(enterKey())
	m = updated.(Model)
	if got := m.settingsCfg.Timezone; got != "Europe/Paris" {
		t.Errorf("custom timezone = %q, want Europe/Paris", got)
	}
	if len(sc.updates) != 0 {
		t.Errorf("custom timezone staging called UpdateConfig %d times", len(sc.updates))
	}

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 || sc.updates[0].Timezone != "Europe/Paris" {
		t.Errorf("updates = %+v, want one Europe/Paris write after ctrl+s", sc.updates)
	}
}

// TestFilterCustomListFlow checks the two-step custom list input:
// validation errors keep the flow open, a valid https URL applies.
func TestFilterCustomListFlow(t *testing.T) {
	sc := &stubClient{cfg: config.Default()}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterConfigLoadedMsg{cfg: config.Default()})

	m = step(m, key('c'))
	if !m.inputActive || m.inputMode != inputFilterListID {
		t.Fatalf("c did not open the ID input")
	}
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if cmd != nil || m.filterErr == nil {
		t.Fatalf("an empty ID was accepted (cmd=%v, err=%v)", cmd, m.filterErr)
	}
	if len(sc.updates) != 0 {
		t.Fatalf("UpdateConfig called %d times for an empty ID", len(sc.updates))
	}

	m = typeText(m, "my-list")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if cmd != nil || m.inputMode != inputFilterListURL || m.filterNewID != "my-list" {
		t.Fatalf("the ID step did not advance (mode=%v id=%q err=%v)", m.inputMode, m.filterNewID, m.filterErr)
	}

	m = typeText(m, "http://example.com/list.txt")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if cmd != nil || m.filterErr == nil || !strings.Contains(m.filterErr.Error(), "https") {
		t.Fatalf("an http URL was accepted (cmd=%v, err=%v)", cmd, m.filterErr)
	}
	if len(sc.updates) != 0 {
		t.Fatalf("UpdateConfig called %d times for an http URL", len(sc.updates))
	}
	if !m.inputActive || m.inputMode != inputFilterListURL {
		t.Fatalf("the flow did not stay open after a bad URL")
	}

	m.input = ""
	m = typeText(m, "https://example.com/list.txt")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	got := sc.updates[0].Filter.Lists
	if len(got) != 1 || got[0].ID != "my-list" || got[0].URL != "https://example.com/list.txt" {
		t.Errorf("lists = %+v, want the custom {my-list, https URL}", got)
	}

	// A duplicate ID is rejected without another apply.
	m = step(m, key('c'))
	if m.inputMode != inputFilterListID {
		t.Fatalf("c did not reopen the ID input")
	}
	m = typeText(m, "my-list")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if cmd != nil || m.filterErr == nil || !strings.Contains(m.filterErr.Error(), "уже добавлен") {
		t.Fatalf("a duplicate ID was accepted (cmd=%v, err=%v)", cmd, m.filterErr)
	}
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1 after the duplicate", len(sc.updates))
	}
}

// TestFilterListManagement checks d, e and r on the filters screen.
func TestFilterListManagement(t *testing.T) {
	cfg := config.Default()
	cfg.Filter.Enabled = true
	cfg.Filter.Lists = []config.FilterList{{ID: "a"}, {ID: "b"}}
	sc := &stubClient{cfg: cfg}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterConfigLoadedMsg{cfg: cfg})
	m = step(m, filterLoadedMsg{lists: []filter.ListStatus{{ID: "a"}, {ID: "b"}}})

	updated, cmd := m.Update(key('d'))
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Filter.Lists; len(got) != 1 || got[0].ID != "b" {
		t.Errorf("lists after d = %+v, want just b", got)
	}

	updated, cmd = m.Update(key('e'))
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 2 {
		t.Fatalf("UpdateConfig calls = %d, want 2", len(sc.updates))
	}
	if sc.updates[1].Filter.Enabled {
		t.Errorf("e did not disable the filter")
	}

	m = step(m, key('r'))
	if !m.inputActive || m.inputMode != inputRule {
		t.Fatalf("r did not open the rule input")
	}
	m = typeText(m, "block ads.example.com")
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 3 {
		t.Fatalf("UpdateConfig calls = %d, want 3", len(sc.updates))
	}
	if got := sc.updates[2].Filter.UserBlock; len(got) != 1 || got[0] != "ads.example.com" {
		t.Errorf("user_block = %v, want [ads.example.com]", got)
	}
}

// TestFilterListsVisibleWhenDisabled checks that the screen always shows
// the configured lists, even with filtering off and no status entries,
// and that d acts on the visible row (or refuses when there is none).
func TestFilterListsVisibleWhenDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Filter.Enabled = false
	cfg.Filter.Lists = []config.FilterList{{ID: "only-list"}}
	sc := &stubClient{cfg: cfg}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, filterConfigLoadedMsg{cfg: cfg})

	view := m.View()
	for _, want := range []string{"only-list", "не загружен"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Списков нет") {
		t.Errorf("the empty hint is shown while a list is configured:\n%s", view)
	}

	// d on the visible row removes exactly that list.
	updated, cmd := m.Update(key('d'))
	m = updated.(Model)
	m = drainCmd(t, m, cmd)
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Filter.Lists; len(got) != 0 {
		t.Errorf("lists after d = %+v, want none", got)
	}

	// With no rows at all, d is refused and never touches the config.
	empty := config.Default()
	sc2 := &stubClient{cfg: empty}
	m2 := New(sc2, Options{Initial: "filters"})
	m2 = step(m2, filterConfigLoadedMsg{cfg: empty})
	updated, cmd = m2.Update(key('d'))
	m2 = updated.(Model)
	if cmd != nil {
		t.Errorf("d without rows returned a command")
	}
	if m2.filterErr == nil || !strings.Contains(m2.filterErr.Error(), "список не выбран") {
		t.Errorf("d without rows gave err=%v, want «список не выбран»", m2.filterErr)
	}
	if len(sc2.updates) != 0 {
		t.Errorf("d without rows called UpdateConfig %d times", len(sc2.updates))
	}
}

// TestHelpMentionsFilterKeys checks that ? documents the new filter
// keys.
func TestHelpMentionsFilterKeys(t *testing.T) {
	m := New(&stubClient{}, Options{})
	m = step(m, key('?'))
	view := m.View()
	for _, want := range []string{"каталог", "свой список", "удалить выбранный", "включить или выключить", "block домен"} {
		if !strings.Contains(view, want) {
			t.Errorf("help View() misses %q:\n%s", want, view)
		}
	}
}
