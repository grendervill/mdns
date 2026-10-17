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

// enterKey and escKey are the shared key messages.
func enterKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func escKey() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyEsc} }

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

// TestFilterModeToggle checks that m cycles the block mode and sends
// the full config.
func TestFilterModeToggle(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, statusLoadedMsg{st: sampleStatus()}) // mode zero

	updated, cmd := m.Update(key('m'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("m returned no command")
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

// TestUserRuleAdd checks the a-key rule input for both block and allow.
func TestUserRuleAdd(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{Initial: "filters"})
	m = step(m, statusLoadedMsg{st: sampleStatus()})

	m = step(m, key('a'))
	m = typeText(m, "block ads.example.com")
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("enter after the rule returned no command")
	}
	_ = cmd()

	m = step(m, key('a'))
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
