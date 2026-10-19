package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/auth"
	"mydns/internal/config"
)

// maintenanceCfg is a live config with the panel enabled, so the
// password flow is allowed.
func maintenanceCfg() *config.Config {
	cfg := config.Default()
	cfg.Timezone = "Europe/Moscow"
	cfg.Panel = config.PanelConfig{Enabled: true, PasswordHash: "$argon2id$old"}
	return cfg
}

// maintenanceModel builds the maintenance screen with its config
// already loaded.
func maintenanceModel(sc *stubClient, cfg *config.Config) Model {
	m := New(sc, Options{Initial: "maintenance"})
	return step(m, maintenanceConfigMsg{cfg: cfg})
}

// startPassword presses p and folds the live-config reload it schedules.
func startPassword(t *testing.T, m Model) Model {
	t.Helper()
	updated, cmd := m.Update(key('p'))
	m = updated.(Model)
	return drainCmd(t, m, cmd)
}

// drainMutation folds a mutation command and the reload command its
// result schedules (drainCmd itself does not follow the returned cmd).
func drainMutation(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	if cmd == nil {
		return m
	}
	updated, next := m.Update(cmd())
	m = updated.(Model)
	return drainCmd(t, m, next)
}

// sampleBackups returns an older snapshot first, so the screen has to
// sort it newest first.
func sampleBackups() (newest, older BackupInfo) {
	newest = BackupInfo{
		Name:    "config-20261019-120000-manual.json",
		Size:    2048,
		ModTime: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
	}
	older = BackupInfo{
		Name:    "config-20261018-090000-auto.json",
		Size:    128,
		ModTime: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC),
	}
	return newest, older
}

// TestMaintenanceListsBackups checks the table: newest first, the name,
// the configured timezone and a human size.
func TestMaintenanceListsBackups(t *testing.T) {
	newest, older := sampleBackups()
	sc := &stubClient{backups: []BackupInfo{older, newest}}
	m := maintenanceModel(sc, maintenanceCfg())
	m = step(m, backupsLoadedMsg{backups: sc.backups})

	view := m.View()
	for _, want := range []string{newest.Name, older.Name, "19.10 15:00", "18.10 12:00", "2 КиБ", "128 Б"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q:\n%s", want, view)
		}
	}
	if strings.Index(view, newest.Name) > strings.Index(view, older.Name) {
		t.Errorf("the backups are not newest first:\n%s", view)
	}
	if !strings.Contains(view, "заменяет конфигурацию") || !strings.Contains(view, "снапшот") {
		t.Errorf("View() misses the restore note:\n%s", view)
	}
}

// TestMaintenanceActions checks c/enter/d reach the client with the
// selected name and that every mutation reloads the list.
func TestMaintenanceActions(t *testing.T) {
	newest, older := sampleBackups()
	sc := &stubClient{backups: []BackupInfo{newest, older}}
	m := maintenanceModel(sc, maintenanceCfg())
	m = step(m, backupsLoadedMsg{backups: sc.backups})

	before := sc.backupCalls
	updated, cmd := m.Update(key('c'))
	m = updated.(Model)
	m = drainMutation(t, m, cmd)
	if len(sc.created) != 1 || sc.created[0] != "manual" {
		t.Errorf("created = %v, want [manual]", sc.created)
	}
	if sc.backupCalls != before+1 {
		t.Errorf("backup loads = %d after create, want %d", sc.backupCalls, before+1)
	}

	// Restore selects the highlighted row, so move to the older one.
	m = step(m, key('j'))
	before = sc.backupCalls
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	m = drainMutation(t, m, cmd)
	if len(sc.restored) != 1 || sc.restored[0] != older.Name {
		t.Errorf("restored = %v, want [%s]", sc.restored, older.Name)
	}
	if sc.backupCalls != before+1 {
		t.Errorf("backup loads = %d after restore, want %d", sc.backupCalls, before+1)
	}

	before = sc.backupCalls
	updated, cmd = m.Update(key('d'))
	m = updated.(Model)
	m = drainMutation(t, m, cmd)
	if len(sc.deleted) != 1 || sc.deleted[0] != older.Name {
		t.Errorf("deleted = %v, want [%s]", sc.deleted, older.Name)
	}
	if sc.backupCalls != before+1 {
		t.Errorf("backup loads = %d after delete, want %d", sc.backupCalls, before+1)
	}
}

// TestMaintenanceAPIErrorRendered checks a rejected mutation and a
// failed list load both surface their message in place.
func TestMaintenanceAPIErrorRendered(t *testing.T) {
	newest, older := sampleBackups()
	sc := &stubClient{
		backups:   []BackupInfo{newest, older},
		backupErr: errors.New(`configbackup: invalid backup name "../escape.json"`),
	}
	m := maintenanceModel(sc, maintenanceCfg())
	m = step(m, backupsLoadedMsg{backups: sc.backups})

	updated, cmd := m.Update(key('d'))
	m = updated.(Model)
	m = drainMutation(t, m, cmd)
	if view := m.View(); !strings.Contains(view, "invalid backup name") {
		t.Errorf("View() misses the API error:\n%s", view)
	}

	m = step(m, backupsLoadedMsg{err: errors.New("daemon down")})
	if view := m.View(); !strings.Contains(view, "daemon down") {
		t.Errorf("View() misses the list error:\n%s", view)
	}
}

// TestMaintenancePasswordChanged checks the successful flow: the hash
// is derived off the UI loop and applied through UpdateConfig.
func TestMaintenancePasswordChanged(t *testing.T) {
	cfg := maintenanceCfg()
	sc := &stubClient{cfg: cfg}
	m := maintenanceModel(sc, cfg)

	updated, cmd := m.Update(key('p'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("p returned no live-config reload")
	}
	m = drainCmd(t, m, cmd)
	if !m.inputActive || m.inputMode != inputMaintenancePassword {
		t.Fatalf("input = (%v, %v), want the password prompt", m.inputActive, m.inputMode)
	}

	const pw = "supersecret"
	m = typeText(m, pw)
	if view := m.View(); strings.Contains(view, pw) {
		t.Errorf("the password prompt echoes the password:\n%s", view)
	} else if !strings.Contains(view, strings.Repeat("•", len(pw))) {
		t.Errorf("the password prompt is not masked:\n%s", view)
	}

	updated, _ = m.Update(enterKey())
	m = updated.(Model)
	if m.inputMode != inputMaintenanceConfirm {
		t.Fatalf("input mode = %v, want the confirmation prompt", m.inputMode)
	}

	m = typeText(m, pw)
	if view := m.View(); strings.Contains(view, pw) {
		t.Errorf("the confirmation prompt echoes the password:\n%s", view)
	}

	// Confirm: hash, then apply.
	updated, cmd = m.Update(enterKey())
	m = updated.(Model)
	if m.inputActive || m.input != "" || m.passwordFirst != "" {
		t.Fatalf("the plaintext buffer survived the flow: active=%v input=%q first=%q",
			m.inputActive, m.input, m.passwordFirst)
	}
	if cmd == nil {
		t.Fatalf("the confirmation returned no hash command")
	}
	hashed := cmd()
	if msg, ok := hashed.(passwordHashedMsg); !ok || msg.err != nil || msg.hash == "" {
		t.Fatalf("hash msg = %#v, want a non-empty hash", hashed)
	}
	updated, cmd = m.Update(hashed)
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("the hash produced no apply command")
	}
	msg := cmd()
	changed, ok := msg.(passwordChangedMsg)
	if !ok || changed.err != nil {
		t.Fatalf("apply msg = %#v, want success", msg)
	}
	updated, _ = m.Update(msg)
	m = updated.(Model)

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	hash := sc.updates[0].Panel.PasswordHash
	if hash == "" {
		t.Fatalf("the applied config has an empty PasswordHash")
	}
	if !auth.Verify(hash, pw) {
		t.Errorf("the applied hash does not verify %q", pw)
	}
	if !strings.Contains(m.View(), "пароль изменён") {
		t.Errorf("View() misses the success note:\n%s", m.View())
	}
}

// TestMaintenancePasswordRejected checks short, whitespace and mismatched
// passwords never reach UpdateConfig.
func TestMaintenancePasswordRejected(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		sc := &stubClient{cfg: maintenanceCfg()}
		m := maintenanceModel(sc, sc.cfg)
		m = startPassword(t, m)
		m = typeText(m, "short")
		m = step(m, enterKey())

		if !m.inputActive || m.inputMode != inputMaintenancePassword {
			t.Fatalf("input = (%v, %v), want the password prompt still open", m.inputActive, m.inputMode)
		}
		if m.maintenanceErr == nil || !strings.Contains(m.maintenanceErr.Error(), "8") {
			t.Errorf("err = %v, want the minimum-length message", m.maintenanceErr)
		}
		if len(sc.updates) != 0 {
			t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
		}
	})

	t.Run("whitespace", func(t *testing.T) {
		sc := &stubClient{cfg: maintenanceCfg()}
		m := maintenanceModel(sc, sc.cfg)
		m = startPassword(t, m)
		m = typeText(m, " supersecret ")
		m = step(m, enterKey())

		if m.maintenanceErr == nil || !strings.Contains(m.maintenanceErr.Error(), "пробел") {
			t.Errorf("err = %v, want the whitespace message", m.maintenanceErr)
		}
		if len(sc.updates) != 0 {
			t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		sc := &stubClient{cfg: maintenanceCfg()}
		m := maintenanceModel(sc, sc.cfg)
		m = startPassword(t, m)
		m = typeText(m, "password-one")
		m = step(m, enterKey())
		m = typeText(m, "password-two")
		m = step(m, enterKey())

		if !m.inputActive || m.inputMode != inputMaintenancePassword {
			t.Fatalf("input = (%v, %v), want the pair restarted", m.inputActive, m.inputMode)
		}
		if m.input != "" {
			t.Errorf("input = %q, want it cleared after the mismatch", m.input)
		}
		if m.maintenanceErr == nil || !strings.Contains(m.maintenanceErr.Error(), "не совпадают") {
			t.Errorf("err = %v, want the mismatch message", m.maintenanceErr)
		}
		if len(sc.updates) != 0 {
			t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
		}
	})
}

// TestMaintenancePasswordDisabled refuses the change while the panel is
// off.
func TestMaintenancePasswordDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Panel = config.PanelConfig{Enabled: false}
	sc := &stubClient{cfg: cfg}
	m := maintenanceModel(sc, cfg)

	m = startPassword(t, m)
	if m.inputActive {
		t.Errorf("the password prompt opened for a disabled panel")
	}
	if m.maintenanceErr == nil || !strings.Contains(m.maintenanceErr.Error(), "выключена") {
		t.Errorf("err = %v, want the disabled-panel message", m.maintenanceErr)
	}
	if len(sc.updates) != 0 {
		t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
	}
}

// TestMaintenancePasswordEsc checks esc cancels at either step, leaves
// the config untouched and clears the buffers.
func TestMaintenancePasswordEsc(t *testing.T) {
	t.Run("first step", func(t *testing.T) {
		sc := &stubClient{cfg: maintenanceCfg()}
		m := maintenanceModel(sc, sc.cfg)
		m = startPassword(t, m)
		m = typeText(m, "supersecret")
		m = step(m, tea.KeyMsg{Type: tea.KeyEsc})

		if m.inputActive || m.input != "" || m.passwordFirst != "" {
			t.Errorf("esc left state behind: active=%v input=%q first=%q", m.inputActive, m.input, m.passwordFirst)
		}
		if len(sc.updates) != 0 {
			t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
		}
	})

	t.Run("confirmation step", func(t *testing.T) {
		sc := &stubClient{cfg: maintenanceCfg()}
		m := maintenanceModel(sc, sc.cfg)
		m = startPassword(t, m)
		m = typeText(m, "supersecret")
		m = step(m, enterKey())
		m = typeText(m, "supersecret")
		m = step(m, tea.KeyMsg{Type: tea.KeyEsc})

		if m.inputActive || m.input != "" || m.passwordFirst != "" {
			t.Errorf("esc left state behind: active=%v input=%q first=%q", m.inputActive, m.input, m.passwordFirst)
		}
		if len(sc.updates) != 0 {
			t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
		}
	})
}

// TestMaintenanceShowsVersionAndUptime checks the daemon identity line:
// the version comes from the loaded status and uptime from /stats since.
func TestMaintenanceShowsVersionAndUptime(t *testing.T) {
	sc := &stubClient{cfg: maintenanceCfg()}
	m := maintenanceModel(sc, sc.cfg)
	m = step(m, statusLoadedMsg{st: api.Status{Version: "0.7.0", Domain: "dns.example.com"}})
	m = step(m, statsLoadedMsg{stats: api.StatsResponse{Since: time.Now().Add(-2*time.Hour - 5*time.Minute)}})

	view := m.View()
	for _, want := range []string{"версия v0.7.0", "uptime 2 ч 5 мин"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() misses %q:\n%s", want, view)
		}
	}

	m = step(m, statsLoadedMsg{err: errors.New("stats: daemon down")})
	if view := m.View(); !strings.Contains(view, "uptime недоступен") {
		t.Errorf("View() misses the stats error note:\n%s", view)
	}
}

// TestMaintenanceReapply checks a re-reads the live config and PUTs that
// exact copy back, then reports success.
func TestMaintenanceReapply(t *testing.T) {
	cfg := maintenanceCfg()
	cfg.Domain = "fresh.example.test"
	sc := &stubClient{cfg: cfg}
	m := maintenanceModel(sc, cfg)

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("a returned no reapply command")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Domain; got != "fresh.example.test" {
		t.Errorf("applied domain = %q, want the fetched config", got)
	}
	if view := m.View(); !strings.Contains(view, "конфигурация применена заново") {
		t.Errorf("View() misses the reapply note:\n%s", view)
	}
}

// TestMaintenanceReapplyError checks a rejected reapply surfaces the API
// message and clears the success note.
func TestMaintenanceReapplyError(t *testing.T) {
	sc := &stubClient{cfg: maintenanceCfg(), updateErr: errors.New("validation: bad domain")}
	m := maintenanceModel(sc, sc.cfg)

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("a returned no reapply command")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	if m.maintenanceNote != "" {
		t.Errorf("note = %q, want it cleared on error", m.maintenanceNote)
	}
	if view := m.View(); !strings.Contains(view, "validation: bad domain") {
		t.Errorf("View() misses the reapply error:\n%s", view)
	}
}

// TestMaintenanceReapplyLoadError checks a failed config read never
// reaches UpdateConfig.
func TestMaintenanceReapplyLoadError(t *testing.T) {
	sc := &stubClient{configErr: errors.New("config: unreadable")}
	m := maintenanceModel(sc, maintenanceCfg())

	updated, cmd := m.Update(key('a'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("a returned no reapply command")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	if len(sc.updates) != 0 {
		t.Errorf("UpdateConfig calls = %d, want 0", len(sc.updates))
	}
	if view := m.View(); !strings.Contains(view, "config: unreadable") {
		t.Errorf("View() misses the config read error:\n%s", view)
	}
}

// TestMaintenanceFooterAndHelp checks the tab 8 keys are discoverable.
func TestMaintenanceFooterAndHelp(t *testing.T) {
	sc := &stubClient{cfg: maintenanceCfg()}
	m := maintenanceModel(sc, sc.cfg)
	m = step(m, tea.WindowSizeMsg{Width: 170, Height: 40})

	view := m.View()
	for _, want := range []string{"c — создать", "enter — восстановить", "d — удалить", "a — применить заново", "p — пароль панели"} {
		if !strings.Contains(view, want) {
			t.Errorf("maintenance footer misses %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "пауза ленты") {
		t.Errorf("the maintenance footer advertises the feed's pause key:\n%s", view)
	}

	// While the password prompt owns the keys, the footer advertises
	// only enter and esc: d would otherwise look like a live delete.
	m = startPassword(t, m)
	prompt := m.View()
	if !strings.Contains(prompt, "enter — подтвердить · esc — отмена") {
		t.Errorf("prompt footer misses the input keys:\n%s", prompt)
	}
	if strings.Contains(prompt, "d — удалить") {
		t.Errorf("prompt footer advertises a screen key:\n%s", prompt)
	}

	m = step(m, tea.KeyMsg{Type: tea.KeyEsc})
	m = step(m, key('?'))
	help := m.View()
	for _, want := range []string{"Обслуживание (экран 8)", "резервную копию", "сменить пароль", "применить текущую конфигурацию", "uptime"} {
		if !strings.Contains(help, want) {
			t.Errorf("help misses %q:\n%s", want, help)
		}
	}
}

// TestMaintenanceEmptyState checks an empty store renders its hint and
// the destructive keys do nothing without a selection.
func TestMaintenanceEmptyState(t *testing.T) {
	sc := &stubClient{}
	m := maintenanceModel(sc, maintenanceCfg())
	m = step(m, backupsLoadedMsg{backups: nil})

	if view := m.View(); !strings.Contains(view, "Резервных копий пока нет") {
		t.Errorf("View() misses the empty state:\n%s", view)
	}

	m = step(m, enterKey())
	if m.maintenanceErr == nil || !strings.Contains(m.maintenanceErr.Error(), "не выбрана") {
		t.Errorf("enter without a selection: err = %v, want the no-selection message", m.maintenanceErr)
	}
	m = step(m, key('d'))
	if m.maintenanceErr == nil || !strings.Contains(m.maintenanceErr.Error(), "не выбрана") {
		t.Errorf("d without a selection: err = %v, want the no-selection message", m.maintenanceErr)
	}
	if len(sc.restored) != 0 || len(sc.deleted) != 0 {
		t.Errorf("restored = %v, deleted = %v, want no calls", sc.restored, sc.deleted)
	}
}

// TestMaintenanceCursorAfterEmptyReload checks the cursor returns to row
// zero when the list empties, so the next create selects it.
func TestMaintenanceCursorAfterEmptyReload(t *testing.T) {
	newest, older := sampleBackups()
	sc := &stubClient{backups: []BackupInfo{newest, older}}
	m := maintenanceModel(sc, maintenanceCfg())
	m = step(m, backupsLoadedMsg{backups: sc.backups})
	m = step(m, key('j'))
	if m.backupCursor != 1 {
		t.Fatalf("cursor = %d, want 1", m.backupCursor)
	}

	// The last snapshot was removed elsewhere: the reload empties the
	// table.
	m = step(m, backupsLoadedMsg{backups: nil})
	if m.backupCursor != 0 {
		t.Errorf("cursor = %d after an empty reload, want 0", m.backupCursor)
	}
	if view := m.View(); !strings.Contains(view, "Резервных копий пока нет") {
		t.Errorf("View() misses the empty state:\n%s", view)
	}

	// A subsequent create lists one row and selects it.
	sc.backups = []BackupInfo{newest}
	updated, cmd := m.Update(key('c'))
	m = updated.(Model)
	m = drainMutation(t, m, cmd)
	if len(sc.created) != 1 {
		t.Fatalf("created = %v, want one call", sc.created)
	}
	if m.backupCursor != 0 {
		t.Errorf("cursor = %d after create, want 0", m.backupCursor)
	}
	if _, ok := m.selectedBackup(); !ok {
		t.Errorf("no row is selected after create")
	}
}

// TestMaintenancePasswordFetchesLiveConfig checks p re-reads the config
// instead of applying the cached copy, so a concurrent change survives.
func TestMaintenancePasswordFetchesLiveConfig(t *testing.T) {
	stale := maintenanceCfg()
	stale.Domain = "stale.example.test"
	fresh := maintenanceCfg()
	fresh.Domain = "fresh.example.test"

	sc := &stubClient{cfg: fresh}
	m := maintenanceModel(sc, stale)

	m = startPassword(t, m)
	if !m.inputActive || m.inputMode != inputMaintenancePassword {
		t.Fatalf("input = (%v, %v), want the password prompt", m.inputActive, m.inputMode)
	}
	if m.maintenanceCfg == nil || m.maintenanceCfg.Domain != fresh.Domain {
		t.Fatalf("maintenanceCfg = %+v, want the live config", m.maintenanceCfg)
	}

	m = typeText(m, "supersecret")
	m = step(m, enterKey())
	m = typeText(m, "supersecret")
	updated, cmd := m.Update(enterKey())
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("the confirmation returned no hash command")
	}
	hashMsg := cmd()
	if msg, ok := hashMsg.(passwordHashedMsg); !ok || msg.err != nil {
		t.Fatalf("hash msg = %#v, want success", hashMsg)
	}
	updated, cmd = m.Update(hashMsg)
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("the hash produced no apply command")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}
	if got := sc.updates[0].Domain; got != fresh.Domain {
		t.Errorf("applied domain = %q, want the live %q", got, fresh.Domain)
	}
	if !auth.Verify(sc.updates[0].Panel.PasswordHash, "supersecret") {
		t.Errorf("the applied hash does not verify the new password")
	}
}
