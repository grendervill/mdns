package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

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
	if cmd != nil {
		t.Fatalf("p with a loaded config returned a command")
	}
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
		m = step(m, key('p'))
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
		m = step(m, key('p'))
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
		m = step(m, key('p'))
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

	m = step(m, key('p'))
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
		m = step(m, key('p'))
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
		m = step(m, key('p'))
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

// TestMaintenanceFooterAndHelp checks the tab 8 keys are discoverable.
func TestMaintenanceFooterAndHelp(t *testing.T) {
	sc := &stubClient{cfg: maintenanceCfg()}
	m := maintenanceModel(sc, sc.cfg)
	m = step(m, tea.WindowSizeMsg{Width: 140, Height: 40})

	view := m.View()
	for _, want := range []string{"c — создать", "enter — восстановить", "d — удалить", "p — пароль панели"} {
		if !strings.Contains(view, want) {
			t.Errorf("maintenance footer misses %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "пауза ленты") {
		t.Errorf("the maintenance footer advertises the feed's pause key:\n%s", view)
	}

	m = step(m, key('?'))
	help := m.View()
	for _, want := range []string{"Обслуживание (экран 8)", "резервную копию", "сменить пароль"} {
		if !strings.Contains(help, want) {
			t.Errorf("help misses %q:\n%s", want, help)
		}
	}
}
