package tui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/auth"
	"mydns/internal/config"
)

// errPanelDisabled refuses a password change while the web panel is
// off: there is no login to protect, and enabling the panel is a
// separate decision. The panel fields live in the wizard, which the
// settings screen opens with w.
var errPanelDisabled = errors.New("веб-панель выключена — сначала включите её в мастере (экран 6 → w)")

// loadBackups fetches the stored config snapshots.
func loadBackups(c Client) tea.Cmd {
	return func() tea.Msg {
		backups, err := c.Backups(context.Background())
		return backupsLoadedMsg{backups: backups, err: err}
	}
}

// loadMaintenanceConfig fetches the live config for the display timezone
// and the panel password change.
func loadMaintenanceConfig(c Client) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		return maintenanceConfigMsg{cfg: cfg, err: err}
	}
}

// loadStats fetches the cumulative counters and the daemon start time,
// which the maintenance header renders as uptime.
func loadStats(c Client) tea.Cmd {
	return func() tea.Msg {
		st, err := c.Stats(context.Background())
		return statsLoadedMsg{stats: st, err: err}
	}
}

// reapplyConfigCmd re-reads the live config and PUTs it back unchanged:
// the TUI twin of the web panel's maintenance action.
func reapplyConfigCmd(c Client) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		if err != nil {
			return configReappliedMsg{err: err}
		}
		return configReappliedMsg{err: c.UpdateConfig(context.Background(), cfg)}
	}
}

// createBackupCmd stores a snapshot with the given label.
func createBackupCmd(c Client, label string) tea.Cmd {
	return func() tea.Msg {
		return backupDoneMsg{action: "create", err: c.CreateBackup(context.Background(), label)}
	}
}

// restoreBackupCmd applies one stored snapshot.
func restoreBackupCmd(c Client, name string) tea.Cmd {
	return func() tea.Msg {
		return backupDoneMsg{action: "restore", name: name, err: c.RestoreBackup(context.Background(), name)}
	}
}

// deleteBackupCmd removes one stored snapshot.
func deleteBackupCmd(c Client, name string) tea.Cmd {
	return func() tea.Msg {
		return backupDoneMsg{action: "delete", name: name, err: c.DeleteBackup(context.Background(), name)}
	}
}

// hashPasswordCmd derives the argon2id hash off the UI goroutine: the
// call deliberately costs tens of milliseconds and 64 MiB.
func hashPasswordCmd(pw string) tea.Cmd {
	return func() tea.Msg {
		hash, err := auth.HashPassword(pw)
		return passwordHashedMsg{hash: hash, err: err}
	}
}

// applyPasswordCmd writes the config carrying the new hash.
func applyPasswordCmd(c Client, cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		return passwordChangedMsg{cfg: cfg, err: c.UpdateConfig(context.Background(), cfg)}
	}
}

// sortBackups renders the newest snapshot first even if the daemon ever
// returns them in another order.
func sortBackups(in []BackupInfo) []BackupInfo {
	out := append([]BackupInfo(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ModTime.After(out[j].ModTime)
	})
	return out
}

// selectedBackup returns the highlighted snapshot.
func (m *Model) selectedBackup() (BackupInfo, bool) {
	if m.backupCursor < 0 || m.backupCursor >= len(m.backups) {
		return BackupInfo{}, false
	}
	return m.backups[m.backupCursor], true
}

// restoreSelectedBackup applies the highlighted snapshot.
func (m Model) restoreSelectedBackup() (tea.Model, tea.Cmd) {
	backup, ok := m.selectedBackup()
	if !ok {
		m.maintenanceErr = errors.New("резервная копия не выбрана")
		return m, nil
	}
	m.maintenanceErr = nil
	m.maintenanceNote = ""
	return m, restoreBackupCmd(m.client, backup.Name)
}

// deleteSelectedBackup removes the highlighted snapshot.
func (m Model) deleteSelectedBackup() (tea.Model, tea.Cmd) {
	backup, ok := m.selectedBackup()
	if !ok {
		m.maintenanceErr = errors.New("резервная копия не выбрана")
		return m, nil
	}
	m.maintenanceErr = nil
	m.maintenanceNote = ""
	return m, deleteBackupCmd(m.client, backup.Name)
}

// startPasswordChange opens the panel password flow. The live config is
// always re-read first: the password change rewrites the whole config,
// so applying a cached copy would revert a concurrent panel change.
func (m Model) startPasswordChange() (tea.Model, tea.Cmd) {
	m.maintenanceErr = nil
	m.maintenanceNote = ""
	m.passwordPending = true
	return m, loadMaintenanceConfig(m.client)
}

// openPasswordPrompt asks for the new password.
func (m Model) openPasswordPrompt() Model {
	m.inputActive = true
	m.inputMode = inputMaintenancePassword
	m.input = ""
	m.passwordFirst = ""
	m.passwordPending = false
	return m
}

// commitMaintenancePassword validates the first entry and asks for the
// repeat, keeping the typed text and the error on a rejection.
func (m Model) commitMaintenancePassword() (tea.Model, tea.Cmd) {
	if err := validPanelPassword(m.input); err != nil {
		m.maintenanceErr = err
		return m, nil
	}
	m.passwordFirst = m.input
	m.input = ""
	m.inputMode = inputMaintenanceConfirm
	m.maintenanceErr = nil
	return m, nil
}

// commitMaintenanceConfirm checks the repeat, then hashes off the UI
// goroutine and drops every plaintext buffer before returning.
func (m Model) commitMaintenanceConfirm() (tea.Model, tea.Cmd) {
	pw := m.input
	if pw != m.passwordFirst {
		m.passwordFirst = ""
		m.input = ""
		m.inputMode = inputMaintenancePassword
		m.maintenanceErr = errors.New("пароли не совпадают; введите пароль заново")
		return m, nil
	}

	m.passwordFirst = ""
	m.input = ""
	m.inputActive = false
	m.inputMode = inputNone
	m.maintenanceErr = nil
	return m, hashPasswordCmd(pw)
}

// backupTime renders a snapshot's modification time in the configured
// IANA zone (the system zone when none is set).
func backupTime(t time.Time, cfg *config.Config) string {
	loc := time.Local
	if cfg != nil && cfg.Timezone != "" {
		if loaded, err := time.LoadLocation(cfg.Timezone); err == nil {
			loc = loaded
		}
	}
	return t.In(loc).Format("02.01 15:04")
}

// humanSize renders a byte count in a compact binary unit.
func humanSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d Б", n)
	}
	units := []string{"КиБ", "МиБ", "ГиБ", "ТиБ"}
	v := float64(n)
	for _, unit := range units {
		v /= 1024
		if v < 1024 {
			return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + " " + unit
		}
	}
	return fmt.Sprintf("%.1f ПиБ", v/1024)
}

// humanUptime renders a daemon uptime in Russian units, rounded to the
// minute; the maintenance screen shows it next to the version.
func humanUptime(d time.Duration) string {
	if d < time.Minute {
		return "меньше минуты"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d д %d ч", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d ч %d мин", hours, mins)
	default:
		return fmt.Sprintf("%d мин", mins)
	}
}

// maintenanceMeta is the daemon identity line: version from the loaded
// status and uptime from the stats start time.
func (m Model) maintenanceMeta() string {
	version := "неизвестна"
	if m.status.Version != "" {
		version = "v" + m.status.Version
	}
	meta := "версия " + version
	switch {
	case m.statsErr != nil:
		meta += " · uptime недоступен"
	case m.uptimeKnown:
		meta += " · uptime " + humanUptime(m.uptime)
	case !m.statsLoaded:
		meta += " · uptime …"
	}
	return dimStyle.Render(meta)
}

// maintenanceView renders the backups table, the password prompt and
// the feedback lines.
func (m *Model) maintenanceView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Обслуживание — резервные копии и пароль панели"))
	b.WriteString("\n")
	b.WriteString(m.maintenanceMeta())
	b.WriteString("\n\n")

	switch {
	case !m.backupsLoaded && m.backupsErr == nil:
		b.WriteString(dimStyle.Render("Загружаю резервные копии…") + "\n")
	case m.backupsErr != nil && len(m.backups) == 0:
		b.WriteString(errStyle.Render("Не удалось загрузить копии: "+m.backupsErr.Error()) + "\n")
	case len(m.backups) == 0:
		b.WriteString(dimStyle.Render("Резервных копий пока нет — c создаст первую.") + "\n")
	default:
		b.WriteString(dimStyle.Render(fmt.Sprintf("  %-40s %-12s %10s", "имя", "изменена", "размер")) + "\n")
		for i, backup := range m.backups {
			marker := "  "
			if i == m.backupCursor {
				marker = "> "
			}
			line := fmt.Sprintf("%s%-40s %-12s %10s",
				marker, truncate(backup.Name, 40), backupTime(backup.ModTime, m.maintenanceCfg), humanSize(backup.Size))
			if i == m.backupCursor {
				line = activeTabStyle.Render(line)
			}
			b.WriteString(line + "\n")
		}
		if m.backupsErr != nil {
			b.WriteString("\n" + errStyle.Render("Не удалось обновить список: "+m.backupsErr.Error()) + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Восстановление заменяет конфигурацию целиком, включая пароль панели и состояние DoH;"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("перед восстановлением автоматически создаётся снапшот текущей конфигурации."))
	b.WriteString("\n")

	if m.inputActive && (m.inputMode == inputMaintenancePassword || m.inputMode == inputMaintenanceConfirm) {
		prompt := "Новый пароль:"
		if m.inputMode == inputMaintenanceConfirm {
			prompt = "Повторите пароль:"
		}
		b.WriteString("\n")
		b.WriteString(titleStyle.Render(prompt) + " " + maskInput("", m.input, true) + "▏")
		b.WriteString("\n")
	}

	if m.maintenanceNote != "" {
		b.WriteString("\n" + okStyle.Render(m.maintenanceNote) + "\n")
	}
	if m.maintenanceErr != nil {
		b.WriteString("\n" + errStyle.Render("Ошибка: "+m.maintenanceErr.Error()) + "\n")
	}
	return b.String()
}
