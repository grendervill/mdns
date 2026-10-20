package tui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
)

// settingField is one editable setting on the settings screen.
type settingField struct {
	name string
	get  func(*config.Config) string
	set  func(*config.Config, string) error // nil for toggles
	// toggle flips the value; nil for value-edited fields.
	toggle func(*config.Config)
}

// timezoneFieldName is the settings label of the timezone field; the
// view uses it to render the example zones.
const (
	timezoneFieldName = "Часовой пояс (IANA, пусто = системный)"
	dohPathFieldName  = "Путь DoH"
)

// timezoneChoice is one row of the timezone picker; an empty value means
// the server's own zone.
type timezoneChoice struct {
	label  string
	value  string
	custom bool
}

// timezoneChoices are the common zones plus the manual entry row.
var timezoneChoices = []timezoneChoice{
	{label: "системный", value: ""},
	{label: "UTC", value: "UTC"},
	{label: "Europe/Moscow", value: "Europe/Moscow"},
	{label: "Europe/London", value: "Europe/London"},
	{label: "Europe/Berlin", value: "Europe/Berlin"},
	{label: "Europe/Kyiv", value: "Europe/Kyiv"},
	{label: "Asia/Almaty", value: "Asia/Almaty"},
	{label: "Asia/Tbilisi", value: "Asia/Tbilisi"},
	{label: "Asia/Yerevan", value: "Asia/Yerevan"},
	{label: "Asia/Dubai", value: "Asia/Dubai"},
	{label: "America/New_York", value: "America/New_York"},
	{label: "Своё…", custom: true},
}

// settingsFields is the fixed field list of the settings screen.
func (m *Model) settingsFields() []settingField {
	return []settingField{
		stringField("Домен", func(c *config.Config) *string { return &c.Domain }),
		stringAllowEmptyField(timezoneFieldName, func(c *config.Config) *string { return &c.Timezone }),
		stringField("Стратегия", func(c *config.Config) *string { return &c.Strategy }),
		intField("Порт plain", func(c *config.Config) *int { return &c.Protocols.Plain.Port }),
		protocolToggle("Plain включён", func(c *config.Config) *config.Protocol { return &c.Protocols.Plain }),
		intField("Порт DoH", func(c *config.Config) *int { return &c.Protocols.DoH.Port }),
		stringAllowEmptyField(dohPathFieldName, func(c *config.Config) *string { return &c.Protocols.DoH.Path }),
		protocolToggle("DoH включён", func(c *config.Config) *config.Protocol { return &c.Protocols.DoH }),
		intField("Порт DoT", func(c *config.Config) *int { return &c.Protocols.DoT.Port }),
		protocolToggle("DoT включён", func(c *config.Config) *config.Protocol { return &c.Protocols.DoT }),
		intField("Порт DoQ", func(c *config.Config) *int { return &c.Protocols.DoQ.Port }),
		protocolToggle("DoQ включён", func(c *config.Config) *config.Protocol { return &c.Protocols.DoQ }),
		intField("Размер кеша", func(c *config.Config) *int { return &c.Cache.Size }),
		uint32Field("Кеш: min TTL",
			func(c *config.Config) uint32 { return c.Cache.MinTTL },
			func(c *config.Config, v uint32) { c.Cache.MinTTL = v }),
		uint32Field("Кеш: max TTL",
			func(c *config.Config) uint32 { return c.Cache.MaxTTL },
			func(c *config.Config, v uint32) { c.Cache.MaxTTL = v }),
		intField("Лимит запросов на IP (plain)", func(c *config.Config) *int { return &c.Limits.PlainRPSPerIP }),
		boolField("Фильтрация включена",
			func(c *config.Config) bool { return c.Filter.Enabled },
			func(c *config.Config, v bool) { c.Filter.Enabled = v }),
		stringField("Режим фильтра (zero/nxdomain/refused)", func(c *config.Config) *string { return &c.Filter.Mode }),
		intField("Интервал обновления списков, ч", func(c *config.Config) *int { return &c.Filter.UpdateIntervalHours }),
		filterListField("Списки фильтра (ID через запятую)", func(c *config.Config) *[]config.FilterList { return &c.Filter.Lists }),
		stringListField("Разрешённые домены (через запятую)", func(c *config.Config) *[]string { return &c.Filter.UserAllow }),
		stringListField("Заблокированные домены (через запятую)", func(c *config.Config) *[]string { return &c.Filter.UserBlock }),
	}
}

// stringField is a plain whitespace-free string setting.
func stringField(name string, target func(*config.Config) *string) settingField {
	return settingField{
		name: name,
		get:  func(c *config.Config) string { return *target(c) },
		set: func(c *config.Config, v string) error {
			v = strings.TrimSpace(v)
			if v == "" {
				return fmt.Errorf("%s: значение не может быть пустым", name)
			}
			if strings.ContainsAny(v, " \t\r\n") {
				return fmt.Errorf("%s: недопустимые символы", name)
			}
			*target(c) = v
			return nil
		},
	}
}

// stringAllowEmptyField is a plain whitespace-free string setting that
// accepts an empty value (the timezone means the system zone).
func stringAllowEmptyField(name string, target func(*config.Config) *string) settingField {
	return settingField{
		name: name,
		get:  func(c *config.Config) string { return *target(c) },
		set: func(c *config.Config, v string) error {
			v = strings.TrimSpace(v)
			if strings.ContainsAny(v, " \t\r\n") {
				return fmt.Errorf("%s: недопустимые символы", name)
			}
			*target(c) = v
			return nil
		},
	}
}

// intField is a numeric int setting.
func intField(name string, target func(*config.Config) *int) settingField {
	return settingField{
		name: name,
		get:  func(c *config.Config) string { return strconv.Itoa(*target(c)) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%s: ожидается число", name)
			}
			*target(c) = n
			return nil
		},
	}
}

// uint32Field is a numeric uint32 setting (TTL clamps).
func uint32Field(name string, get func(*config.Config) uint32, set func(*config.Config, uint32)) settingField {
	return settingField{
		name: name,
		get:  func(c *config.Config) string { return strconv.FormatUint(uint64(get(c)), 10) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			if err != nil {
				return fmt.Errorf("%s: ожидается целое число", name)
			}
			set(c, uint32(n))
			return nil
		},
	}
}

// protocolToggle flips one protocol's Enabled flag.
func protocolToggle(name string, target func(*config.Config) *config.Protocol) settingField {
	return boolField(name,
		func(c *config.Config) bool { return target(c).Enabled },
		func(c *config.Config, v bool) { target(c).Enabled = v },
	)
}

// boolField builds a toggle field.
func boolField(name string, get func(*config.Config) bool, set func(*config.Config, bool)) settingField {
	return settingField{
		name: name,
		get: func(c *config.Config) string {
			if get(c) {
				return "включён"
			}
			return "выключен"
		},
		toggle: func(c *config.Config) { set(c, !get(c)) },
	}
}

// filterListField edits the block-list IDs as a comma-separated list.
func filterListField(name string, target func(*config.Config) *[]config.FilterList) settingField {
	return settingField{
		name: name,
		get: func(c *config.Config) string {
			ids := make([]string, 0, len(*target(c)))
			for _, l := range *target(c) {
				ids = append(ids, l.ID)
			}
			return strings.Join(ids, ", ")
		},
		set: func(c *config.Config, v string) error {
			lists, err := parseFilterLists(v)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			*target(c) = lists
			return nil
		},
	}
}

// parseFilterLists parses "id1, id2" into FilterList values.
func parseFilterLists(v string) ([]config.FilterList, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	var out []config.FilterList
	for _, part := range strings.Split(v, ",") {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		if strings.ContainsAny(id, " \t/") {
			return nil, fmt.Errorf("недопустимый идентификатор %q", id)
		}
		out = append(out, config.FilterList{ID: id})
	}
	return out, nil
}

// stringListField edits a comma-separated domain list.
func stringListField(name string, target func(*config.Config) *[]string) settingField {
	return settingField{
		name: name,
		get:  func(c *config.Config) string { return strings.Join(*target(c), ", ") },
		set: func(c *config.Config, v string) error {
			v = strings.TrimSpace(v)
			if v == "" {
				*target(c) = nil
				return nil
			}
			var out []string
			for _, part := range strings.Split(v, ",") {
				d := strings.TrimSpace(part)
				if d == "" {
					continue
				}
				if strings.ContainsAny(d, " \t/") {
					return fmt.Errorf("%s: недопустимый домен %q", name, d)
				}
				out = append(out, d)
			}
			*target(c) = out
			return nil
		},
	}
}

// loadConfig fetches the current configuration.
func loadConfig(c Client) tea.Cmd {
	return func() tea.Msg {
		cfg, err := c.Config(context.Background())
		return configLoadedMsg{cfg: cfg, err: err}
	}
}

// applySettingsCmd sends the edited configuration.
func applySettingsCmd(c Client, cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		return configAppliedMsg{err: c.UpdateConfig(context.Background(), cfg)}
	}
}

// cloneConfig deep-copies the slices so the settings copy and the live
// config cannot share mutable state.
func cloneConfig(cfg *config.Config) *config.Config {
	out := *cfg
	out.Upstreams = slices.Clone(cfg.Upstreams)
	out.Limits.TrustedCIDRs = slices.Clone(cfg.Limits.TrustedCIDRs)
	out.Filter.Lists = slices.Clone(cfg.Filter.Lists)
	out.Filter.UserAllow = slices.Clone(cfg.Filter.UserAllow)
	out.Filter.UserBlock = slices.Clone(cfg.Filter.UserBlock)
	return &out
}

// commitSettingsField writes the typed value into the field.
func commitSettingsField(field settingField, cfg *config.Config, value string) error {
	if field.set == nil {
		return errors.New("поле не редактируется значением")
	}
	return field.set(cfg, value)
}

// settingsView renders the settings form.
func (m *Model) settingsView() string {
	if m.settingsCfg == nil {
		return dimStyle.Render("Настройки загружаются… (r — повторить)") + "\n"
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("Настройки"))
	b.WriteString(dimStyle.Render("  (enter — изменить/переключить, ctrl+s — применить, s — стратегия, w — мастер)") + "\n\n")

	fields := m.settingsFields()
	for i, f := range fields {
		marker := "  "
		if i == m.settingsCursor {
			marker = "> "
		}
		value := f.get(m.settingsCfg)
		if value == "" && f.name == timezoneFieldName {
			value = dimStyle.Render("(системный)")
		}
		line := fmt.Sprintf("%s%-42s %s", marker, f.name, value)
		if i == m.settingsCursor {
			line = activeTabStyle.Render(line)
		}
		b.WriteString(line + "\n")
		if f.name == timezoneFieldName {
			b.WriteString(dimStyle.Render("    напр. Europe/Moscow, Europe/London, UTC") + "\n")
		}
	}

	if m.inputActive && m.inputMode == inputSettingsField {
		b.WriteString("\n")
		b.WriteString(titleStyle.Render(fields[m.inputField].name+": ") + m.input + "▏")
		b.WriteString("\n")
	}

	if m.settingsErr != nil {
		b.WriteString("\n")
		b.WriteString(errStyle.Render("Ошибка: " + m.settingsErr.Error()))
		b.WriteString("\n")
	}
	return b.String()
}

// timezonePickerView renders the timezone picker.
func (m *Model) timezonePickerView() string {
	m.timezonePickerItems()
	return m.pickerView(&m.picker)
}

// randomDoHPath suggests a fresh DoH path client-side: the daemon does
// not expose a generator, so the value is only staged until ctrl+s.
func randomDoHPath() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "/dns-query"
	}
	return "/dns-query-" + hex.EncodeToString(b[:])
}

// timezonePickerChoices returns the preset zones plus, when the
// configured zone is not among them, a dynamic row carrying the custom
// value. «Своё…» stays the free-text entry, and «системный» is never
// marked for a custom zone.
func timezonePickerChoices(current string) []timezoneChoice {
	out := append([]timezoneChoice(nil), timezoneChoices...)
	if current == "" {
		return out
	}
	for _, c := range timezoneChoices {
		if !c.custom && c.value == current {
			return out
		}
	}
	custom := timezoneChoice{label: "Своё: " + current, value: current}
	out = append(out[:len(out)-1], custom, out[len(out)-1])
	return out
}

// timezoneChoicesFor is timezonePickerChoices for the staged config.
func (m *Model) timezoneChoicesFor() []timezoneChoice {
	current := ""
	if m.settingsCfg != nil {
		current = m.settingsCfg.Timezone
	}
	return timezonePickerChoices(current)
}

// openTimezonePicker opens the zone list on the configured value.
func (m Model) openTimezonePicker() (tea.Model, tea.Cmd) {
	if m.settingsCfg == nil {
		return m, m.lazyLoadCmd()
	}
	m.pickerReturn = screenSettings
	m.picker = picker{title: "Часовой пояс"}
	m.timezonePickerItems()
	for i, c := range m.timezoneChoicesFor() {
		if !c.custom && c.value == m.settingsCfg.Timezone {
			m.picker.cursor = i
		}
	}
	m.screen = screenTimezonePicker
	m.settleRail()
	return m, nil
}

// timezonePickerItems fills the zone rows and marks the staged value.
func (m *Model) timezonePickerItems() {
	current := ""
	if m.settingsCfg != nil {
		current = m.settingsCfg.Timezone
	}
	choices := m.timezoneChoicesFor()
	items := make([]pickerItem, 0, len(choices))
	for _, c := range choices {
		status := ""
		if !c.custom && c.value == current {
			status = "сейчас"
		}
		items = append(items, pickerItem{
			Label:   c.label,
			Status:  status,
			Details: timezoneDetails(c),
		})
	}
	m.picker.setItems(items)
}

// timezoneDetails shows the current local time and UTC offset of a zone.
func timezoneDetails(c timezoneChoice) []string {
	now := time.Now()
	if c.custom {
		local := now.In(time.Local)
		return []string{
			"Своя IANA-зона: введите её вручную.",
			"Например, Australia/Sydney или America/Sao_Paulo.",
			"",
			"Сейчас на сервере: " + local.Format("02.01.2006 15:04:05") +
				" (" + utcOffsetLabel(local) + ")",
			"Пустое значение — системная зона сервера.",
		}
	}

	loc := time.Local
	label := "системный"
	detail := []string{"Системная зона сервера (" + time.Local.String() + ")"}
	if c.value != "" {
		loaded, err := time.LoadLocation(c.value)
		if err != nil {
			return []string{
				"Не удалось загрузить зону " + c.value + ": " + err.Error(),
				"Пустое значение — системная зона сервера.",
			}
		}
		loc = loaded
		label = c.value
		detail = []string{"IANA: " + c.value}
	}
	local := now.In(loc)
	_, offset := local.Zone()
	detail = append(detail,
		"Сейчас: "+local.Format("02.01.2006 15:04:05")+" ("+utcOffsetLabel(local)+")",
		"Смещение от UTC: "+formatUTCOffset(offset),
	)
	if c.value == "" {
		detail = append(detail, "Пустое значение — сервер следует своей системной зоне.")
	} else {
		detail = append(detail,
			"Пустое значение — системная зона сервера;",
			"иначе в конфиг попадёт "+label+".")
	}
	return detail
}

// utcOffsetLabel renders a time's zone offset as UTC+HH:MM.
func utcOffsetLabel(t time.Time) string {
	_, offset := t.Zone()
	return formatUTCOffset(offset)
}

// formatUTCOffset formats a seconds offset from UTC.
func formatUTCOffset(offset int) string {
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, offset/3600, (offset%3600)/60)
}

// applyTimezonePick stages the highlighted zone in the settings copy and
// returns; ctrl+s on the settings screen applies it.
func (m Model) applyTimezonePick() (tea.Model, tea.Cmd) {
	choices := m.timezoneChoicesFor()
	if m.picker.cursor < 0 || m.picker.cursor >= len(choices) {
		return m, nil
	}
	choice := choices[m.picker.cursor]
	m.screen = screenSettings
	m.settleRail()

	if m.settingsCfg == nil {
		return m, m.lazyLoadCmd()
	}

	idx := -1
	for i, f := range m.settingsFields() {
		if f.name == timezoneFieldName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return m, nil
	}
	m.settingsCursor = idx

	if choice.custom {
		// Reuse the existing free-text input for an arbitrary IANA zone.
		m.inputActive = true
		m.inputMode = inputSettingsField
		m.inputField = idx
		m.input = ""
		return m, nil
	}

	if err := commitSettingsField(m.settingsFields()[idx], m.settingsCfg, choice.value); err != nil {
		m.settingsErr = err
	} else {
		m.settingsErr = nil
	}
	return m, nil
}
