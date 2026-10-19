package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

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
const timezoneFieldName = "Часовой пояс (IANA, пусто = системный)"

// settingsFields is the fixed field list of the settings screen.
func (m *Model) settingsFields() []settingField {
	return []settingField{
		stringField("Домен", func(c *config.Config) *string { return &c.Domain }),
		stringAllowEmptyField(timezoneFieldName, func(c *config.Config) *string { return &c.Timezone }),
		stringField("Стратегия", func(c *config.Config) *string { return &c.Strategy }),
		intField("Порт plain", func(c *config.Config) *int { return &c.Protocols.Plain.Port }),
		protocolToggle("Plain включён", func(c *config.Config) *config.Protocol { return &c.Protocols.Plain }),
		intField("Порт DoH", func(c *config.Config) *int { return &c.Protocols.DoH.Port }),
		stringField("Путь DoH", func(c *config.Config) *string { return &c.Protocols.DoH.Path }),
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
	b.WriteString(dimStyle.Render("  (enter — изменить/переключить, ctrl+s — применить, w — мастер)") + "\n\n")

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
