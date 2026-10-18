package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/tlscert"
)

// Diagnostic marks: the same set `mdns diag` renders. ✓ is a passing
// check, ! a warning and ✗ a failure.
const (
	diagOK   = "✓"
	diagWarn = "!"
	diagFail = "✗"
)

// dateLayout is the Russian date format used by the interfaces.
const dateLayout = "02.01.2006"

// diagCheck is one rendered diagnostic line.
type diagCheck struct {
	mark   string
	name   string
	detail string
}

// diagLoadedMsg carries one full diagnostic pass over the control API:
// the same checks `mdns diag` performs, but collected through the
// client because the TUI is a thin client of the daemon.
type diagLoadedMsg struct {
	status    api.Status
	statusErr error

	cfg    *config.Config
	cfgErr error

	// upstreams are the enabled upstreams whose endpoints were probed,
	// in the same order as probes.
	upstreams []config.UpstreamConfig
	probes    []probe.Result
	probeErr  error

	lists    []filter.ListStatus
	listsErr error
}

// loadDiag runs the diagnostic pass: the status and config snapshots,
// the upstream pings and the filter list statuses.
func loadDiag(c Client) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		var msg diagLoadedMsg

		msg.status, msg.statusErr = c.Status(ctx)
		msg.cfg, msg.cfgErr = c.Config(ctx)

		if msg.cfg != nil {
			msg.upstreams = enabledUpstreams(msg.cfg)
			if eps := upstreamEndpoints(msg.upstreams); len(eps) > 0 {
				msg.probes, msg.probeErr = c.Probe(ctx, eps)
			}
		}

		msg.lists, msg.listsErr = c.FilterStatus(ctx)
		return msg
	}
}

// enabledUpstreams selects the upstreams the diagnostic pings.
func enabledUpstreams(cfg *config.Config) []config.UpstreamConfig {
	var out []config.UpstreamConfig
	for _, u := range cfg.Upstreams {
		if u.Enabled {
			out = append(out, u)
		}
	}
	return out
}

// upstreamEndpoints maps upstream configs onto probe endpoints, the
// same way `mdns diag` does.
func upstreamEndpoints(ups []config.UpstreamConfig) []providers.Endpoint {
	out := make([]providers.Endpoint, 0, len(ups))
	for _, u := range ups {
		out = append(out, providers.Endpoint{
			Transport:  u.Transport,
			Address:    u.Address,
			ServerName: u.ServerName,
		})
	}
	return out
}

// buildDiagChecks turns one diagnostic pass into the rendered lines.
func buildDiagChecks(msg diagLoadedMsg) []diagCheck {
	checks := []diagCheck{diagConfigCheck(msg)}
	checks = append(checks, diagListenerCheck(msg))
	checks = append(checks, diagCertCheck(msg.status.Cert, msg.statusErr))
	checks = append(checks, diagUpstreamChecks(msg)...)
	checks = append(checks, diagFilterChecks(msg)...)
	checks = append(checks, diagVersionCheck(msg.status, msg.statusErr))
	return checks
}

// diagConfigCheck validates the config the daemon returned, which is
// also the round-trip check of the API's /config endpoint.
func diagConfigCheck(msg diagLoadedMsg) diagCheck {
	switch {
	case msg.cfgErr != nil:
		return diagCheck{diagFail, "Конфигурация", msg.cfgErr.Error()}
	case msg.cfg == nil:
		return diagCheck{diagFail, "Конфигурация", "демон не вернул конфигурацию"}
	}
	if err := msg.cfg.Validate(); err != nil {
		return diagCheck{diagFail, "Конфигурация", "не проходит валидацию: " + err.Error()}
	}
	return diagCheck{diagOK, "Конфигурация", "валидна, домен " + msg.cfg.Domain}
}

// diagListenerCheck compares the listeners the daemon reports with the
// ones the config enables.
func diagListenerCheck(msg diagLoadedMsg) diagCheck {
	want := configListeners(msg.cfg)
	// All protocols disabled is a valid setup, and the CLI reports it
	// as a passing check rather than a missing listener.
	if want != nil && len(want) == 0 {
		return diagCheck{diagOK, "Порты", "все протоколы выключены"}
	}
	if msg.statusErr != nil {
		return diagCheck{diagWarn, "Порты", "демон недоступен: " + msg.statusErr.Error()}
	}
	got := msg.status.Listeners
	if len(got) == 0 {
		return diagCheck{diagWarn, "Порты", "демон не сообщил ни об одном листенере"}
	}
	if want != nil && !sameStrings(want, got) {
		return diagCheck{diagWarn, "Порты", fmt.Sprintf("листенеры расходятся с конфигом: слушает %s, в конфиге %s",
			strings.Join(got, ", "), strings.Join(want, ", "))}
	}
	return diagCheck{diagOK, "Порты", "слушает: " + strings.Join(got, ", ")}
}

// configListeners renders the listeners the config enables, in the
// "plain:53" form the daemon uses; nil when no config is available.
func configListeners(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, 4)
	for _, p := range []struct {
		name string
		on   bool
		port int
	}{
		{"plain", cfg.Protocols.Plain.Enabled, cfg.Protocols.Plain.Port},
		{"doh", cfg.Protocols.DoH.Enabled, cfg.Protocols.DoH.Port},
		{"dot", cfg.Protocols.DoT.Enabled, cfg.Protocols.DoT.Port},
		{"doq", cfg.Protocols.DoQ.Enabled, cfg.Protocols.DoQ.Port},
	} {
		if p.on {
			out = append(out, fmt.Sprintf("%s:%d", p.name, p.port))
		}
	}
	return out
}

// sameStrings compares two lists as sets.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// diagCertCheck renders the certificate state.
func diagCertCheck(c tlscert.Status, statusErr error) diagCheck {
	if statusErr != nil {
		return diagCheck{diagWarn, "Сертификат", "демон не запущен: " + statusErr.Error()}
	}

	switch c.State {
	case "ok":
		parts := []string{"ok"}
		if c.Issuer != "" {
			parts = append(parts, c.Issuer)
		} else if c.Mode != "" {
			parts = append(parts, c.Mode)
		}
		if !c.NotAfter.IsZero() {
			parts = append(parts, "до "+c.NotAfter.Format(dateLayout))
		}
		return diagCheck{diagOK, "Сертификат", strings.Join(parts, ", ")}
	case "waiting":
		return diagCheck{diagWarn, "Сертификат", "ожидание выпуска"}
	case "error":
		if detail := oneLine(c.Error, 40); detail != "" {
			return diagCheck{diagFail, "Сертификат", "ошибка — " + detail}
		}
		return diagCheck{diagFail, "Сертификат", "ошибка"}
	}
	return diagCheck{diagWarn, "Сертификат", "демон не сообщил состояние сертификата"}
}

// oneLine keeps the first line of s, trimmed and cut to n runes, so a
// multi-line ACME error cannot break the fixed-width check list.
func oneLine(s string, n int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return truncate(strings.TrimSpace(s), n)
}

// diagUpstreamChecks pings the enabled upstreams and reports every
// failure plus the best latency, like the CLI does.
func diagUpstreamChecks(msg diagLoadedMsg) []diagCheck {
	if msg.cfgErr != nil || msg.cfg == nil {
		return nil // the config check already reported the problem
	}
	if len(msg.upstreams) == 0 {
		return []diagCheck{{diagWarn, "Upstream'ы", "нет включённых upstream'ов"}}
	}
	if msg.probeErr != nil {
		return []diagCheck{{diagFail, "Upstream'ы", "проверка не удалась: " + msg.probeErr.Error()}}
	}

	var checks []diagCheck
	var best time.Duration
	bestName := ""

	for i, u := range msg.upstreams {
		name := u.Name
		if name == "" {
			name = u.Transport
		}
		if i >= len(msg.probes) {
			checks = append(checks, diagCheck{diagWarn, "Upstream «" + name + "»", u.Address + " — нет ответа проверки"})
			continue
		}
		r := msg.probes[i]
		if r.Err != "" {
			checks = append(checks, diagCheck{diagWarn, "Upstream «" + name + "»", u.Address + " — " + truncate(r.Err, 40)})
			continue
		}
		if bestName == "" || r.Latency < best {
			best, bestName = r.Latency, name
		}
	}
	if bestName != "" {
		checks = append(checks, diagCheck{diagOK, "Upstream'ы", fmt.Sprintf("лучший — %s, %s", bestName, probeLatency(best))})
	}
	return checks
}

// probeLatency renders a probe result's latency in milliseconds.
func probeLatency(d time.Duration) string {
	return formatLatency(float64(d.Microseconds()) / 1000)
}

// diagFilterChecks reports the block-list statuses the daemon serves.
func diagFilterChecks(msg diagLoadedMsg) []diagCheck {
	if msg.cfgErr != nil || msg.cfg == nil {
		return nil
	}
	if !msg.cfg.Filter.Enabled {
		return []diagCheck{{diagOK, "Списки фильтра", "фильтрация выключена"}}
	}
	if len(msg.cfg.Filter.Lists) == 0 {
		return []diagCheck{{diagOK, "Списки фильтра", "фильтрация включена без списков"}}
	}
	if msg.listsErr != nil {
		return []diagCheck{{diagFail, "Списки фильтра", msg.listsErr.Error()}}
	}

	byID := make(map[string]filter.ListStatus, len(msg.lists))
	for _, l := range msg.lists {
		byID[l.ID] = l
	}

	var checks []diagCheck
	var missing []string
	rules := 0
	for _, l := range msg.cfg.Filter.Lists {
		st, ok := byID[l.ID]
		if !ok {
			missing = append(missing, l.ID)
			continue
		}
		if st.Error != "" {
			checks = append(checks, diagCheck{diagWarn, "Список «" + l.ID + "»", st.Error})
			continue
		}
		rules += st.Applied
	}
	if len(missing) > 0 {
		checks = append(checks, diagCheck{diagWarn, "Списки фильтра", "нет статуса: " + strings.Join(missing, ", ")})
	}
	if len(missing) == 0 && len(checks) == 0 {
		checks = append(checks, diagCheck{diagOK, "Списки фильтра", fmt.Sprintf("правил %d, списков %d", rules, len(msg.cfg.Filter.Lists))})
	}
	return checks
}

// diagVersionCheck reports the daemon version (and domain) the status
// carries.
func diagVersionCheck(st api.Status, statusErr error) diagCheck {
	if statusErr != nil {
		return diagCheck{diagWarn, "Версия", "демон недоступен"}
	}
	if st.Version == "" {
		return diagCheck{diagWarn, "Версия", "демон не сообщил версию"}
	}
	return diagCheck{diagOK, "Версия", "mdns " + st.Version + " · домен " + st.Domain}
}

// diagView renders the diagnostic screen.
func (m *Model) diagView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Диагностика — self-check через API демона"))
	b.WriteString("\n\n")

	if !m.diagLoaded {
		b.WriteString(dimStyle.Render("Проверяю демон…"))
		b.WriteString("\n")
		return b.String()
	}

	for _, c := range m.diagChecks {
		b.WriteString(fmt.Sprintf("%s %s: %s\n", diagMark(c.mark), c.name, c.detail))
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("✓ — в порядке · ! — предупреждение · ✗ — ошибка"))
	b.WriteString("\n")
	return b.String()
}

// diagMark styles one check mark.
func diagMark(mark string) string {
	switch mark {
	case diagOK:
		return okStyle.Render(mark)
	case diagFail:
		return errStyle.Render(mark)
	default:
		return warnStyle.Render(mark)
	}
}
