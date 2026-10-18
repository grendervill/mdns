package tui

import (
	"context"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// wizardOpenedMsg delivers a ready embedded wizard to the root model.
type wizardOpenedMsg struct {
	w   WizardModel
	err error
}

// apiBackend drives the wizard from a running TUI through the daemon
// control API.
type apiBackend struct{ c Client }

// Load implements WizardBackend.
func (b apiBackend) Load() (*config.Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return b.c.Config(ctx)
}

// Save implements WizardBackend.
func (b apiBackend) Save(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return b.c.UpdateConfig(ctx, cfg)
}

// Providers implements WizardBackend: the daemon catalog, with the
// built-in one as a fallback when the API is unreachable.
func (b apiBackend) Providers() []providers.Provider {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ps, err := b.c.Providers(ctx); err == nil && len(ps) > 0 {
		return ps
	}
	return providers.List()
}

// Probe implements WizardBackend. When the API cannot be reached every
// endpoint is reported as failed, so the wizard shows "недоступен"
// instead of bare dots forever.
func (b apiBackend) Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result {
	if len(eps) == 0 {
		return nil
	}
	res, err := b.c.Probe(ctx, eps)
	if err != nil {
		out := make([]probe.Result, len(eps))
		for i, ep := range eps {
			out[i] = probe.Result{Endpoint: ep, Err: err.Error()}
		}
		return out
	}
	return res
}

// openWizardCmd loads the config over the API and returns an embedded
// wizard.
func openWizardCmd(c Client) tea.Cmd {
	return func() tea.Msg {
		w, err := NewWizard(apiBackend{c})
		if err != nil {
			return wizardOpenedMsg{err: err}
		}
		w.embedded = true
		return wizardOpenedMsg{w: w}
	}
}

// wizardView renders the wizard tab: the wizard itself, a loading line
// or the tab's landing page.
func (m *Model) wizardView() string {
	if m.wizard != nil {
		return m.wizard.View()
	}

	var b strings.Builder
	if m.wizardLoading {
		b.WriteString(dimStyle.Render("Открываю мастер…"))
		b.WriteString("\n")
		return b.String()
	}
	if m.wizardNote != "" {
		b.WriteString(titleStyle.Render(m.wizardNote))
		b.WriteString("\n\n")
	}
	b.WriteString("Мастер настройки проведёт по шагам: домен, сертификат, протоколы,\n")
	b.WriteString("DNS-провайдеры (с замерами задержек), стратегия, фильтры, веб-панель.\n\n")
	b.WriteString(dimStyle.Render("Нажмите 2 или «w» на экране настроек, чтобы открыть мастер."))
	b.WriteString("\n")
	return b.String()
}
