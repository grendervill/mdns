package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// fakeWizardBackend scripts the wizard's environment.
type fakeWizardBackend struct {
	cfg     *config.Config
	saved   *config.Config
	saveErr error
	probes  int
}

func newFakeWizardBackend(t *testing.T) *fakeWizardBackend {
	t.Helper()
	return &fakeWizardBackend{cfg: config.Default()}
}

func (b *fakeWizardBackend) Load() (*config.Config, error) {
	return cloneConfig(b.cfg), nil
}
func (b *fakeWizardBackend) Save(cfg *config.Config) error {
	if b.saveErr != nil {
		return b.saveErr
	}
	b.saved = cloneConfig(cfg)
	return nil
}
func (b *fakeWizardBackend) Providers() []providers.Provider { return providers.List() }
func (b *fakeWizardBackend) Probe(context.Context, []providers.Endpoint) []probe.Result {
	b.probes++
	return nil
}

// wizardStep applies one message to the wizard.
func wizardStep(t *testing.T, w WizardModel, msg tea.Msg) WizardModel {
	t.Helper()
	u, _ := w.Update(msg)
	return u.(WizardModel)
}

// typeWizard feeds s as individual rune keys.
func typeWizard(t *testing.T, w WizardModel, s string) WizardModel {
	t.Helper()
	for _, r := range s {
		w = wizardStep(t, w, key(r))
	}
	return w
}

// TestWizardFlow walks the wizard through every step, including a
// back-and-forth that must not lose earlier answers, and checks the
// saved configuration.
func TestWizardFlow(t *testing.T) {
	b := newFakeWizardBackend(t)
	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}

	// Step 1: the domain input is open on entry.
	if !w.inputActive {
		t.Fatalf("the domain input is not open on entry")
	}
	w = typeWizard(t, w, "dns.example.com")
	w = wizardStep(t, w, enterKey())
	if w.stage != stageTLS {
		t.Fatalf("stage = %v, want TLS", w.stage)
	}

	// Step 2: self-signed certificate (first option).
	w = wizardStep(t, w, enterKey())
	if w.cfg.TLS.Mode != "self-signed" {
		t.Fatalf("tls mode = %q, want self-signed", w.cfg.TLS.Mode)
	}
	w = wizardStep(t, w, key('n'))
	if w.stage != stageProtocols {
		t.Fatalf("stage = %v, want protocols", w.stage)
	}

	// Exercise the default-port rule on the DoH row: empty input keeps
	// the default 443.
	w = wizardStep(t, w, key('j')) // cursor to DoH
	w = wizardStep(t, w, key('p'))
	w = typeWizard(t, w, "")
	w = wizardStep(t, w, enterKey())
	if got := w.cfg.Protocols.DoH.Port; got != 443 {
		t.Fatalf("DoH port after an empty edit = %d, want the default 443", got)
	}

	w = wizardStep(t, w, key('n'))
	if w.stage != stageProviders {
		t.Fatalf("stage = %v, want providers", w.stage)
	}

	// Select the first provider (Cloudflare) with its default transport.
	w = wizardStep(t, w, enterKey())
	if !w.selected["cloudflare"] {
		t.Fatalf("cloudflare was not selected")
	}

	// Review Focus #4: walk back to the very start and forward again;
	// the provider selection must survive.
	w = wizardStep(t, w, tea.KeyMsg{Type: tea.KeyEsc}) // protocols
	w = wizardStep(t, w, tea.KeyMsg{Type: tea.KeyEsc}) // tls
	w = wizardStep(t, w, tea.KeyMsg{Type: tea.KeyEsc}) // domain
	w = wizardStep(t, w, enterKey())                   // reopen the domain input (prefilled)
	w = wizardStep(t, w, enterKey())                   // commit unchanged
	w = wizardStep(t, w, key('n'))                     // tls -> protocols
	w = wizardStep(t, w, key('n'))                     // protocols -> providers
	if !w.selected["cloudflare"] {
		t.Fatalf("provider selection was lost on the back-and-forth")
	}

	w = wizardStep(t, w, key('n'))   // -> strategy
	w = wizardStep(t, w, enterKey()) // select the first strategy (fastest)
	w = wizardStep(t, w, key('n'))   // -> filters
	w = wizardStep(t, w, key('n'))   // -> summary
	if w.stage != stageSummary {
		t.Fatalf("stage = %v, want summary", w.stage)
	}

	// Save.
	w = wizardStep(t, w, enterKey())
	if !w.saved {
		t.Fatalf("wizard did not save: err=%v", w.err)
	}
	if b.saved == nil {
		t.Fatalf("backend.saved = nil")
	}

	if b.saved.Domain != "dns.example.com" {
		t.Errorf("saved domain = %q", b.saved.Domain)
	}
	if b.saved.Strategy != "fastest" {
		t.Errorf("saved strategy = %q, want fastest", b.saved.Strategy)
	}
	if len(b.saved.Upstreams) != 1 {
		t.Fatalf("saved upstreams = %d, want 1", len(b.saved.Upstreams))
	}
	u := b.saved.Upstreams[0]
	if u.ID != "cloudflare" || u.Transport != "doh" || u.Address != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("saved upstream = %+v, want cloudflare over doh", u)
	}
}

// TestWizardRequiresProvider checks that saving without providers is
// refused with a clear error.
func TestWizardRequiresProvider(t *testing.T) {
	b := newFakeWizardBackend(t)
	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}

	w = typeWizard(t, w, "dns.example.com")
	w = wizardStep(t, w, enterKey()) // -> tls
	w = wizardStep(t, w, enterKey()) // select self-signed
	w = wizardStep(t, w, key('n'))   // -> protocols
	w = wizardStep(t, w, key('n'))   // -> providers
	w = wizardStep(t, w, key('n'))   // -> strategy
	w = wizardStep(t, w, enterKey())
	w = wizardStep(t, w, key('n')) // -> filters
	w = wizardStep(t, w, key('n')) // -> summary

	w = wizardStep(t, w, enterKey())
	if w.saved {
		t.Fatalf("wizard saved without providers")
	}
	if w.err == nil || !strings.Contains(w.err.Error(), "провайдер") {
		t.Errorf("err = %v, want a provider-required error", w.err)
	}
	if b.saved != nil {
		t.Errorf("backend was asked to save %+v", b.saved)
	}
}

// TestWizardProbeUpdates checks that probe results land next to the
// provider.
func TestWizardProbeUpdates(t *testing.T) {
	b := newFakeWizardBackend(t)
	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}
	w.enterStage(stageProviders) // proper transition: resets the domain input

	w = wizardStep(t, w, wizardProbeMsg{byID: map[string]probe.Result{
		"cloudflare": {Latency: 12 * time.Millisecond},
	}})

	view := w.View()
	if !strings.Contains(view, "Cloudflare") {
		t.Fatalf("View() misses Cloudflare:\n%s", view)
	}
	if !strings.Contains(view, "12.0") {
		t.Errorf("View() misses the probed latency:\n%s", view)
	}
}

// TestSetupSummary checks the closing summary contains every link.
func TestSetupSummary(t *testing.T) {
	b := newFakeWizardBackend(t)
	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}

	w = typeWizard(t, w, "dns.example.com")
	w = wizardStep(t, w, enterKey())
	w = wizardStep(t, w, enterKey()) // self-signed
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, key('n'))   // providers
	w = wizardStep(t, w, enterKey()) // select cloudflare
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, enterKey()) // fastest
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, key('n'))   // summary
	w = wizardStep(t, w, enterKey()) // save

	if !w.saved {
		t.Fatalf("wizard did not save: err=%v", w.err)
	}

	sum := w.Summary()
	for _, want := range []string{
		"https://dns.example.com/dns-query",
		"tls://dns.example.com:853",
		"quic://dns.example.com:853",
		"dns.example.com:53",
		"Cloudflare",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("Summary() misses %q:\n%s", want, sum)
		}
	}
}

// TestWizardTransportCycle checks the t key over a provider's
// transports.
func TestWizardTransportCycle(t *testing.T) {
	b := newFakeWizardBackend(t)
	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}
	w.enterStage(stageProviders) // proper transition: resets the domain input

	w = wizardStep(t, w, enterKey()) // select cloudflare (doh by default)
	if got := w.transport["cloudflare"]; got != "doh" {
		t.Fatalf("default transport = %q, want doh", got)
	}
	w = wizardStep(t, w, key('t'))
	if got := w.transport["cloudflare"]; got == "doh" {
		t.Errorf("transport did not cycle: %q", got)
	}
}

// TestWizardPreselectsExistingUpstreams checks that re-running the
// wizard keeps providers configured by catalog ID.
func TestWizardPreselectsExistingUpstreams(t *testing.T) {
	b := newFakeWizardBackend(t)
	b.cfg.Upstreams = []config.UpstreamConfig{{
		ID: "cloudflare", Name: "Cloudflare", Transport: "doh",
		Address: "https://cloudflare-dns.com/dns-query", Enabled: true,
	}}

	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}
	if !w.selected["cloudflare"] {
		t.Errorf("cloudflare was not pre-selected from the current config")
	}
	if got := w.transport["cloudflare"]; got != "doh" {
		t.Errorf("pre-selected transport = %q, want doh", got)
	}
}

// TestWizardKeepsCustomUpstreams checks that hand-configured upstreams
// survive a wizard run.
func TestWizardKeepsCustomUpstreams(t *testing.T) {
	b := newFakeWizardBackend(t)
	b.cfg.Upstreams = []config.UpstreamConfig{{
		ID: "my-custom", Name: "My resolver", Transport: "plain",
		Address: "10.0.0.1:53", Enabled: true,
	}}

	w, err := NewWizard(b)
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}

	w.enterStage(stageProviders)
	w = wizardStep(t, w, enterKey()) // select the first catalog provider

	ups := w.buildUpstreams()
	if len(ups) != 2 {
		t.Fatalf("buildUpstreams() = %d entries, want 2 (selected + custom)", len(ups))
	}
	if ups[1].ID != "my-custom" {
		t.Errorf("custom upstream = %q, want my-custom kept", ups[1].ID)
	}
}
