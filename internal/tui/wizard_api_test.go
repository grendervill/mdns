package tui

import (
	"strings"
	"testing"

	"mydns/internal/config"
)

// TestAPIWizardLoad checks that the wizard starts from the daemon's
// current configuration.
func TestAPIWizardLoad(t *testing.T) {
	sc := &stubClient{}
	cfg := config.Default()
	cfg.Domain = "custom.example.com"
	cfg.Protocols.DoH.Port = 8443
	sc.cfg = cfg

	w, err := NewWizard(apiBackend{sc})
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}

	if w.cfg.Domain != "custom.example.com" {
		t.Errorf("wizard domain = %q, want the daemon's custom.example.com", w.cfg.Domain)
	}

	w.enterStage(stageProtocols)
	if view := w.View(); !strings.Contains(view, "8443") {
		t.Errorf("protocols step misses the daemon's DoH port 8443:\n%s", view)
	}
}

// TestAPIWizardSave walks the wizard over the API backend and checks
// the config sent to UpdateConfig.
func TestAPIWizardSave(t *testing.T) {
	sc := &stubClient{}
	w, err := NewWizard(apiBackend{sc})
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}

	w = typeWizard(t, w, "api.example.com")
	w = wizardStep(t, w, enterKey()) // -> tls
	w = tlsCursor(t, w, tlsOptionSelfSigned)
	w = wizardStep(t, w, enterKey()) // self-signed
	w = wizardStep(t, w, key('n'))   // -> protocols
	w = wizardStep(t, w, key('n'))   // -> providers
	w = wizardStep(t, w, enterKey()) // select cloudflare
	w = wizardStep(t, w, key('n'))   // -> strategy
	w = wizardStep(t, w, enterKey()) // fastest
	w = wizardStep(t, w, key('n'))   // -> filters
	w = wizardStep(t, w, key('n'))   // -> panel (opens the question)
	w = answerPanelDisabled(t, w)    // answer «н» and move on to the summary
	w = wizardStep(t, w, enterKey()) // save

	if !w.saved {
		t.Fatalf("wizard did not save: err=%v", w.err)
	}
	if len(sc.updates) != 1 {
		t.Fatalf("UpdateConfig calls = %d, want 1", len(sc.updates))
	}

	sent := sc.updates[0]
	if sent.Domain != "api.example.com" {
		t.Errorf("sent domain = %q", sent.Domain)
	}
	if len(sent.Upstreams) != 1 || sent.Upstreams[0].ID != "cloudflare" {
		t.Errorf("sent upstreams = %+v, want cloudflare", sent.Upstreams)
	}
	if sent.TLS.Mode != "self-signed" {
		t.Errorf("sent tls mode = %q", sent.TLS.Mode)
	}
}

// TestAPIWizardSaveEmbedded checks the embedded wizard reports its end
// through wizardDoneMsg instead of quitting the program.
func TestAPIWizardSaveEmbedded(t *testing.T) {
	sc := &stubClient{}
	w, err := NewWizard(apiBackend{sc})
	if err != nil {
		t.Fatalf("NewWizard() = %v, want nil", err)
	}
	w.embedded = true

	w = typeWizard(t, w, "api.example.com")
	w = wizardStep(t, w, enterKey())
	w = tlsCursor(t, w, tlsOptionSelfSigned)
	w = wizardStep(t, w, enterKey())
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, enterKey())
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, enterKey())
	w = wizardStep(t, w, key('n'))
	w = wizardStep(t, w, key('n'))
	w = answerPanelDisabled(t, w)

	u, cmd := w.Update(enterKey())
	w = u.(WizardModel)
	if !w.saved {
		t.Fatalf("wizard did not save: err=%v", w.err)
	}
	if cmd == nil {
		t.Fatalf("embedded save returned no command")
	}
	msg, ok := cmd().(wizardDoneMsg)
	if !ok || !msg.saved {
		t.Errorf("embedded save produced %#v, want wizardDoneMsg{saved: true}", cmd())
	}
}

// TestTUIWizardEntry checks opening the wizard from the tab, delegating
// keys to it and returning to the TUI after cancel.
func TestTUIWizardEntry(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{})

	// Tab 2 opens the wizard through the API backend.
	updated, cmd := m.Update(key('2'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("pressing 2 returned no command")
	}
	opened, ok := cmd().(wizardOpenedMsg)
	if !ok {
		t.Fatalf("opening produced %T, want wizardOpenedMsg", cmd())
	}
	if opened.err != nil {
		t.Fatalf("wizardOpenedMsg.err = %v", opened.err)
	}
	m = step(m, opened)
	if m.wizard == nil {
		t.Fatalf("wizard not embedded after wizardOpenedMsg")
	}
	if !m.wizard.embedded {
		t.Errorf("embedded = false, want true for a TUI wizard")
	}

	// Keys reach the wizard (the domain input is open on entry).
	m = step(m, key('x'))
	if got := m.wizard.input; got != "x" {
		t.Errorf("wizard input = %q, want the typed x", got)
	}
	if view := m.View(); !strings.Contains(view, "шаг 1/8") {
		t.Errorf("View() does not render the wizard:\n%s", view)
	}

	// Cancelling returns to the TUI.
	m = step(m, wizardDoneMsg{})
	if m.wizard != nil {
		t.Fatalf("wizard still attached after wizardDoneMsg")
	}
	if view := m.View(); !strings.Contains(view, "без сохранения") {
		t.Errorf("View() misses the cancel note:\n%s", view)
	}
}
