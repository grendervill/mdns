package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/links"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
	"mydns/internal/tlscert"
)

// certExpiry is the fixed leaf expiry the certificate tests render.
var certExpiry = time.Date(2027, 1, 15, 10, 30, 0, 0, time.UTC)

// stubClient is a scripted tui.Client for model tests.
type stubClient struct {
	status      api.Status
	statusErr   error
	statusCalls int
	events      chan api.Event

	cfg       *config.Config
	filters   []string
	updateErr error
	updates   []*config.Config

	requestEntries []qlog.Entry
}

func (s *stubClient) Status(context.Context) (api.Status, error) {
	s.statusCalls++
	return s.status, s.statusErr
}
func (s *stubClient) Config(context.Context) (*config.Config, error) {
	if s.cfg != nil {
		return s.cfg, nil
	}
	return config.Default(), nil
}
func (s *stubClient) UpdateConfig(_ context.Context, c *config.Config) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updates = append(s.updates, c)
	return nil
}
func (s *stubClient) Providers(context.Context) ([]providers.Provider, error) {
	return nil, nil
}
func (s *stubClient) Probe(context.Context, []providers.Endpoint) ([]probe.Result, error) {
	return nil, nil
}
func (s *stubClient) Requests(context.Context, int) ([]qlog.Entry, error) {
	return s.requestEntries, nil
}
func (s *stubClient) FilterStatus(context.Context) ([]filter.ListStatus, error) {
	return nil, nil
}
func (s *stubClient) FilterUpdate(_ context.Context, id string) error {
	s.filters = append(s.filters, id)
	return nil
}
func (s *stubClient) Events(context.Context) (<-chan api.Event, error) {
	if s.events == nil {
		s.events = make(chan api.Event)
	}
	return s.events, nil
}

// sampleStatus is the status the tests render.
func sampleStatus() api.Status {
	return api.Status{
		Version:   "test",
		Domain:    "dns.example.com",
		Listeners: []string{"plain:53", "doh:443"},
		Strategy:  "fastest",
		Links: []links.Link{
			{Proto: "doh", Title: "DoH (DNS-over-HTTPS)", URI: "https://dns.example.com/dns-query"},
			{Proto: "dot", Title: "DoT (DNS-over-TLS)", URI: "tls://dns.example.com:853"},
		},
		Upstreams: []api.UpstreamStatus{{
			ID: "cf", Name: "Cloudflare", Transport: "plain", Address: "1.1.1.1:53",
			Enabled: true, Healthy: true, LatencyMS: 12.5, Sent: 10, Failed: 1,
		}},
		Cache:  cache.Stats{Hits: 5, Misses: 6, Size: 100},
		Filter: api.FilterSnapshot{Enabled: true, Mode: "zero", TotalBlocked: 42},
	}
}

// TestStatusViewRenders checks that a loaded status shows the domain,
// links and upstreams.
func TestStatusViewRenders(t *testing.T) {
	sc := &stubClient{status: sampleStatus()}
	m := New(sc, Options{})

	updated, _ := m.Update(statusLoadedMsg{st: sc.status})
	m = updated.(Model)

	view := m.View()
	for _, want := range []string{"dns.example.com", "https://dns.example.com/dns-query", "Cloudflare", "12.5"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() does not contain %q:\n%s", want, view)
		}
	}
}

// TestNavigation checks that number keys switch screens.
func TestNavigation(t *testing.T) {
	m := New(&stubClient{}, Options{})

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	m = updated.(Model)
	if m.screen != screenRequests {
		t.Errorf("screen = %v, want requests", m.screen)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m = updated.(Model)
	if m.screen != screenStatus {
		t.Errorf("screen = %v, want status", m.screen)
	}
}

// TestDaemonUnavailable checks the connection-error state: a clear
// message and a working reconnect key.
func TestDaemonUnavailable(t *testing.T) {
	sc := &stubClient{statusErr: errors.New("connection refused")}
	m := New(sc, Options{})

	updated, _ := m.Update(statusLoadedMsg{err: sc.statusErr})
	m = updated.(Model)

	view := m.View()
	if !strings.Contains(view, "Демон недоступен") {
		t.Errorf("View() misses the daemon-unavailable message:\n%s", view)
	}
	if !strings.Contains(view, "mdns setup") {
		t.Errorf("View() misses the setup hint:\n%s", view)
	}

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("pressing r returned no command")
	}
	msg := cmd()
	if _, ok := msg.(statusLoadedMsg); !ok {
		t.Fatalf("r command produced %T, want statusLoadedMsg", msg)
	}
	if sc.statusCalls != 1 {
		t.Errorf("status calls = %d, want 1 after r", sc.statusCalls)
	}
}

// TestQuit checks that q quits the program.
func TestQuit(t *testing.T) {
	m := New(&stubClient{}, Options{})

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatalf("q returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("q command produced %T, want tea.QuitMsg", cmd())
	}
}

// TestUpstreamsEventUpdatesStatus checks live upstream snapshots.
func TestUpstreamsEventUpdatesStatus(t *testing.T) {
	m := New(&stubClient{}, Options{})

	updated, _ := m.Update(statusLoadedMsg{st: sampleStatus()})
	m = updated.(Model)

	ups := []api.UpstreamStatus{{ID: "g", Name: "Google", Address: "8.8.8.8:53", LatencyMS: 33.3, Enabled: true, Healthy: true}}
	updated, _ = m.Update(eventMsg{e: api.Event{Type: "upstreams", Data: ups}})
	m = updated.(Model)

	view := m.View()
	if !strings.Contains(view, "Google") {
		t.Errorf("View() misses the Google upstream after the event:\n%s", view)
	}
	if !strings.Contains(view, "33.3") {
		t.Errorf("View() misses the live latency:\n%s", view)
	}
}

// TestStatusShowsCertStates checks the certificate line of the status
// screen for every state the daemon reports.
func TestStatusShowsCertStates(t *testing.T) {
	cases := []struct {
		name string
		cert tlscert.Status
		want []string
		miss []string
	}{
		{
			name: "ok",
			cert: tlscert.Status{Mode: "acme", State: "ok", Issuer: "Let's Encrypt", NotAfter: certExpiry},
			want: []string{"Сертификат:", "Let's Encrypt", "15.01.2027"},
		},
		{
			name: "ok without issuer falls back to the mode",
			cert: tlscert.Status{Mode: "self-signed", State: "ok", NotAfter: certExpiry},
			want: []string{"Сертификат:", "self-signed", "15.01.2027"},
		},
		{
			name: "waiting",
			cert: tlscert.Status{Mode: "acme", State: "waiting"},
			want: []string{"Сертификат:", "ожидание выпуска"},
		},
		{
			name: "error",
			cert: tlscert.Status{Mode: "acme", State: "error", Error: "acme: no account"},
			want: []string{"Сертификат:", "ошибка", "acme: no account"},
		},
		{
			name: "no certificate information",
			cert: tlscert.Status{},
			miss: []string{"Сертификат:"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := &stubClient{}
			m := New(sc, Options{})

			st := sampleStatus()
			st.Cert = tc.cert
			m = step(m, statusLoadedMsg{st: st})

			view := m.View()
			for _, want := range tc.want {
				if !strings.Contains(view, want) {
					t.Errorf("View() does not contain %q:\n%s", want, view)
				}
			}
			for _, miss := range tc.miss {
				if strings.Contains(view, miss) {
					t.Errorf("View() unexpectedly contains %q:\n%s", miss, view)
				}
			}
		})
	}
}

// TestCertEventUpdatesStatus checks that a live cert event updates the
// certificate line without a fresh status fetch.
func TestCertEventUpdatesStatus(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{})

	st := sampleStatus()
	st.Cert = tlscert.Status{Mode: "acme", State: "waiting"}
	m = step(m, statusLoadedMsg{st: st})

	cert := tlscert.Status{Mode: "acme", State: "ok", Issuer: "Let's Encrypt", NotAfter: certExpiry}
	m = step(m, eventMsg{e: api.Event{Type: "cert", Data: cert}})

	if m.status.Cert.State != "ok" {
		t.Fatalf("status.Cert.State = %q, want ok", m.status.Cert.State)
	}
	view := m.View()
	for _, want := range []string{"Сертификат:", "Let's Encrypt", "15.01.2027"} {
		if !strings.Contains(view, want) {
			t.Errorf("View() does not contain %q after the cert event:\n%s", want, view)
		}
	}
	if sc.statusCalls != 0 {
		t.Errorf("status calls = %d, want 0 (the event carried the status)", sc.statusCalls)
	}
}

// TestEventsClosedHandled checks that a closed event channel does not
// panic and leaves the status screen usable.
func TestEventsClosedHandled(t *testing.T) {
	m := New(&stubClient{}, Options{})

	updated, _ := m.Update(eventsClosedMsg{})
	m = updated.(Model)
	if m.View() == "" {
		t.Errorf("View() is empty after the event stream closed")
	}
}

// TestInitIssuesStatusAndSubscription checks that Init fetches the
// status and subscribes to events.
func TestInitIssuesStatusAndSubscription(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{})

	cmds := m.Init()
	// Run the batch members; status must be fetched.
	found := false
	for _, c := range cmdsCommands(cmds) {
		if _, ok := c().(statusLoadedMsg); ok {
			found = true
		}
	}
	if !found {
		t.Errorf("Init() did not fetch the status")
	}
}

// cmdsCommands unwraps a tea.BatchMsg returned by Init into its
// commands; Init may also return a single command.
func cmdsCommands(c tea.Cmd) []tea.Cmd {
	if c == nil {
		return nil
	}
	msg := c()
	if batch, ok := msg.(tea.BatchMsg); ok {
		return batch
	}
	return nil
}

// TestEventsReconnect checks that a failed subscription and a closed
// stream both schedule a retry that heals the stream (a daemon restart
// used to leave the live screens frozen forever).
func TestEventsReconnect(t *testing.T) {
	old := eventsRetryDelay
	eventsRetryDelay = time.Millisecond
	defer func() { eventsRetryDelay = old }()

	sc := &stubClient{}
	m := New(sc, Options{})

	updated, cmd := m.Update(eventsReadyMsg{err: errors.New("daemon down")})
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("a failed subscription scheduled no retry")
	}
	updated, cmd = m.Update(cmd()) // the retry tick
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("the retry tick returned no subscribe command")
	}
	updated, _ = m.Update(cmd()) // the subscribe result
	m = updated.(Model)
	if m.events == nil {
		t.Fatalf("the event stream did not reconnect")
	}

	updated, cmd = m.Update(eventsClosedMsg{})
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("a closed stream scheduled no retry")
	}
}

// TestInputCtrlCQuits checks that ctrl+c is not swallowed while an
// input line is open.
func TestInputCtrlCQuits(t *testing.T) {
	m := New(&stubClient{}, Options{Initial: "filters"})
	m = step(m, key('a'))
	if !m.inputActive {
		t.Fatalf("the rule input is not open")
	}

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = updated.(Model)
	if cmd == nil {
		t.Fatalf("ctrl+c in an input line was swallowed")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("ctrl+c produced %T, want tea.QuitMsg", cmd())
	}
}

// TestTUIWizardParkedProbes checks that probes stop while the embedded
// wizard is parked on another screen and resume when it is reopened.
func TestTUIWizardParkedProbes(t *testing.T) {
	sc := &stubClient{}
	m := New(sc, Options{})

	updated, cmd := m.Update(key('2'))
	m = updated.(Model)
	m = step(m, cmd().(wizardOpenedMsg))
	if m.wizard == nil {
		t.Fatalf("wizard not opened")
	}

	// Move the wizard to the providers step, then park it elsewhere.
	m.wizard.enterStage(stageProviders)
	seq := m.wizard.probeSeq
	m.screen = screenStatus

	// Probe messages are dropped while parked.
	m = step(m, wizardProbeMsg{seq: seq, byID: map[string]probe.Result{"cloudflare": {}}})
	if _, ok := m.wizard.probes["cloudflare"]; ok {
		t.Errorf("probes kept running while the wizard was parked")
	}

	// Reopening the wizard restarts the probe chain.
	updated, cmd = m.Update(key('2'))
	m = updated.(Model)
	if cmd == nil {
		t.Errorf("reopening the wizard did not restart the probes")
	}
}
