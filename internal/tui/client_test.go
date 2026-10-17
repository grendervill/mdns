package tui_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
	"mydns/internal/tui"
)

// stubController implements api.Controller with scripted answers.
type stubController struct {
	status  api.Status
	cfg     *config.Config
	updates []*config.Config
	filters []string
}

func (s *stubController) Status(context.Context) (api.Status, error) { return s.status, nil }
func (s *stubController) Config() *config.Config                     { return s.cfg }
func (s *stubController) UpdateConfig(_ context.Context, c *config.Config) error {
	s.updates = append(s.updates, c)
	return nil
}
func (s *stubController) Providers() []providers.Provider { return providers.List() }
func (s *stubController) Probe(context.Context, []providers.Endpoint) []probe.Result {
	return nil
}
func (s *stubController) Requests(int) []qlog.Entry         { return nil }
func (s *stubController) FilterStatus() []filter.ListStatus { return nil }
func (s *stubController) FilterUpdate(_ context.Context, id string) error {
	s.filters = append(s.filters, id)
	return nil
}

// startAPIServer serves the API on a temp unix socket and returns the
// socket path plus the event bus.
func startAPIServer(t *testing.T, ctl api.Controller) (string, *api.Bus) {
	t.Helper()

	// A short socket directory: macOS caps unix socket paths.
	dir, err := os.MkdirTemp("", "mdns-tui-")
	if err != nil {
		t.Fatalf("MkdirTemp() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "mdns.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen(unix) = %v, want nil", err)
	}

	bus := api.NewBus()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.New(ctl, bus, logger, api.ServerOptions{PingInterval: 50 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()

	return sock, bus
}

// TestUnixClientStatus checks the status round-trip over the socket.
func TestUnixClientStatus(t *testing.T) {
	ctl := &stubController{status: api.Status{Domain: "dns.example.com", Version: "test"}}
	sock, _ := startAPIServer(t, ctl)

	c := tui.NewUnixClient(sock)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() = %v, want nil", err)
	}
	if st.Domain != "dns.example.com" {
		t.Errorf("Domain = %q, want dns.example.com", st.Domain)
	}
}

// TestUnixClientUpdateConfig checks the config PUT.
func TestUnixClientUpdateConfig(t *testing.T) {
	cfg := config.Default()
	ctl := &stubController{cfg: cfg}
	sock, _ := startAPIServer(t, ctl)

	next := config.Default()
	next.Domain = "new.example.com"

	c := tui.NewUnixClient(sock)
	if err := c.UpdateConfig(context.Background(), next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}
	if len(ctl.updates) != 1 || ctl.updates[0].Domain != "new.example.com" {
		t.Errorf("controller saw %+v, want the new config", ctl.updates)
	}
}

// TestUnixClientEvents checks the SSE channel: published events arrive
// and cancelling the context closes the channel.
func TestUnixClientEvents(t *testing.T) {
	ctl := &stubController{}
	sock, bus := startAPIServer(t, ctl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := tui.NewUnixClient(sock)
	events, err := c.Events(ctx)
	if err != nil {
		t.Fatalf("Events() = %v, want nil", err)
	}

	bus.Publish(api.Event{Type: "requests", Data: qlog.Entry{QName: "example.com."}})

	select {
	case e, ok := <-events:
		if !ok {
			t.Fatalf("events channel closed early")
		}
		entry, isEntry := e.Data.(qlog.Entry)
		if e.Type != "requests" || !isEntry || entry.QName != "example.com." {
			t.Errorf("event = %+v, want a requests entry for example.com.", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("event did not arrive")
	}

	cancel()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return // channel closed as expected
			}
		case <-deadline:
			t.Fatalf("events channel did not close after cancellation")
		}
	}
}

// TestUnixClientErrors checks the error mentions the socket path.
func TestUnixClientErrors(t *testing.T) {
	c := tui.NewUnixClient("/nonexistent-dir/mdns.sock")
	_, err := c.Status(context.Background())
	if err == nil {
		t.Fatalf("Status() = nil, want a connection error")
	}
	if !strings.Contains(err.Error(), "mdns.sock") {
		t.Errorf("error = %q, want it to mention the socket path", err.Error())
	}
}
