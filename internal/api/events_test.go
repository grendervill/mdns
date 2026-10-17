package api_test

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mydns/internal/api"
)

// newTestHTTPServer wraps an API server into an httptest server.
func newTestHTTPServer(t *testing.T, srv *api.Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// newUnixListener returns a listener on a temp unix socket.
func newUnixListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "api.sock"))
	if err != nil {
		t.Fatalf("net.Listen(unix) = %v, want nil", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// waitSSELine scans lines until one contains want or the deadline
// passes.
func waitSSELine(t *testing.T, lines <-chan string, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return false
			}
			if strings.Contains(line, want) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// TestSSEStream checks the event stream end to end: published events
// arrive, and a disconnecting client releases its subscription.
func TestSSEStream(t *testing.T) {
	bus := api.NewBus()
	ctl := &fakeController{}
	srv := api.New(ctl, bus, discardLogger(), api.ServerOptions{})
	ts := newTestHTTPServer(t, srv)

	resp, err := http.Get(ts.URL + "/api/v1/events")
	if err != nil {
		t.Fatalf("GET events = %v, want nil", err)
	}
	scanner := bufio.NewScanner(resp.Body)
	lines := make(chan string, 100)
	go func() {
		defer close(lines)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	if !waitSSELine(t, lines, "event: ping", 3*time.Second) {
		t.Fatalf("no initial ping on the stream")
	}

	bus.Publish(api.Event{Type: "requests", Data: map[string]string{"qname": "example.com."}})
	if !waitSSELine(t, lines, "example.com.", 3*time.Second) {
		t.Fatalf("published event did not reach the stream")
	}

	// Disconnect: the server must release the subscriber.
	resp.Body.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if bus.Subscribers() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("subscribers = %d after disconnect, want 0", bus.Subscribers())
}

// TestSSEKeepAlive checks the periodic ping with a shortened interval.
func TestSSEKeepAlive(t *testing.T) {
	srv := api.New(&fakeController{}, api.NewBus(), discardLogger(), api.ServerOptions{PingInterval: 20 * time.Millisecond})
	ts := newTestHTTPServer(t, srv)

	resp, err := http.Get(ts.URL + "/api/v1/events")
	if err != nil {
		t.Fatalf("GET events = %v, want nil", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	lines := make(chan string, 100)
	go func() {
		defer close(lines)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	first := waitSSELine(t, lines, "event: ping", time.Second)
	second := waitSSELine(t, lines, "event: ping", time.Second)
	if !first || !second {
		t.Errorf("pings received: first=%v second=%v, want both", first, second)
	}
}

// TestSSEPublishDropWhenFull checks that a stalled subscriber does not
// block Publish.
func TestSSEPublishDropWhenFull(t *testing.T) {
	bus := api.NewBus()
	_, cancel := bus.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10000; i++ {
			bus.Publish(api.Event{Type: "requests", Data: i})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Publish blocked on a full subscriber")
	}
}

// TestServerServeStopsWithContext checks Serve returns after ctx
// cancellation.
func TestServerServeStopsWithContext(t *testing.T) {
	srv := api.New(&fakeController{}, api.NewBus(), discardLogger(), api.ServerOptions{})
	ln := newUnixListener(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, ln) }()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve() = %v, want nil after cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Serve did not return after cancellation")
	}
}
