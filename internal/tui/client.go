// Package tui is the terminal interface: bubbletea models and the API
// client they run on. The TUI is a thin client of the daemon's control
// API and holds no state of its own.
package tui

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
)

// Client is everything the TUI needs from the daemon.
type Client interface {
	Status(ctx context.Context) (api.Status, error)
	Config(ctx context.Context) (*config.Config, error)
	UpdateConfig(ctx context.Context, c *config.Config) error
	Providers(ctx context.Context) ([]providers.Provider, error)
	Probe(ctx context.Context, eps []providers.Endpoint) ([]probe.Result, error)
	Requests(ctx context.Context, n int) ([]qlog.Entry, error)
	FilterStatus(ctx context.Context) ([]filter.ListStatus, error)
	FilterUpdate(ctx context.Context, id string) error
	Events(ctx context.Context) (<-chan api.Event, error)
}

// UnixClient talks to the daemon's control API over its unix socket.
type UnixClient struct {
	socketPath string
	base       string
	http       *http.Client
	stream     *http.Client
}

// NewUnixClient builds a client for the given socket path.
func NewUnixClient(socketPath string) *UnixClient {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	transport := &http.Transport{DialContext: dial}

	return &UnixClient{
		socketPath: socketPath,
		base:       "http://unix",
		http:       &http.Client{Transport: transport, Timeout: 10 * time.Second},
		stream:     &http.Client{Transport: transport}, // no overall timeout for SSE
	}
}

// Status implements Client.
func (c *UnixClient) Status(ctx context.Context) (api.Status, error) {
	var st api.Status
	err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, &st)
	return st, err
}

// Config implements Client.
func (c *UnixClient) Config(ctx context.Context) (*config.Config, error) {
	var cfg config.Config
	if err := c.do(ctx, http.MethodGet, "/api/v1/config", nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// UpdateConfig implements Client.
func (c *UnixClient) UpdateConfig(ctx context.Context, cfg *config.Config) error {
	return c.do(ctx, http.MethodPut, "/api/v1/config", cfg, nil)
}

// Providers implements Client.
func (c *UnixClient) Providers(ctx context.Context) ([]providers.Provider, error) {
	var out []providers.Provider
	err := c.do(ctx, http.MethodGet, "/api/v1/providers", nil, &out)
	return out, err
}

// Probe implements Client.
func (c *UnixClient) Probe(ctx context.Context, eps []providers.Endpoint) ([]probe.Result, error) {
	req := struct {
		Endpoints []providers.Endpoint `json:"endpoints"`
	}{Endpoints: eps}

	var resp struct {
		Results []probe.Result `json:"results"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/probe", req, &resp); err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// Requests implements Client.
func (c *UnixClient) Requests(ctx context.Context, n int) ([]qlog.Entry, error) {
	var out []qlog.Entry
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/requests?n=%d", n), nil, &out)
	return out, err
}

// FilterStatus implements Client.
func (c *UnixClient) FilterStatus(ctx context.Context) ([]filter.ListStatus, error) {
	var out []filter.ListStatus
	err := c.do(ctx, http.MethodGet, "/api/v1/filter/status", nil, &out)
	return out, err
}

// FilterUpdate implements Client.
func (c *UnixClient) FilterUpdate(ctx context.Context, id string) error {
	req := struct {
		ID string `json:"id"`
	}{ID: id}
	return c.do(ctx, http.MethodPost, "/api/v1/filter/update", req, nil)
}

// Events implements Client: a channel of live events until ctx ends.
func (c *UnixClient) Events(ctx context.Context) (<-chan api.Event, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/events", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.stream.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mdns API at %s: %w", c.socketPath, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("mdns API at %s: events status %s", c.socketPath, resp.Status)
	}

	out := make(chan api.Event, 64)
	go func() {
		defer close(out)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

		eventType := ""
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				eventType = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				raw := strings.TrimPrefix(line, "data: ")
				data := decodeEventData(eventType, raw)
				if data == nil {
					continue // ping and unknown types
				}
				select {
				case out <- api.Event{Type: eventType, Data: data}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// decodeEventData parses one SSE payload by event type; nil means
// "ignore this event".
func decodeEventData(eventType, raw string) any {
	switch eventType {
	case "requests":
		var e qlog.Entry
		if err := json.Unmarshal([]byte(raw), &e); err == nil {
			return e
		}
	case "upstreams":
		var u []api.UpstreamStatus
		if err := json.Unmarshal([]byte(raw), &u); err == nil {
			return u
		}
	case "filter":
		var f api.FilterSnapshot
		if err := json.Unmarshal([]byte(raw), &f); err == nil {
			return f
		}
	}
	return nil
}

// do performs one JSON request against the API.
func (c *UnixClient) do(ctx context.Context, method, path string, reqBody, out any) error {
	var body io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("mdns API at %s: %w", c.socketPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("mdns API at %s: %s %s: %s", c.socketPath, method, path, resp.Status)
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
