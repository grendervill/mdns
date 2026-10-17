// Package api is the control API of the daemon: a small JSON HTTP
// surface (status, configuration, providers, probes, filter control,
// request log and an SSE event stream) that both the TUI and the future
// web panel consume. The daemon serves it on a unix socket.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/links"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/qlog"
	"mydns/internal/tlscert"
)

// Status is the read-only snapshot the interfaces render.
type Status struct {
	Version   string
	Domain    string
	Links     []links.Link
	Listeners []string // "doh:443", "plain:53", ...
	Strategy  string
	Upstreams []UpstreamStatus
	Cache     cache.Stats
	Filter    FilterSnapshot
	Cert      tlscert.Status
}

// UpstreamStatus is one upstream's live state.
type UpstreamStatus struct {
	ID        string
	Name      string
	Transport string
	Address   string
	Enabled   bool
	Healthy   bool
	LatencyMS float64
	Sent      uint64
	Failed    uint64
}

// FilterSnapshot is the block-list engine state.
type FilterSnapshot struct {
	Enabled      bool
	Mode         string
	TotalBlocked uint64
	Lists        []filter.ListStat
}

// Controller is everything the daemon exposes over the API; *app.App
// implements it.
type Controller interface {
	Status(ctx context.Context) (Status, error)
	Config() *config.Config
	UpdateConfig(ctx context.Context, c *config.Config) error
	Providers() []providers.Provider
	Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result
	Requests(n int) []qlog.Entry
	FilterStatus() []filter.ListStatus
	FilterUpdate(ctx context.Context, id string) error
}

// Server is the HTTP API. It is safe for concurrent use after New.
type Server struct {
	ctl    Controller
	bus    *Bus
	logger *slog.Logger
	mux    *http.ServeMux

	// pingInterval paces SSE keep-alives; tests shorten it.
	pingInterval time.Duration
}

// ServerOptions adjust the server for tests.
type ServerOptions struct {
	PingInterval time.Duration // 0 → 15s
}

// New builds the API server over ctl. bus carries live events for the
// /events stream; it may be nil (stream then carries pings only).
func New(ctl Controller, bus *Bus, logger *slog.Logger, opts ServerOptions) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	ping := opts.PingInterval
	if ping <= 0 {
		ping = 15 * time.Second
	}

	s := &Server{ctl: ctl, bus: bus, logger: logger, pingInterval: ping}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/config", s.handleConfigGet)
	mux.HandleFunc("PUT /api/v1/config", s.handleConfigPut)
	mux.HandleFunc("GET /api/v1/providers", s.handleProviders)
	mux.HandleFunc("POST /api/v1/probe", s.handleProbe)
	mux.HandleFunc("GET /api/v1/requests", s.handleRequests)
	mux.HandleFunc("GET /api/v1/filter/status", s.handleFilterStatus)
	mux.HandleFunc("POST /api/v1/filter/update", s.handleFilterUpdate)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	s.mux = mux
	return s
}

// Handler returns the API handler (for tests and for mounting into the
// HTTPS server in the web plan).
func (s *Server) Handler() http.Handler { return s.mux }

// Serve runs the API on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.mux}

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

// writeJSON writes one JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Warn("api: writing response failed", "error", err)
	}
}

// writeError writes the standard error body.
func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]string{"error": msg})
}
