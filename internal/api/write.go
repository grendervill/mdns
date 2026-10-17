package api

import (
	"encoding/json"
	"io"
	"net/http"

	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
)

// maxBodyBytes bounds every write request body.
const maxBodyBytes = 4 << 20

// handleConfigPut applies a new configuration: the body is validated
// here first, then handed to the controller, which applies it
// transactionally and persists it. The body is the complete config, as
// returned by GET /api/v1/config.
func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	cfg := new(config.Config)

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	if err := json.Unmarshal(body, cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid config JSON: "+err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid config: "+err.Error())
		return
	}

	if err := s.ctl.UpdateConfig(r.Context(), cfg); err != nil {
		s.writeError(w, http.StatusInternalServerError, "apply config: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

// handleProbe measures the given endpoints.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Endpoints []struct {
			Transport  string `json:"transport"`
			Address    string `json:"address"`
			ServerName string `json:"server_name"`
		} `json:"endpoints"`
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	eps := make([]providers.Endpoint, 0, len(req.Endpoints))
	for _, e := range req.Endpoints {
		eps = append(eps, providers.Endpoint{
			Transport:  e.Transport,
			Address:    e.Address,
			ServerName: e.ServerName,
		})
	}

	results := s.ctl.Probe(r.Context(), eps)
	if results == nil {
		results = []probe.Result{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleFilterUpdate triggers a manual (re)load of one list or all of
// them and returns the fresh statuses.
func (s *Server) handleFilterUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}

	if err := s.ctl.FilterUpdate(r.Context(), req.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "filter update: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"lists": s.ctl.FilterStatus()})
}
