package api

import (
	"net/http"
	"strconv"
)

// requestsDefault and requestsMax bound the /requests parameter.
const (
	requestsDefault = 200
	requestsMax     = 10000
)

// handleStatus returns the full read-only snapshot.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.ctl.Status(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "status: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, st)
}

// handleConfigGet returns the current configuration.
func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.ctl.Config())
}

// handleProviders returns the resolver catalog.
func (s *Server) handleProviders(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.ctl.Providers())
}

// handleRequests returns the newest query-log entries, newest last.
func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	n := requestsDefault
	if raw := r.URL.Query().Get("n"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			s.writeError(w, http.StatusBadRequest, "n must be a positive integer")
			return
		}
		n = v
	}
	if n > requestsMax {
		n = requestsMax
	}
	s.writeJSON(w, http.StatusOK, s.ctl.Requests(n))
}

// handleFilterStatus returns the block-list statuses.
func (s *Server) handleFilterStatus(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.ctl.FilterStatus())
}
