package api

import (
	"net/http"
	"net/url"
	"strconv"

	"mydns/internal/qlog"
)

// requestsDefault and requestsMax bound the legacy /requests ?n=
// parameter.
const (
	requestsDefault = 200
	requestsMax     = 10000
)

// Paged /requests bounds: per defaults to requestsPerDefault, is clamped
// to [1, requestsPerMax] and page is at least 1.
const (
	requestsPerDefault = 100
	requestsPerMax     = 500
)

// pagedParams are the query parameters that select the paged /requests
// shape. Presence, not value, decides: the panel sends the parameters
// even when they are empty.
var pagedParams = [...]string{"page", "per", "q", "outcome", "proto", "client", "upstream"}

// knownOutcomes are the outcome filters the API accepts. Any other value
// is treated as no filter rather than an error, so the panel can never
// get a 400 for a name the daemon does not know.
var knownOutcomes = map[string]bool{
	"cached": true, "blocked": true, "upstream": true, "error": true,
}

// handleStatus returns the full read-only snapshot.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.ctl.Status(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "status: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, st)
}

// handleStats returns the cumulative query statistics plus the daemon
// start time.
func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, StatsResponse{
		Snapshot: s.ctl.Stats(),
		Since:    s.ctl.Started(),
	})
}

// handleConfigGet returns the current configuration.
func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.ctl.Config())
}

// handleProviders returns the resolver catalog.
func (s *Server) handleProviders(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.ctl.Providers())
}

// handleRequests serves the query log in one of two shapes. The legacy
// shape (a bare array of the newest N entries) is used when none of the
// paged parameters is present; the TUI depends on it. Otherwise the
// paged, filtered shape is returned.
func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	if !paged(params) {
		n := requestsDefault
		if raw := params.Get("n"); raw != "" {
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
		return
	}

	page := atoiDefault(params.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	per := atoiDefault(params.Get("per"), requestsPerDefault)
	if per < 1 {
		per = 1
	}
	if per > requestsPerMax {
		per = requestsPerMax
	}

	q := qlog.Query{
		Search:   params.Get("q"),
		Outcome:  outcomeFilter(params.Get("outcome")),
		Proto:    params.Get("proto"),
		Client:   params.Get("client"),
		Upstream: params.Get("upstream"),
	}

	entries, total := s.ctl.RequestsQuery(q, page, per)
	if entries == nil {
		entries = []qlog.Entry{} // an empty page is [], never null
	}
	s.writeJSON(w, http.StatusOK, RequestsPage{
		Entries: entries,
		Total:   total,
		Page:    page,
		Pages:   pageCount(total, per),
		Per:     per,
	})
}

// paged reports whether any parameter selecting the paged shape is
// present.
func paged(params url.Values) bool {
	for _, name := range pagedParams {
		if _, ok := params[name]; ok {
			return true
		}
	}
	return false
}

// atoiDefault parses a non-negative integer parameter, falling back to
// def when it is empty or malformed. The paged endpoint is read-only, so
// a malformed value degrades to the default rather than erroring.
func atoiDefault(raw string, def int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

// outcomeFilter validates an outcome name; unknown values mean "no
// filter".
func outcomeFilter(raw string) string {
	if knownOutcomes[raw] {
		return raw
	}
	return ""
}

// pageCount is ceil(total/per), at least 1 so an empty result still
// reports a valid first page.
func pageCount(total, per int) int {
	n := (total + per - 1) / per
	if n < 1 {
		n = 1
	}
	return n
}

// handleFilterStatus returns the block-list statuses.
func (s *Server) handleFilterStatus(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.ctl.FilterStatus())
}
