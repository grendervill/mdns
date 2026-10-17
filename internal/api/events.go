package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleEvents streams live updates as Server-Sent Events until the
// client disconnects.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var events <-chan Event
	if s.bus != nil {
		ch, cancel := s.bus.Subscribe()
		defer cancel()
		events = ch
	}

	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	// An immediate ping lets clients distinguish "connected" from
	// "waiting for the first event".
	if !writeSSE(w, flusher, "ping", struct{}{}) {
		return
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			if !writeSSE(w, flusher, e.Type, e.Data) {
				return
			}
		case <-ticker.C:
			if !writeSSE(w, flusher, "ping", struct{}{}) {
				return
			}
		}
	}
}

// writeSSE writes one event; it reports false when the client is gone.
func writeSSE(w http.ResponseWriter, flusher http.Flusher, eventType string, data any) bool {
	payload, err := json.Marshal(data)
	if err != nil {
		payload = []byte(`{}`)
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}
