package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"mydns/internal/configbackup"
)

// backupInfo is the JSON shape of one stored snapshot. configbackup.Info
// carries Go field names, so the API maps it to the snake_case wire
// shape both the TUI and the web panel consume.
type backupInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// backupInfoOf maps one stored snapshot to the wire shape.
func backupInfoOf(info configbackup.Info) backupInfo {
	return backupInfo{Name: info.Name, Size: info.Size, ModTime: info.ModTime}
}

// handleBackupsList returns the stored snapshots, newest first.
func (s *Server) handleBackupsList(w http.ResponseWriter, _ *http.Request) {
	infos, err := s.ctl.ListConfigBackups()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list backups: "+err.Error())
		return
	}

	out := make([]backupInfo, 0, len(infos))
	for _, info := range infos {
		out = append(out, backupInfoOf(info))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"backups": out})
}

// handleBackupCreate stores a new snapshot and returns it. The body is
// optional: an absent or empty label leaves the label off the name.
func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
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

	// The mutation itself is the user's request, so any failure is
	// reported as a bad request with the controller's explanation,
	// exactly as the web panel does.
	if err := s.ctl.CreateConfigBackup(strings.TrimSpace(req.Label)); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	infos, err := s.ctl.ListConfigBackups()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list backups: "+err.Error())
		return
	}
	if len(infos) == 0 {
		s.writeError(w, http.StatusInternalServerError, "created backup is not listed")
		return
	}
	// List is newest first and the snapshot was just written, so its
	// head is the created one.
	s.writeJSON(w, http.StatusOK, backupInfoOf(infos[0]))
}

// handleBackupRestore applies one stored snapshot.
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	name, ok := s.readBackupName(w, r)
	if !ok {
		return
	}
	if err := s.ctl.RestoreConfigBackup(name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}

// handleBackupDelete removes one stored snapshot.
func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	name, ok := s.readBackupName(w, r)
	if !ok {
		return
	}
	if err := s.ctl.DeleteConfigBackup(name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// readBackupName decodes the {"name":...} body shared by restore and
// delete and rejects a missing or blank name before the controller sees
// it. It writes the error response itself and reports whether the caller
// may continue.
func (s *Server) readBackupName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Name string `json:"name"`
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "cannot read request body")
		return "", false
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return "", false
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "backup name is required")
		return "", false
	}
	return name, true
}
