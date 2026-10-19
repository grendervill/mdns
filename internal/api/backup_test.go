package api_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"mydns/internal/configbackup"
)

// backupListBody is the wire shape of GET /api/v1/backups.
type backupListBody struct {
	Backups []struct {
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"mod_time"`
	} `json:"backups"`
}

// backupBody is the wire shape of one backup.
type backupBody struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// TestBackupsList checks the list shape, the newest-first order and the
// snake_case mod_time field.
func TestBackupsList(t *testing.T) {
	newest := configbackup.Info{
		Name:    "config-20261019-120000-manual.json",
		Size:    128,
		ModTime: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
	}
	older := configbackup.Info{
		Name:    "config-20261018-090000-auto.json",
		Size:    64,
		ModTime: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC),
	}
	ctl := &fakeController{backups: []configbackup.Info{newest, older}}
	ts := newTestServer(t, ctl)

	var got backupListBody
	if code := getJSON(t, ts, "/api/v1/backups", &got); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if len(got.Backups) != 2 {
		t.Fatalf("backups = %d, want 2", len(got.Backups))
	}
	if got.Backups[0].Name != newest.Name || got.Backups[1].Name != older.Name {
		t.Errorf("order = [%s %s], want newest first", got.Backups[0].Name, got.Backups[1].Name)
	}
	if got.Backups[0].Size != newest.Size {
		t.Errorf("size = %d, want %d", got.Backups[0].Size, newest.Size)
	}
	if !got.Backups[0].ModTime.Equal(newest.ModTime) {
		t.Errorf("mod_time = %v, want %v", got.Backups[0].ModTime, newest.ModTime)
	}
}

// TestBackupsListEmpty checks an empty store serializes as [] and not
// null, so clients can range over it unconditionally.
func TestBackupsListEmpty(t *testing.T) {
	ts := newTestServer(t, &fakeController{})

	resp, err := http.Get(ts.URL + "/api/v1/backups")
	if err != nil {
		t.Fatalf("GET = %v, want nil", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(raw), `"backups":[]`) {
		t.Errorf("body = %s, want backups:[]", raw)
	}
}

// TestBackupCreate checks the label reaches the controller and the
// created snapshot comes back.
func TestBackupCreate(t *testing.T) {
	created := configbackup.Info{
		Name:    "config-20261019-120000-manual.json",
		Size:    256,
		ModTime: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
	}
	ctl := &fakeController{createdBackup: created}
	ts := newTestServer(t, ctl)

	resp := postJSON(t, ts.URL+"/api/v1/backups", map[string]string{"label": "manual"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ctl.lastLabel != "manual" {
		t.Errorf("CreateConfigBackup(%q), want manual", ctl.lastLabel)
	}

	var got backupBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != created.Name || got.Size != created.Size || !got.ModTime.Equal(created.ModTime) {
		t.Errorf("created = %+v, want %+v", got, created)
	}
}

// TestBackupCreateNoLabel checks the body is optional and an absent
// label reaches the controller as "".
func TestBackupCreateNoLabel(t *testing.T) {
	ctl := &fakeController{}
	ts := newTestServer(t, ctl)

	resp, err := http.Post(ts.URL+"/api/v1/backups", "application/json", nil)
	if err != nil {
		t.Fatalf("POST = %v, want nil", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ctl.lastLabel != "" {
		t.Errorf("CreateConfigBackup(%q), want an empty label", ctl.lastLabel)
	}
}

// TestBackupRestoreAndDelete checks the name is passed through and the
// status shape is stable.
func TestBackupRestoreAndDelete(t *testing.T) {
	name := "config-20261019-120000-manual.json"
	ctl := &fakeController{backups: []configbackup.Info{{Name: name, Size: 64}}}
	ts := newTestServer(t, ctl)

	resp := postJSON(t, ts.URL+"/api/v1/backups/restore", map[string]string{"name": " " + name + " "})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore status = %d, want 200", resp.StatusCode)
	}
	if ctl.lastRestore != name {
		t.Errorf("RestoreConfigBackup(%q), want %q", ctl.lastRestore, name)
	}
	var restored map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&restored); err != nil {
		t.Fatalf("decode restore: %v", err)
	}
	if restored["status"] != "restored" {
		t.Errorf("restore body = %v, want status restored", restored)
	}

	resp = postJSON(t, ts.URL+"/api/v1/backups/delete", map[string]string{"name": name})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", resp.StatusCode)
	}
	if ctl.lastDelete != name {
		t.Errorf("DeleteConfigBackup(%q), want %q", ctl.lastDelete, name)
	}
	var deleted map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&deleted); err != nil {
		t.Fatalf("decode delete: %v", err)
	}
	if deleted["status"] != "deleted" {
		t.Errorf("delete body = %v, want status deleted", deleted)
	}
}

// TestBackupBadRequests checks blank names, malformed JSON, a missing
// name and an unknown name are all rejected with 400 before the
// controller's mutation runs.
func TestBackupBadRequests(t *testing.T) {
	ctl := &fakeController{backups: []configbackup.Info{{Name: "config-20261019-120000.json"}}}
	ts := newTestServer(t, ctl)

	for _, path := range []string{"/api/v1/backups/restore", "/api/v1/backups/delete"} {
		if resp := postJSON(t, ts.URL+path, map[string]string{"name": "  "}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s blank name status = %d, want 400", path, resp.StatusCode)
		}
		if resp := postJSON(t, ts.URL+path, map[string]string{}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s missing name status = %d, want 400", path, resp.StatusCode)
		}

		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader("{not json"))
		if err != nil {
			t.Fatalf("POST %s = %v, want nil", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s bad JSON status = %d, want 400", path, resp.StatusCode)
		}

		// Not in the listed set: neither restore nor delete may address
		// it, and a traversal-looking name is just an unknown name.
		for _, name := range []string{"config-20260101-000000-gone.json", "../escape.json"} {
			resp := postJSON(t, ts.URL+path, map[string]string{"name": name})
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s %q status = %d, want 400", path, name, resp.StatusCode)
			}
			var body map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if !strings.Contains(body["error"], "не найдена") {
				t.Errorf("%s %q error = %q, want the not-found message", path, name, body["error"])
			}
		}
	}
	if ctl.lastRestore != "" || ctl.lastDelete != "" {
		t.Errorf("the controller ran a mutation for a name it never listed")
	}

	resp, err := http.Post(ts.URL+"/api/v1/backups", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("POST create = %v, want nil", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("create bad JSON status = %d, want 400", resp.StatusCode)
	}
}

// TestBackupValidationError checks a listed snapshot whose content the
// controller rejects still surfaces as 400 with its text, while a list
// failure is a 500.
func TestBackupValidationError(t *testing.T) {
	name := "config-20261019-120000.json"
	ctl := &fakeController{
		backups:    []configbackup.Info{{Name: name}},
		restoreErr: fmt.Errorf("%w: domain must not be empty", configbackup.ErrInvalid),
	}
	ts := newTestServer(t, ctl)

	resp := postJSON(t, ts.URL+"/api/v1/backups/restore", map[string]string{"name": name})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("restore status = %d, want 400", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body["error"], "domain must not be empty") {
		t.Errorf("error = %q, want the controller's text", body["error"])
	}

	ctl.listErr = errors.New("read permission denied")
	if code := getJSON(t, ts, "/api/v1/backups", nil); code != http.StatusInternalServerError {
		t.Errorf("list status = %d, want 500", code)
	}
	// The same failure while gating a mutation is a 500 too.
	if resp := postJSON(t, ts.URL+"/api/v1/backups/delete", map[string]string{"name": name}); resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("delete with a failed list status = %d, want 500", resp.StatusCode)
	}
}

// TestBackupInternalErrors checks a disk or apply failure in any
// mutation is a 500, not a bad request.
func TestBackupInternalErrors(t *testing.T) {
	name := "config-20261019-120000.json"
	boom := errors.New("write permission denied")

	t.Run("create", func(t *testing.T) {
		ctl := &fakeController{createErr: boom}
		ts := newTestServer(t, ctl)
		if resp := postJSON(t, ts.URL+"/api/v1/backups", map[string]string{"label": "manual"}); resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("create status = %d, want 500", resp.StatusCode)
		}

		// A rejected label stays a bad request.
		ctl.createErr = configbackup.ErrInvalidName
		if resp := postJSON(t, ts.URL+"/api/v1/backups", map[string]string{"label": "../x"}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create with a bad label status = %d, want 400", resp.StatusCode)
		}
	})

	for _, tc := range []struct {
		path string
		ctl  *fakeController
	}{
		{"/api/v1/backups/restore", &fakeController{backups: []configbackup.Info{{Name: name}}, restoreErr: boom}},
		{"/api/v1/backups/delete", &fakeController{backups: []configbackup.Info{{Name: name}}, deleteErr: boom}},
	} {
		ts := newTestServer(t, tc.ctl)
		resp := postJSON(t, ts.URL+tc.path, map[string]string{"name": name})
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s status = %d, want 500", tc.path, resp.StatusCode)
		}
	}
}
