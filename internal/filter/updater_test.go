package filter_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mydns/internal/filter"
)

// newTestUpdater builds an updater over a fresh engine and temp data
// dir with an HTTP client that trusts the test server's certificate.
func newTestUpdater(t *testing.T, engine *filter.Engine, specs []filter.ListSpec) (*filter.Updater, string) {
	t.Helper()

	dir := t.TempDir()
	u := filter.NewUpdater(filter.UpdaterOptions{
		Engine:  engine,
		Specs:   specs,
		DataDir: dir,
		Client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			Timeout:   5 * time.Second,
		},
	})
	return u, dir
}

// TestUpdateFetchesAndApplies checks the happy path: fetch, parse,
// persist to disk, apply to the engine.
func TestUpdateFetchesAndApplies(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "! list\n||ads.example.com^\n@@||good.example.com^\n")
	}))
	defer srv.Close()

	e := filter.NewEngine(filter.EngineOptions{})
	u, dir := newTestUpdater(t, e, []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}})
	u.Update(context.Background())

	if blocked, source := e.Check("sub.ads.example.com"); !blocked || source != "t1" {
		t.Fatalf("Check(sub.ads.example.com) = (%v, %q), want (true, t1)", blocked, source)
	}
	if blocked, _ := e.Check("good.example.com"); blocked {
		t.Errorf("Check(good.example.com) = true, want false (list exception)")
	}

	for _, name := range []string{"t1.rules", "t1.meta.json"} {
		if _, err := os.Stat(filepath.Join(dir, "filters", name)); err != nil {
			t.Errorf("os.Stat(%s) = %v, want the file to exist", name, err)
		}
	}

	st := u.Status()
	if len(st) != 1 {
		t.Fatalf("len(Status()) = %d, want 1", len(st))
	}
	if st[0].Error != "" {
		t.Errorf("Status().Error = %q, want empty", st[0].Error)
	}
	if st[0].Applied != 2 || st[0].Skipped != 0 {
		t.Errorf("Status() = %+v, want Applied 2, Skipped 0", st[0])
	}
	if st[0].UpdatedAt.IsZero() {
		t.Errorf("Status().UpdatedAt is zero, want the fetch time")
	}
}

// TestUpdateConditional304 checks the ETag flow: the second update
// sends If-None-Match, gets 304 and keeps the previous data.
func TestUpdateConditional304(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, "||a.example.com^\n")
	}))
	defer srv.Close()

	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}})
	u.Update(context.Background())
	before := u.Status()[0].UpdatedAt

	time.Sleep(5 * time.Millisecond)
	u.Update(context.Background())

	if got := requests.Load(); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
	st := u.Status()[0]
	if !st.UpdatedAt.Equal(before) {
		t.Errorf("UpdatedAt changed on 304: %v -> %v", before, st.UpdatedAt)
	}
	if st.Error != "" {
		t.Errorf("Status().Error = %q, want empty", st.Error)
	}
	if blocked, _ := e.Check("a.example.com"); !blocked {
		t.Errorf("Check(a.example.com) = false, want true after 304")
	}
}

// TestUpdateFailureKeepsOldData checks that a dead server leaves the
// previous rules working and surfaces the error in the status.
func TestUpdateFailureKeepsOldData(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "||sticky.example.com^\n")
	}))

	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}})
	u.Update(context.Background())
	if blocked, _ := e.Check("sticky.example.com"); !blocked {
		t.Fatalf("Check(sticky.example.com) = false before server death, want true")
	}

	srv.Close()
	u.Update(context.Background())

	if blocked, _ := e.Check("sticky.example.com"); !blocked {
		t.Errorf("Check(sticky.example.com) = false after failed update, want the old rules")
	}
	if st := u.Status()[0]; st.Error == "" {
		t.Errorf("Status().Error = empty, want the fetch error")
	}
}

// TestUpdateRejectsHTTP checks the https-only policy.
func TestUpdateRejectsHTTP(t *testing.T) {
	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "bad", URL: "http://example.com/list.txt"}})

	u.Update(context.Background())

	if blocked, _ := e.Check("example.com"); blocked {
		t.Errorf("Check(example.com) = true, want false (nothing applied)")
	}
	if st := u.Status()[0]; !strings.Contains(st.Error, "https") {
		t.Errorf("Status().Error = %q, want a mention of https", st.Error)
	}
}

// TestUpdateTooLarge checks the size limit.
func TestUpdateTooLarge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("||x.example.com^\n", 100))
	}))
	defer srv.Close()

	e := filter.NewEngine(filter.EngineOptions{})
	u := filter.NewUpdater(filter.UpdaterOptions{
		Engine:   e,
		Specs:    []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}},
		DataDir:  t.TempDir(),
		Client:   &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		MaxBytes: 100,
	})
	u.Update(context.Background())

	if st := u.Status()[0]; st.Error == "" {
		t.Errorf("Status().Error = empty, want the size error")
	}
}

// TestUpdateRefusesEmptyList checks that a 200 response carrying no
// usable rules (an HTML error page, say) is treated as a failure and
// never wipes the working rules.
func TestUpdateRefusesEmptyList(t *testing.T) {
	var broken atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if broken.Load() {
			fmt.Fprint(w, "<html><body>temporarily unavailable</body></html>")
			return
		}
		fmt.Fprint(w, "||sticky.example.com^\n")
	}))
	defer srv.Close()

	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}})
	u.Update(context.Background())
	if blocked, _ := e.Check("sticky.example.com"); !blocked {
		t.Fatalf("Check(sticky.example.com) = false before the garbage reply, want true")
	}

	broken.Store(true)
	u.Update(context.Background())

	if blocked, _ := e.Check("sticky.example.com"); !blocked {
		t.Errorf("Check(sticky.example.com) = false after a 200-with-garbage reply, want the old rules")
	}
	if st := u.Status()[0]; st.Error == "" {
		t.Errorf("Status().Error = empty, want an empty-list error")
	}
}

// TestLoadFromDisk checks reading persisted rules at startup, and that
// a missing directory is not an error.
func TestLoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "filters"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "filters", "l1.rules"),
		[]byte("+blocked.example.com\n-except.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "filters", "l1.meta.json"),
		[]byte(`{"id":"l1","url":"https://x/list.txt","updated_at":"2026-10-17T12:00:00Z","applied":2,"skipped":0}`), 0o644); err != nil {
		t.Fatal(err)
	}

	e := filter.NewEngine(filter.EngineOptions{})
	u := filter.NewUpdater(filter.UpdaterOptions{
		Engine:  e,
		Specs:   []filter.ListSpec{{ID: "l1", URL: "https://x/list.txt"}},
		DataDir: dir,
	})
	if err := u.LoadFromDisk(); err != nil {
		t.Fatalf("LoadFromDisk() = %v, want nil", err)
	}

	if blocked, source := e.Check("blocked.example.com"); !blocked || source != "l1" {
		t.Errorf("Check(blocked.example.com) = (%v, %q), want (true, l1)", blocked, source)
	}
	if blocked, _ := e.Check("except.example.com"); blocked {
		t.Errorf("Check(except.example.com) = true, want false (disk exception)")
	}
	if st := u.Status()[0]; !st.FromDisk || st.Applied != 2 {
		t.Errorf("Status() = %+v, want FromDisk with Applied 2", st)
	}

	// A fresh dir without any files must load cleanly too.
	e2 := filter.NewEngine(filter.EngineOptions{})
	u2 := filter.NewUpdater(filter.UpdaterOptions{
		Engine:  e2,
		Specs:   []filter.ListSpec{{ID: "none", URL: "https://x/list.txt"}},
		DataDir: t.TempDir(),
	})
	if err := u2.LoadFromDisk(); err != nil {
		t.Errorf("LoadFromDisk() with no files = %v, want nil", err)
	}
}

// TestRunFirstUpdateImmediateAndStops checks that Run fetches right
// away, keeps fetching on the interval and stops with the context.
func TestRunFirstUpdateImmediateAndStops(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "||a.example.com^\n")
	}))
	defer srv.Close()

	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Run(ctx, 20*time.Millisecond)
		close(done)
	}()

	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done

	if got := requests.Load(); got < 2 {
		t.Errorf("requests = %d, want at least 2 (immediate + interval)", got)
	}
}

// TestRunResumesFromManualMode checks that a manual (zero-interval)
// updater stays alive and starts periodic refreshes once SetInterval
// arms an interval - previously it returned for good.
func TestRunResumesFromManualMode(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "||a.example.com^\n")
	}))
	defer srv.Close()

	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "t1", URL: srv.URL + "/list.txt"}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Run(ctx, 0)
		close(done)
	}()

	waitFor := func(want int64) bool {
		deadline := time.Now().Add(2 * time.Second)
		for requests.Load() < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		return requests.Load() >= want
	}

	if !waitFor(1) {
		t.Fatalf("no immediate update in manual mode")
	}
	select {
	case <-done:
		t.Fatalf("Run returned in manual mode; SetInterval can never resume it")
	default:
	}

	u.SetInterval(20 * time.Millisecond)
	if !waitFor(2) {
		t.Errorf("periodic refreshes did not resume after SetInterval: requests = %d", requests.Load())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not stop with the context")
	}
}

// TestLoadFromDiskRejectsUnsafeID checks that a traversal-style list ID
// cannot read files outside the filters directory.
func TestLoadFromDiskRejectsUnsafeID(t *testing.T) {
	dir := t.TempDir()

	// A crafted id resolves to <dir>/secret.* - plant files there.
	if err := os.WriteFile(filepath.Join(dir, "secret.meta.json"),
		[]byte(`{"URL":"https://x/","UpdatedAt":"2026-01-01T00:00:00Z","Applied":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.rules"), []byte("+evil.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := filter.NewEngine(filter.EngineOptions{})
	u, _ := newTestUpdater(t, e, []filter.ListSpec{{ID: "../secret", URL: "https://x/list.txt"}})

	if err := u.LoadFromDisk(); err != nil {
		t.Fatalf("LoadFromDisk() = %v, want nil", err)
	}
	if blocked, _ := e.Check("evil.example.com."); blocked {
		t.Errorf("a traversal list id loaded rules from outside the filters dir")
	}
}
