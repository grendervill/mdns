package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultMaxBytes bounds one downloaded list.
const defaultMaxBytes = 128 << 20

// defaultFetchTimeout bounds one download when no client is supplied.
const defaultFetchTimeout = 60 * time.Second

// ListSpec is one configured list: an ID and the https URL to fetch.
type ListSpec struct {
	ID  string
	URL string
}

// ListStatus is the live state of one list for the interfaces.
type ListStatus struct {
	ID        string
	URL       string
	UpdatedAt time.Time // last successful update
	Applied   int
	Skipped   int
	FromDisk  bool   // loaded from the local cache at startup
	Error     string // last failure; empty on success
}

// UpdaterOptions configure an Updater.
type UpdaterOptions struct {
	Engine   *Engine
	Specs    []ListSpec
	DataDir  string
	Client   *http.Client // nil: https client with a 60s timeout
	MaxBytes int64        // <= 0: 128 MiB
	Logger   *slog.Logger
}

// listMeta is the persisted state of one list.
type listMeta struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
	Applied      int       `json:"applied"`
	Skipped      int       `json:"skipped"`
}

// Updater fetches lists over HTTPS, persists them under
// DataDir/filters and installs them into the engine. Safe for
// concurrent Status calls; Update itself is meant to run from one
// goroutine (Run) at a time.
type Updater struct {
	engine   *Engine
	specs    []ListSpec
	dataDir  string
	client   *http.Client
	maxBytes int64
	logger   *slog.Logger

	interval atomic.Int64 // nanoseconds; the sleeping Run picks changes up immediately
	wake     chan struct{}

	mu     sync.Mutex
	status map[string]*ListStatus
	order  []string
}

// NewUpdater builds an updater; zero options fall back to production
// defaults.
func NewUpdater(opts UpdaterOptions) *Updater {
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	u := &Updater{
		engine:   opts.Engine,
		specs:    opts.Specs,
		dataDir:  opts.DataDir,
		client:   client,
		maxBytes: maxBytes,
		logger:   logger,
		wake:     make(chan struct{}, 1),
		status:   make(map[string]*ListStatus, len(opts.Specs)),
	}
	for _, s := range opts.Specs {
		u.order = append(u.order, s.ID)
		u.status[s.ID] = &ListStatus{ID: s.ID, URL: s.URL}
	}
	return u
}

// SetInterval changes the update period; a Run currently sleeping
// re-arms immediately. A zero interval means "single update": a running
// Run stops after its current pass.
func (u *Updater) SetInterval(d time.Duration) {
	u.interval.Store(int64(d))
	select {
	case u.wake <- struct{}{}:
	default:
	}
}

// LoadFromDisk installs every list that has persisted rules under
// DataDir/filters. Missing or unreadable files are skipped: the engine
// simply starts without those lists.
func (u *Updater) LoadFromDisk() error {
	for _, spec := range u.specs {
		if err := validateListID(spec.ID); err != nil {
			continue // never touch paths outside the filters dir
		}
		meta, err := u.readMeta(spec.ID)
		if err != nil {
			continue // nothing cached for this list yet
		}
		block, except, err := u.readRules(spec.ID)
		if err != nil {
			continue // rules missing or unreadable
		}

		u.engine.SetList(CompiledList{
			ID:     spec.ID,
			URL:    meta.URL,
			Block:  block,
			Except: except,
		})

		u.mu.Lock()
		u.status[spec.ID] = &ListStatus{
			ID:        spec.ID,
			URL:       meta.URL,
			UpdatedAt: meta.UpdatedAt,
			Applied:   meta.Applied,
			Skipped:   meta.Skipped,
			FromDisk:  true,
		}
		u.mu.Unlock()
	}
	return nil
}

// Update fetches and applies every configured list. Per-list failures
// are recorded in the status and never abort the remaining lists.
func (u *Updater) Update(ctx context.Context) {
	for _, spec := range u.specs {
		if ctx.Err() != nil {
			return
		}
		u.updateOne(ctx, spec)
	}
}

// Run performs an immediate Update and then repeats it every interval
// until ctx is cancelled; a non-positive interval means no periodic
// refreshes until SetInterval arms one. While idle or sleeping,
// SetInterval changes take effect immediately.
func (u *Updater) Run(ctx context.Context, interval time.Duration) {
	u.SetInterval(interval)

	u.Update(ctx)
	for {
		d := time.Duration(u.interval.Load())
		if d <= 0 {
			// Manual mode: stay alive so a later SetInterval can arm
			// periodic refreshes without a daemon restart.
			select {
			case <-ctx.Done():
				return
			case <-u.wake:
			}
			continue
		}

		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-u.wake:
			timer.Stop() // new interval: re-arm
		case <-timer.C:
			u.Update(ctx)
		}
	}
}

// UpdateOne refreshes one list by ID; an empty id refreshes every
// list. Unknown IDs are an error.
func (u *Updater) UpdateOne(ctx context.Context, id string) error {
	if id == "" {
		u.Update(ctx)
		return nil
	}
	for _, spec := range u.specs {
		if spec.ID == id {
			u.updateOne(ctx, spec)
			return nil
		}
	}
	return fmt.Errorf("filter: unknown list %q", id)
}

// Status returns the current state of every configured list, in
// configuration order.
func (u *Updater) Status() []ListStatus {
	u.mu.Lock()
	defer u.mu.Unlock()

	out := make([]ListStatus, 0, len(u.order))
	for _, id := range u.order {
		if s := u.status[id]; s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// updateOne performs one conditional fetch and install for one list.
func (u *Updater) updateOne(ctx context.Context, spec ListSpec) {
	if ctx.Err() != nil {
		return
	}
	if err := validateListID(spec.ID); err != nil {
		u.fail(spec.ID, err)
		return
	}

	parsedURL, err := url.Parse(spec.URL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
		u.fail(spec.ID, fmt.Errorf("list URL must be https: %q", spec.URL))
		return
	}

	meta, _ := u.readMeta(spec.ID) // nil when nothing is cached yet

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		u.fail(spec.ID, fmt.Errorf("build request: %w", err))
		return
	}
	if meta != nil {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}

	resp, err := u.client.Do(req)
	if err != nil {
		// A cancelled context means a shutdown or a runtime swap
		// aborted the fetch; that is not a list failure, so never mark
		// the list and never warn. A shared updater would otherwise
		// carry a spurious "context canceled" error into the new
		// generation's status.
		if ctx.Err() != nil {
			return
		}
		u.fail(spec.ID, fmt.Errorf("fetch: %w", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		u.markChecked(spec.ID)
		return
	}
	if resp.StatusCode != http.StatusOK {
		u.fail(spec.ID, fmt.Errorf("unexpected status %s", resp.Status))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, u.maxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return // aborted mid-body, same as an aborted fetch
		}
		u.fail(spec.ID, fmt.Errorf("read body: %w", err))
		return
	}
	if int64(len(body)) > u.maxBytes {
		u.fail(spec.ID, fmt.Errorf("list exceeds %d bytes", u.maxBytes))
		return
	}

	parsed, err := Parse(bytes.NewReader(body))
	if err != nil {
		u.fail(spec.ID, fmt.Errorf("parse: %w", err))
		return
	}
	if parsed.Applied == 0 {
		// A 200 carrying no usable rules is almost always an error
		// page or an emptied list; never let it wipe working rules.
		u.fail(spec.ID, fmt.Errorf("list has no usable rules (%d lines skipped)", parsed.Skipped))
		return
	}

	newMeta := listMeta{
		ID:           spec.ID,
		URL:          spec.URL,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		UpdatedAt:    time.Now(),
		Applied:      parsed.Applied,
		Skipped:      parsed.Skipped,
	}
	if err := u.save(spec.ID, parsed, newMeta); err != nil {
		u.fail(spec.ID, fmt.Errorf("persist: %w", err))
		return
	}

	u.engine.SetList(CompiledList{
		ID:     spec.ID,
		URL:    spec.URL,
		Block:  parsed.Block,
		Except: parsed.Except,
	})

	u.mu.Lock()
	u.status[spec.ID] = &ListStatus{
		ID:        spec.ID,
		URL:       spec.URL,
		UpdatedAt: newMeta.UpdatedAt,
		Applied:   parsed.Applied,
		Skipped:   parsed.Skipped,
	}
	u.mu.Unlock()

	u.logger.Debug("filter list updated",
		"id", spec.ID, "applied", parsed.Applied, "skipped", parsed.Skipped)
}

// fail records a per-list error, keeping everything else intact.
func (u *Updater) fail(id string, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if s := u.status[id]; s != nil {
		s.Error = err.Error()
	}
	u.logger.Warn("filter list update failed", "id", id, "error", err)
}

// markChecked clears the error after a 304 without touching the data.
func (u *Updater) markChecked(id string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if s := u.status[id]; s != nil {
		s.Error = ""
	}
}

// validateListID keeps IDs safe to use in file names.
func validateListID(id string) error {
	if id == "" {
		return fmt.Errorf("list id must not be empty")
	}
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return fmt.Errorf("list id %q must not contain path separators", id)
	}
	return nil
}

// filtersDir returns DataDir/filters.
func (u *Updater) filtersDir() string {
	return filepath.Join(u.dataDir, "filters")
}

// save persists the parsed rules and the meta file atomically.
func (u *Updater) save(id string, parsed Parsed, meta listMeta) error {
	dir := u.filtersDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var rules strings.Builder
	for _, d := range parsed.Block {
		rules.WriteString("+")
		rules.WriteString(d)
		rules.WriteString("\n")
	}
	for _, d := range parsed.Except {
		rules.WriteString("-")
		rules.WriteString(d)
		rules.WriteString("\n")
	}
	if err := writeFileAtomic(filepath.Join(dir, id+".rules"), []byte(rules.String())); err != nil {
		return err
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, id+".meta.json"), metaJSON)
}

// readMeta loads the persisted meta of one list; a missing or broken
// file reads as "nothing cached".
func (u *Updater) readMeta(id string) (*listMeta, error) {
	raw, err := os.ReadFile(filepath.Join(u.filtersDir(), id+".meta.json"))
	if err != nil {
		return nil, err
	}
	var m listMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// readRules loads the persisted rule lines of one list.
func (u *Updater) readRules(id string) (block, except []string, err error) {
	raw, err := os.ReadFile(filepath.Join(u.filtersDir(), id+".rules"))
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case '+':
			block = append(block, line[1:])
		case '-':
			except = append(except, line[1:])
		}
	}
	return block, except, nil
}

// writeFileAtomic writes data via a temp file and rename, so readers
// never see a partial file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name()) // no-op after a successful rename
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
