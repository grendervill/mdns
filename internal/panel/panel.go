// Package panel serves the mdns admin web UI. It is mounted on the DoH
// listener next to /dns-query: a small server-rendered HTML surface
// with session login and CSRF-protected forms. Later tasks add the
// status, history and management pages on top of this skeleton.
package panel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"mydns/internal/api"
	"mydns/internal/auth"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/qlog"
	"mydns/internal/stats"
)

const (
	// SessionTTL is how long a login lasts. Sessions live in memory,
	// so a restart logs everybody out.
	SessionTTL = 30 * 24 * time.Hour

	// LoginFailLimit and LoginFailWindow bound failed logins per client
	// address. They are positive on purpose: a zero limit or window
	// would switch the auth.Throttle off silently, and the panel must
	// never do that.
	LoginFailLimit  = 5
	LoginFailWindow = 15 * time.Minute

	// sessionCookie is the name of the login cookie. It never appears
	// in a URL: the SSE stream and every page read it from the header.
	sessionCookie = "mdns_session"

	// defaultPingInterval paces the /panel/events keep-alives between
	// live query events.
	defaultPingInterval = 15 * time.Second
)

// Controller is the slice of the daemon the panel consumes. It mirrors
// api.Controller; *app.App implements both. Later pages widen this
// interface as they need more of the API.
type Controller interface {
	// Config returns the current configuration.
	Config() *config.Config
	// UpdateConfig validates, applies and persists a new configuration.
	// It is transactional: a rejected change leaves the running daemon
	// untouched, so a management page can re-render with the error.
	UpdateConfig(ctx context.Context, c *config.Config) error
	// Status returns the read-only daemon snapshot.
	Status(ctx context.Context) (api.Status, error)
	// Stats returns the cumulative query statistics since start.
	Stats() stats.Snapshot
	// Started is when the daemon was constructed; the maintenance page
	// renders its uptime.
	Started() time.Time
	// Requests returns the newest n query records, oldest first. The
	// status feed backfills its buffer with it.
	Requests(n int) []qlog.Entry
	// RequestsQuery returns one page (1-based page, per entries) of
	// filtered history, newest first, with the total match count. The
	// history page and its CSV export use it.
	RequestsQuery(q qlog.Query, page, per int) ([]qlog.Entry, int)
	// FilterStatus returns the per-list block-list updater status.
	FilterStatus() []filter.ListStatus
	// FilterUpdate reloads one block list, or every list when id is "".
	FilterUpdate(ctx context.Context, id string) error
}

// Options configure a Panel. Zero values are safe: Sessions and
// Throttle are built with the production defaults when omitted.
type Options struct {
	// Enabled and PasswordHash are a static answer used when Auth is
	// nil (tests and embedders). A nil Auth means the panel never sees
	// a password change.
	Enabled      bool
	PasswordHash string

	// Auth, when set, is the live source of the enabled flag and the
	// password hash. It is consulted on every request and nothing is
	// cached, so a password change from the panel applies without a
	// restart. Changing the hash does not revoke the sessions that are
	// already open; that is deliberate, so an admin who rotates the
	// password is not logged out of the tab they are using. It wins
	// over Enabled and PasswordHash.
	Auth func() (enabled bool, hash string)

	// Sessions holds the live login tokens. Nil builds the default
	// store with SessionTTL; pass one to share it with a caller that
	// wants to revoke sessions itself.
	Sessions *auth.Sessions
	// Throttle bounds failed logins. Nil builds the default throttle
	// with LoginFailLimit and LoginFailWindow.
	Throttle *auth.Throttle

	// Ctrl is the daemon behind the panel. It may be nil in tests that
	// only exercise routing and auth.
	Ctrl Controller

	// Bus carries the live query events behind /panel/events. It may be
	// nil: the page still renders and the stream still delivers its
	// snapshot and pings, it just never gains a new row.
	Bus *api.Bus

	// Version is the daemon version shown in the shell.
	Version string
	// Logger receives warnings; nil falls back to slog.Default.
	Logger *slog.Logger

	// PingInterval paces /panel/events keep-alives; 0 → 15s.
	PingInterval time.Duration
}

// Panel is the web UI. Build it with New and mount it with Mount; it is
// safe for concurrent use.
type Panel struct {
	// authFn resolves the live enabled flag and password hash. It is
	// either Options.Auth or a closure over the static Options fields.
	authFn   func() (enabled bool, hash string)
	version  string
	ctrl     Controller
	sessions *auth.Sessions
	throttle *auth.Throttle
	logger   *slog.Logger

	// csrfKey is a per-process random secret: CSRF tokens are an HMAC
	// of a request's session token under it, so a token is bound to one
	// session and cannot be replayed across sessions. It lives only in
	// memory, consistent with the in-memory sessions.
	csrfKey []byte

	pingInterval time.Duration

	// feed is the rolling buffer behind the status page's live feed. It
	// holds the newest feedSize entries, shared by every SSE client, so
	// a client that connects late (or reconnects) still sees the recent
	// traffic instead of an empty list.
	feed *feed

	// bus is the live event source; nil when the panel is not wired to
	// a daemon.
	bus *api.Bus

	// refresh is the single-flight state of the block-list update. The
	// POST returns at once and the download runs in the background, so
	// the DoH listener's write timeout cannot truncate it.
	refresh filterRefresh
}

// New builds a Panel. A nil Sessions or Throttle is replaced with the
// production default, so the panel never runs without its abuse
// controls.
func New(opts Options) *Panel {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sessions := opts.Sessions
	if sessions == nil {
		sessions = auth.NewSessions(SessionTTL)
	}
	throttle := opts.Throttle
	if throttle == nil {
		throttle = auth.NewThrottle(LoginFailLimit, LoginFailWindow)
	}
	ping := opts.PingInterval
	if ping <= 0 {
		ping = defaultPingInterval
	}

	authFn := opts.Auth
	if authFn == nil {
		enabled, hash := opts.Enabled, opts.PasswordHash
		authFn = func() (bool, string) { return enabled, hash }
	}

	p := &Panel{
		authFn:       authFn,
		version:      opts.Version,
		ctrl:         opts.Ctrl,
		sessions:     sessions,
		throttle:     throttle,
		logger:       logger,
		csrfKey:      mustRandom(32),
		pingInterval: ping,
		feed:         newFeed(feedSize),
		bus:          opts.Bus,
	}
	p.startFeed()
	return p
}

// startFeed seeds the live feed with the recent queries the daemon
// already has and, when a bus is wired, keeps it current. The panel is
// a process-lifetime object, so the subscription is deliberately not
// torn down; it ends with the process.
func (p *Panel) startFeed() {
	if p.ctrl != nil {
		p.feed.seed(p.ctrl.Requests(feedSize))
	}
	if p.bus == nil {
		return
	}
	events, _ := p.bus.Subscribe()
	go func() {
		for e := range events {
			if e.Type != "requests" {
				continue
			}
			if entry, ok := e.Data.(qlog.Entry); ok {
				p.feed.push(entry)
			}
		}
	}()
}

// auth reports the live enabled flag and stored password hash. When
// Options.Auth is set it is the only source — the panel caches nothing,
// so an update to the running configuration takes effect at once.
func (p *Panel) auth() (enabled bool, hash string) {
	return p.authFn()
}

// location is the zone the panel renders query times in: the configured
// IANA zone, the daemon's local zone when none is set, and local again
// for a value the time database cannot load (an invalid stored zone must
// never panic a page). It reads the live config on every call, so a
// timezone change applies without a restart; only the display changes,
// the stored timestamps stay as they are.
func (p *Panel) location() *time.Location {
	cfg := p.currentConfig()
	if cfg == nil || cfg.Timezone == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return time.Local
	}
	return loc
}

// Mount registers every panel route on mux. The DoH listener shares one
// mux with /dns-query, so the patterns here never collide with it. A
// disabled panel still registers the routes but answers 404 on all of
// them, so it does not reveal that it exists.
func (p *Panel) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", p.handleRoot)

	mux.HandleFunc("GET /login", p.handleLoginForm)
	mux.HandleFunc("POST /login", p.handleLoginSubmit)

	mux.Handle("POST /logout", p.requireSession(http.HandlerFunc(p.handleLogout)))

	// Static assets are public: the login page itself needs them.
	mux.Handle("GET /panel/static/", http.StripPrefix("/panel/static/", p.staticHandler()))
	mux.Handle("GET /panel/events", p.requireSession(http.HandlerFunc(p.handleEvents)))
	mux.Handle("GET /panel/{$}", p.requireSession(http.HandlerFunc(p.handleStatus)))

	// Query history: the page and its CSV export share one filter
	// parser. Both are read-only and non-live.
	mux.Handle("GET /panel/history", p.requireSession(http.HandlerFunc(p.handleHistory)))
	mux.Handle("GET /panel/history.csv", p.requireSession(http.HandlerFunc(p.handleHistoryCSV)))

	// Management pages. Every mutation is a POST behind the session and
	// the CSRF token; the pages carry no script and redirect after a
	// successful change, so a reload never resubmits.
	mux.Handle("GET /panel/upstreams", p.requireSession(http.HandlerFunc(p.handleUpstreams)))
	mux.Handle("POST /panel/upstreams/toggle", p.requireSession(http.HandlerFunc(p.handleUpstreamToggle)))
	mux.Handle("POST /panel/upstreams/priority", p.requireSession(http.HandlerFunc(p.handleUpstreamPriority)))
	mux.Handle("POST /panel/upstreams/strategy", p.requireSession(http.HandlerFunc(p.handleUpstreamStrategy)))
	mux.Handle("POST /panel/upstreams/add", p.requireSession(http.HandlerFunc(p.handleUpstreamAdd)))
	mux.Handle("POST /panel/upstreams/custom", p.requireSession(http.HandlerFunc(p.handleUpstreamCustom)))
	mux.Handle("POST /panel/upstreams/remove", p.requireSession(http.HandlerFunc(p.handleUpstreamRemove)))

	mux.Handle("GET /panel/filters", p.requireSession(http.HandlerFunc(p.handleFilters)))
	mux.Handle("POST /panel/filters/refresh", p.requireSession(http.HandlerFunc(p.handleFiltersRefresh)))
	mux.Handle("POST /panel/filters/mode", p.requireSession(http.HandlerFunc(p.handleFilterMode)))
	mux.Handle("POST /panel/filters/lists/add", p.requireSession(http.HandlerFunc(p.handleFilterListAdd)))
	mux.Handle("POST /panel/filters/lists/remove", p.requireSession(http.HandlerFunc(p.handleFilterListRemove)))
	mux.Handle("POST /panel/filters/rules/add", p.requireSession(http.HandlerFunc(p.handleFilterRuleAdd)))
	mux.Handle("POST /panel/filters/rules/remove", p.requireSession(http.HandlerFunc(p.handleFilterRuleRemove)))

	mux.Handle("GET /panel/settings", p.requireSession(http.HandlerFunc(p.handleSettings)))
	mux.Handle("POST /panel/settings", p.requireSession(http.HandlerFunc(p.handleSettingsApply)))
	mux.Handle("POST /panel/settings/password", p.requireSession(http.HandlerFunc(p.handlePasswordChange)))

	mux.Handle("GET /panel/cert", p.requireSession(http.HandlerFunc(p.handleCert)))

	mux.Handle("GET /panel/maintenance", p.requireSession(http.HandlerFunc(p.handleMaintenance)))
	mux.Handle("GET /panel/maintenance/config.json", p.requireSession(http.HandlerFunc(p.handleConfigDownload)))
	mux.Handle("POST /panel/maintenance/reapply", p.requireSession(http.HandlerFunc(p.handleReapply)))

	// The slash-less spellings. Without an exact route ServeMux would
	// answer its own 307 before the panel sees the request, which leaks
	// the route's existence when the panel is off. Registering them
	// makes the disabled panel answer 404 like every other path and lets
	// the enabled one redirect deliberately. /panel/static has no index
	// to fall back to, so its slash-less form is 404 in both modes.
	mux.HandleFunc("GET /panel", p.handlePanelNoSlash)
	mux.HandleFunc("GET /panel/static", p.handleNotFound)

	// Catch-alls for the wrong method or an unknown subpath. They gate
	// on the session like the rest of /panel/, and answer 404 behind
	// it, so no route leaks into an unauthenticated answer.
	mux.Handle("/login", http.HandlerFunc(p.handleNotFound))
	mux.Handle("/logout", http.HandlerFunc(p.handleNotFound))
	mux.Handle("/panel/", p.requireSession(http.HandlerFunc(p.handleNotFound)))
}

// handleRoot is the convenience root: it points at the panel when the
// panel is on, and 404s when it is off, before redirecting anywhere.
func (p *Panel) handleRoot(w http.ResponseWriter, r *http.Request) {
	if enabled, _ := p.auth(); !enabled {
		p.handleNotFound(w, r)
		return
	}
	http.Redirect(w, r, "/panel/", http.StatusFound)
}

// handlePanelNoSlash is GET /panel: a disabled panel answers 404 like
// every other route; an enabled one sends the visitor to /panel/.
func (p *Panel) handlePanelNoSlash(w http.ResponseWriter, r *http.Request) {
	if enabled, _ := p.auth(); !enabled {
		p.handleNotFound(w, r)
		return
	}
	http.Redirect(w, r, "/panel/", http.StatusPermanentRedirect)
}

// handleNotFound answers 404 without a body that hints at the panel.
func (p *Panel) handleNotFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// requireSession gates a handler behind a valid session. Anonymous GETs
// are sent to /login; anonymous mutations get a 401 (there is no form
// to redirect back to). Mutations additionally need the session-bound
// CSRF token; a bad token is a 403 and leaves the session intact.
func (p *Panel) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enabled, _ := p.auth()
		if !enabled {
			p.handleNotFound(w, r)
			return
		}

		token := p.sessionToken(r)
		if token == "" || !p.sessions.Valid(token) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "authentication required", http.StatusUnauthorized)
			}
			return
		}

		if isMutating(r.Method) && !p.csrfValid(w, r, sessionCSRFBinding(token)) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isMutating reports whether a method changes state and therefore needs
// a CSRF token.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// mustRandom returns n cryptographically random bytes, or panics. A
// failure here means the process cannot get randomness, which no panel
// can recover from.
func mustRandom(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("panel: cannot read randomness: %v", err))
	}
	return buf
}

// randomToken returns a fresh URL-safe random token.
func randomToken() string {
	return base64.RawURLEncoding.EncodeToString(mustRandom(32))
}

// clearWriteDeadline removes the per-connection write deadline the DoH
// listener sets (dohWriteTimeout, 10 s) for one request. The event
// stream, a CSV export and a transactional apply all legitimately
// outlive it; without this the listener would cut the response (and,
// for the apply, cancel an operation that is already underway) while
// the work is still running. Clearing the deadline does not block: a
// client that gives up simply sees its own timeout.
func clearWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
}
