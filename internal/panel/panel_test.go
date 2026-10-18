package panel_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/panel"
	"mydns/internal/qlog"
	"mydns/internal/stats"
)

// testPassword is the fixture password the login tests authenticate
// with. The stored value is an argon2id hash of it.
const testPassword = "correct horse battery staple"

// testSessionCookie is the session cookie the panel is expected to set.
const testSessionCookie = "mdns_session"

// fakeController is the slice of the daemon the panel consumes today.
type fakeController struct{ cfg *config.Config }

func (f *fakeController) Config() *config.Config { return f.cfg }

// UpdateConfig is a no-op here: the shell tests never mutate.
func (f *fakeController) UpdateConfig(context.Context, *config.Config) error { return nil }

func (f *fakeController) Status(context.Context) (api.Status, error) {
	return api.Status{Version: "v-test"}, nil
}

func (f *fakeController) Stats() stats.Snapshot { return stats.Snapshot{} }

func (f *fakeController) StatsRange(time.Time, time.Time) stats.Snapshot {
	return stats.Snapshot{}
}

func (f *fakeController) Started() time.Time { return time.Time{} }

func (f *fakeController) Requests(int) []qlog.Entry { return nil }

func (f *fakeController) RequestsQuery(qlog.Query, int, int) ([]qlog.Entry, int) {
	return nil, 0
}

func (f *fakeController) FilterStatus() []filter.ListStatus { return nil }

func (f *fakeController) FilterUpdate(context.Context, string) error { return nil }

// discardLogger drops every log line the panel writes.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestServer mounts a panel on an HTTPS test server. hash is the
// stored password hash; an empty hash builds the disabled panel. The
// returned client keeps cookies and does not follow redirects, so
// tests can assert status codes and Location themselves.
func newTestServer(t *testing.T, enabled bool, hash string) (*httptest.Server, *http.Client) {
	t.Helper()
	return newTestServerOpts(t, panel.Options{Enabled: enabled, PasswordHash: hash})
}

// newTestServerOpts is newTestServer with full control over the panel
// options, for tests that wire their own dependencies (an Auth callback,
// a shared session store).
func newTestServerOpts(t *testing.T, opts panel.Options) (*httptest.Server, *http.Client) {
	t.Helper()

	if opts.Ctrl == nil {
		opts.Ctrl = &fakeController{cfg: &config.Config{Domain: "dns.example.test"}}
	}
	if opts.Version == "" {
		opts.Version = "v-test"
	}
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}

	p := panel.New(opts)

	mux := http.NewServeMux()
	p.Mount(mux)

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	return srv, newClient(t, srv)
}

// newClient builds a cookie-keeping, redirect-refusing client for an
// existing test server, so a test can act as a second browser.
func newClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

// hashPassword returns a valid argon2id PHC hash of pw at the cheapest
// cost auth.Verify accepts (8 KiB, one iteration). The panel only feeds
// the hash to auth.Verify, and the login tests do not need to burn
// 64 MiB per attempt; the exact production format is covered by the
// auth package's own tests.
func hashPassword(t *testing.T, pw string) string {
	t.Helper()

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generating a salt: %v", err)
	}
	key := argon2.IDKey([]byte(pw), salt, 1, 8, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=8,t=1,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// csrfPattern extracts the hidden CSRF field from a rendered form.
var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrfToken returns the CSRF token embedded in body.
func csrfToken(t *testing.T, body string) string {
	t.Helper()

	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf field in body:\n%s", body)
	}
	return m[1]
}

// readBody drains and returns a response body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(data)
}

// do performs a request with the given method and form, returning the
// response with its body already drained.
func do(t *testing.T, client *http.Client, method, rawURL string, form url.Values) (*http.Response, string) {
	t.Helper()

	var (
		resp *http.Response
		err  error
	)
	if form == nil {
		req, rerr := http.NewRequest(method, rawURL, nil)
		if rerr != nil {
			t.Fatalf("NewRequest(%s %s): %v", method, rawURL, rerr)
		}
		resp, err = client.Do(req)
	} else {
		resp, err = client.PostForm(rawURL, form)
	}
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	return resp, readBody(t, resp)
}

// loginForm fetches /login and returns the CSRF token for a POST.
func loginForm(t *testing.T, srv *httptest.Server, client *http.Client) string {
	t.Helper()

	resp, body := do(t, client, http.MethodGet, srv.URL+"/login", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200\n%s", resp.StatusCode, body)
	}
	return csrfToken(t, body)
}

// login submits the login form with pw, pulling a fresh CSRF token.
func login(t *testing.T, srv *httptest.Server, client *http.Client, pw string) *http.Response {
	t.Helper()

	token := loginForm(t, srv, client)
	resp, _ := do(t, client, http.MethodPost, srv.URL+"/login", url.Values{
		"password": {pw},
		"csrf":     {token},
	})
	return resp
}

// sessionCookie returns the session cookie carried by a response, with
// its attributes, so tests can check HttpOnly/Secure/SameSite.
func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == testSessionCookie {
			return c
		}
	}
	return nil
}

// TestDisabledPanelIs404 checks that a disabled panel is invisible:
// every route answers 404, never 403 or a redirect, so the running
// daemon does not reveal that a panel exists.
func TestDisabledPanelIs404(t *testing.T) {
	srv, client := newTestServer(t, false, "")

	getPaths := []string{
		"/", "/login", "/panel", "/panel/", "/panel/events",
		"/panel/static", "/panel/static/app.css",
		"/panel/upstreams", "/panel/filters", "/panel/settings",
	}
	for _, path := range getPaths {
		resp, body := do(t, client, http.MethodGet, srv.URL+path, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (disabled panel must not reveal itself)\n%s",
				path, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Location"); got != "" {
			t.Errorf("GET %s on a disabled panel set Location = %q, want none", path, got)
		}
	}

	posts := []string{"/login", "/logout"}
	for _, path := range posts {
		resp, body := do(t, client, http.MethodPost, srv.URL+path, url.Values{"password": {"x"}})
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404 (disabled panel must not reveal itself)\n%s",
				path, resp.StatusCode, body)
		}
	}
}

// TestPanelNoSlashPaths pins the slash-less spellings: an enabled panel
// redirects /panel to /panel/ on purpose, and /panel/static has no
// index, so its slash-less form is a plain 404 (never a directory
// listing).
func TestPanelNoSlashPaths(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	resp, body := do(t, client, http.MethodGet, srv.URL+"/panel", nil)
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("GET /panel = %d, want 308\n%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/panel/" {
		t.Errorf("GET /panel Location = %q, want /panel/", got)
	}

	resp, body = do(t, client, http.MethodGet, srv.URL+"/panel/static", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /panel/static = %d, want 404\n%s", resp.StatusCode, body)
	}
}

// TestLoginFlow covers the whole sign-in path: a wrong password is
// refused (and throttled after the built-in limit), a right one mints
// a session cookie and opens /panel/.
func TestLoginFlow(t *testing.T) {
	hash := hashPassword(t, testPassword)

	t.Run("wrong password is refused and throttled", func(t *testing.T) {
		// The panel builds its own throttle here (Options.Throttle is
		// nil), so this also proves it passes positive constants and
		// does not silently disable abuse control.
		srv, client := newTestServer(t, true, hash)

		for i := 1; i <= panel.LoginFailLimit; i++ {
			resp := login(t, srv, client, "not the password")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("wrong password attempt %d = %d, want 401", i, resp.StatusCode)
			}
		}

		resp := login(t, srv, client, "not the password")
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("attempt after %d failures = %d, want 429 (throttled)",
				panel.LoginFailLimit, resp.StatusCode)
		}
	})

	t.Run("right password signs in", func(t *testing.T) {
		srv, client := newTestServer(t, true, hash)

		resp := login(t, srv, client, testPassword)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("correct password = %d, want 303", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != "/panel/" {
			t.Errorf("Location = %q, want /panel/", got)
		}

		cookie := sessionCookie(resp)
		if cookie == nil {
			t.Fatal("no session cookie was set")
		}
		if !cookie.HttpOnly {
			t.Error("session cookie is not HttpOnly")
		}
		if !cookie.Secure {
			t.Error("session cookie is not Secure")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("session cookie SameSite = %v, want Lax", cookie.SameSite)
		}

		resp, body := do(t, client, http.MethodGet, srv.URL+"/panel/", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /panel/ with a session = %d, want 200\n%s", resp.StatusCode, body)
		}
	})
}

// TestSessionRequired checks that every page behind the login redirects
// an anonymous visitor to /login, and that a mutating request without a
// session is refused outright.
func TestSessionRequired(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	pages := []string{"/panel/", "/panel/events"}
	for _, path := range pages {
		resp, body := do(t, client, http.MethodGet, srv.URL+path, nil)
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s without a session = %d, want 303\n%s", path, resp.StatusCode, body)
			continue
		}
		if got := resp.Header.Get("Location"); got != "/login" {
			t.Errorf("GET %s Location = %q, want /login", path, got)
		}
	}

	resp, body := do(t, client, http.MethodPost, srv.URL+"/logout", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /logout without a session = %d, want 401\n%s", resp.StatusCode, body)
	}
}

// TestCSRFRejected checks that a session-bound form is only accepted
// with the matching token: a foreign or absent token is a 403 and does
// not damage the session.
func TestCSRFRejected(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	if resp := login(t, srv, client, testPassword); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", resp.StatusCode)
	}

	cases := []struct {
		name string
		form url.Values
	}{
		{"foreign token", url.Values{"csrf": {"deadbeef"}}},
		{"absent token", url.Values{}},
	}
	for _, tc := range cases {
		resp, body := do(t, client, http.MethodPost, srv.URL+"/logout", tc.form)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: POST /logout = %d, want 403\n%s", tc.name, resp.StatusCode, body)
		}
	}

	// The rejected requests must not have touched the session.
	resp, body := do(t, client, http.MethodGet, srv.URL+"/panel/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("session after a CSRF rejection = %d, want still 200\n%s", resp.StatusCode, body)
	}
}

// TestLogoutRevokes checks that logging out kills the session and
// clears the cookie.
func TestLogoutRevokes(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	if resp := login(t, srv, client, testPassword); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", resp.StatusCode)
	}
	if resp, body := do(t, client, http.MethodGet, srv.URL+"/panel/", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/ after login = %d, want 200\n%s", resp.StatusCode, body)
	}

	token := loginFormFromPanel(t, srv, client)
	resp, body := do(t, client, http.MethodPost, srv.URL+"/logout", url.Values{"csrf": {token}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /logout = %d, want 303\n%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/login" {
		t.Errorf("logout Location = %q, want /login", got)
	}

	resp, body = do(t, client, http.MethodGet, srv.URL+"/panel/", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET /panel/ after logout = %d, want 303 (session revoked)\n%s", resp.StatusCode, body)
	}
}

// loginFormFromPanel pulls the CSRF token out of the authenticated
// index page (the logout form's hidden field).
func loginFormFromPanel(t *testing.T, srv *httptest.Server, client *http.Client) string {
	t.Helper()

	resp, body := do(t, client, http.MethodGet, srv.URL+"/panel/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/ = %d, want 200\n%s", resp.StatusCode, body)
	}
	return csrfToken(t, body)
}

// TestStaticServedWithoutAuth checks that the stylesheet and the app
// script are readable before signing in, so the login page itself can
// load them.
func TestStaticServedWithoutAuth(t *testing.T) {
	srv, _ := newTestServer(t, true, hashPassword(t, testPassword))
	client := srv.Client() // deliberately no cookie jar

	cases := []struct {
		path    string
		ctype   string
		content string
	}{
		{"/panel/static/app.css", "text/css", "--copper"},
		{"/panel/static/app.js", "javascript", "EventSource"},
	}
	for _, tc := range cases {
		resp, body := do(t, client, http.MethodGet, srv.URL+tc.path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s without a session = %d, want 200", tc.path, resp.StatusCode)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, tc.ctype) {
			t.Errorf("GET %s Content-Type = %q, want it to contain %q", tc.path, ct, tc.ctype)
		}
		if tc.content != "" && !strings.Contains(body, tc.content) {
			t.Errorf("GET %s body does not contain %q", tc.path, tc.content)
		}
	}
}

// checkPageHeaders asserts the anti-framing, CSP and cache headers the
// render path must set on every HTML page.
func checkPageHeaders(t *testing.T, what string, resp *http.Response) {
	t.Helper()

	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("%s: X-Frame-Options = %q, want DENY", what, got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'; default-src 'self'" {
		t.Errorf("%s: Content-Security-Policy = %q, want frame-ancestors 'none'; default-src 'self'", what, got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s: Cache-Control = %q, want no-store (the page carries a CSRF token)", what, got)
	}
}

// TestPageSecurityHeaders checks that both the login page and the
// authenticated page refuse framing and caching: a framed same-origin
// page would keep a valid CSRF token, and a cached page would keep the
// token around.
func TestPageSecurityHeaders(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	loginResp, _ := do(t, client, http.MethodGet, srv.URL+"/login", nil)
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", loginResp.StatusCode)
	}
	checkPageHeaders(t, "GET /login", loginResp)

	if resp := login(t, srv, client, testPassword); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", resp.StatusCode)
	}
	panelResp, _ := do(t, client, http.MethodGet, srv.URL+"/panel/", nil)
	if panelResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/ = %d, want 200", panelResp.StatusCode)
	}
	checkPageHeaders(t, "GET /panel/", panelResp)
}

// TestEventsStream checks the placeholder event stream: with a session
// it answers 200 text/event-stream and sends an immediate ping, so the
// status page can tell "connected" from "waiting for an event".
func TestEventsStream(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	if resp := login(t, srv, client, testPassword); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", resp.StatusCode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/panel/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /panel/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /panel/events = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	if err != nil {
		t.Fatalf("reading the stream: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "event: ping") {
		t.Errorf("first chunk = %q, want an immediate ping", buf[:n])
	}
}

// TestAuthCallbackIsLive checks R6: the panel reads the enabled flag and
// the password hash on every request, so rotating the password or
// switching the panel off takes effect without a restart.
func TestAuthCallbackIsLive(t *testing.T) {
	var mu sync.Mutex
	enabled := true
	hash := hashPassword(t, "first password")

	srv, client := newTestServerOpts(t, panel.Options{
		Auth: func() (bool, string) {
			mu.Lock()
			defer mu.Unlock()
			return enabled, hash
		},
	})

	if resp := login(t, srv, client, "first password"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login with the first password = %d, want 303", resp.StatusCode)
	}

	// Rotate the hash the panel reads; no restart, no new panel.
	mu.Lock()
	hash = hashPassword(t, "second password")
	mu.Unlock()

	other := newClient(t, srv)
	if resp := login(t, srv, other, "first password"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old password after rotation = %d, want 401", resp.StatusCode)
	}
	if resp := login(t, srv, other, "second password"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("the new password after rotation = %d, want 303", resp.StatusCode)
	}

	// Switching the panel off must make every route disappear at once.
	mu.Lock()
	enabled = false
	mu.Unlock()

	resp, _ := do(t, other, http.MethodGet, srv.URL+"/login", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /login after disabling = %d, want 404", resp.StatusCode)
	}
}

// TestRootRedirectsToPanel checks the convenience root: it points at
// the panel, which then sends an anonymous visitor on to /login.
func TestRootRedirectsToPanel(t *testing.T) {
	srv, client := newTestServer(t, true, hashPassword(t, testPassword))

	resp, body := do(t, client, http.MethodGet, srv.URL+"/", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET / = %d, want 302\n%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/panel/" {
		t.Errorf("GET / Location = %q, want /panel/", got)
	}
}
