package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"time"

	"mydns/internal/auth"
)

const (
	// loginCookie carries the pre-session value a login form's CSRF
	// token is bound to. It exists only between GET and POST /login.
	loginCookie = "mdns_login"

	// csrfField is the hidden form field every mutating form carries;
	// csrfHeader is the alternative for scripted clients.
	csrfField  = "csrf"
	csrfHeader = "X-CSRF-Token"

	// maxFormBytes bounds a submitted form so a POST cannot make the
	// panel allocate without limit before authenticating.
	maxFormBytes = 64 << 10
)

// sessionToken returns the session token from the request cookie, or ""
// when there is none. The token never travels in a URL.
func (p *Panel) sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// sessionCSRFBinding namespaces a session token inside the CSRF input,
// so a token minted for one purpose can never validate for another.
func sessionCSRFBinding(token string) string { return "session:" + token }

// loginCSRFBinding namespaces the pre-session cookie value the same way.
func loginCSRFBinding(cookie string) string { return "login:" + cookie }

// csrfToken derives the CSRF token bound to a value. It is an HMAC
// under a per-process secret, so a token copied from another session
// (or guessed) never validates; the "login:" and "session:" prefixes
// keep the two families apart.
func (p *Panel) csrfToken(binding string) string {
	mac := hmac.New(sha256.New, p.csrfKey)
	mac.Write([]byte(binding))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// csrfValid reports whether the request carries the CSRF token for
// binding. The comparison is constant time, a missing token fails, and
// nothing about the session is changed here — a failure is a 403 and
// the session stays alive.
func (p *Panel) csrfValid(w http.ResponseWriter, r *http.Request, binding string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		return false
	}
	got := r.PostFormValue(csrfField)
	if got == "" {
		got = r.Header.Get(csrfHeader)
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(p.csrfToken(binding))) == 1
}

// loginBinding returns the value the login CSRF token is bound to,
// minting and setting a fresh cookie when the client has none. It is a
// double-submit scheme with the HMAC above, so a page that merely reads
// the field cannot forge a matching cookie.
func (p *Panel) loginBinding(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(loginCookie); err == nil && c.Value != "" {
		return c.Value
	}
	value := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return value
}

// setSessionCookie sets the login cookie, scoped so it never reaches a
// script (HttpOnly), a plaintext connection (Secure) or a cross-site
// request (SameSite=Lax).
func (p *Panel) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL / time.Second),
	})
}

// clearSessionCookie expires the session cookie.
func (p *Panel) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// clientIP is the address the throttle counts against.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleLoginForm renders the login page, sending an already signed-in
// visitor straight to the panel.
func (p *Panel) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	enabled, _ := p.auth()
	if !enabled {
		p.handleNotFound(w, r)
		return
	}
	if token := p.sessionToken(r); token != "" && p.sessions.Valid(token) {
		http.Redirect(w, r, "/panel/", http.StatusSeeOther)
		return
	}
	binding := p.loginBinding(w, r)
	p.render(w, http.StatusOK, "login", loginView{CSRF: p.csrfToken(loginCSRFBinding(binding))})
}

// handleLoginSubmit verifies the password behind the login throttle and
// mints a session on success. The failure answer is the same for an
// unknown user and a wrong password — there is only one account, and
// the message never says which part was wrong.
func (p *Panel) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	enabled, hash := p.auth()
	if !enabled {
		p.handleNotFound(w, r)
		return
	}

	binding := ""
	if c, err := r.Cookie(loginCookie); err == nil {
		binding = c.Value
	}
	if !p.csrfValid(w, r, loginCSRFBinding(binding)) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	ip := clientIP(r)
	if !p.throttle.Allow(ip) {
		p.renderLoginError(w, r, http.StatusTooManyRequests,
			"Слишком много неудачных попыток входа. Попробуйте позже.")
		return
	}

	// Config validation only prefix-checks the stored hash for
	// "$argon2id$"; it does not parse the PHC parameters. An
	// unparseable hash therefore reaches Verify, which returns false
	// without running argon2 — the login path treats it exactly like a
	// wrong password.
	if !auth.Verify(hash, r.PostFormValue("password")) {
		p.throttle.Fail(ip)
		p.logger.Warn("panel: failed login", "ip", ip)
		p.renderLoginError(w, r, http.StatusUnauthorized, "Неверный пароль.")
		return
	}

	p.throttle.Success(ip)
	token, err := p.sessions.Create()
	if err != nil {
		p.logger.Error("panel: creating a session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.logger.Info("panel: login", "ip", ip)
	p.setSessionCookie(w, token)
	http.Redirect(w, r, "/panel/", http.StatusSeeOther)
}

// renderLoginError re-renders the login page with a message. It keeps
// the login cookie so the resent form still carries a valid token.
func (p *Panel) renderLoginError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	binding := p.loginBinding(w, r)
	p.render(w, status, "login", loginView{
		CSRF:  p.csrfToken(loginCSRFBinding(binding)),
		Error: msg,
	})
}

// handleLogout revokes the session and clears the cookie. It runs
// behind requireSession, so it always carries a valid CSRF token.
func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := p.sessionToken(r); token != "" {
		p.sessions.Revoke(token)
		p.logger.Info("panel: logout", "ip", clientIP(r))
	}
	p.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
