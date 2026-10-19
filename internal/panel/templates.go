package panel

import (
	"embed"
	"html/template"
	"net/http"
)

// loginView is the data behind the login page.
type loginView struct {
	CSRF  string
	Error string
}

// templateFS holds the page templates. They are embedded so a release
// is one binary, like the static assets.
//
//go:embed templates/*.html
var templateFS embed.FS

// templates holds the page templates by name. A page file defines one
// root template (its page name) plus any {{template}} fragments it
// renders, so the same set serves both a full page and an SSE frame
// (see layout.html's feed_row). The shared shell (the rail) and the
// feed row live in layout.html, which every page parses.
var templates = map[string]*template.Template{
	"login":       template.Must(template.New("login").Parse(loginPage)),
	"status":      pageTemplates("status", "templates/status.html"),
	"live":        pageTemplates("live", "templates/live.html"),
	"history":     pageTemplates("history", "templates/history.html"),
	"upstreams":   pageTemplates("upstreams", "templates/manage.html"),
	"filters":     pageTemplates("filters", "templates/manage.html"),
	"settings":    pageTemplates("settings", "templates/manage.html"),
	"cert":        pageTemplates("cert", "templates/manage.html"),
	"maintenance": pageTemplates("maintenance", "templates/manage.html"),
}

// pageTemplates parses one page file together with the shared fragments.
func pageTemplates(name string, files ...string) *template.Template {
	return template.Must(template.New(name).ParseFS(templateFS,
		append([]string{"templates/layout.html"}, files...)...))
}

// render writes one page. Every header is set before the status so a
// caller's headers cannot be overwritten.
//
// The framing and CSP headers matter for the whole render path: a
// clickjacked page keeps its same-origin CSRF token, so framing would
// defeat CSRF. default-src 'self' also means pages may not carry
// inline <style>/style="…" or inline scripts — styles go in
// /panel/static/app.css and behaviour in /panel/static/*.js.
func (p *Panel) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; default-src 'self'")
	// The pages carry a CSRF token in the HTML; no browser or proxy may
	// keep a copy of them.
	w.Header().Set("Cache-Control", "no-store")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	if err := templates[name].ExecuteTemplate(w, name, data); err != nil {
		p.logger.Warn("panel: rendering a page", "name", name, "error", err)
	}
}

// loginPage is the sign-in screen: the copper accent and ink palette of
// the mockups, one password field, and the CSRF token bound to the
// pre-session cookie.
const loginPage = `{{define "login"}}<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mdns — вход в панель</title>
<link rel="stylesheet" href="/panel/static/app.css">
</head>
<body class="login-body">
<main class="login-card">
  <div class="brand-lg">mdns<small>панель управления</small></div>
  {{if .Error}}<p class="alert" role="alert">{{.Error}}</p>{{end}}
  <form method="post" action="/login" class="login-form">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label class="field">
      <span>Пароль</span>
      <input type="password" name="password" autocomplete="current-password" autofocus required>
    </label>
    <button class="btn primary" type="submit">Войти</button>
  </form>
  <p class="hint">Логин — admin. Пароль хранится на сервере как argon2id-хэш.</p>
</main>
</body>
</html>
{{end}}`
