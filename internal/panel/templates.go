package panel

import (
	"html/template"
	"net/http"
)

// loginView is the data behind the login page.
type loginView struct {
	CSRF  string
	Error string
}

// indexView is the data behind the authenticated landing page.
type indexView struct {
	Domain    string
	Version   string
	Strategy  string
	Listeners int
	CSRF      string
}

// templates holds the page templates by name. They are plain strings
// for now; later tasks add per-page files under templates/ and parse
// them the same way.
var templates = map[string]*template.Template{
	"login": template.Must(template.New("login").Parse(loginPage)),
	"index": template.Must(template.New("index").Parse(indexPage)),
}

// render writes one page. The content type and nosniff are set before
// the status so a caller's headers cannot be overwritten.
func (p *Panel) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	if err := templates[name].Execute(w, data); err != nil {
		p.logger.Warn("panel: rendering a page", "name", name, "error", err)
	}
}

// loginPage is the sign-in screen: the copper accent and ink palette of
// the mockups, one password field, and the CSRF token bound to the
// pre-session cookie.
const loginPage = `<!doctype html>
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
`

// indexPage is the authenticated shell. Task 7 fills the main area with
// the status screen (gauges, donuts, live feed); the shell, palette and
// navigation are already the ones the mockups specify.
const indexPage = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mdns — панель</title>
<link rel="stylesheet" href="/panel/static/app.css">
<script src="/panel/static/htmx.min.js" defer></script>
<script src="/panel/static/app.js" defer></script>
</head>
<body>
<div class="shell">
  <aside class="rail">
    <div class="brand">mdns<small>{{.Domain}}</small></div>
    <nav class="nav">
      <a class="on" href="/panel/" aria-current="page">Статус</a>
    </nav>
    <form method="post" action="/logout" class="rail-foot">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <button class="btn small" type="submit">Выйти</button>
    </form>
  </aside>
  <main class="main">
    <div class="topline">
      <h2>Статус</h2>
      <div class="state"><span class="dot"></span>работает{{if .Version}} · <b>{{.Version}}</b>{{end}}</div>
    </div>
    <dl class="kv">
      <div><dt>Домен</dt><dd>{{.Domain}}</dd></div>
      <div><dt>Версия</dt><dd>{{.Version}}</dd></div>
      {{if .Strategy}}<div><dt>Стратегия</dt><dd>{{.Strategy}}</dd></div>{{end}}
      {{if .Listeners}}<div><dt>Слушателей</dt><dd>{{.Listeners}}</dd></div>{{end}}
    </dl>
    <p class="note">Панель подключена. Приборы, распределение запросов и живая лента появятся здесь на следующем шаге.</p>
  </main>
</div>
</body>
</html>
`
