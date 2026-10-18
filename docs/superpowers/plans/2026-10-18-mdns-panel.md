# Веб-панель, статистика и полировка — план этапа 5

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** веб-панель управления по утверждённым макетам (`.superpowers/mockups/web-panel.html` + вкладка Review) поверх той же TLS-точки, что DoH: пароль из визарда, сессии/CSRF/троттлинг, живая лента на 30, круговые диаграммы «куда идут запросы» (наведение — подпись, клик — история с фильтром), история запросов (не live, 100/стр, поиск, фильтры), мобильная вёрстка; API статистики и пагинированной истории в демоне; экран TUI «Диагностика»; повторяемый перф-стенд; e2e с Playwright; релиз v0.2.0.

**Architecture:** новые пакеты `internal/auth` (argon2id, сессии, троттлинг) и `internal/panel` (шаблоны+htmx+SSE, монтируется в mux DoH-листенера; всё за сессией); `internal/stats` (кумулятивные счётчики по исходам/протоколам/upstream/клиентам, хук из core) и расширение `qlog` запросами с фильтрами и пагинацией для API; `api` получает `/stats` и расширенный `/requests`; перф-стенд переносится из скретча в `e2e/perf/` (фейк-upstream + генератор нагрузки + сценарий).

**Tech Stack:** Go 1.26, `html/template` + htmx (встраивается в бинарник, никаких CDN), SSE, `golang.org/x/crypto/argon2`, Playwright (Python, для e2e), pprof не нужен.

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md` (§12 п.7, §13, §14, §15, §16); макеты — `panel.html` v2, одобрены пользователем (лента 30, 4 диаграммы, история с поиском и пагинацией).

## Global Constraints

- Панель живёт на той же TLS-точке, что DoH (`https://<домен>/`), `/dns-query` не затрагивается; до появления сертификата панель недоступна, plain DNS работает (уже так).
- Всё управление панели — только за аутентификацией: логин `admin` + пароль (argon2id-хэш в конфиге, файл 0600); сессионная cookie HttpOnly+Secure+SameSite=Lax, CSRF-токен на всех мутациях, троттлинг попыток входа; секреты не логируются.
- Никаких внешних ассетов: шаблоны, CSS, минимальный JS и htmx встраиваются через `go:embed`; панель работает без интернета.
- Русский интерфейс; английский код и комментарии; фокус-стили и reduced-motion; мобильная вёрстка до 390 px.
- Счётчики статистики — кумулятивные с момента старта демона (десятки миллионов запросов не должны течь по памяти); история — кольцо в памяти (`log.memory_entries`, по умолчанию 10 000), «с начала до конца» = от самой старой записи кольца.
- Каждый коммит: `go test ./... -race -count=1`, `go vet ./...`, `gofmt -l .` — чисто; CI зелёный.

## Review Focus

1. Аутентификация не обходится: ни один маршрут панели/API на HTTPS не отдаёт данные без сессии; CSRF-негатив реально отклоняется; троттлинг ограничивает перебор; при `panel.enabled=false` наружу не торчит ничего. (Tasks 3, 5, 12)
2. Панель под нагрузкой: при 50–65 тыс. qps на демоне живая лента не вешает браузер и не тормозит демон (bus дропает для медленных), SSE-соединение панели восстанавливается после рестарта демона. (Tasks 4, 13)
3. История консистентна при перезаписи кольца: пагинация/поиск/фильтры не паникуют и не теряют строки при обёртке ring-буфера между страницами. (Tasks 2, 7)
4. Перф-тест повторяем и не бьёт по публичным резолверам: локальный фейк-upstream, контролируемый микс, фиксированные пороги отчёта. (Task 13)
5. Пароль панели: хэш только argon2id; путь «визард → конфиг → вход» работает и в non-interactive; смена пароля из панели не требует рестарта. (Tasks 1, 3, 10)

---

### Task 1: Конфиг — секция `panel` и пароль

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces:
  ```go
  type PanelConfig struct {
      Enabled      bool   `json:"enabled"`
      PasswordHash string `json:"password_hash,omitempty"` // argon2id, формат PHC
  }
  // в Config: Panel PanelConfig `json:"panel,omitempty"`
  ```
- Валидация: `enabled=true` требует непустой `PasswordHash`, начинающийся с `$argon2id$` (грубый префикс-чек; точную проверку делает auth.Verify при входе).
- `config.Default()`: `Panel{Enabled:false}`.

- [ ] **Step 1: Падающие тесты**: `TestPanelValidation` (enabled без хэша → ошибка; с хэшем → ок; выключенная с мусором в поле → игнор), `TestPanelRoundTrip` (JSON сохраняется/читается).
- [ ] **Step 2: RED** (`go test ./internal/config/ -run TestPanel -count=1`).
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS** + существующие тесты не сломаны.
- [ ] **Step 5: Commit** `feat: panel section in the config`.

---

### Task 2: qlog — запрос с фильтрами и пагинацией

**Files:**
- Modify: `internal/qlog/qlog.go`, `internal/qlog/qlog_test.go`

**Interfaces:**
- Produces:
  ```go
  // Query фильтрует кольцо (новые записи первыми) и возвращает страницу.
  type Query struct {
      Search   string // подстрока (без учёта регистра) по qname/upstream/client
      Outcome  string // "" | cached | blocked | upstream | error
      Proto    string // "" | udp | tcp | doh | dot | doq
      Client   string // точное совпадение IP или ""
      Upstream string // точное совпадение ID или ""
  }
  func (l *Log) Query(q Query, offset, limit int) (entries []Entry, total int)
  func outcome(e Entry) string // cached | blocked | upstream | error
  ```
- Получить снимок кольца под mutex, фильтровать копию; `total` — число совпавших; порядок — новейшие первыми; `limit` зажимается в [1,500].

- [ ] **Step 1: Падающие тесты**: `TestQueryFilters` (outcome cached/blocked/upstream/error, proto, client, upstream, поиск по подстроке домена без регистра), `TestQueryPagination` (offset/limit, total, порядок новейшие первыми; offset за концом → пусто), `TestQueryUnderWraparound` (кольцо меньше записей: пишем 3×cap, проверяем total и отсутствие дублей на границах страниц).
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS**; существующие тесты журнала.
- [ ] **Step 5: Commit** `feat: paginated query history in the log`.

---

### Task 3: auth — argon2id, сессии, троттлинг

**Files:**
- Create: `internal/auth/auth.go`, `internal/auth/auth_test.go` (+ go.mod: `golang.org/x/crypto` уже есть)

**Interfaces:**
- Produces:
  ```go
  func HashPassword(pw string) (string, error)          // PHC: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
  func Verify(hash, pw string) bool
  type Sessions struct { ... }                          // в памяти
  func NewSessions(ttl time.Duration) *Sessions
  func (s *Sessions) Create() (token string, err error)
  func (s *Sessions) Valid(token string) bool
  func (s *Sessions) Revoke(token string)
  func (s *Sessions) Purge()                            // удаление истёкших (вызывается лениво)
  type Throttle struct { ... }                          // по IP
  func NewThrottle(limit int, window time.Duration) *Throttle
  func (t *Throttle) Allow(ip string) bool              // false при превышении
  func (t *Throttle) Fail(ip string)                    // регистрирует неудачу
  func (t *Throttle) Success(ip string)                 // сброс
  ```
- `HashPassword`: argon2id m=64MiB t=3 p=2, 16-байтная соль, 32-байтный ключ; `Verify` — constant-time сравнение, ошибка формата → false.
- Тестовые параметры: экспортируемое поле/функция `SetParams(mem, iters, par)` (или неэкспортируемая переменная) — чтобы тесты не жгли 64 MiB ×N ранений; в отчёте указать.

- [ ] **Step 1: Падающие тесты**: `TestHashVerify` (верный/неверный пароль, мусорный хэш), `TestSessions` (create/valid/revoke, истечение по фейковым часам), `TestThrottle` (limit неудач → блок, success сбрасывает, окно истекает).
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS** (`-race`).
- [ ] **Step 5: Commit** `feat: argon2id passwords, sessions and login throttle`.

---

### Task 4: stats — кумулятивные счётчики

**Files:**
- Create: `internal/stats/stats.go`, `internal/stats/stats_test.go`
- Modify: `internal/core/core.go` (хук после обработки запроса), `internal/core/core_test.go`

**Interfaces:**
- Produces:
  ```go
  type Collector struct { ... }
  func NewCollector() *Collector
  func (c *Collector) Observe(e qlog.Entry)
  type Snapshot struct {
      Total    uint64            `json:"total"`
      Outcomes map[string]uint64 `json:"outcomes"` // cached|blocked|upstream|error
      Protos   map[string]uint64 `json:"protos"`
      Upstreams map[string]uint64 `json:"upstreams"` // id → ответил
      Clients  []ClientCount     `json:"clients"`     // топ-20 + "остальные"
  }
  type ClientCount struct { IP string `json:"ip"`; Count uint64 `json:"count"` }
  func (c *Collector) Snapshot() Snapshot
  ```
- Классификация исходов — как в `qlog.outcome`: `blocked` (Blocked), иначе `cached` (CacheHit), иначе `error` (Rcode != NOERROR и Upstream пуст?), иначе `upstream` (есть Upstream). Зафиксировать правило в комментарии и тесте.
- Core: дёргает `Observe` на том же пути, где отдаёт запись в qlog (интерфейс `interface{ Observe(qlog.Entry) }`, nil допустим).
- Клиенты: map[ip]count + overflow «остальные» (сумма за пределами топ-20), не более 4096 уникальных IP в памяти (дальше — в «остальные», защита от роста).

- [ ] **Step 1: Падающие тесты**: `TestCollectorOutcomes` (по миксу), `TestCollectorTopClients` (25 IP → топ-20 + «остальные» = сумма), `TestCollectorCap` (5000 IP не растят map >4096), `TestCoreObserves` (интеграция: прогон через core наполняет коллектор).
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать + wire в app (collector в runtime, живущий дольше генераций — как qlog).**
- [ ] **Step 4: PASS** весь `./internal/...`.
- [ ] **Step 5: Commit** `feat: cumulative query statistics`.

---

### Task 5: API — `/stats` и расширенный `/requests`

**Files:**
- Modify: `internal/api/api.go`, `internal/api/read.go`, `internal/api/read_test.go`
- Modify: `internal/app/control.go` (реализация Controller), `internal/tui/client.go` (интерфейс Client, при необходимости)

**Interfaces:**
- Produces:
  - `GET /api/v1/stats` → `stats.Snapshot` (+ поле `since` — время старта).
  - `GET /api/v1/requests?page=1&per=100&q=&outcome=&proto=&client=&upstream=` → `{"entries":[...],"total":N,"page":P,"pages":Pages,"per":Per}`; `per` зажимается [1,500], `page` ≥1. Старый `?n=N` сохраняется (эквивалент последних N, без пагинации) для совместимости с TUI.
  - Controller: `Stats() stats.Snapshot`, `RequestsQuery(q qlog.Query, page, per int) (entries []qlog.Entry, total int)`.

- [ ] **Step 1: Падающие тесты** (`read_test.go`): `/stats` отдаёт снимок; `/requests` пагинация+фильтры+поиск; `?n=` по-прежнему работает; `per=100000` → 500.
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать + `api_test.go` в app (реальные запросы → статистика видна через сокет).**
- [ ] **Step 4: PASS** `./internal/api ./internal/app ./internal/tui`.
- [ ] **Step 5: Commit** `feat: stats and paginated history API`.

---

### Task 6: panel — каркас, аутентификация, вход

**Files:**
- Create: `internal/panel/panel.go`, `internal/panel/auth.go`, `internal/panel/templates.go`, `internal/panel/panel_test.go`, `internal/panel/assets.go` (go:embed css/htmx)
- Create: `internal/panel/static/app.css`, `internal/panel/static/app.js`, `internal/panel/static/htmx.min.js` (вендорим htmx 2.x ~14 КБ, MIT; записать версию и лицензию в комментарии файла)
- Modify: `internal/dnsserver/doh.go` (панель в mux DoH-листенера), `internal/app/app.go` (создание панели, передача controller-интерфейса)

**Interfaces:**
- Produces:
  ```go
  type Options struct {
      Enabled bool
      PasswordHash string
      Sessions *auth.Sessions
      Throttle *auth.Throttle
      Ctrl Controller // тот же интерфейс, что у api.Server (Status/Stats/RequestsQuery/UpdateConfig/...)
      Version string
      Logger *slog.Logger
  }
  func New(opts Options) *Panel
  func (p *Panel) Mount(mux *http.ServeMux) // "/", "/login", "/logout", "/panel/", "/panel/api/", "/panel/events"
  ```
- Маршруты: `GET /` → редирект на `/panel/` (или логин); `GET /login` + `POST /login` (троттлинг, сессия, redirect); `POST /logout`; всё под `/panel/*` — только с валидной сессией (middleware), при `!Enabled` — 404 на всё; CSRF: скрытый токен в формах (сессия-привязанный), проверка на POST/PUT/DELETE; `/panel/events` — SSE (токен в cookie, не в URL).
- Ответ «неверный пароль» — единый, без утечек; время ответа при неверном пароле ≥ времени argon2id Verify.
- e2e-обвязка для тестов: `httptest` + `http.Client` с cookiejar.

- [ ] **Step 1: Падающие тесты**: `TestDisabledPanelIs404`; `TestLoginFlow` (неверный пароль → 401 + троттлинг после N; верный → cookie → `/panel/` 200); `TestSessionRequired` (все `/panel/*` без сессии → redirect/401); `TestCSRFRejected` (POST с чужим токеном → 403); `TestLogoutRevokes`.
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать; `doh.go` монтирует панель (mux общий с /dns-query); app передаёт controller (уже есть) и Version.**
- [ ] **Step 4: PASS**; `go test ./internal/panel ./internal/dnsserver ./internal/app -race`; ручная проверка в tmux? Позже (Task 8).
- [ ] **Step 5: Commit** `feat: panel skeleton with session auth`.

---

### Task 7: panel — экран «Статус» (приборы, 4 диаграммы, лента 30, ссылки, сертификат)

**Files:**
- Create: `internal/panel/status.go`, `internal/panel/status_test.go`, `internal/panel/static/app.css` (дополнение), `internal/panel/templates/status.html`

**Interfaces:**
- Страница `/panel/` = «Статус» по макету: gauges (всего/кеш/блок/лучший upstream), 4 SVG-доната из `Stats()` (Ответы/Протоколы/Upstream'ы/Клиенты; серверный рендер сегментов — та же математика `dasharray/offset`, что в макете, с исправленными offset = start%), лента последних 30 (SSE `requests`, буфер, пауза/продолжить/очистить — htmx), ссылки устройств, сертификат.
- Донаты: каждый сегмент — `<a href="/panel/history?outcome=...">` для клика; тултип — CSS `:hover` c `<title>`/JS-подписью (без внешних зависимостей); сегменты фокусируются с клавиатуры (aria-label).
- SSE-эндпоинт `/panel/events`: отдаёт те же события шины (`api.Event`), фильтруя `requests` до буфера 30 на сервере (шаблонная вставка строк через htmx `sse` extension? — вендорим htmx sse-расширение в тот же файл; версии зафиксировать).

- [ ] **Step 1: Падающие тесты**: `TestStatusRenders` (все секции присутствуют; донаты — корректные `stroke-dasharray/offset` для набора 74/19/6.7/0.3 и клики-ссылки), `TestStatusFeedBuffer` (SSE-буфер ограничен 30 и очищается), `TestDonutMath` (чистая функция `segments([]share) → [(offset, dash)]`, сумма 100±0.1).
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS**; визуальная проверка: Playwright-скриншот против макета (desktop 1280 и phone 390) — сохранить в отчёт.
- [ ] **Step 5: Commit** `feat: panel status page with live feed and charts`.

---

### Task 8: panel — «История запросов» (поиск, фильтры, пагинация 100)

**Files:**
- Create: `internal/panel/history.go`, `internal/panel/history_test.go`, `internal/panel/templates/history.html`
- Modify: `internal/panel/status.go` (ссылки «полная история»)

**Interfaces:**
- `/panel/history?q=&outcome=&proto=&client=&upstream=&page=` — таблица как лента (время, протокол, домен, тип, результат, источник, мс), 100/стр, `total/pages`, ссылки «назад/вперёд» (htmx-подгрузка или полные переходы — выбрать полные ссылки: проще и надёжнее), чипы активных фильтров, сброс; кнопка «экспорт CSV» (`/panel/history.csv?...` — поток, RFC4180, BOM для Excel).
- Клик по донату ведёт сюда с соответствующим `outcome`/`proto`/`upstream`/`client`.

- [ ] **Step 1: Падающие тесты**: `TestHistoryPage` (фильтр blocked: строки только заблокированные, total=кол-ву в журнале), `TestHistorySearch` (подстрока, регистронезависимо), `TestHistoryPagination` (страницы не пересекаются, порядок новейшие первыми), `TestHistoryCSV` (заголовки+строки; экранирование запятой/кавычек).
- [ ] **Step 2: RED.** — но сначала: **добавить в qlog тестовые записи через фейковый Controller** (в panel-тестах controller-мок).
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS** + визуальная проверка страницы (скриншот в отчёт).
- [ ] **Step 5: Commit** `feat: panel query history with search and filters`.

---

### Task 9: panel — «Upstream'ы», «Фильтры», «Настройки», «Сертификат», «Обслуживание»

**Files:**
- Create: `internal/panel/manage.go`, `internal/panel/manage_test.go`, `internal/panel/templates/manage.html` (+ частичные шаблоны)
- Modify: `internal/panel/panel.go` (маршруты)

**Interfaces:**
- `/panel/upstreams`: таблица (состояние, задержка, «ответил %», ошибки; вкл/выкл — htmx POST → `UpdateConfig` мягко; приоритет для failover — число+кнопки).
- `/panel/filters`: списки (обновить один/все — существующий API `FilterUpdate`), режим блокировки (цикл zero→nxdomain→refused через `UpdateConfig`), свои правила (добавить/удалить allow/block), топ заблокированного (из Stats/логов).
- `/panel/settings`: ключевые поля (домен, порты/протоколы, стратегия, кеш, лимиты, панель-пароль) — форма → полный конфиг → `UpdateConfig` (мягкое/структурное применение уже реализовано); смена пароля панели отдельной формой (HashPassword → UpdateConfig).
- `/panel/cert`: статус сертификата (мода, выдача/ошибка, продление), экспорт текущего листа.
- `/panel/maintenance`: скачать конфиг (JSON, секреты маскируются? — сохранить как есть, файл 0600 у владельца), перезапуск listeners (кнопка «применить конфиг заново» — через UpdateConfig текущим), версия/аптайм.
- Все мутации: CSRF + полный конфиг (транзакционный UpdateConfig с откатом уже есть).

- [ ] **Step 1: Падающие тесты** (мок-controller): вкл/выкл upstream шлёт полный конфиг с изменённым флагом; смена режима фильтра; добавление правила; смена пароля меняет `panel.password_hash` и вход работает со старым паролем до рестарта? — нет: сессии в памяти; после смены хэша старые сессии остаются валидными (ок, задокументировать), новый вход — только новым паролем (тест).
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS** + визуальные скриншоты всех страниц в отчёт.
- [ ] **Step 5: Commit** `feat: panel management pages`.

---

### Task 10: Визард и установщик — пароль панели

**Files:**
- Modify: `internal/tui/wizard.go` (новый шаг «Панель» между фильтрами и сводкой), `internal/tui/wizard_test.go`
- Modify: `internal/installer/install.go`, `internal/installer/config_build.go`, `internal/installer/install_test.go`, `cmd/mdns/main.go` (`--password`, `--panel`/`--no-panel`)

**Interfaces:**
- Шаг визарда: «Включить веб-панель? д/н» → при «да»: логин `admin`, ввод пароля с повтором (минимальная длина 8), `cfg.Panel = {Enabled:true, PasswordHash: HashPassword(pw)}`; при «нет» — `Enabled:false`.
- Non-interactive: `--panel` (default: включить, если задан `--password`), `--password <pw>` → хешируется; без пароля панель выключена (в сводке предупреждение).
- Сводка установщика: при включённой панели — строка `Панель: https://<домен>/ · логин admin`.

- [ ] **Step 1: Падающие тесты**: визард (д/н, несовпадение паролей, короткий пароль), `buildConfig` с паролем (хэш в конфиге, не plaintext; в JSON нет открытого пароля — grep по сериализации), сводка содержит URL панели.
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS** + tmux-прогон шага панели в `mdns setup`.
- [ ] **Step 5: Commit** `feat: panel password in the wizard and installer`.

---

### Task 11: TUI — экран «Диагностика» и клиент в ленте

**Files:**
- Modify: `internal/tui/model.go`, `internal/tui/status.go` (или новый `internal/tui/diag.go`), `internal/tui/requests.go`, тесты
- Modify: `cmd/mdns` не требуется (диагностика внутри TUI через API)

**Interfaces:**
- Вкладка 7 «Помощь» → «Диагностика» (help переносится на `?`-оверлей и футер); экран показывает результаты тех же проверок, что `mdns diag`, собранные через API (конфиг валиден, порты, сертификат, upstream-пинги, каталог данных, файлы списков, юнит) с `✓/!/✗`.
- Лента запросов: колонка «клиент» (ClientIP уже в Entry); `f` — фильтр по подстроке (домен/клиент) с индикатором и сбросом.

- [ ] **Step 1: Падающие тесты**: `TestDiagScreen` (строки состояний из api-мока), `TestRequestsClientColumn`, `TestRequestsFilter` (ввод подстроки фильтрует строки; esc отменяет).
- [ ] **Step 2: RED.**
- [ ] **Step 3: реализовать.**
- [ ] **Step 4: PASS** + tmux-визуал (Диагностика и фильтр ленты).
- [ ] **Step 5: Commit** `feat: TUI diagnostics screen and request filters`.

---

### Task 12: docker e2e панели (Playwright, systemd-контейнер)

**Files:**
- Create: `scripts/e2e-panel.sh`, `e2e/panel/panel_test.py` (Python Playwright)
- Modify: `scripts/e2e-install.sh` (пароль в non-interactive; проверить, что панель отвечает 401 без сессии)

**Interfaces:**
- Сценарий: systemd-контейнер (как e2e-install), install с `--panel --password`; HTTPS на published 8443 (self-signed: Playwright `ignoreHTTPSErrors`); проверки: логин (неверный пароль → ошибка; верный → Статус), все разделы рендерятся, hover по сегменту доната → подпись, клик → история с фильтром, поиск и пагинация, живая лента обновляется после `dig` (сделать запрос из контейнера и увидеть строку), мобильный вьюпорт 390×844 (скриншот), CSRF-негатив (POST без токена → 403), `panel.enabled=false` → `/panel/` 404.
- Скриншоты всех экранов — в `e2e/panel/shots/` и в отчёт.

- [ ] **Step 1: написать сценарий.**
- [ ] **Step 2: прогнать; красное — фиксить (продукт или сценарий).**
- [ ] **Step 3: повторить дважды.**
- [ ] **Step 4: приложить скриншоты.**
- [ ] **Step 5: Commit** `test: Playwright e2e for the panel`.

---

### Task 13: перф-стенд в репозитории + UI под нагрузкой

**Files:**
- Create: `e2e/perf/fakedns/main.go`, `e2e/perf/loadgen/main.go`, `e2e/perf/go.mod`, `scripts/perf-local.sh`, `docs/perf-results.md`
- Move: логика из скретч-стенда (эта сессия), с доработками: `loadgen` сохраняет перцентили по бакетам, печатает машиночитаемый итог (JSON-строка), `perf-local.sh` поднимает фейк+демон на временном конфиге, гоняет миксы (миллионный смоук, 20 мин? — параметризуемо: `PERF_TOTAL` по умолчанию 20 000 000, `PERF_BURST=60s`), снимает RSS/CPU/латентность API до/во время/после, гоняет TUI-capture через tmux и (если панель включена) Playwright-скриншот под нагрузкой, пишет результаты в `docs/perf-results.md`.

**Interfaces:**
- Пороговые проверки сценария (fail если хуже): API `/status` во время нагрузки ≤ 250 мс; демон не теряет ответы в миксе (0 ошибок); RSS после прогона ≤ 200 МБ; TUI отвечает на клавиши ≤ 2 с; панель отдаёт «Статус» под нагрузкой ≤ 1 с и лента не ломается.
- Прогон включает и проверку «миллионы запросов видны в UI»: счётчики в панели и TUI соответствуют (с точностью до кольца журнала).

- [ ] **Step 1: перенести и отполировать генератор/фейк (go.mod: `github.com/miekg/dns`).**
- [ ] **Step 2: `scripts/perf-local.sh` — полный сценарий с порогами и артефактами.**
- [ ] **Step 3: прогнать (20M микс + 60s burst + DoH-фаза 100k); результаты в `docs/perf-results.md`; скриншоты TUI/панели под нагрузкой — в отчёт.**
- [ ] **Step 4: `go test ./... -race` не затронут (e2e/perf — отдельный модуль, исключён из основного `go test ./...`; убедиться, что `./...` его не подхватывает — каталог с собственным go.mod не входит).**
- [ ] **Step 5: Commit** `test: repeatable local perf harness and load-time UI checks`.

---

### Task 14: README, релиз v0.2.0 и повторная однушка

**Files:**
- Modify: `README.md` (раздел «Веб-панель»: включение в визарде, вход, что показывает; раздел перфа со ссылкой на `docs/perf-results.md`; скриншоты — файлы в `docs/img/`)

**Interfaces:**
- Обновить документацию по фактам (никаких обещаний): панель, пароль, история 10k в памяти, CSV, перф-числа с этой машины (и с VPS позже).
- Релиз: merge в main (по согласованию), тег `v0.2.0`, CI+release зелёные, реальная однушка в контейнере с `--panel --password`, вход в панель из контейнера.

- [ ] **Step 1: README + скриншоты.**
- [ ] **Step 2: финальное ревью ветки субагентом (flash) → фиксы → мерж.**
- [ ] **Step 3: тег `v0.2.0` + релиз + однушка-проверка.**
- [ ] **Step 4: отчёт пользователю с числами перфа и скриншотами.**
- [ ] **Step 5: Commit** `docs: panel, perf numbers and v0.2.0`.

---

### Task 15: VPS — установка с панелью и проверка (ждёт SSH)

**Files:** — (ручной прогон по чек-листу)

- [ ] **Step 1: однушка на VPS с доменом и Let's Encrypt + пароль панели.**
- [ ] **Step 2: `dig`/DoT/DoQ/DoH снаружи; `https://<домен>/` — вход, Статус, история, диаграммы.**
- [ ] **Step 3: лёгкий локальный нагрев с VPS-машины (например, 1M запросов через наш perf-стенд на loopback) + скриншоты панели.**
- [ ] **Step 4: ребут-тест, `mdns diag`.**
- [ ] **Step 5: отчёт.**

---

## Self-Review (при написании плана)

- **Покрытие запросов пользователя**: лента 30 (T7), диаграммы с hover/кликом (T7), история 100/стр с поиском и фильтрами (T8), «целиком от начала до конца» = кольцо памяти + серверная пагинация (T2/T8), статистика кумулятивная (T4), хард-тест миллионов и UI под нагрузкой (T13), TUI-полировка (T11), панель по макетам (T6–T9), e2e (T12), релиз (T14), VPS (T15).
- **Консистентность типов**: `qlog.Query` (T2) → `api` (T5) → `panel.history` (T8); `stats.Snapshot` (T4) → API (T5) → донаты (T7); `auth` (T3) → `panel` (T6) → визард (T10).
- **Review Focus → тесты**: 1) T6 `TestSessionRequired`/`TestCSRFRejected`/`TestDisabledPanelIs404` + T12 негативные; 2) T7 буфер+SSE, T13 пороги UI; 3) T2 `TestQueryUnderWraparound`, T8 пагинация; 4) T13 `perf-local.sh` пороги; 5) T3 хэш, T10 «нет plaintext в JSON».
- **Открытые мелочи, которые Task-исполнители решают сами**: конкретная вендорная версия htmx (зафиксировать и записать), формат CSV-заголовков, тонкости CSS (взять из макета).
