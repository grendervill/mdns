# mdns — управление: план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Единый источник правды для управления сервисом: ControlAPI на
unix-сокете (снимок статуса, чтение/применение конфига с мягким и
структурным применением и откатом, каталог провайдеров, измерение
задержек, ручное обновление списков, live-поток событий), полноценный
TUI на `bubbletea` (статус, живые запросы, upstream'ы, фильтры,
настройки) и визард `mdns setup`, работающий и до первого запуска
(локальный режим), и из работающего TUI (через API).

**Architecture:** Новые пакеты: `internal/providers` (каталог публичных
DNS-провайдеров с endpoint'ами по транспортам), `internal/probe`
(параллельное измерение задержек через существующие `transport`),
`internal/links` (генерация ссылок DoH/DoT/DoQ/plain), `internal/api`
(HTTP API и SSE поверх интерфейса `Controller`; слушает unix-сокет) и
`internal/tui` (модели bubbletea + клиент API по сокету). `internal/app`
получает атомарный runtime и `UpdateConfig` (мягкое применение —
стратегия, кеш, лимиты, правила/режим фильтра; структурное — домен,
протоколы/порты, TLS, upstream'ы, включение фильтра — с перезапуском
листенеров и откатом конфига при ошибке), поднимает ControlAPI в
`Start` и публикует события.

**Tech Stack:** Go 1.26 (`mydns`), `github.com/charmbracelet/bubbletea` +
`bubbles` + `lipgloss` (TUI), стандартная библиотека для HTTP/SSE и
unix-сокета. Веб-панель, ACME и установщик — следующий план (этап 4/4);
пароль панели появится вместе с вебом.

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md` (§6
ControlAPI/EventBus, §8 каталог провайдеров, §11 TUI и визард, §14 CLI,
§15 тесты). Предыдущие планы: `2026-10-17-mdns-core.md`,
`2026-10-17-mdns-filters.md`.

## Global Constraints

- Интерфейс один: API — источник правды; TUI — только клиент. Любое
  действие TUI доступно через API (и так же будет доступно вебу).
- API слушает unix-сокет `/run/mdns/mdns.sock` (путь настраивается в
  тестах через `app.Options`); права сокета 0660; HTTP/1.1 + SSE.
- Обновление конфига: валидация → резервная копия старого файла →
  запись нового → применение; при любой ошибке применения конфиг
  откатывается на диске, а runtime остаётся/восстанавливается прежним.
- Мягкое применение (без разрыва клиентских соединений): `strategy`,
  `cache`, `limits`, `filter.mode`, `filter.user_allow/user_block`.
  Структурное (перезапуск DNS-листенеров): `domain`, `tls`, `protocols`,
  `upstreams`, `filter` (enabled/lists/interval), `log`.
- Тексты интерфейса (TUI, визард, ошибки API) — русский; код, логи —
  английский, как в проекте.
- TUI при недоступном демоне завершается понятным сообщением (или
  предлагает `mdns setup`), а не паникой.
- Ссылки: DoH `https://<domain>/dns-query` (порт добавляется, если не
  443), DoT `tls://<domain>:<port>`, DoQ `quic://<domain>:<port>`,
  plain `<domain>:<port>`. При включённом plain по умолчанию порт 53.
- Пробы задержек: запрос `NS .` транспортом этого endpoint'а, таймаут
  2s, параллельно не более 16; для TLS-endpoint'ов проверка сертификата
  ВЫКЛЮЧЕНА не бывает — self-signed виден как ошибка соединения (визард
  показывает это как «недоступен»); вручную добавленные пользователем
  upstream'ы с `insecure_skip_verify` пробуются с этим флагом.
- События SSE: `requests` (каждая запись журнала), `upstreams` (снимок
  раз в секунду), `filter` (после ручного обновления списка). Каждый
  клиент получает события из своего канала; при отключении канал и
  горутина освобождаются.
- Тестовые команды: `go test ./... -race -count=1`, `go vet ./...`,
  `gofmt -l .` — чисто. Тесты не требуют root и не слушают порты
  ниже 1024. Тесты TUI — юнит на модель (`Update`/`View`), без TTY.

## Review Focus

Классы условий, которые легко упустить; на каждый пункт заведён тест с
пометкой **Review Focus**:

1. PUT config с занятым новым портом: ошибка понятна, конфиг на диске
   откатан, старые листенеры продолжают работать (**Task 7**).
2. SSE-клиент отключился на середине потока: подписка и горутина
   освобождаются, демон не течёт (**Task 5**).
3. TUI без демона (сокет отсутствует, EOF, «connection refused») —
   статус-экран показывает понятную ошибку и не падает (**Task 10**).
4. Визард: возврат назад (shift+tab/esc) и повторное прохождение не
   теряет уже введённые ответы (**Task 13**).
5. Мягкое изменение (стратегия/кеш/лимиты/правила) не перезапускает
   листенеры: активный TCP-запрос к plain DNS остаётся живым
   (**Task 7**).

---

### Task 1: Каталог провайдеров

**Files:**
- Create: `internal/providers/catalog.go`
- Test: `internal/providers/catalog_test.go`

**Interfaces:**
- Consumes: `config.UpstreamConfig` (для преобразования в конфиг).
- Produces:

```go
// Section: "plain" (без фильтров) | "blocking" (с фильтрами)
type Provider struct {
	ID          string
	Name        string
	Section     string
	Description string
	DoH, DoT, DoQ, Plain []Endpoint
}
type Endpoint struct {
	Transport  string // plain | dot | doh | doq
	Address    string // host:port или https URL
	ServerName string // SNI для dot/doq по IP-адресу
}
func List() []Provider
func ByID(id string) (Provider, bool)
func (p Provider) AllEndpoints() []Endpoint
func (e Endpoint) UpstreamConfig(id, name string) config.UpstreamConfig
```

Состав (не менее 12 провайдеров; адреса/URL выверяются в Step 4
DNS-запросами): без фильтров — Cloudflare, Google, Quad9, Яндекс,
AdGuard DNS, dns.sb, dns0.eu, Mullvad, ControlD, OpenDNS; с фильтрами —
AdGuard Family, Cloudflare Family, CleanBrowsing (security/family),
OpenDNS FamilyShield, Яндекс Family, ControlD Family, dns0.eu kids.

- [ ] **Step 1: Падающие тесты**

- `TestCatalogShape`: у каждого провайдера непустые ID/Name/Section/Description; Section ∈ {plain, blocking}; ID уникальны; у каждого есть ≥1 endpoint;
- `TestEndpointsShape`: Transport ∈ {plain,dot,doh,doq}; для plain/dot/doq Address — host:port (`net.SplitHostPort`), для doh — https URL с хостом; для dot/doq по IP-адресу ServerName непуст;
- `TestSections`: обе секции непустые; ≥ 12 провайдеров;
- `TestUpstreamConfigMapping`: `Endpoint.UpstreamConfig` даёт совпадающие Transport/Address/ServerName и Enabled=true; результат проходит `config.Validate` в составе минимального конфига.

- [ ] **Step 2: `go test ./internal/providers/` — FAIL**
- [ ] **Step 3: Реализовать данные и функции**
- [ ] **Step 4: Ручная выверка** (не тест, зафиксировать в отчёте задачи): для каждого endpoint'а прогнать `dig @<addr>` (plain), `kdig +tls` (DoT), `curl -H 'accept: application/dns-message' <url>?dns=...` (DoH); неотвечающие — исправить/убрать.
- [ ] **Step 5: `go test ./internal/providers/ -race` — PASS**
- [ ] **Step 6: Commit**

```bash
git add internal/providers && git commit -m "feat: public resolver catalog with per-transport endpoints"
```

---

### Task 2: Генерация ссылок

**Files:**
- Create: `internal/links/links.go`
- Test: `internal/links/links_test.go`

**Interfaces:**
- Consumes: `config.Config`.
- Produces:

```go
type Link struct {
	Proto string // plain | doh | dot | doq
	Title string // русская подпись
	URI   string // строка для устройства
}
func Links(cfg *config.Config) []Link // только включённые протоколы, порядок: doh, dot, doq, plain
```

- [ ] **Step 1: Падающие тесты**

- `TestDefaultPorts`: домен `dns.example.com`, все протоколы: DoH `https://dns.example.com/dns-query` (443 без порта), DoT `tls://dns.example.com:853`, DoQ `quic://dns.example.com:853`, plain `dns.example.com:53`;
- `TestCustomPorts`: DoH `https://…:8443/dns-query`, DoT `:8853`, plain `:5353`;
- `TestDisabledSkipped`: выключенный протокол отсутствует в списке.

- [ ] **Step 2: `go test ./internal/links/` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/links/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/links && git commit -m "feat: device link rendering"
```

---

### Task 3: Измерение задержек (probe)

**Files:**
- Create: `internal/probe/probe.go`
- Test: `internal/probe/probe_test.go`

**Interfaces:**
- Consumes: `providers.Endpoint`, `transport`.
- Produces:

```go
type Result struct {
	Endpoint providers.Endpoint
	Latency  time.Duration
	Err      string // пусто при успехе
}
func Measure(ctx context.Context, eps []providers.Endpoint, opts Options) []Result
type Options struct {
	Parallel int           // 0 → 16
	Timeout  time.Duration // 0 → 2s
}
```

Проба — запрос `NS .` транспортом endpoint'а (как health-монитор);
успех — ответ с NOERROR/NXDOMAIN без TC. Результаты — в порядке входа.

- [ ] **Step 1: Падающие тесты** (локальные серверы: `dnsfake` для plain/DoT через `NewTLS`, `httptest` для DoH; DoQ — мини-сервер из `transport`-тестов повторить не нужно: покрыть kdig-ом в ручном smoke, юнит — через fake plain)

- `TestMeasurePlain`: fake-сервер отвечает → Latency > 0, Err пусто;
- `TestMeasureErrors`: недоступный endpoint (закрытый порт) → Err непустой, остальные результаты на месте;
- `TestMeasureTimeout`: сервер молчит → Err содержит timeout в пределах ~2×timeout;
- `TestMeasureParallel`: 8 медленных endpoint'ов (50ms) при Parallel=8 → общее время < 200ms (идут параллельно);
- `TestMeasureOrder`: результаты в порядке входа даже при разных задержках.

- [ ] **Step 2: `go test ./internal/probe/` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/probe/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/probe && git commit -m "feat: parallel latency probe for resolver endpoints"
```

---

### Task 4: ControlAPI — чтение

**Files:**
- Create: `internal/api/api.go`, `internal/api/status.go`, `internal/api/read.go`
- Test: `internal/api/read_test.go`

**Interfaces:**
- Consumes: `config`, `qlog`, `filter`, `providers`, `upstream`, `cache`, `links` (типы только).
- Produces:

```go
// Controller — всё, что API умеет у демона (реализует *app.App).
type Controller interface {
	Status(ctx context.Context) (Status, error)
	Config() *config.Config
	UpdateConfig(ctx context.Context, c *config.Config) error
	Providers() []providers.Provider
	Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result
	Requests(n int) []qlog.Entry
	FilterStatus() []filter.ListStatus
	FilterUpdate(ctx context.Context, id string) error
}

// Status — снимок для интерфейсов.
type Status struct {
	Version    string
	Domain     string
	Links      []links.Link
	Listeners  []string // "doh:443", "plain:53", ...
	Strategy   string
	Upstreams  []UpstreamStatus
	Cache      cache.Stats
	Filter     FilterSnapshot
}
type UpstreamStatus struct {
	ID, Name, Transport, Address string
	Enabled                      bool
	Healthy                      bool
	LatencyMS                    float64
	Sent, Failed                 uint64
}
type FilterSnapshot struct {
	Enabled      bool
	Mode         string
	TotalBlocked uint64
	Lists        []filter.ListStat
}

type Server struct{ /* ... */ }
func New(ctl Controller, logger *slog.Logger) *Server
func (s *Server) Handler() http.Handler // для тестов и веба (этап 4)
func (s *Server) Serve(ctx context.Context, ln net.Listener) error
```

Роуты (Go 1.22 mux, нотация методов): `GET /api/v1/status`,
`GET /api/v1/config`, `GET /api/v1/providers`, `GET /api/v1/requests?n=200`
(максимум 10000), `GET /api/v1/filter/status`. JSON-ошибки:
`{"error": "..."}` со статусом 4xx/5xx; content-type JSON.

- [ ] **Step 1: Падающие тесты** (фейковый Controller в тесте; `httptest`)

- `TestStatusJSON`: поля снимка сериализуются; links соответствуют конфигу;
- `TestConfigJSON`: возвращает текущий конфиг;
- `TestProvidersJSON`: каталог отдаётся;
- `TestRequestsLimit`: `?n=5` отдаёт 5; n>10000 обрезается; без n — 200;
- `TestFilterStatusJSON`;
- `TestUnknownPath404`, `TestMethodNotAllowed405`.

- [ ] **Step 2: `go test ./internal/api/ -run 'TestStatus|TestConfig|TestProviders|TestRequests|TestFilterStatus|TestUnknown|TestMethod'` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/api/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/api && git commit -m "feat: control API read endpoints"
```

---

### Task 5: ControlAPI — запись, пробы и события

**Files:**
- Modify: `internal/api/api.go`
- Create: `internal/api/write.go`, `internal/api/events.go`
- Test: `internal/api/write_test.go`, `internal/api/events_test.go`

**Interfaces:**
- Consumes: Task 4.
- Produces:

```go
// POST /api/v1/probe   — {"endpoints":[{transport,address,server_name}]} → {"results":[...]}
// PUT  /api/v1/config  — полный конфиг → 200 {"status":"applied"} | 400/409/500 с ошибкой
// POST /api/v1/filter/update — {"id":"..."} ("" = все) → {"lists":[...status...]}
// GET  /api/v1/events  — SSE; строки "event: <type>\ndata: <json>\n\n",
//        типы: requests (qlog.Entry), upstreams ([]UpstreamStatus), filter (FilterSnapshot),
//        ping (каждые 15s, keep-alive).
// Публикация: Controller получает шину через тип:
type Event struct{ Type string; Data any }
type Bus struct{ /* ... */ }
func NewBus() *Bus
func (b *Bus) Publish(e Event)
func (b *Bus) Subscribe() (<-chan Event, func()) // возвращает cancel
```

- [ ] **Step 1: Падающие тесты**

- `TestProbeEndpoint`: POST probe с двумя endpoint'ами (сотрудничают два dnsfake) → результаты по порядку;
- `TestPutConfigApplied`: PUT валидного конфига → 200, фейковый Controller получил UpdateConfig;
- `TestPutConfigInvalid`: невалидный → 400 и Controller не вызван;
- `TestPutConfigError`: UpdateConfig вернул ошибку → 500 и текст ошибки в теле;
- `TestFilterUpdate`: POST с id → Controller.FilterUpdate("id");
- `TestSSEStream` (**Review Focus №2**): подписка, Publish двух событий → SSE-поток содержит оба; отмена ctx клиента → серверный канал освобождён (Bus: `Subscribers() == 0` через короткое ожидание);
- `TestSSEKeepAlive`: ping приходит (таймаут ping сокращён в тесте через опцию `ServerOptions{PingInterval: 20ms}`).

- [ ] **Step 2: `go test ./internal/api/ -run 'TestProbe|TestPut|TestFilterUpdate|TestSSE'` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/api/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/api && git commit -m "feat: control API writes, probe and SSE events"
```

---

### Task 6: Мягкое применение настроек в ядре

**Files:**
- Modify: `internal/routing/router.go` (+test), `internal/cache/cache.go` (+test), `internal/ratelimit/ratelimit.go` (+test), `internal/filter/engine.go` (+test), `internal/core/core.go` (+test)

**Interfaces:**
- Consumes: существующие компоненты.
- Produces (методы для `app.UpdateConfig`, все — потокобезопасные):

```go
// routing
func (r *Router) SetStrategy(name string) error
// cache
func (c *Cache) SetLimits(minTTL, maxTTL uint32)
func (c *Cache) SetSize(size int) // уменьшение вытесняет LRU-лишние
// ratelimit
func (l *Limiter) Reload(rpsPerIP int, trustedCIDRs []string) error
// filter
func (e *Engine) SetUserRules(allow, block []string) // пересборка индекса
// core
func (c *Core) SetBlockMode(mode string)
```

- [ ] **Step 1: Падающие тесты**

- router: `TestSetStrategy` (failover→random меняет порядок), неизвестная стратегия — ошибка;
- cache: `TestSetSizeEvicts` (10→2 записи — Size()==2, самые свежие живы), `TestSetLimits` (новый clamp виден на выдаче);
- ratelimit: `TestReload` (10 rps → 1 rps сразу лимитирует; битый CIDR — ошибка, старые параметры живы);
- filter: `TestSetUserRules` (новое allow перебивает список; удалённое — перестаёт);
- core: `TestSetBlockMode` (zero → nxdomain на лету).

- [ ] **Step 2: целевые тесты — FAIL**
- [ ] **Step 3: Реализовать** (mutex/atomic по месту)
- [ ] **Step 4: `go test ./... -race -count=1` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/core internal/routing internal/cache internal/ratelimit internal/filter \
  && git commit -m "feat: live settings application across core components"
```

---

### Task 7: app — runtime, UpdateConfig, откат

**Files:**
- Modify: `internal/app/app.go` (переработать в runtime + атомарные указатели), `internal/app/app_test.go`
- Create: `internal/app/update_test.go`

**Interfaces:**
- Consumes: Task 6, `config.Save/Load`.
- Produces:

```go
func (a *App) UpdateConfig(ctx context.Context, next *config.Config) error
func (a *App) Status(ctx context.Context) (api.Status, error)
func (a *App) Config() *config.Config
func (a *App) Providers() []providers.Provider
func (a *App) Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result
func (a *App) Requests(n int) []qlog.Entry
func (a *App) FilterStatus() []filter.ListStatus
func (a *App) FilterUpdate(ctx context.Context, id string) error
func (a *App) Events() *api.Bus
```

Изменения в структуре: `App` хранит `cfgPath`, `bus`, и `rt` (runtime:
upstreams, monitor, router, cache, limiter, filter, updater, core,
server, links); `UpdateConfig`:

1. `next.Validate()` → иначе ошибка без изменений;
2. вычислить структурность (список полей из Global Constraints);
3. **мягкий путь**: применить Task-6 методы, обновить указатель cfg,
   сохранить файл (атомарно; при ошибке записи — откатить применения
   обратно старыми значениями);
4. **структурный путь**: собрать новый runtime (переиспользуя
   `filter.Engine` и `Updater`, если фильтр остался включён); остановить
   старый `server`, запустить новый; при ошибке — вернуть старый
   runtime на место (перезапустить прежние листенеры) и вернуть ошибку
   с указанием причины; файл конфига сохраняется только после успеха.
5. Опубликовать событие `filter`/`upstreams` при изменениях.

`Options` дополняется: `SocketPath string` (путь API-сокета).

- [ ] **Step 1: Падающие тесты**

- `TestUpdateConfigSoft` (**Review Focus №5**): стратегия fastest→failover и cache.limits через `UpdateConfig` — 200/no error; **активный TCP-запрос** к plain-порту, открытый до изменения, получает ответ после (листенеры не перезапускались — проверить по тому же TCP-соединению `dns.Client` не поможет; тест: открыть raw net.Conn, после UpdateConfig отправить запрос по нему через dns.Conn из miekg);
- `TestUpdateConfigStructural`: смена plain-порта → старый порт не отвечает, новый отвечает; конфиг на диске обновился;
- `TestUpdateConfigBindFailureRollsBack` (**Review Focus №1**): занять порт чужаком (`net.Listen`) → `UpdateConfig` с новым plain-портом возвращает ошибку; старый порт по-прежнему отвечает; файл конфига не изменён;
- `TestUpdateConfigInvalid`: невалидный конфиг — ошибка, ничего не изменено.

- [ ] **Step 2: `go test ./internal/app/ -run TestUpdateConfig` — FAIL**
- [ ] **Step 3: Реализовать** (сначала рефакторинг App на runtime — существующие тесты должны остаться зелёными)
- [ ] **Step 4: `go test ./internal/app/ -race -count=1` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/app && git commit -m "feat: transactional config updates in the app runtime"
```

---

### Task 8: app — ControlAPI на unix-сокете и события

**Files:**
- Modify: `internal/app/app.go` (+test)
- Create: `internal/app/api_test.go`

**Interfaces:**
- Consumes: Task 4–7.
- Produces: `App.Start` поднимает `api.Server` на `Options.SocketPath`
  (при пустом — `/run/mdns/mdns.sock`, каталог сокета создаётся при
  необходимости, права каталога 0755, сокета — 0660); `qlog` получает
  наблюдателя, публикующего `requests`; тикер раз в секунду публикует
  `upstreams`; `FilterUpdate` публикует `filter`. `App.Events()` — шина.

Дополнительно в `qlog`: `func (l *Log) SetObserver(f func(Entry))` (вызывается после Add; nil — выключить).

- [ ] **Step 1: Падающие тесты**

- `TestAppServesAPI`: app.Start c `SocketPath` в t.TempDir → `http.Client` с `Transport{DialContext: unix-dial}` → `GET /api/v1/status` 200 и содержит домен;
- `TestAppAPIEvents` (**Review Focus №2**, интеграция): подписаться на SSE, сделать DNS-запрос → в потоке появилось событие `requests`;
- `TestAppFilterUpdateViaAPI`: app с фильтром (httptest-список) → `POST /api/v1/filter/update` → 200;
- `TestAppStopClosesSocket`: после Stop сокет-файл удалён (или не отвечает).

- [ ] **Step 2: `go test ./internal/app/ -run 'TestAppServesAPI|TestAppAPIEvents|TestAppFilterUpdate|TestAppStopClosesSocket'` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/app/ -race -count=1` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/app internal/qlog && git commit -m "feat: control API on the daemon socket with live events"
```

---

### Task 9: API-клиент для TUI

**Files:**
- Create: `internal/tui/client.go`
- Test: `internal/tui/client_test.go`

**Interfaces:**
- Consumes: `internal/api` (тестовый сервер можно поднять на unix или TCP).
- Produces:

```go
type Client interface {
	Status(ctx context.Context) (api.Status, error)
	Config(ctx context.Context) (*config.Config, error)
	UpdateConfig(ctx context.Context, c *config.Config) error
	Providers(ctx context.Context) ([]providers.Provider, error)
	Probe(ctx context.Context, eps []providers.Endpoint) ([]probe.Result, error)
	Requests(ctx context.Context, n int) ([]qlog.Entry, error)
	FilterStatus(ctx context.Context) ([]filter.ListStatus, error)
	FilterUpdate(ctx context.Context, id string) error
	Events(ctx context.Context) (<-chan api.Event, error)
}
// UnixClient — реализация поверх unix-сокета (или любого адреса http://…).
func NewUnixClient(socketPath string) *UnixClient
```

- [ ] **Step 1: Падающие тесты**

- `TestUnixClientStatus`: клиент к тестовому API (фейковый Controller на unix-сокете в tempdir) отдаёт Status;
- `TestUnixClientUpdateConfig`: PUT проходит;
- `TestUnixClientEvents`: SSE-канал отдаёт события; отмена ctx закрывает канал;
- `TestUnixClientErrors`: недоступный сокет → ошибка с понятным текстом (содержит путь).

- [ ] **Step 2: `go test ./internal/tui/ -run TestUnixClient` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/tui/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/tui && git commit -m "feat: TUI API client over the daemon socket"
```

---

### Task 10: TUI — каркас и экран «Статус»

**Files:**
- Create: `internal/tui/model.go`, `internal/tui/status.go`
- Test: `internal/tui/model_test.go`, `internal/tui/status_test.go`

**Interfaces:**
- Consumes: `Client` (Task 9).
- Produces:

```go
type Model struct{ /* ... */ }
func New(c Client, opts Options) Model
type Options struct {
	SocketPath string
	Initial    string // экран при старте: "status" (по умолчанию) и т.д.
}
func (m Model) Init() tea.Cmd
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd)
func (m Model) View() string
// Экраны: status, wizard, requests, upstreams, filters, settings, help.
```

Экран «Статус»: домен; ссылки (Task 2) с копированием по `c`; таблица
upstream'ов (имя, задержка, состояние); кеш (hits/misses/size); фильтр
(режим, всего заблокировано, списки с статусами); версия. Данные —
`Status` + живые обновления из `Events`. Ошибка соединения —
**Review Focus №3**: рамка с текстом «демон недоступен: <причина>»,
подсказка `mdns setup`, клавиша `r` — переподключение, `q` — выход.

Навигация: `1..7`/`tab` — экраны, `q` — выход, `?` — помощь.

- [ ] **Step 1: Падающие тесты** (мок Client)

- `TestStatusViewRenders`: `Update(statusLoaded{...})` → `View()` содержит домен, URI DoH, имя upstream'а;
- `TestNavigation`: `Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})` → текущий экран requests;
- `TestDaemonUnavailable` (**Review Focus №3**): мок Client возвращает ошибку соединения → `View()` содержит «демон недоступен» и не паникует; `r` инициирует перезапрос (мок вызван повторно);
- `TestQuit`: `q` → `tea.Quit`.

- [ ] **Step 2: `go test ./internal/tui/ -run 'TestStatus|TestNavigation|TestDaemon|TestQuit'` — FAIL**
- [ ] **Step 3: Реализовать** (`go get github.com/charmbracelet/bubbletea@latest github.com/charmbracelet/bubbles@latest github.com/charmbracelet/lipgloss@latest`; тема тёмного терминала; русские подписи)
- [ ] **Step 4: `go test ./internal/tui/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/tui go.mod go.sum && git commit -m "feat: TUI skeleton with the status screen"
```

---

### Task 11: TUI — «Запросы» и «Upstream'ы»

**Files:**
- Create: `internal/tui/requests.go`, `internal/tui/upstreams.go`
- Test: `internal/tui/requests_test.go`, `internal/tui/upstreams_test.go`

**Interfaces:**
- Consumes: Task 10; события `requests`, `upstreams`.
- Produces: экран «Запросы» — таблица (время, прототип, домен, тип,
  результат/источник, upstream, задержка; заблокированные помечены),
  пауза (`space`), очистка (`x`), прокрутка; буфер ≤ 500 строк.
  Экран «Upstream'ы» — детальная таблица (ID, транспорт, адрес,
  состояние, EWMA, sent/failed), без ручного управления в этом плане
  (управление приоритетами — в вебе; здесь только просмотр).

- [ ] **Step 1: Падающие тесты**

- `TestRequestsFeed`: событие `requests` добавляет строку; `space` останавливает приём (новые не добавляются), `space` снова включает;
- `TestRequestsCap`: 600 событий → в модели 500;
- `TestBlockedMarked`: запись с `Blocked=true` рендерится со пометкой источника;
- `TestUpstreamsView`: событие `upstreams` обновляет таблицу (задержка форматируется в ms, unhealthy помечен).

- [ ] **Step 2: целевые тесты — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/tui/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/tui && git commit -m "feat: TUI live requests and upstreams screens"
```

---

### Task 12: TUI — «Фильтры» и «Настройки»

**Files:**
- Create: `internal/tui/filters.go`, `internal/tui/settings.go`
- Test: `internal/tui/filters_test.go`, `internal/tui/settings_test.go`

**Interfaces:**
- Consumes: Task 10; API `filter/status`, `filter/update`, `config`.
- Produces:
  - «Фильтры»: список списков (ID, правил, попаданий, обновлён, ошибка),
    `enter` — обновить список, `u` — обновить все, `m` — переключить
    режим блокировки (zero/nxdomain/refused, мягкое применение), поле
    пользовательских правил (добавление через `a`: allow/block домен,
    применение через PUT config).
  - «Настройки»: форма ключевых полей (домен, порты и вкл/выкл
    протоколов, стратегия, кеш size/min/max, лимит plain, списки
    фильтров по ID) с применением по `ctrl+s` через `UpdateConfig`;
    ошибка применения показывается поверх формы и не теряет введённое.

- [ ] **Step 1: Падающие тесты**

- `TestFiltersView`: статусы списков рендерятся (ID, hits, ошибка помечена);
- `TestFilterManualUpdate`: `enter` вызывает `FilterUpdate(id)`;
- `TestFilterModeToggle`: `m` меняет режим и шлёт PUT config c новым `filter.mode`;
- `TestSettingsApply`: правка стратегии + `ctrl+s` → `UpdateConfig` вызван с новым значением;
- `TestSettingsApplyError`: `UpdateConfig` вернул ошибку → сообщение на экране, значения не сброшены.

- [ ] **Step 2: целевые тесты — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/tui/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/tui && git commit -m "feat: TUI filters and settings screens"
```

---

### Task 13: Визард и `mdns setup`

**Files:**
- Create: `internal/tui/wizard.go`, `internal/tui/wizard_test.go`, `internal/setup/setup.go`
- Modify: `cmd/mdns/main.go` (`mdns setup` — визард; `mdns` без аргументов — TUI)
- Test: `internal/tui/wizard_test.go`, `internal/setup/setup_test.go`

**Interfaces:**
- Consumes: `providers`, `probe`, `config`, `tui`.
- Produces:

```go
// internal/setup — локальный бэкенд визарда (до первого запуска демона).
type Backend struct{ /* ... */ }
func NewLocalBackend(configPath string) *Backend
// реализует tui.WizardBackend:
//   Load() — конфиг с диска или config.Default()
//   Save(cfg) — валидация + атомарная запись файла
//   Providers() — каталог
//   Probe(ctx, eps) — probe.Measure
type WizardBackend interface { /* тот же набор */ }
```

Шаги визарда (порядок по дизайну §11): домен → TLS-режим
(self-signed / files с путями; строка «Let's Encrypt — в следующем
обновлении») → протоколы и порты (дефолты в скобках, пустой ввод
применяет дефолт) → провайдеры: две секции, мультивыбор, транспорт на
провайдера, таблица пингов с обновлением раз в секунду (`probe`) →
стратегия → фильтрация (пресеты basic/strict/выключено/свой набор) →
сводка со ссылками и кнопкой «Применить». **Review Focus №4**: возврат
назад сохраняет все ранее введённые ответы.

`mdns setup`: запускает `tea.NewProgram(tui.NewWizard(setup.NewLocalBackend(path)))`;
по завершении печатает ту же сводку и подсказку «запустите: systemctl
start mdns» (установщик этапа 4 доработает автозапуск). `mdns` без
аргументов: если сокет есть — TUI в режиме демона; если нет — сообщение
«демон не запущен; для первичной настройки: mdns setup».

- [ ] **Step 1: Падающие тесты**

- `TestWizardFlow`: прогон шагов через Update до сводки: домен введён, providers выбраны, стратегия fastest → `Save` вызван с конфигом, где domain/upstreams/strategy совпадают (**Review Focus №4**: шаг назад — правка домена — вперёд — провайдеры и стратегия сохранены);
- `TestWizardDefaultPorts`: пустой ввод порта → значение по умолчанию;
- `TestLocalBackendSaveLoad`: Save→Load roundtrip (использует t.TempDir, режим файла 0600); невалидный домен → ошибка Save и понятный текст;
- `TestSetupSummary`: строки сводки содержат URI DoH/DoT/DoQ/plain.

- [ ] **Step 2: целевые тесты — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/tui/ ./internal/setup/ -race` — PASS**
- [ ] **Step 5: Ручной визуальный прогон (tmux)**: поднять локальный smoke-сервер (как в README, порты 5533+) и прогнать TUI и визард, снять скриншоты текста `tmux capture-pane`; проверить вёрстку/русские подписи; результат — в отчёте задачи.
- [ ] **Step 6: Commit**

```bash
git add internal/tui internal/setup cmd && git commit -m "feat: setup wizard with local backend and mdns setup"
```

---

### Task 14: Визард из работающего TUI (API-бэкенд)

**Files:**
- Create: `internal/tui/wizard_api.go`
- Modify: `internal/tui/model.go` (вход в визард из меню + бэкенд по режиму)
- Test: `internal/tui/wizard_api_test.go`

**Interfaces:**
- Consumes: `Client` (Task 9), визард (Task 13).
- Produces: `apiBackend` — `Load`: GET config; `Save`: PUT config;
  `Providers`/`Probe`: соответствующие эндпоинты. В TUI визард открыт
  из «Настройки → Визард» или клавишей `w`; при старте из TUI
  используется API-бэкенд, из `mdns setup` — локальный.

- [ ] **Step 1: Падающие тесты**

- `TestAPIWizardSave`: прогон визарда на мок-клиенте → `UpdateConfig` вызван с ожидаемым конфигом;
- `TestAPIWizardLoad`: текущий конфиг подставляется в шаги (например, порты совпадают с конфигом клиента).

- [ ] **Step 2: целевые тесты — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/tui/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/tui && git commit -m "feat: wizard over the control API"
```

---

### Task 15: Документация и финальная проверка

**Files:**
- Modify: `README.md`, `examples/config.json`

- [ ] **Step 1: README**: раздел «Управление»: TUI (запуск `mdns`, экраны), `mdns setup`, API по сокету (краткая таблица эндпоинтов + `curl --unix-socket` пример), мягкое/структурное применение конфига.
- [ ] **Step 2: `scripts/docker-smoke.sh`**: добавить проверку API на сокете внутри контейнера (`curl --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status` после запуска serve с предустановленным примером?) — конфиг в контейнере задаёт `socket_path`? Нет: путь фиксирован. В контейнере запуск от root — сокет `/run/mdns/mdns.sock` возможен: добавить в скрипт `mkdir -p /run/mdns` (если демон не создаёт сам — **демон должен создавать каталог сокета**; включить в Task 8) и проверку `curl --unix-socket` status.
- [ ] **Step 3: Ручной smoke**: локально — TUI против работающего демона (tmux), `mdns setup` на пустом конфиге, проверка сводки; вывод — в отчёт.
- [ ] **Step 4: `go test ./... -race -count=1`, `go vet ./...`, `gofmt -l .` — чисто; `scripts/docker-smoke.sh` — оба образа зелёные.**
- [ ] **Step 5: Commit**

```bash
git add README.md examples scripts && git commit -m "docs: control surfaces guide and smoke updates"
```

---

## Self-Review (при написании плана)

- **Spec coverage (§6/§8/§11/§14)**: ControlAPI и шина — Tasks 4, 5, 8; каталог провайдеров и пинги — Tasks 1, 3; TUI-экраны — Tasks 10–12; визард — Tasks 13, 14; CLI (`mdns` → TUI, `mdns setup`) — Task 13; ссылки — Task 2. Веб-панель, ACME, установщик, docker e2e-обвязка установщика — план этапа 4 (вне этого плана, по roadmap §17).
- **Type consistency**: `Controller` (Task 4) — методы совпадают с Produces Tasks 6–8; `Status`/`UpstreamStatus`/`FilterSnapshot` определены один раз (Task 4) и используются в Tasks 7, 8, 10; `WizardBackend` (Task 13) совпадает с вызовами визарда (Task 14).
- **Review Focus**: пять пунктов привязаны к тестам в Tasks 5, 7, 8, 10, 13.
- **Риски исполнения**: bubbletea добавляется в go.mod (Step в Task 10); визуальные проверки TUI — tmux (Task 13, 15), веб-панели в этом плане нет; путь сокета в тестах всегда во временном каталоге.
