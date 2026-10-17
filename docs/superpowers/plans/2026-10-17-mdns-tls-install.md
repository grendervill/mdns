# Сертификаты (ACME) и установка — план этапа 4

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** живой демон выпускает сертификаты Let's Encrypt/ZeroSSL/произвольные ACME с автопродлением и поднимает TLS-листенеры без перезапуска; установка на Ubuntu 24.04/Debian 13 — одной командой из GitHub-репозитория `grendervill/mdns`; CLI `status/diag/logs/install/uninstall`; CI и релиз `v0.1.0`; docker-e2e с локальным pebble и установщиком; финальный прогон на VPS.

**Architecture:** новый пакет `internal/acmecert` оборачивает `golang.org/x/crypto/acme/autocert` и реализует тот же шов `tlscert.Source`, что и статический `tlscert.Store`; `dnsserver` учится поднимать TLS-листенеры по готовности сертификата, держать challenge-слушатель :80 и сообщать список реально запущенных листенеров; `app` владеет менеджером сертификата (переиспользование между генерациями, событие `cert`, статус в API/TUI). Установщик — `internal/installer` (вся файловая/системная работа через настраиваемый `Root` и `Runner` — тестируемо без root), плюс тонкий `install.sh`-бутстрап; релизы — GitHub Actions по тегам.

**Tech Stack:** Go 1.26, `golang.org/x/crypto/acme/autocert`, systemd, GitHub Actions, Docker (systemd-контейнер; pebble + challtestsrv для ACME без интернета).

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md` (§10, §11, §14, §16; частично §5, §15)

## Global Constraints

- Go 1.26; один бинарник `mdns`; linux amd64/arm64; целевые ОС Ubuntu 24.04 и Debian 13 (trixie).
- Ключи сертификатов — ECDSA P-256 (autocert по умолчанию); сертификаты и ACME-аккаунт — в `<data_dir>/certs` (data_dir по умолчанию `/var/lib/mdns`), файлы 600, каталог данных 700.
- Продление: за 30 дней до истечения (`RenewBefore: 30*24h`), hot reload через `GetCertificate` без разрыва; ежедневная проверка.
- Режим «без TLS»: при недоступном сертификате plain DNS и локальное управление работают, TLS-листенеры не подняты; ошибка видна в TUI/API; повторные попытки с джиттером от 5 минут до 6 часов; при успехе TLS поднимается без перезапуска демона.
- TLS-ALPN-01 работает только когда DoH включён на порту 443; иначе включается HTTP-01 и поднимается слушатель :80, отвечающий только на `/.well-known/acme-challenge/…` (остальное — 404).
- Разрешённые исходящие соединения: ACME, выбранные upstream'ы, GitHub (скачивание релиза). Телеметрии нет; секреты (EAB HMAC и др.) никогда не логируются.
- Русский интерфейс, английский код и комментарии; каждый коммит — зелёные тесты под `-race`, `gofmt`/`go vet` чисты.

## Review Focus

1. Сертификат не получен: демон жив, plain DNS работает, TLS-порты закрыты, ошибка видна и повторяется с бэкоффом; после появления ACME-сервера TLS поднимается сам (Tasks 5, 9).
2. Установщик не оставляет полусостояний: ошибка визарда/невалидные флаги — сервис не запущен, конфиг не тронут; повторный запуск идемпотентен (Tasks 11, 14).
3. Смена TLS на живом демоне (self-signed↔files, *→acme) транзакционна; при сбое старая конфигурация продолжает отвечать (Tasks 5, 9).
4. Валидный кэшированный сертификат переиспользуется: рестарт без ACME-сервера не заказывает новый сертификат, TLS продолжает работать (Task 9).
5. `mdns uninstall` по умолчанию сохраняет конфиг и сертификаты; `--purge` удаляет только по явному запросу (Tasks 12, 14).

---

### Task 1: Конфиг — секция ACME в TLS

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces:
  ```go
  type TLS struct {
      Mode     string `json:"mode"` // "files" | "self-signed" | "acme"
      CertFile string `json:"cert_file"`
      KeyFile  string `json:"key_file"`
      ACME     ACME   `json:"acme,omitempty"`
  }
  type ACME struct {
      Provider           string `json:"provider"` // letsencrypt | zerossl | custom
      Email              string `json:"email,omitempty"`
      DirectoryURL       string `json:"directory_url,omitempty"`
      EABKeyID           string `json:"eab_kid,omitempty"`
      EABHMAC            string `json:"eab_hmac,omitempty"`
      InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
  }
  // ACMEDirectoryURL resolves the provider to a directory URL.
  func (t TLS) ACMEDirectoryURL() (string, error)
  ```
- Провайдеры: `letsencrypt` → `https://acme-v02.api.letsencrypt.org/directory`, `zerossl` → `https://acme.zerossl.com/v2/DV90`; `custom` требует `DirectoryURL` (https).

- [ ] **Step 1: Падающие тесты** (`config_test.go`): `TestTLSACMEModeValid` (таблица: letsencrypt+email, zerossl+email+EAB, custom+URL+insecure — валидны); `TestTLSACMEModeInvalid` (неизвестный провайдер; letsencrypt без email; zerossl без EAB; custom без URL; `http://` URL; пустой домен); `TestACMEDirectoryURL` (оба провайдера + custom + ошибка).
- [ ] **Step 2: целевые тесты — FAIL** (`go test ./internal/config/ -run TestTLSACME -count=1`).
- [ ] **Step 3: реализовать** поля, парсинг провайдеров, правила в `Validate` (проверять секцию только при `mode == "acme"`).
- [ ] **Step 4: `go test ./internal/config/ -race -count=1` — PASS** (существующие тесты конфига не сломаны, в т.ч. round-trip JSON).
- [ ] **Step 5: Commit** `git add internal/config && git commit -m "feat: ACME settings in the TLS config"`.

---

### Task 2: tlscert — интерфейс Source и статус сертификата

**Files:**
- Modify: `internal/tlscert/store.go`, `internal/tlscert/store_test.go`

**Interfaces:**
- Produces:
  ```go
  // Source provides the server certificate to the TLS listeners; a
  // static store and the ACME manager both implement it.
  type Source interface {
      GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
      Ready() bool        // a usable certificate is available
      ACMEALPN() bool     // the 443 listener must advertise acme-tls/1
      Status() Status
  }
  type Status struct {
      Mode      string    `json:"mode"`  // self-signed | files | acme
      State     string    `json:"state"` // ok | waiting | error
      Issuer    string    `json:"issuer,omitempty"`
      NotAfter  time.Time `json:"not_after,omitempty"`
      Error     string    `json:"error,omitempty"`
      LastCheck time.Time `json:"last_check,omitempty"`
  }
  ```
- `Store` получает поля `mode` и `cert`; `Ready() == true`, `ACMEALPN() == false`, `Status()` собирает Issuer CN и NotAfter из `cert.Leaf`.

- [ ] **Step 1: Падающие тесты**: `TestStoreImplementsSource` (var _ Source = (*Store)(nil)); `TestStoreStatus` (self-signed: Mode/State, `NotAfter ≈ now+90d`, Issuer == домен; files: сертификат из тестового PEM-файла, NotAfter из него).
- [ ] **Step 2: целевые тесты — FAIL** (`go test ./internal/tlscert/ -count=1`).
- [ ] **Step 3: реализовать** интерфейс, статус; `New` сохраняет режим.
- [ ] **Step 4: `go test ./internal/tlscert/ ./internal/app/ ./internal/dnsserver/ -race -count=1` — PASS** (вызовы `tlscert.New` в app/dnsserver не меняются до Task 4).
- [ ] **Step 5: Commit** `git add internal/tlscert && git commit -m "feat: certificate source interface and store status"`.

---

### Task 3: acmecert — менеджер сертификатов

**Files:**
- Create: `internal/acmecert/acmecert.go`, `internal/acmecert/acmecert_test.go`

**Interfaces:**
- Produces:
  ```go
  type Options struct {
      Domain             string
      Email              string
      DirectoryURL       string
      EAB                *acme.ExternalAccountBinding
      CacheDir           string // <data_dir>/certs/acme
      InsecureSkipVerify bool   // тестовые ACME-серверы (pebble)
      Logger             *slog.Logger
      BackoffMin         time.Duration // 0 → 5m
      BackoffMax         time.Duration // 0 → 6h
  }
  func New(opts Options) (*Manager, error)
  func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
  func (m *Manager) HTTPHandler() http.Handler  // включает http-01 в autocert
  func (m *Manager) Ready() bool
  func (m *Manager) ReadyChan() <-chan struct{} // закрывается при первом сертификате
  func (m *Manager) ACMEALPN() bool             // true
  func (m *Manager) Status() tlscert.Status
  // Run проактивно получает сертификат, затем проверяет ежедневно,
  // повторяет с джиттером и вызывает onState при каждом изменении.
  func (m *Manager) Run(ctx context.Context, onState func(tlscert.Status))
  var _ tlscert.Source = (*Manager)(nil)
  // ParseEAB декодирует base64url/base64 HMAC из конфига.
  func ParseEAB(kid, hmacB64 string) (*acme.ExternalAccountBinding, error)
  ```
- Реализация: `autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(CacheDir), HostPolicy: autocert.HostWhitelist(Domain), RenewBefore: 30*24h, Email, ExternalAccountBinding, Client: &acme.Client{DirectoryURL, HTTPClient при InsecureSkipVerify}}`. `GetCertificate` — обёртка: успех → `State ok` (Issuer/NotAfter из `Certificate.Leaf`), ошибка → `State error` с текстом. `Run`: цикл «получить → 24ч пауза»; при ошибке — пауза `backoff = min(BackoffMin·2^n, BackoffMax)` с джиттером ±20%, n растёт до успеха. Только `New` строит autocert; тесты используют неэкспортируемый `newWithGetter(getter, opts, now)` — шов для подмены.

- [ ] **Step 1: Падающие тесты**: `TestParseEAB` (base64url, base64, мусор → ошибка); `TestManagerStatusTransitions` (getter-заглушка: ошибка → waiting/error и LastCheck, успех → ok+NotAfter+Issuer, `Ready()` и `ReadyChan` закрывается один раз); `TestBackoffSchedule` (чистая функция: 5m→10m→…→cap 6h, джиттер в ±20%); `TestRunRetriesUntilSuccess` (getter падает 2 раза, потом успех: Run за 3 коротких бэкоффа (1ms) с `onState`; после успеха следующий вызов — через сутки, в тестах не ждём: отменяем ctx).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать** пакет (в go.mod: `golang.org/x/crypto` → direct `require`).
- [ ] **Step 4: `go test ./internal/acmecert/ -race -count=1` — PASS**; `go vet`.
- [ ] **Step 5: Commit** `git add internal/acmecert go.mod go.sum && git commit -m "feat: ACME certificate manager"`.

---

### Task 4: dnsserver — отложенный TLS, challenge-слушатель, фактический список листенеров

**Files:**
- Modify: `internal/dnsserver/server.go`, `internal/dnsserver/doh.go`, `internal/dnsserver/doh_internal_test.go`
- Create: `internal/dnsserver/lifecycle_test.go`

**Interfaces:**
- Consumes: `tlscert.Source` (Task 2).
- Produces:
  ```go
  func New(cfg *config.Config, c *core.Core, certs tlscert.Source, lim *ratelimit.Limiter, logger *slog.Logger) *Server
  func (s *Server) StartTLS() error                 // идемпотентно; поднимает DoT/DoH/DoQ
  func (s *Server) TLSStarted() bool
  func (s *Server) StartChallengeHTTP(handler http.Handler, port int) error
  func (s *Server) StopChallengeHTTP(ctx context.Context) error
  func (s *Server) Listeners() []string             // реально запущенные: "plain:53", "doh:443", …
  ```
- `Start`: plain (если включён) всегда; TLS — только если `certs.Ready()`, иначе `logger.Info("TLS listeners waiting for the certificate")`. DoH-листенер добавляет `acme-tls/1` в `NextProtos`, когда `certs.ACMEALPN()`.

- [ ] **Step 1: Падающие тесты** (`lifecycle_test.go`, заглушка Source с управляемым `ready`): `TestDeferredTLSStart` (неготовый источник: `Start` → plain отвечает, TLS-порт закрыт; `ready=true; StartTLS()` → TLS отвечает); `TestStartTLSIdempotent`; `TestListenersReflectsStart` (до StartTLS — без tls-записей, после — с ними); `TestChallengeHTTP01` (handler отвечает на `/.well-known/acme-challenge/x`, StopChallenge закрывает порт).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать** (хранение tls-серверов отдельно от plain, mutex тот же; challenge — отдельный `http.Server`).
- [ ] **Step 4: `go test ./internal/dnsserver/ -race -count=1` — PASS** (все существующие тесты листенеров).
- [ ] **Step 5: Commit** `git add internal/dnsserver && git commit -m "feat: deferred TLS listeners and challenge responder"`.

---

### Task 5: app — жизненный цикл сертификата, статус в API, события

**Files:**
- Modify: `internal/app/app.go`, `internal/app/control.go`, `internal/api/api.go`
- Create: `internal/app/cert_test.go`

**Interfaces:**
- Consumes: `acmecert` (Task 3), `tlscert.Source` (Task 2), `dnsserver` (Task 4).
- Produces:
  - `runtime` поля: `certSource tlscert.Source`, `acmeMgr *acmecert.Manager`, `certCfg config.TLS`.
  - `buildRuntime(cfg, prev, opts, logger, bus)` выбирает источник: files/self-signed → `tlscert.New`; acme → `acmecert.New(Options{..., EAB: ParseEAB(...), CacheDir: <data_dir>/certs/acme, DirectoryURL: cfg.TLS.ACMEDirectoryURL()})`. Менеджер переиспользуется при `prev.acmeMgr != nil && prev.certCfg == cfg.TLS && prev.dataDir == cfg.DataDir`.
  - `runtime.start` (acme): при `!(DoH включён и порт == 443)` → `server.StartChallengeHTTP(m.HTTPHandler(), 80)`; `go rt.certLoop(ctx)` — раз в секунду читает `Status()`: изменение → `bus.Publish(Event{Type: "cert"})`; `Ready() && !TLSStarted()` → `StartTLS()` + лог.
  - `api.Status` + `Cert tlscert.Status`; `Status()` приложения берёт `a.rt.certSource.Status()`, а `Listeners` — из `a.rt.server.Listeners()`.
  - Тестовый хук: env `MDNS_ACME_BACKOFF_MIN`/`MDNS_ACME_BACKOFF_MAX` (времена парсятся в `acmecert.Options`) — нужен e2e (Task 9).

- [ ] **Step 1: Падающие тесты** (`cert_test.go`, режимы без ACME): `TestCertStatusSelfSigned` (`a.Status().Cert`: mode self-signed, state ok; Listeners содержит `doh:<port>`); `TestTLSSwitchSelfSignedToFiles` (записать тестовую PEM-пару временно; `UpdateConfig(files)` → handshake на DoH отдаёт этот сертификат и старую пару перестаёт использовать); `TestTLSSwitchInvalidACMERejected` (`mode=acme, provider=zerossl` без EAB → ошибка валидации; конфиг и листенеры прежние); `TestListenersExcludeTLSWhenWaiting` — покрыт Task 4, здесь проверяем только проброс в статус (self-signed → TLS есть).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать** (переиспользование менеджера, certLoop, статус; `UpdateConfig`-путь не меняется — TLS остаётся структурной секцией).
- [ ] **Step 4: `go test ./internal/app/ ./internal/api/ -race -count=1` — PASS**.
- [ ] **Step 5: Commit** `git add internal/app internal/api && git commit -m "feat: ACME certificate lifecycle in the app and the API"`.

---

### Task 6: TUI — сертификат на экране «Статус»

**Files:**
- Modify: `internal/tui/status.go`, `internal/tui/client.go`, `internal/tui/model.go`, `internal/tui/model_test.go`

**Interfaces:**
- Consumes: `api.Status.Cert` (Task 5), SSE-событие `cert` (`tlscert.Status`).
- Produces: строка «Сертификат: …» в `statusView`: ok → «Let's Encrypt, истекает 15.01.2027»; waiting → жёлтым «ожидание выпуска»; error → красным «ошибка: <текст>»; `decodeEventData` учит тип `cert`; `applyEvent` обновляет `m.status.Cert`.

- [ ] **Step 1: Падающие тесты**: `TestStatusShowsCertStates` (три состояния через `statusLoadedMsg`); `TestCertEventUpdatesStatus` (SSE-сообщение меняет строку).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать**.
- [ ] **Step 4: `go test ./internal/tui/ -race -count=1` — PASS**; визуальная проверка в tmux (tmux + реальный демон с self-signed).
- [ ] **Step 5: Commit** `git add internal/tui && git commit -m "feat: certificate status in the TUI"`.

---

### Task 7: Визард — выбор сертификата с ACME

**Files:**
- Modify: `internal/tui/wizard.go`, `internal/tui/wizard_test.go`

**Interfaces:**
- Шаг «Сертификат» получает варианты: 0 Let's Encrypt (ввод email) → `TLS{Mode: acme, ACME{Provider: letsencrypt, Email}}`; 1 ZeroSSL (email, EAB kid, EAB HMAC) → provider zerossl; 2 Свой ACME-сервер (directory URL, email опц., вопрос «пропускать проверку сертификата ACME-сервера? (y/N)» → InsecureSkipVerify) → provider custom; 3 Самоподписанный; 4 Свои файлы (cert/key — как сейчас).
- В сводке: при `acme` и DoH `port != 443` — предупреждение «ACME использует HTTP-01 на порту 80»; при acme — строка «сертификат будет выпущен после запуска демона».
- Существующие тесты файлов/self-signed продолжают проходить (варианты 3–4 сохраняют прежние пути).

- [ ] **Step 1: Падающие тесты**: `TestWizardTLSLetsEncrypt` (cursor 0 → email → cfg.TLS.ACME); `TestWizardTLSZeroSSL` (EAB kid/hmac попадают в конфиг); `TestWizardTLSCustom` (URL + insecure y/n); обновить `TestWizardFlow` (курсор теперь 3 для self-signed — взять значение из константы, не магическое число); `TestWizardSummaryWarnsHTTP01`.
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать** (очередь вводов на шаг TLS: список вариантов + последовательные input'ы).
- [ ] **Step 4: `go test ./internal/tui/ -race -count=1` — PASS**; tmux-прогон ветки Let's Encrypt (до сохранения, без реального выпуска).
- [ ] **Step 5: Commit** `git add internal/tui && git commit -m "feat: ACME options in the setup wizard"`.

---

### Task 8: pebble e2e — выдача сертификата и отложенный старт TLS

**Files:**
- Create: `e2e/pebble/docker-compose.yml`, `e2e/pebble/daemon-config.json`, `scripts/e2e-pebble.sh`

**Interfaces:**
- Сервисы compose: `challtestsrv` (`ghcr.io/letsencrypt/pebble-challtestsrv`, HTTP :8055), `pebble` (`ghcr.io/letsencrypt/pebble`, `-config /test/config/pebble-config.json -dnsserver challtestsrv:8053`, `PEBBLE_VA_NOSLEEP=1`), `daemon` (ubuntu:24.04, смонтированный `dist/mdns-linux-<arch>`, конфиг `e2e/pebble/daemon-config.json`: domain `mdns.test`, plain 53, DoH 443/DoT+DoQ 853, `tls.mode=acme`, provider custom, `directory_url=https://pebble:14000/dir`, `insecure_skip_verify=true`, email `e2e@example.com`), `client` (ubuntu с `dnsutils knot-dnsutils openssl curl`).
- Скрипт: `make dist-linux` → `docker compose up -d challtestsrv pebble` → POST `http://localhost:8055/set-default-ipv4 {"ip": <IP daemon-контейнера>}` → `docker compose up -d daemon` → ждать ≤60 c, пока `curl -sk https://localhost:5443/dns-query` не ответит (DoH опубликован на 5443 хоста) — это доказывает hot-start TLS (демон стартовал без сертификата) → проверки из `client`: `openssl s_client` (сертификат для mdns.test, issuer — pebble), `kdig +tls` с корнем pebble (`https://pebble:15000/roots/0`), `kdig +quic`, plain `dig` → `docker compose down -v`.

- [ ] **Step 1: тест-скрипт**: сценарий выше; на каждом шаге явные assert'ы и печать (в стиле `scripts/docker-smoke.sh`).
- [ ] **Step 2: запустить до реализации Task 5 по факту уже готового кода — ожидаемый результат: скрипт зелёный** (если красный — фиксить Task 5/3, не скрипт).
- [ ] **Step 3: прогнать дважды** (повторяемость/чистота сети).
- [ ] **Step 4: зафиксировать в README-разделе тестов (Task 17)**, скрипт вызывается `scripts/e2e-pebble.sh`.
- [ ] **Step 5: Commit** `git add e2e scripts && git commit -m "test: pebble e2e for ACME issuance and deferred TLS"`.

---

### Task 9: pebble e2e — отказ, самовосстановление, кэш, смена режима на живом демоне

**Files:**
- Modify: `scripts/e2e-pebble.sh` (фазы B–D)

**Interfaces:**
- Фаза B (отказ): поднять только `daemon` (`MDNS_ACME_BACKOFF_MIN=5s`): `status.Cert.State ∈ {waiting,error}`, 443 закрыт, `dig` на 53 работает; поднять `pebble`+`challtestsrv` → ≤30 c TLS поднимается сам.
- Фаза C (кэш): `docker compose restart daemon` при остановленном pebble → TLS снова отвечает сразу (сертификат из кэша, новый заказ не делается).
- Фаза D (смена на живом): старт `daemon` с `self-signed` → через unix-сокет (volume) `curl -X PUT /api/v1/config` с `tls.mode=acme` → ждать TLS с pebble-сертификатом (issuer pebble), plain не прерывался (непрерывный `dig`-цикл с 0 ошибок).

- [ ] **Step 1: расширить скрипт фазами B–D** (каждая — отдельный `docker compose` профиль/этап, с чистым down между фазами).
- [ ] **Step 2: прогнать целиком; красное — фиксить код (app/acmecert), не скрипт**.
- [ ] **Step 3: прогнать повторно** (детерминизм бэкоффа с env-хуком).
- [ ] **Step 4: `go test ./... -race -count=1` — PASS** (скрипт ничего не сломал).
- [ ] **Step 5: Commit** `git add scripts && git commit -m "test: ACME failure, self-heal and cache reuse in e2e"`.

---

### Task 10: installer — preflight

**Files:**
- Create: `internal/installer/preflight.go`, `internal/installer/preflight_test.go`, `internal/installer/disk_linux.go`, `internal/installer/disk_other.go`

**Interfaces:**
- Produces:
  ```go
  type Options struct {
      Root       string           // default "/"; тесты — t.TempDir()
      ConfigPath string           // default /etc/mdns/config.json
      DataDir    string           // default /var/lib/mdns
      BindPorts  []int            // 53, 80, 443, 853 (из выбранных протоколов)
      Domain     string
      Runner     func(name string, args ...string) ([]byte, error) // systemctl и пр.; nil → exec
  }
  type Check struct {
      Name    string
      OK      bool
      Warning bool   // не блокирует установку
      Detail  string
  }
  func Preflight(opts Options) []Check
  // parseOSRelease разбирает /etc/os-release.
  func parseOSRelease(data []byte) (id, versionID string)
  // supportedDistro — Ubuntu 24.04, Debian 13 (trixie).
  func supportedDistro(id, versionID string) bool
  ```
- Проверки: root (`os.Geteuid()`); os-release; arch (amd64/arm64); systemd (`<Root>/run/systemd/system` + `systemctl --version`); порты (bind TCP+UDP на 0.0.0.0, каждый `BindPorts`; занятость → detail с именем держащего через `ss -ltnup`); systemd-resolved на :53 (файл `<Root>/run/systemd/resolve/stub-resolv.conf` + активен) → warning с инструкцией DNSStubListener=no; A/AAAA домена (резолв через 1.1.1.1 vs локальные глобальные адреса интерфейсов) → warning при несовпадении; диск ≥ 500 MiB (`disk_linux.go`, no-op на других ОС).

- [ ] **Step 1: Падающие тесты**: `TestParseOSRelease` (ubuntu/debian/мусор); `TestSupportedDistro` (24.04/13 ok; 22.04/12 — нет); `TestPortChecks` (высокие порты: свободный ок, занятый — ошибка c портом в Detail); `TestResolvedWarning` (temp Root с маркером stub-resolv + фейковый Runner «active» → Warning); `TestSystemdMissingFails` (пустой Root → error-check); `TestARecordNameMismatchWarns` (инъекция списка локальных адресов в Options для теста — сравнение без сети).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать**.
- [ ] **Step 4: `go test ./internal/installer/ -race -count=1` — PASS**.
- [ ] **Step 5: Commit** `git add internal/installer && git commit -m "feat: installer preflight checks"`.

---

### Task 11: installer — действия, systemd-юнит, ufw, non-interactive setup

**Files:**
- Create: `internal/installer/install.go`, `internal/installer/unit.go`, `internal/installer/config_build.go`, `internal/installer/install_test.go`

**Interfaces:**
- Produces:
  ```go
  type Spec struct { // non-interactive настройка; все поля необязательные кроме Domain
      Domain       string
      TLSMode      string // acme | self-signed | files (default self-signed)
      ACMEProvider string // letsencrypt | zerossl | custom
      ACMEEmail    string
      ACMEDirectory string
      ACMEInsecure bool
      EABKid       string
      EABHMAC      string
      CertFile, KeyFile string
      Providers    []string // ID каталога; пусто → ["cloudflare"]
      Strategy     string   // пусто → fastest
      PlainPort, DoHPort, DoTPort, DoQPort int // 0 → дефолт
      FilterPreset string   // off | basic | strict (default off)
  }
  type InstallOptions struct {
      Options              // Root/ConfigPath/DataDir/Runner
      BinarySource string  // os.Executable()
      DryRun       bool
      Spec         *Spec   // nil → интерактивный визард
      Output       io.Writer
  }
  func Run(opts InstallOptions) error
  func buildConfig(spec Spec) (*config.Config, error)
  func renderUnit(binaryPath, configPath string) string
  ```
- Действия `Run`: preflight (ошибки → отказ, warning'и печатаются); каталоги (`/etc/mdns` 755, `/var/lib/mdns` 700); бинарник → `/usr/local/bin/mdns` (если `BinarySource` — другой путь); non-interactive → `buildConfig` + валидация + атомарная запись `cfg.Save`; interactive → `tui.NewWizard(setup.NewLocalBackend(ConfigPath))` (без запуска сервиса при отмене); юнит `/etc/systemd/system/mdns.service` (Restart=always, After=network-online.target, `ExecStart=/usr/local/bin/mdns serve --config /etc/mdns/config.json`), `daemon-reload`, `enable --now mdns`; ufw: если `ufw status` активен — `allow 53/tcp`, `53/udp`, `80/tcp` (только acme+http01), `443/tcp`, `443/udp`, `853/tcp`, `853/udp` по включённым протоколам; сводка (домен, порты+ссылки, статус сертификата «выпуск после запуска» при acme, лучший upstream, фильтр). `DryRun`: печатает план, ничего не пишет.
- Идемпотентность: существующий конфиг + non-interactive без `--reconfigure` → конфиг не перезаписывается (сообщение), юнит/бинарник обновляются.

- [ ] **Step 1: Падающие тесты**: `TestRenderUnitGolden`; `TestBuildConfigFull` (spec → все поля, включая acme+EAB+пресет basic); `TestBuildConfigDefaults` (провайдеры/порты/стратегия по умолчанию); `TestBuildConfigInvalid` (неизвестный провайдер каталога, плохой пресет → ошибка); `TestInstallDryRun` (temp Root + nil-Runner: «планируемые действия» напечатаны, файлы не созданы); `TestUFURulesEnabled` (фейковый Runner «Status: active» → в логе нужные allow); `TestUFUInactiveSkips`; `TestIdempotentKeepsConfig` (существующий конфиг + spec → файл не перезаписан, mtime тот же).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать**.
- [ ] **Step 4: `go test ./internal/installer/ -race -count=1` — PASS**.
- [ ] **Step 5: Commit** `git add internal/installer && git commit -m "feat: mdns install with systemd unit and non-interactive setup"`.

---

### Task 12: CLI — install/uninstall/status/diag/logs

**Files:**
- Create: `internal/installer/uninstall.go`, `internal/installer/uninstall_test.go`, `internal/diag/diag.go`, `internal/diag/diag_test.go`
- Modify: `cmd/mdns/main.go`

**Interfaces:**
- Produces:
  ```go
  type UninstallOptions struct {
      Options                  // Root/Runner/ConfigPath/DataDir
      Purge      bool          // удалить конфиг, данные и сертификаты
      KeepBinary bool
      Output     io.Writer
  }
  func Uninstall(opts UninstallOptions) error
  // internal/diag
  func Status(ctx context.Context, socketPath string) (api.Status, error) // через unix-сокет
  func StatusText(st api.Status) string
  func Run(ctx context.Context, configPath, socketPath string, out io.Writer) int // diag; код выхода
  func Logs(configPath string, n int, follow bool, out io.Writer, runner func(string, ...string) ([]byte, error)) error
  ```
- `main.go`: подкоманды `install` (все флаги из `Spec` + `--non-interactive`, `--dry-run`, `--config`, `--data-dir`), `uninstall` (`--purge` + подтверждение с TTY, при `--non-interactive` без подтверждения), `status` (`--json`), `diag`, `logs` (`-n N`, `-f`). Usage обновлён.
- `diag` проверяет: конфиг читается/валиден; порты из конфига свободны или заняты нашим процессом; статус сертификата (через сокет, если демон жив); пинги upstream'ов (пакет `probe`); запись в data_dir; файлы списков фильтра на месте; unit-файл `mdns.service` присутствует. Вывод `✓/!/✗`, код выхода 1 при ✗.
- `logs`: если `log.file` задан — хвост файла; иначе `journalctl -u mdns -n N [-f]`; иначе подсказка.

- [ ] **Step 1: Падающие тесты**: `TestUninstallKeepsData` (temp Root: unit+бинарник удалены, ConfigPath и DataDir на месте); `TestUninstallPurge` (всё удалено); `TestStatusTextGolden` (строки статуса, включая сертификат); `TestDiagFlagsIssues` (temp конфиг: занятый порт → ✗ и код 1; невалидный конфиг → ✗); `TestLogsTail` (temp файл → последние N строк, follow-режим не тестируем).
- [ ] **Step 2: целевые тесты — FAIL**.
- [ ] **Step 3: реализовать** (uninstall через Runner: `systemctl disable --now mdns`, `daemon-reload`; удаление файлов по Root).
- [ ] **Step 4: `go test ./internal/installer/ ./internal/diag/ ./cmd/... -race -count=1` — PASS**.
- [ ] **Step 5: Commit** `git add internal/installer internal/diag cmd && git commit -m "feat: install, uninstall, status, diag and logs commands"`.

---

### Task 13: install.sh и `make dist-linux`

**Files:**
- Create: `install.sh` (корень репозитория)
- Modify: `Makefile`

**Interfaces:**
- `Makefile`: `dist-linux` — кросс-сборка `dist/mdns-linux-amd64`, `dist/mdns-linux-arm64` (`CGO_ENABLED=0`, `-ldflags -X mydns/internal/version.Version=$(VERSION)`) + `dist/SHA256SUMS` (формат `sha256sum`); `VERSION` уже вычисляется из `git describe`.
- `install.sh` (bash, `set -euo pipefail`): флаги `--local <bin>`, `--version vX.Y.Z`, остальное передаётся `mdns install "$@"`. Режим по умолчанию: `BASE=${MDNS_BASE_URL:-https://github.com/grendervill/mdns/releases}`; latest → `$BASE/latest/download`, версия → `$BASE/download/$VERSION`; скачать `mdns-linux-$ARCH` и `SHA256SUMS`, сверить `sha256sum -c`, поставить в `/usr/local/bin/mdns` (0755); затем `exec /usr/local/bin/mdns install "$@"`. `MDNS_BASE_URL` — тестовый хук (Task 14).
- ARCH: `x86_64→amd64`, `aarch64/arm64→arm64`.

- [ ] **Step 1: тест**: `bash -n install.sh` — синтаксис; `make dist-linux` — оба бинарника и `SHA256SUMS` на месте, сумма в файле совпадает с `shasum -a 256 dist/mdns-linux-<arch>`; проверить парсинг флагов (`--local`, `--version`) ревью-чтением скрипта. Полная проверка download-режима — Task 14 (в контейнере, где linux-бинарник исполним).
- [ ] **Step 2: полная проверка в Task 14** (download-режим через `MDNS_BASE_URL` на host-файл-сервер).
- [ ] **Step 3: реализовать**.
- [ ] **Step 4: `make dist-linux && ls dist/` — файлы и суммы на месте**.
- [ ] **Step 5: Commit** `git add install.sh Makefile && git commit -m "feat: install.sh bootstrap and dist-linux target"`.

---

### Task 14: docker e2e установщика (systemd-контейнер, download-режим)

**Files:**
- Create: `scripts/e2e-install.sh`

**Interfaces:**
- Скрипт: `make dist-linux`; host-файл-сервер (`python3 -m http.server 8931 -d dist`) → контейнер `ubuntu:24.04` c systemd: `docker run -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw -p 5300:53 -p 4430:443 ... /sbin/init` (если systemd не установлен — `apt-get install -y systemd` первым шагом через `docker exec`); внутри:
  - `bash -c 'curl -fsSL http://host.docker.internal:8931/install.sh | bash -s -- --non-interactive --domain mdns.test --tls self-signed --provider cloudflare --plain-port 53 --doh-port 443 --dot-port 853 --doq-port 853'` — download-режим через `MDNS_BASE_URL` (проверяет скачивание, SHA256, установку бинарника).
  - Assert'ы: `systemctl is-enabled mdns` && `is-active`; `dig @127.0.0.1 example.com` отвечает; юнит содержит `Restart=always`; файлы прав (конфиг 600, data dir 700).
  - Идемпотентность: второй прогон `install.sh --local ... --non-interactive ...` → сервис перезапущен, конфиг не перезаписан (sha256 конфига до/после равен).
  - Ошибка без полусостояния: `--domain "bad domain"` → exit≠0, `systemctl is-enabled mdns` не «enabled», сервис не запущен.
  - `mdns uninstall` (без --purge) → сервис снят, `/etc/mdns/config.json` на месте; повторный `install` → снова работает; `mdns uninstall --purge` → конфиг/данные удалены.
- В run.sh: печатать ключевые выводы и итоговый «e2e-install: passed».

- [ ] **Step 1: написать скрипт** по шагам выше.
- [ ] **Step 2: прогнать; красное — фиксить install.sh/installer**.
- [ ] **Step 3: прогнать повторно** (идемпотентность скрипта; контейнеры именуются и удаляются по trap).
- [ ] **Step 4: задокументировать в README (Task 17)**.
- [ ] **Step 5: Commit** `git add scripts && git commit -m "test: docker e2e for the installer"`.

---

### Task 15: CI — тесты на push

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Workflow: `on: [push, pull_request]`; job `test` (`ubuntu-latest`): `actions/checkout@v4`, `actions/setup-go@v5` c `go-version-file: go.mod`, кэш модулей; шаги: `test -z "$(gofmt -l .)"`, `go vet ./...`, `go test ./... -race -count=1`.

- [ ] **Step 1: написать workflow**.
- [ ] **Step 2: push и дождаться зелёного прогона** (`gh run watch`); при падении — фиксить, не ослаблять.
- [ ] **Step 3: закрепить бейдж в README (Task 17)**.
- [ ] **Step 4: `go test ./... -race -count=1` локально — PASS**.
- [ ] **Step 5: Commit** `git add .github && git commit -m "ci: vet, fmt and race tests on push"`.

---

### Task 16: релизный workflow, v0.1.0 и проверка «одной строки» из GitHub

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Workflow: `on: push: tags: ['v*']`; job: сборка `dist/mdns-linux-amd64`/`arm64` (`CGO_ENABLED=0`, версия из тега), `SHA256SUMS`, `gh release create` (или `softprops/action-gh-release@v2`) с файлами: оба бинарника, `SHA256SUMS`, `install.sh`.
- Последовательность: push main → `git tag -a v0.1.0 -m "mdns v0.1.0"` → push тега → `gh run watch` → `gh release view v0.1.0` → в systemd-контейнере (харнесс Task 14) без `MDNS_BASE_URL`: реальная строка `curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | bash -s -- --non-interactive …` ставит из реального релиза; `dig` отвечает.

- [ ] **Step 1: написать workflow**.
- [ ] **Step 2: commit + push + tag + push tag; релиз собран** (Actions зелёный).
- [ ] **Step 3: проверить содержимое релиза** (`gh release view`: оба бинарника, SHA256SUMS, install.sh; `gh release download -p SHA256SUMS` и сверка с локальной сборкой).
- [ ] **Step 4: реальный one-liner в контейнере — сервис работает**.
- [ ] **Step 5: Commit-закрепление** (если менялся README/теги) — отдельным `git commit` или аннотация тега.

---

### Task 17: README — установка, ACME, CLI

**Files:**
- Modify: `README.md`

**Interfaces:**
- Раздел «Установка (VPS)»: one-liner, `--version`, `--local`, что делает установщик (preflight, systemd, ufw, визард), сводка, `mdns uninstall [--purge]`.
- Раздел «Сертификаты»: режимы (Let's Encrypt/ZeroSSL EAB/свой ACME/self-signed/files), TLS-ALPN-01 vs HTTP-01 (когда порт DoH ≠ 443), поведение при неудаче (без TLS, бэкофф, авто-подъём), пути сертификатов, переживание переустановки.
- Раздел CLI: `status/diag/logs/install/uninstall/setup/serve/tui/check/version` одной таблицей.
- Тесты: `scripts/e2e-pebble.sh`, `scripts/e2e-install.sh`, бейдж CI.

- [ ] **Step 1: обновить README**.
- [ ] **Step 2: проверить все команды из README руками** (что не выполнимо локально — отметить).
- [ ] **Step 3: `markdownlint` нет — визуальная вычитка**.
- [ ] **Step 4: финальный прогон** `go test ./... -race -count=1`, `vet`, `gofmt -l .`.
- [ ] **Step 5: Commit** `git add README.md && git commit -m "docs: installation, certificates and CLI guide"`.

---

### Task 18: VPS — установка и проверка на реальном сервере (ждёт SSH-доступ от пользователя)

**Files:** — (ручной прогон по чек-листу)

**Interfaces:**
- Чек-лист: получить SSH-доступ; one-liner из README; визард (реальный домен, Let's Encrypt, email); дождаться `mdns status` → Cert ok; `dig @<vps> example.com` снаружи; DoH/DoT/DoQ с клиента; `systemctl status mdns`; ребут VPS → сервис поднялся, сертификат на месте; `mdns diag` чистый; при проблемах — фиксить, повторять.

- [ ] **Step 1: согласовать доступ и домен с пользователем**.
- [ ] **Step 2: установка одной строкой на VPS**.
- [ ] **Step 3: проверки из чек-листа (вывод — в отчёт)**.
- [ ] **Step 4: ребут-тест и `mdns diag`**.
- [ ] **Step 5: отчёт пользователю; сертификат/настройки сохраняем (удаляем только по явному запросу)**.

---

## Self-Review (при написании плана)

- **Spec coverage (§10/§11/§14/§16)**: ACME-провайдеры, вызовы, продление, hot reload, режим без TLS, повторный setup с валидным сертификатом — Tasks 1–9; установщик (preflight/действия/идемпотентность/--non-interactive/uninstall/сводка) — Tasks 10–14; CLI — Task 12; тестирование (pebble, systemd-контейнер, Playwright — панель в плане 5) — Tasks 8, 9, 14; хостинг/релизы — Tasks 13, 15, 16; VPS — Task 18.
- **Type consistency**: `tlscert.Source`/`Status` (Task 2) используются в Tasks 4–6; `acmecert.Options`/`Manager` (Task 3) — в Task 5; `api.Status.Cert` (Task 5) — в Tasks 6, 12; `installer.Options`/`Spec` (Tasks 10, 11) — в Tasks 12–14; `install.sh` передаёт те же флаги, что `Spec` (Task 13).
- **Review Focus → тесты**: 1) Task 5 `TestCertStatus…` + Task 9 фазы B; 2) Tasks 11 `TestInstallDryRun`/`TestIdempotentKeepsConfig` + 14; 3) Task 5 `TestTLSSwitch*` + Task 9 фаза D; 4) Task 9 фаза C; 5) Task 12 `TestUninstallKeepsData`/`TestUninstallPurge` + Task 14.
- **Риски исполнения**: systemd в Docker Desktop на macOS (privileged + cgroup v2) — при неработоспособности зафиксировать и согласовать fallback (job в GitHub Actions ubuntu-latest, где systemd-контейнеры работают); pebble образы могут требовать `--platform linux/<arch>`; `mdns.test` в pebble резолвится через challtestsrv (не /etc/hosts).
