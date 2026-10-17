# mdns — фильтрация: план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Собственный движок блок-листов в ядре mdns: парсер доменных
списков (adblock-подмножество, hosts, простые списки), суффиксный индекс с
приоритетами правил, загрузка/обновление списков по HTTPS с дисковым кэшем
и атомарной подменой, пользовательские правила, счётчики и интеграция в
pipeline ядра (блокировка до кеша и до upstream, одинаково для всех
протоколов и клиентов).

**Architecture:** Новый пакет `internal/filter`: `set.go` (суффиксный
набор на generic-мапе), `parse.go` (построчный классификатор форматов),
`engine.go` (индекс, приоритеты, счётчики, `Check`, атомарная подмена через
`atomic.Pointer[Index]`), `catalog.go` (каталог списков и пресеты),
`updater.go` (загрузка по HTTPS, ETag/If-Modified-Since, дисковый кэш,
расписание, статусы). Интеграция: `core` получает узкий интерфейс
`Filter` и режим блокировки; `app` собирает движок из конфига и запускает
апдейтер; конфиг получает секцию `filter` и `data_dir`.

**Tech Stack:** Go 1.26 (модуль `mydns`), стандартная библиотека
(`net/http`, `atomic`, `bufio`, `encoding/json`), `github.com/miekg/dns`
для синтеза блокирующих ответов. Никаких сторонних парсеров/движков
фильтрации — всё своё (решение дизайна).

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md`, раздел 9
(Фильтрация), а также §6 (FilterEngine), §15 (тесты), §17 (дорожная
карта). Предыдущий план ядра: `docs/superpowers/plans/2026-10-17-mdns-core.md`.

## Global Constraints

- Порядок обработки запроса в ядре: пользовательское разрешение (allow)
  → пользовательская блокировка → исключения списков (`@@`) → правила
  списков. Фильтрация — до кеша и до форварда; заблокированный домен
  никогда не отдаётся из кеша и не уходит к upstream.
- Режимы блокирующего ответа: `zero` (по умолчанию: A → `0.0.0.0`,
  AAAA → `::`, прочие типы → NOERROR без ответа), `nxdomain`, `refused`.
  TTL блокирующего ответа — 10 секунд (константа с комментарием; так
  делают публичные блокировщики, чтобы разблокировка вступала в силу
  быстро).
- Фильтр по умолчанию выключен (`filter.enabled: false`); включение и
  пресеты каталога — через конфиг (визард — в плане управления).
- Загрузка списков: только `https`, таймаут 60s, максимум 128 MiB на
  список, ETag/If-Modified-Since, ошибка загрузки не ломает текущий
  рабочий набор, подмена набора — атомарная.
- Интервал автообновления по умолчанию 24h; `0` — только вручную;
  первая сетевая загрузка — сразу при старте, после загрузки сохранённых
  данных с диска.
- Данные: `data_dir` (по умолчанию `/var/lib/mdns`); каждый список —
  `<data_dir>/filters/<id>.rules` (строки `+domain` блок, `-domain`
  исключение) и `<id>.meta.json` (URL, etag, last_modified, updated_at,
  применено/пропущено).
- Пользовательские правила: домен действует на него самого и все
  поддомены.
- Нормализация имён: нижний регистр, без завершающей точки. Списки уже
  в punycode (DNS wire — ASCII), перекодирование не делаем.
- Счётчики: применено/пропущено правил по каждому списку, попадания по
  спискам, всего заблокировано, топ-50 доменов.
- Тестовые команды: `go test ./... -race -count=1`, `go vet ./...`,
  `gofmt -l .` — чисто. Тесты не ходят в интернет (только httptest).

## Review Focus

Классы входов/условий, которые дизайн подразумевает, но легко забыть; на
каждый пункт в задачах заведён тест с пометкой **Review Focus**:

1. Домен в другом регистре, с завершающей точкой или punycode из списка —
   матчится (нормализация с обеих сторон).
2. Список недоступен, но на диске есть старая копия — работает старая
   копия, сервис не падает, ошибка видна в статусе.
3. Домен был закеширован до включения правила — после правила он всё
   равно блокируется (фильтр раньше кеша).
4. Конкурентные запросы во время атомарной подмены индекса (обновление
   списка) — без гонок и паник.
5. Мусор в списке (битые строки, косметика, огромная строка) — не падает,
   попадает в skipped с подсчётом.

---

### Task 1: Конфиг — секция `filter` и `data_dir`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: существующий `config.Config`.
- Produces:

```go
type FilterList struct {
    ID  string `json:"id"`
    URL string `json:"url,omitempty"` // пусто: взять из каталога по ID
}
type FilterConfig struct {
    Enabled             bool         `json:"enabled"`
    Mode                string       `json:"mode"` // zero | nxdomain | refused
    UpdateIntervalHours int          `json:"update_interval_hours"` // 0 = вручную
    Lists               []FilterList `json:"lists"`
    UserAllow           []string     `json:"user_allow"`
    UserBlock           []string     `json:"user_block"`
}
// Config добавляет:
//   DataDir string       `json:"data_dir"`
//   Filter  FilterConfig `json:"filter"`
```

Дефолты: `DataDir: "/var/lib/mdns"`, `Filter.Mode: "zero"`,
`Filter.UpdateIntervalHours: 24`, `Filter.Enabled: false`.

Валидация: `mode` из набора; `update_interval_hours >= 0`; ID списков
непустые и уникальные; заданный `url` — валидный URL со схемой `https`;
`user_allow`/`user_block` — без пробелов и схем; `data_dir` непустой.

- [ ] **Step 1: Падающие тесты** (таблица в `config_test.go`)

- `TestFilterDefaults`: `Default().Filter.Mode == "zero"`, интервал 24, выключен, `DataDir == "/var/lib/mdns"`;
- `TestValidateFilterTable`: ошибки — mode `bogus`; интервал `-1`; два списка с одним ID; пустой ID; `url: "http://x/list.txt"`; user-правило с пробелом; пустой `data_dir`. Валидные — кастомный список без URL (возьмётся из каталога), интервал 0.
- Roundtrip-тест дополняется секцией `filter`.

- [ ] **Step 2: `go test ./internal/config/` — FAIL**
- [ ] **Step 3: Реализовать** (поля, дефолты, валидация — по сигнатурам выше)
- [ ] **Step 4: `go test ./internal/config/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/config && git commit -m "feat: filter configuration and data directory"
```

---

### Task 2: Суффиксный набор

**Files:**
- Create: `internal/filter/set.go`
- Test: `internal/filter/set_test.go`

**Interfaces:**
- Consumes: ничего.
- Produces:

```go
// suffixSet — домены с суффиксным матчингом: правило «d» покрывает d и
// все его поддомены. value ищет самый длинный совпавший суффикс.
type suffixSet[T any] map[string]T

func (s suffixSet[T]) add(domain string, v T)
func (s suffixSet[T]) value(numLabels []string) (T, bool) // поиск по уже разложенному имени
func normalizeName(name string) string                     // нижний регистр, без завершающей точки
func labels(name string) []string                          // "a.b.com." → ["a","b","com"]
```

- [ ] **Step 1: Падающие тесты**

- `TestSuffixSetExactAndSub`: `add("b.c.com")`; матч `b.c.com`, `a.b.c.com`; не матч `c.com`, `other.com`;
- `TestSuffixSetCaseAndDot` (**Review Focus №1**): `add("Example.COM")`, матч `A.B.example.com.`;
- `TestSuffixSetLongestValue`: `add("c.com", "outer")`, `add("b.c.com", "inner")` → `value(a.b.c.com)` == `"inner"`;
- `TestSuffixSetMiss`: пустое множество, нерелевантные имена.

- [ ] **Step 2: `go test ./internal/filter/ -run TestSuffixSet` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/filter/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/filter && git commit -m "feat: suffix domain set for filter rules"
```

---

### Task 3: Парсер списков

**Files:**
- Create: `internal/filter/parse.go`
- Test: `internal/filter/parse_test.go`

**Interfaces:**
- Consumes: `normalizeName` (Task 2).
- Produces:

```go
// Parsed — результат разбора одного списка.
type Parsed struct {
    Block   []string // уникальные домены, по строке на домен
    Except  []string // исключения @@
    Applied int      // принято правил (уникальных)
    Skipped int      // отброшено (косметика, модификаторы, мусор, oversize)
}
func Parse(r io.Reader) (Parsed, error)
```

Построчный классификатор (каждая строка независимо):

- строки, начинающиеся с `!`, — комментарий; `#` в начале со следующим
  пробелом или в конце строки, а также `#` после данных — комментарий
  (обрезается); `##`, `#@#`, `#?#` — косметика, `skipped`;
- `||domain^` → блок (домен нормализуется); `@@||domain^` → исключение;
  `@@domain` → исключение; такой же разбор допустим с завершающей `.`;
- правила с `$` (модификаторы `$important`, `$third-party` и т.п.),
  `*`, `/`, `|` не в начале, и любые нетокенные конструкции —
  `skipped` (счётчик **Review Focus №5**);
- hosts-строки: первый токен — `0.0.0.0`, `127.0.0.1`, `::` или `::1`,
  второй токен — домен → блок; больше двух токенов — `skipped`;
- одиночный валидный домен (не менее двух меток, только `a-z0-9-`,
  метка не начинается/не кончается дефисом) → блок;
- пустые строки — пропускаются без счёта; строки длиннее 1 MiB —
  `skipped`;
- домены: нижний регистр, без завершающей точки, дедупликация.

- [ ] **Step 1: Падающие тесты** (таблица «вход → ожидаемые Block/Except/Applied/Skipped»)

Покрыть: `! comment`; `# comment`; `##.banner` (skip); `0.0.0.0 ads.x.com`; `127.0.0.1 a.b.com # inline`; `::1 v6.example.com`; `||ads.example.com^`; `@@||good.example.com^`; `||x.com^$third-party` (skip); `||x.com^$important` (skip); `example.com` (block); `EXAMPLE.COM.` (block, нормализация — **Review Focus №1**); `not a domain` (skip); `*/ads/*` (skip); строка 2 MiB (skip, не падает — **Review Focus №5**); `0.0.0.0 a.com b.com` (skip).

- [ ] **Step 2: `go test ./internal/filter/ -run TestParse` — FAIL**
- [ ] **Step 3: Реализовать** (чтение через `bufio.Reader.ReadString`, лимит строки 1 MiB)
- [ ] **Step 4: `go test ./internal/filter/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/filter && git commit -m "feat: block-list parser with per-format classification"
```

---

### Task 4: Движок — индекс, приоритеты, счётчики

**Files:**
- Create: `internal/filter/engine.go`
- Test: `internal/filter/engine_test.go`

**Interfaces:**
- Consumes: `suffixSet` (Task 2), `Parsed` (Task 3).
- Produces:

```go
// CompiledList — разобранный список, готовый к установке в движок.
type CompiledList struct {
    ID     string
    URL    string
    Block  []string
    Except []string
}
type EngineOptions struct {
    UserAllow []string
    UserBlock []string
    Logger    *slog.Logger
}
type Engine struct { /* ... */ }
func NewEngine(opts EngineOptions) *Engine

// SetList заменяет список и атомарно пересобирает индекс.
func (e *Engine) SetList(l CompiledList)
func (e *Engine) RemoveList(id string)
// Check — приоритеты из дизайна: user allow → user block → список @@ → список.
func (e *Engine) Check(qname string) (blocked bool, source string)
func (e *Engine) Stats() Stats

type ListStat struct { ID string; Block, Except int; Hits uint64 }
type DomainCount struct { Domain string; Count uint64 }
type Stats struct {
    TotalBlocked uint64
    Lists        []ListStat  // по порядку установки
    Top          []DomainCount // ≤ 50, по убыванию
}
```

Реализация: `Index` неизменяем; хранится в `atomic.Pointer[Index]`;
`SetList`/`RemoveList` мутируют карту списков под mutex и публикуют новый
индекс. Источник блокировки — первый список (в порядке установки),
который покрыл имя. Топ-домены: map с лимитом 4096 записей (новые сверх
лимита не добавляются), сортировка при `Stats()`.

- [ ] **Step 1: Падающие тесты**

- `TestCheckPriorities`: userConflict: user allow `x.com` + user block `x.com` → НЕ блокировка (allow выше); user block vs list except: block побеждает; list `@@` перекрывает list-блок;
- `TestCheckSuffix`: блок `ads.example.com` → `sub.ads.example.com` тоже блокируется;
- `TestCheckSource`: два списка блокируют `a.com` и `b.a.com` → source глубокого (`b.a.com`);
- `TestSetListReplaces`: замена списка снимает старые блокировки;
- `TestRemoveList`: удаление работает;
- `TestStatsCounters`: total, hits по спискам, топ-домены сортирован;
- `TestCheckConcurrentReload` (**Review Focus №4**): 8 горутин дёргают `Check` 1000 раз каждая, параллельно `SetList` 100 раз — под `-race` без гонок;
- `TestNormalization` (**Review Focus №1**): блок `Example.COM` ловит `ADS.example.com.`.

- [ ] **Step 2: `go test ./internal/filter/ -run 'TestCheck|TestSet|TestRemove|TestStats' -race` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/filter/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/filter && git commit -m "feat: filter engine with rule priorities and atomic reload"
```

---

### Task 5: Каталог списков и пресеты

**Files:**
- Create: `internal/filter/catalog.go`
- Test: `internal/filter/catalog_test.go`

**Interfaces:**
- Consumes: ничего.
- Produces:

```go
type CatalogEntry struct {
    ID, Name, URL, Category, Description string
}
func Catalog() []CatalogEntry          // статический список
func EntryByID(id string) (CatalogEntry, bool)
func Preset(name string) ([]string, bool) // "basic" | "strict"
```

Состав каталога (URL выверяются при реализации: доступность и актуальный
host через curl; в тестах — только структурные проверки):

- Реклама/трекеры: `adguard-dns-filter`, `adguard-base`, `ublock-filters`,
  `easylist-domains`, `peter-lowe`;
- Комплексные: `oisd-small`, `oisd-full`, `hagezi-pro`, `hagezi-proplus`,
  `stevenblack-unified`, `1hosts-lite`.

Пресеты: `basic` — умеренный набор (adguard-dns-filter, oisd-small);
`strict` — максимум (adguard-base, ublock-filters, oisd-full,
hagezi-proplus).

- [ ] **Step 1: Падающие тесты**

- `TestCatalogShape`: непустые ID/Name/URL/Category; `url.Scheme == "https"` и непустой host у всех; ID уникальны (set);
- `TestPresetRefsExist`: каждый ID в `basic`/`strict` есть в каталоге; неизвестный пресет → `false`.

- [ ] **Step 2: `go test ./internal/filter/ -run 'TestCatalog|TestPreset'` — FAIL**
- [ ] **Step 3: Реализовать** (данные + функции)
- [ ] **Step 4: Ручная выверка URL** (не тест): `curl -sI <url>` по каждому — 200/302 и `text/plain`; зафиксировать результат в отчёте задачи; неверные URL поправить.
- [ ] **Step 5: `go test ./internal/filter/ -race` — PASS**
- [ ] **Step 6: Commit**

```bash
git add internal/filter && git commit -m "feat: block-list catalog and presets"
```

---

### Task 6: Загрузка, дисковый кэш и обновление

**Files:**
- Create: `internal/filter/updater.go`
- Test: `internal/filter/updater_test.go`

**Interfaces:**
- Consumes: `Parse` (Task 3), `Engine` (Task 4).
- Produces:

```go
type ListSpec struct { ID, URL string }
type ListStatus struct {
    ID        string
    URL       string
    UpdatedAt time.Time // время последнего успешного обновления
    Applied   int
    Skipped   int
    FromDisk  bool
    Error     string // последняя ошибка (пусто при успехе)
}
type UpdaterOptions struct {
    Engine  *Engine
    Specs   []ListSpec
    DataDir string
    Client  *http.Client // nil: &http.Client{Timeout: 60s}
    MaxBytes int64       // nil-значение 0: 128 MiB
    Logger  *slog.Logger
}
type Updater struct { /* ... */ }
func NewUpdater(opts UpdaterOptions) *Updater

// LoadFromDisk читает сохранённые списки и устанавливает их в движок;
// отсутствие файлов — не ошибка.
func (u *Updater) LoadFromDisk() error
// Update скачивает и применяет каждый список; ошибки отдельных списков
// не прерывают остальные.
func (u *Updater) Update(ctx context.Context)
// Run делает первый Update сразу и далее по интервалу (0 — выключено).
func (u *Updater) Run(ctx context.Context, interval time.Duration)
func (u *Updater) Status() []ListStatus
```

Поведение: URL вне `https` → ошибка списка (не загрузка); `If-None-Match`
/`If-Modified-Since` из meta; `304` → статус «актуален», данные не
пересобираются; `200` → тело ограничено 128 MiB (превышение — ошибка);
парсинг → запись `<id>.rules`/`<id>.meta.json` атомарно (tmp+rename) →
`Engine.SetList`. При ошибке сети/парсинга — старые данные в движке
сохраняются, в статусе ошибка (**Review Focus №2** в Task 8 через app,
здесь — юнит с сервером, который падает после первого успеха).

- [ ] **Step 1: Падающие тесты** (httptest.NewTLSServer, клиент с `InsecureSkipVerify` из теста; `t.TempDir()` как DataDir)

- `TestUpdateFetchesAndApplies`: TLR-сервер отдаёт список; `Update` → движок блокирует домен; на диске есть `.rules` и `.meta.json`;
- `TestUpdateConditional304`: сервер требовал заголовки и вернул 304 на втором проходе (счётчик запросов 2, `UpdatedAt` не изменился);
- `TestUpdateFailureKeepsOldData` (**Review Focus №2**): первый `Update` успешен; сервер выключен; второй `Update` → движок по-прежнему блокирует, `Status().Error != ""`;
- `TestUpdateRejectsHTTP`: `http://` URL → ошибка статуса, движок пуст;
- `TestUpdateTooLarge`: сервер отдаёт больше лимита (лимит уменьшается тестом через маленький... — параметр `MaxBytes int64` в `UpdaterOptions`, дефолт 128 MiB) → ошибка;
- `TestLoadFromDisk`: записать дисковые файлы вручную → `LoadFromDisk` → движок блокирует; отсутствие каталога — не ошибка;
- `TestRunFirstUpdateImmediateAndStops`: `Run` с интервалом 20ms — счётчик обновлений > 1 за 70ms, выход по ctx.

- [ ] **Step 2: `go test ./internal/filter/ -run TestUpdate|TestLoadFromDisk|TestRun` — FAIL**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./internal/filter/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/filter && git commit -m "feat: list updater with conditional fetch, disk cache and atomic swap"
```

---

### Task 7: Интеграция в ядро — блокировка до кеша

**Files:**
- Modify: `internal/core/core.go`
- Test: `internal/core/core_test.go`

**Interfaces:**
- Consumes: `Engine.Check` (Task 4).
- Produces:

```go
// В internal/core:
type Filter interface {
    Check(qname string) (blocked bool, source string)
}
// Сигнатура New меняется (обновить app и тесты):
func New(r Resolver, c *cache.Cache, l *qlog.Log, f Filter, mode string, logger *slog.Logger) *Core
```

Поведение `Resolve`: после проверки вопроса и **до** обращения к кешу:
`f.Check(qname)` (nil-безопасно) → при блокировке синтезировать ответ по
`mode` (TTL 10s) и записать в журнал `Blocked=true`, `BlockSource=source`;
кеш и resolver не затрагиваются. Существующий задел `qlog.Entry.Blocked`
/`BlockSource` уже есть.

- [ ] **Step 1: Падающие тесты** (мок `Filter` в тесте)

- `TestFilterBlocksBeforeCache` (**Review Focus №3**): домен посеяли в кеш (`cacheStore.Put`), блокирующий фильтр → ответ блокировки, resolver не вызван, кеш не отдал старый ответ;
- `TestFilterBlockModes`: `zero` — A→`0.0.0.0`, AAAA→`::`, TXT→NOERROR пусто, TTL 10; `nxdomain` → NXDOMAIN; `refused` → REFUSED;
- `TestFilterAllowPasses`: `Check` вернул `false` → обычный путь (resolver вызван);
- `TestFilterNil`: фильтр nil → поведение как раньше;
- `TestFilterLogsBlocked`: запись журнала с `Blocked=true` и `BlockSource`.

- [ ] **Step 2: `go test ./internal/core/ -run TestFilter` — FAIL**
- [ ] **Step 3: Реализовать** (обновить существующие вызовы `core.New` в тестах)
- [ ] **Step 4: `go test ./internal/core/ -race` — PASS; `go build ./...` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/core && git commit -m "feat: filter stage in the core pipeline"
```

---

### Task 8: Сборка приложения — движок, апдейтер, старт/стоп

**Files:**
- Modify: `internal/app/app.go`
- Test: `internal/app/app_test.go`

**Interfaces:**
- Consumes: всё из `internal/filter`, `core.Filter`.
- Produces:

```go
// Options дополняется:
type Options struct {
    Monitor        upstream.MonitorOptions
    FilterClient   *http.Client    // тесты; nil → таймаут 60s
    FilterInterval time.Duration   // тесты; 0 → из конфига
}
// App получает:
func (a *App) Filter() *filter.Engine
func (a *App) FilterStatus() []filter.ListStatus // nil при выключенном фильтре
```

Проводка `app.New`: при `cfg.Filter.Enabled` — собрать `Engine`
(UserAllow/UserBlock), `Updater` со спеками (ID+URL: URL из конфига, при
пустом — из каталога `EntryByID`; неизвестный ID без URL — ошибка
конфигурации), `engine.LoadFromDisk()`. `app.Start` — `go
updater.Run(ctx, interval)`. `app.Stop` — как сейчас (ctx отменяется).
При выключенном фильтре — `filter == nil`, ядро работает как раньше.

- [ ] **Step 1: Падающие тесты**

- `TestAppFilterBlocks` (**Review Focus №2** и интеграция): `httptest.NewTLSServer` отдаёт список `||ads.example.com^`; конфиг: фильтр включён, один список с URL сервера, `Options.FilterClient` с `InsecureSkipVerify`, `FilterInterval: 50ms`; старт → пауза до применения (опрос `App.Filter().Stats().Lists > 0`) → A-запрос `ads.example.com` → `0.0.0.0`; `example.com` → от fake; сервер выключить, дождаться ошибки в `Updater.Status()` (через `App.Filter()`... статусы апдейтера — добавить `App.FilterStatus()`), запрос всё ещё блокируется;
- `TestAppFilterDisabled`: фильтр выключен → `App.Filter() == nil`, обычная работа.

- [ ] **Step 2: `go test ./internal/app/ -run TestAppFilter` — FAIL**
- [ ] **Step 3: Реализовать** (включая маленький аксессор статусов)

Хм: `App.FilterStatus()` тянет `Updater.Status()` — экспортировать метод у App: `FilterStatus() []filter.ListStatus` (nil при выключенном фильтре). Это граница для будущего API — не расширять дальше.

- [ ] **Step 4: `go test ./internal/app/ -race` — PASS**
- [ ] **Step 5: Commit**

```bash
git add internal/app && git commit -m "feat: filter wiring in the application"
```

---

### Task 9: E2E — блокировка по всем протоколам

**Files:**
- Create: `internal/app/filter_e2e_test.go`

**Interfaces:**
- Consumes: `app`, `transport` (как клиенты), `dnsfake`, httptest-список.

- [ ] **Step 1: Написать тест** `TestFilterEndToEndAllProtocols`

Сценарий:
1. Fake upstream (отвечает `192.0.2.1`); httptest-список: блок `ads.example.com`, исключение `@@||good.ads.example.com^`, user_block `manual.example.com`, user_allow `manual.example.com` НЕ добавляем — в конфиге только блок; плюс отдельный кейс allow: `user_allow: ["allowed.example.com"]`, а список блокирует `allowed.example.com`.
2. Конфиг: все четыре протокола на высоких портах; фильтр включён; интервал 50ms; TTL upstream-ответов 1s.
3. Дождаться применения списка; проверить по всем четырём протоколам:
   - `ads.example.com` → `0.0.0.0` (zero-режим), fake-апстрим для этих запросов не вызывался (счётчик его A-запросов не растёт);
   - `good.ads.example.com` → `192.0.2.1` (исключение);
   - `allowed.example.com` → `192.0.2.1` (user allow поверх блок-правила списка);
   - `manual.example.com` → `0.0.0.0` (user block).
4. Ответ `ads.example.com` повторно → по-прежнему `0.0.0.0` (блокировка не кеширует и не кешируется).
5. Остановить приложение — чисто.

- [ ] **Step 2: `go test ./internal/app/ -run TestFilterEndToEnd -race -count=1` — PASS**
- [ ] **Step 3: Commit**

```bash
git add internal/app && git commit -m "test: end-to-end filtering across all protocols"
```

---

### Task 10: Техдолг ядра из финального ревью

**Files:**
- Modify: `internal/config/config.go` (+test), `internal/cache/cache.go` (+test), `internal/dnsserver/server.go`, `internal/routing/router.go` (+test), `cmd/mdns/main.go`

**Interfaces:**
- Consumes: существующий код ядра.
- Produces: закрытые отложенные minor-находки ревью (без изменения
  публичных контрактов):

- `config.Validate`: `cache.size >= 1`; `cache.min_ttl <= cache.max_ttl`;
- `cache.Get`: из отдаваемой копии EDNS0-ответа вычищаются опции COOKIE (`dns.EDNS0_COOKIE`) — чужой cookie первого клиента не должен уходить второму (RFC 7873);
- `dnsserver.Server.Shutdown`: возвращает первую ошибку остановки листенеров (`stopLocked` собирает ошибки `ShutdownContext`/`Close`);
- `routing.Router.Exchange`: защита от `(nil, nil)` от транспорта (считать ошибкой и идти к следующему);
- `cmd/mdns`: убрать избыточный `os.Exit(0)` в ветке `version`;
- package-doc `internal/dnsserver`: актуальный текст (все листенеры уже здесь).

- [ ] **Step 1: Падающие тесты**

- config: `size 0` и `min > max` → ошибки;
- cache: `TestGetStripsCookies` — ответ с OPT и `EDNS0_COOKIE` → после `Get` опции cookie нет, DO-бит и прочие опции живы;
- routing: `TestRouterNilResponseIsFailure` — транспорт вернул `(nil, nil)` → ошибка, следующий upstream получает запрос;
- dnsserver/routing: остальные правки — без новых тестов (поведение при ошибках остановки; текст).

- [ ] **Step 2: Прогон целевых тестов — FAIL (где применимо)**
- [ ] **Step 3: Реализовать**
- [ ] **Step 4: `go test ./... -race -count=1` — PASS; `go vet ./...`; `gofmt -l .` — чисто**
- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "fix: core review follow-ups (cookie strip, validation, shutdown errors)"
```

---

### Task 11: Документация

**Files:**
- Modify: `README.md`, `examples/config.json`

- [ ] **Step 1: examples/config.json** — добавить `data_dir` и секцию `filter` (выключен, mode zero, интервал 24, пустые списки/правила); `mdns check` проходит.
- [ ] **Step 2: README** — секция Filter: как включить, режимы, каталог/пресеты, формат списка и дисковых файлов, счётчики.
- [ ] **Step 3: Ручной smoke**: включить в локальном конфиге фильтр с одним реальным списком по HTTPS (например, oisd-small): запустить, дождаться загрузки (проверить статус), затем `dig` реального домена из списка (для тестовых пресетов подойдёт домен вида рекламного трекера, который присутствует в списке — проверить `grep` по сохранённому файлу) → должен вернуться блокирующий ответ; разблокированный домен (`example.com`) → нормальный ответ. Зафиксировать вывод в отчёте.
- [ ] **Step 4: `go test ./... -race -count=1` — PASS**
- [ ] **Step 5: Commit**

```bash
git add README.md examples && git commit -m "docs: filtering guide and example config"
```

---

## Self-Review (при написании плана)

- **Spec coverage (§9)**: назначение — Tasks 2–9; порядок обработки — Tasks 4, 7; форматы — Task 3; каталог/пресеты — Task 5; обновление — Task 6; реакция на блокировку — Task 7; пользовательские правила — Tasks 4, 8; производительность/атомарность — Tasks 2, 4, 6. Пресеты для визарда — данные в Task 5, UI — план управления.
- **Type consistency**: `Check(qname) (bool, string)` — у `Engine` (Task 4), интерфейса `core.Filter` (Task 7) и моков (Task 7/9) совпадает. `ListStatus` определён в Task 6 и используется в Task 8 (`FilterStatus`). `Parsed` (Task 3) → `CompiledList` (Task 4) — поля совпадают по смыслу (Block/Except/Applied/Skipped).
- **Review Focus**: каждый пункт привязан к конкретному тесту в задачах 2, 3, 4, 6, 7.
- **Риски исполнения**: точные URL каталога проверяются руками в Task 5 (Step 4); большие реальные списки в тестах не скачиваются — только httptest.
