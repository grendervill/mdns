# Panel Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the panel defects the first real user hit (clipped donuts, the upstream bootstrap loop that turned every result into «ошибка», missing ready-made lists/upstream editing) and add the requested timezone and period statistics.

**Architecture:** The daemon stays the single source of truth. Panel pages remain server-rendered forms; the only JS stays the SSE feed and chart tooltip. New behaviour lives behind the existing `UpdateConfig` transactional path; statistics history is a new in-process daily-bucket layer in `internal/stats`, persisted under `cfg.DataDir`.

**Tech Stack:** Go 1.26, miekg/dns, server-rendered html/template, vanilla JS + EventSource, Playwright e2e, Docker systemd e2e.

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md` plus this iteration's requirements in the conversation (user report 2026-10-18).

## Global Constraints

- One binary, no CDN, no new runtime dependencies. Panel copy is Russian.
- Panel security invariants stay: requireSession, CSRF, CSP `default-src 'self'`, no-store, disabled ⇒ 404.
- Config changes only through `UpdateConfig` (validate → apply → persist).
- `go test ./... -race`, `go vet`, `gofmt` must stay green; Playwright e2e twice before merge.
- Subagents: only `opencode-go/deepseek-v4.1-flash`. Never touch `main`.
- Do not regress: disabled 404, live auth, async filter refresh single-flight, CSV formula neutralization.

## Review Focus

1. A hostname upstream (DoH/DoT/DoQ/plain) must keep working when the system resolver points at the daemon itself — the bootstrap loop is the exact failure the user saw.
2. Adding/removing a list or upstream must not leave the daemon with no enabled upstream or a broken config; validation errors must render in the page, not a 500.
3. Timezone must be validated (IANA), must never change stored timestamps, and must apply to feed, history and CSV; an invalid stored value must fall back to local time, not panic.
4. Period statistics must not make the live counters lie: the all-time block keeps its meaning; range totals are sums of whole UTC days; range UI must clamp a reversed/future/too-old range.
5. Panel forms keep working on mobile (390 px) and remain keyboard/AT reachable; the new donut viewBox must not clip at hover either.

---

### Task 1: Bootstrap resolver + donut geometry

**Files:**
- Create: `internal/transport/bootstrap.go`, `internal/transport/bootstrap_test.go`
- Modify: `internal/transport/doh.go`, `dot.go`, `doq.go`, `plain.go`
- Modify: `internal/panel/templates/status.html`, `internal/panel/static/app.css`, `internal/panel/status_test.go`

**Interfaces:**
- Produces: `type bootstrapResolver struct`, `func newBootstrapResolver(servers []string) *bootstrapResolver`, `func (r *bootstrapResolver) dialContext(ctx context.Context, network, address string) (net.Conn, error)`; package default `defaultResolver` with servers `1.1.1.1:53`, `8.8.8.8:53`, `9.9.9.9:53`.
- `newDoH`/`newDoT`/`newDoQ`/`newPlain` route every hostname lookup through `defaultResolver`; IP literals bypass DNS.

**Steps:**
- [ ] Write `TestBootstrapResolvesAndCaches`: a fake UDP DNS server (miekg/dns) answers `upstream.test A 127.0.0.1`, TTL 60; `dialContext(ctx,"tcp","upstream.test:<local port>")` reaches a local listener; stop the DNS server; a second dial still succeeds from cache.
- [ ] Write `TestBootstrapFallsBackToSystem`: resolver with an unreachable server list resolves `localhost` via `net.DefaultResolver` (guard with a short test deadline).
- [ ] Write `TestDoHResolvesViaBootstrap`: local TLS DoH server, cert for `doh.test`; `newDoH` with `Address: https://doh.test:<port>/dns-query` and a resolver mapping `doh.test`→127.0.0.1; Exchange returns the reply. (Reuse the existing doh_test TLS fixture; constructor may take the resolver via an unexported variant for tests.)
- [ ] Wire DoT: dial the resolved IP, keep `ServerName` from cfg or URL host, then `tls.Client` handshake. Wire DoQ and Plain similarly; a hostname is resolved once per dial.
- [ ] `status.html`: `<svg viewBox="0 0 48 48">`, `cx="24" cy="24"`; `app.css` hover `stroke-width: 16px` (track stays 14). Add a status test asserting the markup.
- [ ] Verify: transport + panel suites, then a Docker check: in the demo container set `/etc/resolv.conf` to `nameserver 127.0.0.1`, restart `mdns`, query a fresh name — answer arrives (bootstrap used); restore the file.
- [ ] Commit `fix: bootstrap upstream hostnames and unclip the donuts`.

### Task 2: Ready-made filter lists + custom list

**Files:**
- Modify: `internal/panel/manage.go` (filters section), `internal/panel/templates/manage.html`, `internal/panel/manage_test.go`
- Reuse: `internal/filter.Catalog()`, `internal/filter.EntryByID`, `config.FilterList{ID,URL}`

**Interfaces:**
- New handlers: `POST /panel/filters/lists/add` (catalog `id`, or custom `custom_id`+`custom_url`), `POST /panel/filters/lists/remove` (`id`).
- `filtersView` gains `Catalog []catalogRow{ID,Name,Category,Description,Added}` and custom-form echo fields.
- After apply: 303 `?ok=list`; failures render the filters page with a Russian notice.

**Steps:**
- [ ] Tests: adding a catalog ID appends `FilterList{ID}` with empty URL; duplicate catalog add → 400; custom `https://…/hosts.txt` with an unused slug is stored; `http://` and empty host → 400; remove drops only that list; CSRF-less POST stays 403.
- [ ] Implement handlers with `cloneConfig`; validate custom ID (lowercase slug), unique ID, `https` URL, not a catalog duplicate; never silently enable filtering.
- [ ] Template: a «Готовые списки» grid (name, category badge, description, Добавить/Убрать) above the current status table; a «Свой список» form (ID, URL); keep the existing refresh/mode/rule forms.
- [ ] Verify panel suite + screenshot of the new section; commit `feat(panel): add the block-list catalog`.

### Task 3: Upstream management and strategy on the Upstreams page

**Files:**
- Modify: `internal/panel/manage.go` (upstreams section), `internal/panel/templates/manage.html`, `internal/panel/manage_test.go`
- Reuse: `internal/providers.List()` and `Endpoint`.

**Interfaces:**
- New handlers: `POST /panel/upstreams/add` (`provider`+`transport`), `POST /panel/upstreams/custom` (`id`,`name`,`transport`,`address`,`server_name`,`priority`), `POST /panel/upstreams/remove` (`id`), `POST /panel/upstreams/strategy` (`strategy`).
- `upstreamsView` gains `Endpoints []endpointOption{Value,Label}` and `StrategyOptions`.

**Steps:**
- [ ] Tests: adding a catalog endpoint stores a unique ID and the catalog address; duplicate address/transport → 400; custom upstream stores normalized fields; removing the only enabled upstream → 400; strategy saves each of the four names and rejects an unknown one.
- [ ] Implement: unique ID (`provider` else `provider-transport` else `-2`…), duplicate address+transport rejection, priority = max+1; validate transport/address; render errors in place.
- [ ] Template: strategy select + «Добавить из каталога» (provider/transport dropdown + submit) + «Свой upstream» fields; each row gets a «Удалить» form next to the toggle; keep priority/toggle forms.
- [ ] Also rename the Settings password section to «Пароль веб-панели» (the feature exists; make it discoverable).
- [ ] Verify panel suite + screenshot; commit `feat(panel): add upstreams and strategy management`.

### Task 4: Timezone setting

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `cmd/mdns/main.go` (blank `time/tzdata`)
- Modify: `internal/panel/manage.go` (settings), `templates/manage.html`
- Modify: `internal/panel/status.go`, `history.go`, `manage.go` (formatting), tests

**Interfaces:**
- `Config.Timezone string` (`json:"timezone,omitempty"`), empty = daemon local; `Validate` accepts only loadable IANA names.
- `func (p *Panel) location() *time.Location` reads the live config and falls back to `time.Local`.
- `rowViewFor(e qlog.Entry, loc *time.Location)`, `rowsFor(entries, loc)`, `historyCSVRecord(e, loc)`; call sites pass `p.location()`.

**Steps:**
- [ ] Tests: config accepts `Europe/Moscow`, rejects `Mars/Base`, empty stays local; status feed renders 12:00 UTC as 15:04:05 MSK; history table and CSV use the same; settings POST persists; an unknown stored zone does not panic.
- [ ] Add the `timezone` field to the Settings form as a text input with a datalist of common zones (`Europe/Moscow`, `Europe/London`, `Europe/Berlin`, `Asia/Almaty`, `Asia/Tbilisi`, `Asia/Dubai`, `America/New_York`, `UTC`) and a hint «IANA, пусто = системный».
- [ ] Apply the location to feed rows, history rows, CSV; leave stored `Entry.Time` untouched. Certificate dates may keep their current formatting.
- [ ] Verify panel suite + a visual check; set the demo to `Europe/Moscow` after deploy; commit `feat: make panel time follow a configurable timezone`.

### Task 5: Statistics history and the period selector

**Files:**
- Modify: `internal/stats/stats.go`, new `internal/stats/history.go`, `internal/stats/history_test.go`
- Modify: `internal/app/app.go`, `control.go`, `internal/panel/panel.go` (Controller), `status.go`, `templates/status.html`, tests

**Interfaces:**
- `Collector.SnapshotRange(from, to time.Time) Snapshot` — whole UTC days, `from`/`to` inclusive; zero bound means open.
- `Collector.Save(path string) error` / `Collector.Load(path string) error` — JSON v1, atomic temp+rename, 0600; cumulative counters and ≤400 daily buckets (outcomes, protos, upstreams, clients capped 256/day + overflow).
- `App.StatsRange(from, to time.Time) stats.Snapshot`; `Controller` gains it.
- Panel: `GET /panel/?period=30|90|180|365|custom&from=YYYY-MM-DD&to=YYYY-MM-DD`; default 30 days. Top four gauges stay all-time; below them a period form + period totals (total/blocked/cached/errors) + the four donuts built from the range snapshot.

**Steps:**
- [ ] Tests (stats): day rollover with an injected clock; range sums only included days; client aggregation top-20 + «остальные»; retention prunes; Save/Load round-trip restores cumulative and days; concurrent Observe/SnapshotRange.
- [ ] Implement history in `stats`, prune to 400 days, keep `Observe` cheap (one mutex as today).
- [ ] App: load `cfg.DataDir/stats.json` in New (warn on error), save every 30 s from `Start`'s appCtx and once in `Stop`; `StatsRange` delegates. Empty/unwritable path must not stop the daemon.
- [ ] Panel: parse/clamp the period; invalid or reversed custom range → notice + 30 days; `fillDonuts` takes the range snapshot; add the form and period summary, labels in Russian; keep donut links to history.
- [ ] Tests (panel): default 30 days; custom range forwarded; reversed range rejected; zero-history renders; the all-time gauges do not change with the period.
- [ ] Verify suite, restart persistence (start daemon, query, stop, start, totals survive), visual screenshot; commit `feat: add period statistics with persistent daily history`.

### Task 6: Integration verification and release

**Steps:**
- [ ] Full `go test ./... -race`, vet, gofmt; extend Playwright e2e for: catalog list add, custom upstream add + strategy change, timezone save (feed shows the chosen zone), period selector; run twice.
- [ ] Rebuild the Linux binary and reinstall the local demo by the real one-liner; verify the loop scenario (container resolver → 127.0.0.1) and the user's Mac DNS flow.
- [ ] Visual pass on status/history/filters/upstreams/settings at 1440 px and 390 px; refresh `docs/img` and `e2e/panel/shots`.
- [ ] Branch review (independent subagent), fixes, PR, merge, tag `v0.3.0`, release workflow, real one-liner smoke.
