# goDNS-parity iteration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bring four capabilities we saw in goDNS Pro (probe before save, secret DoH path, config backups with restore/migration, live request screen) and split the README into clean Russian and English versions with language links.

**Architecture:** Everything stays inside the existing single binary. Config gains a DoH path; the panel gains a probe action, backup management on Обслуживание and a new live page; backups are plain JSON snapshots of the config under `DataDir/backups` restored through the same validated `UpdateConfig` path. No new runtime dependencies, no frontend build step.

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md`; user request 2026-10-19 (parity with goDNS Pro).

## Global Constraints

- One binary, no CDN; panel copy Russian; code comments English.
- Panel invariants: requireSession, CSRF, CSP `default-src 'self'`, no-store, disabled ⇒ 404.
- All config changes go through `UpdateConfig` (validate → apply → persist); restore is an `UpdateConfig` of the migrated file.
- `go test ./... -race`, `vet`, `gofmt` green; Playwright e2e green before merge; subagents only `opencode-go/deepseek-v4.1-flash`; main untouched.

## Review Focus

1. The DoH path must not overlap the panel/login/static routes and must not break existing device links, wizard output or the e2e; changing it must not lock the panel out.
2. Probe results must never mutate state, never block the request longer than the probe budget, and must render failures truthfully.
3. Backups: restore must run the normal config load/migration and never leave a half-applied config; retention bounded; files 0600 in a 0700 dir; a restore is itself snapshotted first.
4. The live screen must not slow the hot path (shared ring under one mutex), must bound memory, and must escape every field.
5. README: both files complete and self-consistent; no mixed-language prose beyond verbatim UI labels.

---

### Task A: Secret DoH path

**Files:** `internal/config/config.go`, `internal/dnsserver/doh.go` (+ tests), `internal/links/*`, `internal/panel/manage.go`, `templates/manage.html`, tests.

**Interfaces:**
- `config.Protocols.DoH.Path string` (`json:"path,omitempty"`), default `/dns-query`; validation: `^/[A-Za-z0-9._~-]{1,64}$` (one segment), must not equal `/`, and must not collide with `/login`, `/logout`, `/panel`, `/panel/static` or any prefix of them.
- `dnsserver` mounts the DoH handler at `cfg.Protocols.DoH.Path` (fallback `/dns-query` when empty); every other route unchanged.
- `links` builds the DoH device URL with the configured path.

**Steps:**
- [ ] Config: field + default + validation table tests (ok, empty→default, no leading slash, whitespace, too long, reserved, `/`).
- [ ] dnsserver: use the configured pattern; tests: default serves, custom path serves and the old path answers 404, `/panel/` still works.
- [ ] `links`/status/panel device links and `mdns status` output use the path; tests updated.
- [ ] Panel Настройки: «Путь DoH» field + «Сгенерировать» submit that returns a random path into the form (not saved until Apply); hint that the path is obfuscation, not authentication.
- [ ] Commit `feat: make the DoH path configurable`.

### Task B: Probe an upstream before saving

**Files:** `internal/panel/manage.go`, `templates/manage.html`, `internal/panel/panel.go` (Controller), tests.

**Interfaces:**
- `panel.Controller` gains `Probe(ctx context.Context, eps []providers.Endpoint) []probe.Result` (App already implements it for the unix API).
- `POST /panel/upstreams/probe`: builds one `providers.Endpoint` from the custom form (`transport`, `address`, `server_name`, `insecure_skip_verify`), runs the probe with a short budget (≤5 s), re-renders the Upstreams page with the result in a notice: success «отвечает: 84 мс, rcode NOERROR», failure «нет ответа: таймаут|TLS|…», and echoes the form.
- Add/remove handlers unchanged; saving after a failed probe stays possible (an upstream may be temporarily down) but the result is shown.

**Steps:**
- [ ] Controller method + fake in tests.
- [ ] Handler + route + form button; tests: success и failure отображаются, форма сохраняется, CSRF, unknown transport → 400.
- [ ] Commit `feat(panel): probe a custom upstream before saving it`.

### Task C: Config backups with restore and migration

**Files:** new `internal/configbackup/` (+ tests), `internal/app/` (methods + snapshot before change), `internal/panel/` (Обслуживание page + Controller), tests.

**Interfaces:**
- `configbackup.Create(dir string, cfg *config.Config, label string) (Info, error)`, `List(dir)`, `Load(dir, name) (*config.Config, error)` (uses the normal `config` load/migration), `Delete(dir, name)`; files `config-20060102-150405[-label].json`, 0600, dir 0700, retention 10 (oldest pruned).
- `App` methods: `CreateConfigBackup(label string)`, `ListConfigBackups()`, `RestoreConfigBackup(name string) error` (loads+migrates, snapshots the current config first, then `UpdateConfig`); auto-snapshot before every persisted `UpdateConfig`.
- Panel Обслуживание: «Резервные копии» list (name, date, size), «Создать копию», «Восстановить», «Удалить»; restore re-renders with the applied result.

**Steps:**
- [ ] Package + tests: create/list/load/delete, retention, mode 0600/0700, migration of a minimal old file (missing fields get defaults), bad JSON rejected.
- [ ] App integration: auto-snapshot before a persisted change; restore goes through UpdateConfig and is itself snapshotted; tests with temp DataDir.
- [ ] Panel UI + handlers + tests (list renders, create/restore/delete work, CSRF, unknown name → 400).
- [ ] Commit `feat: keep config backups and restore them through validation`.

### Task D: Live request screen

**Files:** `internal/panel/status.go` (feed generalization or second ring), new `internal/panel/live.go` + template + rail, tests, e2e.

**Interfaces:**
- `GET /panel/live` renders a table of the newest ≤100 requests (server-rendered snapshot) and opens `GET /panel/live/events` (SSE) that streams `row` HTML of the richer row: время · клиент · протокол · имя (тип) · результат · источник/апстрим · задержка · rcode.
- A second ring (`feed` with limit 100) fed by the same bus subscription as the status feed; bounded (≤100 entries), one mutex.

**Steps:**
- [ ] Ring + seeding from `Ctrl.Requests(100)`; escape every field; unit tests for push/seed/snapshot bounds.
- [ ] Page + SSE endpoint + rail entry «Живой экран» (after Статус); pause/clear buttons optional.
- [ ] Update tests asserting the rail count (7→8) and add an e2e check that the page streams a row after a dig.
- [ ] Commit `feat(panel): add the live request screen`.

### Task E: README language split

**Files:** `README.md` (English-only), new `README.ru.md` (Russian-only).

**Steps:**
- [ ] Top of each file: `**English** · [Русский](README.ru.md)` / `[English](README.md) · **Русский**` (tab names in their own language).
- [ ] English README: prose strictly English; UI labels verbatim in quotes when needed (the panel UI is Russian).
- [ ] Russian README: complete translation of the same structure (all sections, tables, commands).
- [ ] Commit `docs: split the README into English and Russian editions`.

### Task F: Verification and release

- [ ] Full suite, e2e twice, quick perf, screenshots/`docs/img` refresh for the live screen and backups.
- [ ] Whole-branch review + scoped re-review, fixes, PR, merge, tag `v0.5.0`, release workflow, real one-liner smoke, demo reinstall from the release.
- [ ] Then the VPS task: install on 193.148.58.216 with ACME (needs the domain with an A record), external DoH/DoT/DoQ checks, reboot test, upgrade test.
