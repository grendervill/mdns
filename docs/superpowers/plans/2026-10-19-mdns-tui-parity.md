# TUI parity and live statistics

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the web panel's statistics self-refreshing and add a «Сегодня» period; bring the TUI's management up to the panel's level for upstreams, filter lists and settings (including timezone and the DoH path). No VPS changes until the final release.

**Architecture:** Panel statistics get a small server-rendered fragment endpoint polled by JS every 2 s; the TUI keeps using the existing unix-socket control API (`Config`/`UpdateConfig`, `Providers`, `Probe`, `FilterStatus`/`FilterUpdate`) and gains pickers/forms on the existing bubbletea screens. No new dependencies.

## Global Constraints

- One binary, no CDN; panel copy Russian; code comments English.
- Panel invariants: requireSession, CSRF (mutations), CSP `default-src 'self'`, no-store, disabled ⇒ 404.
- TUI talks only through the existing control API; no direct App access.
- Config changes go through `UpdateConfig` (validate → apply → persist). Preserve the last-enabled-upstream guard and unique IDs.
- `go test ./... -race`, `vet`, `gofmt` green; Playwright e2e green; TUI visual check via tmux capture.
- Subagents: only `opencode-go/deepseek-v4.1-flash`; never touch `main`; **do not touch the VPS during development**.

## Review Focus

1. Panel polling: no overlapping requests, no work in a hidden tab, no resetting the period form or the live feed, tooltips/keys keep working after a swap, and errors degrade quietly.
2. «Сегодня» must use the same whole-UTC-day model as the other periods (it is the current UTC date) and clamp like them.
3. TUI settings: every new field is validated by the same config path; invalid timezone/path input never leaves the daemon broken.
4. TUI filters: catalog entries map to `{ID}` (no URL), custom lists require an https URL and a unique ID; removing a list is explicit; enabling/disabling filtering is a config update.
5. TUI upstreams: unique IDs, duplicate address+transport rejection, last-enabled guard, probe is read-only, priority/strategy semantics match the panel.
6. Terminal UX: every new key is discoverable in the footer/help, works with the existing input line, and does not break the wizard or the requests screen.

---

### Task A: Panel statistics auto-refresh + «Сегодня»

**Files:** `internal/panel/status.go`, `templates/status.html`, `static/app.js` (or new `stats.js`), `assets.go`, `panel.go` (route), tests, `e2e/panel/panel_test.py`.

**Interfaces:**
- `GET /panel/stats` (session-gated) returns the server-rendered statistics fragment (gauges + period summary + donuts) for the same `period`/`from`/`to` query as the status page. Headers: `no-store`; no feed.
- Status page wraps those parts in `<div id="stats-block">`; the period form stays outside so polling never resets it.
- JS polls every 2000 ms, skips while `document.hidden`, never overlaps, replaces the block with the response, and re-binds donut tooltip handlers (event delegation or an exported init function). Errors are silent (or a tiny `aria-live` note).
- `period=today` — label «Сегодня», first option; `from = to = current UTC date`; default remains 30. Update parser/labels/tests.

**Steps:**
- [ ] Refactor `handleStatus` so the fragment and the full page share one stats builder; add the route and the block wrapper.
- [ ] Add the polling script (embedded asset, CSP-safe) and keep the status SSE feed untouched.
- [ ] Add `today` to the period parser/options; tests for the range and label.
- [ ] Tests: fragment handler returns gauges/donuts for a period; `today` range; e2e: open Статус, run a dig, wait >2 s, assert a gauge number changed without reload.
- [ ] Commit `feat(panel): refresh the statistics live and add the today period`.

### Task B: TUI settings and filter-list management

**Files:** `internal/tui/settings.go`, `filters.go`, `model.go`, tests.

**Interfaces:**
- Settings fields add: `Часовой пояс (IANA, пусто = системный)` → `cfg.Timezone`; `Путь DoH` → `cfg.Protocols.DoH.Path`; `Интервал обновления списков, ч` → `cfg.Filter.UpdateIntervalHours`.
- Filters screen:
  - `a` opens a catalog picker (`screenFilterCatalog`) listing `filter.Catalog()` with «установлен/нет»; j/k + Enter toggles the list in `cfg.Filter.Lists` (`{ID}`), Esc back; changes apply via `UpdateConfig`.
  - `c` opens a two-step input (ID, then https URL) for a custom list; duplicate ID or non-https URL shows an error without applying.
  - `d` removes the selected configured list; `e` toggles `Filter.Enabled`; Enter refreshes the selected list; `u` refreshes all; `m` cycles the mode; `r` adds a user rule (renamed from `a`).

**Steps:**
- [ ] Settings fields + tests (values round-trip, invalid values rejected by config.Validate on apply).
- [ ] Catalog picker screen + config mutations + tests (fake client records UpdateConfig).
- [ ] Custom list input flow + remove + enable toggle + tests.
- [ ] Update footer/help; commit `feat(tui): manage filter lists and the new settings`.

### Task C: TUI upstream management

**Files:** `internal/tui/model.go`, new `upstreams.go`, tests.

**Interfaces:**
- Upstreams screen gains:
  - `a` — catalog picker of `providers.List()` endpoints (label «Provider — transport · address»), Enter adds with a unique ID/priority (same rules as the panel).
  - `c` — custom upstream form (ID, name, transport picker plain/dot/doh/doq, address, server_name, priority; j/k fields, Enter edits/cycles, ctrl+s applies, Esc cancels). Validation via `UpdateConfig`.
  - `space` toggle enabled, `d` remove (last-enabled guard), `p` edit priority (input), `s` cycle strategy, `t` probe the selected upstream via `Client.Probe` and show latency/rcode or the failure reason.
- Show the strategy above the table; refresh status after mutations.

**Steps:**
- [ ] Catalog picker + add (unique IDs, duplicate endpoint rejection) + tests.
- [ ] Custom form + tests (valid config, validation errors surfaced, Esc leaves config untouched).
- [ ] Toggle/remove/priority/strategy/probe + tests (last-enabled guard, probe result rendering).
- [ ] Footer/help updates; commit `feat(tui): manage upstreams`.

### Task D: Verification, docs, release

- [ ] Full suite, panel e2e twice, TUI tmux captures (status/upstreams/filters/settings), panel screenshots of the live stats and the «Сегодня» period.
- [ ] README EN/RU: TUI management keys, live statistics, «Сегодня».
- [ ] Whole-branch review + scoped re-review, fixes, PR, merge, tag `v0.6.0`, release workflow, one-liner smoke.
- [ ] **Only then** update the VPS once (same ACME config, keep the cert), verify the panel/TUI on it.
