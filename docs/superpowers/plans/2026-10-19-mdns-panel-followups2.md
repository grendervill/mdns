# Panel Follow-ups II — Async Runtime Swap, Regional Lists, Provider Trust

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the ~5 s structural-change freeze the admin sees when adding an upstream or a filter list, add verified regional block lists to the catalog, and show a public-source trust rating for every DNS provider in the picker.

**Architecture:** The runtime swap becomes asynchronous: the old server releases its listeners immediately (the in-flight management POST keeps its connection and writes its response), the new runtime binds, and a background goroutine drains and retires the old one. Regional lists join the existing built-in filter catalog; provider trust is static read-only data in the providers catalog rendered by the Upstreams page.

**Tech Stack:** Go 1.26, miekg/dns, server-rendered html/template, Playwright e2e.

**Spec:** `docs/superpowers/specs/2026-10-17-mdns-design.md` plus the user report of 2026-10-19 (upstream add appears only after navigation; regional lists; trust ratings).

## Global Constraints

- One binary, no CDN. Panel copy in Russian; code comments in English.
- Panel security invariants stay: requireSession, CSRF, CSP, no-store, disabled ⇒ 404.
- Config changes only through `UpdateConfig` (validate → apply → persist); a rejected change must leave the running daemon untouched.
- `go test ./... -race`, `go vet`, `gofmt` stay green; Playwright e2e twice before merge.
- Subagents: only `opencode-go/deepseek-v4.1-flash`. Never touch `main`.
- The filter catalog comment (“URLs are verified against their hosts when this list changes”) stays true: every new URL below was fetched (HTTP 200, adblock/hosts title) on 2026-10-19.

## Review Focus

1. A structural change from the panel must not depend on the request that triggered it: the POST returns promptly, the new runtime serves the redirect target, and the old runtime retires in the background without leaking listeners, goroutines or transports.
2. A failed swap (bind error, save error) must restore service: the previous config keeps serving and the error reaches the admin.
3. `ReleaseListeners` must free every port (plain UDP/TCP, DoT, DoH TCP + HTTP/3, DoQ) yet leave in-flight HTTP responses writable; closing a listener directly must not log scary warnings.
4. Regional lists must be DNS-usable (adblock domain rules; include-only files are useless — RU AdList is taken from `advblock.txt`, not the 1 KB `RuAdList-uBO.txt`) and must not break the presets.
5. Trust data must be honest and cited: no invented audits; every rating carries a source link, and providers without a strong public source are marked as such.

---

### Task A: Asynchronous runtime swap

**Files:**
- Modify: `internal/dnsserver/server.go`, `doh.go`, `plain.go`, `dot.go`
- Modify: `internal/app/app.go`
- Test: `internal/dnsserver/lifecycle_test.go`, `internal/app/update_rebuild_test.go`

**Interfaces:**
- `func (s *Server) ReleaseListeners()` — closes every listener socket (plain UDP/TCP, DoT, DoH TCP stored as `s.dohLn`, HTTP/3, DoQ) without cancelling `baseCtx` and without touching `httpSrv`, so in-flight handlers (the panel POST) can still write their response. Ports are free for the next generation.
- `func (s *Server) ForceClose()` — closes the remaining HTTP/3 + HTTP server (`Close`, not `Shutdown`); used by the retirement goroutine when a graceful stop times out.
- `App` gains `retiring sync.WaitGroup`; `func (a *App) retireRuntime(oldRT *runtime, keep *runtime)` starts the drain goroutine (`stop` with a 10 s ctx; on timeout `ForceClose`; then `closeResources(keep)`), and `App.Stop` waits for it.

**Steps:**
- [ ] dnsserver: store the DoH TCP listener (`dohLn`) in `startDoH`; `ReleaseListeners` as above; in `serve`, do not log `net.ErrClosed` (“listener stopped” must not fire for a normal swap).
- [ ] app `UpdateConfig` structural path: `a.panel.EndStreams()` → `oldRT.server.ReleaseListeners()` → `newRT.start(a.appCtx)` → `next.Save` → `a.rt/a.cfg/wireEvents` → `a.retireRuntime(oldRT, newRT)`. No synchronous `oldRT.stop` remains on this path.
- [ ] Rollback: on `newRT.start` or `next.Save` failure, build a fresh runtime from `old` (`buildRuntime(old, nil, …)`), `SetPanel`, start it, wire it, and `retireRuntime(oldRT, restored)`; return the original error. A failed `Save` also stops the half-started `newRT`.
- [ ] Tests: (a) `TestReleaseListenersFreesPortsKeepsResponses` — start the server, open an HTTP connection and complete one request, `ReleaseListeners`, start a second server on the same ports and serve; the first connection can still complete a second request. (b) `TestUpdateConfigBindingFailureRestoresService` — occupy the new plain port, call `UpdateConfig`, expect an error and the old daemon still answering on its ports. (c) `TestUpdateConfigReturnsBeforeInflightStop` — call `UpdateConfig` from a goroutine while a slow HTTP request is open (use a raw connection with a partial request or the events stream) and assert `UpdateConfig` returns in < 1.5 s.
- [ ] Remove the now-unused synchronous stop helpers if nothing else uses them; keep `runtime.stop` for `App.Stop`.
- [ ] Verify on the demo: adding an upstream from the catalog returns in < ~1.5 s and the row is visible without a reload; `journalctl` has no “stopping the old listeners … deadline exceeded” on that path.
- [ ] Commit `fix: swap the runtime without freezing the management request`.

### Task B: Regional lists and provider trust

**Files:**
- Modify: `internal/filter/catalog.go`, `internal/panel/manage.go`, `internal/panel/templates/manage.html`, tests
- Modify: `internal/providers/catalog.go`, `internal/panel/manage.go`, tests

**Interfaces:**
- `filter.CatalogEntry.Category` gains `"regional"`; the panel maps it to «региональные».
- `providers.Provider` gains `Trust providers.Trust` with `Level` (`recommended` | `limited` | `unknown`), `Label`, `Note`, `SourceName`, `SourceURL`.
- `func providers.TrustForUpstream(id string) (Trust, bool)` — matches a configured upstream ID (exact, or the known provider ID it is derived from, e.g. `cloudflare-doh` → `cloudflare`); longest match wins.

**Steps:**
- [ ] Add the 14 verified regional entries (IDs/URLs below). `advblock.txt` is the RU AdList proper; do not use the include-only `RuAdList-uBO.txt`.
- [ ] Trust data (sources: Privacy Guides DNS page, fetched 2026-10-19, plus each provider's privacy policy):
  - `recommended` — AdGuard DNS + Family (anonymised metrics, 24 h domain DB), Cloudflare + Family (limited data ≤25 h, no PII), Control D + Family (free resolvers log nothing), Mullvad (explicit no-logging), Quad9 (threat-monitoring data without IP/PII): Label «рекомендован Privacy Guides», Source `privacyguides.org/en/dns/`.
  - `limited` — Google (transient logs, US), Яндекс DNS + Family (RU jurisdiction, not in the recommendations), DNS.SB, OpenDNS + FamilyShield, CleanBrowsing Security: Label «нет в рекомендациях», each with its own privacy-policy URL.
  - `unknown` — any provider without a source (none expected in the current catalog).
- [ ] Upstreams page: a «Доверие провайдерам» table under the catalog add form (provider, level badge, note, source link) with one disclaimer line «Публичные источники; проект не связан с провайдерами». Configured rows show a small badge next to the name when `TrustForUpstream` matches.
- [ ] Fix the remove handler: an unknown upstream ID must be a 400, not a silent 303 (found while testing on the demo).
- [ ] Tests: catalog has ≥ 14 regional entries with https URLs and unique IDs; panel renders the regional category label and the trust table rows with source links; `TrustForUpstream("cloudflare-doh")` resolves; unknown upstream remove → 400.
- [ ] Commit `feat: add regional block lists and provider trust information`.

### Task C: Integration and release

- [ ] Extend the Playwright e2e: the trust table exists with at least one Privacy Guides link; adding a regional list from the catalog works; the upstream add returns to the page with the row present (already covered) and the POST completes within 4 s (asserting the freeze is gone, generous bound).
- [ ] Full suite, e2e twice, quick perf (hot path unchanged; sanity), live demo verification (add/remove upstream speed, regional list applies).
- [ ] Whole-branch review + scoped re-review, PR, merge, tag `v0.4.0`, release, real one-liner smoke, demo reinstall from the release, screenshots/README refresh.
