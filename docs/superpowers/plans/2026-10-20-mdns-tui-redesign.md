# TUI redesign: parity, two-pane pickers, motion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Make the TUI a full second interface, not a viewer: every setting the web panel can change is editable here, selections use list pickers (left choices, right description), and screen transitions are smooth and fast. **No VPS deployment during development.**

**Architecture:** A small design layer (palette, panes, rows), a left navigation rail with a sliding selection marker, and a reusable two-pane picker component. All edits still go through the control API (`Config`/`UpdateConfig`, `Providers`, `Probe`, `FilterStatus`/`FilterUpdate`, backups, password via local hash + config PUT).

## Global Constraints

- One binary; bubbletea/lipgloss only; no new dependencies.
- TUI talks only through the control API; config changes via `UpdateConfig`.
- Russian copy; code comments English; tests deterministic (animations must not break screen/tab assertions).
- `go test ./... -race`, `vet`, `gofmt` green; tmux visual checks at 120×40 and 80×24.
- Subagents: only `opencode-go/deepseek-v4.1-flash`; never touch the VPS.

## Review Focus

1. Every panel-managed setting is editable in the TUI, with list pickers where the value is an enumeration (strategy, filter mode, timezone, transport, upstream/filter catalogs).
2. Two-pane pickers: left list scrolls, right details describe the selected item; Enter acts on the visible row; Esc returns; errors are visible; narrow terminals degrade gracefully.
3. The rail replaces the top tabs at normal widths but keeps all screens reachable and the digit shortcuts working; the footer/help always match the active screen.
4. Motion is fast (≤150 ms), does not steal input, stops on its own, and is disabled/irrelevant in tests and on narrow terminals.
5. No regressions in the wizard, requests feed, settings, backups/password or the control API.

---

### Task 1: Shell — rail, header, footer, motion

**Files:** `internal/tui/model.go`, new `internal/tui/layout.go` (or `styles.go`), `status.go` (styles), tests.

**Interfaces:**
- Palette/styles in one place: accent copper, muted, ok/warn/err, pane border, selected row, header.
- `Model.View`: header (`mdns · <domain>` and connection/version), body, footer. Body = left rail + content when `m.width >= 64`, otherwise the existing top-tab fallback. Rail entries: all 8 tabs, numbers, active style, and a **sliding marker** animated on screen change.
- Motion: `anim` state (from/to index, start, frame), `tea.Tick` frames (~20 ms, 6 frames, total ≤150 ms); stops by itself; a new screen change retargets; no motion when width < 64. Tests can ignore ticks; the active text must be correct immediately.
- Footer: keep the per-screen contextual footers; the shell owns the layout.
- Help overlay lists the rail keys and the current management keys.
- Tests: rail renders all tabs and marks exactly one active; digit navigation still works; tick messages advance/stop the animation; narrow width falls back to tabs; no panic at 40×12.

**Steps:**
- [ ] Styles + header/rail/footer layout with responsive fallback; update existing view tests.
- [ ] Sliding marker animation (tick-driven, bounded, retargetable).
- [ ] Help/footer consistency; commit `feat(tui): rail shell and fast screen transitions`.

### Task 2: Two-pane pickers and list-based selection

**Files:** new `internal/tui/picker.go`, `model.go`, `filters.go`, `upstreams.go`, `settings.go`, `maintenance.go` (if needed), tests.

**Interfaces:**
- Reusable `picker` view: title, items (`label`, `status`, `details []string`), cursor, scroll window; left pane ≈40% (min 24, max 48), right pane with wrapped details; Enter acts, Esc returns; a bottom hint. Narrow (<72): stack list above details.
- Upstream catalog picker (two-pane): provider, transport, address, trust label/note/source, duplicate/installed status. Enter adds.
- Filter catalog picker (two-pane): name, category, description, installed status, applied/skipped (when status exists), URL. Enter toggles.
- **Strategy picker** (`s` on Upstreams/Settings): list fastest/failover/round_robin/random with descriptions; Enter applies; current marked.
- **Filter mode picker** (`m` on Filters): zero/nxdomain/refused with explanations; Enter applies.
- **Timezone picker** (Settings field): system (empty), UTC, Europe/Moscow, Europe/London, Europe/Berlin, Europe/Kyiv, Asia/Almaty, Asia/Tbilisi, Asia/Yerevan, Asia/Dubai, America/New_York, plus «Своё…» (input); details show the current local time and UTC offset for the zone. Enter stages the value in the settings screen (ctrl+s applies).
- **Transport picker** (custom upstream form): plain/dot/doh/doq with address-format notes; Enter sets the field.
- Tests: picker scrolling/details, Enter/Esc, each new picker applies/stages the right value, narrow layout.
- Commit `feat(tui): two-pane list pickers for every enumeration`.

### Task 3: Parity audit, polish, docs, verification

- [ ] Audit panel settings/actions vs TUI; close gaps (e.g., any missing setting), ensure footers/help list the real keys.
- [ ] README EN/RU: describe the rail, two-pane pickers and the list selection for strategy/mode/timezone/transport.
- [ ] tmux captures at 120×40 and 80×24 of the rail, upstream picker, filter picker, strategy picker, timezone picker, maintenance screen; inspect for wrapping/garbling.
- [ ] Full suite, e2e (panel unchanged; run once), review + scoped re-review, PR/merge, tag `v0.8.0`, release, smoke.
- [ ] **Do not deploy to the VPS unless the user asks.**
