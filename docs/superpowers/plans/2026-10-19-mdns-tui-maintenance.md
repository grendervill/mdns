# TUI maintenance: backups and panel password

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Close the last TUI gaps to the web panel: manage config backups and change the panel password from the terminal. **Do not deploy to the VPS during this iteration** — the user is actively using it.

**Architecture:** Four unix-socket API endpoints wrap the existing `App` backup methods; the TUI client calls them and renders a new «Обслуживание» screen. The password change validates and hashes locally in the TUI (shared `auth.ValidatePassword`/`HashPassword`) and applies through the existing `UpdateConfig`; no plaintext crosses the API.

## Global Constraints

- One binary; no new dependencies; TUI talks only through the control API.
- Panel/API invariants unchanged: unix socket only, mode 0660; no network exposure.
- Config changes go through `UpdateConfig`; restore/password errors must leave the daemon untouched.
- `go test ./... -race`, `vet`, `gofmt` green; TUI tmux visual check.
- Subagents: only `opencode-go/deepseek-v4.1-flash`; **never touch the VPS**; main untouched.

## Review Focus

1. Backups API: validated names, no traversal, JSON shapes, 400 vs 500, and the unix-socket-only exposure.
2. Restore is the panel's transactional path (migrate → pre-restore snapshot → UpdateConfig); a bad backup leaves the daemon serving.
3. Password: shared validator, masked input, confirmation, argon2 hash, no plaintext in logs/config/API; disabled panel handled.
4. TUI: the screen is reachable (tab 8), keys discoverable, errors visible, and the list reloads after each mutation.
5. No regression in the existing screens, wizard or e2e.

---

### Task 1: Backups API + TUI client

**Files:** `internal/api/api.go` (Controller + routes), new `internal/api/backup.go`, tests; `internal/tui/client.go`, tests.

**Interfaces:**
- `api.Controller` gains `CreateConfigBackup(label string) error`, `ListConfigBackups() ([]configbackup.Info, error)`, `RestoreConfigBackup(name string) error`, `DeleteConfigBackup(name string) error` (App already implements them).
- Routes: `GET /api/v1/backups` → `{"backups":[{"name","size","mod_time"}]}`; `POST /api/v1/backups` (optional `{"label":""}`) → 200 with the created info; `POST /api/v1/backups/restore` `{"name":...}`; `POST /api/v1/backups/delete` `{"name":...}`. Bad/unknown name → 400; internal → 500.
- TUI `Client` gains `Backups(ctx)`, `CreateBackup(ctx, label)`, `RestoreBackup(ctx, name)`, `DeleteBackup(ctx, name)`; fake clients updated.

**Steps:**
- [ ] Handlers + routes + controller wiring; tests with the API fake for success/400/500 and the JSON shapes.
- [ ] Client methods + tests decoding the shapes.
- [ ] Commit `feat(api): expose config backups on the control socket`.

### Task 2: TUI «Обслуживание» screen + password change

**Files:** `internal/tui/model.go`, new `maintenance.go`, `client.go` (if not fully in Task 1), tests.

**Interfaces:**
- New tab 8 «Обслуживание» (`screenMaintenance`, digit `8`): list backups (`name`, `mod_time`, `size`) newest first; `j/k`, `r` reload, `c` create a copy, `enter` restore the selected one, `d` delete the selected one; a note that restore replaces the config including the panel password and DoH state, and that a pre-restore snapshot is created automatically. Errors (bad/unknown name, API failure) are rendered in place.
- Password change on the same screen with `p`: prompt «Новый пароль» (masked), then «Повторите пароль» (masked); use `auth.ValidatePassword` and the wizard's Russian error texts; on success hash with `auth.HashPassword` in a tea.Cmd, clone the config, set `Panel.PasswordHash`, apply via `UpdateConfig`; refuse when the panel is disabled. Esc cancels at either step. The plaintext lives only in the input buffer and is cleared after use.
- Masking: reuse/extend the wizard's `maskInput` pattern for the main input line (new input modes), so the password is never echoed.
- Tabs/digits/help/footer updated; a per-screen footer listing the keys.

**Steps:**
- [ ] Screen + backup actions + tests (fake client; create/restore/delete called with the selected name; errors surfaced; reload after mutation).
- [ ] Password flow + tests (short/whitespace/mismatch rejected without UpdateConfig; valid password hashes and applies; disabled panel refused; Esc leaves config untouched).
- [ ] Tab/help/footer + tests; commit `feat(tui): manage backups and the panel password`.

### Task 3: Verification and release (no VPS)

- [ ] Full suite; TUI tmux capture of the maintenance screen and the masked password prompt; README EN/RU update (tab 8 keys).
- [ ] Whole-branch review + scoped re-review; fixes; PR/merge; tag `v0.7.0`; release; one-liner smoke.
- [ ] **Do not touch the VPS.** The user keeps running v0.6.1; deployment happens later on request.
