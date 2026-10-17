# mdns

A self-hosted DNS service for personal VPS: it answers DNS-over-HTTPS,
DNS-over-TLS, DNS-over-QUIC and plain DNS queries for your devices and
forwards them to a pool of public upstream resolvers, picking the
fastest healthy one, caching answers and keeping a query log.

The current repository state implements the core engine, the filter
engine and the control surfaces (plans 1–3 of 4): config, certificate
store, upstream transports (plain/DoT/DoH/DoQ), answer cache, health
monitor, routing strategies, query log, rate limiting, the server
listeners for all four protocols, the own block-list engine, and the
management layer — a control API on a unix socket, a terminal UI
(`mdns`) and the first-run wizard (`mdns setup`). The web panel, ACME
certificates and the one-command installer arrive in the last plan.

Design and plans live in `docs/superpowers/`:

- `docs/superpowers/specs/2026-10-17-mdns-design.md` — the design.
- `docs/superpowers/plans/2026-10-17-mdns-core.md` — the core plan.
- `docs/superpowers/plans/2026-10-17-mdns-filters.md` — filtering.
- `docs/superpowers/plans/2026-10-17-mdns-control.md` — the control layer.

## Requirements

- Go 1.26 or newer (quic-go v0.64 needs it).
- Linux (Ubuntu 24.04 / Debian 13) for deployment; macOS works for
  local development.

## Build

```sh
make build          # produces bin/mdns
./bin/mdns version
```

## Run locally

```sh
./bin/mdns serve --config examples/config.json
```

The example config answers on high ports (plain 5533, DoH 8443, DoT
8853, DoQ 8853) with a self-signed certificate for `mdns.test`, so
nothing needs root and the real ports stay free. (Port 5533 rather
than the common 5353: on macOS that port belongs to the system's own
mDNS responder.)

Query it (in another terminal):

```sh
# plain DNS
dig @127.0.0.1 -p 5533 example.com

# DNS-over-HTTPS (self-signed certificate: -k)
Q=$(printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | base64 | tr '+/' '-_' | tr -d '=')
curl -k -H 'Accept: application/dns-message' "https://127.0.0.1:8443/dns-query?dns=$Q" | xxd | head
```

Validate a config without starting anything:

```sh
./bin/mdns check --config examples/config.json   # prints "ok"
```

## Configuration

`/etc/mdns/config.json` in production (the path is a flag). The full
schema is in `internal/config/config.go`; the example shows every
section:

- `protocols` — which listeners are on and on which ports.
- `tls` — `self-signed` or `files` (paths to a certificate pair).
- `upstreams` — public resolvers: `transport` is one of `plain`, `dot`,
  `doh` (a full URL) or `doq`; `server_name` sets the TLS SNI when the
  address is an IP; `insecure_skip_verify` allows self-signed upstreams.
- `strategy` — `fastest` (default), `failover`, `round_robin` or
  `random`.
- `cache` — entry count (at least 1) and TTL clamp.
- `limits` — plain-DNS per-IP rate limit and trusted CIDRs
  (exempt from it).
- `log` — in-memory entry count and an optional JSONL file.
- `data_dir` — where persistent data lives (filter list caches);
  defaults to `/var/lib/mdns`.

### Filtering (block lists)

The own block-list engine is off by default; turn it on in the config:

```json
"filter": {
  "enabled": true,
  "mode": "zero",
  "update_interval_hours": 24,
  "lists": [
    { "id": "oisd-small" },
    { "id": "custom", "url": "https://example.com/my-list.txt" }
  ],
  "user_allow": ["allowed.example.com"],
  "user_block": ["manual.example.com"]
}
```

- `mode` — how blocked names are answered: `zero` (A → `0.0.0.0`,
  AAAA → `::`, other types NODATA), `nxdomain` or `refused`.
- `lists` — catalog IDs or your own HTTPS URLs. Each list refreshes
  every `update_interval_hours` (0 = fetch once at startup) with
  conditional requests; cached copies live in `<data_dir>/filters` and
  keep working when a list server is down.
- Catalog: `adguard-dns-filter`, `adguard-base`, `ublock-filters`,
  `easylist`, `peter-lowe`, `oisd-small`, `oisd-full`, `hagezi-pro`,
  `hagezi-proplus`, `stevenblack-unified`, `1hosts-lite`. The wizard's
  `basic` (adguard-dns-filter + oisd-small) and `strict` presets are
  shortcuts over this catalog.
- `user_allow` / `user_block` — your own rules; each covers the domain
  and its subdomains. A user allow beats everything, then user blocks,
  then list exceptions (`@@`), then list rules.
- Lists may be adblock-style (`||domain^`, `@@||domain^`), hosts files
  (`0.0.0.0 domain`) or plain domain lists; cosmetic rules, modifiers
  and junk lines are skipped and counted.
- Filtering happens in the core before cache and upstream, so blocked
  names are answered the same way over plain DNS, DoT, DoH and DoQ.

## Control: TUI, wizard and the daemon API

The daemon exposes a control API on a unix socket (`/run/mdns/mdns.sock`
by default; `serve --socket <path>` overrides it). The TUI and the
wizard are thin clients of that API, so the terminal interface, the
upcoming web panel and the daemon itself always agree — the daemon is
the single source of truth.

### TUI

Run `mdns` with no arguments (opens the TUI when the daemon socket
answers, prints a hint otherwise) or `mdns tui --socket <path>`:

- **1 Статус** — domain, listeners, ready-to-use links, upstream health,
  cache counters.
- **2 Визард** — the setup wizard running against the live daemon
  (same steps as `mdns setup`; `ctrl+c` closes it without saving).
- **3 Запросы** — the live query journal: protocol, name, type, result,
  cache/upstream, latency; blocked entries show their list
  (`space` pauses the feed, `x` clears it, `↑↓` scrolls).
- **4 Upstream'ы** — per-upstream state, EWMA latency, sent/failed.
- **5 Фильтры** — per-list state; `enter` refreshes the list under the
  cursor, `u` — all lists, `m` cycles the block mode, `a` adds a user
  rule (`block domain` / `allow domain`).
- **6 Настройки** — the key config fields in place; `enter` edits or
  toggles, `ctrl+s` applies (`w` opens the wizard).
- **7 Помощь** — the key reference.

`q` quits, `r` reloads the active screen's data, digits switch screens.

### First-run wizard

```sh
mdns setup --config /etc/mdns/config.json
```

The steps: domain, certificate (self-signed or your own PEM files),
protocols and ports, DNS providers with live latency probes (pick
several, choose the per-provider transport with `t`), routing
strategy, filter preset. On save it writes the config and prints the
ready-to-use device links.

### Control API

```sh
curl -s --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status
```

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/v1/status` | GET | listeners, upstream health, cache, filter counters |
| `/api/v1/config` | GET | the full current configuration |
| `/api/v1/config` | PUT | validate, apply and persist a full configuration |
| `/api/v1/providers` | GET | the resolver catalog (with all endpoints) |
| `/api/v1/probe` | POST | measure endpoints: `{"endpoints": [...]}` |
| `/api/v1/requests` | GET | the query journal: `?n=100` |
| `/api/v1/filter/status` | GET | per-list state (rules, errors, timestamps) |
| `/api/v1/filter/update` | POST | refresh one list (`{"id": "oisd-small"}`) or all (`{"id": ""}`) |
| `/api/v1/events` | GET | SSE stream: `requests`, `upstreams`, `filter`, `ping` |

Updating the configuration from a script:

```sh
curl -s --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/config > cfg.json
# edit cfg.json ...
curl -s -X PUT -H 'Content-Type: application/json' --data @cfg.json \
  http://localhost/api/v1/config     # -> {"status":"applied"}
```

`PUT /config` applies what it can without a restart (routing strategy,
cache sizes, rate limits, filter mode and user rules, update interval)
and restarts listeners only for structural changes (domain, TLS,
protocols, upstreams, log, data dir, filter lists). If the new runtime
fails to come up, the previous one keeps serving and the API returns
the error.

## Tests

```sh
make test           # go test ./...
make race           # go test -race ./...
make vet
```

The end-to-end test (`internal/app/e2e_test.go`) brings up the whole
server in-process on high ports with fake upstreams and exercises all
four protocols, the cache and failover.

A Docker smoke test runs the built linux binary in real target images
(`ubuntu:24.04` and `debian:trixie`), starts every protocol with the
filter engine on a real block list, and checks plain DNS, DoT, DoQ,
DoH and the persisted rules:

```sh
scripts/docker-smoke.sh            # both images
scripts/docker-smoke.sh ubuntu:24.04
```
