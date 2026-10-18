# mdns

[![CI](https://github.com/grendervill/mdns/actions/workflows/ci.yml/badge.svg)](https://github.com/grendervill/mdns/actions/workflows/ci.yml)

A self-hosted DNS service for personal VPS: it answers DNS-over-HTTPS,
DNS-over-TLS, DNS-over-QUIC and plain DNS queries for your devices and
forwards them to a pool of public upstream resolvers, picking the
fastest healthy one, caching answers and keeping a query log.

All four plans of the project are implemented (plans 1–4 of 4): the core
engine (config, upstream transports plain/DoT/DoH/DoQ, answer cache,
health monitor, routing strategies, query log, rate limiting, the
listeners for all four protocols), the own block-list engine, the
management layer (a control API on a unix socket, a terminal UI
(`mdns`) and the first-run wizard (`mdns setup`)), and — in the last
plan — automatic ACME certificates with renewal, the one-command
installer and the `status` / `diag` / `logs` / `install` / `uninstall`
CLI. The web panel is the remaining milestone.

Design and plans live in `docs/superpowers/`:

- `docs/superpowers/specs/2026-10-17-mdns-design.md` — the design.
- `docs/superpowers/plans/2026-10-17-mdns-core.md` — the core plan.
- `docs/superpowers/plans/2026-10-17-mdns-filters.md` — filtering.
- `docs/superpowers/plans/2026-10-17-mdns-control.md` — the control layer.
- `docs/superpowers/plans/2026-10-17-mdns-tls-install.md` —
  certificates and the installer.

## Requirements

- Go 1.26 or newer (quic-go v0.64 needs it) to build from source.
- Linux (Ubuntu 24.04 / Debian 13) with systemd for deployment; macOS
  works for local development.
- The installer runs as root (it writes `/usr/local/bin`,
  `/etc/systemd/system` and `/etc/mdns`). `iproute2` is recommended:
  the port preflight uses `ss` from it to tell the running `mdns`
  holding its own ports from a foreign listener; without `ss` a busy
  port is reported as taken and the install stops.

## Install (one command)

On a fresh Ubuntu 24.04 or Debian 13 VPS, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | sudo bash
```

The wizard asks for the domain, the certificate, the ports, the DNS
providers and the filter preset. The same install without any question:

```sh
curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | sudo bash -s -- \
  --non-interactive --domain dns.example.com --tls acme --acme-email me@example.com
```

`install.sh` is served from the repository's `main` branch, but the
binary it installs comes from a GitHub release. Releases appear from
`v0.1.0` on, so until the first release tag exists the download step
fails; build the binary yourself (`make build`) and pass it with
`--local` in the meantime:

```sh
sudo bash install.sh --local ./bin/mdns --non-interactive --domain dns.example.com
```

Flags of `install.sh` (`bash install.sh --help`):

| Flag | Effect |
| --- | --- |
| `--local <file>` | install the given binary instead of downloading a release |
| `--version vX.Y.Z` | download that release instead of the latest one |
| `-h`, `--help` | print the help |

Every other argument is passed to `mdns install` unchanged.

The script picks the release for this machine (`mdns-linux-amd64` or
`mdns-linux-arm64`), verifies it against the release `SHA256SUMS` and
aborts if the checksum does not match, installs it as
`/usr/local/bin/mdns`, and hands over to `mdns install`.

### What `mdns install` does

1. **Preflight** (a failure aborts before anything is written, a
   warning is printed and does not stop the install):
   root rights; a supported distribution (Ubuntu 24.04 / Debian 13);
   architecture amd64 or arm64; systemd present; the ports the selected
   protocols need are bindable — a port held by the running `mdns`
   itself is fine, the re-run restarts it; a running `systemd-resolved`
   stub listener on `:53` is a warning with the fix to apply
   (`DNSStubListener=no`); the public A/AAAA record of the domain
   should point at this server, otherwise ACME cannot issue a
   certificate; at least 500 MB free on the install filesystem.
2. **Directories** — `/etc/mdns` (0755) and the data directory
   `/var/lib/mdns` (0700).
3. **Binary** — installed as `/usr/local/bin/mdns`.
4. **Config** — the wizard writes `/etc/mdns/config.json`, or the
   non-interactive spec builds it from the flags.
5. **systemd unit** — `/etc/systemd/system/mdns.service`
   (`ExecStart=/usr/local/bin/mdns serve --config /etc/mdns/config.json`,
   `Restart=always`, `LimitNOFILE=65536`), then `daemon-reload`,
   `enable` and `restart`.
6. **Firewall** — when ufw is active its rules are added (plain DNS,
   DoH, DoT, DoQ, plus `80/tcp` when ACME falls back to HTTP-01);
   otherwise the exact `ufw allow` lines to run by hand are printed.
7. **Summary** — the domain, the enabled protocols with ready-to-use
   device links, the upstreams, the strategy and the installed paths.

The non-interactive flags (`mdns install --help`): `--non-interactive`,
`--dry-run`, `--reconfigure`, `--config`, `--data-dir`, `--domain`,
`--tls` (`acme`, `self-signed`, `files`), `--acme-provider`,
`--acme-email`, `--acme-directory`, `--acme-insecure`, `--eab-kid`,
`--eab-hmac`, `--cert-file`, `--key-file`, `--provider` (repeatable,
resolver catalog id), `--strategy`, `--plain-port`, `--doh-port`,
`--dot-port`, `--doq-port`, `--filter` (`off`, `basic`, `strict`).
Only `--domain` is required with `--non-interactive`. `--dry-run`
prints the plan and changes nothing (it still runs the full preflight,
so it needs root).

### Re-running, updating, removing

Re-running the one-liner is the upgrade path: the binary and the unit
are replaced and the service restarts. In the non-interactive form an
existing `/etc/mdns/config.json` is kept (the run says so);
`--reconfigure` rewrites it — the running daemon picks the new
configuration up without a manual restart. Without `--non-interactive`
the wizard opens again.

```sh
sudo mdns uninstall                 # asks for confirmation on a terminal
sudo mdns uninstall --yes           # no question
sudo mdns uninstall --purge         # also remove the config, the data and the certificates
sudo mdns uninstall --keep-binary   # leave /usr/local/bin/mdns in place
```

`mdns uninstall` stops and disables the service, removes the unit and
the binary, and keeps `/etc/mdns/config.json`, `/var/lib/mdns` and the
certificates by default, so a reinstall finds them again; `--purge`
removes them too. A second uninstall does not fail: missing paths are
reported, not treated as errors. The ufw rules `mdns install` added are
not removed by `mdns uninstall`; close the ports by hand (`sudo ufw
delete allow …`) if you no longer need them.

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
- `tls` — `self-signed`, `files` (paths to a certificate pair) or
  `acme` (automatic issuance and renewal; see below).
- `upstreams` — public resolvers: `transport` is one of `plain`, `dot`,
  `doh` (a full URL) or `doq`; `server_name` sets the TLS SNI when the
  address is an IP; `insecure_skip_verify` allows self-signed upstreams.
- `strategy` — `fastest` (default), `failover`, `round_robin` or
  `random`.
- `cache` — entry count (at least 1) and TTL clamp.
- `limits` — plain-DNS per-IP rate limit and trusted CIDRs
  (exempt from it).
- `log` — in-memory entry count and an optional JSONL file.
- `data_dir` — where persistent data lives (filter list caches and the
  ACME certificates); defaults to `/var/lib/mdns`.

### Certificates (ACME)

`tls.mode` selects where the server certificate comes from:

- `self-signed` — an ECDSA P-256 certificate for the domain, generated
  in memory at every startup and never written to disk, so each restart
  regenerates it. It is valid for 90 days — that is only its lifetime,
  not something a restart extends. Good for a first try; every client
  needs `-k` / an explicit trust.
- `files` — the PEM pair given by `tls.cert_file` and `tls.key_file`.
  It is loaded at startup, so a missing or broken pair fails the start
  instead of the first handshake.
- `acme` — the certificate is issued and renewed automatically:

```json
"tls": {
  "mode": "acme",
  "acme": {
    "provider": "letsencrypt",
    "email": "me@example.com"
  }
}
```

| Provider | Directory | Required |
| --- | --- | --- |
| `letsencrypt` (default) | `https://acme-v02.api.letsencrypt.org/directory` | `email` |
| `zerossl` | `https://acme.zerossl.com/v2/DV90` | `email`, the EAB pair `eab_kid` + `eab_hmac` issued by ZeroSSL |
| `custom` | your own `directory_url` (must be https) | `directory_url` |

`acme.insecure_skip_verify` (CLI `--acme-insecure`) skips the TLS
verification of the ACME directory; it exists for a test CA on the
local network and is not meant for production.

The non-interactive install takes the same values as flags:
`--tls acme --acme-provider zerossl --acme-email … --eab-kid … --eab-hmac …`
(or `--acme-directory` for a custom CA); the wizard asks for them in
the certificate step.

**How the domain is validated.** With DoH enabled on port 443 the
daemon uses TLS-ALPN-01 (RFC 8737): that DoH listener starts before any
certificate exists and advertises the `acme-tls/1` protocol, so the CA
can validate the name on the DoH port itself. In every other
configuration it falls back to HTTP-01: a responder binds `:80` and
answers `/.well-known/acme-challenge/…`, returning 404 to anything
else, while the DoH listener waits for the certificate like DoT and
DoQ.

**While there is no certificate yet, or when issuance fails.** The
daemon is up and useful: plain DNS and the local management (control
API, TUI, `mdns status`) work, while the TLS listeners stay closed —
apart from the DoH listener on 443, which is up for the challenge only
(a normal handshake there fails). The certificate state is visible as
`waiting` or `error` with the CA's message in `mdns status`, TUI and
the API (`/api/v1/status`), and the event stream publishes every
change. Failed attempts are retried with a backoff from 5 minutes,
doubling up to 6 hours, spread by ±20% jitter, until the first
success; once the certificate arrives the TLS listeners start without
a restart of the daemon.

**Switching a running daemon to ACME.** Changing `tls.mode` to `acme`
on a daemon that is already serving (a config update or
`mdns install --reconfigure`) takes DoT and DoQ offline until the
certificate is issued: plain DNS keeps answering and the status shows
the `waiting` state meanwhile. A fresh install configured with ACME
from the start has no such window — nothing was serving TLS before.

**Renewal.** autocert renews over the handshake path before the leaf
expires — at the lesser of 30 days or a third of the certificate
lifetime (30 days for a 90-day certificate) — and the daemon rechecks
the certificate once a day. There is no restart and no gap.

**Where the certificate lives.** The ACME account key and the issued
certificates are kept under `<data_dir>/certs/acme`
(`/var/lib/mdns/certs/acme` with the default data directory), written
0600 into the 0700 data directory. They survive a reinstall — `mdns
install` never touches them — and `mdns uninstall` keeps them unless
`--purge` is given, so a reinstall (or a restart while the CA is
unreachable) keeps serving the stored certificate.

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

## CLI

One binary, `mdns`; every command has a `--help`.

| Command | What it does |
| --- | --- |
| `mdns` | open the TUI (prints a hint when the daemon is not running) |
| `mdns setup [--config <path>]` | first-run wizard: writes the config, prints the device links |
| `mdns serve [--config <path>] [--socket <path>]` | run the DNS server in the foreground (this is what the unit runs) |
| `mdns check [--config <path>]` | validate the configuration file, print `ok` |
| `mdns status [--json] [--socket <path>]` | daemon state from the control API: listeners, certificate, upstream health, cache, filters |
| `mdns diag [--config <path>] [--socket <path>] [--data-dir <path>]` | installation self-check: config, ports, certificate, upstream reachability, data dir, unit |
| `mdns logs [-n <N>] [-f] [--config <path>]` | tail the daemon log: the configured log file, the systemd journal otherwise |
| `mdns install [flags]` | install or update the service: binary, config, systemd unit, firewall (see above) |
| `mdns uninstall [--purge] [--keep-binary] [--config <path>] [--data-dir <path>] [--yes]` | remove the service; config, data and certificates survive unless `--purge` (`--non-interactive` is the same as `--yes`) |
| `mdns tui [--socket <path>]` | open the terminal interface |
| `mdns version` | print the version |

`mdns status` needs the running daemon (it reads the control API over
the unix socket). `mdns diag` works either way: it reads the config,
the ports, the data directory and the unit from the filesystem and
reports the certificate and the upstream health from the daemon when
it answers.

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

The steps: domain, certificate (Let's Encrypt, ZeroSSL with its EAB
credentials, a custom ACME CA, self-signed or your own PEM files),
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

Two more end-to-end scripts need Docker; they exercise the parts the
in-process test cannot:

```sh
scripts/e2e-pebble.sh    # ACME against a local pebble CA: issuance over
                         # tls-alpn-01, failure and self-heal, certificate
                         # cache reuse, live switch to ACME on a running daemon
scripts/e2e-install.sh   # the installer in a systemd container: download
                         # mode, idempotent re-run, --reconfigure, uninstall,
                         # and that a failed install leaves no half-state
```
