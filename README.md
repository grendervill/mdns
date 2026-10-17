# mdns

A self-hosted DNS service for personal VPS: it answers DNS-over-HTTPS,
DNS-over-TLS, DNS-over-QUIC and plain DNS queries for your devices and
forwards them to a pool of public upstream resolvers, picking the
fastest healthy one, caching answers and keeping a query log.

The current repository state implements the core engine (plan 1 of 4):
config, certificate store, upstream transports (plain/DoT/DoH/DoQ),
answer cache, health monitor, routing strategies, query log, rate
limiting and the server listeners for all four protocols. Filtering,
the control API, the TUI, the web panel, ACME certificates and the
one-command installer arrive in the following plans.

Design and plans live in `docs/superpowers/`:

- `docs/superpowers/specs/2026-10-17-mdns-design.md` — the design.
- `docs/superpowers/plans/2026-10-17-mdns-core.md` — the core plan.

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
- `cache` — entry count and TTL clamp.
- `limits` — plain-DNS per-IP rate limit and trusted CIDRs
  (exempt from it).
- `log` — in-memory entry count and an optional JSONL file.

## Tests

```sh
make test           # go test ./...
make race           # go test -race ./...
make vet
```

The end-to-end test (`internal/app/e2e_test.go`) brings up the whole
server in-process on high ports with fake upstreams and exercises all
four protocols, the cache and failover.
