#!/usr/bin/env bash
# End-to-end test of ACME certificate issuance and deferred TLS startup.
#
# Brings up a local ACME CA (pebble) with its own DNS server
# (pebble-challtestsrv), points the test domain at a fresh `mdns serve`
# container that has no certificate at all, and proves that:
#   - the daemon comes up serving plain DNS and the eager DoH listener
#     on :443 while DoT/DoQ wait for a certificate (hot start),
#   - pebble issues a certificate for mdns.test over tls-alpn-01,
#   - the certificate verifies against the pebble root, and
#   - plain DNS, DoT, DoQ and DoH all answer,
#   - the control API reports the certificate state "ok".
#
# The compose project is fixed to mdns-e2e-pebble and torn down with
# `down -v` on exit, so the test is repeatable. Both CA images are
# unpinned: the e2e deliberately runs against the current pebble release.
#
# One limit of the local CA shapes this test (see the task report for
# the evidence):
#   - pebble issues leaves with an empty subject DN, and kdig (GnuTLS)
#     refuses to complete a handshake with them, so the DoT and DoQ
#     phases fall back to the dnsprobe helper (Go crypto/tls) after
#     reporting what kdig said.
#
# Usage:
#   scripts/e2e-pebble.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT=mdns-e2e-pebble
COMPOSE=(docker compose -p "$PROJECT" -f e2e/pebble/docker-compose.yml)
CERT_WAIT=60

# The linux binary is built here, exactly like scripts/docker-smoke.sh
# does, so the test does not depend on a Makefile target.
case "$(docker info --format '{{.Architecture}}')" in
  aarch64 | arm64) GOARCH=arm64 ;;
  x86_64 | amd64) GOARCH=amd64 ;;
  *)
    echo "unsupported docker architecture" >&2
    exit 1
    ;;
esac
export MDNS_BIN="$PWD/dist/mdns-linux-$GOARCH"
export DNSPROBE_BIN="$PWD/dist/dnsprobe-linux-$GOARCH"

# The daemon gets a fixed address (E2E_DAEMON_IP/E2E_SUBNET) so its DNS
# answer can be in challtestsrv before the daemon starts: an ACME
# attempt against an unresolvable name would send the manager into a
# multi-minute backoff. A static compose network needs a static subnet,
# so probe a few candidates first — `docker network create` rejects any
# subnet that overlaps an existing one.
pick_subnet() {
  local cand
  for cand in 172.31.240.0/24 172.30.240.0/24 172.29.240.0/24 10.212.99.0/24 10.211.99.0/24; do
    if docker network create --subnet "$cand" mdns-e2e-pebble-probe >/dev/null 2>&1; then
      docker network rm mdns-e2e-pebble-probe >/dev/null 2>&1 || true
      printf '%s' "$cand"
      return 0
    fi
  done
  return 1
}

E2E_SUBNET=$(pick_subnet) || {
  echo "no free subnet for the e2e network" >&2
  exit 1
}
E2E_DAEMON_IP="${E2E_SUBNET%.0/24}.10"
export E2E_SUBNET E2E_DAEMON_IP

cleanup() {
  status=$?
  echo
  if [ "$status" -ne 0 ]; then
    # Keep the evidence: the containers are about to be removed, so a
    # failure anywhere (probe, DoH, status API) still leaves readable
    # logs behind.
    echo "--- post-mortem (exit $status) ---"
    "${COMPOSE[@]}" logs --tail 40 daemon >&2 || true
    "${COMPOSE[@]}" logs --tail 40 pebble >&2 || true
    "${COMPOSE[@]}" logs --tail 20 client >&2 || true
  fi
  echo "--- teardown ---"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

# probe_retry runs the DNS probe for one protocol, retrying twice: a
# QUIC handshake over the container bridge occasionally loses its first
# packet pair (both ends warn about a small UDP receive buffer), and
# DNS clients retry for the same reason.
probe_retry() {
  local proto=$1 attempt
  for attempt in 1 2 3; do
    if "${COMPOSE[@]}" exec -T client /mnt/dnsprobe \
      -proto "$proto" -server daemon:853 -name example.com -servername mdns.test \
      -timeout 15s -ca /tmp/pebble-root.pem; then
      return 0
    fi
    echo "probe attempt $attempt for $proto failed" >&2
    sleep 1
  done
  echo "the $proto probe never answered" >&2
  return 1
}

echo "--- pre-clean: drop a previous run ---"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

echo "--- build linux/$GOARCH binary ---"
mkdir -p dist
GOOS=linux GOARCH="$GOARCH" go build \
  -ldflags "-X mydns/internal/version.Version=pebble-e2e" \
  -o "$MDNS_BIN" ./cmd/mdns

echo "--- build the DNS client probe ---"
# kdig is tried first for DoT and DoQ; the probe is the fallback for
# CAs whose certificates GnuTLS rejects (see the phase below).
GOOS=linux GOARCH="$GOARCH" go build -o "$DNSPROBE_BIN" ./e2e/pebble/dnsprobe

echo "--- start challtestsrv and pebble ---"
"${COMPOSE[@]}" up -d challtestsrv pebble

echo "--- wait for the challtestsrv management API (:8055) ---"
for _ in $(seq 1 60); do
  # Any HTTP answer means the management server is up (404 counts).
  curl -s -o /dev/null --max-time 2 http://localhost:8055/ && break
  sleep 1
done
curl -s -o /dev/null --max-time 2 http://localhost:8055/

echo "--- wait for the pebble directory (:14000) ---"
for _ in $(seq 1 60); do
  curl -skf --max-time 2 https://localhost:14000/dir >/dev/null && break
  sleep 1
done
curl -skf --max-time 2 https://localhost:14000/dir >/dev/null
echo "pebble directory is up"

echo "--- point mdns.test at the daemon ($E2E_DAEMON_IP) ---"
curl -sf -X POST -H 'Content-Type: application/json' \
  -d "{\"ip\":\"$E2E_DAEMON_IP\"}" http://localhost:8055/set-default-ipv4
echo
# Empty IPv6 answer: pebble must not pick a broken IPv6 path.
curl -sf -X POST -H 'Content-Type: application/json' \
  -d '{"ip":""}' http://localhost:8055/set-default-ipv6
echo

echo "--- start the daemon and the client ---"
"${COMPOSE[@]}" build client
"${COMPOSE[@]}" up -d daemon client

echo "--- challtestsrv answers mdns.test with the daemon address ---"
"${COMPOSE[@]}" exec -T client bash -s "$E2E_DAEMON_IP" <<'CLIENT'
set -euo pipefail
want=$1
got=$(dig @challtestsrv -p 8053 mdns.test A +short +timeout=4 +tries=1)
echo "mdns.test A = $got (want $want)"
[ "$got" = "$want" ]
CLIENT

echo "--- hot start: the daemon had no certificate at startup ---"
# In ACME mode the 443 DoH listener starts eagerly (it terminates the
# TLS-ALPN-01 challenge) and logs that fact; DoT/DoQ only appear later,
# once the certificate exists. The log order is the proof.
hot=0
for _ in $(seq 1 30); do
  if "${COMPOSE[@]}" logs daemon 2>&1 \
    | grep -q 'DoH listening for ACME TLS-ALPN-01 ahead of the certificate'; then
    hot=1
    break
  fi
  sleep 1
done
if [ "$hot" -ne 1 ]; then
  echo "the daemon never reported starting without a certificate" >&2
  "${COMPOSE[@]}" logs daemon
  exit 1
fi
daemon_log=$("${COMPOSE[@]}" logs daemon 2>&1)
printf '%s\n' "$daemon_log" | grep 'DoH listening for ACME TLS-ALPN-01 ahead of the certificate'
eager_line=$(printf '%s\n' "$daemon_log" | grep -n 'DoH listening for ACME TLS-ALPN-01' | head -1 | cut -d: -f1)

# Wait for the DoT/DoQ lines, then check that they came after the eager
# 443 listener. The readiness gate opens on a real serving-certificate
# lookup (the TLS-ALPN-01 challenge handshake no longer counts, see
# commit 3c07edf), so the ordering also shows the listeners coming up
# with the certificate: both "acme: certificate ready" and
# "app: TLS listeners started mode=acme issuer=…" carry the CA issuer,
# while the eager 443 listener logged ahead of the certificate.
for _ in $(seq 1 "$CERT_WAIT"); do
  printf '%s\n' "$("${COMPOSE[@]}" logs daemon 2>&1)" | grep -q 'DoT listening' && break
  sleep 1
done
daemon_log=$("${COMPOSE[@]}" logs daemon 2>&1)
printf '%s\n' "$daemon_log" | grep -E 'DoT listening|DoQ listening|TLS listeners started'
dot_line=$(printf '%s\n' "$daemon_log" | grep -n 'DoT listening' | head -1 | cut -d: -f1)
if [ -z "$eager_line" ] || [ -z "$dot_line" ] || [ "$eager_line" -ge "$dot_line" ]; then
  echo "DoT did not start after the certificate-less DoH listener" >&2
  printf '%s\n' "$daemon_log" >&2
  exit 1
fi
echo "DoT/DoQ started after the certificate-less DoH listener (log lines $eager_line -> $dot_line)"

echo "--- fetch the pebble root into the client ---"
"${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
for _ in $(seq 1 30); do
  if curl -sk --max-time 5 https://pebble:15000/roots/0 -o /tmp/pebble-root.pem \
    && [ -s /tmp/pebble-root.pem ]; then
    break
  fi
  sleep 1
done
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.pem
echo "pebble root: $(openssl x509 -in /tmp/pebble-root.pem -noout -subject)"
CLIENT

echo "--- wait for the certificate for mdns.test (<= ${CERT_WAIT}s) ---"
# A verified handshake alone is not enough: openssl prints
# "Verify return code: 0 (ok)" even when the server sent no certificate
# at all, so the check also requires the served chain to parse.
cert_ok=0
for i in $(seq 1 "$CERT_WAIT"); do
  if "${COMPOSE[@]}" exec -T client bash -s >/tmp/e2e-pebble-cert.log 2>&1 <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
printf '%s\n' "$out" | grep -q 'Verify return code: 0 (ok)'
printf '%s\n' "$out" | openssl x509 -noout -subject
CLIENT
  then
    cert_ok=1
    echo "certificate verified after ${i}s"
    break
  fi
  sleep 1
done
if [ "$cert_ok" -ne 1 ]; then
  echo "no verified certificate within ${CERT_WAIT}s; last attempt:" >&2
  cat /tmp/e2e-pebble-cert.log >&2
  echo "--- status API ---" >&2
  "${COMPOSE[@]}" exec -T client curl -s --unix-socket /run/mdns/mdns.sock \
    http://localhost/api/v1/status >&2 || true
  echo >&2
  echo "--- daemon log ---" >&2
  "${COMPOSE[@]}" logs daemon >&2 || true
  echo "--- pebble log ---" >&2
  "${COMPOSE[@]}" logs pebble >&2 || true
  exit 1
fi

echo "--- served certificate (openssl s_client) ---"
"${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
echo "verify: $(printf '%s\n' "$out" | grep -m1 'Verify return code')"
printf '%s\n' "$out" | openssl x509 -noout -subject -issuer
printf '%s\n' "$out" | openssl x509 -noout -ext subjectAltName -dates
# The leaf must be the pebble-issued certificate for the domain.
printf '%s\n' "$out" | openssl x509 -noout -issuer | grep -q 'Pebble'
printf '%s\n' "$out" | openssl x509 -noout -ext subjectAltName | grep -q 'mdns.test'
CLIENT

echo "--- plain DNS (dig @daemon) ---"
"${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(dig @daemon example.com A +short +timeout=4 +tries=1)
echo "$out"
[ -n "$out" ]
CLIENT

echo "--- DoT (kdig +tls, :853) ---"
# kdig is the reference client, and it counts as the result only when it
# exits 0 *and* prints an answer line: the query is "example.com A", so a
# bare IP address is the expected shape. Anything else — a FATAL from an
# unsupported flag, a GnuTLS refusal of the CA's certificate, a missing
# binary, an empty reply — falls back to the probe, which makes the same
# verified query with crypto/tls.
if kdig_out=$("${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -uo pipefail
kdig @daemon -p 853 +tls +tls-ca=/tmp/pebble-root.pem +tls-hostname=mdns.test \
  +timeout=5 example.com A +short 2>&1
CLIENT
); then
  kdig_status=0
else
  kdig_status=$?
fi
if [ "$kdig_status" -eq 0 ] && printf '%s\n' "$kdig_out" | grep -qE '^[0-9a-fA-F:.]+$'; then
  printf '%s\n' "$kdig_out"
else
  echo "kdig did not answer (exit status $kdig_status); falling back to the probe:"
  printf '%s\n' "$kdig_out" | grep -E 'FATAL|WARNING|ERROR' | head -2 || true
  probe_retry dot
fi

echo "--- DoQ (kdig +quic, :853/udp) ---"
# Same success criterion as DoT: exit status 0 plus an answer line.
if kdig_out=$("${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -uo pipefail
kdig @daemon -p 853 +quic +tls-ca=/tmp/pebble-root.pem +tls-hostname=mdns.test \
  +timeout=5 example.com A +short 2>&1
CLIENT
); then
  kdig_status=0
else
  kdig_status=$?
fi
if [ "$kdig_status" -eq 0 ] && printf '%s\n' "$kdig_out" | grep -qE '^[0-9a-fA-F:.]+$'; then
  printf '%s\n' "$kdig_out"
else
  echo "kdig did not answer (exit status $kdig_status); falling back to the probe:"
  printf '%s\n' "$kdig_out" | grep -E 'FATAL|WARNING|ERROR' | head -2 || true
  probe_retry doq
fi

echo "--- DoH (curl, RFC 8484 GET, :443) ---"
"${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
Q=$(printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
  | base64 | tr '+/' '-_' | tr -d '=')
code=$(curl -s --max-time 5 -o /tmp/doh.bin -w '%{http_code}' \
  --cacert /tmp/pebble-root.pem \
  --connect-to mdns.test:443:daemon:443 \
  -H 'Accept: application/dns-message' \
  "https://mdns.test/dns-query?dns=$Q")
echo "doh http status: $code"
[ "$code" = 200 ]
[ "$(wc -c < /tmp/doh.bin)" -gt 12 ]
id=$(od -An -tx1 -N2 /tmp/doh.bin | tr -d ' \n')
flags=$(od -An -tx1 -j2 -N1 /tmp/doh.bin | tr -d ' \n')
echo "doh reply id: $id flags: $flags"
[ "$id" = "1234" ]
[ $(( 0x$flags & 0x80 )) -ne 0 ]
CLIENT

echo "--- control API: certificate status over the unix socket ---"
"${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status > /tmp/status.json
sed -n 's/.*\("Listeners":\[[^]]*\]\).*/\1/p' /tmp/status.json
sed -n 's/.*\("Cert":{[^}]*}\).*/\1/p' /tmp/status.json
grep -q '"state":"ok"' /tmp/status.json
# The deferred listeners must be up now: DoT and DoQ only start after
# the eager 443 listener, once the manager has a certificate.
grep -q 'doh:443' /tmp/status.json
grep -q 'dot:853' /tmp/status.json
grep -q 'doq:853' /tmp/status.json
echo "cert state ok, TLS listeners up"
CLIENT

echo "--- daemon log ---"
"${COMPOSE[@]}" logs daemon 2>&1 | tail -12

echo
echo "e2e-pebble: passed"
