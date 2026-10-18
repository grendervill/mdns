#!/usr/bin/env bash
# End-to-end test of ACME certificate issuance and deferred TLS startup.
#
# Brings up a local ACME CA (pebble) with its own DNS server
# (pebble-challtestsrv) and drives `mdns serve` through four phases:
#
#   A. issuance and deferred TLS (the Task 8 scenario): the daemon comes
#      up with no certificate at all, serving plain DNS and the eager
#      DoH listener on :443 while DoT/DoQ wait; pebble issues a
#      certificate over tls-alpn-01, it verifies against the pebble
#      root, and plain DNS, DoT, DoQ and DoH all answer.
#   B. failure and self-heal: only the daemon runs (no CA at all). Plain
#      DNS keeps answering, the control API reports a waiting/error
#      certificate with a non-empty error, and a normal TLS handshake on
#      :443 fails (the TCP port is open — Ruling R6 — but no certificate
#      exists). Starting pebble+challtestsrv afterwards lets the daemon
#      heal itself without a restart (bounded by autocert's one-minute
#      failed-state cache, see phase B).
#   C. cache reuse: with pebble stopped, restarting the daemon still
#      serves the certificate saved under <data_dir>/certs/acme, so a
#      handshake verifies against the saved pebble root and the status
#      is "ok" while the ACME server is unreachable.
#   D. live mode switch: the daemon starts self-signed, a continuous
#      plain-DNS loop runs, and PUT /api/v1/config (unix socket) swaps
#      the TLS section to ACME. The switch is transactional: plain DNS
#      never fails a query, and the :443 handshake ends up verifying
#      against the pebble root.
#
# The compose project is fixed to mdns-e2e-pebble and torn down with
# `down -v` between phases and on exit, so the test is repeatable. Both
# CA images are unpinned: the e2e deliberately runs against the current
# pebble release.
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
# HEAL_WAIT bounds the self-heal phases (B and D): autocert keeps the
# failed state for createCertRetryAfter (1 minute), so a transient
# failure floors the next attempt at ~60s — the window has to exceed
# that, not just the daemon's own MDNS_ACME_BACKOFF_MIN/MAX (5s/30s).
HEAL_WAIT=120

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

# plain_loop_pid tracks the phase D plain-DNS loop so the trap can stop
# it even when a later assertion aborts the run.
plain_loop_pid=""

cleanup() {
  status=$?
  echo
  if [ -n "$plain_loop_pid" ]; then
    kill "$plain_loop_pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then
    # Keep the evidence: the containers are about to be removed, so a
    # failure anywhere (probe, DoH, status API) still leaves readable
    # logs behind.
    echo "--- post-mortem (exit $status) ---"
    "${COMPOSE[@]}" logs --tail 40 daemon >&2 || true
    "${COMPOSE[@]}" logs --tail 40 pebble >&2 || true
    "${COMPOSE[@]}" logs --tail 20 challtestsrv >&2 || true
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

# wait_challtestsrv waits for the challtestsrv management API on :8055.
# Any HTTP answer means the management server is up (404 counts).
wait_challtestsrv() {
  local _
  echo "--- wait for the challtestsrv management API (:8055) ---"
  for _ in $(seq 1 60); do
    curl -s -o /dev/null --max-time 2 http://localhost:8055/ && break
    sleep 1
  done
  curl -s -o /dev/null --max-time 2 http://localhost:8055/
}

# wait_pebble waits for the pebble directory endpoint on :14000.
wait_pebble() {
  local _
  echo "--- wait for the pebble directory (:14000) ---"
  for _ in $(seq 1 60); do
    curl -skf --max-time 2 https://localhost:14000/dir >/dev/null && break
    sleep 1
  done
  curl -skf --max-time 2 https://localhost:14000/dir >/dev/null
  echo "pebble directory is up"
}

# start_ca brings up the CA and waits until it answers.
start_ca() {
  echo "--- start challtestsrv and pebble ---"
  "${COMPOSE[@]}" up -d challtestsrv pebble
  wait_challtestsrv
  wait_pebble
}

# point_domain_at_daemon makes challtestsrv answer mdns.test with the
# daemon's fixed address, so pebble validates against the daemon.
point_domain_at_daemon() {
  echo "--- point mdns.test at the daemon ($E2E_DAEMON_IP) ---"
  curl -sf -X POST -H 'Content-Type: application/json' \
    -d "{\"ip\":\"$E2E_DAEMON_IP\"}" http://localhost:8055/set-default-ipv4
  echo
  # Empty IPv6 answer: pebble must not pick a broken IPv6 path.
  curl -sf -X POST -H 'Content-Type: application/json' \
    -d '{"ip":""}' http://localhost:8055/set-default-ipv6
  echo
}

# assert_dns_answer checks that challtestsrv serves the daemon address.
assert_dns_answer() {
  echo "--- challtestsrv answers mdns.test with the daemon address ---"
  "${COMPOSE[@]}" exec -T client bash -s "$E2E_DAEMON_IP" <<'CLIENT'
set -euo pipefail
want=$1
got=$(dig @challtestsrv -p 8053 mdns.test A +short +timeout=4 +tries=1)
echo "mdns.test A = $got (want $want)"
[ "$got" = "$want" ]
CLIENT
}

# fetch_pebble_root copies the pebble root into the client, where every
# verified handshake uses it as the CA file.
fetch_pebble_root() {
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
}

# wait_tls_verified polls a normal handshake on daemon:443, verifying
# the served chain against the pebble root saved in the client, and
# returns 0 once it succeeds (1 on timeout). A verified return code
# alone is not enough: openssl prints "Verify return code: 0 (ok)" even
# when the server sent no certificate at all, so the check also
# requires the served chain to parse.
wait_tls_verified() {
  local timeout=$1 i
  for i in $(seq 1 "$timeout"); do
    if "${COMPOSE[@]}" exec -T client bash -s >/tmp/e2e-pebble-cert.log 2>&1 <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
printf '%s\n' "$out" | grep -q 'Verify return code: 0 (ok)'
printf '%s\n' "$out" | openssl x509 -noout -subject
CLIENT
    then
      echo "certificate verified after ${i}s"
      return 0
    fi
    sleep 1
  done
  return 1
}

# phase_a is the Task 8 scenario: hot start, issuance over tls-alpn-01,
# all four protocols and the control API.
phase_a() {
  echo
  echo "=== phase A: issuance and deferred TLS (hot start) ==="
  echo "--- fresh state: down -v ---"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

  start_ca
  point_domain_at_daemon

  echo "--- start the daemon and the client ---"
  "${COMPOSE[@]}" up -d daemon client
  assert_dns_answer

  echo "--- hot start: the daemon had no certificate at startup ---"
  # In ACME mode the 443 DoH listener starts eagerly (it terminates the
  # TLS-ALPN-01 challenge) and logs that fact; DoT/DoQ only appear later,
  # once the certificate exists. The log order is the proof.
  local hot=0
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
  local daemon_log eager_line dot_line
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

  fetch_pebble_root

  echo "--- wait for the certificate for mdns.test (<= ${CERT_WAIT}s) ---"
  if ! wait_tls_verified "$CERT_WAIT"; then
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
  local kdig_out kdig_status
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
}

# phase_b starts with a fresh volume and a CA-less world: the daemon must
# stay healthy (plain DNS up, a waiting/error certificate, no TLS), and
# then heal itself once the CA appears.
phase_b() {
  echo
  echo "=== phase B: failure and self-heal ==="
  echo "--- fresh state: down -v ---"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

  # --no-deps keeps pebble and challtestsrv stopped: only the daemon and
  # the client (the tool container) come up.
  echo "--- start ONLY the daemon and the client (pebble and challtestsrv stay down) ---"
  "${COMPOSE[@]}" up -d --no-deps daemon client

  echo "--- plain DNS answers although the CA is absent ---"
  local plain_ok=0 out
  for _ in $(seq 1 30); do
    if out=$("${COMPOSE[@]}" exec -T client dig @daemon example.com A +short +timeout=4 +tries=1 2>/dev/null) \
      && [ -n "$out" ]; then
      printf '%s\n' "$out"
      plain_ok=1
      break
    fi
    sleep 1
  done
  if [ "$plain_ok" -ne 1 ]; then
    echo "plain DNS never answered without the CA" >&2
    exit 1
  fi

  echo "--- control API: the certificate waits or errors while the CA is absent ---"
  local cert_error=0
  for _ in $(seq 1 30); do
    "${COMPOSE[@]}" exec -T client curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock \
      http://localhost/api/v1/status > /tmp/e2e-pebble-phase-b-status.json || true
    if grep -qE '"state":"(error|waiting)"' /tmp/e2e-pebble-phase-b-status.json \
      && grep -qE '"error":"[^"]' /tmp/e2e-pebble-phase-b-status.json; then
      cert_error=1
      break
    fi
    sleep 1
  done
  sed -n 's/.*\("Cert":{[^}]*}\).*/\1/p' /tmp/e2e-pebble-phase-b-status.json
  grep -q '"mode":"acme"' /tmp/e2e-pebble-phase-b-status.json
  if grep -q '"state":"ok"' /tmp/e2e-pebble-phase-b-status.json; then
    echo "the certificate state is ok although no CA is reachable" >&2
    exit 1
  fi
  grep -qE '"state":"(waiting|error)"' /tmp/e2e-pebble-phase-b-status.json
  if [ "$cert_error" -ne 1 ]; then
    echo "no waiting/error certificate with a non-empty error within 30s" >&2
    exit 1
  fi
  echo "certificate is waiting/error with a non-empty error (no CA)"

  echo "--- a normal TLS handshake on :443 fails without a certificate ---"
  # Ruling R6: the DoH listener on the TLS-ALPN port is up eagerly, so
  # the TCP connection is accepted; the handshake itself must fail, and
  # no certificate must be presented.
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -uo pipefail
out=$(timeout 20 openssl s_client -connect daemon:443 -servername mdns.test </dev/null 2>&1 || true)
printf '%s\n' "$out" | grep -E 'CONNECTED|no peer certificate|alert|error' | head -4 || true
if ! printf '%s\n' "$out" | grep -q 'CONNECTED'; then
  echo "the :443 listener did not accept TCP (R6 says it must)" >&2
  exit 1
fi
if printf '%s\n' "$out" | grep -q 'BEGIN CERTIFICATE'; then
  echo "the daemon served a certificate although no CA is reachable" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi
echo "TCP accepted, no certificate served (as expected without a CA)"
CLIENT

  echo "--- DoT (:853) is not accepting connections while no certificate exists ---"
  # The deferred TLS listeners must stay down until the certificate is
  # available: the DoT port is not even bound, so a TCP connect is refused.
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
if timeout 3 bash -c '</dev/tcp/daemon/853' 2>/dev/null; then
  echo "DoT :853 accepts TCP although no certificate exists (TLS listeners must wait)" >&2
  exit 1
fi
echo "DoT :853 refused (the TLS listeners stay down while waiting)"
CLIENT

  echo "--- start the CA; the daemon must heal itself through the backoff ---"
  start_ca
  point_domain_at_daemon
  assert_dns_answer
  fetch_pebble_root
  # The window has to cover more than the daemon's own backoff
  # (MDNS_ACME_BACKOFF_MIN=5s / MAX=30s): after the first failed order
  # autocert keeps the failed state for createCertRetryAfter (1 minute)
  # and every handshake in between gets "acme/autocert: missing
  # certificate" without a fresh attempt, so the effective self-heal
  # bound is ~1 minute from the daemon start regardless of the backoff.
  # The retry loop here is 1s, so the certificate appears within a
  # second of that state expiring.
  echo "--- wait for the certificate to appear on its own (self-heal, <= ${HEAL_WAIT}s) ---"
  if ! wait_tls_verified "$HEAL_WAIT"; then
    echo "the daemon did not heal itself; last attempt:" >&2
    cat /tmp/e2e-pebble-cert.log >&2
    echo "--- status API ---" >&2
    "${COMPOSE[@]}" exec -T client curl -s --unix-socket /run/mdns/mdns.sock \
      http://localhost/api/v1/status >&2 || true
    echo >&2
    exit 1
  fi

  echo "--- control API: the certificate healed without a restart ---"
  # The served leaf's serial is saved for phase C, which must serve the
  # very same certificate from the cache instead of a fresh one.
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
printf '%s\n' "$out" | openssl x509 -noout -subject -issuer
printf '%s\n' "$out" | openssl x509 -noout -issuer | grep -q 'Pebble'
curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status > /tmp/status.json
sed -n 's/.*\("Cert":{[^}]*}\).*/\1/p' /tmp/status.json
grep -q '"state":"ok"' /tmp/status.json
printf '%s\n' "$out" | openssl x509 -noout -serial > /tmp/leaf-serial
cat /tmp/leaf-serial
CLIENT
}

# phase_c stops the CA and restarts the daemon: the certificate cached
# under <data_dir>/certs/acme must be served with the ACME server
# unreachable, which proves cache reuse.
phase_c() {
  echo
  echo "=== phase C: a cached certificate survives without the ACME server ==="
  echo "--- stop pebble and challtestsrv (keep the daemon and its mdns-data volume) ---"
  "${COMPOSE[@]}" stop pebble challtestsrv
  if [ -n "$("${COMPOSE[@]}" ps --status running -q pebble)" ] \
    || [ -n "$("${COMPOSE[@]}" ps --status running -q challtestsrv)" ]; then
    echo "pebble or challtestsrv is still running" >&2
    exit 1
  fi

  echo "--- the client confirms the ACME server is unreachable ---"
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
if curl -skf --max-time 2 https://pebble:14000/dir >/dev/null 2>&1; then
  echo "the pebble directory is still reachable" >&2
  exit 1
fi
echo "pebble:14000 is unreachable"
CLIENT

  echo "--- restart the daemon (fresh process, same mdns-data volume) ---"
  "${COMPOSE[@]}" restart daemon

  # The cached certificate is loaded from the volume on the first
  # handshake, so this must succeed quickly and without any CA request.
  echo "--- the cached certificate is served without the CA (<= 15s) ---"
  if ! wait_tls_verified 15; then
    echo "no cached certificate after the restart; last attempt:" >&2
    cat /tmp/e2e-pebble-cert.log >&2
    exit 1
  fi

  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
printf '%s\n' "$out" | grep -m1 'Verify return code'
printf '%s\n' "$out" | openssl x509 -noout -subject -issuer
# The cached leaf is the pebble-issued one, and the status is ok even
# though no new order could have been placed.
printf '%s\n' "$out" | openssl x509 -noout -issuer | grep -q 'Pebble'
curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status > /tmp/status.json
sed -n 's/.*\("Cert":{[^}]*}\).*/\1/p' /tmp/status.json
grep -q '"state":"ok"' /tmp/status.json
echo "cached certificate served with the ACME server down"
CLIENT

  echo "--- phase C serves the SAME leaf as phase B (cache reuse, not a fresh cert) ---"
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
printf '%s\n' "$out" | openssl x509 -noout -serial > /tmp/leaf-serial-c
b=$(cat /tmp/leaf-serial)
c=$(cat /tmp/leaf-serial-c)
echo "phase B leaf serial: $b"
echo "phase C leaf serial: $c"
[ "$b" = "$c" ]
echo "the cached leaf is the same one issued in phase B, not a fresh one"
CLIENT
}

# start_plain_loop runs a 1 query/second plain-DNS loop in the client,
# appending one line per query to /tmp/plain.log, until /tmp/plain-stop
# exists. It is backgrounded on the host; stop_plain_loop ends it.
start_plain_loop() {
  "${COMPOSE[@]}" exec -T client bash -c '
rm -f /tmp/plain-stop /tmp/plain.log
while [ ! -e /tmp/plain-stop ]; do
  if out=$(dig @daemon example.com A +short +timeout=4 +tries=1 2>&1) && [ -n "$out" ]; then
    echo "ok" >> /tmp/plain.log
  else
    printf "FAIL: %s\n" "$out" >> /tmp/plain.log
  fi
  sleep 1
done
' &
  plain_loop_pid=$!
}

stop_plain_loop() {
  "${COMPOSE[@]}" exec -T client touch /tmp/plain-stop >/dev/null 2>&1 || true
  wait "$plain_loop_pid" 2>/dev/null || true
  plain_loop_pid=""
}

# phase_d starts self-signed, keeps a plain-DNS loop running, and swaps
# the TLS section to ACME over the unix socket. The switch has to be
# transactional: plain DNS never fails, and the :443 handshake ends up
# carrying the pebble-issued certificate.
phase_d() {
  echo
  echo "=== phase D: live switch self-signed -> acme ==="
  echo "--- fresh state: down -v ---"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

  echo "--- start the CA and the daemon with a SELF-SIGNED config ---"
  MDNS_CONFIG_FILE=daemon-config-selfsigned.json \
    "${COMPOSE[@]}" up -d challtestsrv pebble daemon client
  wait_challtestsrv
  wait_pebble
  point_domain_at_daemon
  assert_dns_answer
  fetch_pebble_root

  echo "--- the daemon serves the self-signed certificate ---"
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test </dev/null 2>&1)
printf '%s\n' "$out" | grep -q 'BEGIN CERTIFICATE'
printf '%s\n' "$out" | openssl x509 -noout -subject -issuer
# A self-signed certificate must NOT verify against the pebble root.
verified=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
if printf '%s\n' "$verified" | grep -q 'Verify return code: 0 (ok)'; then
  echo "the self-signed certificate verified against the pebble root" >&2
  exit 1
fi
echo "self-signed served and not issued by pebble"
CLIENT

  echo "--- start a plain-DNS loop (1 query/second) for the duration of the switch ---"
  start_plain_loop
  sleep 2

  echo "--- live switch: PUT /api/v1/config with tls.mode=acme (unix socket) ---"
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
code=$(curl -s --max-time 30 -o /tmp/put.json -w '%{http_code}' \
  --unix-socket /run/mdns/mdns.sock -X PUT \
  -H 'Content-Type: application/json' \
  --data @/mnt/pebble-config/daemon-config.json \
  http://localhost/api/v1/config)
echo "PUT /api/v1/config http status: $code"
cat /tmp/put.json; echo
[ "$code" = 200 ]
grep -q '"status":"applied"' /tmp/put.json
CLIENT

  # Same bound as phase B: if the first post-switch order fails
  # transiently (TLS-ALPN-01 validation is the flaky part, and pebble
  # retries authz/order itself), autocert keeps the failed state for
  # createCertRetryAfter (1 minute), so the next attempt is floored at
  # ~60s — the window has to cover that floor, not just the backoff.
  echo "--- the :443 handshake now verifies against the pebble root (<= ${HEAL_WAIT}s) ---"
  if ! wait_tls_verified "$HEAL_WAIT"; then
    echo "the switched daemon did not serve a pebble certificate; last attempt:" >&2
    cat /tmp/e2e-pebble-cert.log >&2
    echo "--- status API ---" >&2
    "${COMPOSE[@]}" exec -T client curl -s --unix-socket /run/mdns/mdns.sock \
      http://localhost/api/v1/status >&2 || true
    echo >&2
    exit 1
  fi

  echo "--- control API: acme mode, ok, pebble issuer, TLS listeners back ---"
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
out=$(openssl s_client -connect daemon:443 -servername mdns.test \
  -CAfile /tmp/pebble-root.pem </dev/null 2>&1)
printf '%s\n' "$out" | openssl x509 -noout -subject -issuer
printf '%s\n' "$out" | openssl x509 -noout -issuer | grep -q 'Pebble'
for _ in $(seq 1 15); do
  curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status > /tmp/status.json
  grep -q 'dot:853' /tmp/status.json && grep -q 'doq:853' /tmp/status.json && break
  sleep 1
done
sed -n 's/.*\("Listeners":\[[^]]*\]\).*/\1/p' /tmp/status.json
sed -n 's/.*\("Cert":{[^}]*}\).*/\1/p' /tmp/status.json
grep -q '"mode":"acme"' /tmp/status.json
grep -q '"state":"ok"' /tmp/status.json
grep -q '"issuer":"Pebble' /tmp/status.json
grep -q 'dot:853' /tmp/status.json
grep -q 'doq:853' /tmp/status.json
echo "live switch applied: acme certificate, all listeners up"
CLIENT

  echo "--- stop the plain-DNS loop and check it never failed ---"
  stop_plain_loop
  "${COMPOSE[@]}" exec -T client bash -s <<'CLIENT'
set -euo pipefail
total=$(wc -l < /tmp/plain.log)
fails=$(grep -c '^FAIL' /tmp/plain.log || true)
echo "plain DNS queries during the switch: $total, failures: $fails"
[ "$total" -gt 0 ]
[ "$fails" -eq 0 ]
CLIENT
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

echo "--- build the client image ---"
"${COMPOSE[@]}" build client

phase_a
phase_b
phase_c
phase_d

echo
echo "e2e-pebble: passed"
