#!/usr/bin/env bash
# Docker end-to-end test of the mdns installer.
#
# The installer is exercised the way a user runs it: the download-mode
# one-liner
#
#   curl -fsSL $BASE/install.sh | bash -s -- --non-interactive ...
#
# with MDNS_BASE_URL pointing at a local file server that mirrors the
# GitHub release layout ($BASE/latest/download/<file>), so the download,
# the SHA256 verification and the binary installation are all real. The
# container is a real systemd machine: `systemctl enable/is-active` are
# what the installer itself calls.
#
# Phases:
#   A  download-mode install: download + checksum, binary, config, unit,
#      running service, a DNS answer, `mdns status` and `mdns diag`.
#   B  idempotence: a re-run over the running service keeps the config;
#      --reconfigure rewrites it and the service comes up on it cleanly.
#   C  a failed install leaves no half-state: a bad domain aborts before
#      anything is written, the unit is not enabled, no config exists.
#   D  uninstall: the config/data survive by default, --keep-binary keeps
#      the binary, --purge removes everything.
#
# Known defect this script measures (found by Task 14, not fixed there):
# a re-run over a *running* service aborts in the installer's port
# preflight, because the service it installed already holds the ports the
# new config asks for — the installer even names the holder
# ("53 (занят: mdns)"). Re-running the one-liner is how this project
# upgrades (design spec §3, "обновление — переустановкой скриптом"), so
# B1 asserts it and is RED until `internal/installer` stops (or exempts)
# its own service before the port check. Everything else passes; see
# .superpowers/sdd/2026-10-17-mdns-tls-install/task-14-report.md.
#
# Container notes (macOS / Docker Desktop):
#   * ubuntu:24.04 ships no init, so the container starts as
#     `bash -c '<install systemd> && exec /sbin/init'`: bash is PID 1 for
#     the apt step and hands PID 1 over to systemd.
#   * --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw
#     give systemd a writable cgroup tree to manage units with.
#   * --add-host=host.docker.internal:host-gateway makes the host file
#     server reachable from the Linux container.
#   * The systemd-resolved stub listener owns :53 inside the container, so
#     the installer's port preflight (correctly) refuses to install until
#     it is disabled. The bootstrap writes the same drop-in the installer
#     prints in its own warning (DNSStubListener=no) — that is the
#     documented prerequisite of a real installation, not a test hack.
#   * No host ports are published: every assertion runs inside the
#     container, so binding 53/443 on the developer machine (where a real
#     resolver lives) would only add conflicts.
#
# The container has a fixed name and is removed both at the start and in
# the exit trap, so the script is repeatable.
#
# Usage:
#   scripts/e2e-install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=ubuntu:24.04
NAME=mdns-e2e-install
HOST=host.docker.internal
DOMAIN=mdns.test
# Ports of the install under test.
PLAIN_PORT=53
DOH_PORT=443
DOT_PORT=853
DOQ_PORT=853
# Ports of the --reconfigure phase: a different port set, so the rewrite
# is visible in the config and in the running daemon. (Reconfiguring with
# the same ports while the service runs hits the defect phase B measures,
# see the note there.)
RE_PLAIN_PORT=5300
RE_DOH_PORT=4430
RE_DOT_PORT=8530
RE_DOQ_PORT=8530
RE_DOMAIN=reconf.test

# Flags of every successful install below; phase C deliberately breaks
# the domain.
INSTALL_FLAGS="--non-interactive --domain $DOMAIN --tls self-signed --provider cloudflare --plain-port $PLAIN_PORT --doh-port $DOH_PORT --dot-port $DOT_PORT --doq-port $DOQ_PORT"
RECONFIG_FLAGS="--non-interactive --reconfigure --domain $RE_DOMAIN --tls self-signed --provider cloudflare --plain-port $RE_PLAIN_PORT --doh-port $RE_DOH_PORT --dot-port $RE_DOT_PORT --doq-port $RE_DOQ_PORT"

# The container bootstrap installs systemd (the image has none), the
# client tools the phases need, disables the resolved stub listener and
# only then execs init, so systemd is PID 1.
BOOTSTRAP='
set -e
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus curl dnsutils iproute2 >/dev/null
mkdir -p /etc/systemd/resolved.conf.d
printf "[Resolve]\nDNSStubListener=no\n" > /etc/systemd/resolved.conf.d/99-mdns.conf
exec /sbin/init
'

# --- assertion bookkeeping ------------------------------------------------
# Every assertion prints its own line; the run never stops at the first
# failure, so one run shows the full picture and the summary counts them.
checks=0
failed=0

pass() { checks=$((checks + 1)); printf '  ✓ %s\n' "$1"; }
fail() {
  checks=$((checks + 1))
  failed=$((failed + 1))
  printf '  ✗ %s\n' "$1"
  if [ -n "${2:-}" ]; then printf '%s\n' "$2" | sed 's/^/      /'; fi
}
note() { printf '%s\n' "$1" | sed 's/^/      /'; }

# run_installer runs the download-mode one-liner inside the container.
# $1 is the flag string handed to `mdns install`; it is spliced into the
# inner command unquoted, so single quotes are what a caller uses to keep
# an argument together (see the bad-domain phase) and double quotes are
# not usable there.
run_installer() {
  docker exec -e "MDNS_BASE_URL=$BASE_URL" "$NAME" \
    bash -c "curl -fsSL '$BASE_URL/install.sh' | bash -s -- $1"
}

# iassert records the outcome of the one-liner: want is ok or fail.
# LAST_OUT/LAST_STATUS keep its output for the notes.
LAST_OUT=""
LAST_STATUS=0
iassert() {
  LAST_STATUS=0
  LAST_OUT=$(run_installer "$2" 2>&1) || LAST_STATUS=$?
  if { [ "$3" = ok ] && [ "$LAST_STATUS" -eq 0 ]; } ||
    { [ "$3" = fail ] && [ "$LAST_STATUS" -ne 0 ]; }; then
    pass "$1"
  else
    fail "$1" "$LAST_OUT"
  fi
}

# cassert runs a shell script in the container: it must exit 0.
cassert() {
  local status=0 out
  out=$(docker exec "$NAME" bash -c "$2" 2>&1) || status=$?
  if [ "$status" -eq 0 ]; then pass "$1"; else fail "$1" "$out"; fi
}

# cexpect_fail runs a script that must exit non-zero.
cexpect_fail() {
  local status=0 out
  out=$(docker exec "$NAME" bash -c "$2" 2>&1) || status=$?
  if [ "$status" -ne 0 ]; then pass "$1"; else fail "$1" "$out"; fi
}

# ccontains runs a script that must exit 0 and print the needle.
ccontains() {
  local status=0 out
  out=$(docker exec "$NAME" bash -c "$2" 2>&1) || status=$?
  if [ "$status" -eq 0 ] && printf '%s' "$out" | grep -qF "$3"; then
    pass "$1"
  else
    fail "$1" "$out
      (expected: $3)"
  fi
}

# reset_install removes every trace of an installation in the container,
# so each phase starts from a known state.
reset_install() {
  docker exec "$NAME" bash -c '
    if [ -x /usr/local/bin/mdns ]; then
      /usr/local/bin/mdns uninstall --purge --yes >/dev/null 2>&1 || true
    fi
    systemctl disable --now mdns >/dev/null 2>&1 || true
    rm -rf /etc/mdns /var/lib/mdns /usr/local/bin/mdns /etc/systemd/system/mdns.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed mdns >/dev/null 2>&1 || true
  ' || true
}

# --- teardown -------------------------------------------------------------
stage=""
http_pid=""
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo
    echo "--- post-mortem (exit $status) ---"
    echo "--- container log (tail 30) ---"
    docker logs --tail 30 "$NAME" 2>&1 || true
    echo "--- journal of mdns.service ---"
    docker exec "$NAME" journalctl -u mdns --no-pager -n 30 2>&1 || true
    if docker exec "$NAME" test -x /usr/local/bin/mdns 2>/dev/null; then
      echo "--- mdns status ---"
      docker exec "$NAME" mdns status 2>&1 || true
      echo "--- mdns diag ---"
      docker exec "$NAME" mdns diag 2>&1 || true
    else
      echo "(no mdns binary installed at the point of failure)"
    fi
  fi
  echo "--- teardown ---"
  if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || true; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -n "$stage" ]; then rm -rf "$stage"; fi
  exit "$status"
}
trap cleanup EXIT

# sha256 prints the SHA256 of a file, with the tool the host has.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# --- 1. build and stage the release tree ----------------------------------
echo "--- build the release binaries (make dist-linux) ---"
make dist-linux

case "$(docker info --format '{{.Architecture}}')" in
  aarch64 | arm64) GOARCH=arm64 ;;
  x86_64 | amd64) GOARCH=amd64 ;;
  *)
    echo "unsupported docker architecture" >&2
    exit 1
    ;;
esac
echo "docker architecture: $GOARCH"

echo "--- stage the release tree in the GitHub layout ---"
stage=$(mktemp -d)
mkdir -p "$stage/latest/download"
cp "dist/mdns-linux-$GOARCH" dist/SHA256SUMS "$stage/latest/download/"
cp install.sh "$stage/"

echo "--- serve $stage on 127.0.0.1 ---"
(cd "$stage" && exec python3 -m http.server 8931 --bind 127.0.0.1) \
  >"$stage/http.log" 2>&1 &
http_pid=$!
BASE_URL="http://$HOST:8931"

# The served tree must be this tree: a leftover server from an earlier run
# would answer on 8931 with whatever it was started on. (The host reaches
# the server on 127.0.0.1; only the container uses host.docker.internal.)
served_ok=0
for _ in $(seq 1 20); do
  curl -fsS -o "$stage/served-install.sh" "http://127.0.0.1:8931/install.sh" 2>/dev/null || true
  curl -fsS -o "$stage/served-binary" \
    "http://127.0.0.1:8931/latest/download/mdns-linux-$GOARCH" 2>/dev/null || true
  if [ -f "$stage/served-install.sh" ] && [ -f "$stage/served-binary" ] &&
    [ "$(sha256 "$stage/served-install.sh")" = "$(sha256 install.sh)" ] &&
    [ "$(sha256 "$stage/served-binary")" = "$(sha256 "dist/mdns-linux-$GOARCH")" ]; then
    served_ok=1
    break
  fi
  sleep 0.5
done
rm -f "$stage/served-install.sh" "$stage/served-binary"
if [ "$served_ok" -ne 1 ]; then
  echo "the file server on 8931 does not serve this tree;" >&2
  echo "another process may hold the port: stop it and re-run" >&2
  exit 1
fi
echo "serving $BASE_URL (install.sh, latest/download/mdns-linux-$GOARCH, latest/download/SHA256SUMS)"

# --- 2. the systemd container ---------------------------------------------
echo "--- start the systemd container ($IMAGE) ---"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --add-host="$HOST:host-gateway" \
  --hostname mdns-e2e-install \
  "$IMAGE" bash -c "$BOOTSTRAP" >/dev/null

echo "--- wait for systemd ---"
systemd_state=starting
for _ in $(seq 1 120); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
    echo "the container exited during setup:" >&2
    docker logs "$NAME" >&2 || true
    exit 1
  fi
  systemd_state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case "$systemd_state" in
    running | degraded) break ;;
  esac
  sleep 1
done
case "$systemd_state" in
  running | degraded) echo "systemd is $systemd_state" ;;
  *)
    echo "systemd did not come up (state: ${systemd_state:-none})" >&2
    docker logs "$NAME" >&2 || true
    exit 1
    ;;
esac

# The installer's port preflight binds 0.0.0.0:53; make sure the container
# really freed it (the stub drop-in above).
cassert "precondition: nothing listens on :53 (resolved stub disabled)" \
  '! ss -H -ltnu | grep -qE "[.:]53[[:space:]]"'

# --- phase A: download-mode install ---------------------------------------
echo
echo "=== phase A: download-mode install ==="
iassert "A1  download-mode one-liner exits 0 (download + SHA256 + install)" "$INSTALL_FLAGS" ok
note "$(printf '%s\n' "$LAST_OUT" | grep -E 'скачиваем|сумма|конфиг записан|юнит установлен|Установлено' | head -5 || true)"
if printf '%s\n' "$LAST_OUT" | grep -q "сумма mdns-linux-$GOARCH совпала"; then
  pass "A2  the downloaded release passed its SHA256 check"
else
  fail "A2  the downloaded release passed its SHA256 check" "$LAST_OUT"
fi

cassert "A3  /usr/local/bin/mdns is installed with mode 0755" \
  '[ -f /usr/local/bin/mdns ] && [ "$(stat -c %a /usr/local/bin/mdns)" = 755 ]'
cassert "A4  systemctl is-enabled mdns succeeds" 'systemctl is-enabled mdns'
ccontains "A5  systemctl is-active mdns is active" 'systemctl is-active mdns' 'active'
ccontains "A6  the unit restarts the daemon (Restart=always)" \
  'cat /etc/systemd/system/mdns.service' 'Restart=always'
ccontains "A7  /etc/mdns/config.json is mode 0600" 'stat -c %a /etc/mdns/config.json' '600'
ccontains "A8  /var/lib/mdns is mode 0700" 'stat -c %a /var/lib/mdns' '700'

# The daemon forwards to a real upstream, so the first answer can take a
# moment; the port is bound before the first query, hence the poll.
dns_answer=""
for _ in $(seq 1 30); do
  dns_answer=$(docker exec "$NAME" dig @127.0.0.1 example.com A +short +timeout=2 +tries=1 2>/dev/null || true)
  [ -n "$dns_answer" ] && break
  sleep 1
done
if [ -n "$dns_answer" ]; then
  pass "A9  plain DNS answers on 127.0.0.1:$PLAIN_PORT"
  note "example.com A -> $(printf '%s' "$dns_answer" | tr '\n' ' ')"
else
  fail "A9  plain DNS answers on 127.0.0.1:$PLAIN_PORT" \
    "$(docker exec "$NAME" mdns status 2>&1 || true)"
fi

ccontains "A10 mdns status reports the domain" 'mdns status' "Домен: $DOMAIN"

diag_status=0
diag_out=$(docker exec "$NAME" mdns diag 2>&1) || diag_status=$?
note "$(printf '%s\n' "$diag_out" | head -8)"
if [ "$diag_status" -eq 0 ] && ! printf '%s\n' "$diag_out" | grep -q '✗'; then
  pass "A11 mdns diag reports no failed check (only ! items are accepted)"
else
  fail "A11 mdns diag reports no failed check (only ! items are accepted)" "$diag_out"
fi

# --- phase B: idempotence -------------------------------------------------
echo
echo "=== phase B: idempotence ==="
config_before=$(docker exec "$NAME" sha256sum /etc/mdns/config.json | cut -d' ' -f1)
note "config hash before the re-run: $config_before"

iassert "B1  a second run over the running service exits 0" "$INSTALL_FLAGS" ok
if [ "$LAST_STATUS" -ne 0 ]; then
  note "NOTE: the installer aborted in its port preflight because the"
  note "service it installed already holds 53/443/853 — the installer even"
  note "names the holder: 'ports: заняты порты: 53 (занят: mdns), ...'. A"
  note "live re-run is how this project upgrades (design spec §3) and must"
  note "not fail (§4: 'повторный запуск ломает уже настроенное' is an"
  note "anti-goal). Defect measured by B1; see the Task 14 report."
fi
ccontains "B2  the service is still active after the re-run" 'systemctl is-active mdns' 'active'
config_after=$(docker exec "$NAME" sha256sum /etc/mdns/config.json | cut -d' ' -f1)
if [ "$config_after" = "$config_before" ]; then
  pass "B3  the existing config was kept (hash unchanged)"
else
  fail "B3  the existing config was kept (hash unchanged)" \
    "before $config_before / after $config_after"
fi

# Diagnostic probe (not an assertion): measure the same re-run with the
# service stopped, to pin the root cause of B1 on the running service.
# The installer starts it again through `systemctl enable --now`.
docker exec "$NAME" systemctl stop mdns
probe_status=0
probe_hash=""
probe_status_text=""
probe_log=$(run_installer "$INSTALL_FLAGS" 2>&1) || probe_status=$?
probe_hash=$(docker exec "$NAME" sha256sum /etc/mdns/config.json | cut -d' ' -f1)
if [ "$probe_hash" = "$config_before" ]; then probe_status_text=unchanged; else probe_status_text=rewritten; fi
note "probe: with 'systemctl stop mdns' first, the same command exits $probe_status;"
note "       the config is $probe_status_text and the service is $(docker exec "$NAME" systemctl is-active mdns)"

iassert "B4  a --reconfigure run exits 0" "$RECONFIG_FLAGS" ok
note "$(printf '%s\n' "$LAST_OUT" | grep -E 'конфиг записан|Установлено' | head -2 || true)"
reconfig_hash=$(docker exec "$NAME" sha256sum /etc/mdns/config.json | cut -d' ' -f1)
if [ "$reconfig_hash" != "$config_before" ]; then
  pass "B5  --reconfigure rewrote the config (hash changed)"
else
  fail "B5  --reconfigure rewrote the config (hash changed)" \
    "the config is still $reconfig_hash"
fi
ccontains "B6  the service is still active after the reconfigure" 'systemctl is-active mdns' 'active'

# `systemctl enable --now` is a no-op on an already-active unit, so the
# running daemon keeps the old config until it is restarted; restart it
# here to prove the rewritten config is valid and complete.
note "NOTE: the installer does not restart an active service, so the"
note "reconfigure applies from the next start (measured; see the report)."
docker exec "$NAME" systemctl restart mdns
dns_re=""
for _ in $(seq 1 30); do
  dns_re=$(docker exec "$NAME" dig @127.0.0.1 -p "$RE_PLAIN_PORT" example.com A +short +timeout=2 +tries=1 2>/dev/null || true)
  [ -n "$dns_re" ] && break
  sleep 1
done
if [ -n "$dns_re" ]; then
  pass "B7  the rewritten config is valid: the service runs it after a restart"
  note "example.com A on :$RE_PLAIN_PORT -> $(printf '%s' "$dns_re" | tr '\n' ' ')"
else
  fail "B7  the rewritten config is valid: the service runs it after a restart" \
    "$(docker exec "$NAME" mdns status 2>&1 || true)"
fi
ccontains "B8  the restarted daemon reports the new domain" 'mdns status' "Домен: $RE_DOMAIN"

# --- phase C: a failed install leaves no half-state -----------------------
echo
echo "=== phase C: a failed install leaves no half-state ==="
reset_install
cexpect_fail "C1  precondition: no unit is enabled" 'systemctl is-enabled mdns'
cassert "C2  precondition: no config exists" '[ ! -e /etc/mdns/config.json ]'

iassert "C3  install with --domain 'bad domain' fails" \
  "--non-interactive --domain 'bad domain' --tls self-signed --provider cloudflare" fail
note "$(printf '%s\n' "$LAST_OUT" | tail -2)"
if printf '%s\n' "$LAST_OUT" | grep -q 'domain'; then
  pass "C4  the failure names the domain"
else
  fail "C4  the failure names the domain" "$LAST_OUT"
fi
cexpect_fail "C5  systemctl is-enabled mdns fails (no unit was installed)" 'systemctl is-enabled mdns'
cexpect_fail "C6  systemctl is-active mdns fails (no service was started)" 'systemctl is-active mdns'
cassert "C7  /etc/mdns/config.json does not exist" '[ ! -e /etc/mdns/config.json ]'
cassert "C8  /var/lib/mdns does not exist" '[ ! -e /var/lib/mdns ]'
note "the binary is the only artifact install.sh left behind: $(docker exec "$NAME" ls -l /usr/local/bin/mdns 2>&1 || true)"

# --- phase D: uninstall ---------------------------------------------------
echo
echo "=== phase D: uninstall ==="
reset_install
iassert "D1  install exits 0" "$INSTALL_FLAGS" ok
ccontains "D2  the service is active" 'systemctl is-active mdns' 'active'

cassert "D3  mdns uninstall --yes exits 0" 'mdns uninstall --yes'
cexpect_fail "D4  the service is gone" 'systemctl is-active mdns'
cassert "D5  the config is kept" '[ -f /etc/mdns/config.json ]'
cassert "D6  the data dir is kept" '[ -d /var/lib/mdns ]'
cassert "D7  the binary is gone" '[ ! -e /usr/local/bin/mdns ]'
cassert "D8  the unit is gone" '[ ! -e /etc/systemd/system/mdns.service ]'

iassert "D9  a reinstall after the uninstall exits 0" "$INSTALL_FLAGS" ok
ccontains "D10 the service works again" 'systemctl is-active mdns' 'active'

cassert "D11 uninstall --keep-binary --yes exits 0" 'mdns uninstall --keep-binary --yes'
cassert "D12 the binary is kept" '[ -x /usr/local/bin/mdns ]'
cexpect_fail "D13 the service is gone again" 'systemctl is-active mdns'

iassert "D14 install (before the purge) exits 0" "$INSTALL_FLAGS" ok
cassert "D15 uninstall --purge --yes exits 0" 'mdns uninstall --purge --yes'
cexpect_fail "D16 the service is gone" 'systemctl is-active mdns'
cassert "D17 the config is gone" '[ ! -e /etc/mdns/config.json ]'
cassert "D18 the data dir is gone" '[ ! -e /var/lib/mdns ]'
cassert "D19 the unit is gone" '[ ! -e /etc/systemd/system/mdns.service ]'

# --- summary --------------------------------------------------------------
echo
echo "--- summary ---"
printf '%s assertions, %s failed\n' "$checks" "$failed"
if [ "$failed" -ne 0 ]; then
  echo "e2e-install: FAILED ($failed of $checks assertions)" >&2
  exit 1
fi

echo
echo "e2e-install: passed"
