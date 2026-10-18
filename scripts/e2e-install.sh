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
#   B  idempotence and the live reconfigure: a re-run over the running
#      service keeps the config and restarts the daemon on the new binary;
#      --reconfigure rewrites the config and the *running* daemon serves
#      it without any manual restart.
#   C  a failed install leaves no half-state: a bad domain aborts before
#      anything is written, the unit is not enabled, no config exists.
#   D  uninstall: the config/data survive by default, --keep-binary keeps
#      the binary, --purge removes everything.
#
# Phase B is the regression test for two installer defects Task 14 found
# and 01372cc fixed (ledger R14): the port preflight used to abort when the
# service it installed held the very ports the new config wants, and
# `systemctl enable --now mdns` is a no-op on an active unit, so a
# reconfigure never reached the running daemon. Both matter because the
# design spec §3 makes re-running the one-liner the upgrade path
# ("обновление — переустановкой скриптом") and §4 makes "повторный запуск
# ломает уже настроенное" an anti-goal.
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
source scripts/e2e-lib.sh

IMAGE=ubuntu:24.04
NAME=mdns-e2e-install
HOST=host.docker.internal
DOMAIN=mdns.test
# Ports of the install under test.
PLAIN_PORT=53
DOH_PORT=443
DOT_PORT=853
DOQ_PORT=853
# The --reconfigure run changes the domain and keeps the ports, so it is
# both the natural "change my domain" reconfiguration and the strongest
# case for the port preflight: the running service holds exactly the ports
# the new config asks for.
RE_DOMAIN=mdns2.test

# Flags of every successful install below; phase C deliberately breaks
# the domain.
INSTALL_FLAGS="--non-interactive --domain $DOMAIN --tls self-signed --provider cloudflare --plain-port $PLAIN_PORT --doh-port $DOH_PORT --dot-port $DOT_PORT --doq-port $DOQ_PORT --panel --password 'test-panel-pass'"
RECONFIG_FLAGS="--non-interactive --reconfigure --domain $RE_DOMAIN --tls self-signed --provider cloudflare --plain-port $PLAIN_PORT --doh-port $DOH_PORT --dot-port $DOT_PORT --doq-port $DOQ_PORT --panel --password 'test-panel-pass'"

# The container bootstrap (systemd, client tools, resolved stub off),
# the release staging and the readiness poll live in scripts/e2e-lib.sh,
# shared with e2e-panel.sh; this script owns its phases and assertions.

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
  if [ -n "$http_pid" ]; then
    kill "$http_pid" 2>/dev/null || true
    wait "$http_pid" 2>/dev/null || true
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -n "$stage" ]; then rm -rf "$stage"; fi
  exit "$status"
}
trap cleanup EXIT

# --- 1. build and stage the release tree ----------------------------------
echo "--- build the release binaries (make dist-linux) ---"
make dist-linux

GOARCH=$(e2e_goarch) || exit 1
echo "docker architecture: $GOARCH"

echo "--- stage the release tree in the GitHub layout ---"
stage=$(mktemp -d)
e2e_stage_release "$stage" "$GOARCH" 8931
http_pid=$E2E_HTTP_PID
BASE_URL="http://$HOST:8931"
echo "serving $BASE_URL (install.sh, latest/download/mdns-linux-$GOARCH, latest/download/SHA256SUMS)"

# --- 2. the systemd container ---------------------------------------------
e2e_start_systemd "$NAME" "$IMAGE" mdns-e2e-install

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

# The panel (Task 10/12) is installed by the same one-liner; these three
# checks pin the non-interactive contract the panel e2e builds on: the
# summary announces it, the browser-facing GET redirects an anonymous
# visitor to the login form, and an anonymous mutation is 401 (not a 404
# and not a redirect) because there is no form to send it back to.
if printf '%s\n' "$LAST_OUT" | grep -q "Панель: https://$DOMAIN/"; then
  pass "A12 the install summary announces the web panel"
else
  fail "A12 the install summary announces the web panel" "$LAST_OUT"
fi
panel_get=$(docker exec "$NAME" bash -c \
  "curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' https://127.0.0.1/panel/" 2>&1 || true)
if printf '%s' "$panel_get" | grep -qE '^303 .*/login$'; then
  pass "A13 an anonymous GET /panel/ redirects to /login"
else
  fail "A13 an anonymous GET /panel/ redirects to /login" "$panel_get"
fi
panel_post=$(docker exec "$NAME" bash -c \
  "curl -sk -o /dev/null -w '%{http_code}' -X POST --data 'id=cloudflare' https://127.0.0.1/panel/upstreams/toggle" 2>&1 || true)
if [ "$panel_post" = 401 ]; then
  pass "A14 an anonymous panel mutation is 401"
else
  fail "A14 an anonymous panel mutation is 401" "status: $panel_post"
fi
cassert "A15 the panel password is stored only as an argon2id hash" \
  "grep -q argon2id /etc/mdns/config.json && ! grep -q test-panel-pass /etc/mdns/config.json"

# --- phase B: idempotence and the live reconfigure ------------------------
echo
echo "=== phase B: idempotence and the live reconfigure ==="
# The hash of the config and the identity of the running daemon, before
# anything: the hash proves "config kept / config rewritten", the MainPID
# proves the installer actually restarted the service.
config_hash() { docker exec "$NAME" sha256sum /etc/mdns/config.json | cut -d' ' -f1; }
main_pid() { docker exec "$NAME" systemctl show -p MainPID --value mdns 2>/dev/null | tr -d ' \n'; }
active_since() { docker exec "$NAME" systemctl show -p ActiveEnterTimestamp --value mdns 2>/dev/null; }
# valid_pid reports whether a MainPID reading identifies a live process.
# A comparison of two PIDs is only meaningful when both sides are live, so
# every restart assertion guards both: a dead daemon must fail loudly here
# rather than make B1/B5/B9 pass without exercising anything.
valid_pid() { [ -n "$1" ] && [ "$1" != "0" ]; }

config_before=$(config_hash)
pid_before=$(main_pid)
note "before the re-run: config $config_before, daemon MainPID $pid_before, $(active_since)"

# B0 is the precondition of the whole phase: the daemon has to be up and
# has to be the process holding 53/443/853. Without it B1 would not take
# the held-port path (the D1 case) and the PID comparisons would compare
# nothing.
ccontains "B0  the daemon is active before the re-run (it holds the ports)" \
  'systemctl is-active mdns' 'active'
if valid_pid "$pid_before"; then
  pass "B0b the daemon reported a live MainPID ($pid_before)"
else
  fail "B0b the daemon reported a live MainPID" "MainPID before the re-run: '${pid_before}'"
fi
cassert "B0c the daemon holds a listening port (ss names the mdns process)" \
  'ss -H -ltnup | grep -q "mdns"'

iassert "B1  a second run over the running service exits 0" "$INSTALL_FLAGS" ok
note "$(printf '%s\n' "$LAST_OUT" | grep -E 'скачиваем|сумма|оставлен без изменений' | head -3 || true)"
if printf '%s\n' "$LAST_OUT" | grep -q 'оставлен без изменений'; then
  pass "B2  the re-run reported that it keeps the existing config"
else
  fail "B2  the re-run reported that it keeps the existing config" "$LAST_OUT"
fi
config_after=$(config_hash)
if [ "$config_after" = "$config_before" ]; then
  pass "B3  the config file is unchanged (hash $config_before)"
else
  fail "B3  the config file is unchanged" "before $config_before / after $config_after"
fi
ccontains "B4  the service is active after the re-run" 'systemctl is-active mdns' 'active'
pid_after=$(main_pid)
if valid_pid "$pid_before" && valid_pid "$pid_after" && [ "$pid_after" != "$pid_before" ]; then
  pass "B5  the re-run restarted the daemon (MainPID $pid_before -> $pid_after)"
else
  fail "B5  the re-run restarted the daemon" \
    "MainPID before '${pid_before}', after '${pid_after}'; both must be live and must differ"
fi

iassert "B6  a --reconfigure run exits 0 (same ports, new domain $RE_DOMAIN)" "$RECONFIG_FLAGS" ok
note "$(printf '%s\n' "$LAST_OUT" | grep -E 'конфиг записан|Установлено' | head -2 || true)"
reconfig_hash=$(config_hash)
if [ "$reconfig_hash" != "$config_before" ]; then
  pass "B7  --reconfigure rewrote the config (hash changed)"
else
  fail "B7  --reconfigure rewrote the config (hash changed)" "the config is still $reconfig_hash"
fi
ccontains "B8  the service is active after the reconfigure" 'systemctl is-active mdns' 'active'
reconfig_pid=$(main_pid)
if valid_pid "$pid_after" && valid_pid "$reconfig_pid" && [ "$reconfig_pid" != "$pid_after" ]; then
  pass "B9  the reconfigure restarted the daemon (MainPID $pid_after -> $reconfig_pid)"
else
  fail "B9  the reconfigure restarted the daemon" \
    "MainPID before '${pid_after}', after '${reconfig_pid}'; both must be live and must differ"
fi

# The strongest proof of D2's fix: the daemon that is running right now —
# nobody restarted it by hand — reports the rewritten config. The status
# call is polled because the restart ends the old listener first.
live_domain=""
for _ in $(seq 1 30); do
  live_domain=$(docker exec "$NAME" mdns status 2>/dev/null | sed -n 's/^Домен: //p' || true)
  [ "$live_domain" = "$RE_DOMAIN" ] && break
  sleep 1
done
if [ "$live_domain" = "$RE_DOMAIN" ]; then
  pass "B10 the running daemon serves the new config (mdns status: Домен: $live_domain)"
else
  fail "B10 the running daemon serves the new config (mdns status: Домен: $live_domain)" \
    "$(docker exec "$NAME" mdns status 2>&1 || true)"
fi
note "daemon MainPID $pid_before -> $pid_after -> $reconfig_pid; $(active_since)"

dns_re=""
for _ in $(seq 1 30); do
  dns_re=$(docker exec "$NAME" dig @127.0.0.1 -p "$PLAIN_PORT" example.com A +short +timeout=2 +tries=1 2>/dev/null || true)
  [ -n "$dns_re" ] && break
  sleep 1
done
if [ -n "$dns_re" ]; then
  pass "B11 plain DNS still answers on :$PLAIN_PORT after the reconfigure"
  note "example.com A -> $(printf '%s' "$dns_re" | tr '\n' ' ')"
else
  fail "B11 plain DNS still answers on :$PLAIN_PORT after the reconfigure" \
    "$(docker exec "$NAME" mdns status 2>&1 || true)"
fi

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
