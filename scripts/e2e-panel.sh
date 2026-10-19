#!/usr/bin/env bash
# Docker end-to-end test of the mdns web panel.
#
# The panel is a browser surface: the Go handler tests prove the routes and
# the templates, but only a real browser can prove the login flow, the
# chart tooltip, the live feed and the live request screen over SSE, and the
# phone layout. This test
# installs mdns inside a real systemd container with the same download-mode
# one-liner a user runs, then drives a real Chromium on the host against
# https://127.0.0.1:8443 (the container's DoH/panel port 443, published
# there; the self-signed certificate is for mdns.test, and the test ignores
# the TLS error — the Go mux routes by path, so the host address is fine).
#
# Harness:
#   * scripts/e2e-lib.sh owns the systemd container, the release staging and
#     the readiness poll — the same harness as e2e-install.sh, not a second
#     one.
#   * Phase A installs with `--panel --password 'test-panel-pass'` and
#     --filter basic, waits for the block lists, generates traffic (130
#     searchable names + 10 blocked ones), runs e2e/panel/panel_test.py and
#     leaves screenshots in e2e/panel/shots/.
#   * Phase B uninstalls and reinstalls without --panel/--password, then
#     runs the same test with --disabled: /panel/ and /login must be 404.
#
# Playwright (host):
#   The Python Playwright is not a repo dependency. The test uses a local
#   .venv-pw (gitignored). If it is missing, this script creates it and
#   downloads Playwright + Chromium (one-time, ~250 MB), saying so first.
#   To prepare it by hand instead:
#
#     python3 -m venv .venv-pw
#     .venv-pw/bin/pip install playwright
#     .venv-pw/bin/playwright install chromium
#
# Publishing only 443->8443 keeps :53, :853 and :443 on the developer
# machine untouched (a real resolver may own them).
#
# Usage:
#   scripts/e2e-panel.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/e2e-lib.sh

IMAGE=ubuntu:24.04
NAME=mdns-e2e-panel
HOST=host.docker.internal
DOMAIN=mdns.test
PLAIN_PORT=53
DOH_PORT=443
DOT_PORT=853
DOQ_PORT=853
# The host port the panel is tested on; the container's 443 stays canonical.
HOST_PORT=8443
PANEL_URL="https://127.0.0.1:$HOST_PORT"
PORT=8932
PASSWORD=test-panel-pass
VENV=.venv-pw
SHOTS="$PWD/e2e/panel/shots"

# Phase A installs the panel and the basic block lists (the blocked name
# below is in adguard-dns-filter and oisd-small). Phase B installs neither:
# no --password means panel.enabled=false, no --filter means filtering off.
PANEL_FLAGS="--non-interactive --domain $DOMAIN --tls self-signed --provider cloudflare --plain-port $PLAIN_PORT --doh-port $DOH_PORT --dot-port $DOT_PORT --doq-port $DOQ_PORT --filter basic --panel --password '$PASSWORD'"
PLAIN_FLAGS="--non-interactive --domain $DOMAIN --tls self-signed --provider cloudflare --plain-port $PLAIN_PORT --doh-port $DOH_PORT --dot-port $DOT_PORT --doq-port $DOQ_PORT"

# --- assertion bookkeeping ------------------------------------------------
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
# inner command unquoted, so single quotes keep an argument together.
run_installer() {
  docker exec -e "MDNS_BASE_URL=$BASE_URL" "$NAME" \
    bash -c "curl -fsSL '$BASE_URL/install.sh' | bash -s -- $1"
}

# iassert records the outcome of the one-liner: want is ok or fail.
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

# http_status prints the HTTP status curl received from the panel.
http_status() {
  curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$PANEL_URL$1" 2>/dev/null || true
}

# wait_panel waits until the panel answers on the published port.
wait_panel() {
  local want=$1 path=$2 code=""
  for _ in $(seq 1 60); do
    code=$(http_status "$path")
    [ "$code" = "$want" ] && return 0
    sleep 1
  done
  return 1
}

# ensure_playwright makes the host venv usable, announcing the download.
ensure_playwright() {
  if [ -x "$VENV/bin/python" ] &&
    "$VENV/bin/python" -c 'import playwright' >/dev/null 2>&1; then
    return 0
  fi
  echo "e2e-panel: $VENV is missing or incomplete; creating it now."
  echo "e2e-panel: this is a one-time download of Playwright and Chromium (~250 MB)."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet playwright
  "$VENV/bin/playwright" install chromium
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
    docker exec "$NAME" journalctl -u mdns --no-pager -n 40 2>&1 || true
    if docker exec "$NAME" test -x /usr/local/bin/mdns 2>/dev/null; then
      echo "--- mdns status ---"
      docker exec "$NAME" mdns status 2>&1 || true
      echo "--- mdns diag ---"
      docker exec "$NAME" mdns diag 2>&1 || true
      echo "--- /etc/mdns/config.json (panel section) ---"
      docker exec "$NAME" sh -c 'sed -n "/\"panel\"/,/}/p" /etc/mdns/config.json' 2>&1 || true
      echo "--- filter list files ---"
      docker exec "$NAME" ls -l /var/lib/mdns/filters 2>&1 || true
    else
      echo "(no mdns binary installed at the point of failure)"
    fi
    echo "--- panel over the published port ---"
    curl -sk -o /dev/null -w '/login -> %{http_code}\n' --max-time 5 "$PANEL_URL/login" 2>&1 || true
    curl -sk -o /dev/null -w '/panel/ -> %{http_code}\n' --max-time 5 "$PANEL_URL/panel/" 2>&1 || true
    echo "--- screenshots present ---"
    ls -l "$SHOTS" 2>&1 || true
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

# --- 1. build, stage and start -------------------------------------------
if command -v lsof >/dev/null 2>&1 &&
  lsof -nP -iTCP:"$HOST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "host port $HOST_PORT is already in use; stop that process and re-run" >&2
  exit 1
fi

ensure_playwright
"$VENV/bin/python" -c 'import playwright' >/dev/null

echo "--- build the release binaries (make dist-linux) ---"
make dist-linux

GOARCH=$(e2e_goarch) || exit 1
echo "docker architecture: $GOARCH"

echo "--- stage the release tree in the GitHub layout ---"
stage=$(mktemp -d)
e2e_stage_release "$stage" "$GOARCH" "$PORT"
http_pid=$E2E_HTTP_PID
BASE_URL="http://$HOST:$PORT"
echo "serving $BASE_URL (install.sh, latest/download/mdns-linux-$GOARCH, latest/download/SHA256SUMS)"

mkdir -p "$SHOTS"
# Keep this run's output from passing for the previous run's: an empty
# shots directory means a failed test cannot leave stale evidence behind.
rm -f "$SHOTS"/*.png

e2e_start_systemd "$NAME" "$IMAGE" mdns-e2e-panel \
  -p "127.0.0.1:$HOST_PORT:$DOH_PORT"

# The installer's port preflight binds 0.0.0.0:53; make sure the container
# really freed it (the stub drop-in in the shared bootstrap).
cassert "precondition: nothing listens on :53 (resolved stub disabled)" \
  '! ss -H -ltnu | grep -qE "[.:]53[[:space:]]"'

# --- phase A: the panel on a real installation ---------------------------
echo
echo "=== phase A: install with --panel and drive the UI ==="
iassert "A1  the one-liner installs with --panel --password and exits 0" "$PANEL_FLAGS" ok
note "$(printf '%s\n' "$LAST_OUT" | grep -E 'скачиваем|сумма|конфиг записан|Панель|Фильтрация' | head -6 || true)"
if printf '%s\n' "$LAST_OUT" | grep -q "Панель: https://$DOMAIN/"; then
  pass "A2  the install summary announces the panel"
else
  fail "A2  the install summary announces the panel" "$LAST_OUT"
fi
if printf '%s\n' "$LAST_OUT" | grep -q 'Фильтрация: включена, списков 2'; then
  pass "A3  the basic filter preset installed two block lists"
else
  fail "A3  the basic filter preset installed two block lists" "$LAST_OUT"
fi
ccontains "A4  systemctl is-active mdns is active" 'systemctl is-active mdns' 'active'
cassert "A5  the panel password is stored only as an argon2id hash" \
  "grep -q argon2id /etc/mdns/config.json && ! grep -q '$PASSWORD' /etc/mdns/config.json"

# The panel shares the DoH listener, and the container port is published to
# the host; wait for the login page to answer before the browser starts.
if wait_panel 200 /login; then
  pass "A6  the panel answers https://127.0.0.1:$HOST_PORT/login with 200"
else
  fail "A6  the panel answers https://127.0.0.1:$HOST_PORT/login with 200" \
    "$(docker exec "$NAME" mdns status 2>&1 || true)"
fi
anon=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 5 \
  "$PANEL_URL/panel/" 2>/dev/null || true)
if printf '%s' "$anon" | grep -qE '^303 .*/login$'; then
  pass "A7  an anonymous GET /panel/ redirects to /login"
else
  fail "A7  an anonymous GET /panel/ redirects to /login" "$anon"
fi

# A block list is fetched by the daemon after the restart. The network is
# outside the test's control (a Docker Desktop DNS hiccup once failed
# small.oisd.nl while adguard-dns-filter loaded), and the panel only
# needs *a* working list: wait for the blocked name itself to answer
# zero, not for every configured download. `doubleclick.ne.jp` is in
# both lists of the basic preset.
echo "--- wait for the block list to take effect ---"
blocked_answer=""
for _ in $(seq 1 120); do
  blocked_answer=$(docker exec "$NAME" bash -c \
    'dig @127.0.0.1 doubleclick.ne.jp A +short +timeout=3 +tries=1' 2>/dev/null || true)
  printf '%s' "$blocked_answer" | grep -qx '0.0.0.0' && break
  sleep 1
done
if printf '%s' "$blocked_answer" | grep -qx '0.0.0.0'; then
  pass "A8  a basic block list is applied (doubleclick.ne.jp answers 0.0.0.0)"
  note "doubleclick.ne.jp A -> $(printf '%s' "$blocked_answer" | tr '\n' ' ')"
else
  fail "A8  a basic block list is applied (doubleclick.ne.jp answers 0.0.0.0)" \
    "$(docker exec "$NAME" mdns status 2>&1 || true)"
fi
rules_loaded=$(docker exec "$NAME" sh -c \
  'ls /var/lib/mdns/filters/*.rules 2>/dev/null | wc -l' 2>/dev/null | tr -d ' \n')
if [ -n "$rules_loaded" ] && [ "$rules_loaded" -ge 1 ]; then
  pass "A9  the applied block list is persisted under /var/lib/mdns/filters"
  note "rules files: $rules_loaded of 2 configured ($(docker exec "$NAME" sh -c \
    'ls /var/lib/mdns/filters/*.rules 2>/dev/null | xargs -r -n1 basename' | tr '\n' ' '))"
else
  fail "A9  the applied block list is persisted under /var/lib/mdns/filters" \
    "$(docker exec "$NAME" ls -l /var/lib/mdns/filters 2>&1 || true)"
fi

# Traffic: 130 unique names sharing the substring the browser search types
# (two history pages at 100 per page), ten blocked queries so the
# «заблокировано» segment and its filtered history are non-empty, and one
# normal query. Batching 40 names at a time stays under the plain-DNS rate
# limit (50 rps/IP); the one-second gaps refill the bucket.
echo "--- generate DNS traffic inside the container ---"
docker exec "$NAME" bash -c '
set -e
for batch in 0 1 2 3; do
  names=""
  for i in $(seq $((batch * 40 + 1)) $((batch * 40 + 40))); do
    [ "$i" -le 130 ] || continue
    names="$names e2e-search-$i.example.com"
  done
  if [ -n "$names" ]; then
    dig @127.0.0.1 $names A +short +timeout=3 +tries=1 >/dev/null 2>&1 || true
  fi
  sleep 1
done
dig @127.0.0.1 doubleclick.ne.jp doubleclick.ne.jp doubleclick.ne.jp \
  doubleclick.ne.jp doubleclick.ne.jp doubleclick.ne.jp doubleclick.ne.jp \
  doubleclick.ne.jp doubleclick.ne.jp doubleclick.ne.jp A +short \
  +timeout=3 +tries=1 >/dev/null 2>&1 || true
dig @127.0.0.1 example.com A +short +timeout=3 +tries=1 >/dev/null 2>&1 || true
'
# Prove the traffic reached the query journal, not just dig: the search
# filter used by the browser must see all 130 names, and the blocked
# outcome must see the ten blocked queries.
api_total() {
  docker exec "$NAME" bash -c \
    "curl -s --unix-socket /run/mdns/mdns.sock 'http://localhost/api/v1/requests?$1&per=1'" 2>/dev/null |
    tr ',' '\n' | sed -n 's/.*"total":\([0-9]*\).*/\1/p'
}
search_total=$(api_total 'q=e2e-search')
blocked_total=$(api_total 'outcome=blocked')
if [ "$search_total" = 130 ] && [ -n "$blocked_total" ] && [ "$blocked_total" -ge 10 ]; then
  pass "A10 the query journal holds the generated traffic ($search_total search, $blocked_total blocked)"
else
  fail "A10 the query journal holds the generated traffic" \
    "search total: ${search_total:-none} (want 130), blocked total: ${blocked_total:-none} (want >= 10)"
fi

echo "--- browser: e2e/panel/panel_test.py ---"
browser_ok=0
if PANEL_BASE_URL="$PANEL_URL" \
  PANEL_PASSWORD="$PASSWORD" \
  PANEL_CONTAINER="$NAME" \
  PANEL_SHOTS="$SHOTS" \
  "$VENV/bin/python" e2e/panel/panel_test.py; then
  browser_ok=1
  pass "A11 the Playwright scenario passes (login, charts, history, feed, CSRF, mobile)"
else
  fail "A11 the Playwright scenario passes (login, charts, history, feed, CSRF, mobile)" \
    "see the assertion lines above; post-mortem follows the summary"
fi

shots_ok=1
for shot in login.png status-desktop.png history-filtered.png history-page2.png mobile.png; do
  [ -s "$SHOTS/$shot" ] || shots_ok=0
done
if [ "$shots_ok" -eq 1 ]; then
  pass "A12 all five screenshots were captured into e2e/panel/shots/"
  note "$(cd "$SHOTS" && ls -lh *.png | awk '{print $5, $9}' | tr '\n' ' ')"
else
  fail "A12 all five screenshots were captured into e2e/panel/shots/" \
    "$(ls -l "$SHOTS" 2>&1 || true)"
fi

# --- phase B: the panel off ----------------------------------------------
echo
echo "=== phase B: reinstall without --password (panel.enabled=false) ==="
cassert "B1  mdns uninstall --purge --yes exits 0" 'mdns uninstall --purge --yes'
iassert "B2  the one-liner installs without --panel/--password and exits 0" "$PLAIN_FLAGS" ok
note "$(printf '%s\n' "$LAST_OUT" | grep -E 'конфиг записан|Веб-панель выключена|Установлено' | head -3 || true)"
if printf '%s\n' "$LAST_OUT" | grep -q 'Веб-панель выключена'; then
  pass "B3  the install summary says the panel is off"
else
  fail "B3  the install summary says the panel is off" "$LAST_OUT"
fi
ccontains "B4  the service is active after the reinstall" 'systemctl is-active mdns' 'active'
cassert "B5  the config carries no panel password" \
  '! grep -q password_hash /etc/mdns/config.json'

if wait_panel 404 /login; then
  pass "B6  /login answers 404 with the panel off"
else
  fail "B6  /login answers 404 with the panel off" "status: $(http_status /login)"
fi
if wait_panel 404 /panel/; then
  pass "B7  /panel/ answers 404 with the panel off"
else
  fail "B7  /panel/ answers 404 with the panel off" "status: $(http_status /panel/)"
fi

echo "--- browser: e2e/panel/panel_test.py --disabled ---"
disabled_ok=0
if PANEL_BASE_URL="$PANEL_URL" \
  PANEL_PASSWORD="$PASSWORD" \
  PANEL_CONTAINER="$NAME" \
  PANEL_SHOTS="$SHOTS" \
  "$VENV/bin/python" e2e/panel/panel_test.py --disabled; then
  disabled_ok=1
  pass "B8  the Playwright request API sees 404 on /panel/ and /login"
else
  fail "B8  the Playwright request API sees 404 on /panel/ and /login" \
    "see the assertion lines above"
fi

# --- summary --------------------------------------------------------------
echo
echo "--- summary ---"
printf '%s assertions, %s failed\n' "$checks" "$failed"
if [ "$failed" -ne 0 ]; then
  echo "e2e-panel: FAILED ($failed of $checks assertions)" >&2
  exit 1
fi
if [ "$browser_ok" -ne 1 ] || [ "$disabled_ok" -ne 1 ]; then
  echo "e2e-panel: a browser run failed (see above)" >&2
  exit 1
fi
if [ "$shots_ok" -ne 1 ]; then
  echo "e2e-panel: screenshots are missing (see above)" >&2
  exit 1
fi

echo
echo "e2e-panel: passed"
