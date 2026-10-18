#!/usr/bin/env bash
# Local performance stand for mdns: a fake upstream, a daemon on a temp
# config, a query generator and load-time checks of the API, the TUI and
# the web panel.
#
# The harness is deliberately a plain bash script: it runs on a developer
# macOS machine (or a Linux VPS) without Docker, uses only localhost ports
# and leaves nothing behind on success. Ports are env-overridable:
#
#   PERF_PLAIN=53 PERF_DOH=8443 PERF_DOT=8853 PERF_DOQ=8853 \
#     scripts/perf-local.sh
#
# Scenario knobs:
#   PERF_SMOKE=200000       warm-up mix (200k, 64 workers)
#   PERF_TOTAL=20000000     main mix (default 20M, 64 workers)
#   PERF_PROBE_DELAY=60     seconds of main load before the UI probes
#   PERF_BURST=60s          burst duration (128 workers)
#   PERF_DOH_TOTAL=100000   DoH queries (32 workers)
#
# Thresholds (the script fails if any is missed):
#   * 0 errors in every load phase (smoke, main, burst, DoH)
#   * `mdns status` under load <= 250 ms
#   * TUI key response <= 2 s
#   * authenticated panel page under load <= 1 s and it renders the feed
#   * physical footprint after the run <= 200 MB (hard failure;
#     `ps` RSS is printed for reference only, it counts shared pages)
#   * counters converge: blocked ~20%, upstream ~10%, hits+misses+blocked
#     ~ all sent queries (see docs/perf-results.md)
#
# Output: docs/perf-results.md is filled from a real run; screenshots and
# TUI captures go to .superpowers/sdd/2026-10-18-mdns-panel/task-13-shots/
# (gitignored). The temp dir is removed on success and kept on failure.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD

PERF_PLAIN=${PERF_PLAIN:-53}
PERF_DOH=${PERF_DOH:-8443}
PERF_DOT=${PERF_DOT:-8853}
PERF_DOQ=${PERF_DOQ:-8853}
PERF_SMOKE=${PERF_SMOKE:-200000}
PERF_TOTAL=${PERF_TOTAL:-20000000}
PERF_PROBE_DELAY=${PERF_PROBE_DELAY:-60}
PERF_BURST=${PERF_BURST:-60s}
PERF_BURST_WORKERS=${PERF_BURST_WORKERS:-128}
PERF_DOH_TOTAL=${PERF_DOH_TOTAL:-100000}
PERF_WORKERS=${PERF_WORKERS:-64}

DOMAIN=perf.test
PASSWORD=perf-panel-pass
UPSTREAM=127.0.0.1:53530
CACHE_SIZE=50000
LOG_ENTRIES=20000
SHOTS="$REPO/.superpowers/sdd/2026-10-18-mdns-panel/task-13-shots"

# A short path: the unix socket cannot exceed ~104 bytes.
TMP=$(mktemp -d /tmp/mdns-perf.XXXXXX)
SOCKET="$TMP/mdns.sock"
CONFIG="$TMP/config.json"
TMUX_SESSION="mdns-perf-$$"

CHECKS=0
FAILS=0
MDNS_PID=""
FAKE_PID=""
TMUX_STARTED=0
TOTAL_SENT=0
TOTAL_PRE=0

pass() {
  CHECKS=$((CHECKS + 1))
  printf '  PASS  %s\n' "$1"
}
fail() {
  CHECKS=$((CHECKS + 1))
  FAILS=$((FAILS + 1))
  printf '  FAIL  %s\n' "$1"
  if [ -n "${2:-}" ]; then
    printf '%s\n' "$2" | sed 's/^/        /'
  fi
}
note() { printf '%s\n' "$1" | sed 's/^/        /'; }
phase() { printf '\n--- %s ---\n' "$1"; }

now_ms() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000'; }
is_num() { case "${1:-}" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }
rss_mb() { ps -o rss= -p "$1" 2>/dev/null | awk '{printf "%.0f", $1 / 1024}'; }
# ps RSS counts shared pages too (dyld cache, shared libraries), so it
# overstates the daemon's own memory. vmmap's "physical footprint" is the
# accurate number and the one the 200 MB gate uses; it is best-effort and
# macOS-only, so a missing value prints nothing and the caller warns
# instead of silently passing.
footprint_mb() {
  if ! command -v vmmap >/dev/null 2>&1; then
    return
  fi
  local out
  out=$(vmmap -summary "$1" 2>/dev/null |
    awk '/^Physical footprint:/ {
      v = $3
      if (v ~ /K$/) { sub(/K$/, "", v); printf "%.0f", v / 1024 }
      else if (v ~ /G$/) { sub(/G$/, "", v); printf "%.0f", v * 1024 }
      else { sub(/M$/, "", v); printf "%.0f", v }
      exit
    }')
  echo "$out"
}
json_get() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]])' "$1" "$2"; }

banner() {
  echo "perf-local: mdns local performance stand"
  echo "  repo:       $REPO"
  echo "  temp:       $TMP"
  echo "  domain:     $DOMAIN (plain :$PERF_PLAIN, doh :$PERF_DOH, dot :$PERF_DOT, doq :$PERF_DOQ)"
  echo "  upstream:   $UPSTREAM (fakedns)"
  echo "  load:       smoke=$PERF_SMOKE main=$PERF_TOTAL burst=$PERF_BURST/$PERF_BURST_WORKERS doh=$PERF_DOH_TOTAL"
  echo "  panel:      https://127.0.0.1:$PERF_DOH/panel/ (password $PASSWORD)"
  echo "  shots:      $SHOTS"
}

# --- teardown -------------------------------------------------------------
cleanup() {
  status=$?
  trap - EXIT INT TERM

  if [ "$TMUX_STARTED" -eq 1 ] &&
    tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
  fi
  if [ -n "$MDNS_PID" ] && kill -0 "$MDNS_PID" 2>/dev/null; then
    kill -TERM "$MDNS_PID" 2>/dev/null || true
    wait "$MDNS_PID" 2>/dev/null || true
  fi
  if [ -n "$FAKE_PID" ] && kill -0 "$FAKE_PID" 2>/dev/null; then
    kill -TERM "$FAKE_PID" 2>/dev/null || true
    wait "$FAKE_PID" 2>/dev/null || true
  fi

  if [ "$status" -ne 0 ] || [ "$FAILS" -ne 0 ]; then
    echo
    echo "--- post-mortem ---"
    echo "--- mdns log (tail 30) ---"
    tail -30 "$TMP/mdns.log" 2>/dev/null || true
    echo "--- fakedns log (tail 10) ---"
    tail -10 "$TMP/fakedns.log" 2>/dev/null || true
    echo "perf-local: temp dir kept for post-mortem: $TMP" >&2
  else
    rm -rf "$TMP"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

# --- port preflight -------------------------------------------------------
port_in_use() {
  local p=$1
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then return 0; fi
  if lsof -nP -iUDP:"$p" >/dev/null 2>&1; then return 0; fi
  return 1
}
require_port() { # label port var-name
  if port_in_use "$2"; then
    echo "perf-local: $1 port $2 is already in use." >&2
    echo "perf-local: stop the process holding it, or choose another port via $3=..." >&2
    lsof -nP -iTCP:"$2" -iUDP:"$2" 2>/dev/null | sed 's/^/  /' >&2 || true
    exit 1
  fi
}

mkdir -p "$SHOTS"
banner

phase preflight
require_port plain "$PERF_PLAIN" PERF_PLAIN
require_port doh "$PERF_DOH" PERF_DOH
require_port dot "$PERF_DOT" PERF_DOT
require_port doq "$PERF_DOQ" PERF_DOQ
note "ports free"

phase build
mkdir -p "$REPO/bin"
go build -o "$REPO/bin/mdns" ./cmd/mdns
(
  cd e2e/perf
  go build -o "$REPO/bin/fakedns" ./fakedns
  go build -o "$REPO/bin/loadgen" ./loadgen
)
PASSWORD_HASH=$(go run ./e2e/perf/hashgen/main.go "$PASSWORD")
note "bin/mdns, bin/fakedns, bin/loadgen built; panel hash generated"

# --- config ---------------------------------------------------------------
mkdir -p "$TMP/data"
PERF_CONFIG="$CONFIG" PERF_DATA="$TMP/data" PERF_HASH="$PASSWORD_HASH" \
  PERF_PLAIN="$PERF_PLAIN" PERF_DOH="$PERF_DOH" PERF_DOT="$PERF_DOT" PERF_DOQ="$PERF_DOQ" \
  PERF_UPSTREAM="$UPSTREAM" PERF_CACHE="$CACHE_SIZE" PERF_LOG="$LOG_ENTRIES" \
  python3 - <<'PY'
import json, os

env = os.environ
cfg = {
    "version": 1,
    "domain": "perf.test",
    "protocols": {
        "plain": {"enabled": True, "port": int(env["PERF_PLAIN"])},
        "doh": {"enabled": True, "port": int(env["PERF_DOH"])},
        "dot": {"enabled": True, "port": int(env["PERF_DOT"])},
        "doq": {"enabled": True, "port": int(env["PERF_DOQ"])},
    },
    "tls": {"mode": "self-signed"},
    "upstreams": [{
        "id": "fake",
        "name": "Fake Local",
        "transport": "plain",
        "address": env["PERF_UPSTREAM"],
        "priority": 0,
        "enabled": True,
    }],
    "strategy": "fastest",
    "cache": {"size": int(env["PERF_CACHE"]), "min_ttl": 0, "max_ttl": 86400},
    "limits": {"plain_rps_per_ip": 0, "trusted_cidrs": []},
    "log": {"memory_entries": int(env["PERF_LOG"]), "file": "", "max_file_size_bytes": 0},
    "data_dir": env["PERF_DATA"],
    "filter": {
        "enabled": True,
        "mode": "zero",
        "update_interval_hours": 0,
        "lists": [],
        "user_block": ["blk%d.test" % i for i in range(500)],
        "user_allow": [],
    },
    "panel": {"enabled": True, "password_hash": env["PERF_HASH"]},
}
with open(env["PERF_CONFIG"], "w") as f:
    json.dump(cfg, f, indent=1)
PY
chmod 600 "$CONFIG"
note "config written: $CONFIG"

# --- start fake upstream and daemon --------------------------------------
"$REPO/bin/fakedns" "$UPSTREAM" >"$TMP/fakedns.log" 2>&1 &
FAKE_PID=$!
"$REPO/bin/mdns" serve --config "$CONFIG" --socket "$SOCKET" >"$TMP/mdns.log" 2>&1 &
MDNS_PID=$!

ready=0
for _ in $(seq 1 100); do
  if "$REPO/bin/mdns" status --socket "$SOCKET" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$MDNS_PID" 2>/dev/null; then break; fi
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  echo "perf-local: the daemon did not become ready; see $TMP/mdns.log" >&2
  cat "$TMP/mdns.log" >&2 || true
  exit 1
fi

panel_ready=0
for _ in $(seq 1 100); do
  code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$PERF_DOH/login" 2>/dev/null || true)
  if [ "$code" = "200" ]; then
    panel_ready=1
    break
  fi
  sleep 0.1
done
if [ "$panel_ready" -ne 1 ]; then
  echo "perf-local: the panel did not answer https://127.0.0.1:$PERF_DOH/login (last code: ${code:-none})" >&2
  exit 1
fi
pass "daemon and panel are up (status + /login)"
RSS_BASE=$(rss_mb "$MDNS_PID")
FP_BASE=$(footprint_mb "$MDNS_PID")
note "RSS at start: ${RSS_BASE:-?} MB (physical footprint ${FP_BASE:-?} MB)"

# --- load helper ----------------------------------------------------------
# load_once runs one generator invocation. Results are globals so the
# caller can assert on them; bash 3.2 has no tuples.
load_once() {
  LOAD_LOG=$1
  shift
  LOAD_RC=0
  L_SENT=0
  L_DONE=0
  L_ERRS=0
  L_QPS=0
  L_PRE=0
  L_P50=""
  L_P95=""
  L_JSON_OK=0

  "$REPO/bin/loadgen" "$@" >"$LOAD_LOG" 2>&1 || LOAD_RC=$?
  cat "$LOAD_LOG" || true

  if grep -q '^PERF_JSON ' "$LOAD_LOG" 2>/dev/null; then
    L_JSON_OK=1
    grep '^PERF_JSON ' "$LOAD_LOG" | tail -1 | sed 's/^PERF_JSON //' >"$LOAD_LOG.json"
    L_SENT=$(json_get "$LOAD_LOG.json" sent)
    L_DONE=$(json_get "$LOAD_LOG.json" done)
    L_ERRS=$(json_get "$LOAD_LOG.json" errs)
    L_QPS=$(json_get "$LOAD_LOG.json" qps)
    L_PRE=$(json_get "$LOAD_LOG.json" prewarmed)
    L_P50=$(json_get "$LOAD_LOG.json" p50_bucket)
    L_P95=$(json_get "$LOAD_LOG.json" p95_bucket)
  fi
}

# --- UI probes under load -------------------------------------------------
start_tui() {
  if ! command -v tmux >/dev/null 2>&1; then
    fail "tmux is installed (TUI captures skipped)"
    return 1
  fi
  tmux new-session -d -s "$TMUX_SESSION" -x 140 -y 36 \
    "'$REPO/bin/mdns' tui --socket '$SOCKET'" 2>/dev/null || {
    fail "tmux starts a session for the TUI"
    return 1
  }
  TMUX_STARTED=1

  for _ in $(seq 1 100); do
    if tmux capture-pane -p -t "$TMUX_SESSION" 2>/dev/null | grep -q 'Стратегия:'; then
      return 0
    fi
    sleep 0.1
  done
  fail "TUI renders the status screen within 10 s"
  return 1
}

panel_probe() {
  local jar="$TMP/jar.txt" page="$TMP/login.html" csrf code tt
  if ! curl -sk --max-time 5 -c "$jar" -o "$page" \
    "https://127.0.0.1:$PERF_DOH/login"; then
    fail "panel /login answers under load"
    return
  fi
  csrf=$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$page" | head -1)
  if [ -z "$csrf" ]; then
    fail "the login page carries a CSRF token under load"
    return
  fi
  code=$(curl -sk --max-time 5 -c "$jar" -b "$jar" -o /dev/null -w '%{http_code}' \
    -d "csrf=$csrf" --data-urlencode "password=$PASSWORD" \
    "https://127.0.0.1:$PERF_DOH/login" 2>/dev/null || true)
  case "$code" in
  200 | 303) pass "panel login under load (HTTP $code)" ;;
  *)
    fail "panel login under load (HTTP ${code:-none})"
    return
    ;;
  esac

  tt=$(curl -sk --max-time 5 -b "$jar" -o "$TMP/panel-under-load.html" \
    -w '%{time_total}' "https://127.0.0.1:$PERF_DOH/panel/" 2>/dev/null || true)
  if [ -z "$tt" ]; then
    fail "authenticated /panel/ fetch under load"
    return
  fi
  if awk -v t="$tt" 'BEGIN { exit !(t <= 1.0) }'; then
    pass "authenticated /panel/ under load: ${tt}s <= 1s"
  else
    fail "authenticated /panel/ under load: ${tt}s > 1s"
  fi
  if grep -q 'Живая лента' "$TMP/panel-under-load.html"; then
    pass "the panel renders «Живая лента» under load"
  else
    fail "the panel renders «Живая лента» under load"
  fi

  if [ -x "$REPO/.venv-pw/bin/python" ] &&
    "$REPO/.venv-pw/bin/python" -c 'import playwright' >/dev/null 2>&1; then
    if PERF_PANEL_URL="https://127.0.0.1:$PERF_DOH" \
      PERF_PANEL_PASSWORD="$PASSWORD" \
      PERF_SHOT="$SHOTS/panel-under-load.png" \
      "$REPO/.venv-pw/bin/python" e2e/perf/shot.py >"$TMP/shot.log" 2>&1; then
      pass "panel screenshot under load: $SHOTS/panel-under-load.png"
    else
      fail "panel screenshot under load" "$(tail -20 "$TMP/shot.log" 2>/dev/null || true)"
    fi
  else
    note "Playwright venv .venv-pw is absent or incomplete — panel screenshot skipped (fetch checks still ran)"
  fi
}

probe_under_load() {
  echo "--- UI / API under load (main phase) ---"

  local t0 t1 ms
  t0=$(now_ms)
  if "$REPO/bin/mdns" status --socket "$SOCKET" >"$TMP/status-under-load.txt" 2>&1; then
    t1=$(now_ms)
    ms=$((t1 - t0))
    if [ "$ms" -le 250 ]; then
      pass "mdns status under load: ${ms} ms <= 250 ms"
    else
      fail "mdns status under load: ${ms} ms > 250 ms"
    fi
  else
    fail "mdns status under load failed"
  fi

  RSS_LOAD=$(rss_mb "$MDNS_PID")
  note "RSS while under load: ${RSS_LOAD} MB"

  if start_tui; then
    tmux capture-pane -p -t "$TMUX_SESSION" >"$SHOTS/tui-status-under-load.txt" 2>/dev/null || true
    pass "TUI status captured under load: $SHOTS/tui-status-under-load.txt"

    t0=$(now_ms)
    tmux send-keys -t "$TMUX_SESSION" 3
    t1=$t0
    key_ok=0
    while [ "$t1" -lt $((t0 + 2000)) ]; do
      if tmux capture-pane -p -t "$TMUX_SESSION" 2>/dev/null |
        grep -Eq 'прото|Запросов пока нет'; then
        key_ok=1
        break
      fi
      sleep 0.05
      t1=$(now_ms)
    done
    if [ "$key_ok" -eq 1 ]; then
      pass "TUI key response under load: «3» -> «Запросы» in $((t1 - t0)) ms <= 2000 ms"
    else
      fail "TUI key response under load: «3» did not switch within 2 s"
    fi
    tmux capture-pane -p -t "$TMUX_SESSION" >"$SHOTS/tui-requests-under-load.txt" 2>/dev/null || true
  fi

  panel_probe
}

# --- phase: smoke ---------------------------------------------------------
phase smoke
load_once "$TMP/smoke.log" -addr "127.0.0.1:$PERF_PLAIN" -total "$PERF_SMOKE" -workers 64
if [ "$L_JSON_OK" -eq 1 ] && [ "$LOAD_RC" -eq 0 ] && [ "$L_ERRS" -eq 0 ]; then
  pass "smoke: $L_DONE answers, 0 errors ($(printf '%.0f' "$L_QPS") qps)"
else
  fail "smoke: 0 errors (exit $LOAD_RC, errs $L_ERRS)"
fi
note "smoke latency: p50 $L_P50, p95 $L_P95"
note "RSS after smoke: $(rss_mb "$MDNS_PID") MB"
TOTAL_SENT=$((TOTAL_SENT + L_SENT))
TOTAL_PRE=$((TOTAL_PRE + L_PRE))

# --- phase: main + UI under load -----------------------------------------
phase main
"$REPO/bin/loadgen" -addr "127.0.0.1:$PERF_PLAIN" -total "$PERF_TOTAL" -workers "$PERF_WORKERS" \
  >"$TMP/main.log" 2>&1 &
MAIN_PID=$!

sleep "$PERF_PROBE_DELAY"
if kill -0 "$MAIN_PID" 2>/dev/null; then
  note "main load still running after ${PERF_PROBE_DELAY}s — probing the UI"
  probe_under_load
else
  fail "main load is still running when the UI probes start (raise PERF_TOTAL or lower PERF_PROBE_DELAY)"
fi

MAIN_RC=0
wait "$MAIN_PID" || MAIN_RC=$?
cat "$TMP/main.log" || true
L_JSON_OK=0
if grep -q '^PERF_JSON ' "$TMP/main.log" 2>/dev/null; then
  L_JSON_OK=1
  grep '^PERF_JSON ' "$TMP/main.log" | tail -1 | sed 's/^PERF_JSON //' >"$TMP/main.log.json"
  L_SENT=$(json_get "$TMP/main.log.json" sent)
  L_DONE=$(json_get "$TMP/main.log.json" done)
  L_ERRS=$(json_get "$TMP/main.log.json" errs)
  L_QPS=$(json_get "$TMP/main.log.json" qps)
  L_PRE=$(json_get "$TMP/main.log.json" prewarmed)
  L_P50=$(json_get "$TMP/main.log.json" p50_bucket)
  L_P95=$(json_get "$TMP/main.log.json" p95_bucket)
else
  L_SENT=0
  L_DONE=0
  L_ERRS=0
  L_QPS=0
  L_PRE=0
  L_P50=""
  L_P95=""
fi
if [ "$L_JSON_OK" -eq 1 ] && [ "$MAIN_RC" -eq 0 ] && [ "$L_ERRS" -eq 0 ]; then
  pass "main: $L_DONE answers, 0 errors ($(printf '%.0f' "$L_QPS") qps)"
else
  fail "main: 0 errors (exit $MAIN_RC, errs $L_ERRS)"
fi
note "main latency: p50 $L_P50, p95 $L_P95"
note "RSS after main: $(rss_mb "$MDNS_PID") MB"
TOTAL_SENT=$((TOTAL_SENT + L_SENT))
TOTAL_PRE=$((TOTAL_PRE + L_PRE))

# --- phase: burst ---------------------------------------------------------
phase burst
load_once "$TMP/burst.log" -addr "127.0.0.1:$PERF_PLAIN" -dur "$PERF_BURST" \
  -workers "$PERF_BURST_WORKERS"
if [ "$L_JSON_OK" -eq 1 ] && [ "$LOAD_RC" -eq 0 ] && [ "$L_ERRS" -eq 0 ]; then
  pass "burst: $L_DONE answers in $PERF_BURST, 0 errors ($(printf '%.0f' "$L_QPS") qps)"
else
  fail "burst: 0 errors (exit $LOAD_RC, errs $L_ERRS)"
fi
note "burst latency: p50 $L_P50, p95 $L_P95"
note "RSS after burst: $(rss_mb "$MDNS_PID") MB"
TOTAL_SENT=$((TOTAL_SENT + L_SENT))
TOTAL_PRE=$((TOTAL_PRE + L_PRE))

# --- phase: DoH -----------------------------------------------------------
phase doh
load_once "$TMP/doh.log" -doh "https://127.0.0.1:$PERF_DOH/dns-query" \
  -total "$PERF_DOH_TOTAL" -workers 32
if [ "$L_JSON_OK" -eq 1 ] && [ "$LOAD_RC" -eq 0 ] && [ "$L_ERRS" -eq 0 ]; then
  pass "doh: $L_DONE answers, 0 errors ($(printf '%.0f' "$L_QPS") qps)"
else
  fail "doh: 0 errors (exit $LOAD_RC, errs $L_ERRS)"
fi
note "doh latency: p50 $L_P50, p95 $L_P95"
note "RSS after doh: $(rss_mb "$MDNS_PID") MB"
TOTAL_SENT=$((TOTAL_SENT + L_SENT))
TOTAL_PRE=$((TOTAL_PRE + L_PRE))

# --- phase: post-run counters and resilience -----------------------------
phase post
sleep 2
RSS_AFTER=$(rss_mb "$MDNS_PID")
FP_AFTER=$(footprint_mb "$MDNS_PID")
# The memory gate is the process's own physical footprint (ruling R4/R15):
# ps RSS includes shared pages and would fail a healthy daemon. A missing
# metric is a loud WARNING, never a silent pass.
if is_num "$FP_AFTER"; then
  if [ "$FP_AFTER" -gt 200 ]; then
    fail "physical footprint after the run: ${FP_AFTER} MB > 200 MB"
  else
    pass "physical footprint after the run: ${FP_AFTER} MB <= 200 MB"
  fi
else
  note "WARNING: vmmap physical footprint is unavailable (vmmap missing or unparsable) — memory gate skipped"
fi
if is_num "$RSS_AFTER"; then
  note "ps RSS after the run: ${RSS_AFTER} MB (informational only; includes shared pages)"
else
  note "WARNING: ps RSS after the run is unavailable"
fi
note "RSS: start ${RSS_BASE:-?} MB -> under load ${RSS_LOAD:-?} MB -> after ${RSS_AFTER:-?} MB"

"$REPO/bin/mdns" status --socket "$SOCKET" --json >"$TMP/status.json"
HITS=0
MISSES=0
CACHE_ENTRIES=0
BLOCKED=0
UP_SENT=0
UP_FAILED=0
eval "$(python3 - "$TMP/status.json" <<'PY'
import json, sys
st = json.load(open(sys.argv[1]))
cache = st["Cache"]
up = st["Upstreams"][0] if st["Upstreams"] else {"Sent": 0, "Failed": 0}
print("HITS=%d" % cache["Hits"])
print("MISSES=%d" % cache["Misses"])
print("CACHE_ENTRIES=%d" % cache["Size"])
print("BLOCKED=%d" % st["Filter"]["TotalBlocked"])
print("UP_SENT=%d" % up["Sent"])
print("UP_FAILED=%d" % up["Failed"])
PY
)"

STATS_JSON=$(curl -s --max-time 5 --unix-socket "$SOCKET" http://localhost/api/v1/stats || true)
# The paged shape reports the number of entries in the ring as "total",
# which is exactly what the bounded-ring assertion needs.
RING_JSON=$(curl -s --max-time 5 --unix-socket "$SOCKET" \
  'http://localhost/api/v1/requests?page=1&per=1' || true)
STATS_TOTAL=$(printf '%s' "$STATS_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("total",0))' 2>/dev/null || echo 0)
RING_LEN=$(printf '%s' "$RING_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("total",0))' 2>/dev/null || echo 0)
EXPECTED=$((TOTAL_SENT + TOTAL_PRE))
note "loadgen sent $TOTAL_SENT + prewarmed $TOTAL_PRE = $EXPECTED queries"
note "daemon counters: stats total $STATS_TOTAL, cache hits $HITS misses $MISSES, blocked $BLOCKED, upstream sent $UP_SENT, failed $UP_FAILED"

# TUI still answers after the load: switch back to the status screen.
if [ "$TMUX_STARTED" -eq 1 ] && tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
  t0=$(now_ms)
  tmux send-keys -t "$TMUX_SESSION" 1
  tui_ok=0
  t1=$t0
  while [ "$t1" -lt $((t0 + 2000)) ]; do
    if tmux capture-pane -p -t "$TMUX_SESSION" 2>/dev/null | grep -q 'Стратегия:'; then
      tui_ok=1
      break
    fi
    sleep 0.05
    t1=$(now_ms)
  done
  if [ "$tui_ok" -eq 1 ]; then
    pass "TUI still responds after the run: «1» -> status in $((t1 - t0)) ms"
  else
    fail "TUI still responds after the run"
  fi
  tmux send-keys -t "$TMUX_SESSION" r
  sleep 0.2
  tmux capture-pane -p -t "$TMUX_SESSION" >"$SHOTS/tui-post-status.txt" 2>/dev/null || true
fi

# The fake upstream prints its served count on SIGTERM. Read it before
# the convergence assertions so a mismatch is attributed correctly.
if [ -n "$FAKE_PID" ] && kill -0 "$FAKE_PID" 2>/dev/null; then
  kill -TERM "$FAKE_PID" 2>/dev/null || true
  wait "$FAKE_PID" 2>/dev/null || true
  FAKE_PID=""
fi
FAKE_SERVED=$(sed -n 's/^fakedns served: //p' "$TMP/fakedns.log" | tail -1)
FAKE_SERVED=${FAKE_SERVED:-0}
note "fake upstream served $FAKE_SERVED queries (daemon reports sent $UP_SENT, failed $UP_FAILED)"

# Convergence. The 0.5% slack is for the couple of queries in flight when
# the counters are sampled; everything else must match exactly.
if [ "$EXPECTED" -gt 0 ]; then
  if awk -v a="$STATS_TOTAL" -v b="$EXPECTED" \
    'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d <= b * 0.005) }'; then
    pass "convergence: stats total $STATS_TOTAL ~ sent $EXPECTED (<= 0.5%)"
  else
    fail "convergence: stats total $STATS_TOTAL != sent $EXPECTED"
  fi

  if awk -v a="$((HITS + MISSES + BLOCKED))" -v b="$STATS_TOTAL" \
    'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d <= b * 0.005) }'; then
    pass "convergence: hits+misses+blocked = $((HITS + MISSES + BLOCKED)) ~ total $STATS_TOTAL"
  else
    fail "convergence: hits+misses+blocked = $((HITS + MISSES + BLOCKED)) != total $STATS_TOTAL"
  fi

  if awk -v b="$BLOCKED" -v t="$STATS_TOTAL" \
    'BEGIN { p = 100 * b / t; exit !(p >= 19 && p <= 21) }'; then
    pass "convergence: blocked share $(awk -v b="$BLOCKED" -v t="$STATS_TOTAL" 'BEGIN { printf "%.2f", 100*b/t }')% in 20% +/-1pp"
  else
    fail "convergence: blocked share is not 20% +/-1pp ($BLOCKED of $STATS_TOTAL)"
  fi

  if awk -v s="$FAKE_SERVED" -v t="$STATS_TOTAL" \
    'BEGIN { p = 100 * s / t; exit !(p >= 9 && p <= 11) }'; then
    pass "convergence: upstream share $(awk -v s="$FAKE_SERVED" -v t="$STATS_TOTAL" 'BEGIN { printf "%.2f", 100*s/t }')% in 10% +/-1pp"
  else
    fail "convergence: upstream share is not 10% +/-1pp ($FAKE_SERVED of $STATS_TOTAL)"
  fi

  if awk -v a="$FAKE_SERVED" -v b="$UP_SENT" -v t="$STATS_TOTAL" \
    'BEGIN { d = a - b; if (d < 0) d = -d; lim = t * 0.0001 + 5; exit !(d <= lim) }'; then
    pass "convergence: fake upstream served $FAKE_SERVED ~ daemon sent $UP_SENT"
  else
    fail "convergence: fake upstream served $FAKE_SERVED != daemon sent $UP_SENT"
  fi
fi

if [ "$UP_FAILED" -eq 0 ]; then
  pass "upstream: 0 failed queries"
else
  fail "upstream: $UP_FAILED failed queries"
fi

if [ "$CACHE_ENTRIES" -le "$CACHE_SIZE" ]; then
  pass "cache entries: $CACHE_ENTRIES <= configured $CACHE_SIZE"
else
  fail "cache entries: $CACHE_ENTRIES > configured $CACHE_SIZE"
fi

if [ "$RING_LEN" -le "$LOG_ENTRIES" ]; then
  pass "query log ring: $RING_LEN <= configured $LOG_ENTRIES"
else
  fail "query log ring: $RING_LEN > configured $LOG_ENTRIES"
fi

# --- summary --------------------------------------------------------------
echo
echo "--- summary ---"
printf '%s checks, %s failed\n' "$CHECKS" "$FAILS"
if [ "$FAILS" -ne 0 ]; then
  echo "perf-local: FAILED ($FAILS of $CHECKS checks)" >&2
  exit 1
fi
echo "perf-local: passed"
