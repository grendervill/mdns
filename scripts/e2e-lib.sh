#!/usr/bin/env bash
# Shared harness for the Docker end-to-end scripts (e2e-install.sh,
# e2e-panel.sh). Source it from a script that has already changed to the
# repository root:
#
#   source scripts/e2e-lib.sh
#
# Both scripts test a real installation on a real machine: ubuntu:24.04
# with systemd as PID 1, the release binary served in the GitHub layout
# and installed through install.sh's one-liner. Keeping the container
# bring-up, the release staging and the readiness poll here means the two
# scripts cannot drift into two different harnesses; each script still
# owns its phases, assertions and teardown.
#
# Container notes (macOS / Docker Desktop):
#   * ubuntu:24.04 ships no init, so the container starts as
#     `bash -c '<install systemd> && exec /sbin/init'`: bash is PID 1
#     for the apt step and hands PID 1 over to systemd.
#   * --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw
#     give systemd a writable cgroup tree to manage units with.
#   * --add-host=host.docker.internal:host-gateway makes the host file
#     server reachable from the Linux container.
#   * The systemd-resolved stub listener owns :53 inside the container,
#     so the bootstrap writes the drop-in the installer's own warning
#     prints (DNSStubListener=no) — the documented prerequisite of a real
#     installation, not a test hack.

# E2E_BOOTSTRAP is run as the container's command. It installs systemd
# and the client tools the scripts need, frees :53 and execs init.
E2E_BOOTSTRAP='
set -e
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus curl dnsutils iproute2 >/dev/null
mkdir -p /etc/systemd/resolved.conf.d
printf "[Resolve]\nDNSStubListener=no\n" > /etc/systemd/resolved.conf.d/99-mdns.conf
exec /sbin/init
'

# e2e_goarch prints the Linux architecture matching the Docker daemon.
e2e_goarch() {
  case "$(docker info --format '{{.Architecture}}')" in
    aarch64 | arm64) echo arm64 ;;
    x86_64 | amd64) echo amd64 ;;
    *)
      echo "unsupported docker architecture" >&2
      return 1
      ;;
  esac
}

# e2e_sha256 prints the SHA256 of a file, with the tool the host has.
e2e_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# e2e_stage_release <stage> <goarch> <port>
#
# Stages dist/ and install.sh in the GitHub release layout
# (<stage>/latest/download/<file>) and serves them on 127.0.0.1:<port>.
# The served bytes are then read back and hashed: a leftover server from
# an earlier run would answer on the port with a different tree, and the
# test must not install yesterday's binary. The server's pid is left in
# E2E_HTTP_PID for the caller's teardown.
e2e_stage_release() {
  local stage=$1 goarch=$2 port=$3
  local ok=0

  mkdir -p "$stage/latest/download"
  cp "dist/mdns-linux-$goarch" dist/SHA256SUMS "$stage/latest/download/"
  cp install.sh "$stage/"

  (cd "$stage" && exec python3 -m http.server "$port" --bind 127.0.0.1) \
    >"$stage/http.log" 2>&1 &
  E2E_HTTP_PID=$!

  for _ in $(seq 1 20); do
    curl -fsS -o "$stage/served-install.sh" \
      "http://127.0.0.1:$port/install.sh" 2>/dev/null || true
    curl -fsS -o "$stage/served-binary" \
      "http://127.0.0.1:$port/latest/download/mdns-linux-$goarch" 2>/dev/null || true
    if [ -f "$stage/served-install.sh" ] && [ -f "$stage/served-binary" ] &&
      [ "$(e2e_sha256 "$stage/served-install.sh")" = "$(e2e_sha256 install.sh)" ] &&
      [ "$(e2e_sha256 "$stage/served-binary")" = "$(e2e_sha256 "dist/mdns-linux-$goarch")" ]; then
      ok=1
      break
    fi
    sleep 0.5
  done
  rm -f "$stage/served-install.sh" "$stage/served-binary"

  if [ "$ok" -ne 1 ]; then
    echo "the file server on $port does not serve this tree;" >&2
    echo "another process may hold the port: stop it and re-run" >&2
    return 1
  fi
}

# e2e_start_systemd <name> <image> <hostname> [docker run arguments...]
#
# Starts (or restarts) the named systemd container and waits until init
# reports running or degraded. Extra arguments go to `docker run` before
# the image, which is how e2e-panel publishes 443. On failure the
# container log is printed and the function returns 1; the caller's trap
# still owns the final teardown. The final state is left in
# E2E_SYSTEMD_STATE.
e2e_start_systemd() {
  local name=$1 image=$2 hostname=$3 state=starting
  shift 3

  echo "--- start the systemd container ($image) ---"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" \
    --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --add-host="host.docker.internal:host-gateway" \
    --hostname "$hostname" \
    "$@" \
    "$image" bash -c "$E2E_BOOTSTRAP" >/dev/null

  echo "--- wait for systemd ---"
  for _ in $(seq 1 120); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]; then
      echo "the container exited during setup:" >&2
      docker logs "$name" >&2 || true
      return 1
    fi
    state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$state" in
      running | degraded) break ;;
    esac
    sleep 1
  done
  E2E_SYSTEMD_STATE=$state
  case "$state" in
    running | degraded)
      echo "systemd is $state"
      return 0
      ;;
    *)
      echo "systemd did not come up (state: ${state:-none})" >&2
      docker logs "$name" >&2 || true
      return 1
      ;;
  esac
}
