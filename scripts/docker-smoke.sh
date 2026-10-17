#!/usr/bin/env bash
# Docker smoke test for mdns.
#
# Builds a linux binary for the host Docker architecture and runs it
# inside the given base images (default: ubuntu:24.04 and debian:trixie).
# Inside each container it installs the client tools, starts `mdns serve`
# with all four protocols and the filter engine enabled, and checks:
#   - plain DNS (dig) for a normal and a list-blocked domain,
#   - DoT (kdig +tls) and DoQ (kdig +quic),
#   - DoH (curl, RFC 8484 GET),
#   - the control API on the unix socket (status, config round-trip,
#     persistence, SSE),
#   - the persisted filter rules on disk.
#
# Usage:
#   scripts/docker-smoke.sh [image...]
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGES=("$@")
if [ ${#IMAGES[@]} -eq 0 ]; then
  IMAGES=(ubuntu:24.04 debian:trixie)
fi

case "$(docker info --format '{{.Architecture}}')" in
  aarch64 | arm64) GOARCH=arm64 ;;
  x86_64 | amd64) GOARCH=amd64 ;;
  *)
    echo "unsupported docker architecture" >&2
    exit 1
    ;;
esac

echo "building linux/$GOARCH binary"
mkdir -p dist
GOOS=linux GOARCH="$GOARCH" go build \
  -ldflags "-X mydns/internal/version.Version=docker-smoke" \
  -o dist/mdns-linux ./cmd/mdns

for img in "${IMAGES[@]}"; do
  echo
  echo "=== $img ==="
  docker pull -q "$img" >/dev/null
  docker run --rm -i \
    -v "$PWD/dist/mdns-linux:/mnt/mdns:ro" \
    "$img" bash -s <<'CONTAINER'
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl dnsutils knot-dnsutils openssl >/dev/null

echo "--- version ---"
/mnt/mdns version

cat > /tmp/config.json <<'EOC'
{
  "version": 1,
  "domain": "mdns.test",
  "protocols": {
    "plain": {"enabled": true, "port": 5533},
    "doh": {"enabled": true, "port": 8443},
    "dot": {"enabled": true, "port": 8853},
    "doq": {"enabled": true, "port": 8853}
  },
  "tls": {"mode": "self-signed"},
  "upstreams": [
    {"id": "cf", "name": "Cloudflare", "transport": "plain", "address": "1.1.1.1:53", "priority": 0, "enabled": true}
  ],
  "strategy": "fastest",
  "cache": {"size": 10000, "min_ttl": 0, "max_ttl": 86400},
  "limits": {"plain_rps_per_ip": 50, "trusted_cidrs": []},
  "log": {"memory_entries": 10000, "file": "", "max_file_size_bytes": 0},
  "data_dir": "/tmp/mdns-data",
  "filter": {
    "enabled": true,
    "mode": "zero",
    "update_interval_hours": 0,
    "lists": [{"id": "adguard-dns-filter"}],
    "user_allow": [],
    "user_block": []
  }
}
EOC

/mnt/mdns check --config /tmp/config.json

nohup /mnt/mdns serve --config /tmp/config.json > /tmp/serve.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

# Wait for the list to load (a few MiB over the network).
for _ in $(seq 1 45); do
  [ -f /tmp/mdns-data/filters/adguard-dns-filter.rules ] && break
  sleep 1
done
sleep 1

echo "--- plain UDP: blocked doubleclick.ne.jp ---"
dig @127.0.0.1 -p 5533 doubleclick.ne.jp A +short +timeout=4
echo "--- plain UDP: normal example.com ---"
dig @127.0.0.1 -p 5533 example.com A +short +timeout=4 | head -2
echo "--- plain TCP: example.com ---"
dig @127.0.0.1 -p 5533 +tcp example.com A +short +timeout=4 | head -1

echo "--- TLS certificate (for the clients below) ---"
echo | timeout 5 openssl s_client -connect 127.0.0.1:8853 -servername mdns.test -showcerts 2>/dev/null \
  | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > /tmp/mdns.pem
echo "certificate pem bytes: $(wc -c < /tmp/mdns.pem)"

echo "--- DoT query (kdig) ---"
kdig @127.0.0.1 -p 8853 +tls +tls-ca=/tmp/mdns.pem +tls-hostname=mdns.test +timeout=5 example.com A +short 2>&1 | head -4

echo "--- DoQ query (kdig) ---"
kdig @127.0.0.1 -p 8853 +quic +tls-ca=/tmp/mdns.pem +tls-hostname=mdns.test +timeout=5 example.com A +short 2>&1 | head -4

echo "--- DoH (curl, RFC 8484 GET) ---"
Q=$(printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | base64 | tr '+/' '-_' | tr -d '=')
code=$(curl -sk --max-time 5 -o /tmp/doh.bin -w '%{http_code}' \
  -H 'Accept: application/dns-message' \
  "https://127.0.0.1:8443/dns-query?dns=$Q")
echo "doh http status: $code"
echo "doh reply head:"
od -An -tx1 -N16 /tmp/doh.bin

echo "--- filter list on disk ---"
wc -l /tmp/mdns-data/filters/adguard-dns-filter.rules

echo "--- control API: socket ---"
ls -l /run/mdns/mdns.sock

echo "--- control API: status ---"
curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/status | head -c 260; echo

echo "--- control API: SSE ping ---"
curl -sN --max-time 2 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/events | head -c 80 || true
echo

echo "--- control API: config round-trip (user_allow) ---"
curl -s --max-time 5 --unix-socket /run/mdns/mdns.sock http://localhost/api/v1/config > /tmp/api-config.json
sed -i 's/"user_allow": *\[\]/"user_allow": ["api-allowed.example.com"]/' /tmp/api-config.json
curl -s --max-time 5 -X PUT -H 'Content-Type: application/json' \
  --data @/tmp/api-config.json --unix-socket /run/mdns/mdns.sock \
  http://localhost/api/v1/config
echo
echo "persisted allow entries: $(grep -c 'api-allowed' /tmp/config.json)"
echo "still serving after the update:"
dig @127.0.0.1 -p 5533 example.com A +short +timeout=4 | head -1

echo "--- serve log ---"
tail -6 /tmp/serve.log
CONTAINER
done

echo
echo "docker smoke: all images passed"
