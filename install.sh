#!/usr/bin/env bash
#
# mdns bootstrap installer (Linux).
#
# Downloads the release binary for this machine's architecture, verifies it
# against the release SHA256SUMS, installs it as /usr/local/bin/mdns and then
# hands over to `mdns install`, which sets up the service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | sudo bash -s -- \
#     --non-interactive --domain dns.example.com --tls acme --acme-email me@example.com
#
# Flags of this script:
#   --local <file>     install the given binary instead of downloading one
#   --version vX.Y.Z   download that release instead of the latest one
#   -h, --help         print this help
#
# Every other argument is passed to `mdns install` unchanged.
#
# MDNS_BASE_URL overrides the base URL of the releases. It is a test hook:
# the installer e2e serves dist/ from a local file server and points here.
set -euo pipefail

BASE="${MDNS_BASE_URL:-https://github.com/grendervill/mdns/releases}"
BIN=/usr/local/bin/mdns

usage() {
  cat <<'EOF'
Установка mdns одной командой (Linux, нужен root):

  curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/grendervill/mdns/main/install.sh | sudo bash -s -- \
    --non-interactive --domain dns.example.com --tls acme --acme-email me@example.com

Флаги install.sh:
  --local <файл>     поставить указанный бинарник, не скачивая релиз
  --version vX.Y.Z   скачать конкретную версию (по умолчанию — последнюю)
  -h, --help         эта справка

Остальные аргументы передаются команде `mdns install` без изменений
(список: `mdns install -h`).
EOF
}

die() {
  echo "install.sh: $*" >&2
  exit 1
}

local_bin=""
version=""
pass=() # arguments forwarded to `mdns install`

while [ $# -gt 0 ]; do
  case "$1" in
  --local)
    [ $# -ge 2 ] || die "--local требует путь к файлу"
    local_bin=$2
    shift 2
    ;;
  --local=*)
    local_bin=${1#--local=}
    shift
    ;;
  --version)
    [ $# -ge 2 ] || die "--version требует значение, например v0.1.0"
    version=$2
    shift 2
    ;;
  --version=*)
    version=${1#--version=}
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    pass+=("$1")
    shift
    ;;
  esac
done

# Root is required in both modes: /usr/local/bin and `mdns install`.
if [ "$(id -u)" -ne 0 ]; then
  die "запустите через sudo: curl -fsSL <ссылка на install.sh> | sudo bash"
fi

tmp=""
src=""

if [ -n "$local_bin" ]; then
  [ -f "$local_bin" ] || die "файл не найден: $local_bin"
  src=$local_bin
else
  case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "неподдерживаемая архитектура: $(uname -m) (нужна x86_64 или aarch64)" ;;
  esac

  # Latest release, or a specific tag: GitHub's release URL layout.
  dir="$BASE/latest/download"
  if [ -n "$version" ]; then
    dir="$BASE/download/$version"
  fi

  file="mdns-linux-$arch"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  echo "скачиваем $dir/$file"
  curl -fsSL -o "$tmp/$file" "$dir/$file" || die "не удалось скачать $dir/$file"
  curl -fsSL -o "$tmp/SHA256SUMS" "$dir/SHA256SUMS" || die "не удалось скачать $dir/SHA256SUMS"

  # sha256sum on Linux, shasum on macOS (dev machines).
  if command -v sha256sum >/dev/null 2>&1; then
    hash=(sha256sum)
  else
    hash=(shasum -a 256)
  fi

  grep " $file\$" "$tmp/SHA256SUMS" >"$tmp/$file.sum" ||
    die "в SHA256SUMS нет записи для $file"
  if ! (cd "$tmp" && "${hash[@]}" -c "$file.sum" >/dev/null); then
    rm -f "$tmp/$file"
    die "контрольная сумма $file не совпала — файл удалён, установка прервана"
  fi
  echo "сумма $file совпала"

  src="$tmp/$file"
fi

mkdir -p "$(dirname "$BIN")"
install -m 0755 "$src" "$BIN"
if [ -n "$tmp" ]; then
  # exec replaces this shell, so the EXIT trap never runs: clean up early.
  rm -rf "$tmp"
fi

exec "$BIN" install ${pass[@]+"${pass[@]}"}
