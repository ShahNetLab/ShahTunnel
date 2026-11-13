#!/usr/bin/env bash
set -Eeuo pipefail

# Install the official Tor Expert Bundle (Tor + Lyrebird) on demand.
# The archive checksum is pinned to Tor Project's signed build manifest.
STATE_DIR="/usr/local/lib/shah-tunnel"
BUNDLE_DIR="${STATE_DIR}/tor-bundle"
TOR_VERSION="16.0.1"
BASE_URL="https://dist.torproject.org/torbrowser/${TOR_VERSION}"

fail() { echo "Tor installer: $*" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run as root (ShahTunnel invokes this automatically as root)."
for cmd in curl sha256sum tar find install mv rm mktemp chmod cp chown mkdir grep; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

# Reuse a complete previously installed bundle, including an alternative official layout.
if grep -Fxq "version=${TOR_VERSION}" "${STATE_DIR}/tor-bundle.info" 2>/dev/null && \
   find "$BUNDLE_DIR" -type f -name tor -perm /111 -print -quit 2>/dev/null | grep -q . && \
   find "$BUNDLE_DIR" -type f -name lyrebird -perm /111 -print -quit 2>/dev/null | grep -q . && \
   [[ -s "${BUNDLE_DIR}/data/geoip" && -s "${BUNDLE_DIR}/data/geoip6" ]]; then
  echo "Official Tor Expert Bundle ${TOR_VERSION} is already installed."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64)
    ARCHIVE="tor-expert-bundle-linux-x86_64-${TOR_VERSION}.tar.gz"
    EXPECTED_SHA256="7039cb16060ab22e669852e55774d894b55f25ea8bd0ab7194d3478429a58725"
    ;;
  aarch64|arm64)
    ARCHIVE="tor-expert-bundle-linux-aarch64-${TOR_VERSION}.tar.gz"
    EXPECTED_SHA256="67040520d44c87ccaaf5aa7df0dc1ff122eb938dbb600ae7722e8b6b75282a4b"
    ;;
  *) fail "unsupported CPU architecture: $(uname -m); supported: amd64 and arm64." ;;
esac

TMP="$(mktemp -d /tmp/shahtunnel-tor.XXXXXX)"
chmod 0700 "$TMP"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT
ARCHIVE_PATH="${TMP}/${ARCHIVE}"
EXTRACT_DIR="${TMP}/extract"
mkdir -p "$EXTRACT_DIR"

echo "Downloading official Tor Expert Bundle ${TOR_VERSION} for $(uname -m)..."
curl -fL --proto '=https' --proto-redir '=https' \
  --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 600 \
  "${BASE_URL}/${ARCHIVE}" -o "$ARCHIVE_PATH" \
  || fail "could not download the official Tor Expert Bundle. Install/create the profile while internet access is available."

printf '%s  %s\n' "$EXPECTED_SHA256" "$ARCHIVE_PATH" | sha256sum -c - \
  || fail "Tor Expert Bundle SHA-256 mismatch; refusing to install the archive."
tar -tzf "$ARCHIVE_PATH" >/dev/null 2>&1 || fail "downloaded Tor Expert Bundle is not a valid tar.gz archive."
tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR" || fail "could not extract Tor Expert Bundle."
[[ -s "${EXTRACT_DIR}/data/geoip" && -s "${EXTRACT_DIR}/data/geoip6" ]] \
  || fail "official Tor Expert Bundle is missing its IPv4/IPv6 GeoIP databases; refusing to install without non-US relay enforcement."

# Prefer the real Expert Bundle daemon. Some bundles also ship a file named
# debug/tor; selecting the first filesystem match can pick an incompatible
# helper and cause Linux exec format errors.
TOR_BIN="${EXTRACT_DIR}/tor/tor"
if [[ ! -x "$TOR_BIN" ]] || ! env LD_LIBRARY_PATH="$(dirname "$TOR_BIN")" "$TOR_BIN" --version >/dev/null 2>&1; then
  TOR_BIN=""
  while IFS= read -r candidate; do
    [[ -x "$candidate" ]] || continue
    if env LD_LIBRARY_PATH="$(dirname "$candidate")" "$candidate" --version >/dev/null 2>&1; then
      TOR_BIN="$candidate"
      break
    fi
  done < <(find "$EXTRACT_DIR" -type f -name tor -perm /111 -print | sort)
fi
LYREBIRD_BIN="${EXTRACT_DIR}/tor/pluggable_transports/lyrebird"
if [[ ! -x "$LYREBIRD_BIN" ]]; then
  LYREBIRD_BIN="$(find "$EXTRACT_DIR" -type f -name lyrebird -perm /111 -print -quit)"
fi
[[ -n "$TOR_BIN" && -x "$TOR_BIN" && -n "$LYREBIRD_BIN" && -x "$LYREBIRD_BIN" ]] || fail "official bundle does not contain runnable Tor and Lyrebird executables for this architecture."

install -d -o root -g root -m 0755 "$STATE_DIR"
NEW_DIR="${STATE_DIR}/tor-bundle.new.$$"
BACKUP_DIR="${STATE_DIR}/tor-bundle.backup.$$"
rm -rf -- "$NEW_DIR" "$BACKUP_DIR"
cp -a "$EXTRACT_DIR" "$NEW_DIR"
chown -R root:root "$NEW_DIR"
find "$NEW_DIR" -type d -exec chmod 0755 {} +
find "$NEW_DIR" -type f -perm /111 -exec chmod 0755 {} +
find "$NEW_DIR" -type f ! -perm /111 -exec chmod 0644 {} +

# Verify that the expected executables survived the staged copy before swapping.
[[ -x "${NEW_DIR}/${TOR_BIN#"$EXTRACT_DIR"/}" ]] || fail "staged Tor executable is missing."
[[ -x "${NEW_DIR}/${LYREBIRD_BIN#"$EXTRACT_DIR"/}" ]] || fail "staged Lyrebird executable is missing."
[[ -s "${NEW_DIR}/data/geoip" && -s "${NEW_DIR}/data/geoip6" ]] || fail "staged Tor GeoIP databases are missing."

if [[ -e "$BUNDLE_DIR" ]]; then mv "$BUNDLE_DIR" "$BACKUP_DIR"; fi
if mv "$NEW_DIR" "$BUNDLE_DIR"; then
  rm -rf -- "$BACKUP_DIR"
else
  [[ ! -e "$BACKUP_DIR" ]] || mv "$BACKUP_DIR" "$BUNDLE_DIR"
  fail "could not atomically activate the verified Tor bundle."
fi

cat > "${STATE_DIR}/tor-bundle.info" <<INFO
source=${BASE_URL}/${ARCHIVE}
version=${TOR_VERSION}
architecture=$(uname -m)
sha256=${EXPECTED_SHA256}
tor=${BUNDLE_DIR}/${TOR_BIN#"$EXTRACT_DIR"/}
lyrebird=${BUNDLE_DIR}/${LYREBIRD_BIN#"$EXTRACT_DIR"/}
INFO
chmod 0644 "${STATE_DIR}/tor-bundle.info"
echo "Official Tor Expert Bundle ${TOR_VERSION} installed and SHA-256 verified."
