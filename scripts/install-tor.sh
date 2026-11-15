#!/usr/bin/env bash
set -Eeuo pipefail

# Install the official Tor Expert Bundle (Tor + Lyrebird) on demand.
# The archive checksum is pinned to Tor Project's signed build manifest.
STATE_DIR="/usr/local/lib/shah-tunnel"
BUNDLE_DIR="${STATE_DIR}/tor-bundle"
TOR_VERSION="16.0.1"
BASE_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}"

fail() { echo "Tor installer: $*" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run as root (ShahTunnel invokes this automatically as root)."
for cmd in curl sha256sum tar find install mv rm mktemp chmod cp chown mkdir grep od tr; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

# Validate Linux ELF architecture before any binary is trusted. This deliberately
# accepts only the official runtime paths below; debug/tor is never a runtime.
native_elf() {
  local path="$1" expected_machine magic elf_class elf_data machine
  [[ -f "$path" && -x "$path" ]] || return 1
  magic="$(od -An -t x1 -N 4 "$path" 2>/dev/null | tr -d '[:space:]')"
  [[ "$magic" == "7f454c46" ]] || return 1
  elf_class="$(od -An -t u1 -j 4 -N 1 "$path" 2>/dev/null | tr -d '[:space:]')"
  elf_data="$(od -An -t u1 -j 5 -N 1 "$path" 2>/dev/null | tr -d '[:space:]')"
  machine="$(od -An -t x1 -j 18 -N 2 "$path" 2>/dev/null | tr -d '[:space:]')"
  [[ "$elf_class" == "2" && "$elf_data" == "1" ]] || return 1
  case "$(uname -m)" in
    x86_64|amd64) expected_machine="3e00" ;;
    aarch64|arm64) expected_machine="b700" ;;
    *) return 1 ;;
  esac
  [[ "$machine" == "$expected_machine" ]]
}

runtime_tor_self_test() {
  local tor_path="$1" pt_dir="$2" output
  native_elf "$tor_path" || return 1
  native_elf "$pt_dir/lyrebird" || return 1
  output="$(LD_LIBRARY_PATH="$(dirname "$tor_path"):$pt_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$tor_path" --version 2>&1)" || return 1
  grep -qi 'Tor version' <<<"$output"
}

# Official Linux Expert Bundle layout. Avoid arbitrary find-first selection:
# debug/tor is a debug artifact and has caused exec format errors on Agents.
TOR_REL="tor/tor"
LYREBIRD_REL="tor/pluggable_transports/lyrebird"
if grep -Fxq "version=${TOR_VERSION}" "${STATE_DIR}/tor-bundle.info" 2>/dev/null && \
   runtime_tor_self_test "$BUNDLE_DIR/$TOR_REL" "$BUNDLE_DIR/tor/pluggable_transports"; then
  echo "Official Tor Expert Bundle ${TOR_VERSION} is already installed and runtime-verified."
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

TOR_BIN="${EXTRACT_DIR}/${TOR_REL}"
LYREBIRD_BIN="${EXTRACT_DIR}/${LYREBIRD_REL}"
native_elf "$TOR_BIN" || fail "official Tor runtime is missing, non-ELF, or not built for Linux/$(uname -m): ${TOR_REL}"
native_elf "$LYREBIRD_BIN" || fail "official Lyrebird runtime is missing, non-ELF, or not built for Linux/$(uname -m): ${LYREBIRD_REL}"
TOR_VERSION_OUTPUT="$(LD_LIBRARY_PATH="${EXTRACT_DIR}/tor:${EXTRACT_DIR}/tor/pluggable_transports${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$TOR_BIN" --version 2>&1)" \
  || fail "official Tor runtime cannot execute on this VPS; refusing to install a broken bundle: ${TOR_VERSION_OUTPUT}"
grep -qi 'Tor version' <<<"$TOR_VERSION_OUTPUT" || fail "unexpected output from official Tor runtime: ${TOR_VERSION_OUTPUT}"

install -d -o root -g root -m 0755 "$STATE_DIR"
NEW_DIR="${STATE_DIR}/tor-bundle.new.$$"
BACKUP_DIR="${STATE_DIR}/tor-bundle.backup.$$"
rm -rf -- "$NEW_DIR" "$BACKUP_DIR"
cp -a "$EXTRACT_DIR" "$NEW_DIR"
chown -R root:root "$NEW_DIR"
find "$NEW_DIR" -type d -exec chmod 0755 {} +
find "$NEW_DIR" -type f -perm /111 -exec chmod 0755 {} +
find "$NEW_DIR" -type f ! -perm /111 -exec chmod 0644 {} +

# Verify exact staged runtime paths and execute Tor after the copy, before swap.
STAGED_TOR="${NEW_DIR}/${TOR_REL}"
STAGED_LYREBIRD="${NEW_DIR}/${LYREBIRD_REL}"
native_elf "$STAGED_TOR" || fail "staged Tor binary failed native ELF architecture validation."
native_elf "$STAGED_LYREBIRD" || fail "staged Lyrebird binary failed native ELF architecture validation."
STAGED_TOR_VERSION="$(LD_LIBRARY_PATH="${NEW_DIR}/tor:${NEW_DIR}/tor/pluggable_transports${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$STAGED_TOR" --version 2>&1)" \
  || fail "staged Tor binary cannot execute after installation copy: ${STAGED_TOR_VERSION}"
grep -qi 'Tor version' <<<"$STAGED_TOR_VERSION" || fail "staged Tor binary returned unexpected --version output: ${STAGED_TOR_VERSION}"

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
tor=${BUNDLE_DIR}/${TOR_REL}
lyrebird=${BUNDLE_DIR}/${LYREBIRD_REL}
INFO
chmod 0644 "${STATE_DIR}/tor-bundle.info"
echo "Official Tor Expert Bundle ${TOR_VERSION} installed and SHA-256 verified."
