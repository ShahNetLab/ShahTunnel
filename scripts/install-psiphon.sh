#!/usr/bin/env bash
set -Eeuo pipefail

# Build the official Psiphon ConsoleClient from a pinned upstream source commit.
# This helper is invoked automatically by ShahTunnel when Psiphon egress is selected.
PSIPHON_REPO="https://github.com/Psiphon-Labs/psiphon-tunnel-core"
PSIPHON_ARCHIVE="https://codeload.github.com/Psiphon-Labs/psiphon-tunnel-core/tar.gz/96f782c"
PSIPHON_COMMIT="96f782c"
PSIPHON_VERSION="v2.0.41"
INSTALL_PATH="/usr/local/bin/psiphon-console-client"
LICENSE_PATH="/usr/local/share/licenses/psiphon-tunnel-core/LICENSE"
STATE_DIR="/usr/local/lib/shah-tunnel"

fail() { echo "Psiphon installer: $*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run as root (ShahTunnel invokes this automatically as root)."
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v tar >/dev/null 2>&1 || fail "tar is required."
command -v python3 >/dev/null 2>&1 || fail "python3 is required."
command -v timeout >/dev/null 2>&1 || fail "coreutils timeout is required."

case "$(uname -m)" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *) fail "unsupported architecture: $(uname -m) (supported: amd64, arm64)." ;;
esac

# Fast path: a previously built, executable ConsoleClient is reused.
if [[ -x "$INSTALL_PATH" ]]; then
  if timeout --kill-after=2s 8s "$INSTALL_PATH" -version >/dev/null 2>&1; then
    echo "Psiphon ConsoleClient is already installed: $INSTALL_PATH"
    exit 0
  fi
fi

GO_BIN=""
for candidate in \
  "${STATE_DIR}/toolchains/go1.26.1-${TARGET_ARCH}/bin/go" \
  "${STATE_DIR}/toolchains/go1.26.5-${TARGET_ARCH}/bin/go" \
  "/usr/local/go/bin/go" \
  "$(command -v go 2>/dev/null || true)"; do
  [[ -n "$candidate" && -x "$candidate" ]] || continue
  if "$candidate" version >/dev/null 2>&1; then GO_BIN="$candidate"; break; fi
done
[[ -n "$GO_BIN" ]] || fail "Go toolchain not found. Install/update ShahTunnel first so its pinned Go toolchain is present."

TMP="$(mktemp -d /tmp/shahtunnel-psiphon.XXXXXX)"
chmod 0700 "$TMP"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

ARCHIVE="$TMP/psiphon-source.tar.gz"
SRC="$TMP/source"
mkdir -p "$SRC"
echo "Downloading official Psiphon Tunnel Core ${PSIPHON_VERSION} (${PSIPHON_COMMIT})..."
curl -fL --proto '=https' --proto-redir '=https' \
  --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 900 \
  "$PSIPHON_ARCHIVE" -o "$ARCHIVE" || fail "could not download the pinned upstream source archive."

tar -tzf "$ARCHIVE" >/dev/null 2>&1 || fail "downloaded source archive is invalid."
tar -xzf "$ARCHIVE" -C "$SRC" --strip-components=1
[[ -s "$SRC/go.mod" && -s "$SRC/ConsoleClient/main.go" && -s "$SRC/LICENSE" && -d "$SRC/vendor" ]] || \
  fail "upstream source archive is incomplete (go.mod, ConsoleClient, LICENSE or vendor missing)."
grep -Eq '^go 1\.26\.0$' "$SRC/go.mod" || fail "unexpected Go module version in upstream source."
grep -Eq '^toolchain go1\.26\.5$' "$SRC/go.mod" || fail "upstream toolchain directive changed; review before updating the pin."

# Psiphon v2.0.41 specifies Go 1.26.5. Starting from ShahTunnel's Go 1.26.1
# toolchain, Go's official toolchain selection downloads/verifies the exact
# required Go toolchain. Dependencies are built from the upstream vendor tree.
echo "Building Psiphon ConsoleClient for linux/${TARGET_ARCH}; upstream toolchain go1.26.5..."
(
  cd "$SRC"
  env GOTOOLCHAIN=auto GOPROXY="https://proxy.golang.org,direct" \
    GOSUMDB=sum.golang.org GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 \
    GOMAXPROCS=1 GOGC=50 \
    "$GO_BIN" build -mod=vendor -p=1 -trimpath -buildvcs=false \
      -ldflags='-s -w' -o "$TMP/psiphon-console-client" ./ConsoleClient
) || fail "official Psiphon ConsoleClient build failed. See the Go error above."

[[ -s "$TMP/psiphon-console-client" ]] || fail "build produced no ConsoleClient binary."
chmod 0755 "$TMP/psiphon-console-client"
timeout --kill-after=2s 10s "$TMP/psiphon-console-client" -version >"$TMP/version.txt" 2>&1 || \
  fail "built ConsoleClient failed its -version self-test."

# Verify the ELF machine ID before installing a binary for this host.
python3 - "$TMP/psiphon-console-client" "$TARGET_ARCH" <<'PY'
import sys
p, arch = sys.argv[1:]
b = open(p, "rb").read(20)
if len(b) < 20 or b[:4] != b"\x7fELF":
    raise SystemExit("Psiphon output is not a valid ELF executable")
endian = "<" if b[5] == 1 else ">" if b[5] == 2 else None
if endian is None:
    raise SystemExit("unknown ELF byte order")
import struct
machine = struct.unpack(endian + "H", b[18:20])[0]
expected = {"amd64": 62, "arm64": 183}[arch]
if machine != expected:
    raise SystemExit(f"wrong ELF machine: {machine}; expected {expected} for {arch}")
PY

install -d -o root -g root -m 0755 /usr/local/bin
install -d -o root -g root -m 0755 "$(dirname "$LICENSE_PATH")"
install -o root -g root -m 0755 "$TMP/psiphon-console-client" "${INSTALL_PATH}.new"
mv -f "${INSTALL_PATH}.new" "$INSTALL_PATH"
install -o root -g root -m 0644 "$SRC/LICENSE" "$LICENSE_PATH"
install -d -o root -g root -m 0755 "${STATE_DIR}"
cat > "${STATE_DIR}/psiphon-build.info" <<INFO
source=${PSIPHON_REPO}
version=${PSIPHON_VERSION}
commit=${PSIPHON_COMMIT}
architecture=${TARGET_ARCH}
upstream_go_toolchain=1.26.5
binary=${INSTALL_PATH}
INFO
chmod 0644 "${STATE_DIR}/psiphon-build.info"

# Final installed-binary check.
timeout --kill-after=2s 10s "$INSTALL_PATH" -version >/dev/null 2>&1 || fail "installed ConsoleClient self-test failed."
echo "Psiphon ConsoleClient installed successfully: ${INSTALL_PATH} (${TARGET_ARCH}, ${PSIPHON_VERSION})."
