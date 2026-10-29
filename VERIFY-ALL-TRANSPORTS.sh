#!/usr/bin/env bash
# Local verification helper. It reuses an existing Go 1.26.x or 1.27.x toolchain and never downloads one.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GO_VERSION="1.26.10" # installer download default; verifier accepts installed 1.26.x/1.27.x
GO_HOME="$ROOT/.toolchains/go${GO_VERSION}"
case "$(uname -m)" in
  x86_64|amd64) VERIFY_ARCH="amd64" ;;
  aarch64|arm64) VERIFY_ARCH="arm64" ;;
  *) echo "Unsupported architecture for pinned Go verification: $(uname -m)" >&2; exit 1 ;;
esac
GO_BIN=""

fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[ OK ] %s\n' "$*"; }

version_is_compatible() {
  local bin="$1" v
  [[ -x "$bin" ]] || return 1
  v="$(GOTOOLCHAIN=local "$bin" version 2>/dev/null || true)"
  [[ "$v" =~ go[[:space:]]version[[:space:]]go1\.(26|27)\.[0-9]+[[:space:]]linux/${VERIFY_ARCH} ]]
}

# Prefer a compatible local toolchain; this helper never downloads Go.
shopt -s nullglob
local_candidates=(
  "$GO_HOME/bin/go"
  /usr/local/lib/shah-tunnel/toolchains/go1.26.*-"$VERIFY_ARCH"/bin/go
  /usr/local/lib/shah-tunnel/toolchains/go1.27.*-"$VERIFY_ARCH"/bin/go
  /usr/local/lib/shah-tunnel/go-*/bin/go
  "$(command -v go 2>/dev/null || true)"
)
shopt -u nullglob
for candidate in "${local_candidates[@]}"; do
  if [[ -n "$candidate" ]] && version_is_compatible "$candidate"; then
    GO_BIN="$candidate"
    break
  fi
done

if [[ -z "$GO_BIN" ]]; then
  fail "Go 1.26.x or 1.27.x is not installed locally. This verification script will not download toolchains."
fi

version_out="$(GOTOOLCHAIN=local "$GO_BIN" version)"
[[ "$version_out" =~ go[[:space:]]version[[:space:]]go1\.(26|27)\.[0-9]+[[:space:]]linux/${VERIFY_ARCH} ]] || fail "Expected Go 1.26.x/1.27.x, got: $version_out"
GO_USED_VERSION="$(awk '{print $3}' <<<"$version_out")"
export PATH="$(dirname "$GO_BIN"):$PATH"
export GOTOOLCHAIN=local
pass "Pinned toolchain: $version_out"

printf '\n== 1/7: Resolve Go module metadata ==\n'
"$GO_BIN" mod tidy || fail "Could not validate Go module metadata."
"$GO_BIN" mod download || fail "go mod download failed."
pass "Module metadata resolved"

printf '\n== 2/7: Formatting ==\n'
unformatted="$(gofmt -l S1T-CAPSULE/main.go S1T-CAPSULE/main_test.go S1T-CAPSULE/reality_transport.go)"
[[ -z "$unformatted" ]] || fail "gofmt required for: $unformatted"
pass "Go source formatting"

printf '\n== 3/7: Installer syntax ==\n'
bash -n S1T-START.sh
bash -n install.sh
pass "Shell syntax"

printf '\n== 4/7: Transport loopback suite ==\n'
"$GO_BIN" test -count=20 ./S1T-CAPSULE || fail "Automated transport tests failed."
pass "Transport suite (20 iterations)"

printf '\n== 5/7: Race detector ==\n'
if command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
  "$GO_BIN" test -race -count=5 ./S1T-CAPSULE || fail "Race detector test failed."
  pass "Race detector (5 iterations)"
else
  echo "[WARN] gcc/clang not found; race-detector run skipped. Standard tests above still ran. GitHub Actions uses an Ubuntu runner with a C toolchain."
fi

printf '\n== 6/7: Static analysis ==\n'
"$GO_BIN" vet ./S1T-CAPSULE || fail "go vet reported an issue."
pass "go vet"

printf '\n== 7/7: Linux binaries build ==\n'
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-amd64 ./S1T-CAPSULE
[[ "$(dist/shah-tunnel-linux-amd64 version)" == "Shah Tunnel 1.7.1 (linux/amd64)" ]] || fail "Built amd64 binary version/target check failed."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO_BIN" build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-arm64 ./S1T-CAPSULE
(cd dist && sha256sum shah-tunnel-linux-amd64 > shah-tunnel-linux-amd64.sha256)
(cd dist && sha256sum shah-tunnel-linux-arm64 > shah-tunnel-linux-arm64.sha256)
pass "Linux amd64 and arm64 binaries built; amd64 runtime version verified"

echo
echo "ALL CHECKS PASSED using Go ${GO_USED_VERSION}."
