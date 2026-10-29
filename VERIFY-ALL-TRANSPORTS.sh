#!/usr/bin/env bash
# Local verification helper. It reuses an existing Go 1.26.1 toolchain and never downloads one.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GO_VERSION="1.26.1"
GO_HOME="$ROOT/.toolchains/go${GO_VERSION}"
GO_BIN=""

fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[ OK ] %s\n' "$*"; }

version_is_pinned() {
  local bin="$1" v
  [[ -x "$bin" ]] || return 1
  v="$(GOTOOLCHAIN=local "$bin" version 2>/dev/null || true)"
  [[ "$v" == *"go${GO_VERSION}"* ]]
}

# Reuse only an exact Go 1.26.1 binary. An older/newer system toolchain is not used.
for candidate in "$GO_HOME/bin/go" "/usr/local/lib/shah-tunnel/go-${GO_VERSION}/bin/go" "$(command -v go 2>/dev/null || true)"; do
  if [[ -n "$candidate" ]] && version_is_pinned "$candidate"; then
    GO_BIN="$candidate"
    break
  fi
done

if [[ -z "$GO_BIN" ]]; then
  fail "Go ${GO_VERSION} is not installed locally. This verification script will not download toolchains."
fi

version_out="$(GOTOOLCHAIN=local "$GO_BIN" version)"
[[ "$version_out" == *"go${GO_VERSION}"* ]] || fail "Expected Go ${GO_VERSION}, got: $version_out"
export PATH="$(dirname "$GO_BIN"):$PATH"
export GOTOOLCHAIN=local
pass "Pinned toolchain: $version_out"

printf '\n== 1/7: Resolve Go module metadata ==\n'
"$GO_BIN" mod tidy || fail "Could not validate Go module metadata."
"$GO_BIN" mod download || fail "go mod download failed."
pass "Module metadata resolved"

printf '\n== 2/7: Formatting ==\n'
unformatted="$(gofmt -l S1T-CAPSULE/main.go S1T-CAPSULE/main_test.go)"
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
[[ "$(dist/shah-tunnel-linux-amd64 version)" == "Shah Tunnel 1.6.2 (linux/amd64)" ]] || fail "Built amd64 binary version/target check failed."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO_BIN" build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-arm64 ./S1T-CAPSULE
(cd dist && sha256sum shah-tunnel-linux-amd64 > shah-tunnel-linux-amd64.sha256)
(cd dist && sha256sum shah-tunnel-linux-arm64 > shah-tunnel-linux-arm64.sha256)
pass "Linux amd64 and arm64 binaries built; amd64 runtime version verified"

echo
echo "ALL CHECKS PASSED using Go ${GO_VERSION}."
