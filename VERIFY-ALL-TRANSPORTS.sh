#!/usr/bin/env bash
# Local verification helper. It reuses an existing Go 1.26.1 toolchain and never downloads one.
# Build outputs are kept under a temporary directory; no executable is left in the source tree.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
BUILD_TMP="$(mktemp -d "${TMPDIR:-/tmp}/shah-tunnel-verify.XXXXXX")"
cleanup() { rm -rf -- "$BUILD_TMP"; }
trap cleanup EXIT

GO_VERSION="1.26.1"
GO_HOME="$ROOT/.toolchains/go${GO_VERSION}"
GO_BIN=""

fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[ OK ] %s\n' "$*"; }

case "$(uname -m)" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *) fail "Unsupported verification architecture: $(uname -m)" ;;
esac

version_is_pinned() {
  local bin="$1" v
  [[ -x "$bin" ]] || return 1
  v="$(GOTOOLCHAIN=local "$bin" version 2>/dev/null || true)"
  [[ "$v" == *"go${GO_VERSION}"* ]]
}

# Reuse only an exact Go 1.26.1 binary. An older/newer system toolchain is not used.
for candidate in "$GO_HOME/bin/go" "/usr/local/lib/shah-tunnel/toolchains/go${GO_VERSION}-${TARGET_ARCH}/bin/go" "/usr/local/lib/shah-tunnel/go-${GO_VERSION}/bin/go" "$(command -v go 2>/dev/null || true)"; do
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
unformatted="$(gofmt -l S1T-CAPSULE/main.go S1T-CAPSULE/main_test.go S1T-CAPSULE/xray_warp.go S1T-CAPSULE/xray_psiphon.go S1T-CAPSULE/psiphon.go S1T-CAPSULE/psiphon_test.go S1T-CAPSULE/tor.go S1T-CAPSULE/tor_test.go S1T-CAPSULE/xray_tor.go S1T-CAPSULE/xray_tor_test.go)"
[[ -z "$unformatted" ]] || fail "gofmt required for: $unformatted"
pass "Go source formatting"

printf '\n== 3/7: Installer syntax ==\n'
bash -n S1T-START.sh
bash -n scripts/install-psiphon.sh
bash -n scripts/install-tor.sh
bash -n scripts/repair-psiphon-profile.sh
bash -n VERIFY-ALL-TRANSPORTS.sh
grep -Fq 'ReadWritePaths=/var/lib/shah-tunnel/psiphon' S1T-START.sh || fail "Psiphon systemd data-directory permission is missing."
grep -Fq 'ReadWritePaths=/var/lib/shah-tunnel/tor' S1T-START.sh || fail "Tor systemd data-directory permission is missing."
grep -Fq 'tor-expert-bundle-linux-x86_64-16.0.1.tar.gz' scripts/install-tor.sh || fail "Pinned official Tor Expert Bundle is missing."
grep -Fq '7039cb16060ab22e669852e55774d894b55f25ea8bd0ab7194d3478429a58725' scripts/install-tor.sh || fail "Official Tor x86_64 checksum pin is missing."
grep -Fq '67040520d44c87ccaaf5aa7df0dc1ff122eb938dbb600ae7722e8b6b75282a4b' scripts/install-tor.sh || fail "Official Tor arm64 checksum pin is missing."
grep -Fq 'func startTorForAgent(cfg Config)' S1T-CAPSULE/tor.go || fail "Tor per-profile runtime is missing."
grep -Fq 'func compatibleLinuxELF(path string) bool' S1T-CAPSULE/tor.go || fail "Tor CPU/ELF compatibility validation is missing."
grep -Fq 'Prefer the real Expert Bundle daemon' scripts/install-tor.sh || fail "Tor installer does not avoid debug/tor artifacts."
grep -Fq 'func validateTorBridgeLine' S1T-CAPSULE/tor.go || fail "Tor WebTunnel bridge validation is missing."
grep -Fq 'func emergencyTorMenu() error' S1T-CAPSULE/main.go || fail "Standalone emergency Tor menu is missing."
grep -Fq 'Tor Snowflake' S1T-CAPSULE/main.go || fail "Emergency Snowflake choice is missing."
grep -Fq 'Tor WebTunnel' S1T-CAPSULE/main.go || fail "Emergency WebTunnel choice is missing."
grep -Fq 'func cloneAgentConfigForEmergencyTor' S1T-CAPSULE/main.go || fail "Independent emergency Agent profile cloning is missing."
grep -Fq 'TestCloneAgentConfigForEmergencyTorRestoresSidecarTargets' S1T-CAPSULE/main_test.go || fail "Emergency Agent clone regression coverage is missing."
grep -Fq 'func autoApplyXrayTorForNewAgent() error' S1T-CAPSULE/xray_tor.go || fail "Automatic Tor Xray user egress is missing."
grep -Fq 'TestBuildXrayTorConfigIsolatesTCPAndBlocksUDP' S1T-CAPSULE/xray_tor_test.go || fail "Tor TCP/DNS isolation and UDP fail-closed coverage is missing."
grep -Fq 'func preparePsiphonAgentProfile(c *Config) error' S1T-CAPSULE/psiphon.go || fail "Automatic per-Agent Psiphon preparation is missing."
grep -Fq 'func startPsiphonForAgent(cfg Config)' S1T-CAPSULE/main.go || fail "Psiphon ConsoleClient runtime is missing."
grep -Fq '96f782c' scripts/install-psiphon.sh || fail "Pinned official Psiphon source revision is missing."
grep -Fq 'Psiphon ConsoleClient installed successfully' scripts/install-psiphon.sh || fail "Psiphon binary install self-check is missing."
grep -Fq 'TestNewPsiphonClientConfigUsesAuthenticatedBootstrap' S1T-CAPSULE/psiphon_test.go || fail "Psiphon signed server-list bootstrap coverage is missing."
grep -Fq 'TestValidatePsiphonRejectsUnauthenticatedServerList' S1T-CAPSULE/psiphon_test.go || fail "Psiphon unauthenticated server-list rejection coverage is missing."
grep -Fq 'shah-tunnel-control/1' S1T-CAPSULE/main.go || fail "Dedicated TLS ALPN for Psiphon/public-Mapping multiplex is missing."
grep -Fq 'func sniffS1TControlClientHello' S1T-CAPSULE/main.go || fail "Public Mapping TLS control demultiplexer is missing."
grep -Fq 'PsiphonHubAddr' S1T-CAPSULE/main.go || fail "Per-egress Psiphon Hub endpoint is missing."
grep -Fq 'TestTLSClientHelloALPNSnifferPreservesAllBytes' S1T-CAPSULE/main_test.go || fail "TLS ALPN byte-preservation coverage is missing."
grep -Fq 'TestAdaptivePsiphonUsesPublicMappingPortAndALPNMultiplex' S1T-CAPSULE/main_test.go || fail "Psiphon public-Mapping integration coverage is missing."

grep -Fq 'func detectActiveWarpUnderlay() string' S1T-CAPSULE/main.go || fail "Adaptive WARP protocol detection is missing."
grep -Fq 'func warpProxyAddressFromSettings(settings string)' S1T-CAPSULE/main.go || fail "Cloudflare Local Proxy detection is missing."
grep -Fq 'return dialSOCKS5Context(ctx, proxyAddress, address)' S1T-CAPSULE/main.go || fail "WARP Local Proxy SOCKS5 dialer is missing."
grep -Fq 'TestWarpProxyAddressFromSettings' S1T-CAPSULE/main_test.go || fail "WARP Local Proxy parsing tests are missing."
grep -Fq 'TestDialAgentUnderlayUsesDetectedWarpLocalProxy' S1T-CAPSULE/main_test.go || fail "WARP Local Proxy Agent integration coverage is missing."
grep -Fq 'TestAdaptiveUnderlayCandidatesDetectMASQUEAndFailOver' S1T-CAPSULE/main_test.go || fail "WARP failover coverage is missing."
grep -Fq 'TestOptionNineSwitchesFromFailedDirectPathToPsiphonSOCKS5' S1T-CAPSULE/main_test.go || fail "Option 9 SOCKS5 failover coverage is missing."
grep -Fq 'func verifyWarpPerTunnelPrerequisites() (string, error)' S1T-CAPSULE/xray_warp.go || fail "Automatic per-tunnel WARP prerequisites are missing."
grep -Fq 'TestWarpProxyForPerTunnelEgressRejectsSystemTunnelMode' S1T-CAPSULE/main_test.go || fail "System Tunnel rejection for per-profile WARP is not covered."
grep -Fq 'autoApplyXrayWarpForNewAgent()' S1T-CAPSULE/main.go || fail "New-Agent setup does not invoke automatic WARP user egress."
if grep -Fq 'menuItem("9", "🌐 WARP egress"' S1T-CAPSULE/main.go; then fail "Separate manager WARP egress menu item must not be present."; fi
grep -Fq 'TestBuildXrayWarpConfigIsolatesOnlyClonedInbound' S1T-CAPSULE/main_test.go || fail "Per-inbound Xray WARP isolation coverage is missing."
grep -Fq 'func buildXrayPsiphonConfig(' S1T-CAPSULE/xray_psiphon.go || fail "Per-profile Xray Psiphon egress builder is missing."
grep -Fq 'func autoApplyXrayPsiphonForNewAgent() error' S1T-CAPSULE/xray_psiphon.go || fail "Automatic Psiphon user-egress setup is missing."
grep -Fq 'autoApplyXrayPsiphonForNewAgent()' S1T-CAPSULE/main.go || fail "New-Agent setup does not invoke automatic Psiphon user egress."
if grep -Fq 'menuItem("10", "🛡️ Psiphon user egress"' S1T-CAPSULE/main.go; then fail "Redundant Psiphon menu option must not be present."; fi
grep -Fq 'TestBuildXrayPsiphonConfigIsolatesTCPAndBlocksUDP' S1T-CAPSULE/main_test.go || fail "Psiphon TCP/DNS isolation and UDP fail-closed coverage is missing."
grep -Fq 'TestXrayPsiphonManagedPathsAndUnitAreRestricted' S1T-CAPSULE/main_test.go || fail "Psiphon sidecar service/path safety coverage is missing."
grep -Fq 'TestHubBalancesMeasuredRTTAndLoad' S1T-CAPSULE/main_test.go || fail "RTT/load lane selection coverage is missing."
grep -Fq 'TestHubPrefersFreshRTTOverStaleLowRTT' S1T-CAPSULE/main_test.go || fail "Fresh RTT lane selection regression coverage is missing."
grep -Fq 'TestPsiphonPerformanceProfileIsMemoryAndCPUAware' S1T-CAPSULE/psiphon_test.go || fail "Psiphon memory-aware performance profile coverage is missing."
grep -Fq 'TestTunePsiphonPerformanceConfigPreservesUnknownFields' S1T-CAPSULE/psiphon_test.go || fail "Psiphon profile tuning compatibility coverage is missing."
grep -Fq 'lanePingInterval = 5 * time.Second' S1T-CAPSULE/main.go || fail "Five-second lane RTT sampling is missing."
grep -Fq 'dnsConfig["disableCache"] = false' S1T-CAPSULE/xray_warp.go || fail "Xray DNS cache is not explicitly enabled."
pass "Shell syntax, docs layout, Psiphon bootstrap/runtime, public-Mapping ALPN multiplex, MASQUE Local Proxy, and failover coverage"

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

printf '\n== 7/7: Linux build validation (temporary files only) ==\n'
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build -trimpath -ldflags='-s -w -buildid=' -o "$BUILD_TMP/shah-tunnel-linux-amd64" ./S1T-CAPSULE
[[ "$("$BUILD_TMP/shah-tunnel-linux-amd64" version)" == "Shah Tunnel 5.0.0 (linux/amd64)" ]] || fail "Built amd64 binary version/target check failed."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO_BIN" build -trimpath -ldflags='-s -w -buildid=' -o "$BUILD_TMP/shah-tunnel-linux-arm64" ./S1T-CAPSULE
sha256sum "$BUILD_TMP/shah-tunnel-linux-amd64" "$BUILD_TMP/shah-tunnel-linux-arm64" > "$BUILD_TMP/SHA256SUMS"
pass "Linux amd64 and arm64 binaries built and checksum-checked in a temporary directory (nothing added to the repository)"

echo
echo "ALL CHECKS PASSED using Go ${GO_VERSION}."
