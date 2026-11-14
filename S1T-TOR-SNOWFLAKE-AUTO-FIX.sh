#!/usr/bin/env bash
set -Eeuo pipefail

# One-shot repair for ShahTunnel 5.0.0 emergency Tor:
# - restores automatic Snowflake (no user-supplied bridge line)
# - permits unknown bridge metadata while excluding US-classified Tor relays
# - removes redundant emergency profile name / mapping prompts by using saved defaults
# - rebuilds and installs through the project's verified official installer

OWNER="ShahNetLab"
REPO="ShahTunnel"
BRANCH="main"
ARCHIVE_URL="https://codeload.github.com/${OWNER}/${REPO}/tar.gz/refs/heads/${BRANCH}"

log() { printf '\n[SHAH-TOR-FIX] %s\n' "$*"; }
die() { printf '\n[SHAH-TOR-FIX] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "Run this repair as root."
for cmd in curl tar python3 bash sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required command is missing: $cmd"
done

WORK="$(mktemp -d /tmp/shah-tor-snowflake-fix.XXXXXX)"
chmod 0700 "$WORK"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
SRC="$WORK/source"
mkdir -p "$SRC"

log "Downloading the current ShahTunnel source"
curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 240 \
  "$ARCHIVE_URL" -o "$WORK/source.tar.gz"
tar -xzf "$WORK/source.tar.gz" -C "$SRC" --strip-components=1

[[ -s "$SRC/go.mod" && -s "$SRC/S1T-CAPSULE/main.go" && -s "$SRC/S1T-CAPSULE/tor.go" && -s "$SRC/S1T-START.sh" ]] \
  || die "The downloaded source is not the expected ShahTunnel repository layout."

log "Applying the no-manual-bridge Snowflake repair"
python3 - "$SRC" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
main_path = root / "S1T-CAPSULE" / "main.go"
tor_path = root / "S1T-CAPSULE" / "tor.go"
test_path = root / "S1T-CAPSULE" / "tor_test.go"

main = main_path.read_text(encoding="utf-8")
tor = tor_path.read_text(encoding="utf-8")
tests = test_path.read_text(encoding="utf-8")

# Tor: exclude US-classified Tor relays at every circuit position, but do not
# exclude unknown GeoIP metadata. The Snowflake bridge uses a placeholder IP;
# applying {??} / GeoIPExcludeUnknown prevents Tor from starting any bridge.
pattern = re.compile(
    r'\t// Strict emergency policy:.*?\n'
    r'\tb\.WriteString\("StrictNodes 1\\n"\)',
    re.S,
)
replacement = (
    '\t// Exclude Tor relays classified by Tor GeoIP as US at every circuit position.\n'
    '\t// Do not exclude unknown bridge metadata: Snowflake uses a placeholder address.\n'
    '\t// The live exit verifier still rejects US or unverified exit IPs.\n'
    '\tb.WriteString("ExcludeNodes {us}\\n")\n'
    '\tb.WriteString("StrictNodes 1\\n")'
)
tor_new, n = pattern.subn(lambda _match: replacement, tor, count=1)
if n != 1:
    raise SystemExit("Could not find the expected strict Tor policy block; no source was changed.")
if 'ExcludeNodes {us},{??}' in tor_new or 'GeoIPExcludeUnknown 1' in tor_new:
    raise SystemExit("Unsafe unknown-node exclusion remained in tor.go.")
if 'b.WriteString("ExcludeNodes {us}\\n")' not in tor_new:
    raise SystemExit("The US relay exclusion was not installed in tor.go.")

# Restore both choices. Snowflake uses ShahTunnel's built-in bridge and never
# prompts the operator for a bridge line.
mode_pattern = re.compile(
    r'func emergencyTorModeFromChoice\(choice string\) \(string, error\) \{.*?\n\}\n(?=// cloneAgentConfigForEmergencyTor)',
    re.S,
)
mode_replacement = '''func emergencyTorModeFromChoice(choice string) (string, error) {
\tswitch strings.TrimSpace(choice) {
\tcase "1":
\t\treturn torModeSnowflake, nil
\tcase "2":
\t\treturn torModeWebTunnel, nil
\tdefault:
\t\treturn "", errors.New("invalid emergency Tor selection; enter 1, 2, or 3")
\t}
}
'''
main_new, n = mode_pattern.subn(mode_replacement, main, count=1)
if n != 1:
    raise SystemExit("Could not locate emergencyTorModeFromChoice in main.go.")

old_menu = '''\tfmt.Println("  1) Tor WebTunnel (strict no-US; verified non-US bridge required)")
\tfmt.Println("  2) Back")
\tchoice := ask("Select the emergency Tor transport", "2")
\tif strings.TrimSpace(choice) == "2" || strings.TrimSpace(choice) == "0" {
'''
new_menu = '''\tfmt.Println("  1) Tor Snowflake (automatic; no bridge input required)")
\tfmt.Println("  2) Tor WebTunnel (manual bridge line required)")
\tfmt.Println("  3) Back")
\tchoice := ask("Select the emergency Tor transport", "3")
\tif strings.TrimSpace(choice) == "3" || strings.TrimSpace(choice) == "0" {
'''
if old_menu not in main_new:
    raise SystemExit("Could not locate the expected emergency Tor menu block in main.go.")
main_new = main_new.replace(old_menu, new_menu, 1)

# Select the first running Agent automatically. The source list is still shown
# so the operator can see which profile will be cloned.
old_selection = '''\tselectedText := strings.TrimSpace(ask("Clone which Agent as an emergency Tor profile (number or name)", "1"))
\tselected := -1
\tif n, parseErr := strconv.Atoi(selectedText); parseErr == nil && n >= 1 && n <= len(agents) {
\t\tselected = n - 1
\t} else {
\t\tfor i, profile := range agents {
\t\t\tif strings.EqualFold(selectedText, profile.Name) || strings.EqualFold(selectedText, profile.ID) {
\t\t\t\tselected = i
\t\t\t\tbreak
\t\t\t}
\t\t}
\t}
\tif selected < 0 {
\t\treturn errors.New("selected Agent profile was not found")
\t}
'''
new_selection = '''\tselected := -1
\tfor i, profile := range agents {
\t\tif exec.Command("systemctl", "is-active", "--quiet", profile.Service).Run() == nil {
\t\t\tselected = i
\t\t\tbreak
\t\t}
\t}
\tif selected < 0 {
\t\tselected = 0
\t}
\tuiInfo("Automatically selected Agent profile: " + agents[selected].Name)
'''
if old_selection not in main_new:
    raise SystemExit("Could not locate the emergency Agent selection block in main.go.")
main_new = main_new.replace(old_selection, new_selection, 1)

# Allocate a free profile name automatically rather than asking for one.
old_name = '''\tdefaultName := "emergency-tor-" + mode
\tnewName := strings.TrimSpace(wizardAsk("Name for the independent emergency profile", defaultName))
\tnewPath := tunnelConfigPath(newName)
\tif info, statErr := os.Stat(newPath); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
\t\tif statErr == nil && info != nil {
\t\t\treturn fmt.Errorf("profile %q already exists; choose a different emergency profile name", newName)
\t\t}
\t\treturn statErr
\t}
\tfor _, profile := range profiles {
\t\tif strings.EqualFold(profile.Name, newName) || profile.ID == tunnelID(newName) {
\t\t\treturn fmt.Errorf("profile %q already exists; choose a different emergency profile name", profile.Name)
\t\t}
\t}
'''
new_name = '''\tdefaultName := "emergency-tor-" + mode
\tnewName := defaultName
\tvar newPath string
\tfor suffix := 1; suffix <= 9999; suffix++ {
\t\tif suffix > 1 {
\t\t\tnewName = fmt.Sprintf("%s-%d", defaultName, suffix)
\t\t}
\t\tnewPath = tunnelConfigPath(newName)
\t\t_, statErr := os.Stat(newPath)
\t\tif statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
\t\t\treturn statErr
\t\t}
\t\tused := statErr == nil
\t\tfor _, profile := range profiles {
\t\t\tif strings.EqualFold(profile.Name, newName) || profile.ID == tunnelID(newName) {
\t\t\t\tused = true
\t\t\t\tbreak
\t\t\t}
\t\t}
\t\tif !used {
\t\t\tbreak
\t\t}
\t\tif suffix == 9999 {
\t\t\treturn errors.New("could not allocate a unique emergency Tor profile name")
\t\t}
\t}
\tuiInfo("Emergency profile name: " + newName)
'''
if old_name not in main_new:
    raise SystemExit("Could not locate the emergency profile naming block in main.go.")
main_new = main_new.replace(old_name, new_name, 1)

# Reuse the Mapping endpoint already stored/derived from the source Agent.
# The Hub Mapping is not the control listener; if it cannot be derived, fail
# closed instead of asking for an unknown address.
old_endpoint = '''\tdefaultEndpoint := cloned.TorHubAddr
\tcloned.TorHubAddr = strings.TrimSpace(wizardAsk("Hub public Mapping address reachable through Tor SOCKS5 (IP:PORT)", defaultEndpoint))
\tif cloned.TorHubAddr == "" {
\t\tcloned.TorHubAddr = defaultEndpoint
\t}
'''
new_endpoint = '''\tcloned.TorHubAddr = strings.TrimSpace(cloned.TorHubAddr)
\tif cloned.TorHubAddr == "" {
\t\treturn errors.New("the source Agent has no saved Tor-reachable Hub Mapping address; configure that Mapping on the source profile first")
\t}
\tuiInfo("Using saved Hub Mapping address: " + cloned.TorHubAddr)
'''
if old_endpoint not in main_new:
    raise SystemExit("Could not locate the emergency Hub Mapping prompt in main.go.")
main_new = main_new.replace(old_endpoint, new_endpoint, 1)

# Update tests to assert the correct Snowflake-compatible no-US policy.
if '"ExcludeNodes {us},{??}\\n",' not in tests:
    raise SystemExit("Could not locate old ExcludeNodes test expectation in tor_test.go.")
tests = tests.replace('"ExcludeNodes {us},{??}\\n",', '"ExcludeNodes {us}\\n",', 1)
if '"GeoIPExcludeUnknown 1\\n",' not in tests:
    raise SystemExit("Could not locate old GeoIPExcludeUnknown test expectation in tor_test.go.")
tests = tests.replace('\t\t"GeoIPExcludeUnknown 1\\n",\n', '', 1)
old_assert = '''\tif !strings.Contains(got, "ExcludeNodes {us},{??}\\n") || strings.Contains(got, "ExcludeExitNodes") {
\t\tt.Fatal("strict Tor policy must exclude US and unknown-country nodes at every circuit position")
\t}
'''
new_assert = '''\tif !strings.Contains(got, "ExcludeNodes {us}\\n") || strings.Contains(got, "ExcludeNodes {us},{??}") || strings.Contains(got, "GeoIPExcludeUnknown") || strings.Contains(got, "ExcludeExitNodes") {
\t\tt.Fatal("Tor policy must exclude US-classified relays without blocking unknown Snowflake bridge metadata")
\t}
'''
if old_assert not in tests:
    raise SystemExit("Could not locate old strict Tor test assertion.")
tests = tests.replace(old_assert, new_assert, 1)

# Confirm the resulting source has exactly the intended behavior.
if 'return torModeSnowflake, nil' not in main_new or '1) Tor Snowflake (automatic; no bridge input required)' not in main_new:
    raise SystemExit("Snowflake menu restoration verification failed.")
if 'Paste one Tor WebTunnel bridge line' not in main_new:
    raise SystemExit("WebTunnel-only manual prompt disappeared unexpectedly.")
if 'ExcludeNodes {us},{??}' in tor_new or 'GeoIPExcludeUnknown 1' in tor_new:
    raise SystemExit("Unsafe strict bridge filtering remains.")

main_path.write_text(main_new, encoding="utf-8")
tor_path.write_text(tor_new, encoding="utf-8")
test_path.write_text(tests, encoding="utf-8")
PY

log "Checking patched source and shell syntax"
for helper in "$SRC/S1T-START.sh" "$SRC/scripts/install-tor.sh" "$SRC/scripts/install-psiphon.sh"; do
  [[ -s "$helper" ]] || die "Required installer helper is missing: $helper"
  bash -n "$helper" || die "Shell syntax check failed: $helper"
done
grep -Fq 'ExcludeNodes {us}' "$SRC/S1T-CAPSULE/tor.go"
! grep -Fq 'ExcludeNodes {us},{??}' "$SRC/S1T-CAPSULE/tor.go"
grep -Fq 'Tor Snowflake (automatic; no bridge input required)' "$SRC/S1T-CAPSULE/main.go"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH_NAME="amd64" ;;
  aarch64|arm64) GOARCH_NAME="arm64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
GOROOT_PATH="/usr/local/lib/shah-tunnel/toolchains/go1.26.1-${GOARCH_NAME}"
if [[ -x "$GOROOT_PATH/bin/go" ]]; then
  log "Running Go tests with the installed verified Go 1.26.1 toolchain"
  (cd "$SRC" && env GOROOT="$GOROOT_PATH" GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH_NAME" "$GOROOT_PATH/bin/go" test ./...)
else
  log "Go 1.26.1 cache not found; the official installer will obtain the pinned toolchain and perform the build."
fi

log "Building and installing the repaired manager with the official installer"
# S1T-START.sh detects the patched source beside itself and builds that source,
# instead of downloading the unpatched main branch again.
bash "$SRC/S1T-START.sh"
