#!/usr/bin/env bash
set -Eeuo pipefail

# ShahTunnel Tor executable-selection repair.
# Downloads the current main branch, patches the Tor binary selector and its
# pinned installer, then rebuilds/reinstalls through the project's own installer.
# Existing tunnel profiles, X-UI configuration, routes, firewall and SSH are kept.

OWNER="ShahNetLab"
REPO="ShahTunnel"
BRANCH="main"
ARCHIVE_URL="https://codeload.github.com/${OWNER}/${REPO}/tar.gz/refs/heads/${BRANCH}"
STATE_DIR="/usr/local/lib/shah-tunnel"

log() { printf '\n[SHAH-TOR-EXEC-FIX] %s\n' "$*"; }
die() { printf '\n[SHAH-TOR-EXEC-FIX] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "Run as root."
for cmd in curl tar python3 bash sha256sum systemctl find awk grep; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required command is missing: $cmd"
done

case "$(uname -m)" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *) die "Unsupported architecture: $(uname -m). ShahTunnel supports Linux amd64/arm64." ;;
esac

WORK="$(mktemp -d /tmp/shah-tor-exec-fix.XXXXXX)"
chmod 0700 "$WORK"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
SRC="$WORK/source"
mkdir -p "$SRC"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -s "$SCRIPT_DIR/S1T-CAPSULE/tor.go" && -s "$SCRIPT_DIR/S1T-START.sh" ]]; then
  log "Using the ShahTunnel source checkout beside this repair script"
  cp -a "$SCRIPT_DIR"/. "$SRC"/
else
  log "Downloading the current ShahTunnel source from ${OWNER}/${REPO}:${BRANCH}"
  curl -fL --proto '=https' --proto-redir '=https' \
  --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 240 \
  "$ARCHIVE_URL" -o "$WORK/source.tar.gz" \
  || die "Could not download the current ShahTunnel source archive. No installed files were changed."
tar -tzf "$WORK/source.tar.gz" >/dev/null 2>&1 || die "The downloaded GitHub archive is not a valid tar.gz file."
tar -xzf "$WORK/source.tar.gz" -C "$SRC" --strip-components=1
fi

TOR_GO="$(find "$SRC" -type f -path '*/S1T-CAPSULE/tor.go' -print -quit)"
TOR_INSTALLER="$(find "$SRC" -type f -name install-tor.sh -print -quit)"
START_SCRIPT="$(find "$SRC" -maxdepth 3 -type f -name S1T-START.sh -print -quit)"
[[ -n "$TOR_GO" && -n "$TOR_INSTALLER" && -n "$START_SCRIPT" ]] \
  || die "The downloaded source layout does not match ShahTunnel (tor.go/install-tor.sh/S1T-START.sh not found)."

log "Patching the Tor daemon/transport selector and the official bundle installer"
python3 - "$TOR_GO" "$TOR_INSTALLER" <<'PY'
from pathlib import Path
import re
import sys

tor_go_path = Path(sys.argv[1])
installer_path = Path(sys.argv[2])
source = tor_go_path.read_text(encoding="utf-8")
installer = installer_path.read_text(encoding="utf-8")

# Derive the existing official version and pinned checksums rather than silently
# changing the Tor release or weakening integrity verification.
version_match = re.search(r'^TOR_VERSION="([^"]+)"', installer, re.M)
if not version_match:
    raise SystemExit("Cannot locate pinned TOR_VERSION in install-tor.sh; refusing to modify source.")
tor_version = version_match.group(1)

def checksum_for(pattern: str) -> str:
    match = re.search(pattern, installer, re.S)
    if not match:
        raise SystemExit("Cannot locate the pinned Tor SHA-256 for both Linux architectures; refusing to weaken verification.")
    value = match.group(1).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit("Pinned Tor checksum has an invalid format.")
    return value

amd64_sha = checksum_for(r'x86_64\|amd64\)\s*ARCHIVE=.*?EXPECTED_SHA256="([0-9a-fA-F]{64})"')
arm64_sha = checksum_for(r'aarch64\|arm64\)\s*ARCHIVE=.*?EXPECTED_SHA256="([0-9a-fA-F]{64})"')

# ELF header architecture validation. This rejects executable-marked debug files,
# wrong-CPU binaries, HTML/error payloads, scripts and corrupted files.
if '"debug/elf"' not in source:
    source = source.replace('import (\n', 'import (\n\t"debug/elf"\n', 1)
if '"runtime"' not in source:
    source = source.replace('import (\n', 'import (\n\t"runtime"\n', 1)

exec_re = re.compile(r'func executableFile\(path string\) bool \{.*?\n\}', re.S)
exec_replacement = r'''func isNativeTorELF(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 {
		return false
	}
	switch runtime.GOARCH {
	case "amd64":
		return f.Machine == elf.EM_X86_64
	case "arm64":
		return f.Machine == elf.EM_AARCH64
	default:
		return false
	}
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 && isNativeTorELF(path)
}'''
source, n = exec_re.subn(lambda _: exec_replacement, source, count=1)
if n != 1:
    raise SystemExit("Could not patch executableFile in tor.go; source was left unchanged.")

walk_re = re.compile(r'func findExecutableInTree\(root, name string\) string \{.*?\n\}', re.S)
walk_replacement = r'''func findExecutableInTree(root, name string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if entry.IsDir() {
			// The official Tor Expert Bundle also contains debug/tor. It is not
			// the runtime daemon; never select anything from a debug tree.
			if strings.EqualFold(entry.Name(), "debug") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != name || !executableFile(path) {
			return nil
		}
		found = path
		return filepath.SkipAll
	})
	return found
}'''
source, n = walk_re.subn(lambda _: walk_replacement, source, count=1)
if n != 1:
    raise SystemExit("Could not patch findExecutableInTree in tor.go; source was left unchanged.")

locate_re = re.compile(r'func locateTorBinaries\(\) \(string, string\) \{.*?\n\}', re.S)
locate_replacement = r'''func locateTorBinaries() (string, string) {
	// Prefer the runtime files in the official Expert Bundle. Its separate
	// debug/ directory may also contain an executable named "tor".
	torCandidates := []string{
		filepath.Join(torBundleRoot, "tor", "tor"),
		filepath.Join(torBundleRoot, "extract", "tor", "tor"),
	}
	ptCandidates := []string{
		filepath.Join(torBundleRoot, "tor", "pluggable_transports", "lyrebird"),
		filepath.Join(torBundleRoot, "extract", "tor", "pluggable_transports", "lyrebird"),
		filepath.Join(torBundleRoot, "pluggable_transports", "lyrebird"),
	}
	var torBinary, ptBinary string
	for _, candidate := range torCandidates {
		if executableFile(candidate) {
			torBinary = candidate
			break
		}
	}
	for _, candidate := range ptCandidates {
		if executableFile(candidate) {
			ptBinary = candidate
			break
		}
	}
	if torBinary == "" {
		torBinary = findExecutableInTree(torBundleRoot, "tor")
	}
	if ptBinary == "" {
		ptBinary = findExecutableInTree(torBundleRoot, "lyrebird")
	}
	if torBinary == "" {
		torBinary, _ = exec.LookPath("tor")
	}
	if ptBinary == "" {
		ptBinary, _ = exec.LookPath("lyrebird")
	}
	if !executableFile(torBinary) || !executableFile(ptBinary) || !canRunTorBinary(torBinary) {
		return "", ""
	}
	return torBinary, ptBinary
}

func canRunTorBinary(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "LD_LIBRARY_PATH=") {
			env = append(env, item)
		}
	}
	dir := filepath.Dir(path)
	libPaths := []string{dir, filepath.Join(dir, "lib"), filepath.Join(filepath.Dir(dir), "lib")}
	if existing := strings.TrimSpace(os.Getenv("LD_LIBRARY_PATH")); existing != "" {
		libPaths = append(libPaths, strings.Split(existing, string(os.PathListSeparator))...)
	}
	cmd.Env = append(env, "LD_LIBRARY_PATH="+strings.Join(libPaths, string(os.PathListSeparator)))
	output, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(output), "Tor ")
}'''
source, n = locate_re.subn(lambda _: locate_replacement, source, count=1)
if n != 1:
    raise SystemExit("Could not patch locateTorBinaries in tor.go; source was left unchanged.")

run_re = re.compile(r'func canRunTorBinary\(path string\) bool \{.*?\n\}', re.S)
run_replacement = r'''func canRunTorBinary(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "LD_LIBRARY_PATH=") {
			env = append(env, item)
		}
	}
	dir := filepath.Dir(path)
	libPaths := []string{dir, filepath.Join(dir, "lib"), filepath.Join(filepath.Dir(dir), "lib")}
	if existing := strings.TrimSpace(os.Getenv("LD_LIBRARY_PATH")); existing != "" {
		libPaths = append(libPaths, strings.Split(existing, string(os.PathListSeparator))...)
	}
	cmd.Env = append(env, "LD_LIBRARY_PATH="+strings.Join(libPaths, string(os.PathListSeparator)))
	output, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(output), "Tor ")
}'''
source, n = run_re.subn(lambda _: run_replacement, source, count=1)
if n != 1:
    raise SystemExit("Could not patch canRunTorBinary in tor.go; source was left unchanged.")

old_tor_env = '''	if strings.HasPrefix(filepath.Clean(cfg.TorBinary), torBundleRoot+string(os.PathSeparator)) || filepath.Clean(filepath.Dir(cfg.TorBinary)) == torBundleRoot {
		paths = append(paths, filepath.Dir(cfg.TorBinary))
	}
	if strings.HasPrefix(filepath.Clean(cfg.TorPTBinary), torBundleRoot+string(os.PathSeparator)) || filepath.Clean(filepath.Dir(cfg.TorPTBinary)) == torBundleRoot {
		paths = append(paths, filepath.Dir(cfg.TorPTBinary))
	}'''
new_tor_env = '''	if strings.HasPrefix(filepath.Clean(cfg.TorBinary), torBundleRoot+string(os.PathSeparator)) || filepath.Clean(filepath.Dir(cfg.TorBinary)) == torBundleRoot {
		dir := filepath.Dir(cfg.TorBinary)
		paths = append(paths, dir, filepath.Join(dir, "lib"), filepath.Join(filepath.Dir(dir), "lib"))
	}
	if strings.HasPrefix(filepath.Clean(cfg.TorPTBinary), torBundleRoot+string(os.PathSeparator)) || filepath.Clean(filepath.Dir(cfg.TorPTBinary)) == torBundleRoot {
		dir := filepath.Dir(cfg.TorPTBinary)
		paths = append(paths, dir, filepath.Join(dir, "lib"), filepath.Join(filepath.Dir(dir), "lib"))
	}'''
if old_tor_env not in source:
    raise SystemExit("Could not patch Tor runtime library paths; source was left unchanged.")
source = source.replace(old_tor_env, new_tor_env, 1)

# Existing profiles store the bad debug/tor path in their JSON. On every Agent
# startup resolve a native runtime binary again and replace those stale paths in
# memory before validating torrc and launching Tor.
needle = '''func startTorForAgent(cfg Config) (func(), error) {
	if cfg.Underlay != underlayTor {
		return func() {}, nil
	}
'''
replacement = needle + '''	torBinary, ptBinary, err := ensureTorBinaries()
	if err != nil {
		return nil, fmt.Errorf("resolve a native Tor Expert Bundle for this server: %w", err)
	}
	cfg.TorBinary = torBinary
	cfg.TorPTBinary = ptBinary
'''
if needle not in source:
    raise SystemExit("Could not patch startTorForAgent; source was left unchanged.")
source = source.replace(needle, replacement, 1)

# The patched selector must not accept a plain executable script or an ELF from
# another CPU architecture. Keep the source's existing package layout untouched.
tor_go_path.write_text(source, encoding="utf-8")

# Rebuild installer using the repository's existing pinned Tor release/checksums.
# It selects tor/tor + tor/pluggable_transports/lyrebird, excludes debug/, validates
# ELF machine IDs and executes tor --version before it installs anything.
new_installer = r'''#!/usr/bin/env bash
set -Eeuo pipefail

STATE_DIR="/usr/local/lib/shah-tunnel"
BUNDLE_DIR="${STATE_DIR}/tor-bundle"
TOR_VERSION="__TOR_VERSION__"
BASE_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}"

fail() { echo "Tor installer: $*" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run as root."
for cmd in curl sha256sum tar find install mv rm mktemp chmod cp chown mkdir grep python3 timeout; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

case "$(uname -m)" in
  x86_64|amd64)
    ARCHIVE="tor-expert-bundle-linux-x86_64-${TOR_VERSION}.tar.gz"
    EXPECTED_SHA256="__AMD64_SHA__"
    ELF_MACHINE=62
    ;;
  aarch64|arm64)
    ARCHIVE="tor-expert-bundle-linux-aarch64-${TOR_VERSION}.tar.gz"
    EXPECTED_SHA256="__ARM64_SHA__"
    ELF_MACHINE=183
    ;;
  *) fail "unsupported CPU architecture: $(uname -m); supported: amd64 and arm64." ;;
esac

is_native_elf() {
  python3 - "$1" "$ELF_MACHINE" <<'PYELF'
import struct, sys
try:
    with open(sys.argv[1], "rb") as f:
        h = f.read(20)
    if len(h) < 20 or h[:4] != b"\x7fELF" or h[4] != 2:
        raise SystemExit(1)
    endian = "<" if h[5] == 1 else ">" if h[5] == 2 else None
    if endian is None:
        raise SystemExit(1)
    machine = struct.unpack(endian + "H", h[18:20])[0]
    raise SystemExit(0 if machine == int(sys.argv[2]) else 1)
except (OSError, ValueError, IndexError, struct.error):
    raise SystemExit(1)
PYELF
}

is_native_tor() {
  local candidate="$1" output
  [[ -f "$candidate" && -x "$candidate" ]] || return 1
  is_native_elf "$candidate" || return 1
  output="$(LD_LIBRARY_PATH="$(dirname "$candidate")" timeout --kill-after=1s 8s "$candidate" --version 2>&1)" || return 1
  grep -qi '^Tor ' <<<"$output"
}

select_bundle_binaries() {
  local root="$1" candidate
  TOR_BIN=""
  LYREBIRD_BIN=""
  for candidate in \
    "$root/tor/tor" \
    "$root/extract/tor/tor"; do
    if is_native_tor "$candidate"; then TOR_BIN="$candidate"; break; fi
  done
  if [[ -z "$TOR_BIN" ]]; then
    while IFS= read -r candidate; do
      [[ "$candidate" == */debug/* ]] && continue
      if is_native_tor "$candidate"; then TOR_BIN="$candidate"; break; fi
    done < <(find "$root" -type f -name tor -perm /111 -print 2>/dev/null | sort)
  fi

  for candidate in \
    "$root/tor/pluggable_transports/lyrebird" \
    "$root/extract/tor/pluggable_transports/lyrebird" \
    "$root/pluggable_transports/lyrebird"; do
    if [[ -f "$candidate" && -x "$candidate" ]] && is_native_elf "$candidate"; then
      LYREBIRD_BIN="$candidate"; break
    fi
  done
  if [[ -z "$LYREBIRD_BIN" ]]; then
    while IFS= read -r candidate; do
      [[ "$candidate" == */debug/* ]] && continue
      if is_native_elf "$candidate"; then LYREBIRD_BIN="$candidate"; break; fi
    done < <(find "$root" -type f -name lyrebird -perm /111 -print 2>/dev/null | sort)
  fi
  [[ -n "$TOR_BIN" && -n "$LYREBIRD_BIN" ]]
}

# Reuse only a bundle that matches this CPU and whose runtime Tor actually starts.
if grep -Fxq "version=${TOR_VERSION}" "${STATE_DIR}/tor-bundle.info" 2>/dev/null && \
   grep -Fxq "architecture=$(uname -m)" "${STATE_DIR}/tor-bundle.info" 2>/dev/null && \
   select_bundle_binaries "$BUNDLE_DIR"; then
  echo "Official Tor Expert Bundle ${TOR_VERSION} is already installed and native (${TARGET_ARCH:-$(uname -m)})."
  exit 0
fi

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
  || fail "could not download the official Tor Expert Bundle."
printf '%s  %s\n' "$EXPECTED_SHA256" "$ARCHIVE_PATH" | sha256sum -c - \
  || fail "Tor Expert Bundle SHA-256 mismatch; refusing to install the archive."
tar -tzf "$ARCHIVE_PATH" >/dev/null 2>&1 || fail "downloaded Tor Expert Bundle is not a valid tar.gz archive."
tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR" || fail "could not extract Tor Expert Bundle."
select_bundle_binaries "$EXTRACT_DIR" || fail "no native runtime tor/lyrebird pair was found (debug binaries are excluded)."

install -d -o root -g root -m 0755 "$STATE_DIR"
NEW_DIR="${STATE_DIR}/tor-bundle.new.$$"
BACKUP_DIR="${STATE_DIR}/tor-bundle.backup.$$"
rm -rf -- "$NEW_DIR" "$BACKUP_DIR"
mkdir -p "$NEW_DIR"
cp -a "$EXTRACT_DIR"/. "$NEW_DIR"/
chown -R root:root "$NEW_DIR"
find "$NEW_DIR" -type d -exec chmod 0755 {} +
find "$NEW_DIR" -type f -perm /111 -exec chmod 0755 {} +
find "$NEW_DIR" -type f ! -perm /111 -exec chmod 0644 {} +

# Re-evaluate paths inside the staged layout, then verify both CPU and Tor version.
select_bundle_binaries "$NEW_DIR" || fail "staged Tor binaries failed native architecture validation."
is_native_tor "$TOR_BIN" || fail "staged Tor daemon did not pass its --version execution check."
TOR_REL="${TOR_BIN#"$NEW_DIR"/}"
PT_REL="${LYREBIRD_BIN#"$NEW_DIR"/}"
[[ "$TOR_REL" != "$TOR_BIN" && "$PT_REL" != "$LYREBIRD_BIN" ]] || fail "staged Tor paths escaped the private bundle."

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
lyrebird=${BUNDLE_DIR}/${PT_REL}
INFO
chmod 0644 "${STATE_DIR}/tor-bundle.info"
# Final post-install execution check; rollback is intentionally not attempted here
# because the atomic directory swap already completed with verified staged files.
is_native_tor "${BUNDLE_DIR}/${TOR_REL}" || fail "installed Tor binary failed its final --version check."
echo "Official Tor Expert Bundle ${TOR_VERSION} installed; native ELF architecture and Tor execution verified."
'''
new_installer = new_installer.replace("__TOR_VERSION__", tor_version).replace("__AMD64_SHA__", amd64_sha).replace("__ARM64_SHA__", arm64_sha)
installer_path.write_text(new_installer, encoding="utf-8")
installer_path.chmod(0o755)

# Add narrowly scoped regression tests (no live network or Tor daemon required).
test_path = tor_go_path.with_name("tor_test.go")
if test_path.exists():
    tests = test_path.read_text(encoding="utf-8")
    if '"os"' not in tests:
        tests = tests.replace('import (\n', 'import (\n\t"os"\n', 1)
    if 'func TestFindExecutableInTreeSkipsDebugDirectory' not in tests:
        tests += r'''

func TestFindExecutableInTreeSkipsDebugDirectory(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	debugDir := filepath.Join(root, "debug")
	runtimeDir := filepath.Join(root, "tor")
	if err := os.MkdirAll(debugDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(debugDir, "tor")); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(runtimeDir, "tor")
	if err := os.Symlink(executable, want); err != nil {
		t.Fatal(err)
	}
	if got := findExecutableInTree(root, "tor"); got != want {
		t.Fatalf("findExecutableInTree() = %q, want runtime daemon %q", got, want)
	}
}

func TestExecutableFileRejectsNonELFExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-tor")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho fake\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if executableFile(path) {
		t.Fatal("executableFile accepted a script instead of a native Linux ELF binary")
	}
}
'''
        # filepath is used by the new tests.
        if '"path/filepath"' not in tests:
            tests = tests.replace('import (\n', 'import (\n\t"path/filepath"\n', 1)
        old_env_expectation = 'if !strings.Contains(env, "LD_LIBRARY_PATH="+torBundleRoot+"/tor:"+torBundleRoot+"/tor/pluggable_transports:/custom/lib") {'
        new_env_expectation = 'expected := "LD_LIBRARY_PATH="+torBundleRoot+"/tor:"+torBundleRoot+"/tor/lib:"+torBundleRoot+"/lib:"+torBundleRoot+"/tor/pluggable_transports:"+torBundleRoot+"/tor/pluggable_transports/lib:/custom/lib"\n\tif !strings.Contains(env, expected) {'
        tests = tests.replace(old_env_expectation, new_env_expectation, 1)
        test_path.write_text(tests, encoding="utf-8")
PY

# Suppress the normal interactive menu only for this unattended repair run.
# S1T-START.sh otherwise execs into the menu and prevents this wrapper from
# restarting the affected Tor profile and checking its state.
python3 - "$START_SCRIPT" <<'PYMENU'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text(encoding="utf-8")
needle = "exec /usr/local/bin/shah-tunnel menu"
if needle not in s:
    raise SystemExit("Could not safely locate S1T-START.sh final menu handoff; refusing unattended upgrade.")
replacement = 'if [[ "${SHAH_TOR_FIX_SUPPRESS_MENU:-0}" != "1" ]]; then\n  exec /usr/local/bin/shah-tunnel menu\nfi\nexit 0'
s = s.replace(needle, replacement, 1)

# Avoid the stock upgrader restarting unrelated Psiphon/Adaptive or legacy
# single-profile services; this repair restarts only profiles using Tor.
psi_needle = 'restart_active_psiphon_agent() {\n  local unit="$1" config="$2"\n'
if psi_needle not in s:
    raise SystemExit("Could not safely isolate the standard Psiphon restart hook.")
psi_replace = psi_needle + '  [[ "${SHAH_TOR_FIX_TOR_ONLY_RESTART:-0}" != "1" ]] || return 0\n'
s = s.replace(psi_needle, psi_replace, 1)
legacy_needle = 'if [[ -f /etc/ravanreverse/config.json ]]; then'
legacy_replace = 'if [[ -f /etc/ravanreverse/config.json && "${SHAH_TOR_FIX_TOR_ONLY_RESTART:-0}" != "1" ]]; then'
if legacy_needle not in s:
    raise SystemExit("Could not safely isolate the legacy single-profile service start.")
s = s.replace(legacy_needle, legacy_replace, 1)
p.write_text(s, encoding="utf-8")
PYMENU

log "Running syntax and patch-integrity checks"
bash -n "$START_SCRIPT"
bash -n "$TOR_INSTALLER"
grep -Fq 'debug/elf' "$TOR_GO" || die "ELF architecture validation was not installed."
grep -Fq 'pluggable_transports' "$TOR_GO" || die "Preferred runtime Lyrebird path was not installed."
grep -Fq 'canRunTorBinary' "$TOR_GO" || die "Tor runtime execution validation was not installed."
grep -Fq 'filepath.SkipDir' "$TOR_GO" || die "Debug directory exclusion was not installed."

if [[ -n "${SHAH_TOR_PATCH_OUTPUT_DIR:-}" ]]; then
  mkdir -p "$SHAH_TOR_PATCH_OUTPUT_DIR"
  cp -a "$SRC"/. "$SHAH_TOR_PATCH_OUTPUT_DIR"/
fi

# The official installer detects and installs its own pinned Go toolchain. Running it
# from the patched source directory makes it compile this exact source revision.
if [[ "${SHAH_TOR_FIX_PATCH_ONLY:-0}" == "1" ]]; then
  log "Patch-only mode: source changes are complete; build/install was intentionally skipped."
  exit 0
fi

log "Building and installing patched ShahTunnel using its official installer"
SHAH_TOR_FIX_SUPPRESS_MENU=1 SHAH_TOR_FIX_TOR_ONLY_RESTART=1 bash "$START_SCRIPT"

# Clear systemd's rate-limit state and restart only Tor-backed profiles.
mapfile -t TOR_PROFILES < <(python3 - "$SRC" <<'PYPROFILES'
# Profile names are read from the live system, not from source files.
import glob, json, os, sys
for path in sorted(glob.glob('/etc/ravanreverse/tunnels/*.json')):
    try:
        with open(path, encoding='utf-8') as f:
            cfg = json.load(f)
        if cfg.get('role') == 'agent' and str(cfg.get('underlay','')).lower() in ('tor_socks5', 'tor'):
            print(os.path.splitext(os.path.basename(path))[0])
    except (OSError, ValueError, TypeError):
        continue
PYPROFILES
)

if ((${#TOR_PROFILES[@]} == 0)); then
  log "No saved Tor Agent profiles were found. The source and installer fix is installed; no tunnel services were restarted."
  exit 0
fi

for profile in "${TOR_PROFILES[@]}"; do
  service="ravanreverse@${profile}.service"
  log "Restarting Tor-backed Agent profile ${profile}"
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl restart "$service" || {
    echo "Agent service failed after the source repair; recent logs:" >&2
    journalctl -u "$service" -n 60 --no-pager >&2 || true
    die "Profile ${profile} did not start. The updated executable and Tor installer remain installed."
  }
  systemctl is-active --quiet "$service" || {
    journalctl -u "$service" -n 60 --no-pager >&2 || true
    die "Profile ${profile} is not active after restart."
  }
  xray_service="shah-tunnel-xray-tor-${profile}.service"
  if systemctl list-unit-files "$xray_service" --no-legend 2>/dev/null | grep -q "$xray_service"; then
    systemctl restart "$xray_service" || log "Warning: $xray_service could not be restarted; check its journal separately."
  fi
done

log "Repair completed. Tor binary selection now excludes debug/, validates native ELF architecture, and re-resolves stale paths at Agent startup."
log "Check the service journal for 'Bootstrapped 100%' and connected Hub lanes before treating the tunnel as ready."
