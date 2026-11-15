#!/usr/bin/env bash
# ShahTunnel: verified sing-box installer (fixed asset URL handling)
# Installs only the pinned official sing-box binary; does not alter ShahTunnel routes/services.
set -Eeuo pipefail
umask 077

VERSION="1.14.4"
REPO="SagerNet/sing-box"
BIN="/usr/local/bin/sing-box"
API="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION}"
TMP="$(mktemp -d /tmp/shah-sing-box.XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || fail "Run this installer as root."

for cmd in curl python3 tar sha256sum install awk find grep uname; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
done

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) fail "Unsupported CPU architecture: $(uname -m)" ;;
esac

ASSET="sing-box-${VERSION}-linux-${ARCH}.tar.gz"

printf 'Fetching official %s release metadata...\n' "$VERSION"
curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 90 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: ShahTunnel-sing-box-installer' \
  "$API" -o "$TMP/release.json" || fail "Could not download official GitHub release metadata. Check DNS/network and retry."

# Resolve the official asset digest from the GitHub API. Build the canonical URL
# from the pinned repository/tag/name instead of trusting browser_download_url,
# whose formatting can vary and caused the old helper to reject a valid asset.
python3 - "$TMP/release.json" "$ASSET" "$VERSION" <<'PY' > "$TMP/asset.meta" || exit 1
import json, re, sys
from pathlib import PurePosixPath

json_path, wanted_name, version = sys.argv[1:]
try:
    with open(json_path, encoding="utf-8") as f:
        obj = json.load(f)
except Exception as exc:
    raise SystemExit(f"Invalid GitHub release JSON: {exc}")

tag = obj.get("tag_name", "")
if tag not in (f"v{version}", version):
    raise SystemExit(f"Unexpected official release tag: {tag!r}")

matches = [a for a in obj.get("assets", []) if a.get("name") == wanted_name]
if len(matches) != 1:
    raise SystemExit(f"Expected exactly one official release asset {wanted_name!r}; found {len(matches)}")

asset = matches[0]
digest = asset.get("digest", "")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
    raise SystemExit("GitHub release metadata has no valid SHA-256 digest; refusing unverified install")

# Only the fixed, official project/release location is allowed.
url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{wanted_name}"
print(url)
print(digest.split(":", 1)[1].lower())
PY

mapfile -t META < "$TMP/asset.meta"
[[ "${#META[@]}" -eq 2 ]] || fail "Could not resolve a uniquely named, SHA-256 verified official release asset."
URL="${META[0]}"
EXPECTED="${META[1]}"

printf 'Downloading %s...\n' "$ASSET"
curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
  -H 'User-Agent: ShahTunnel-sing-box-installer' \
  "$URL" -o "$TMP/sing-box.tar.gz" || fail "Official sing-box asset download failed."

ACTUAL="$(sha256sum "$TMP/sing-box.tar.gz" | awk '{print $1}')"
[[ "$ACTUAL" == "$EXPECTED" ]] || fail "SHA-256 mismatch. Expected $EXPECTED; got $ACTUAL. Refusing installation."
printf 'SHA-256 verified: %s\n' "$ACTUAL"

tar -xzf "$TMP/sing-box.tar.gz" -C "$TMP" || fail "Downloaded archive is not a valid gzip tar archive."
SOURCE="$(find "$TMP" -type f -name sing-box -perm /111 -print -quit)"
[[ -n "$SOURCE" ]] || fail "sing-box executable was not found in the verified archive."

install -d -o root -g root -m 0755 /usr/local/bin
install -o root -g root -m 0755 "$SOURCE" "${BIN}.new"
if ! "${BIN}.new" version 2>&1 | grep -Fq "$VERSION"; then
  rm -f "${BIN}.new"
  fail "Downloaded binary reported an unexpected version."
fi
mv -f "${BIN}.new" "$BIN"

printf '\nSUCCESS: verified sing-box %s installed at %s (%s).\n' "$VERSION" "$BIN" "$ARCH"
"$BIN" version
