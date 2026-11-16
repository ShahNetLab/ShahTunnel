#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ "$(id -u)" -eq 0 ]] || { echo "Run this installer as root." >&2; exit 1; }

VERSION="1.14.4"
REPO="SagerNet/sing-box"
BIN="/usr/local/bin/sing-box"
TMP="$(mktemp -d /tmp/shah-sing-box.XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

for cmd in curl python3 tar sha256sum install; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }
done

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac
ASSET="sing-box-${VERSION}-linux-${ARCH}.tar.gz"
API="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION}"

if [[ -x "$BIN" ]] && "$BIN" version 2>&1 | grep -Fq "sing-box version ${VERSION}"; then
  echo "Verified sing-box ${VERSION} is already installed at ${BIN}; nothing to do."
  exit 0
fi

curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: ShahTunnel-sing-box-installer' \
  "$API" -o "$TMP/release.json"

# The release API's tag_name already includes the leading "v". Construct
# the canonical download URL from the verified repository, tag and exact asset
# name instead of prefixing another "v" or trusting browser_download_url.
if ! python3 - "$TMP/release.json" "$ASSET" "$VERSION" "$REPO" > "$TMP/asset.meta" <<'PY'
import json, re, sys

json_path, wanted_name, version, repository = sys.argv[1:]
try:
    with open(json_path, encoding="utf-8") as handle:
        release = json.load(handle)
except Exception as exc:
    raise SystemExit(f"Invalid GitHub release metadata: {exc}")

expected_tag = f"v{version}"
actual_tag = release.get("tag_name", "")
if actual_tag != expected_tag:
    raise SystemExit(f"Unexpected sing-box release tag {actual_tag!r}; expected {expected_tag!r}")

matches = [asset for asset in release.get("assets", []) if asset.get("name") == wanted_name]
if len(matches) != 1:
    raise SystemExit(f"Expected exactly one official asset {wanted_name!r}; found {len(matches)}")

asset = matches[0]
digest = asset.get("digest", "")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
    raise SystemExit("Official release metadata has no valid SHA-256 digest; refusing unverified install")
if asset.get("state") not in (None, "uploaded"):
    raise SystemExit(f"Official release asset is not uploaded: {asset.get('state')!r}")

url = f"https://github.com/{repository}/releases/download/{expected_tag}/{wanted_name}"
print(url)
print(digest.split(":", 1)[1].lower())
PY
then
  echo "Could not resolve the uniquely named, SHA-256 verified official sing-box release asset." >&2
  exit 1
fi
mapfile -t META < "$TMP/asset.meta"
[[ "${#META[@]}" -eq 2 ]] || { echo "Could not resolve the verified sing-box release asset." >&2; exit 1; }
URL="${META[0]}"
EXPECTED="${META[1]}"

curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
  -H 'User-Agent: ShahTunnel-sing-box-installer' \
  "$URL" -o "$TMP/sing-box.tar.gz"
ACTUAL="$(sha256sum "$TMP/sing-box.tar.gz" | awk '{print $1}')"
[[ "$ACTUAL" == "$EXPECTED" ]] || { echo "sing-box archive SHA-256 mismatch; refusing installation." >&2; exit 1; }

tar -xzf "$TMP/sing-box.tar.gz" -C "$TMP"
SOURCE="$(find "$TMP" -type f -name sing-box -perm /111 -print -quit)"
[[ -n "$SOURCE" ]] || { echo "sing-box executable was not found in the verified archive." >&2; exit 1; }
install -o root -g root -m 0755 "$SOURCE" "${BIN}.new"
if ! "${BIN}.new" version 2>&1 | grep -Fq "$VERSION"; then
  rm -f "${BIN}.new"
  echo "Installed sing-box binary reported an unexpected version." >&2
  exit 1
fi
mv -f "${BIN}.new" "$BIN"
echo "Verified sing-box ${VERSION} installed at ${BIN} (${ARCH}, SHA-256 verified)."
