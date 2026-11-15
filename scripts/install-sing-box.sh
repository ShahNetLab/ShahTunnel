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

curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: ShahTunnel-sing-box-installer' \
  "$API" -o "$TMP/release.json"

readarray -t META < <(python3 - "$TMP/release.json" "$ASSET" <<'PY'
import json, re, sys
obj=json.load(open(sys.argv[1], encoding='utf-8'))
name=sys.argv[2]
for asset in obj.get('assets', []):
    if asset.get('name') == name:
        digest=asset.get('digest', '')
        url=asset.get('browser_download_url', '')
        if not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', digest):
            raise SystemExit('Release asset does not expose a valid SHA-256 digest; refusing unverified install')
        expected_prefix=f'https://github.com/SagerNet/sing-box/releases/download/v{obj.get("tag_name", "")}/'
        if obj.get('tag_name') != 'v1.14.4' or not url.startswith(expected_prefix) or url.rsplit('/', 1)[-1] != name:
            raise SystemExit('Release asset URL is not the expected official pinned sing-box release; refusing install')
        print(url)
        print(digest.split(':',1)[1])
        break
else:
    raise SystemExit(f'Official release asset not found: {name}')
PY
)
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
