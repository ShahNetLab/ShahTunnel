#!/usr/bin/env bash
set -Eeuo pipefail

# Repair ShahTunnel REALITY handshake by rebuilding the current official source.
# Run as root on BOTH the Hub and the Agent. Existing config is preserved.

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: run as root (sudo -i)" >&2
  exit 1
fi
for cmd in curl systemctl install cp date sha256sum sleep; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing command: $cmd" >&2; exit 1; }
done
[[ -s /etc/ravanreverse/config.json ]] || { echo "ERROR: /etc/ravanreverse/config.json not found; this does not look like an installed ShahTunnel server." >&2; exit 1; }
[[ -x /usr/local/bin/ravanreverse ]] || { echo "ERROR: /usr/local/bin/ravanreverse not found." >&2; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/shah-reality-fix-${STAMP}"
install -d -m 0700 "$BACKUP_DIR"
cp -a /etc/ravanreverse/config.json "$BACKUP_DIR/config.json"
cp -a /usr/local/bin/ravanreverse "$BACKUP_DIR/ravanreverse.before"
chmod 0600 "$BACKUP_DIR/config.json" "$BACKUP_DIR/ravanreverse.before"
OLD_SUM="$(sha256sum /usr/local/bin/ravanreverse | awk '{print $1}')"
OLD_VERSION="$(/usr/local/bin/ravanreverse version 2>/dev/null || true)"

TMP_SCRIPT="$(mktemp /tmp/s1t-start.XXXXXX.sh)"
cleanup() { rm -f "$TMP_SCRIPT"; }
trap cleanup EXIT

echo "=== ShahTunnel REALITY repair ==="
echo "Old binary: ${OLD_VERSION:-unknown}"
echo "Backup: $BACKUP_DIR"
echo "Config will be preserved; secrets are not printed."
echo "Downloading the official installer/source..."
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh \
  -o "$TMP_SCRIPT"
chmod 0700 "$TMP_SCRIPT"

# The official installer opens its menu after installing. Feed option 0 so it
# exits cleanly, then restart the existing service with the rebuilt binary.
if ! bash "$TMP_SCRIPT" <<< '0'; then
  echo "ERROR: official installer failed; see messages above." >&2
  echo "Your previous binary and config backup are at: $BACKUP_DIR" >&2
  exit 1
fi

NEW_SUM="$(sha256sum /usr/local/bin/ravanreverse | awk '{print $1}')"
if [[ "$OLD_SUM" == "$NEW_SUM" ]]; then
  echo "WARNING: installed binary hash is unchanged; source may not have updated." >&2
fi

echo "Restarting ravanreverse..."
systemctl restart ravanreverse
sleep 3

if ! systemctl is-active --quiet ravanreverse; then
  echo "ERROR: service is not active after update." >&2
  systemctl --no-pager --full status ravanreverse || true
  journalctl -u ravanreverse -n 50 --no-pager || true
  echo "Backup: $BACKUP_DIR" >&2
  exit 1
fi

echo "=== RESULT ==="
/usr/local/bin/ravanreverse version || true
systemctl is-active ravanreverse
echo "Binary SHA-256: $NEW_SUM"
echo "=== Runtime (if available) ==="
if [[ -r /etc/ravanreverse/runtime.json ]]; then cat /etc/ravanreverse/runtime.json; else echo "runtime.json not present yet"; fi
echo
echo "=== Recent service logs ==="
journalctl -u ravanreverse --since "45 seconds ago" --no-pager | tail -n 30
echo
echo "Finished. Run this same script on the other server too. Config backup: $BACKUP_DIR"
