#!/usr/bin/env bash
set -Eeuo pipefail

# Rebuild ShahTunnel from THIS extracted project directory. Do not download a
# different source tree during repair. Run as root on both Hub and Agent.

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: run as root (sudo -i)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for cmd in bash systemctl install cp date sha256sum sleep journalctl; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: required command missing: $cmd" >&2
    exit 1
  }
done

# Refuse to build if the supplied source does not include the intended fix.
[[ -s "$SCRIPT_DIR/S1T-START.sh" && -s "$SCRIPT_DIR/go.mod" && \
   -s "$SCRIPT_DIR/S1T-CAPSULE/main.go" && \
   -s "$SCRIPT_DIR/S1T-CAPSULE/reality_transport.go" && \
   -s "$SCRIPT_DIR/S1T-CAPSULE/main_test.go" ]] || {
  echo "ERROR: run this script from the complete extracted ShahTunnel project." >&2
  exit 1
}
grep -Fq 'func realityAuthKeyShare(plainX25519, hybridX25519 *ecdh.PrivateKey)' \
  "$SCRIPT_DIR/S1T-CAPSULE/reality_transport.go" || {
  echo "ERROR: source is missing the REALITY key-share fix; refusing to install." >&2
  exit 1
}
grep -Fq 'realityAuthKeyShare(keyShares.Ecdhe, keyShares.MlkemEcdhe)' \
  "$SCRIPT_DIR/S1T-CAPSULE/reality_transport.go" || {
  echo "ERROR: source does not select the standalone X25519 share first; refusing to install." >&2
  exit 1
}
grep -Fq 'TestRealityAuthKeySharePrefersStandaloneX25519' \
  "$SCRIPT_DIR/S1T-CAPSULE/main_test.go" || {
  echo "ERROR: source is missing the key-share regression test; refusing to install." >&2
  exit 1
}

[[ -s /etc/ravanreverse/config.json ]] || {
  echo "ERROR: /etc/ravanreverse/config.json not found; existing install not detected." >&2
  exit 1
}
[[ -x /usr/local/bin/ravanreverse ]] || {
  echo "ERROR: /usr/local/bin/ravanreverse not found or not executable." >&2
  exit 1
}

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/shah-reality-fix-${STAMP}"
install -d -o root -g root -m 0700 "$BACKUP_DIR"
cp -a /etc/ravanreverse/config.json "$BACKUP_DIR/config.json"
cp -a /usr/local/bin/ravanreverse "$BACKUP_DIR/ravanreverse.before"
chmod 0600 "$BACKUP_DIR/config.json"
# Keep the executable bit on the binary backup so rollback is actually usable.
chmod 0750 "$BACKUP_DIR/ravanreverse.before"
OLD_SUM="$(sha256sum /usr/local/bin/ravanreverse | awk '{print $1}')"
OLD_VERSION="$(/usr/local/bin/ravanreverse version 2>/dev/null || true)"

rollback_binary() {
  echo "Attempting to restore the previous binary from $BACKUP_DIR ..." >&2
  install -o root -g root -m 0750 "$BACKUP_DIR/ravanreverse.before" /usr/local/bin/ravanreverse.rollback
  mv -f /usr/local/bin/ravanreverse.rollback /usr/local/bin/ravanreverse
  systemctl restart ravanreverse || true
}

echo "=== ShahTunnel REALITY repair ==="
echo "Source directory: $SCRIPT_DIR"
echo "Old binary: ${OLD_VERSION:-unknown}"
echo "Backup directory: $BACKUP_DIR"
echo "Config and secrets will not be printed or regenerated."
echo "Building/installing from the supplied project source ..."

if ! bash "$SCRIPT_DIR/S1T-START.sh" <<< '0'; then
  echo "ERROR: build/install failed." >&2
  # The installer normally fails before replacement, but restore the backup
  # defensively in case it failed during the final installation phase.
  rollback_binary
  echo "Check the installer output above. Backup: $BACKUP_DIR" >&2
  exit 1
fi

[[ -x /usr/local/bin/ravanreverse ]] || {
  echo "ERROR: installer did not leave an executable binary." >&2
  rollback_binary
  exit 1
}
NEW_SUM="$(sha256sum /usr/local/bin/ravanreverse | awk '{print $1}')"
if [[ "$OLD_SUM" == "$NEW_SUM" ]]; then
  echo "NOTICE: binary SHA-256 is unchanged. The same source may already have been installed." >&2
fi

echo "Restarting ravanreverse ..."
if ! systemctl restart ravanreverse; then
  echo "ERROR: service restart failed; rolling back the previous binary." >&2
  rollback_binary
  systemctl --no-pager --full status ravanreverse || true
  journalctl -u ravanreverse -n 50 --no-pager || true
  exit 1
fi
sleep 3
if ! systemctl is-active --quiet ravanreverse; then
  echo "ERROR: service is not active after restart; rolling back the previous binary." >&2
  rollback_binary
  systemctl --no-pager --full status ravanreverse || true
  journalctl -u ravanreverse -n 50 --no-pager || true
  exit 1
fi

echo "=== RESULT ==="
/usr/local/bin/ravanreverse version || true
systemctl is-active ravanreverse
echo "Binary SHA-256: $NEW_SUM"
echo "=== Runtime status (if available) ==="
if [[ -r /etc/ravanreverse/runtime.json ]]; then
  cat /etc/ravanreverse/runtime.json
else
  echo "runtime.json not present yet"
fi
echo "=== Recent service logs ==="
journalctl -u ravanreverse --since "45 seconds ago" --no-pager | tail -n 30
echo
echo "Finished. Run the same script on the other server. Backup: $BACKUP_DIR"
