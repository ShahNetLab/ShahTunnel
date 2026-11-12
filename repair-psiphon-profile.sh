#!/usr/bin/env bash
set -Eeuo pipefail

# Repairs and starts exactly one ShahTunnel Agent Psiphon profile.
# The installed ShahTunnel binary performs the authenticated JSON migration;
# this script only backs up files, grants profile-scoped data access if needed,
# and verifies real Psiphon and Agent readiness. It does not edit routes, SSH,
# WARP, X-UI, Hub services, or other profiles.

PROFILE="${1:-s}"
[[ "$PROFILE" =~ ^[A-Za-z0-9_.-]{1,48}$ ]] || { echo "ERROR: invalid profile name" >&2; exit 2; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "ERROR: run as root: sudo bash $0 ${PROFILE}" >&2; exit 2; }

BIN="/usr/local/bin/ravanreverse"
TUNNEL_CONFIG="/etc/ravanreverse/tunnels/${PROFILE}.json"
UNIT="ravanreverse@${PROFILE}.service"

for cmd in python3 systemctl journalctl install cp date grep; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: required command missing: $cmd" >&2; exit 1; }
done
[[ -x "$BIN" ]] || { echo "ERROR: ShahTunnel binary not found: $BIN" >&2; exit 1; }
[[ -s "$TUNNEL_CONFIG" ]] || { echo "ERROR: Agent config not found: $TUNNEL_CONFIG" >&2; exit 1; }

VERSION_OUT="$("$BIN" version 2>&1 || true)"
[[ "$VERSION_OUT" == "Shah Tunnel 3.0.6 (linux/amd64)" || "$VERSION_OUT" == "Shah Tunnel 3.0.6 (linux/arm64)" || "$VERSION_OUT" == "Shah Tunnel 3.0.7 (linux/amd64)" || "$VERSION_OUT" == "Shah Tunnel 3.0.7 (linux/arm64)" ]] || {
  echo "ERROR: this repair requires a ShahTunnel 3.0.6/3.0.7 Psiphon-compatible binary; installed: ${VERSION_OUT:-unknown}" >&2
  echo "Run the updated S1T-START.sh installer first." >&2
  exit 1
}

mapfile -t META < <(python3 - "$TUNNEL_CONFIG" <<'PY'
import json, sys
p = sys.argv[1]
with open(p, encoding="utf-8") as f:
    c = json.load(f)
if c.get("role") != "agent":
    raise SystemExit("selected profile is not an Agent")
if c.get("underlay") not in ("psiphon_socks5", "adaptive_external"):
    raise SystemExit("selected Agent is not configured for Psiphon/Adaptive external egress")
for key in ("psiphon_config", "psiphon_proxy", "psiphon_data_dir"):
    if not isinstance(c.get(key), str) or not c[key].strip():
        raise SystemExit("missing Psiphon profile setting: " + key)
print(c["psiphon_config"])
print(c["psiphon_proxy"])
print(c["psiphon_data_dir"])
PY
) || { echo "ERROR: could not read safe Psiphon profile metadata" >&2; exit 1; }

PSIPHON_CONFIG="${META[0]:-}"
PSIPHON_PROXY="${META[1]:-}"
DATA_DIR="${META[2]:-}"
[[ "$PSIPHON_CONFIG" == /etc/ravanreverse/psiphon/* && -s "$PSIPHON_CONFIG" ]] || { echo "ERROR: unexpected or missing Psiphon config path" >&2; exit 1; }
[[ "$PSIPHON_PROXY" =~ ^127\.0\.0\.1:[0-9]{1,5}$ ]] || { echo "ERROR: Psiphon proxy must be loopback-only" >&2; exit 1; }
[[ "$DATA_DIR" == /var/lib/shah-tunnel/psiphon/* ]] || { echo "ERROR: unexpected Psiphon data directory" >&2; exit 1; }

# Stop only this profile before backing up and re-running its one service.
if systemctl is-active --quiet "$UNIT"; then
  systemctl stop "$UNIT"
fi
BACKUP="${PSIPHON_CONFIG}.backup-$(date +%Y%m%d-%H%M%S)"
cp -a -- "$PSIPHON_CONFIG" "$BACKUP"
install -d -o root -g root -m 0700 "$DATA_DIR"

# The template usually already grants the Psiphon data root. Add a narrower
# per-instance path only if the current unit does not inherit that permission.
RW_PATHS="$(systemctl show "$UNIT" -p ReadWritePaths --value 2>/dev/null || true)"
if [[ "$RW_PATHS" != *"/var/lib/shah-tunnel/psiphon"* && "$RW_PATHS" != *"$DATA_DIR"* ]]; then
  DROPIN_DIR="/etc/systemd/system/${UNIT}.d"
  DROPIN="$DROPIN_DIR/psiphon-data.conf"
  install -d -o root -g root -m 0755 "$DROPIN_DIR"
  [[ ! -f "$DROPIN" ]] || cp -a "$DROPIN" "${DROPIN}.backup-$(date +%Y%m%d-%H%M%S)"
  printf '[Service]\nReadWritePaths=%s\n' "$DATA_DIR" > "${DROPIN}.new"
  chmod 0644 "${DROPIN}.new"
  mv -f "${DROPIN}.new" "$DROPIN"
  systemctl daemon-reload
fi

systemctl reset-failed "$UNIT" || true
START_MARK="$(date --iso-8601=seconds)"
if ! systemctl start "$UNIT"; then
  echo "ERROR: Agent service failed to start." >&2
  journalctl -u "$UNIT" --since "$START_MARK" -n 60 --no-pager -o cat >&2 || true
  echo "Config backup: $BACKUP" >&2
  exit 1
fi

echo "Checking the local Psiphon SOCKS5 listener and Agent lane (up to 100 seconds)..."
PROXY_READY=0
PSIPHON_READY=0
LANE_READY=0
for ((i=0; i<100; i++)); do
  LOGS="$(journalctl -u "$UNIT" --since "$START_MARK" --no-pager -o cat 2>/dev/null || true)"
  if grep -Fq "Psiphon local SOCKS5 listener ready" <<<"$LOGS"; then PROXY_READY=1; fi
  if grep -Fq "Psiphon ConsoleClient connected" <<<"$LOGS"; then PSIPHON_READY=1; fi
  if grep -Eq 'tunnel lane [0-9]+/[0-9]+ connected via .* over psiphon_socks5' <<<"$LOGS"; then LANE_READY=1; fi
  if [[ "$PSIPHON_READY" == 1 && "$LANE_READY" == 1 ]] && systemctl is-active --quiet "$UNIT"; then
    echo "SUCCESS: Psiphon is connected and an Agent lane reached the Hub through its private SOCKS5 proxy."
    echo "Profile: $PROFILE | SOCKS5: $PSIPHON_PROXY | Backup: $BACKUP"
    journalctl -u "$UNIT" --since "$START_MARK" -n 20 --no-pager -o cat
    exit 0
  fi
  if [[ "$PROXY_READY" == 1 ]] && systemctl is-active --quiet "$UNIT"; then
    echo "PENDING: local Psiphon SOCKS5 is ready, but the complete Psiphon-to-Hub Agent path is not yet verified."
    echo "The service is deliberately left running; ConsoleClient will keep retrying. No Hub lane is claimed connected."
    echo "Profile: $PROFILE | SOCKS5: $PSIPHON_PROXY | Config backup: $BACKUP"
    journalctl -u "$UNIT" --since "$START_MARK" -n 35 --no-pager -o cat
    exit 0
  fi
  sleep 1
done

echo "ERROR: the local Psiphon SOCKS5 listener did not become ready; only this Agent profile is stopped." >&2
systemctl stop "$UNIT" || true
journalctl -u "$UNIT" --since "$START_MARK" -n 60 --no-pager -o cat >&2 || true
echo "Config backup: $BACKUP" >&2
exit 1
