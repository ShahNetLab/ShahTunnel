#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash tools/install-panel.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/shah-tunnel-panel"
UNIT_FILE="/etc/systemd/system/shah-tunnel-panel.service"
PYTHON="$(command -v python3 || true)"
SYSTEMCTL="$(command -v systemctl || true)"

if [[ -z "${PYTHON}" ]]; then
  echo "Python 3 is required. Install python3 and retry." >&2
  exit 1
fi
if [[ -z "${SYSTEMCTL}" ]]; then
  echo "systemd/systemctl is required for the managed panel service." >&2
  exit 1
fi
if [[ ! -f "${SCRIPT_DIR}/shah_panel.py" || ! -f "${SCRIPT_DIR}/web/index.html" ]]; then
  echo "Panel source files are incomplete; run this script from the extracted ShahTunnel project." >&2
  exit 1
fi

install -d -o root -g root -m 0755 "${INSTALL_DIR}" "${INSTALL_DIR}/web"
install -o root -g root -m 0644 "${SCRIPT_DIR}/shah_panel.py" "${INSTALL_DIR}/shah_panel.py"
install -o root -g root -m 0644 "${SCRIPT_DIR}/web/index.html" "${INSTALL_DIR}/web/index.html"

cat > "${UNIT_FILE}" <<UNIT
[Unit]
Description=ShahTunnel read-only local status dashboard
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=${PYTHON} /opt/shah-tunnel-panel/shah_panel.py --port 8091
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
LockPersonality=true
RestrictSUIDSGID=true
ReadOnlyPaths=/etc/ravanreverse

[Install]
WantedBy=multi-user.target
UNIT

"${SYSTEMCTL}" daemon-reload
"${SYSTEMCTL}" enable --now shah-tunnel-panel.service

echo
 echo "ShahTunnel panel is active on http://127.0.0.1:8091"
echo "For remote access, run this on your workstation:"
echo "  ssh -L 8091:127.0.0.1:8091 USER@SERVER"
echo "Then open http://127.0.0.1:8091 in your local browser."
echo
 echo "The panel is read-only and loopback-only. Do not expose it directly to the public Internet."
echo "Uninstall: systemctl disable --now shah-tunnel-panel && rm -f ${UNIT_FILE} && rm -rf ${INSTALL_DIR} && systemctl daemon-reload"
