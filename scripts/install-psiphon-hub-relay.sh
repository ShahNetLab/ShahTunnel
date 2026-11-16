#!/usr/bin/env bash
set -Eeuo pipefail

# Install a TCP-only Psiphon-compatible entry point on the REAL Hub.
# It forwards an allowed public TCP port (default 443) to the Hub's existing
# authenticated TLS control listener. It does not modify customer mappings.

EXPECTED_PUBLIC_IP="${SHAH_HUB_PUBLIC_IP:-37.32.12.244}"
LISTEN_PORT="${SHAH_PSIPHON_RELAY_PORT:-443}"
BIN="/usr/local/bin/ravanreverse"
UNIT="shah-psiphon-${LISTEN_PORT}-relay.service"
CONFIG="/etc/ravanreverse/psiphon-hub-relay-${LISTEN_PORT}.json"
UNIT_PATH="/etc/systemd/system/${UNIT}"
MARKER="# Managed-By: ShahTunnel 5.5.12 Psiphon Hub Relay Fix"

fail() { echo "ERROR: $*" >&2; exit 1; }
info() { printf '◇ %s\n' "$*"; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run this on the Iran Hub as root: sudo bash $0"
for cmd in python3 systemctl journalctl ss curl install cp date grep timeout mv chmod seq sleep; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done
[[ -x "$BIN" ]] || fail "ShahTunnel binary not found at $BIN; install ShahTunnel 5.5.12 on the Hub first"
[[ "$LISTEN_PORT" =~ ^[0-9]{1,5}$ ]] || fail "invalid relay port: $LISTEN_PORT"
case "$LISTEN_PORT" in
  443|80|8080|465|587|993|995) ;;
  *) fail "Psiphon-compatible destination port must be one of 443, 80, 8080, 465, 587, 993, 995; 2083 is not supported by the published Psiphon port list" ;;
esac

ACTUAL_PUBLIC_IP="$(curl -4 --noproxy '*' -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org || true)"
[[ "$ACTUAL_PUBLIC_IP" == "$EXPECTED_PUBLIC_IP" ]] || fail "wrong VPS. Expected Hub public IP ${EXPECTED_PUBLIC_IP}, but this machine reports ${ACTUAL_PUBLIC_IP:-<unavailable>}. Do not run this on the Agent or relay VPS."

# Locate the one active Hub profile without exposing its token or fingerprint.
mapfile -t HUB_META < <(python3 - "${SHAH_HUB_CONFIG:-}" "$LISTEN_PORT" <<'PY'
import glob, json, os, sys
wanted, listen_port = sys.argv[1], sys.argv[2]
paths = [wanted] if wanted else (['/etc/ravanreverse/config.json'] + sorted(glob.glob('/etc/ravanreverse/tunnels/*.json')))
found = []
for path in paths:
    if not path or not os.path.isfile(path):
        continue
    try:
        with open(path, encoding='utf-8') as f:
            c = json.load(f)
    except Exception:
        continue
    if c.get('role') == 'hub':
        found.append((path, c))
if len(found) != 1:
    if not found:
        raise SystemExit('no Hub config found; set SHAH_HUB_CONFIG=/exact/path/to/hub.json')
    raise SystemExit('more than one Hub config found; set SHAH_HUB_CONFIG to the intended Hub JSON')
path, c = found[0]
control = c.get('control_listen', '')
try:
    host, port = control.rsplit(':', 1)
    port_n = int(port)
except Exception:
    raise SystemExit('Hub config has an invalid control_listen value')
if not (1 <= port_n <= 65535):
    raise SystemExit('Hub control port is outside the valid TCP range')
# If the Hub already exposes the same port as a public Mapping, its own
# listener can multiplex the private control ALPN; a second relay is needless.
mapping_has_port = False
ports = c.get('ports', []) or []
if not ports and c.get('public_listen'):
    ports = [{'listen': c.get('public_listen')}]
for item in ports:
    try:
        if int(item.get('listen', '').rsplit(':', 1)[1]) == int(listen_port):
            mapping_has_port = True
    except Exception:
        pass
base = os.path.basename(path)
service = 'ravanreverse.service' if base == 'config.json' else 'ravanreverse@' + os.path.splitext(base)[0] + '.service'
print(path)
print(str(port_n))
print(service)
print('1' if mapping_has_port else '0')
PY
) || fail "could not identify the correct Hub configuration safely"
HUB_CONFIG="${HUB_META[0]:-}"
CONTROL_PORT="${HUB_META[1]:-}"
HUB_SERVICE="${HUB_META[2]:-}"
HUB_MAPPING_HAS_RELAY_PORT="${HUB_META[3]:-0}"
[[ -s "$HUB_CONFIG" && "$CONTROL_PORT" =~ ^[0-9]+$ && -n "$HUB_SERVICE" ]] || fail "Hub metadata is incomplete"

systemctl is-active --quiet "$HUB_SERVICE" || fail "Hub service $HUB_SERVICE is not active; start the Hub before adding the Psiphon entry point"

# Confirm that the Hub's existing TLS control listener is actually accepting
# local TCP connections before creating a public front door.
LOOPBACK_HOST="$(python3 - "$CONTROL_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
for host in ('127.0.0.1', '::1'):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        print(host)
        raise SystemExit(0)
    except OSError:
        pass
    finally:
        s.close()
raise SystemExit('Hub control listener is not reachable on loopback')
PY
)" || fail "Hub control listener on TCP ${CONTROL_PORT} is not reachable locally"
TARGET="${LOOPBACK_HOST}:${CONTROL_PORT}"

# A Hub public mapping already bound to the chosen port supports the private
# ShahTunnel ALPN itself. Test it rather than installing a conflicting relay.
probe_alpn() {
  python3 - "$1" <<'PY'
import socket, ssl, sys
host, port = sys.argv[1].rsplit(':', 1)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['shah-tunnel-control/1'])
raw = socket.create_connection((host, int(port)), timeout=5)
try:
    with ctx.wrap_socket(raw, server_hostname='localhost') as conn:
        selected = conn.selected_alpn_protocol()
        if selected != 'shah-tunnel-control/1':
            raise SystemExit('TLS works but ShahTunnel control ALPN was not selected: ' + str(selected))
        print('TLS 1.3 / ALPN shah-tunnel-control/1: OK')
finally:
    try: raw.close()
    except Exception: pass
PY
}

# If ControlListen itself is already on the selected public port, verify it
# directly; do not attempt to put a second listener on the same port.
if [[ "$CONTROL_PORT" == "$LISTEN_PORT" ]]; then
  if probe_alpn "127.0.0.1:${LISTEN_PORT}"; then
    echo "SUCCESS: TCP/${LISTEN_PORT} is already the authenticated Hub control listener; no relay is needed."
    echo "Agent PsiphonHubAddr should be ${EXPECTED_PUBLIC_IP}:${LISTEN_PORT}. Customer mappings were not changed."
    exit 0
  fi
  fail "Hub ControlListen uses TCP/${LISTEN_PORT}, but its local TLS/ALPN test failed."
fi

if [[ "$HUB_MAPPING_HAS_RELAY_PORT" == 1 ]]; then
  if probe_alpn "127.0.0.1:${LISTEN_PORT}"; then
    echo "SUCCESS: Hub public Mapping TCP/${LISTEN_PORT} already carries the authenticated ShahTunnel control ALPN. No relay was installed."
    echo "Agent PsiphonHubAddr should be ${EXPECTED_PUBLIC_IP}:${LISTEN_PORT}. Customer mappings were not changed."
    exit 0
  fi
  fail "Hub config says TCP/${LISTEN_PORT} is already a public Mapping, but its local TLS/ALPN probe failed. No changes were made. Check the Hub logs first."
fi

# Replace only a previous relay unit that clearly identifies itself as the
# ShahTunnel Psiphon relay. Never kill or overwrite an unrelated listener.
if [[ -e "$UNIT_PATH" ]]; then
  if ! grep -Eq 'Description=Shah[Tt]unnel Psiphon TCP relay|Managed-By: ShahTunnel .*Psiphon Hub Relay' "$UNIT_PATH"; then
    fail "$UNIT_PATH already exists but is not identifiable as a ShahTunnel Psiphon relay; refusing to overwrite it"
  fi
  BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"
  cp -a -- "$UNIT_PATH" "${UNIT_PATH}.backup-${BACKUP_SUFFIX}"
  if [[ -s "$CONFIG" ]]; then
    cp -a -- "$CONFIG" "${CONFIG}.backup-${BACKUP_SUFFIX}"
  fi
  systemctl stop "$UNIT" 2>/dev/null || true
fi

LISTENERS="$(ss -H -lnt "sport = :${LISTEN_PORT}" 2>/dev/null || true)"
if [[ -n "$LISTENERS" ]]; then
  fail "TCP/${LISTEN_PORT} is already occupied by another listener. No service was stopped or changed. Choose another Psiphon-supported free port with SHAH_PSIPHON_RELAY_PORT=8080 (then update Agent PsiphonHubAddr to ${EXPECTED_PUBLIC_IP}:8080)."
fi

install -d -o root -g root -m 0700 /etc/ravanreverse
TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
python3 - "$CONFIG" "$TOKEN" "$LISTEN_PORT" "$TARGET" <<'PY'
import json, os, sys, tempfile
path, token, listen_port, target = sys.argv[1:]
c = {
    'name': 'shah-psiphon-' + listen_port + '-relay',
    'version': '5.5.12',
    'role': 'relay',
    'token': token,
    'ports': [{
        'id': 'psiphon-control',
        'listen': '0.0.0.0:' + listen_port,
        'target': target,
    }],
}
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix='.psiphon-relay-', dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(c, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY

UNIT_TMP="${UNIT_PATH}.new"
cat > "$UNIT_TMP" <<EOF
# Managed-By: ShahTunnel 5.5.12 Psiphon Hub Relay Fix
[Unit]
Description=ShahTunnel Psiphon TCP relay ${LISTEN_PORT} to Hub ${CONTROL_PORT}
After=network-online.target ${HUB_SERVICE}
Wants=network-online.target ${HUB_SERVICE}

[Service]
Type=simple
User=root
ExecStart=${BIN} run --config ${CONFIG}
Restart=always
RestartSec=2
StartLimitIntervalSec=0
LimitNOFILE=65536
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_TMP"
mv -f "$UNIT_TMP" "$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now "$UNIT"

READY=0
for _ in $(seq 1 10); do
  if ss -H -lnt "sport = :${LISTEN_PORT}" | grep -q .; then READY=1; break; fi
  sleep 1
done
if [[ "$READY" != 1 ]]; then
  journalctl -u "$UNIT" -n 35 --no-pager -o cat >&2 || true
  systemctl stop "$UNIT" || true
  fail "relay service did not bind TCP/${LISTEN_PORT}; see journal above"
fi

if ! probe_alpn "127.0.0.1:${LISTEN_PORT}"; then
  journalctl -u "$UNIT" -n 35 --no-pager -o cat >&2 || true
  systemctl stop "$UNIT" || true
  fail "the new TCP relay is listening, but the Hub TLS/ALPN probe failed. Relay was stopped; inspect the Hub ControlListen service."
fi

echo "SUCCESS: Psiphon-compatible TCP/${LISTEN_PORT} front door is forwarding raw TLS to Hub control ${TARGET}."
echo "Hub profile: ${HUB_CONFIG} (${HUB_SERVICE})"
echo "Agent PsiphonHubAddr must be: ${EXPECTED_PUBLIC_IP}:${LISTEN_PORT}"
echo "Customer-facing port mappings (including TCP/2083) were not edited."
echo "Open TCP/${LISTEN_PORT} in the VPS provider firewall. No firewall rules were changed by this script."
echo "Relay service: ${UNIT}"
