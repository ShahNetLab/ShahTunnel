#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash setup-exit-node.sh" >&2; exit 1; }
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SCRIPT_DIR/install-sing-box.sh"
[[ -s "$INSTALLER" ]] || { echo "Missing scripts/install-sing-box.sh beside this script." >&2; exit 1; }

for cmd in python3 openssl systemctl install; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }
done

read -r -p "Exit protocol (1=TUIC v5, 2=VLESS + REALITY + Vision): " CHOICE
case "$CHOICE" in 1) PROTOCOL=tuic ;; 2) PROTOCOL=vless_reality ;; *) echo "Invalid choice." >&2; exit 1 ;; esac
read -r -p "Listening port [443]: " PORT
PORT="${PORT:-443}"
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid port." >&2; exit 1; }
read -r -p "Public IP or DNS name clients will connect to: " PUBLIC_ADDRESS
[[ -n "$PUBLIC_ADDRESS" && "$PUBLIC_ADDRESS" != *[!A-Za-z0-9.-]* ]] || { echo "Invalid public address." >&2; exit 1; }
bash "$INSTALLER"
SING_BOX="/usr/local/bin/sing-box"
"$SING_BOX" version | grep -Fq '1.14.4' || { echo "Unexpected sing-box version." >&2; exit 1; }

UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
CONGESTION="bbr"
INBOUND=''
CLIENT_DETAILS=''
CONFIG_DIR="/etc/shah-tunnel-exit"
CONFIG="$CONFIG_DIR/config.json"
UNIT="/etc/systemd/system/shah-tunnel-exit.service"
if [[ -e "$UNIT" ]] && ! grep -Fq 'Description=ShahTunnel independent egress node' "$UNIT"; then
  echo "Refusing to replace an unrelated systemd unit at $UNIT." >&2
  exit 1
fi
if [[ -e "$CONFIG" && ! -e "$UNIT" ]]; then
  echo "Refusing to overwrite an existing config not paired with the ShahTunnel exit service: $CONFIG" >&2
  exit 1
fi
mkdir -p "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

if [[ "$PROTOCOL" == "tuic" ]]; then
  read -r -p "TLS certificate server_name (DNS hostname covered by the certificate): " SERVER_NAME
  [[ -n "$SERVER_NAME" && "$SERVER_NAME" != *[!A-Za-z0-9.-]* && "$SERVER_NAME" != .* && "$SERVER_NAME" != *. ]] || { echo "Invalid TLS server name." >&2; exit 1; }
  PASSWORD="$(openssl rand -hex 24)"
  read -r -p "Absolute path to TLS fullchain certificate: " CERT
  read -r -p "Absolute path to TLS private key: " KEY
  [[ -r "$CERT" && -r "$KEY" ]] || { echo "Certificate or private key is not readable." >&2; exit 1; }
  openssl x509 -in "$CERT" -noout -checkhost "$SERVER_NAME" >/dev/null || { echo "TLS certificate does not cover $SERVER_NAME." >&2; exit 1; }
  CERT_PUB="$(openssl x509 -in "$CERT" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  KEY_PUB="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  [[ -n "$CERT_PUB" && "$CERT_PUB" == "$KEY_PUB" ]] || { echo "TLS certificate and key do not match." >&2; exit 1; }
  install -m 0640 "$CERT" "$CONFIG_DIR/fullchain.pem"
  install -m 0640 "$KEY" "$CONFIG_DIR/privkey.pem"
  INBOUND="$(printf '%s\0' "$PORT" "$UUID" "$PASSWORD" "$CONFIG_DIR/fullchain.pem" "$CONFIG_DIR/privkey.pem" | python3 -c 'import json,sys; port,uid,pw,cert,key=sys.stdin.buffer.read().split(b"\0")[:5]; print(json.dumps({"type":"tuic","tag":"s1t-tuic-in","listen":"0.0.0.0","listen_port":int(port),"users":[{"uuid":uid.decode(),"password":pw.decode()}],"congestion_control":"bbr","zero_rtt_handshake":False,"heartbeat":"10s","tls":{"enabled":True,"certificate_path":cert.decode(),"key_path":key.decode(),"alpn":["h3"]}},separators=(",",":")))')"
  CLIENT_DETAILS="Protocol: TUIC v5
Server: $PUBLIC_ADDRESS
Port: $PORT/UDP
UUID: $UUID
Password: $PASSWORD
TLS server_name: $SERVER_NAME
Congestion control: bbr"
  REQUIRED_FIREWALL="UDP/$PORT"
else
  read -r -p "REALITY handshake destination hostname (TLS 1.3 capable): " HANDSHAKE_HOST
  [[ -n "$HANDSHAKE_HOST" && "$HANDSHAKE_HOST" != *[!A-Za-z0-9.-]* ]] || { echo "Invalid handshake hostname." >&2; exit 1; }
  python3 - "$HANDSHAKE_HOST" <<'PY'
import socket,sys
try:
    socket.create_connection((sys.argv[1],443),timeout=6).close()
except Exception as e:
    raise SystemExit(f'Cannot reach REALITY handshake destination on TCP/443: {e}')
PY
  KEYPAIR="$("$SING_BOX" generate reality-keypair)"
  PRIVATE_KEY="$(printf '%s\n' "$KEYPAIR" | awk -F': *' 'tolower($1) ~ /privatekey/ {print $2; exit}')"
  PUBLIC_KEY="$(printf '%s\n' "$KEYPAIR" | awk -F': *' 'tolower($1) ~ /publickey/ {print $2; exit}')"
  [[ -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" ]] || { echo "Could not generate the REALITY X25519 keypair." >&2; exit 1; }
  SHORT_ID="$(openssl rand -hex 8)"
  INBOUND="$(printf '%s\0' "$PORT" "$UUID" "$PRIVATE_KEY" "$SHORT_ID" "$HANDSHAKE_HOST" | python3 -c 'import json,sys; port,uid,private,short,host=sys.stdin.buffer.read().split(b"\0")[:5]; print(json.dumps({"type":"vless","tag":"s1t-reality-in","listen":"0.0.0.0","listen_port":int(port),"users":[{"uuid":uid.decode(),"flow":"xtls-rprx-vision"}],"tls":{"enabled":True,"reality":{"enabled":True,"handshake":{"server":host.decode(),"server_port":443},"private_key":private.decode(),"short_id":[short.decode()]}}},separators=(",",":")))')"
  CLIENT_DETAILS="Protocol: VLESS + REALITY + Vision
Server: $PUBLIC_ADDRESS
Port: $PORT/TCP
UUID: $UUID
TLS server_name: $HANDSHAKE_HOST
REALITY public_key: $PUBLIC_KEY
REALITY short_id: $SHORT_ID
uTLS fingerprint: chrome
Flow: xtls-rprx-vision
IMPORTANT: Keep the REALITY private key on this server only."
  REQUIRED_FIREWALL="TCP/$PORT"
fi

python3 -c 'import json,os,sys,tempfile; path=sys.argv[1]; inbound=json.load(sys.stdin); root={"log":{"level":"warn","timestamp":True},"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","auto_detect_interface":True}}; os.makedirs(os.path.dirname(path),mode=0o700,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix=".config-",dir=os.path.dirname(path));
try:
 f=os.fdopen(fd,"w"); json.dump(root,f,indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno()); f.close(); os.chmod(tmp,0o640); os.replace(tmp,path)
except Exception:
 try: os.unlink(tmp)
 except FileNotFoundError: pass
 raise' "$CONFIG" <<< "$INBOUND"

if ! id sing-box >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin sing-box
fi
chown -R root:sing-box "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"
find "$CONFIG_DIR" -type f -exec chmod 0640 {} +
"$SING_BOX" check -c "$CONFIG"

cat > "$UNIT" <<UNIT
[Unit]
Description=ShahTunnel independent egress node (${PROTOCOL})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sing-box
Group=sing-box
ExecStart=/usr/local/bin/sing-box run -c /etc/shah-tunnel-exit/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=262144
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/shah-tunnel-exit
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable shah-tunnel-exit.service
# Restart even if an earlier ShahTunnel exit service is already active; otherwise
# systemd --now would leave the old protocol/config running in memory.
if ! systemctl restart shah-tunnel-exit.service; then
  journalctl -u shah-tunnel-exit.service -n 60 --no-pager
  exit 1
fi
systemctl is-active --quiet shah-tunnel-exit.service || { journalctl -u shah-tunnel-exit.service -n 60 --no-pager; exit 1; }

printf '\n===== ShahTunnel EXIT NODE READY =====\n%s\n' "$CLIENT_DETAILS"
printf '\nOpen this port on your VPS firewall/provider: %s\n' "$REQUIRED_FIREWALL"
printf 'Service: shah-tunnel-exit.service\nConfig: %s (permissions 0640, private-key protected)\n' "$CONFIG"
printf 'No existing firewall rules, default routes, SSH settings, or other services were modified.\n'
