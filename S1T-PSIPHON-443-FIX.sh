#!/usr/bin/env bash
# S1T-PSIPHON-443-FIX.sh
# ShahTunnel / Psiphon workaround:
# Expose the existing Hub TCP listener on 9443 through a raw TCP relay on 443,
# then point the Agent profile at 443 after verifying Psiphon SOCKS5 can reach it.
# This script does NOT change SSH, default routes, UFW/nftables, Xray/WARP, or Hub config.

set -Eeuo pipefail

VERSION="1.0.0"
HUB_IP="37.32.12.244"
HUB_BACKEND_PORT="9443"
HUB_PUBLIC_PORT="443"
SOCKS_HOST="127.0.0.1"
SOCKS_PORT="21082"
PROFILE="${2:-s}"
AGENT_CONF="/etc/ravanreverse/tunnels/${PROFILE}.json"
RELAY_DIR="/usr/local/lib/shah-tunnel"
RELAY_PY="${RELAY_DIR}/psiphon-443-relay.py"
RELAY_UNIT="/etc/systemd/system/shah-psiphon-443-relay.service"
AGENT_BACKUP="${AGENT_CONF}.before-psiphon443"

log()  { printf '\n[INFO] %s\n' "$*"; }
warn() { printf '\n[WARN] %s\n' "$*" >&2; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Run as root."
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

show_usage() {
  cat <<USAGE
ShahTunnel Psiphon 443 workaround v${VERSION}

Run on the IRAN Hub server:
  bash S1T-PSIPHON-443-FIX.sh hub

Run on the OUTSIDE Agent server:
  bash S1T-PSIPHON-443-FIX.sh agent s

Rollback on the OUTSIDE Agent server:
  bash S1T-PSIPHON-443-FIX.sh rollback-agent s

Rollback on the IRAN Hub server:
  bash S1T-PSIPHON-443-FIX.sh rollback-hub

The Hub must already listen on ${HUB_BACKEND_PORT}. Port ${HUB_PUBLIC_PORT} must be unused.
USAGE
}

hub_install() {
  need_root
  need_cmd ss
  need_cmd systemctl
  need_cmd python3

  log "Checking existing Hub listener on ${HUB_BACKEND_PORT}/TCP"
  ss -lntH "( sport = :${HUB_BACKEND_PORT} )" | grep -q . \
    || die "Nothing is listening on TCP ${HUB_BACKEND_PORT}. No changes made."

  if ss -lntH "( sport = :${HUB_PUBLIC_PORT} )" | grep -q .; then
    ss -lntp "( sport = :${HUB_PUBLIC_PORT} )" || true
    die "TCP ${HUB_PUBLIC_PORT} is already in use. I will not stop or replace that service. No changes made."
  fi

  if [[ -e "$RELAY_UNIT" ]] && ! grep -q 'Managed by S1T-PSIPHON-443-FIX' "$RELAY_UNIT"; then
    die "$RELAY_UNIT already exists and is not owned by this script. No changes made."
  fi

  install -d -m 0755 "$RELAY_DIR"
  if [[ -e "$RELAY_PY" ]] && ! grep -q 'Managed by S1T-PSIPHON-443-FIX' "$RELAY_PY"; then
    die "$RELAY_PY already exists and is not owned by this script. No changes made."
  fi

  cat > "$RELAY_PY" <<'PYTHON'
#!/usr/bin/env python3
# Managed by S1T-PSIPHON-443-FIX
"""Minimal raw TCP relay: 0.0.0.0:443 -> 127.0.0.1:9443."""
import logging
import socket
import socketserver
import threading

LISTEN = ("0.0.0.0", 443)
BACKEND = ("127.0.0.1", 9443)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
)


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        try:
            upstream = socket.create_connection(BACKEND, timeout=8)
        except OSError as exc:
            logging.warning("backend connect failed for %s: %s", self.client_address, exc)
            return

        logging.info("accepted %s", self.client_address)
        with upstream:
            client.settimeout(None)
            upstream.settimeout(None)
            forward = threading.Thread(
                target=pipe, args=(client, upstream), daemon=True
            )
            forward.start()
            pipe(upstream, client)
            forward.join(timeout=1)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    with Server(LISTEN, Handler) as server:
        logging.info("relay listening on %s:%d -> %s:%d", *LISTEN, *BACKEND)
        server.serve_forever(poll_interval=0.5)
PYTHON
  chmod 0755 "$RELAY_PY"

  cat > "$RELAY_UNIT" <<EOFUNIT
# Managed by S1T-PSIPHON-443-FIX
[Unit]
Description=ShahTunnel Psiphon TCP relay 443 to Hub 9443
After=network-online.target ravanreverse@${PROFILE}.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${RELAY_PY}
Restart=always
RestartSec=2
User=root
Group=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOFUNIT

  systemctl daemon-reload
  systemctl enable --now shah-psiphon-443-relay.service
  sleep 1

  if ! systemctl is-active --quiet shah-psiphon-443-relay.service; then
    systemctl status shah-psiphon-443-relay.service --no-pager || true
    die "Relay did not start. Existing Hub listener on ${HUB_BACKEND_PORT} was not changed."
  fi

  if ! ss -lntH "( sport = :${HUB_PUBLIC_PORT} )" | grep -q .; then
    systemctl status shah-psiphon-443-relay.service --no-pager || true
    die "Relay service is active but port ${HUB_PUBLIC_PORT} is not listening."
  fi

  log "Hub relay is active: TCP ${HUB_PUBLIC_PORT} -> 127.0.0.1:${HUB_BACKEND_PORT}"
  ss -lntp "( sport = :${HUB_PUBLIC_PORT} or sport = :${HUB_BACKEND_PORT} )" || true
  log "Now run the AGENT command on the outside server. Do not run the agent mode on this Hub."
}

# Verify local SOCKS5 can establish a TCP connection through Psiphon.
socks5_probe() {
  python3 - "$SOCKS_HOST" "$SOCKS_PORT" "$HUB_IP" "$HUB_PUBLIC_PORT" <<'PYTHON'
import ipaddress
import socket
import sys

proxy_host, proxy_port, target_host, target_port = sys.argv[1:]
proxy_port = int(proxy_port)
target_port = int(target_port)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("SOCKS connection closed unexpectedly")
        data += chunk
    return data

try:
    with socket.create_connection((proxy_host, proxy_port), timeout=7) as s:
        s.settimeout(12)
        s.sendall(b"\x05\x01\x00")
        greeting = recv_exact(s, 2)
        if greeting != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 no-auth method rejected: {greeting.hex()}")
        ip = ipaddress.ip_address(target_host)
        if ip.version == 4:
            addr = b"\x01" + ip.packed
        else:
            addr = b"\x04" + ip.packed
        request = b"\x05\x01\x00" + addr + target_port.to_bytes(2, "big")
        s.sendall(request)
        head = recv_exact(s, 4)
        if head[0] != 5:
            raise RuntimeError(f"Unexpected SOCKS version: {head[0]}")
        code = head[1]
        atyp = head[3]
        if atyp == 1:
            recv_exact(s, 4)
        elif atyp == 4:
            recv_exact(s, 16)
        elif atyp == 3:
            ln = recv_exact(s, 1)[0]
            recv_exact(s, ln)
        else:
            raise RuntimeError(f"Unknown SOCKS address type: {atyp}")
        recv_exact(s, 2)
        if code != 0:
            messages = {
                1: "general SOCKS server failure",
                2: "connection not allowed by ruleset",
                3: "network unreachable",
                4: "host unreachable",
                5: "connection refused by destination/proxy exit",
                6: "TTL expired",
                7: "command not supported",
                8: "address type not supported",
            }
            raise RuntimeError(f"SOCKS5 CONNECT failed: reply={code} ({messages.get(code, 'unknown')})")
        print(f"SOCKS5_CONNECT_OK {target_host}:{target_port}")
except Exception as exc:
    print(f"SOCKS5_CONNECT_FAILED: {exc}", file=sys.stderr)
    sys.exit(1)
PYTHON
}

agent_install() {
  need_root
  need_cmd systemctl
  need_cmd python3
  [[ -f "$AGENT_CONF" ]] || die "Agent config not found: $AGENT_CONF"
  systemctl is-active --quiet "shah-psiphon-isolated@${PROFILE}.service" \
    || die "Isolated Psiphon service is not active: shah-psiphon-isolated@${PROFILE}.service"
  systemctl is-active --quiet "ravanreverse@${PROFILE}.service" \
    || die "Agent service is not active: ravanreverse@${PROFILE}.service"

  log "Testing whether Psiphon can reach ${HUB_IP}:${HUB_PUBLIC_PORT} via SOCKS5"
  socks5_probe || die "Psiphon cannot reach Hub on TCP ${HUB_PUBLIC_PORT}. Agent config was not changed. First run hub mode on the Iran server and verify provider/network allows inbound TCP 443."

  if [[ -e "$AGENT_BACKUP" ]]; then
    warn "Backup already exists: $AGENT_BACKUP"
    warn "It will not be overwritten. If this is a repeat run, check the current config first."
  else
    cp -a "$AGENT_CONF" "$AGENT_BACKUP"
    log "Backup created: $AGENT_BACKUP"
  fi

  python3 - "$AGENT_CONF" "$HUB_IP" "$HUB_BACKEND_PORT" "$HUB_PUBLIC_PORT" <<'PYTHON'
import json
import os
import re
import sys
import tempfile

path, host, old_port, new_port = sys.argv[1:]
raw = open(path, "r", encoding="utf-8").read()
try:
    parsed = json.loads(raw)
except Exception as exc:
    raise SystemExit(f"Agent config is not valid JSON; nothing changed: {exc}")

# First handle the common endpoint representation: "37.32.12.244:9443".
pattern = re.compile(re.escape(host) + r":" + re.escape(old_port) + r"(?!\d)")
if pattern.search(raw) is None and (host + ":" + new_port) in raw:
    print(f"ENDPOINT_ALREADY_SET {host}:{new_port}; no config rewrite needed")
    raise SystemExit(0)
updated, count = pattern.subn(host + ":" + new_port, raw)

# Also support separate host/address + port fields in the same JSON object.
if count == 0:
    changed = [0]
    already = [False]
    host_keys = {"host", "address", "ip", "serverip", "server_ip", "endpoint", "remotehost", "remote_host", "target"}
    def walk(node):
        if isinstance(node, dict):
            has_host = any(
                isinstance(v, str) and (v == host or v == host + ":" + old_port)
                for k, v in node.items() if str(k).lower() in host_keys
            )
            if has_host:
                for k, v in list(node.items()):
                    key = str(k).lower()
                    if "port" in key and str(v) == new_port:
                        already[0] = True
                    if "port" in key and str(v) == old_port:
                        node[k] = int(new_port) if isinstance(v, int) else new_port
                        changed[0] += 1
                    if isinstance(v, str):
                        nv, n = pattern.subn(host + ":" + new_port, v)
                        if n:
                            node[k] = nv
                            changed[0] += n
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(parsed)
    if changed[0] == 0 and already[0]:
        print(f"ENDPOINT_ALREADY_SET {host}:{new_port}; no config rewrite needed")
        raise SystemExit(0)
    if changed[0] == 0:
        raise SystemExit(
            f"Could not find {host}:{old_port} or a matching host+port pair in {path}. Nothing changed."
        )
    updated = json.dumps(parsed, ensure_ascii=False, indent=2) + "\n"

# Validate before atomic replacement.
json.loads(updated)
fd, tmp = tempfile.mkstemp(prefix=".psiphon443-", dir=os.path.dirname(path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(updated)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, os.stat(path).st_mode & 0o777)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
print(f"UPDATED_AGENT_ENDPOINT {host}:{old_port} -> {host}:{new_port}")
PYTHON

  log "Restarting only Agent profile ${PROFILE}"
  if ! systemctl restart "ravanreverse@${PROFILE}.service"; then
    warn "Agent restart failed; restoring backup."
    cp -a "$AGENT_BACKUP" "$AGENT_CONF"
    systemctl restart "ravanreverse@${PROFILE}.service" || true
    die "Agent config restored from backup."
  fi
  sleep 2
  if ! systemctl is-active --quiet "ravanreverse@${PROFILE}.service"; then
    warn "Agent did not remain active; restoring backup."
    cp -a "$AGENT_BACKUP" "$AGENT_CONF"
    systemctl restart "ravanreverse@${PROFILE}.service" || true
    die "Agent config restored from backup. Check journalctl for the Agent service."
  fi

  log "Agent profile ${PROFILE} is active and now targets ${HUB_IP}:${HUB_PUBLIC_PORT}."
  log "Recent Agent logs:"
  journalctl -u "ravanreverse@${PROFILE}.service" -n 35 --no-pager -o cat || true
  warn "This confirms the config and service restart only. A working Hub tunnel is confirmed only when Agent logs show an established/connected lane."
}

agent_rollback() {
  need_root
  need_cmd systemctl
  [[ -f "$AGENT_BACKUP" ]] || die "No rollback backup found: $AGENT_BACKUP"
  cp -a "$AGENT_BACKUP" "$AGENT_CONF"
  systemctl restart "ravanreverse@${PROFILE}.service"
  systemctl is-active --quiet "ravanreverse@${PROFILE}.service" \
    || die "Config restored, but Agent service is not active. Check journalctl."
  log "Agent config restored from $AGENT_BACKUP"
}

hub_rollback() {
  need_root
  need_cmd systemctl
  if [[ -f "$RELAY_UNIT" ]] && grep -q 'Managed by S1T-PSIPHON-443-FIX' "$RELAY_UNIT"; then
    systemctl disable --now shah-psiphon-443-relay.service || true
    rm -f "$RELAY_UNIT" "$RELAY_PY"
    systemctl daemon-reload
    log "The TCP 443 relay created by this script has been removed. Hub 9443 listener was not changed."
  else
    die "Managed relay unit not found. Nothing removed."
  fi
}

main() {
  local mode="${1:-}"
  case "$mode" in
    hub)            hub_install ;;
    agent)          agent_install ;;
    rollback-agent) agent_rollback ;;
    rollback-hub)   hub_rollback ;;
    -h|--help|help|'') show_usage ;;
    *) show_usage; die "Unknown mode: $mode" ;;
  esac
}

main "$@"
