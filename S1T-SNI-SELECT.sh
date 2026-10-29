#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG="/etc/ravanreverse/config.json"
SERVICE="ravanreverse.service"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: bash S1T-SNI-SELECT.sh" >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found: $CONFIG" >&2
  echo "Install/configure ShahTunnel first; this script will not create a blank config." >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemctl is required." >&2; exit 1; }

printf '\nShahTunnel REALITY SNI selector\n'
printf 'Choose ONE hostname. The same choice must be applied on Hub and Agent.\n\n'
printf '  1) www.microsoft.com\n'
printf '  2) www.apple.com\n'
printf '  3) www.amazon.com\n'
printf '  4) www.bing.com\n'
printf '  5) www.yahoo.com\n\n'
read -r -p 'Selection [1]: ' choice
choice="${choice:-1}"
case "$choice" in
  1) HOST="www.microsoft.com" ;;
  2) HOST="www.apple.com" ;;
  3) HOST="www.amazon.com" ;;
  4) HOST="www.bing.com" ;;
  5) HOST="www.yahoo.com" ;;
  *) echo "Invalid selection: choose 1, 2, 3, 4, or 5." >&2; exit 2 ;;
esac

RESULT="$(python3 - "$CONFIG" "$HOST" <<'PY'
import datetime, json, os, shutil, socket, ssl, stat, sys, tempfile
path, host = sys.argv[1], sys.argv[2]
try:
    with open(path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
except Exception as e:
    print(f"Cannot read valid JSON config: {e}", file=sys.stderr)
    sys.exit(2)
role = str(cfg.get('role', '')).strip().lower()
if role not in ('hub', 'agent'):
    print(f"Unsupported config role: {role!r}; expected 'hub' or 'agent'.", file=sys.stderr)
    sys.exit(2)
if not str(cfg.get('reality_sni', '')).strip():
    print("This config has no reality_sni field; configure REALITY first.", file=sys.stderr)
    sys.exit(2)
if role == 'hub':
    if not str(cfg.get('reality_private_key', '')).strip() or not str(cfg.get('reality_public_key', '')).strip() or not str(cfg.get('reality_short_id', '')).strip():
        print("Hub config is missing REALITY keys or short ID; refusing to change it.", file=sys.stderr)
        sys.exit(2)
    # Only select a fallback site that this Hub can reach with a verified TLS 1.3 handshake.
    try:
        ctx = ssl.create_default_context()
        if not hasattr(ssl.TLSVersion, 'TLSv1_3'):
            raise RuntimeError('Python/OpenSSL does not expose TLS 1.3 validation')
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((host, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                if tls.version() != 'TLSv1.3':
                    raise RuntimeError(f'negotiated {tls.version()}, not TLS 1.3')
        print(f"Verified Hub reachability: {host}:443 with TLS 1.3 and a valid certificate.")
    except Exception as e:
        print(f"Selected host is not a verified TLS 1.3 destination from this Hub: {host}:443 ({e})", file=sys.stderr)
        print("No configuration was changed. Choose another SNI option and try again.", file=sys.stderr)
        sys.exit(3)
else:
    if not str(cfg.get('reality_public_key', '')).strip() or not str(cfg.get('reality_short_id', '')).strip():
        print("Agent config is missing the REALITY public key or short ID; refusing to change it.", file=sys.stderr)
        sys.exit(2)
    print("Agent selected. Ensure this exact SNI is also selected on the Hub.")

now = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
backup = f'{path}.bak-sni-{now}'
try:
    st = os.stat(path)
    shutil.copy2(path, backup)
    cfg['reality_sni'] = host
    if role == 'hub':
        # Keep the default cover destination aligned with the selected SNI.
        cfg['reality_dest'] = f'{host}:443'
    fd, tmp = tempfile.mkstemp(prefix='.config.json.sni-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
except Exception as e:
    print(f'Could not safely update config: {e}', file=sys.stderr)
    sys.exit(4)
# Validate the written JSON before allowing a service restart.
try:
    with open(path, 'r', encoding='utf-8') as f:
        changed = json.load(f)
    assert changed.get('reality_sni') == host
    if role == 'hub':
        assert changed.get('reality_dest') == f'{host}:443'
except Exception as e:
    shutil.copy2(backup, path)
    print(f'Post-write validation failed; original config restored: {e}', file=sys.stderr)
    sys.exit(5)
print(f'ROLE={role}')
print(f'SNI={host}')
if role == 'hub':
    print(f'DEST={host}:443')
print(f'BACKUP={backup}')
PY
)" || {
  rc=$?
  [[ -n "${RESULT:-}" ]] && printf '%s\n' "$RESULT"
  exit "$rc"
}
printf '%s\n' "$RESULT"
BACKUP="$(sed -n 's/^BACKUP=//p' <<<"$RESULT" | tail -n 1)"
if ! systemctl restart "$SERVICE"; then
  echo "Restart failed. Restoring the previous config from: $BACKUP" >&2
  if [[ -n "$BACKUP" && -f "$BACKUP" ]]; then
    cp -a -- "$BACKUP" "$CONFIG"
    systemctl restart "$SERVICE" || true
  fi
  exit 1
fi
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  echo "Service state: active"
else
  echo "Service did not become active. Restoring the previous config from: $BACKUP" >&2
  if [[ -n "$BACKUP" && -f "$BACKUP" ]]; then
    cp -a -- "$BACKUP" "$CONFIG"
    systemctl restart "$SERVICE" || true
  fi
  systemctl --no-pager --full status "$SERVICE" || true
  exit 1
fi
printf '\nRecent service log (the Agent and Hub must use the same SNI):\n'
journalctl -u "$SERVICE" --since '30 seconds ago' --no-pager 2>/dev/null | tail -n 14 || true
printf '\nSNI update finished. A systemd active state does not guarantee the REALITY handshake succeeded.\n'
