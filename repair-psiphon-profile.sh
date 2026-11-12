#!/usr/bin/env bash
set -Eeuo pipefail

# Repair only one ShahTunnel Agent's Psiphon bootstrap config and restart only
# that Agent instance. No routes, SSH, X-UI, Hub, or other profiles are touched.

PROFILE="${1:-s}"
[[ "$PROFILE" =~ ^[A-Za-z0-9_.-]{1,48}$ ]] || {
  echo "ERROR: invalid profile name: $PROFILE" >&2
  exit 2
}
[[ "${EUID:-$(id -u)}" -eq 0 ]] || {
  echo "ERROR: run as root: sudo bash $0 ${PROFILE}" >&2
  exit 2
}

TUNNEL_CONFIG="/etc/ravanreverse/tunnels/${PROFILE}.json"
UNIT="ravanreverse@${PROFILE}.service"
[[ -s "$TUNNEL_CONFIG" ]] || {
  echo "ERROR: Agent config not found: $TUNNEL_CONFIG" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "ERROR: systemctl is required" >&2; exit 1; }
command -v journalctl >/dev/null 2>&1 || { echo "ERROR: journalctl is required" >&2; exit 1; }

mapfile -t META < <(python3 - "$TUNNEL_CONFIG" <<'PY'
import json,sys
p=sys.argv[1]
with open(p, encoding="utf-8") as f: c=json.load(f)
print(c.get("psiphon_config", ""))
print(c.get("psiphon_proxy", ""))
print(c.get("psiphon_data_dir", ""))
PY
)
PSIPHON_CONFIG="${META[0]:-}"
PSIPHON_PROXY="${META[1]:-}"
DATA_DIR="${META[2]:-}"
[[ -n "$PSIPHON_CONFIG" && -s "$PSIPHON_CONFIG" ]] || {
  echo "ERROR: Psiphon config path missing or unreadable in $TUNNEL_CONFIG" >&2
  exit 1
}
[[ "$PSIPHON_CONFIG" == /etc/ravanreverse/psiphon/* ]] || {
  echo "ERROR: refusing to modify unexpected Psiphon config path: $PSIPHON_CONFIG" >&2
  exit 1
}
[[ "$PSIPHON_PROXY" =~ ^127\.0\.0\.1:[0-9]{1,5}$ ]] || {
  echo "ERROR: expected a loopback SOCKS5 address, got: $PSIPHON_PROXY" >&2
  exit 1
}
[[ "$DATA_DIR" == /var/lib/shah-tunnel/psiphon/* ]] || {
  echo "ERROR: unexpected/missing per-profile Psiphon data directory: $DATA_DIR" >&2
  exit 1
}

BACKUP="${PSIPHON_CONFIG}.backup-$(date +%Y%m%d-%H%M%S)"
cp -a -- "$PSIPHON_CONFIG" "$BACKUP"

# Stop only this Agent so its own ConsoleClient cannot race the config rewrite.
systemctl stop "$UNIT" || true

# The template uses ProtectSystem=strict. Grant write access to this profile's
# Psiphon datastore only; do not widen permissions for the other Agent units.
install -d -o root -g root -m 0700 "$DATA_DIR"
DROPIN_DIR="/etc/systemd/system/${UNIT}.d"
install -d -o root -g root -m 0755 "$DROPIN_DIR"
DROPIN="$DROPIN_DIR/psiphon-data.conf"
if [[ -f "$DROPIN" ]]; then cp -a "$DROPIN" "${DROPIN}.backup-$(date +%Y%m%d-%H%M%S)"; fi
cat > "${DROPIN}.new" <<EOF
[Service]
ReadWritePaths=${DATA_DIR}
EOF
chmod 0644 "${DROPIN}.new"
mv -f "${DROPIN}.new" "$DROPIN"
systemctl daemon-reload

python3 - "$PSIPHON_CONFIG" "$PSIPHON_PROXY" <<'PY'
import base64, json, os, re, sys, tempfile
path, proxy = sys.argv[1:]
port = int(proxy.rsplit(":", 1)[1])

remote = [
    "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed",
    "https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/server_list_compressed",
    "https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/server_list_compressed",
    "https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/server_list_compressed",
]
osl = [
    "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/osl",
    "https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/osl",
    "https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/osl",
    "https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/osl",
]

def transfers(urls):
    return [{"URL": base64.b64encode(u.encode()).decode(),
             "OnlyAfterAttempts": 0, "SkipVerify": False} for u in urls]

with open(path, encoding="utf-8") as f:
    cfg = json.load(f)

# Use the public Psiphon client bootstrap identity and authentication keys.
# These are public verification/bootstrap values; no private credentials are stored.
cfg["ClientVersion"] = cfg.get("ClientVersion") or "1"
cfg["ClientPlatform"] = "Linux"
cfg["PropagationChannelId"] = "92AACC5BABE0944C"
cfg["SponsorId"] = "1BC527D3D09985CF"
cfg["LocalSocksProxyPort"] = port
cfg["DisableLocalSocksProxy"] = False
cfg["DisableLocalHTTPProxy"] = True
cfg["UseUnixDomainSockets"] = False
cfg["UseIndistinguishableTLS"] = True
cfg["RemoteServerListDownloadFilename"] = cfg.get("RemoteServerListDownloadFilename") or "remote_server_list"
cfg["RemoteServerListURLs"] = transfers(remote)
cfg["RemoteServerListSignaturePublicKey"] = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
cfg["ObfuscatedServerListRootURLs"] = transfers(osl)
cfg["ServerEntrySignaturePublicKey"] = "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA="
cfg["ExchangeObfuscationKey"] = "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU="
# Keep the deprecated single URL too, for the already-installed ShahTunnel binary.
cfg["RemoteServerListUrl"] = remote[0]

# Reject placeholder identifiers and malformed key material before writing.
assert re.fullmatch(r"[A-F0-9]{16}", cfg["PropagationChannelId"])
assert re.fullmatch(r"[A-F0-9]{16}", cfg["SponsorId"])
assert base64.b64decode(cfg["ServerEntrySignaturePublicKey"], validate=True).__len__() == 32
assert base64.b64decode(cfg["ExchangeObfuscationKey"], validate=True).__len__() == 32
assert len(base64.b64decode(cfg["RemoteServerListSignaturePublicKey"], validate=True)) >= 256
for collection in (cfg["RemoteServerListURLs"], cfg["ObfuscatedServerListRootURLs"]):
    assert collection and any(x["OnlyAfterAttempts"] == 0 for x in collection)
    for item in collection:
        assert base64.b64decode(item["URL"], validate=True).decode().startswith("https://")

folder = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".psiphon-repair-", suffix=".json", dir=folder)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
print("Psiphon bootstrap repaired and JSON validated.")
PY

if [[ -n "$DATA_DIR" ]]; then install -d -o root -g root -m 0700 "$DATA_DIR"; fi
systemctl reset-failed "$UNIT" || true
START_MARK="$(date --iso-8601=seconds)"
systemctl start "$UNIT" || true

echo "Waiting for Psiphon and at least one authenticated Agent lane (up to 100 seconds)..."
PSIPHON_READY=0
AGENT_LANE_READY=0
for _ in $(seq 1 100); do
  LOGS="$(journalctl -u "$UNIT" --since "$START_MARK" --no-pager -o cat 2>/dev/null || true)"
  if grep -Fq "Psiphon ConsoleClient connected" <<<"$LOGS"; then PSIPHON_READY=1; fi
  if grep -Eq 'tunnel lane [0-9]+/[0-9]+ connected via .* over psiphon_socks5' <<<"$LOGS"; then AGENT_LANE_READY=1; fi
  if [[ "$PSIPHON_READY" == 1 && "$AGENT_LANE_READY" == 1 ]] && systemctl is-active --quiet "$UNIT"; then
    echo "SUCCESS: Psiphon is connected and at least one Agent lane reached the Hub."
    echo "Profile: $PROFILE | SOCKS5: $PSIPHON_PROXY"
    echo "Backup: $BACKUP"
    journalctl -u "$UNIT" --since "$START_MARK" -n 18 --no-pager -o cat
    exit 0
  fi
  sleep 1
done

if [[ "$PSIPHON_READY" == 1 ]]; then
  echo "Psiphon connected, but the Agent has not established a lane to the Hub." >&2
  echo "The service is left running so it can keep retrying. Check Hub address, firewall ports, token, fingerprint and allowed transport." >&2
  journalctl -u "$UNIT" --since "$START_MARK" -n 55 --no-pager -o cat >&2 || true
  echo "Config backup: $BACKUP" >&2
  exit 2
fi

echo "ERROR: Psiphon did not report an established tunnel within 100 seconds." >&2
systemctl stop "$UNIT" || true
journalctl -u "$UNIT" --since "$START_MARK" -n 55 --no-pager -o cat >&2 || true
echo "Original config backup: $BACKUP" >&2
exit 1
