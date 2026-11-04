#!/usr/bin/env bash
set -Eeuo pipefail
# Shah Tunnel 1.6.3 installer.
# Downloads a prebuilt, verified-by-archive-and-binary-version package.
# No Go toolchain download or local compilation is required on the target server.
OWNER="ShahNetLab"
REPO="ShahTunnel"
VERSION="1.6.3"
STATE_DIR="/usr/local/lib/shah-tunnel"
DOWNLOAD_CACHE="/var/cache/shah-tunnel/downloads"
PHASE_HAS_DOWNLOAD=0
RAW_BASE="https://raw.githubusercontent.com/${OWNER}/${REPO}/main"
CDN_BASE="https://cdn.jsdelivr.net/gh/${OWNER}/${REPO}@main"
FASTLY_BASE="https://fastly.jsdelivr.net/gh/${OWNER}/${REPO}@main"
GCORE_BASE="https://gcore.jsdelivr.net/gh/${OWNER}/${REPO}@main"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) TARGET_ARCH="amd64" ;;
  Linux:aarch64|Linux:arm64) TARGET_ARCH="arm64" ;;
  *) echo "Shah Tunnel ${VERSION} supports Linux amd64 and arm64 only." >&2; exit 1 ;;
esac
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: bash <(curl -fsSL ${RAW_BASE}/S1T-START.sh)" >&2
  exit 1
fi
command -v systemctl >/dev/null 2>&1 || { echo "systemd/systemctl is required." >&2; exit 1; }
for cmd in curl install mv grep cp ln date timeout awk cat chmod mktemp rm sleep tar mkdir; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required command missing: $cmd" >&2; exit 1; }
done
TMP="$(mktemp -d /tmp/s1t-install.XXXXXX)"
chmod 0700 "$TMP"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT
# Four final pink progress bars for mobile SSH terminals.
# Do not print intermediate carriage-return bars: some Android SSH clients
# turn them into extra rows. Print exactly four separate rows at completion.
PINK=$'\033[38;5;213m'
PINK_DARK=$'\033[38;5;97m'
RESET=$'\033[0m'

# Validate the archive itself, extract only into a private temporary directory,
# then verify the exact expected version and architecture before accepting it.
prepare_binary_from_package() {
  local archive="$1" label="$2" extracted candidate member
  member="shah-tunnel-universal/bin/linux-${TARGET_ARCH}/ravanreverse"
  extracted="${TMP}/package-${label//[^A-Za-z0-9]/_}"
  rm -rf -- "$extracted"
  mkdir -p "$extracted"

  # tar -t reads the complete gzip stream and checks its CRC/trailer. Reject
  # corrupt, truncated, HTML/error-page, or non-gzip CDN responses immediately.
  if ! tar -tzf "$archive" >/dev/null 2>&1; then
    echo "${label} did not provide a complete, valid gzip archive." >&2
    return 1
  fi

  # Extract the archive into the installer's private temp directory only.
  if ! tar -xzf "$archive" --no-same-owner --no-same-permissions -C "$extracted"; then
    echo "${label} archive could not be extracted." >&2
    rm -rf -- "$extracted"
    return 1
  fi

  candidate="${extracted}/${member}"
  if [[ ! -s "$candidate" ]]; then
    echo "${label} package has no Linux ${TARGET_ARCH} binary at the expected path." >&2
    rm -rf -- "$extracted"
    return 1
  fi
  chmod 0750 "$candidate"
  if ! timeout --kill-after=1s 5s "$candidate" version 2>/dev/null \
      | grep -Fqx "Shah Tunnel ${VERSION} (linux/${TARGET_ARCH})"; then
    echo "${label} binary version/architecture does not match ${VERSION} linux/${TARGET_ARCH}." >&2
    rm -rf -- "$extracted"
    return 1
  fi
  mv -f "$candidate" "$TMP/S1T-CORE"
  chmod 0750 "$TMP/S1T-CORE"
  rm -rf -- "$extracted"
  echo "${label}: archive integrity and binary version/architecture verified." >&2
  return 0
}

# Download from a mirror with bounded retries and resumable partial files.
# Do not compare against a fixed SHA for a mutable @main URL: that stale hash
# was causing a completed, updated package to be discarded and the slow Raw
# fallback to start. Package integrity and the executable's exact build are
# checked by prepare_binary_from_package() instead.
download_from_mirror() {
  local url="$1" part="$2" label="$3" rc=0 attempt
  mkdir -p "$DOWNLOAD_CACHE"
  chmod 0700 "$DOWNLOAD_CACHE"

  if [[ -s "$part" ]]; then
    if prepare_binary_from_package "$part" "${label} cached download"; then
      rm -f "$part"
      return 0
    fi
  else
    : > "$part"
  fi

  echo "Source: ${label}" >&2
  echo "Downloading the prebuilt ${TARGET_ARCH} package; no Go download or local compilation is used." >&2
  echo "Interrupted downloads are saved; rerun the same install command to resume." >&2

  # A stale/full partial can cause HTTP 416 on resume. In that case discard it
  # and perform one clean transfer from this mirror.
  for attempt in 1 2; do
    rc=0
    if [[ -t 2 ]]; then
      curl --fail --location --show-error --progress-bar \
        --proto '=https' --proto-redir '=https' \
        --continue-at - --retry 4 --retry-delay 2 --retry-connrefused \
        --connect-timeout 20 --max-time 1200 \
        --output "$part" "$url" || rc=$?
    else
      curl --fail --location --silent --show-error \
        --proto '=https' --proto-redir '=https' \
        --continue-at - --retry 4 --retry-delay 2 --retry-connrefused \
        --connect-timeout 20 --max-time 1200 \
        --output "$part" "$url" || rc=$?
    fi

    if (( rc == 0 )); then
      if prepare_binary_from_package "$part" "$label"; then
        rm -f "$part"
        return 0
      fi
      echo "${label} returned an invalid or incompatible package; discarding this mirror copy." >&2
      rm -f "$part"
      return 1
    fi

    if (( rc == 33 && attempt == 1 )); then
      echo "${label} does not support this resume request; retrying once from a clean file." >&2
      rm -f "$part"
      : > "$part"
      continue
    fi
    echo "${label} download did not finish (curl exit ${rc}); partial bytes are retained for resume." >&2
    return 1
  done
  return 1
}

# Use most of the available terminal width, then shorten each later phase
# gradually. The first bar is deliberately much wider; all bars remain within
# the terminal to avoid wrapping on mobile SSH clients.
CURRENT_PHASE=1
phase_bar_width() {
  local cols="${COLUMNS:-}" max_width width phase
  phase="${CURRENT_PHASE:-1}"
  if [[ ! "$cols" =~ ^[0-9]+$ ]] || (( cols < 40 )); then
    if [[ -r /dev/tty ]]; then
      cols="$(stty size < /dev/tty 2>/dev/null | awk '{print $2}')" || true
    fi
  fi
  [[ "$cols" =~ ^[0-9]+$ ]] || cols=80
  max_width=$((cols - 8))
  (( max_width > 76 )) && max_width=76
  (( max_width < 28 )) && max_width=28
  [[ "$phase" =~ ^[1-5]$ ]] || phase=5
  width=$((max_width - (phase - 1) * 5))
  (( width < 16 )) && width=16
  printf '%s' "$width"
}
draw_phase_bar() {
  local percent="$1" width filled i
  width="$(phase_bar_width)"
  (( percent < 0 )) && percent=0
  (( percent > 100 )) && percent=100
  filled=$((percent * width / 100))
  printf '\r\033[2K  [' >&2
  for ((i=0; i<width; i++)); do
    if (( i < filled )); then
      printf '%s█%s' "$PINK" "$RESET" >&2
    else
      printf '%s░%s' "$PINK_DARK" "$RESET" >&2
    fi
  done
  printf '] %3d%%' "$percent" >&2
}
draw_indeterminate_bar() {
  local frame="$1" width block=5 start i
  width="$(phase_bar_width)"
  (( width < block )) && block="$width"
  start=$((frame % (width - block + 1)))
  printf '\r\033[2K  [' >&2
  for ((i=0; i<width; i++)); do
    if (( i >= start && i < start + block )); then
      printf '%s█%s' "$PINK" "$RESET" >&2
    else
      printf '%s░%s' "$PINK_DARK" "$RESET" >&2
    fi
  done
  printf ']' >&2
}
phase_start() {
  CURRENT_PHASE="${1:-1}"
  PHASE_HAS_DOWNLOAD=0
}
draw_four_completion_bars() {
  local cols="${COLUMNS:-}" max_width width i row
  if [[ ! "$cols" =~ ^[0-9]+$ ]] || (( cols < 40 )); then
    if [[ -r /dev/tty ]]; then
      cols="$(stty size < /dev/tty 2>/dev/null | awk '{print $2}')" || true
    fi
  fi
  [[ "$cols" =~ ^[0-9]+$ ]] || cols=80
  max_width=$((cols - 12))
  (( max_width > 56 )) && max_width=56
  (( max_width < 20 )) && max_width=20
  for row in 100 84 68 52; do
    width=$((max_width * row / 100))
    (( width < 10 )) && width=10
    printf '  [' >&2
    for ((i=0; i<width; i++)); do
      printf '%s█%s' "$PINK" "$RESET" >&2
    done
    printf '] 100%%\n' >&2
  done
}
PROGRESS_BAR_PRINTED=0
phase_done() {
  if [[ "${CURRENT_PHASE:-0}" == "5" && "$PROGRESS_BAR_PRINTED" -eq 0 ]]; then
    draw_four_completion_bars
    PROGRESS_BAR_PRINTED=1
  fi
  PHASE_HAS_DOWNLOAD=0
}
verify_binary() {
  [[ -s "$TMP/S1T-CORE" ]] || return 1
  chmod 0750 "$TMP/S1T-CORE"
  timeout --kill-after=1s 5s "$TMP/S1T-CORE" version 2>/dev/null \
    | grep -Fqx "Shah Tunnel ${VERSION} (linux/${TARGET_ARCH})"
}
download_prebuilt_binary() {
  local bundle_name cdn_url fastly_url gcore_url raw_url
  bundle_name="shah-tunnel.tar.gz.tar"
  cdn_url="${CDN_BASE}/S1T-CAPSULE/${bundle_name}"
  fastly_url="${FASTLY_BASE}/S1T-CAPSULE/${bundle_name}"
  gcore_url="${GCORE_BASE}/S1T-CAPSULE/${bundle_name}"
  raw_url="${RAW_BASE}/S1T-CAPSULE/${bundle_name}"
  phase_start 1 "Download universal Shah Tunnel package"
  echo "Downloading one package for Linux ${TARGET_ARCH}; no Go download or local compilation is used." >&2

  if download_from_mirror "$cdn_url" "${DOWNLOAD_CACHE}/${bundle_name}.cdn.part" "jsDelivr CDN"; then
    :
  elif download_from_mirror "$fastly_url" "${DOWNLOAD_CACHE}/${bundle_name}.fastly.part" "jsDelivr Fastly"; then
    :
  elif download_from_mirror "$gcore_url" "${DOWNLOAD_CACHE}/${bundle_name}.gcore.part" "jsDelivr Gcore"; then
    :
  elif download_from_mirror "$raw_url" "${DOWNLOAD_CACHE}/${bundle_name}.raw.part" "GitHub Raw"; then
    :
  else
    echo "Could not obtain a valid ${VERSION} package: ${bundle_name}." >&2
    echo "Check that the archive exists in S1T-CAPSULE on the main branch and contains the expected Linux binaries." >&2
    return 1
  fi

  if ! verify_binary; then
    echo "The selected binary failed its final version/architecture check; refusing to install it." >&2
    rm -f "$TMP/S1T-CORE"
    return 1
  fi
  phase_done "Universal package and selected binary verified"
  return 0
}

if ! download_prebuilt_binary; then
  echo "Installation stopped: no verified ShahTunnel binary was downloaded." >&2
  exit 1
fi
phase_start 2 "Installing binary and configuring service"
install -d -o root -g root -m 0700 /etc/ravanreverse
install -d -o root -g root -m 0755 /usr/local/bin
install -d -o root -g root -m 0755 "$STATE_DIR"
BIN="/usr/local/bin/ravanreverse"
if [[ -x "$BIN" ]]; then
  BACKUP="${BIN}.bak-shah-tunnel-$(date +%Y%m%d-%H%M%S)"
  cp -a "$BIN" "$BACKUP"
fi
install -o root -g root -m 0750 "$TMP/S1T-CORE" /usr/local/bin/ravanreverse.new
mv -f /usr/local/bin/ravanreverse.new "$BIN"
ln -sfn /usr/local/bin/ravanreverse /usr/local/bin/shah-tunnel
# Preserve a working service unit on upgrades; create one only for a fresh install.
if [[ ! -f /etc/systemd/system/ravanreverse.service ]]; then
  cat > "$TMP/ravanreverse.service" <<'UNIT'
[Unit]
Description=Shah Tunnel authenticated reverse TCP tunnel
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=10
[Service]
Type=simple
UMask=0077
ExecStart=/usr/local/bin/ravanreverse run
Restart=always
RestartSec=2
TimeoutStopSec=20
LimitNOFILE=262144
TasksMax=4096
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ReadWritePaths=/etc/ravanreverse
[Install]
WantedBy=multi-user.target
UNIT
  install -o root -g root -m 0644 "$TMP/ravanreverse.service" /etc/systemd/system/ravanreverse.service
  if ! timeout --kill-after=3s 15s systemctl daemon-reload; then
    echo "systemd daemon-reload timed out. The binary is installed, but service metadata may need: systemctl daemon-reload" >&2
    exit 1
  fi
fi
if [[ -f /etc/ravanreverse/config.json ]]; then
  if ! timeout --kill-after=2s 10s systemctl enable ravanreverse >/dev/null; then
    echo "systemctl enable timed out or failed; stopping here instead of freezing the SSH session." >&2
    exit 1
  fi
  if timeout --kill-after=2s 8s systemctl is-active --quiet ravanreverse; then
    :
  else
    timeout --kill-after=2s 8s systemctl reset-failed ravanreverse >/dev/null 2>&1 || true
    if ! timeout --kill-after=5s 35s systemctl start ravanreverse; then
      echo "Service start failed or timed out. Recent logs (bounded to 5s):" >&2
      timeout 5s journalctl -u ravanreverse -n 40 --no-pager >&2 || true
      exit 1
    fi
    if ! timeout --kill-after=2s 8s systemctl is-active --quiet ravanreverse; then
      echo "Service is not active after installation. Recent logs (bounded to 5s):" >&2
      timeout 5s journalctl -u ravanreverse -n 40 --no-pager >&2 || true
      exit 1
    fi
  fi
else
  :
fi
phase_done "Binary installed; service/config check complete"
phase_start 5 "Final cleanup and opening the menu"
phase_done "All installer phases complete"
cleanup
trap - EXIT
exec /usr/local/bin/shah-tunnel menu
