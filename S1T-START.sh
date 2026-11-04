#!/usr/bin/env bash
set -Eeuo pipefail
# Shah Tunnel 1.6.2 installer.
# Downloads a prebuilt, SHA-256-verified binary from S1T-CAPSULE in this repository.
# No Go toolchain download or compilation is required on the target server.
OWNER="ShahNetLab"
REPO="ShahTunnel"
VERSION="1.6.2"
STATE_DIR="/usr/local/lib/shah-tunnel"
PHASE_HAS_DOWNLOAD=0
RAW_BASE="https://raw.githubusercontent.com/${OWNER}/${REPO}/main"
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
for cmd in curl sha256sum install mv grep cp ln date timeout awk cat chmod mktemp rm sleep; do
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

curl_download() {
  local url="$1" dest="$2"
  shift 2
  local headers="${TMP}/curl-headers.$$" log="${TMP}/curl-log.$$"
  local pid=0 rc=0
  rm -f "$headers" "$log" "$dest"
  if [[ ! -t 2 ]]; then
    if ! curl -fsSL --proto '=https' --proto-redir '=https' --dump-header "$headers" "$@" "$url" -o "$dest" 2>"$log"; then
      if [[ "${QUIET_CURL_ERRORS:-0}" != 1 ]]; then cat "$log" >&2; fi
      rm -f "$headers" "$log" "$dest"
      return 1
    fi
    # No progress bar is visible without a TTY, so let phase_done emit the
    # single final bar rather than suppressing all progress output.
    PHASE_HAS_DOWNLOAD=0
    rm -f "$headers" "$log"
    return 0
  fi
  curl -fsSL --proto '=https' --proto-redir '=https' --dump-header "$headers" "$@" "$url" -o "$dest" 2>"$log" &
  pid=$!
  # Show a single animated indicator while downloading; hide failed mirror
  # errors when QUIET_CURL_ERRORS=1 so normal fallback does not look broken.
  local frame=0
  while kill -0 "$pid" 2>/dev/null; do
    draw_indeterminate_bar "$frame"
    frame=$((frame + 1))
    sleep 0.12
  done
  wait "$pid" || rc=$?
  printf '\r\033[2K' >&2
  if (( rc != 0 )); then
    if [[ "${QUIET_CURL_ERRORS:-0}" != 1 ]]; then cat "$log" >&2; fi
    rm -f "$headers" "$log" "$dest"
    return "$rc"
  fi
  # Hold all success progress output until the four-line completion display.
  PHASE_HAS_DOWNLOAD=1
  rm -f "$headers" "$log"
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
  # Leave room for indentation, brackets, the percentage and a small margin.
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
  # Phase number controls the bar width. Each phase prints one completed bar,
  # avoiding stacked partial snapshots on mobile SSH terminals.
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
  # Four distinct lines, longest first, then gradually shorter.
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
  # Emit exactly four completion rows once, after installation has succeeded.
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
prebuilt_binary_sha256() {
  case "$TARGET_ARCH" in
    amd64) printf '%s' 'd9397790a5aaf9af4e61ae7bd2a1ccc233b5fba3a9fa330513f5d5a9a09c0f47' ;;
    arm64) printf '%s' '9d06bdc2dc412c6a615a740165ff06d22b73b551db7ed394c89b9843f44e427e' ;;
    *) return 1 ;;
  esac
}
download_prebuilt_binary() {
  local binary_name expected_sha binary_url
  binary_name="shah-tunnel-linux-${TARGET_ARCH}"
  expected_sha="$(prebuilt_binary_sha256)"
  binary_url="${RAW_BASE}/S1T-CAPSULE/${binary_name}"

  phase_start 1 "Download prebuilt Shah Tunnel binary"
  echo "Downloading Shah Tunnel ${VERSION} (${TARGET_ARCH}) from the S1T-CAPSULE folder..." >&2
  if ! curl_download "$binary_url" "$TMP/S1T-CORE" \
      --retry 3 --retry-delay 1 --connect-timeout 12 --max-time 300; then
    echo "Could not download ${binary_name} from ${binary_url}." >&2
    echo "Check that the binary exists in S1T-CAPSULE on the main branch." >&2
    return 1
  fi

  if ! printf '%s  %s\n' "$expected_sha" "$TMP/S1T-CORE" | sha256sum -c - >/dev/null 2>&1; then
    echo "Binary SHA-256 verification failed; refusing to install it." >&2
    rm -f "$TMP/S1T-CORE"
    return 1
  fi
  if ! verify_binary; then
    echo "Downloaded binary version or architecture is incorrect; refusing to install it." >&2
    rm -f "$TMP/S1T-CORE"
    return 1
  fi

  phase_done "Prebuilt binary verified"
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
