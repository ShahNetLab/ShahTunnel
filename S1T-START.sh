#!/usr/bin/env bash
set -Eeuo pipefail
# Shah Tunnel 2.2.2 installer.
# Downloads the pinned Go toolchain, verifies its SHA-256, fetches the source,
# and builds the binary on the target server. No GitHub Release binary is used.
OWNER="ShahNetLab"
REPO="ShahTunnel"
VERSION="2.2.2"
GO_VERSION="1.26.1"
GO_BASE="https://dl.google.com/go"
GO_FALLBACK_BASE="https://go.dev/dl"
STATE_DIR="/usr/local/lib/shah-tunnel"
GO_CACHE_DIR="/var/cache/shah-tunnel"
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
for cmd in curl sha256sum install mv grep cp ln date timeout awk cat chmod tar gzip mktemp rm sleep python3 wc sed tail sort xargs find seq; do
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
# Download a large file while retaining partial bytes between mirror attempts.
# Unlike curl_download(), this helper must NEVER remove the destination file on
# failure, because the next mirror may resume at the existing byte offset.
curl_download_resumable() {
  local url="$1" dest="$2" max_time="${3:-0}" retry_count="${4:-3}" speed_time="${5:-180}"
  local headers="${TMP}/curl-resume-headers.$$" log="${TMP}/curl-resume-log.$$"
  local rc=0 pid=0 frame=0

  [[ -f "$dest" ]] || : > "$dest"
  rm -f "$headers" "$log"
  : > "$log"

  if [[ ! -t 2 ]]; then
    if curl -fsSL --proto '=https' --proto-redir '=https' \
        --continue-at - \
        --retry "$retry_count" --retry-delay 1 --retry-connrefused \
        --connect-timeout 8 --max-time "$max_time" \
        --speed-time "$speed_time" --speed-limit 1024 \
        --dump-header "$headers" "$url" -o "$dest" 2>"$log"; then
      rm -f "$headers" "$log"
      return 0
    else
      rc=$?
    fi
    if [[ "${QUIET_CURL_ERRORS:-0}" != 1 ]]; then cat "$log" >&2; fi
    rm -f "$headers" "$log"
    return "$rc"
  fi

  curl -fsSL --proto '=https' --proto-redir '=https' \
      --continue-at - \
      --retry "$retry_count" --retry-delay 1 --retry-connrefused \
      --connect-timeout 8 --max-time "$max_time" \
      --speed-time "$speed_time" --speed-limit 1024 \
      --dump-header "$headers" "$url" -o "$dest" 2>"$log" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    draw_indeterminate_bar "$frame"
    frame=$((frame + 1))
    sleep 0.12
  done
  wait "$pid" || rc=$?
  printf '\r\033[2K' >&2
  if (( rc != 0 )); then
    if [[ "${QUIET_CURL_ERRORS:-0}" != 1 ]]; then cat "$log" >&2; fi
    rm -f "$headers" "$log"
    return "$rc"
  fi
  PHASE_HAS_DOWNLOAD=1
  rm -f "$headers" "$log"
  return 0
}

# Download a Go archive using concurrent byte ranges. This is especially
# helpful on hosts where a single HTTPS stream is bandwidth-limited. A range
# is accepted only when the server returns the exact number of bytes; the final
# archive must match the pinned SHA-256 before it is used.
curl_download_parallel_ranges() {
  local url="$1" dest="$2" expected_sha="$3"
  local workdir="${dest}.chunks" headers="${TMP}/range-headers.$$" probe="${TMP}/range-probe.$$"
  local total chunk_count=8 chunk_size i start end expected_size part tmp_part
  local pid rc failed=0 alive frame=0
  local -a pids=()
  RANGE_DOWNLOAD_ATTEMPTED=0

  rm -f "$headers" "$probe"
  # --max-filesize prevents a mirror that ignores Range from streaming the
  # entire ~67 MB archive just to probe support.
  if ! curl -fsSL --proto '=https' --proto-redir '=https' --range 0-0 \
      --max-filesize 1024 --connect-timeout 8 --max-time 12 \
      --dump-header "$headers" "$url" -o "$probe" 2>/dev/null; then
    rm -f "$headers" "$probe"
    return 1
  fi
  total="$(sed -nE 's/^[Cc]ontent-[Rr]ange:[[:space:]]*bytes[[:space:]]+0-0\/([0-9]+).*$/\1/p' "$headers" | tail -n 1)"
  if [[ ! "$total" =~ ^[0-9]+$ ]] || [[ "$(wc -c < "$probe" 2>/dev/null || echo 0)" -ne 1 ]]; then
    rm -f "$headers" "$probe"
    return 1
  fi
  rm -f "$headers" "$probe"
  RANGE_DOWNLOAD_ATTEMPTED=1

  mkdir -p "$workdir"
  chunk_size=$(((total + chunk_count - 1) / chunk_count))
  pids=()
  for ((i=0; i<chunk_count; i++)); do
    start=$((i * chunk_size))
    (( start < total )) || break
    end=$((start + chunk_size - 1))
    (( end < total )) || end=$((total - 1))
    expected_size=$((end - start + 1))
    part="${workdir}/chunk-$(printf '%02d' "$i").part"
    # Completed chunks are reusable on the next invocation, but only if their
    # byte count matches the expected range length.
    if [[ -f "$part" ]] && [[ "$(wc -c < "$part")" -eq "$expected_size" ]]; then
      continue
    fi
    tmp_part="${part}.tmp.$$"
    rm -f "$tmp_part"
    (
      if curl -fsSL --proto '=https' --proto-redir '=https' \
          --range "${start}-${end}" --retry 0 \
          --connect-timeout 8 --max-time 35 \
          "$url" -o "$tmp_part" 2>/dev/null &&
          [[ "$(wc -c < "$tmp_part" 2>/dev/null || echo 0)" -eq "$expected_size" ]]; then
        mv -f "$tmp_part" "$part"
        exit 0
      fi
      rm -f "$tmp_part"
      exit 1
    ) &
    pids+=("$!")
  done

  # Keep the existing compact animated indicator while chunks are in flight.
  while :; do
    alive=0
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then alive=1; break; fi
    done
    (( alive == 1 )) || break
    draw_indeterminate_bar "$frame"
    frame=$((frame + 1))
    sleep 0.12
  done
  printf '\r\033[2K' >&2
  for pid in "${pids[@]}"; do
    wait "$pid" || failed=1
  done
  if (( failed != 0 )); then
    return 1
  fi

  local assembled="${TMP}/go-ranges-assembled.$$"
  : > "$assembled"
  for ((i=0; i<chunk_count; i++)); do
    part="${workdir}/chunk-$(printf '%02d' "$i").part"
    [[ -f "$part" ]] || { rm -f "$assembled"; return 1; }
    cat "$part" >> "$assembled" || { rm -f "$assembled"; return 1; }
  done
  if [[ "$(wc -c < "$assembled")" -ne "$total" ]] ||
      ! printf '%s  %s\n' "$expected_sha" "$assembled" | sha256sum -c - >/dev/null 2>&1; then
    rm -f "$assembled"
    rm -rf "$workdir"
    return 1
  fi
  mv -f "$assembled" "$dest"
  return 0
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
run_with_spinner() {
  local label="$1" logfile="$2" rc=0 pid frame=0
  shift 2
  : > "$logfile"
  if [[ ! -t 2 ]]; then
    "$@" >"$logfile" 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
      cat "$logfile" >&2
      return "$rc"
    fi
    return 0
  fi
  "$@" >"$logfile" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    draw_indeterminate_bar "$frame"
    frame=$((frame + 1))
    sleep 0.12
  done
  wait "$pid" || rc=$?
  printf '\r\033[2K' >&2
  if [[ "$rc" -ne 0 ]]; then
    printf 'ERROR: background command failed (exit %s).\n' "$rc" >&2
    cat "$logfile" >&2
    return "$rc"
  fi
  # Keep successful command output hidden; only the animated pink bar is shown.
}
verify_binary() {
  [[ -s "$TMP/S1T-CORE" ]] || return 1
  chmod 0750 "$TMP/S1T-CORE"
  timeout --kill-after=1s 5s "$TMP/S1T-CORE" version 2>/dev/null \
    | grep -Fqx "Shah Tunnel ${VERSION} (linux/${TARGET_ARCH})"
}
official_go_sha256() {
  case "$TARGET_ARCH" in
    amd64) printf '%s' '031f088e5d955bab8657ede27ad4e3bc5b7c1ba281f05f245bcc304f327c987a' ;;
    arm64) printf '%s' 'a290581cfe4fe28ddd737dde3095f3dbeb7f2e4065cab4eae44dfc53b760c2f7' ;;
    *) return 1 ;;
  esac
}

build_project_binary() {
  local go_bin="$1" source_dir="$2" go_root="$3"
  (
    cd "$source_dir"
    env GOROOT="$go_root" GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
      GOCACHE="${GO_CACHE_DIR}/build-cache-${GO_VERSION}-${TARGET_ARCH}" \
      CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" \
      "$go_bin" build -trimpath -ldflags='-s -w -buildid=' \
      -o "$TMP/S1T-CORE" ./S1T-CAPSULE
  )
}
build_from_official_go_toolchain() {
  local go_archive go_sha source_url go_bin go_root source_dir expected_go url downloaded script_dir
  go_archive="go${GO_VERSION}.linux-${TARGET_ARCH}.tar.gz"
  go_sha="$(official_go_sha256)"
  source_url="https://codeload.github.com/${OWNER}/${REPO}/tar.gz/refs/heads/main"
  expected_go="go version go${GO_VERSION} linux/${TARGET_ARCH}"
  source_dir="$TMP/source"
  go_bin=""
  go_root=""

  phase_start 2 "Download verified Go toolchain and source"
  local cache_archive="$GO_CACHE_DIR/$go_archive"
  local toolchain_path="${STATE_DIR}/toolchains/go${GO_VERSION}-${TARGET_ARCH}"
  local toolchain_new="${toolchain_path}.new"
  install -d -o root -g root -m 0755 "$GO_CACHE_DIR" "${STATE_DIR}/toolchains"
  downloaded=0

  # A stable, previously verified toolchain avoids re-extracting Go on every
  # run and keeps GOCACHE effective across installations.
  if [[ -x "$toolchain_path/bin/go" ]] &&
      [[ "$(GOROOT="$toolchain_path" GOTOOLCHAIN=local "$toolchain_path/bin/go" version 2>/dev/null || true)" == "$expected_go" ]]; then
    go_root="$toolchain_path"
    go_bin="$go_root/bin/go"
    downloaded=1
    echo "Reusing installed, verified Go ${GO_VERSION} toolchain." >&2
  else
    # Reuse only an archive whose checksum matches the pinned Go distribution.
    if [[ -s "$cache_archive" ]] && printf '%s  %s\n' "$go_sha" "$cache_archive" | sha256sum -c - >/dev/null 2>&1; then
      cp -f "$cache_archive" "$TMP/$go_archive"
      echo "Using cached, SHA-256-verified Go ${GO_VERSION} archive." >&2
      downloaded=1
    else
      rm -f "$cache_archive"
      # Use parallel ranges first for mirrors that support them; if a mirror
      # lacks byte-range support, fall back to the resumable single-stream path.
      local -a download_sources=(
        "aliyun|https://mirrors.aliyun.com/golang"
        "nju|https://mirror.nju.edu.cn/golang"
        "ustc|https://mirrors.ustc.edu.cn/golang"
        "tsinghua|https://mirrors.tuna.tsinghua.edu.cn/golang"
        "tencent|https://mirrors.cloud.tencent.com/go"
        "163|https://mirrors.163.com/golang"
        "google|https://dl.google.com/go"
        "go-dev|https://go.dev/dl"
        "google-storage|https://storage.googleapis.com/golang"
        "google-cn|https://golang.google.cn/dl"
      )
      local source source_id base part_file bytes
      echo "Downloading Go ${GO_VERSION} (${TARGET_ARCH}) using parallel range requests where supported..." >&2
      for source in "${download_sources[@]}"; do
        source_id="${source%%|*}"
        base="${source#*|}"
        url="${base}/${go_archive}"
        part_file="${GO_CACHE_DIR}/${go_archive}.${source_id}.part"
        echo "Trying ${base}..." >&2

        if [[ -s "$part_file" ]] && printf '%s  %s\n' "$go_sha" "$part_file" | sha256sum -c - >/dev/null 2>&1; then
          cp -f "$part_file" "$TMP/$go_archive"
          downloaded=1
          echo "Using complete SHA-256-verified archive from ${source_id}." >&2
          break
        fi

        RANGE_DOWNLOAD_ATTEMPTED=0
        if curl_download_parallel_ranges "$url" "$part_file" "$go_sha"; then
          cp -f "$part_file" "$TMP/$go_archive"
          downloaded=1
          echo "Parallel download from ${source_id} passed SHA-256 verification." >&2
          break
        fi
        if [[ "$RANGE_DOWNLOAD_ATTEMPTED" == 1 ]]; then
          echo "Parallel chunks were incomplete at ${source_id}; moving to the next mirror instead of restarting a slow full download." >&2
          continue
        fi
        echo "${source_id} does not support a usable byte-range response; trying a time-limited single stream..." >&2
        if curl_download_resumable "$url" "$part_file" 35 0 15; then
          if printf '%s  %s\n' "$go_sha" "$part_file" | sha256sum -c - >/dev/null 2>&1; then
            cp -f "$part_file" "$TMP/$go_archive"
            downloaded=1
            echo "Resumable download from ${source_id} passed SHA-256 verification." >&2
            break
          fi
          bytes="$(wc -c < "$part_file" 2>/dev/null || printf '0')"
          echo "Checksum mismatch from ${source_id} (${bytes} bytes); discarding its single-stream partial." >&2
          rm -f "$part_file"
        else
          bytes="$(wc -c < "$part_file" 2>/dev/null || printf '0')"
          echo "Download failed from ${source_id} (${bytes} bytes retained for the same mirror)." >&2
        fi
      done
      if [[ "$downloaded" -eq 1 ]]; then
        # Cache only a fully downloaded and verified archive.
        install -o root -g root -m 0644 "$TMP/$go_archive" "$cache_archive"
      fi
    fi

    if [[ "$downloaded" -ne 1 ]]; then
      echo "ERROR: Could not obtain a Go ${GO_VERSION} archive matching the pinned SHA-256." >&2
      return 1
    fi
    echo "Go archive SHA-256 verified." >&2
    rm -rf "$TMP/go-root" "$toolchain_new"
    mkdir -p "$TMP/go-root"
    if ! tar -xzf "$TMP/$go_archive" -C "$TMP/go-root"; then
      echo "Downloaded Go archive could not be extracted." >&2
      return 1
    fi
    go_root="$TMP/go-root/go"
    go_bin="$go_root/bin/go"
    if [[ ! -x "$go_bin" ]]; then
      echo "Go archive did not contain the expected bin/go executable." >&2
      return 1
    fi
    if [[ "$(GOROOT="$go_root" GOTOOLCHAIN=local "$go_bin" version 2>/dev/null || true)" != "$expected_go" ]]; then
      echo "Unexpected Go toolchain version or architecture; expected: $expected_go" >&2
      return 1
    fi
    # Install the verified toolchain to a stable location. The build cache is
    # keyed to this path and can be reused on future runs.
    mv "$go_root" "$toolchain_new"
    rm -rf "$toolchain_path"
    mv "$toolchain_new" "$toolchain_path"
    go_root="$toolchain_path"
    go_bin="$go_root/bin/go"
  fi

  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  mkdir -p "$source_dir"
  if [[ -n "$script_dir" && -s "$script_dir/go.mod" && -s "$script_dir/S1T-CAPSULE/main.go" ]]; then
    echo "Building from the local ShahTunnel source beside S1T-START.sh..." >&2
    if ! cp -a "$script_dir/go.mod" "$source_dir/" ||
       ! cp -a "$script_dir/S1T-CAPSULE" "$source_dir/"; then
      echo "Could not copy the local ShahTunnel source tree." >&2
      return 1
    fi
    if [[ -f "$script_dir/go.sum" ]]; then
      cp -a "$script_dir/go.sum" "$source_dir/" || return 1
    fi
  else
    echo "Downloading ShahTunnel source from ${OWNER}/${REPO} (main branch)..." >&2
    if ! curl_download "$source_url" "$TMP/shah-tunnel-source.tar.gz" \
        --retry 2 --retry-delay 1 --connect-timeout 12 --max-time 180; then
      echo "Could not download the source archive from ${source_url}." >&2
      return 1
    fi
    if ! tar -xzf "$TMP/shah-tunnel-source.tar.gz" -C "$source_dir" --strip-components=1; then
      echo "Could not extract the ShahTunnel source archive." >&2
      return 1
    fi
  fi
  [[ -s "$source_dir/go.mod" && -s "$source_dir/S1T-CAPSULE/main.go" ]] \
    || { echo "The downloaded repository does not contain the expected ShahTunnel source files." >&2; return 1; }
  if ! grep -Fq "module github.com/${OWNER}/${REPO}" "$source_dir/go.mod"; then
    echo "The source module path does not match github.com/${OWNER}/${REPO}; refusing to build." >&2
    return 1
  fi
  local source_fingerprint build_cache_dir cached_binary
  source_fingerprint="$(cd "$source_dir" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
  build_cache_dir="${STATE_DIR}/builds"
  cached_binary="${build_cache_dir}/shah-tunnel-${VERSION}-${GO_VERSION}-${TARGET_ARCH}-${source_fingerprint}"
  install -d -o root -g root -m 0755 "$build_cache_dir"
  if [[ -s "$cached_binary" ]] && timeout --kill-after=1s 5s "$cached_binary" version 2>/dev/null | grep -Fqx "Shah Tunnel ${VERSION} (linux/${TARGET_ARCH})"; then
    cp -f "$cached_binary" "$TMP/S1T-CORE"
    echo "Reusing cached ShahTunnel binary for this exact source revision." >&2
  else
    echo "Building Shah Tunnel ${VERSION} with verified Go ${GO_VERSION}..." >&2
    if ! run_with_spinner "Building ShahTunnel" "$TMP/build.log" build_project_binary "$go_bin" "$source_dir" "$go_root"; then
      echo "Source build failed. Build output follows:" >&2
      [[ ! -s "$TMP/build.log" ]] || cat "$TMP/build.log" >&2
      return 1
    fi
    if ! verify_binary; then
      echo "Built binary version or architecture validation failed; refusing to cache it." >&2
      return 1
    fi
    install -o root -g root -m 0750 "$TMP/S1T-CORE" "${cached_binary}.new"
    mv -f "${cached_binary}.new" "$cached_binary"
  fi

  if ! verify_binary; then
    echo "Built binary version or architecture validation failed; refusing to install it." >&2
    return 1
  fi
  phase_done "Source-built binary verified"
  return 0
}

remove_legacy_warp_ssh_bypass() {
  # Older builds installed a global-route workaround. Remove only rules that
  # this helper created (SSH source ports, priorities 80..140, lookup main).
  local family port line pref ports_file="/etc/shah-tunnel/warp-ssh-ports"
  if [[ -r "$ports_file" ]] && command -v ip >/dev/null 2>&1; then
    while read -r port; do
      [[ "$port" =~ ^[0-9]+$ ]] || continue
      for family in -4 -6; do
        while IFS= read -r line; do
          pref="${line%%:*}"
          [[ "$pref" =~ ^[0-9]+$ ]] || continue
          if (( pref >= 80 && pref <= 140 )) && grep -Eq "ipproto tcp sport ${port}([[:space:]]|$).*lookup main|lookup main.*ipproto tcp sport ${port}([[:space:]]|$)" <<<"$line"; then
            ip "$family" rule del priority "$pref" ipproto tcp sport "$port" lookup main 2>/dev/null || true
          fi
        done < <(ip "$family" rule show 2>/dev/null || true)
      done
    done < "$ports_file"
  fi
  systemctl disable --now shah-tunnel-warp-ssh-bypass.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/shah-tunnel-warp-ssh-bypass.service
  rm -f /usr/local/sbin/shah-tunnel-warp-ssh-bypass
  rm -f /etc/systemd/system/warp-svc.service.d/10-shah-tunnel-ssh-bypass.conf
  rmdir /etc/systemd/system/warp-svc.service.d 2>/dev/null || true
  rm -f "$ports_file"
  systemctl daemon-reload
}

CLOUDFLARE_WARP_FALLBACK_VERSION="2026.8.2115.0"
CLOUDFLARE_WARP_KEY_FINGERPRINT="C068A2B5771775193CBE1F2F6E2DD2174FA1C3BA"

cloudflare_warp_prepare_repository_key() {
  local key_asc="$1" key_tmp="$2" fingerprint expiry now
  # Prefer Cloudflare's live endpoint. If this hostname is filtered on an
  # Iranian VPS, use the current public key fetched from that same official
  # endpoint during release preparation. Its full fingerprint is pinned below.
  if ! curl -fLsS --retry 1 --retry-delay 1 --connect-timeout 6 --max-time 18 \
      https://pkg.cloudflareclient.com/pubkey.gpg -o "$key_asc" 2>/dev/null || [[ ! -s "$key_asc" ]]; then
    echo "Cloudflare key host is unreachable; using the pinned current Cloudflare signing key." >&2
    cat > "$key_asc" <<'CLOUDFLARE_WARP_PUBLIC_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGGr2jUBEADHaae1uIKW4JI/E32IR9EJSswkOuZl1J+XXH32U2u3DGtzGuei
dNXyeQ7AWHp5bM2wO7jGRqH/IwiDVHzp6gmJ8r/SFrE+iljNA71LVXY7FjaOGmKC
pZnzl3mlY9zsRgmM+oEbTedg2k1jfeHWiYJfTk4efDUGNqF4D62GBFLpOheeXtNU
DHuZjcRBFKO3wjt3wPpuUx+/NoHrxWK2HZxL6cHUHxmqOHlemGAvZug0pkeAWaAb
YYmlwsi9/KbnZ22poCfubCebeLIIC4GrQd5ZdJn3efa1ps41gHG/s0RpoQvC128x
ZQDfdjskuXA0IlDUwzGK2qeY2PEbHpPAH02cm2JrO0NkVBO/4tJ3QkrBRdkOoS1C
PZRFkzaamA7kZb03wHHLqMZ4lpw+Aa4w0jihndQUvxi9HQVmzjYW1HeQXHmVPdNc
MT6Y/XxFUFfz65zpZy6s5e8250yIaiNtTuvpcXebmkx0uM4naQFjSJTTlrNeXM/L
67JppgInRXwlaevNBTm24HhJy0zef1Gpnt6xJDtCX2qNg0GhbuJXbFhgSF1Ct7eY
tZsfx6UbEXdkwEtcrIAXIqrVjenqcvh8w47I06rqKEoiMliQxh/WrIjTDCsIq/LB
ki820eS6GsJ5N2JmZ2CQ7Kt+y/Gx9uMDmUcCnHY10vX+Va66/GKMX+vbKQARAQAB
tDZDbG91ZGZsYXJlIFBhY2thZ2UgUmVwb3NpdG9yeSA8c3VwcG9ydEBjbG91ZGZs
YXJlLmNvbT6JAlIEEwEIADwCGwMFCwkIBwIDIgIBBhUKCQgLAgQWAgMBAh4HAheA
FiEEwGiitXcXdRk8vh8vbi3SF0+hw7oFAmi5UcQACgkQbi3SF0+hw7pmgBAAudow
XU2c8W2t2R6letWslBDd9M13ME9r8b4do/bN2av1xoXHNk1bTPC//1O+JWJPzzHG
EwRd1XK1U53umPgSQ21RXSWba71iYdfVUnbPBwbmbv4Cp/7kTwMBJsoPxAzyWGkT
p/u5joDS9KU/85vZeTUNLHrxfuDhMH2elzHYAPsBkqxPosEcgnTmMFZ/4ueZwIn4
s3sFGUl1kiFhqVn7f2g+PbSC5UI367+mx9Gcw/Ti7NXeYQFrlaMJePpYbmvkdjC2
Kz+3CVhd+qOSq65bDHI+bW/sqRXmqdUc+lwkCyBhgtrZdTa6e5GFcubagn6U5FQ3
X1Inv2VDPhiTUKj8S5oTQDErdKyRSlqTj7ZibuXetvsFascJVnsEEQH/lsHUGk7N
i281X63qRCn+Iv2wB7tAnH1upifl9tS5ouWhu5MVFJUJ9cJPo+naSksf6M0DROLp
YFX+33IqDDE2bGbQwBUX0TqHOW6Pl/oWnS18EnNvqIRhzVYX/obJvA6sFVF0k4hp
zEkGCdpAzh/6P27ZvnN8cjlDMgB3c1HdPLQbjZnQ0JbZ6lzyNorwx8rRmxLpgMZd
k6veLbWGG1tW8oPuuKWfgYVD00BMmJpyNqs2D30njtbkdZ1cRUyqhxS9BZw88Qb0
TbOm+GteogZ9IbLvjaxCwaojBBzZqXrwGAa4Fso=
=cDDg
-----END PGP PUBLIC KEY BLOCK-----
CLOUDFLARE_WARP_PUBLIC_KEY
  fi

  if ! gpg --batch --show-keys "$key_asc" >/dev/null 2>&1; then
    echo "ERROR: Cloudflare signing key is not a valid OpenPGP key; refusing to install WARP." >&2
    return 1
  fi
  fingerprint="$(gpg --batch --with-colons --show-keys "$key_asc" 2>/dev/null | awk -F: '$1=="fpr" {print toupper($10); exit}')"
  expiry="$(gpg --batch --with-colons --show-keys "$key_asc" 2>/dev/null | awk -F: '$1=="pub" {print $7; exit}')"
  now="$(date +%s)"
  if [[ "$fingerprint" != "$CLOUDFLARE_WARP_KEY_FINGERPRINT" ]]; then
    echo "ERROR: Cloudflare signing-key fingerprint mismatch; refusing to install WARP." >&2
    return 1
  fi
  if [[ -n "$expiry" && "$expiry" =~ ^[0-9]+$ ]] && (( expiry <= now )); then
    echo "ERROR: Cloudflare signing key is expired; refusing to install WARP." >&2
    return 1
  fi
  if ! gpg --batch --yes --dearmor --output "$key_tmp" "$key_asc" || [[ ! -s "$key_tmp" ]]; then
    echo "ERROR: Could not convert the verified Cloudflare signing key." >&2
    return 1
  fi
  return 0
}

cloudflare_warp_install_official_download() {
  local arch platform url deb package version package_arch
  arch="$(dpkg --print-architecture 2>/dev/null || true)"
  case "$arch" in
    amd64) platform="ubuntu" ;;
    arm64) platform="ubuntu-arm" ;;
    *) echo "WARNING: No Cloudflare Ubuntu download mapping for architecture ${arch:-unknown}." >&2; return 1 ;;
  esac
  deb="$TMP/cloudflare-warp-official.deb"
  # These are Cloudflare's own stable-download endpoints. They are a fallback
  # for Iranian VPS networks where pkg.cloudflareclient.com is unreachable.
  local urls=(
    "https://downloads.cloudflareclient.com/v1/download/${platform}/version/${CLOUDFLARE_WARP_FALLBACK_VERSION}"
    "https://downloads.cloudflareclient.com/v1/download/${platform}/ga"
  )
  for url in "${urls[@]}"; do
    echo "Trying Cloudflare official Linux package download: ${url}" >&2
    if ! curl_download "$url" "$deb" --retry 2 --retry-delay 2 --connect-timeout 12 --max-time 300; then
      rm -f "$deb"
      continue
    fi
    if ! command -v dpkg-deb >/dev/null 2>&1; then
      echo "WARNING: dpkg-deb is unavailable; cannot verify the downloaded package metadata." >&2
      rm -f "$deb"
      return 1
    fi
    package="$(dpkg-deb -f "$deb" Package 2>/dev/null || true)"
    version="$(dpkg-deb -f "$deb" Version 2>/dev/null || true)"
    package_arch="$(dpkg-deb -f "$deb" Architecture 2>/dev/null || true)"
    if [[ "$package" != "cloudflare-warp" || ( "$package_arch" != "$arch" && "$package_arch" != "all" ) || -z "$version" ]]; then
      echo "WARNING: Download endpoint did not return a matching cloudflare-warp package; rejecting it." >&2
      rm -f "$deb"
      continue
    fi
    echo "Cloudflare package verified: ${package} ${version} (${package_arch}). Installing..." >&2
    if DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" install -y "$deb"; then
      rm -f "$deb"
      echo "Cloudflare WARP installed from Cloudflare's official download service." >&2
      return 0
    fi
    echo "WARNING: Official package downloaded, but Ubuntu dependencies could not be installed." >&2
    rm -f "$deb"
  done
  return 1
}

install_cloudflare_warp() {
  # /etc/os-release defines VERSION globally when sourced. Keep the product
  # version local and unchanged so Ubuntu's marketing version cannot overwrite
  # the Shah Tunnel version used by binary verification.
  local VERSION="${VERSION}"
  local distro codename key_tmp key_asc repo_file reg_out answer status_out terms_file key_ready
  local apt_opts=(-o Acquire::Retries=1 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10)
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "WARNING: Automatic Cloudflare WARP installation is supported by this installer on Ubuntu/Debian only." >&2
    return 0
  fi
  . /etc/os-release
  distro="${ID:-unknown}"
  codename="${VERSION_CODENAME:-}"
  case "$distro" in
    ubuntu|debian) ;;
    *)
      echo "WARNING: Cloudflare WARP auto-install skipped on unsupported apt distro: $distro" >&2
      return 0
      ;;
  esac
  if [[ -z "$codename" ]]; then
    echo "ERROR: Could not determine the OS codename; refusing to add an incorrect Cloudflare repository." >&2
    return 1
  fi
  repo_file="/etc/apt/sources.list.d/cloudflare-client.list"
  terms_file="/etc/shah-tunnel/cloudflare-terms-consented"
  if ! command -v warp-cli >/dev/null 2>&1; then
    echo "Installing Cloudflare WARP automatically for ${distro} ${codename}..." >&2
    local -a missing_pkgs=()
    command -v gpg >/dev/null 2>&1 || missing_pkgs+=(gpg)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || missing_pkgs+=(ca-certificates)
    command -v ip >/dev/null 2>&1 || missing_pkgs+=(iproute2)
    if ((${#missing_pkgs[@]})); then
      if ! apt-get "${apt_opts[@]}" update; then
        echo "WARNING: APT dependency indexes could not be refreshed; WARP installation is skipped safely." >&2
        return 1
      fi
      if ! DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" install -y curl "${missing_pkgs[@]}"; then
        echo "WARNING: Required WARP prerequisites could not be installed; WARP installation is skipped safely." >&2
        return 1
      fi
    fi

    install -d -o root -g root -m 0755 /usr/share/keyrings
    key_tmp="$TMP/cloudflare-warp-archive-keyring.gpg"
    key_asc="$TMP/cloudflare-warp-pubkey.gpg.asc"
    key_ready=0
    # Official live key first; a pinned copy of the current official key is
    # used automatically when Iran routing blocks the pkg.cloudflareclient.com hostname.
    if cloudflare_warp_prepare_repository_key "$key_asc" "$key_tmp"; then
      key_ready=1
    fi

    if [[ "$key_ready" -eq 1 ]]; then
      install -o root -g root -m 0644 "$key_tmp" /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
      printf 'deb [arch=%s signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main\n' \
        "$(dpkg --print-architecture)" "$codename" > "$TMP/cloudflare-client.list"

      # Only persist the repository after its own index refresh succeeds.
      if apt-get "${apt_opts[@]}" \
          -o Dir::Etc::sourcelist="$TMP/cloudflare-client.list" \
          -o Dir::Etc::sourceparts="-" \
          -o APT::Get::List-Cleanup=0 update; then
        install -o root -g root -m 0644 "$TMP/cloudflare-client.list" "$repo_file"
        if ! DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" install -y cloudflare-warp; then
          echo "WARNING: Cloudflare APT package installation failed; switching to Cloudflare's official package download." >&2
          rm -f "$repo_file"
          if ! cloudflare_warp_install_official_download; then return 1; fi
        fi
      else
        echo "WARNING: pkg.cloudflareclient.com is unreachable from this VPS; trying Cloudflare's official download service." >&2
        rm -f "$repo_file"
        if ! cloudflare_warp_install_official_download; then
          echo "WARNING: Cloudflare's official download endpoints are also unreachable. WARP setup cannot complete on this network." >&2
          return 1
        fi
      fi
    else
      echo "WARNING: Cloudflare APT signing key could not be downloaded from Iran; trying Cloudflare's official package download service." >&2
      if ! cloudflare_warp_install_official_download; then
        echo "WARNING: Cloudflare package repository and official download service are both unreachable. WARP setup cannot complete on this network." >&2
        return 1
      fi
    fi
  else
    echo "Cloudflare WARP already installed; keeping its existing registration and configuration." >&2
  fi
  command -v warp-cli >/dev/null 2>&1 || { echo "WARNING: cloudflare-warp package installed but warp-cli is missing; WARP setup is skipped safely." >&2; return 1; }
  if ! warp-cli --version; then
    echo "WARNING: warp-cli could not communicate with its installation; WARP setup is skipped safely." >&2
    return 1
  fi

  # Remove only the obsolete Shah Tunnel global-route SSH workaround.
  # WARP Local Proxy mode keeps the host default route untouched.
  remove_legacy_warp_ssh_bypass
  # Disconnect a previously active system-wide WARP session before changing
  # its mode; never allow a failed proxy-mode command to be followed by connect.
  warp-cli disconnect >/dev/null 2>&1 || true
  if systemctl list-unit-files warp-svc.service --no-legend 2>/dev/null | grep -q 'warp-svc.service'; then
    if ! systemctl enable --now warp-svc.service >/dev/null; then
      echo "WARNING: warp-svc.service could not be started; WARP setup is skipped safely." >&2
      return 1
    fi
  else
    echo "WARNING: cloudflare-warp is present but warp-svc.service is missing; WARP setup is skipped safely." >&2
    return 1
  fi
  warp-cli disconnect >/dev/null 2>&1 || true

  # Cloudflare terms are accepted only after an explicit interactive approval.
  if [[ ! -s "$terms_file" ]]; then
    echo "Cloudflare Terms of Service and Privacy Policy must be accepted before WARP registration/configuration." >&2
    if [[ ! -r /dev/tty ]]; then
      echo "No interactive terminal is available; WARP is installed but remains unregistered/disconnected." >&2
      return 0
    fi
    read -r -p "Accept Cloudflare Terms of Service and Privacy Policy for this server? [y/N] " answer </dev/tty
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
      echo "Cloudflare terms were not accepted; WARP remains installed but disconnected." >&2
      return 0
    fi
    printf 'accepted-on %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$TMP/cloudflare-terms-consented"
    install -d -o root -g root -m 0700 /etc/shah-tunnel
    install -o root -g root -m 0600 "$TMP/cloudflare-terms-consented" "$terms_file"
  fi

  reg_out="$(warp-cli registration show 2>&1 || true)"
  if [[ -z "$reg_out" ]] || grep -Eiq 'not registered|no registration|unregistered' <<<"$reg_out"; then
    if ! warp-cli --accept-tos registration new; then
      echo "WARNING: WARP registration failed; leaving it disconnected." >&2
      warp-cli disconnect >/dev/null 2>&1 || true
      return 1
    fi
  fi
  # Configure every setting explicitly. Because this function is called in a
  # recoverable `if !` block, errexit is not sufficient here: check each command
  # and NEVER run connect unless Local Proxy mode was accepted.
  if ! warp-cli --accept-tos tunnel protocol set MASQUE; then
    echo "WARNING: WARP could not select MASQUE; leaving it disconnected." >&2
    warp-cli disconnect >/dev/null 2>&1 || true
    return 1
  fi
  if ! warp-cli --accept-tos mode proxy; then
    echo "WARNING: WARP Local Proxy mode is unavailable; refusing a system-wide WARP connection." >&2
    warp-cli disconnect >/dev/null 2>&1 || true
    return 1
  fi
  if ! warp-cli --accept-tos proxy port 40000; then
    echo "WARNING: WARP SOCKS5 proxy port could not be configured; leaving WARP disconnected." >&2
    warp-cli disconnect >/dev/null 2>&1 || true
    return 1
  fi

  # Snapshot effective host routes. Local Proxy must not replace IPv4/IPv6
  # egress, which also protects the return route for the active SSH session.
  if ! command -v ip >/dev/null 2>&1; then
    echo "WARNING: iproute2 is unavailable; refusing to connect WARP without route-safety checks." >&2
    warp-cli disconnect >/dev/null 2>&1 || true
    return 1
  fi
  local route4_before route6_before route4_after route6_after ssh_peer route_ssh_before route_ssh_after
  route4_before="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"||$i=="dev"||$i=="src"||$i=="table") printf "%s %s ",$i,$(i+1)}')"
  route6_before="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"||$i=="dev"||$i=="src"||$i=="table") printf "%s %s ",$i,$(i+1)}')"
  ssh_peer=""
  route_ssh_before=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    ssh_peer="${SSH_CONNECTION%% *}"
    route_ssh_before="$(ip route get "$ssh_peer" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"||$i=="dev"||$i=="src"||$i=="table") printf "%s %s ",$i,$(i+1)}')"
  fi
  if ! warp-cli --accept-tos connect; then
    echo "WARNING: WARP could not connect in Local Proxy mode; leaving it disconnected." >&2
    warp-cli disconnect >/dev/null 2>&1 || true
    return 1
  fi
  for _ in $(seq 1 30); do
    status_out="$(warp-cli status 2>&1 || true)"
    if grep -Eiq '^Status update:[[:space:]]*Connected' <<<"$status_out"; then
      break
    fi
    sleep 2
  done
  if grep -Eiq '^Status update:[[:space:]]*Connected' <<<"$status_out"; then
    route4_after="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"||$i=="dev"||$i=="src"||$i=="table") printf "%s %s ",$i,$(i+1)}')"
    route6_after="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"||$i=="dev"||$i=="src"||$i=="table") printf "%s %s ",$i,$(i+1)}')"
    route_ssh_after="$route_ssh_before"
    if [[ -n "$route_ssh_before" ]]; then
      route_ssh_after="$(ip route get "$ssh_peer" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"||$i=="dev"||$i=="src"||$i=="table") printf "%s %s ",$i,$(i+1)}')"
    fi
    if { [[ -n "$route4_before" && "$route4_after" != "$route4_before" ]] ||
         [[ -n "$route6_before" && "$route6_after" != "$route6_before" ]] ||
         [[ -n "$route_ssh_before" && "$route_ssh_after" != "$route_ssh_before" ]]; }; then
      echo "WARNING: WARP changed an effective host route; disconnecting it to protect SSH and ordinary traffic." >&2
      warp-cli disconnect >/dev/null 2>&1 || true
      return 1
    fi
    if curl --silent --show-error --fail --connect-timeout 5 --max-time 12 \
      --socks5-hostname 127.0.0.1:40000 \
      https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -qx 'warp=on'; then
      echo "Cloudflare WARP is connected in MASQUE Local Proxy mode on 127.0.0.1:40000." >&2
      echo "Only explicitly configured Shah Tunnel carrier connections will use WARP; SSH and other server traffic remain on the normal route." >&2
    else
      echo "WARNING: WARP is connected, but its local SOCKS5 proxy did not pass the warp=on test; disconnecting WARP." >&2
      warp-cli disconnect >/dev/null 2>&1 || true
      return 1
    fi
  else
    echo "WARNING: WARP is installed and configured for MASQUE Local Proxy mode but is not connected:" >&2
    printf '%s\n' "$status_out" >&2
    warp-cli disconnect >/dev/null 2>&1 || true
    return 1
  fi
}

# Prepare WARP in Local Proxy mode; do not change the host default route.
phase_start 1 "Installing Cloudflare WARP Local Proxy"
if ! install_cloudflare_warp; then
  echo "WARNING: Cloudflare WARP auto-setup failed. Continuing with Shah Tunnel; WARP-dependent Agent paths will stay unavailable until WARP is healthy." >&2
fi
if ! build_from_official_go_toolchain; then
  echo "Installation stopped: no verified ShahTunnel binary was built." >&2
  echo "Go archives must match the pinned SHA-256; ShahTunnel is built locally without GitHub Release assets." >&2
  exit 1
fi
phase_start 3 "Installing Shah Tunnel"
install -d -o root -g root -m 0700 /etc/ravanreverse
install -d -o root -g root -m 0700 /etc/ravanreverse/tunnels
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
fi
cat > "$TMP/ravanreverse@.service" <<'UNIT'
[Unit]
Description=Shah Tunnel authenticated reverse TCP tunnel (%i)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=10
[Service]
Type=simple
UMask=0077
ExecStart=/usr/local/bin/ravanreverse run --config /etc/ravanreverse/tunnels/%i.json
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
install -o root -g root -m 0644 "$TMP/ravanreverse@.service" /etc/systemd/system/ravanreverse@.service
if ! timeout --kill-after=3s 15s systemctl daemon-reload; then
  echo "systemd daemon-reload timed out. The binary is installed, but service metadata may need: systemctl daemon-reload" >&2
  exit 1
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
