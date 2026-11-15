#!/usr/bin/env bash
set -Eeuo pipefail
# Shah Tunnel 5.0.2 installer.
# Downloads the pinned Go 1.26.11 toolchain, verifies its SHA-256, validates the exact
# ShahTunnel build-input SHA-256, and builds locally. No prebuilt release binary is used.
OWNER="ShahNetLab"
REPO="ShahTunnel"
VERSION="5.0.2"
GO_VERSION="1.26.11"
# SHA-256 over the exact build inputs (go.mod, S1T-CAPSULE/, scripts/).
# Updated only when a reviewed source change is intentionally released.
SOURCE_INPUT_SHA256="cbdcbb6894929d8f7d22524bb0d0e58dfe31d6bbc3caf88fdf36d125f83171fe"
GO_BASE="https://dl.google.com/go"
GO_FALLBACK_BASE="https://go.dev/dl"
STATE_DIR="/usr/local/lib/shah-tunnel"
GO_CACHE_DIR="/var/cache/shah-tunnel"
PHASE_HAS_DOWNLOAD=0
case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) TARGET_ARCH="amd64" ;;
  Linux:aarch64|Linux:arm64) TARGET_ARCH="arm64" ;;
  *) echo "Shah Tunnel ${VERSION} supports Linux amd64 and arm64 only." >&2; exit 1 ;;
esac
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root. If raw.githubusercontent.com is blocked, fetch this installer through the GitHub API:" >&2
  echo "set -o pipefail; curl -fsSL --connect-timeout 10 --max-time 30 -H 'Accept: application/vnd.github+json' -H 'User-Agent: ShahTunnel-bootstrap' 'https://api.github.com/repos/${OWNER}/${REPO}/contents/S1T-START.sh?ref=main' | python3 -c 'import sys,json,base64; d=json.load(sys.stdin); sys.stdout.buffer.write(base64.b64decode(d[\"content\"]))' | bash" >&2
  exit 1
fi
command -v systemctl >/dev/null 2>&1 || { echo "systemd/systemctl is required." >&2; exit 1; }
for cmd in curl sha256sum install mv grep cp ln date timeout awk cat chmod tar gzip mktemp rm sleep python3 wc sed tail sort xargs find; do
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
    amd64) printf '%s' '9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec' ;;
    arm64) printf '%s' '6c2f29b458b5add0835f18b776f69c8881a6d88428f1484a6da55755e620757e' ;;
    *) return 1 ;;
  esac
}

source_fingerprint() {
  # Hash only the files that influence the compiled program or managed helper
  # installers. This is a content pin: a moving Git branch cannot silently
  # change what this version builds.
  python3 - "$1" <<'PY_SOURCE_FINGERPRINT'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
files = [root / "go.mod"]
if (root / "go.sum").is_file():
    files.append(root / "go.sum")
for directory in ("S1T-CAPSULE", "scripts"):
    base = root / directory
    if not base.is_dir():
        raise SystemExit(f"missing source input directory: {directory}")
    for path in base.rglob("*"):
        # Python bytecode/cache files are generated by local tests and are not
        # source inputs. Exclude them consistently on the build host and CI.
        if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
            continue
        if path.is_symlink():
            raise SystemExit(f"symlink not permitted in pinned source inputs: {path}")
        if path.is_file():
            files.append(path)
if not files or not (root / "go.mod").is_file():
    raise SystemExit("missing go.mod or source inputs")
files.sort(key=lambda path: path.relative_to(root).as_posix())
digest = hashlib.sha256()
for path in files:
    relative = path.relative_to(root).as_posix().encode("utf-8")
    content_digest = hashlib.sha256(path.read_bytes()).digest()
    digest.update(relative + b"\0" + content_digest + b"\0")
print(digest.hexdigest())
PY_SOURCE_FINGERPRINT
}

build_project_binary() {
  local go_bin="$1" source_dir="$2" go_root="$3"
  (
    cd "$source_dir"
    env GOROOT="$go_root" GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS= \
      GOPROXY=off GOSUMDB=off GOCACHE="${GO_CACHE_DIR}/build-cache-${GO_VERSION}-${TARGET_ARCH}" \
      CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" \
      "$go_bin" build -mod=readonly -trimpath -ldflags='-s -w -buildid=' \
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

  phase_start 1 "Download verified Go toolchain and source"
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
    if [[ -d "$script_dir/scripts" ]]; then
      cp -a "$script_dir/scripts" "$source_dir/" || return 1
    else
      mkdir -p "$source_dir/scripts"
      for helper in install-psiphon.sh install-tor.sh repair-psiphon-profile.sh; do
        [[ -s "$script_dir/$helper" ]] && cp -a "$script_dir/$helper" "$source_dir/scripts/" || {
          echo "Missing required helper: $helper" >&2; return 1;
        }
      done
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
    if ! python3 - "$TMP/shah-tunnel-source.tar.gz" "$source_dir" <<'PY_SAFE_SOURCE_ARCHIVE'
import os, pathlib, shutil, sys, tarfile
archive, destination = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
max_members, max_total, max_file = 100000, 2 * 1024**3, 512 * 1024**2
destination.mkdir(mode=0o700, parents=True, exist_ok=True)
if any(destination.iterdir()): raise SystemExit("source destination is not empty")
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members or len(members) > max_members: raise SystemExit("empty source archive or too many entries")
    roots, seen, files, dirs = set(), set(), [], set()
    total = 0
    for m in members:
        n = m.name
        if not n or "\x00" in n or "\\" in n: raise SystemExit(f"invalid source path: {n!r}")
        q = pathlib.PurePosixPath(n)
        if q.is_absolute() or any(x == ".." for x in q.parts) or not q.parts or q.parts[0].endswith(":"):
            raise SystemExit(f"unsafe source path: {n!r}")
        roots.add(q.parts[0])
        if not (m.isdir() or m.isfile()): raise SystemExit(f"unsupported source entry: {n!r}")
        if m.size < 0 or m.size > max_file: raise SystemExit(f"oversized source entry: {n!r}")
        if m.isfile():
            total += m.size
            if total > max_total: raise SystemExit("source archive exceeds size limit")
        parts = q.parts[1:]
        if not parts: continue
        rel = pathlib.PurePosixPath(*parts)
        name = rel.as_posix()
        if name in seen: raise SystemExit(f"duplicate source path: {name!r}")
        seen.add(name)
        if m.isdir(): dirs.add(rel)
        else: files.append((m, rel))
    if len(roots) != 1: raise SystemExit("source archive must have one top-level directory")
    root_name = next(iter(roots))
    if not root_name.startswith("ShahTunnel-"):
        raise SystemExit(f"unexpected ShahTunnel source archive root: {root_name!r}")
    file_paths = {p for _, p in files}
    if file_paths.intersection(dirs):
        raise SystemExit("source archive contains a path as both a file and directory")
    for path in file_paths:
        if any(parent != pathlib.PurePosixPath(".") and parent in file_paths for parent in path.parents):
            raise SystemExit(f"source file/directory path conflict: {path}")
    for rel in sorted(dirs, key=lambda p: (len(p.parts), p.as_posix())):
        destination.joinpath(*rel.parts).mkdir(mode=0o755, parents=True, exist_ok=True)
    for m, rel in files:
        out = destination.joinpath(*rel.parts)
        out.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        mode = 0o755 if m.mode & 0o111 else 0o644
        fd = os.open(out, flags, mode)
        try:
            src = tf.extractfile(m)
            if src is None: raise SystemExit(f"cannot read source file: {m.name}")
            with src, os.fdopen(fd, "wb", closefd=False) as dst:
                shutil.copyfileobj(src, dst, 1024*1024)
                dst.flush()
                os.fsync(fd)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
PY_SAFE_SOURCE_ARCHIVE
    then
      echo "Could not safely extract the ShahTunnel source archive." >&2
      return 1
    fi
  fi
  [[ -s "$source_dir/go.mod" && -s "$source_dir/S1T-CAPSULE/main.go" ]] \
    || { echo "The downloaded repository does not contain the expected ShahTunnel source files." >&2; return 1; }
  mkdir -p "$source_dir/scripts"
  for helper in install-psiphon.sh install-tor.sh repair-psiphon-profile.sh; do
    if [[ -s "$source_dir/scripts/$helper" ]]; then
      cp -f "$source_dir/scripts/$helper" "$source_dir/$helper" || return 1
    elif [[ -s "$source_dir/$helper" ]]; then
      cp -f "$source_dir/$helper" "$source_dir/scripts/$helper" || return 1
    else
      echo "Required helper $helper is missing from scripts/." >&2
      return 1
    fi
  done
  if ! grep -Fq "module github.com/${OWNER}/${REPO}" "$source_dir/go.mod"; then
    echo "The source module path does not match github.com/${OWNER}/${REPO}; refusing to build." >&2
    return 1
  fi
  [[ -s "$source_dir/install-psiphon.sh" ]] || { echo "Pinned Psiphon auto-installer is missing from the ShahTunnel source." >&2; return 1; }
  if ! bash -n "$source_dir/install-psiphon.sh"; then
    echo "Psiphon auto-installer has invalid shell syntax; refusing to continue." >&2
    return 1
  fi
  [[ -s "$source_dir/install-tor.sh" ]] || { echo "Pinned Tor auto-installer is missing from the ShahTunnel source." >&2; return 1; }
  if ! bash -n "$source_dir/install-tor.sh"; then
    echo "Tor auto-installer has invalid shell syntax; refusing to continue." >&2
    return 1
  fi
  local source_fingerprint build_cache_dir cached_binary
  source_fingerprint="$(source_fingerprint "$source_dir")" || {
    echo "Could not calculate the ShahTunnel source fingerprint." >&2
    return 1
  }
  if [[ ! "$SOURCE_INPUT_SHA256" =~ ^[0-9a-f]{64}$ ]] || [[ "$source_fingerprint" != "$SOURCE_INPUT_SHA256" ]]; then
    echo "ERROR: ShahTunnel build inputs do not match the reviewed 5.0.2 source pin." >&2
    echo "Expected: ${SOURCE_INPUT_SHA256}" >&2
    echo "Received: ${source_fingerprint}" >&2
    echo "Refusing to build an unreviewed source tree. Update the pin only after reviewing the source diff." >&2
    return 1
  fi
  echo "ShahTunnel source inputs passed the pinned SHA-256 check." >&2
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

if ! build_from_official_go_toolchain; then
  echo "Installation stopped: no verified ShahTunnel binary was built." >&2
  echo "Go archives must match the pinned SHA-256; ShahTunnel is built locally without GitHub Release assets." >&2
  exit 1
fi
phase_start 2 "Installing binary and configuring service"
install -d -o root -g root -m 0700 /etc/ravanreverse
install -d -o root -g root -m 0700 /etc/ravanreverse/tunnels
install -d -o root -g root -m 0755 /usr/local/bin
install -d -o root -g root -m 0755 "$STATE_DIR"
# Provision the pinned Psiphon builder now. The ConsoleClient binary itself is
# built on-demand only when an Agent selects Psiphon; no TUN/routes are created.
[[ -s "$TMP/source/scripts/safe_extract_tar.py" ]] || { echo "Safe archive extractor is missing from the reviewed source." >&2; exit 1; }
install -o root -g root -m 0750 "$TMP/source/scripts/safe_extract_tar.py" "$STATE_DIR/safe_extract_tar.py.new"
mv -f "$STATE_DIR/safe_extract_tar.py.new" "$STATE_DIR/safe_extract_tar.py"
install -o root -g root -m 0750 "$TMP/source/install-psiphon.sh" "$STATE_DIR/install-psiphon.sh.new"
mv -f "$STATE_DIR/install-psiphon.sh.new" "$STATE_DIR/install-psiphon.sh"
install -o root -g root -m 0750 "$TMP/source/install-tor.sh" "$STATE_DIR/install-tor.sh.new"
mv -f "$STATE_DIR/install-tor.sh.new" "$STATE_DIR/install-tor.sh"
install -d -o root -g root -m 0700 /var/lib/shah-tunnel/tor
[[ -s "$TMP/source/repair-psiphon-profile.sh" ]] || { echo "Psiphon profile repair helper is missing from the source archive." >&2; exit 1; }
install -o root -g root -m 0750 "$TMP/source/repair-psiphon-profile.sh" "$STATE_DIR/repair-psiphon-profile.sh.new"
mv -f "$STATE_DIR/repair-psiphon-profile.sh.new" "$STATE_DIR/repair-psiphon-profile.sh"
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
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
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
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
KeyringMode=private
RemoveIPC=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
ReadWritePaths=/etc/ravanreverse /var/lib/shah-tunnel/tor
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
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
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
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
KeyringMode=private
RemoveIPC=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
ReadWritePaths=/etc/ravanreverse /var/lib/shah-tunnel/tor
[Install]
WantedBy=multi-user.target
UNIT
install -o root -g root -m 0644 "$TMP/ravanreverse@.service" /etc/systemd/system/ravanreverse@.service
# Apply the extra hardening to existing singleton services as well. The main
# unit is intentionally preserved during upgrades; a dedicated drop-in lets
# it inherit these directives without replacing a site's ExecStart/customizations.
for unit in ravanreverse.service ravanreverse@.service; do
  hardening_dir="/etc/systemd/system/${unit}.d"
  install -d -o root -g root -m 0755 "$hardening_dir"
  cat > "$TMP/security-${unit}.conf" <<'SECURITY_DROPIN'
[Service]
ProtectKernelLogs=true
KeyringMode=private
RemoveIPC=true
SECURITY_DROPIN
  install -o root -g root -m 0644 "$TMP/security-${unit}.conf" \
    "$hardening_dir/30-shah-tunnel-security.conf"
done
# Psiphon ConsoleClient runs in local SOCKS5 mode and needs a private persistent
# data directory. Keep ProtectSystem=strict and grant write access only there.
install -d -o root -g root -m 0755 /var/lib/shah-tunnel/psiphon
for unit in ravanreverse.service ravanreverse@.service; do
  dropin_dir="/etc/systemd/system/${unit}.d"
  install -d -o root -g root -m 0755 "$dropin_dir"
  cat > "$TMP/psiphon-${unit}.conf" <<'DROPIN'
[Service]
ReadWritePaths=/var/lib/shah-tunnel/psiphon
DROPIN
  install -o root -g root -m 0644 "$TMP/psiphon-${unit}.conf" "$dropin_dir/psiphon.conf"
  cat > "$TMP/tor-${unit}.conf" <<'TOR_DROPIN'
[Service]
ReadWritePaths=/var/lib/shah-tunnel/tor
TOR_DROPIN
  install -o root -g root -m 0644 "$TMP/tor-${unit}.conf" "$dropin_dir/tor.conf"

  # Keep this as the same standalone override that fixed the live Agent
  # manually. It is deliberately installed under the template drop-in so
  # every existing and future ravanreverse@PROFILE.service inherits it.
  cat > "$TMP/netlink-${unit}.conf" <<'NETLINK'
[Service]
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
NETLINK
  install -o root -g root -m 0644 "$TMP/netlink-${unit}.conf" "$dropin_dir/10-psiphon-netlink.conf"
done

# Migrate installed per-profile Psiphon dependencies from Requires to Wants.
# Requires makes systemd send SIGTERM to the Agent whenever ConsoleClient is
# restarted; this is unsafe for adaptive lanes and leaves the Agent stopped.
# Wants + After still starts Psiphon with the Agent, but Psiphon may recover
# independently without taking down the authenticated Agent service.
for dependency_dropin in \
  /etc/systemd/system/ravanreverse@*.service.d/shah-tunnel-psiphon.conf \
  /etc/systemd/system/ravanreverse.service.d/shah-tunnel-psiphon.conf; do
  [[ -f "$dependency_dropin" ]] || continue
  if grep -q '^Requires=shah-tunnel-psiphon-' "$dependency_dropin"; then
    migrated_dropin="$TMP/psiphon-dependency-migrated.conf"
    sed 's/^Requires=shah-tunnel-psiphon-/Wants=shah-tunnel-psiphon-/' \
      "$dependency_dropin" > "$migrated_dropin"
    install -o root -g root -m 0644 "$migrated_dropin" "$dependency_dropin"
    echo "Migrated Psiphon dependency to non-fatal Wants/After: $dependency_dropin"
  fi
done

if ! timeout --kill-after=3s 15s systemctl daemon-reload; then
  echo "systemd daemon-reload timed out. The binary is installed, but service metadata may need: systemctl daemon-reload" >&2
  exit 1
fi

# A running systemd service keeps the sandbox policy from the time it was
# started. Updating its unit/drop-ins is not enough: restart only active Agent
# profiles configured for Psiphon or Adaptive egress so AF_NETLINK is applied
# to the running ConsoleClient. Hub, Direct, WARP, and unrelated profiles are
# left untouched. Restart is required once during this upgrade; lane recovery
# then proceeds automatically under the existing service.
is_psiphon_agent_config() {
  local config="$1"
  [[ -s "$config" ]] || return 1
  python3 - "$config" <<'PYCONFIG' >/dev/null 2>&1
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        cfg = json.load(f)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if cfg.get("role") == "agent" and cfg.get("underlay") in ("psiphon_socks5", "adaptive_external") else 1)
PYCONFIG
}

restart_active_psiphon_agent() {
  local unit="$1" config="$2"
  if ! timeout --kill-after=2s 8s systemctl is-active --quiet "$unit"; then
    return 0
  fi
  if ! is_psiphon_agent_config "$config"; then
    return 0
  fi
  echo "Applying updated Psiphon systemd sandbox and binary to active profile: $unit"
  if ! timeout --kill-after=5s 45s systemctl restart "$unit"; then
    echo "ERROR: could not restart $unit after applying the Psiphon Netlink policy." >&2
    timeout 5s journalctl -u "$unit" -n 35 --no-pager >&2 || true
    return 1
  fi
  if ! timeout --kill-after=2s 8s systemctl is-active --quiet "$unit"; then
    echo "ERROR: $unit did not return to active state after its automatic upgrade restart." >&2
    timeout 5s journalctl -u "$unit" -n 35 --no-pager >&2 || true
    return 1
  fi
  echo "Profile $unit restarted; Psiphon and Hub lanes are reconnecting automatically."
}

# Legacy single-profile Agent support.
restart_active_psiphon_agent "ravanreverse.service" "/etc/ravanreverse/config.json"

# Named profiles: restart only active Psiphon/Adaptive Agents. The config check
# prevents interrupting Hub services or other egress profiles.
if timeout --kill-after=2s 8s systemctl list-units --type=service --state=active --no-legend --no-pager 'ravanreverse@*.service' > "$TMP/active-ravanreverse-units"; then
  while IFS= read -r unit; do
    [[ "$unit" == ravanreverse@*.service ]] || continue
    profile="${unit#ravanreverse@}"
    profile="${profile%.service}"
    [[ "$profile" =~ ^[A-Za-z0-9_.-]{1,48}$ ]] || continue
    restart_active_psiphon_agent "$unit" "/etc/ravanreverse/tunnels/${profile}.json"
  done < <(awk '{print $1}' "$TMP/active-ravanreverse-units")
else
  echo "WARNING: could not enumerate active ShahTunnel profile services for automatic Psiphon upgrade restart." >&2
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
