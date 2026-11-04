#!/usr/bin/env bash
set -Eeuo pipefail
# Shah Tunnel 1.6.2 installer.
# Downloads the official Go toolchain directly from dl.google.com, verifies SHA-256, and builds from GitHub source.
# No prebuilt ShahTunnel binaries or manual GitHub release uploads are required.
OWNER="ShahNetLab"
REPO="ShahTunnel"
VERSION="1.6.2"
GO_VERSION="1.25.1"
GO_BASE="https://dl.google.com/go"
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
    if ! curl -4 -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 25 --dump-header "$headers" "$@" "$url" -o "$dest" 2>"$log"; then
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
  curl -4 -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 25 --dump-header "$headers" "$@" "$url" -o "$dest" 2>"$log" &
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
# Download a large official archive while retaining partial bytes between retries.
# Unlike curl_download(), this helper never removes the destination on failure.
curl_download_resumable() {
  local url="$1" dest="$2" max_time="${3:-900}" retry_count="${4:-1}" speed_time="${5:-75}" resolve_ip="${6:-}"
  local url_host rc=0
  local -a resolve_args=() progress_args=()

  # Keep partial bytes after a network interruption; the next attempt resumes
  # with an HTTP Range request instead of downloading the whole Go archive again.
  [[ -f "$dest" ]] || : > "$dest"
  if [[ -n "$resolve_ip" ]]; then
    url_host="${url#https://}"
    url_host="${url_host%%/*}"
    resolve_args=(--resolve "${url_host}:443:${resolve_ip}")
  fi

  # Show curl's real transfer percentage/ETA in an interactive SSH terminal.
  # In non-interactive runs, keep output clean while preserving error messages.
  if [[ -t 2 ]]; then
    progress_args=(--progress-bar --show-error)
  else
    progress_args=(--silent --show-error)
  fi

  if curl -4 --fail --location --proto '=https' --proto-redir '=https' \
      "${resolve_args[@]}" "${progress_args[@]}" --continue-at - \
      --retry "$retry_count" --retry-delay 2 --retry-connrefused \
      --connect-timeout 8 --max-time "$max_time" \
      --speed-time "$speed_time" --speed-limit 1024 \
      "$url" -o "$dest"; then
    return 0
  else
    rc=$?
  fi

  # Do not delete the partial archive here. A later official-IP attempt or
  # another installer run can continue from the bytes already received.
  return "$rc"
}

# Resolve a host through authenticated DNS-over-HTTPS when the VPS resolver is
# broken. The archive itself is still fetched from the official HTTPS hostname;
# curl --resolve pins only the IP and keeps TLS hostname verification enabled.
resolve_ipv4_via_doh() {
  local host="$1" response
  # All resolver IPs are public, well-known DNS services. They are used only
  # to discover the CDN address; the later HTTPS request still validates the
  # certificate for dl.google.com and the Go archive SHA-256.
  local -a doh_hosts=(
    'cloudflare-dns.com|1.1.1.1|/dns-query'
    'dns.google|8.8.8.8|/resolve'
    'dns.quad9.net|9.9.9.9|/dns-query'
    'doh.opendns.com|146.112.41.2|/dns-query'
    'dns.adguard-dns.com|94.140.14.14|/dns-query'
  )
  local entry doh_host doh_ip doh_path
  for entry in "${doh_hosts[@]}"; do
    doh_host="${entry%%|*}"
    entry="${entry#*|}"
    doh_ip="${entry%%|*}"
    doh_path="${entry#*|}"
    response="$(curl -4 -fsS --proto '=https' --connect-timeout 3 --max-time 6 \
      --resolve "${doh_host}:443:${doh_ip}" \
      -H 'accept: application/dns-json' \
      "https://${doh_host}${doh_path}?name=${host}&type=A" 2>/dev/null || true)"
    if [[ -n "$response" ]]; then
      local answers
      answers="$(printf '%s' "$response" | python3 -c '
import ipaddress, json, sys
try:
    data = json.load(sys.stdin)
    if data.get("Status") == 0:
        for answer in data.get("Answer", []):
            if answer.get("type") == 1:
                try:
                    ip = ipaddress.ip_address(answer.get("data", ""))
                    if ip.version == 4:
                        print(ip)
                except ValueError:
                    pass
except Exception:
    pass
' 2>/dev/null)"
      if [[ -n "$answers" ]]; then
        printf '%s\n' "$answers"
        return 0
      fi
    fi
  done
}

# Last-resort DNS that does not depend on /etc/resolv.conf and does not need
# curl to resolve any hostname. DNS answers are only used as IP candidates;
# curl still connects to https://dl.google.com with normal TLS verification.
resolve_ipv4_via_public_dns() {
  local host="$1"
  python3 - "$host" <<'PYDNS'
import ipaddress, os, socket, ssl, struct, sys
host = sys.argv[1].rstrip('.')
resolvers = [
    ('1.1.1.1', 'cloudflare-dns.com'),
    ('8.8.8.8', 'dns.google'),
    ('9.9.9.9', 'dns.quad9.net'),
    ('208.67.222.222', 'dns.opendns.com'),
    ('208.67.220.220', 'dns.opendns.com'),
    ('94.140.14.14', 'dns.adguard-dns.com'),
]
try:
    qname = b''.join(bytes([len(label)]) + label.encode('ascii') for label in host.split('.')) + b'\0'
except Exception:
    raise SystemExit(0)
tid = int.from_bytes(os.urandom(2), 'big')
query = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)

def recv_exact(sock, n):
    out = b''
    while len(out) < n:
        part = sock.recv(n-len(out))
        if not part: raise OSError('short DNS response')
        out += part
    return out

def parse(msg):
    if len(msg) < 12: return []
    rid, flags, qd, an, _, _ = struct.unpack('!HHHHHH', msg[:12])
    if rid != tid or not (flags & 0x8000) or (flags & 0x000f) != 0: return []
    pos = 12
    def skip_name(p):
        while p < len(msg):
            n = msg[p]
            if n == 0: return p+1
            if (n & 0xC0) == 0xC0: return p+2
            if n & 0xC0: return len(msg)
            p += n+1
        return len(msg)
    for _ in range(qd):
        pos = skip_name(pos) + 4
    found = []
    for _ in range(an):
        pos = skip_name(pos)
        if pos + 10 > len(msg): break
        typ, cls, ttl, size = struct.unpack('!HHIH', msg[pos:pos+10]); pos += 10
        data = msg[pos:pos+size]; pos += size
        if typ == 1 and cls == 1 and size == 4:
            try: found.append(str(ipaddress.IPv4Address(data)))
            except Exception: pass
    return found

seen = set()
for ip, tls_name in resolvers:
    # UDP/53 and TCP/53 are attempted independently. The query carries no
    # credentials; authenticity is enforced by the pinned Go archive checksum.
    for proto in ('udp', 'tcp'):
        try:
            if proto == 'udp':
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.0); s.sendto(query, (ip, 53)); packet, _ = s.recvfrom(4096)
            else:
                with socket.create_connection((ip, 53), timeout=2.0) as s:
                    s.settimeout(2.0); s.sendall(struct.pack('!H', len(query)) + query)
                    size = struct.unpack('!H', recv_exact(s, 2))[0]
                    packet = recv_exact(s, size)
            for answer in parse(packet):
                if answer not in seen: print(answer); seen.add(answer)
            if seen: break
        except Exception:
            pass
    if seen: break
    # DNS-over-TLS on port 853 provides another path when UDP/53 is blocked.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 853), timeout=2.5) as raw:
            raw.settimeout(2.5)
            with ctx.wrap_socket(raw, server_hostname=tls_name) as s:
                s.sendall(struct.pack('!H', len(query)) + query)
                size = struct.unpack('!H', recv_exact(s, 2))[0]
                packet = recv_exact(s, size)
        for answer in parse(packet):
            if answer not in seen: print(answer); seen.add(answer)
        if seen: break
    except Exception:
        pass
PYDNS
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
build_from_system_go() {
  local go_bin go_text local_go_version minimum source_url source_dir source_fingerprint BUILD_GO_VERSION
  local build_cache_dir cached_binary go_root
  go_bin="$(command -v go 2>/dev/null || true)"
  [[ -n "$go_bin" ]] || return 1
  go_text="$(GOTOOLCHAIN=local "$go_bin" version 2>/dev/null || true)"
  [[ "$go_text" =~ go([0-9]+\.[0-9]+(\.[0-9]+)?) ]] || return 1
  local_go_version="${BASH_REMATCH[1]}"
  minimum="$(printf '%s\n%s\n' '1.23.0' "$local_go_version" | sort -V | sed -n '1p')"
  if [[ "$minimum" != "1.23.0" ]]; then
    echo "Installed Go ${local_go_version} is too old; Shah Tunnel requires Go 1.23.0 or newer." >&2
    return 1
  fi
  go_root="$(GOTOOLCHAIN=local "$go_bin" env GOROOT 2>/dev/null || true)"
  [[ -n "$go_root" && -x "$go_root/bin/go" ]] || return 1

  echo "Building Shah Tunnel from GitHub source with the existing Go ${local_go_version}; no toolchain download is needed." >&2
  phase_start 1 "Download ShahTunnel source from GitHub"
  source_url="https://codeload.github.com/${OWNER}/${REPO}/tar.gz/refs/heads/main"
  source_dir="$TMP/source"
  if ! curl_download "$source_url" "$TMP/shah-tunnel-source.tar.gz" \
      --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 20 --max-time 300; then
    echo "Could not download the source archive from GitHub." >&2
    return 1
  fi
  mkdir -p "$source_dir"
  if ! tar -xzf "$TMP/shah-tunnel-source.tar.gz" -C "$source_dir" --strip-components=1; then
    echo "Could not extract the ShahTunnel source archive." >&2
    return 1
  fi
  [[ -s "$source_dir/go.mod" && -s "$source_dir/S1T-CAPSULE/main.go" ]] || {
    echo "GitHub source archive is missing the expected ShahTunnel source files." >&2
    return 1
  }
  grep -Fq "module github.com/${OWNER}/${REPO}" "$source_dir/go.mod" || {
    echo "Downloaded source module path does not match this repository." >&2
    return 1
  }

  source_fingerprint="$(cd "$source_dir" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
  build_cache_dir="${STATE_DIR}/builds"
  cached_binary="${build_cache_dir}/shah-tunnel-${VERSION}-go${local_go_version}-${TARGET_ARCH}-${source_fingerprint}"
  install -d -o root -g root -m 0755 "$build_cache_dir" "$GO_CACHE_DIR"
  if [[ -s "$cached_binary" ]] && timeout --kill-after=1s 5s "$cached_binary" version 2>/dev/null \
      | grep -Fqx "Shah Tunnel ${VERSION} (linux/${TARGET_ARCH})"; then
    cp -f "$cached_binary" "$TMP/S1T-CORE"
    echo "Reusing cached binary built from this exact GitHub source revision." >&2
  else
    BUILD_GO_VERSION="$local_go_version"
    if ! run_with_spinner "Building ShahTunnel with local Go" "$TMP/build.log" \
        build_project_binary "$go_bin" "$source_dir" "$go_root"; then
      echo "Local Go build failed. Build output follows:" >&2
      [[ ! -s "$TMP/build.log" ]] || cat "$TMP/build.log" >&2
      return 1
    fi
    if ! verify_binary; then
      echo "Locally built binary has an unexpected version or architecture." >&2
      return 1
    fi
    install -o root -g root -m 0750 "$TMP/S1T-CORE" "${cached_binary}.new"
    mv -f "${cached_binary}.new" "$cached_binary"
  fi
  verify_binary || return 1
  phase_done "Locally built binary verified"
  return 0
}

install_compatible_go_from_apt() {
  local pkg candidate candidate_version path versioned_bin
  local -a packages=(golang-1.27-go golang-1.26-go golang-1.25-go golang-1.24-go golang-1.23-go golang-go)

  command -v apt-get >/dev/null 2>&1 || return 1
  command -v apt-cache >/dev/null 2>&1 || return 1
  command -v dpkg >/dev/null 2>&1 || return 1

  echo "The official Go download endpoints are unreachable. Checking the VPS distribution's signed APT repositories for Go >= 1.23.0..." >&2

  # Refresh package metadata only when the current cache has no compatible Go.
  local have_candidate=0
  for pkg in "${packages[@]}"; do
    candidate="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
    candidate_version="${candidate##*:}"
    if [[ -n "$candidate" && "$candidate" != "(none)" ]] && dpkg --compare-versions "$candidate_version" ge "1.23.0"; then
      have_candidate=1
      break
    fi
  done
  if [[ "$have_candidate" -ne 1 ]]; then
    if ! run_with_spinner "Refreshing official APT package indexes" "$TMP/apt-update.log" \
        timeout --kill-after=3s 60s apt-get update -o Acquire::Retries=0 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10; then
      echo "APT package-index refresh failed; checking any cached package metadata anyway." >&2
    fi
  fi

  for pkg in "${packages[@]}"; do
    candidate="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
    [[ -n "$candidate" && "$candidate" != "(none)" ]] || continue
    candidate_version="${candidate##*:}"
    if ! dpkg --compare-versions "$candidate_version" ge "1.23.0"; then
      continue
    fi

    echo "Installing ${pkg} (${candidate}) from the VPS configured APT repositories..." >&2
    if ! run_with_spinner "Installing Go from APT" "$TMP/apt-install.log" \
        timeout --kill-after=5s 300s apt-get install -y --no-install-recommends "$pkg"; then
      echo "APT could not install ${pkg}; trying the next compatible package." >&2
      continue
    fi

    # Versioned Ubuntu/Debian packages keep Go under /usr/lib/go-X.Y/bin.
    if [[ "$pkg" =~ ^golang-(1\.[0-9]+)-go$ ]]; then
      versioned_bin="/usr/lib/go-${BASH_REMATCH[1]}/bin"
      if [[ -x "$versioned_bin/go" ]]; then
        export PATH="${versioned_bin}:${PATH}"
      fi
    fi
    hash -r
    path="$(command -v go 2>/dev/null || true)"
    if [[ -z "$path" ]]; then
      path="$(find /usr/lib -maxdepth 4 -type f -path '/usr/lib/go-*/bin/go' -print 2>/dev/null | sort -V | tail -n 1)"
      if [[ -n "$path" ]]; then
        export PATH="$(dirname "$path"):${PATH}"
        hash -r
      fi
    fi
    if [[ -n "$path" && -x "$path" ]]; then
      echo "Go package installed from the signed APT repository: $path" >&2
      return 0
    fi
    echo "Installed package did not provide a usable Go >= 1.23.0; trying next package." >&2
  done
  return 1
}

prepare_verified_binary() {
  # Preferred route: reuse a verified official Go toolchain cache, or download
  # Go directly from dl.google.com and verify its official pinned SHA-256.
  if build_from_official_go_toolchain; then
    return 0
  fi

  # Fallback only when the official Go host is unreachable: use a compatible
  # Go toolchain already installed on this VPS.
  if build_from_system_go; then
    return 0
  fi

  # Final fallback: install Go from the VPS distribution's signed APT sources.
  if install_compatible_go_from_apt && build_from_system_go; then
    return 0
  fi
  return 1
}

official_go_sha256() {
  case "$TARGET_ARCH" in
    amd64) printf '%s' '7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e' ;;
    arm64) printf '%s' '65a3e34fb2126f55b34e1edfc709121660e1be2dee6bdf405fc399a63a95a87d' ;;
    *) return 1 ;;
  esac
}

build_project_binary() {
  local go_bin="$1" source_dir="$2" go_root="$3"
  (
    cd "$source_dir"
    env GOROOT="$go_root" GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
      GOCACHE="${GO_CACHE_DIR}/build-cache-${BUILD_GO_VERSION:-$GO_VERSION}-${TARGET_ARCH}" \
      CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" \
      "$go_bin" build -trimpath -ldflags='-s -w -buildid=' \
      -o "$TMP/S1T-CORE" ./S1T-CAPSULE
  )
}
build_from_official_go_toolchain() {
  local go_archive go_sha source_url go_bin go_root source_dir expected_go downloaded
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
      local part_file="${GO_CACHE_DIR}/${go_archive}.official.part"
      local official_url="${GO_BASE}/${go_archive}"
      local -a official_ips=()
      local official_ip
      echo "Downloading Go ${GO_VERSION} (${TARGET_ARCH}) from the official Go distribution host: ${GO_BASE}" >&2
      echo "Resolving the official download host through HTTPS DNS first; TLS certificate and SHA-256 will both be verified." >&2

      # First bypass the VPS's possibly broken DNS resolver. DNS-over-HTTPS is
      # used only to obtain IP addresses; the actual archive is still fetched
      # from dl.google.com with its hostname and normal TLS certificate check.
      mapfile -t official_ips < <({
        # Prefer authenticated HTTPS DNS, then query independent public DNS
        # resolvers directly over UDP/TCP 53 and DNS-over-TLS 853, then ask
        # the VPS resolver. The HTTP download itself always uses dl.google.com.
        resolve_ipv4_via_doh "dl.google.com"
        resolve_ipv4_via_public_dns "dl.google.com"
        if command -v getent >/dev/null 2>&1; then
          getent ahostsv4 dl.google.com 2>/dev/null | awk '{print $1}'
        fi
      } | awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}$/' | sort -u)

      if [[ "${#official_ips[@]}" -gt 0 ]]; then
        for official_ip in "${official_ips[@]}"; do
          echo "Downloading from official Go host via resolved address ${official_ip} (HTTPS hostname verification enabled)..." >&2
          if curl_download_resumable "$official_url" "$part_file" 900 1 75 "$official_ip"; then
            if printf '%s  %s\n' "$go_sha" "$part_file" | sha256sum -c - >/dev/null 2>&1; then
              cp -f "$part_file" "$TMP/$go_archive"
              downloaded=1
              echo "Official Go archive downloaded and SHA-256 verified." >&2
              break
            fi
            echo "The downloaded archive did not match the official SHA-256; discarding it before the next address." >&2
            rm -f "$part_file"
          fi
        done
      else
        echo "HTTPS DNS lookup did not return an address; falling back to the VPS resolver for the same official URL." >&2
      fi

      # Last network fallback: use the VPS's normal resolver. This is attempted
      # once with a short connection/DNS timeout; it never switches to a mirror.
      if [[ "$downloaded" -ne 1 ]]; then
        echo "Trying the official Go URL using the VPS DNS resolver..." >&2
        if curl_download_resumable "$official_url" "$part_file" 900 0 75; then
          if printf '%s  %s\n' "$go_sha" "$part_file" | sha256sum -c - >/dev/null 2>&1; then
            cp -f "$part_file" "$TMP/$go_archive"
            downloaded=1
            echo "Official Go archive downloaded and SHA-256 verified." >&2
          else
            echo "The official archive SHA-256 did not match; removing the invalid file." >&2
            rm -f "$part_file"
          fi
        fi
      fi
      if [[ "$downloaded" -eq 1 ]]; then
        # Cache only a fully downloaded and verified archive.
        install -o root -g root -m 0644 "$TMP/$go_archive" "$cache_archive"
        rm -f "$part_file"
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

  echo "Downloading ShahTunnel source from ${OWNER}/${REPO} (main branch)..." >&2
  if ! curl_download "$source_url" "$TMP/shah-tunnel-source.tar.gz" \
      --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 25 --max-time 300; then
    echo "Normal DNS failed for the source host; trying DNS-over-HTTPS..." >&2
    local source_ip source_ok=0
    while IFS= read -r source_ip; do
      [[ "$source_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
      if curl_download "$source_url" "$TMP/shah-tunnel-source.tar.gz" \
          --resolve "codeload.github.com:443:${source_ip}" \
          --retry 2 --retry-delay 2 --retry-connrefused --connect-timeout 25 --max-time 300; then
        source_ok=1
        break
      fi
    done < <(resolve_ipv4_via_doh "codeload.github.com")
    if [[ "$source_ok" -ne 1 ]]; then
      echo "Could not download the source archive from ${source_url}; check outbound HTTPS/DNS access." >&2
      return 1
    fi
  fi
  mkdir -p "$source_dir"
  if ! tar -xzf "$TMP/shah-tunnel-source.tar.gz" -C "$source_dir" --strip-components=1; then
    echo "Could not extract the ShahTunnel source archive." >&2
    return 1
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

if ! prepare_verified_binary; then
  echo "Installation stopped: no verified ShahTunnel binary could be built." >&2
  echo "The installer tried the official Go download service, available system Go, and compatible Go packages from the VPS APT repositories." >&2
  echo "If all of those network routes are blocked, the VPS provider/network must allow outbound HTTPS to the official Go CDN or its configured package mirrors." >&2
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
