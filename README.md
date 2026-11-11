<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V3.0.0 · Secure Reverse TCP Relay · Multi-layer Adaptive Recovery</strong></p>
<p align="center">ShahTunnel relays public TCP connections through a Hub and authenticated Agent lanes to mapped local services. Version 3 supports Agent-side Psiphon SOCKS5 egress and Cloudflare WARP over MASQUE, including both WARP system-tunnel mode and the local HTTP proxy mode, plus WireGuard system-tunnel mode.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## Network flow

<p align="center">
  <img src="docs/img/ShahTunnel-Network-Flow-v3.svg" alt="Version 3 network flow showing Hub, Agent, four inner transports, direct egress, WARP MASQUE/WireGuard and Psiphon SOCKS5" width="100%" />
</p>

## Features

- **Four implemented inner transports:** TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT, and HTTP/1.1 CONNECT/TLS.
- **Option 8 — external egress:** choose Cloudflare WARP over MASQUE, WARP over WireGuard, or the official Psiphon ConsoleClient through a local SOCKS5 proxy.
- **Option 9 — multi-layer adaptive recovery:** try all four inner transports; detect an already-connected WARP mode (MASQUE/WireGuard), and consider it alongside Psiphon SOCKS5 and Direct. An active WARP route is verified first and falls back to Psiphon then Direct; without WARP, each lane prefers its last successful Direct/Psiphon route. Each lane remembers its last successful transport and egress path.
- **Security:** TLS 1.3, token authentication, SHA-256 certificate pinning, and loopback-only Psiphon proxy endpoints.
- **Management:** isolated tunnel profiles and systemd services. Main manager options retain their prior numbering and behaviour.

## Transport selection

Options 1–7 retain their previous behaviour and numbering. Options 8 and 9 are added only to the transport wizard. The main manager's option 8 remains Complete uninstall.

| Option | Transport / strategy | Behaviour |
|---|---|---|
| `1` | TCP/TLS | Native TLS-protected stream. |
| `2` | WebSocket/TLS | Tunnel stream carried in WebSocket binary frames over TLS. |
| `3` | HTTP/2 CONNECT | CONNECT stream over TLS on control port + 1. |
| `4` | HTTP/1.1 CONNECT/TLS | CONNECT stream over TLS on control port + 2. |
| `5` | HTTP CONNECT fallback | HTTP/2, then HTTP/1.1. |
| `6` | Automatic fallback | TCP/TLS, then WebSocket/TLS. |
| `7` | Full Adaptive Failover | All four inner transports; the last successful one is preferred per lane. |
| `8` | External egress | On the Agent, choose MASQUE/WARP, WARP/WireGuard, or Psiphon/SOCKS5. The Hub accepts the adaptive inner transports. |
| `9` | All-Protocol Adaptive | All four inner transports over detected WARP (MASQUE/WireGuard), Psiphon, and Direct; an active WARP path is verified first, while a lost WARP path falls through to Psiphon/Direct; without WARP, the last successful Direct/Psiphon path is preferred. |

### WARP, MASQUE, and SSH safety

ShahTunnel supports two WARP layouts for the Agent. In system-tunnel mode, the host route must already carry traffic through WARP; ShahTunnel verifies `warp-cli` status, the selected protocol, and a live `warp=on` check before connecting. In Local Proxy mode (`Mode: WarpProxy on port 40000`), ShahTunnel detects the loopback proxy port from `warp-cli settings` and checks that its local listener is reachable; each lane then verifies the real HTTP CONNECT to the Hub through `127.0.0.1:<port>`. An HTTP 404 from the optional Cloudflare trace endpoint no longer blocks the proxy, while a failed Hub CONNECT still fails closed without using the direct route. This supports the MASQUE protocol; Cloudflare Local Proxy mode does not support WireGuard. The Agent therefore sends only its Hub control lanes through WARP, while SSH, inbound listeners, and the host default route remain untouched. ShahTunnel **never** runs `warp-cli connect`, changes the WARP protocol, disconnects WARP, or modifies system routes. WARP must already be connected before the Agent service starts. These checks are repeated before every reconnect, and a failed WARP path fails closed for option 8 rather than silently using the direct host route.

If this WARP CLI build asks for Terms of Service acceptance when invoked by systemd, ShahTunnel retries the command with `--accept-tos` and remembers that requirement for later CLI calls; the administrator must have accepted the terms during setup. For an existing Local Proxy installation, do not switch modes: keep `WarpProxy` enabled and use the configured port (the default shown in many installations is `40000`). A read-only check is:

```bash
sudo warp-cli --accept-tos status
sudo warp-cli settings | grep -i -E 'Mode:|WARP tunnel protocol:'
sudo ss -lntp | grep '127.0.0.1:40000'
```

Note: Cloudflare's trace endpoint may return HTTP 404 from some WarpProxy egress locations; that response alone does not mean the proxy is broken. In Local Proxy mode, ShahTunnel checks the local listener and verifies each lane using its real HTTP CONNECT to the Hub instead of gating on the trace endpoint.

Enabling the full system-tunnel mode can change the server's default route and interrupt SSH. Run the commands below only from a provider console or with a tested out-of-band recovery path; do not switch the default route from your only SSH session:

```bash
warp-cli tunnel protocol set MASQUE
warp-cli connect
warp-cli --accept-tos status
warp-cli settings | grep -i protocol
curl -fsS https://api.cloudflare.com/cdn-cgi/trace | grep '^warp=on$'
```

For WireGuard, use `warp-cli tunnel protocol set WireGuard` instead. See Cloudflare's [Linux setup](https://developers.cloudflare.com/warp-client/get-started/linux/) and [WARP modes](https://developers.cloudflare.com/warp-client/warp-modes/).

### Psiphon setup

The integration uses the official Linux `ConsoleClient` and a valid Psiphon client JSON configuration. The Psiphon executable is not bundled in this ZIP; obtain it from the [official Psiphon binary repository](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries). Set `LocalSocksProxyPort` in that JSON to the local SOCKS5 port selected in the Agent wizard (default `1080`). ShahTunnel starts `ConsoleClient` with a profile-specific data directory and binds its proxy to the loopback interface, then dials the Hub through SOCKS5. The installer adds a narrow systemd drop-in granting write access only to `/var/lib/shah-tunnel/psiphon`, preserving `ProtectSystem=strict`. Only the Agent's outbound TCP stream is proxied; SSH and the system default route are not changed.

### Hub firewall ports

If the Hub control port is `9443`:

- `9443/TCP`: native TCP/TLS and WebSocket/TLS.
- `9444/TCP`: HTTP/2 CONNECT.
- `9445/TCP`: HTTP/1.1 CONNECT/TLS.

Keep all three open for adaptive options 7–9. WARP/MASQUE and Psiphon do not add another inbound Hub listener.

## Failover details and layer boundaries

- Option 9 tries the four inner TCP transports over a connected WARP tunnel (MASQUE or WireGuard) when detected, then Psiphon SOCKS5 and Direct. If WARP is not connected, the order is Direct then Psiphon. WARP status, protocol, and live `warp=on` egress are checked before every WARP attempt; each lane remembers its last successful inner transport and egress path.
- MASQUE and WireGuard are Cloudflare WARP tunnel protocols managed by `warp-svc` at the system level; they are not independent per-socket proxies. ShahTunnel does not switch WARP protocols while running because doing so could interrupt SSH and all other host traffic. When WARP is active in system-tunnel mode, its current system route is treated as a separately verified candidate; ensure the Hub IP is not excluded by the WARP split-tunnel policy. When WARP is in Local Proxy mode, each lane uses the detected loopback HTTP CONNECT proxy instead. Local Proxy requires MASQUE. If a WARP candidate fails, option 9 moves to the next configured egress route.
- Psiphon is integrated as a SOCKS5 TCP proxy in this release; this path does not provide an independent UDP transport.
- Each lane reconnects independently. Healthy lanes and the SSH service are not restarted or modified.

## Multiple tunnel profiles and performance

Each create operation stores a unique named profile. Every profile runs as its own systemd service; Start, Stop, Restart, Status, and Delete act only on the selected profile. Existing profiles are not overwritten.

The per-stream in-flight window remains 64 frames of up to 64 KiB. Actual throughput depends on bandwidth, RTT, packet loss, congestion, qdisc, and host limits; no fixed throughput can be guaranteed.

## Install and upgrade

One-line online install/upgrade (run as root on Linux amd64 or arm64 with systemd):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

This command downloads only the installer script from `raw.githubusercontent.com`. The installer then downloads the ShahTunnel **source archive** from the official repository at `codeload.github.com/ShahNetLab/ShahTunnel` (branch `main`), obtains the pinned Go toolchain from the official Go distribution endpoints, verifies its SHA-256, and compiles the Linux binary on the target VPS. The compiled binary is installed locally at `/usr/local/bin/ravanreverse`.

**No ShahTunnel executable/binary is required in GitHub, a GitHub Release, or this source ZIP.** Only source code, tests, documentation, and the installer belong in the repository. The installer never downloads a prebuilt ShahTunnel binary.

To install or upgrade from an already downloaded source checkout instead:

```bash
sudo bash S1T-START.sh
```

When run from a checkout, the installer builds from that local source tree. It backs up an existing executable and does not restart an already-active ShahTunnel service during upgrade, avoiding interruption of current sessions. Legacy service/config names `ravanreverse.service` and `/etc/ravanreverse` remain for compatibility.

The running service keeps its old in-memory binary until you restart the selected ShahTunnel unit during a maintenance window. This interrupts that tunnel's forwarded sessions, but does not restart or modify `sshd`:

```bash
sudo systemctl restart ravanreverse.service
# Or, for a named profile:
sudo systemctl restart 'ravanreverse@PROFILE.service'
```

## Tests

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

The helper runs inner-transport tests, local SOCKS5 and WARP HTTP CONNECT integration tests, static analysis, and amd64/arm64 builds. Live WARP validation requires an active WARP client and Internet connectivity; it is not run as a live test in an offline build environment.
