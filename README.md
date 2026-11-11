<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V3.0.0 · Secure Reverse TCP Relay · Multi-layer Adaptive Recovery</strong></p>
<p align="center">ShahTunnel relays public TCP connections through a Hub and authenticated Agent lanes to mapped local services. Version 3 adds real Agent-side Psiphon SOCKS5 egress and validation for an already-connected Cloudflare WARP tunnel using MASQUE or WireGuard.</p>
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

On Linux, Cloudflare WARP is a system-level tunnel. For option 8, ShahTunnel verifies `warp-cli` presence, Connected status, the protocol reported by `warp-cli settings`, and a live `warp=on` egress check. ShahTunnel **never** runs `warp-cli connect`, changes the WARP protocol, disconnects WARP, or modifies system routes. WARP must already be active before the Agent service starts. The same status, protocol, and live egress checks are repeated before each reconnect, so a lost WARP tunnel does not silently fall back to the ordinary host route.

Enabling WARP can change the server's default route and interrupt SSH. Run the commands below only from a provider console or with a tested out-of-band recovery path; do not switch the default route from your only SSH session:

```bash
warp-cli tunnel protocol set MASQUE
warp-cli connect
warp-cli status
warp-cli settings | grep -i protocol
curl -fsS https://www.cloudflare.com/cdn-cgi/trace | grep '^warp=on$'
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
- MASQUE and WireGuard are Cloudflare WARP tunnel protocols managed by `warp-svc` at the system level; they are not independent per-socket proxies. ShahTunnel does not switch WARP protocols while running because doing so could interrupt SSH and all other host traffic. When WARP is active, its current system route is treated as a separately verified candidate; ensure the Hub IP is not excluded by the WARP split-tunnel policy. If the WARP tunnel drops, ShahTunnel skips it and moves to the next configured route.
- Psiphon is integrated as a SOCKS5 TCP proxy in this release; this path does not provide an independent UDP transport.
- Each lane reconnects independently. Healthy lanes and the SSH service are not restarted or modified.

## Multiple tunnel profiles and performance

Each create operation stores a unique named profile. Every profile runs as its own systemd service; Start, Stop, Restart, Status, and Delete act only on the selected profile. Existing profiles are not overwritten.

The per-stream in-flight window remains 64 frames of up to 64 KiB. Actual throughput depends on bandwidth, RTT, packet loss, congestion, qdisc, and host limits; no fixed throughput can be guaranteed.

## Install and upgrade

Run as root on Linux amd64 or arm64 with systemd:

```bash
sudo bash S1T-START.sh
```

The installer builds version `3.0.0` from the local source tree, verifies the pinned Go toolchain with SHA-256, and backs up an existing binary. It does not restart an already-active service during upgrade, avoiding interruption of current sessions. Legacy service/config names `ravanreverse.service` and `/etc/ravanreverse` remain for compatibility.

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

The helper runs inner-transport tests, a real local SOCKS5 TCP-dial integration test, static analysis, and amd64/arm64 builds. Live WARP validation requires an active WARP client and Internet connectivity; it is not run as a live test in an offline build environment.
