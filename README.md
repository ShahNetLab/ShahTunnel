<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel Galactic emblem" width="290" />
</p>

<h1 align="center">SHAH TUNNEL 3.0.0</h1>
<p align="center"><strong>GALACTIC EDITION · PROFILE-ISOLATED REVERSE TCP TUNNEL</strong></p>
<p align="center">One Hub. Multiple Agents. Adaptive lanes. Independent egress paths.</p>

<p align="center">
  <a href="README-fa.md">🇮🇷 فارسی</a> &nbsp;·&nbsp;
  <a href="#network-flow">🌌 Network Flow</a> &nbsp;·&nbsp;
  <a href="#tunnel-capabilities">⚡ Capabilities</a> &nbsp;·&nbsp;
  <a href="https://t.me/MediaZet">🚀 Install on Telegram</a>
</p>

<p align="center">
  <a href="https://t.me/MediaZet"><img src="https://img.shields.io/badge/Telegram_Channel-%40MediaZet-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="Join ShahTunnel Telegram channel @MediaZet" /></a>
  &nbsp;
  <a href="https://t.me/cloudflare0_bot"><img src="https://img.shields.io/badge/Cloudflare_Bot-%40cloudflare0_bot-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="Open Cloudflare Telegram bot @cloudflare0_bot" /></a>
</p>
<p align="center"><sub>Join the channel for ShahTunnel updates and support. Use the bot for Cloudflare operations.</sub></p>

<a id="network-flow"></a>
## 🌌 Network Flow

<p align="center"><strong>GALACTIC NETWORK ARCHITECTURE</strong><br/><sub>Reverse TCP relay · Adaptive transports · Isolated Agent egress</sub></p>
<p align="center"><img src="docs/img/ShahTunnel-Network-Flow-v3.png" alt="ShahTunnel 3.0.0 Galactic Network Flow" width="100%" /></p>

<a id="tunnel-capabilities"></a>
## ⚡ Tunnel capabilities

<table>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ Hub–Agent reverse relay</h3>
<sub>Hub accepts public TCP connections. Agents open authenticated outbound lanes and forward streams to mapped local services.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ Adaptive transports</h3>
<sub>TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT and HTTP/1.1 CONNECT are available as inner tunnel transports.</sub>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ Lane-level recovery</h3>
<sub>Failed lanes recover independently; healthy lanes do not need to be dropped with them.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ Profile isolation</h3>
<sub>Each tunnel profile has its own configuration and systemd service. Operations stay scoped to the selected profile.</sub>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ Independent Agent egress</h3>
<sub>Agent transport can use Direct, WARP/MASQUE, WARP/WireGuard or Psiphon/SOCKS5, according to the selected mode.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ Per-profile Xray WARP</h3>
<sub>Only the selected Xray inbound is cloned to a loopback-only sidecar and routed through the local WARP SOCKS5 proxy.</sub>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>🔵✔ Automatic DNS path</h3>
<sub>The sidecar handles client DNS and sends its DoH resolver traffic through the same profile-specific WARP egress.</sub>
</td>
<td width="50%" valign="top">
<h3>🔵✔ Host-route safety</h3>
<sub>No server default-route changes, SSH restarts, or edits to the X-UI-managed Xray configuration and service.</sub>
</td>
</tr>
</table>

## 🚦 Tunnel transport matrix

| Option | Transport / strategy | Tunnel behaviour |
|:--:|---|---|
| `1` | TCP/TLS | TLS-protected stream between Hub and Agent. |
| `2` | WebSocket/TLS | Tunnel stream carried in WebSocket binary frames over TLS. |
| `3` | HTTP/2 CONNECT | CONNECT stream over TLS on control port + 1. |
| `4` | HTTP/1.1 CONNECT/TLS | CONNECT stream over TLS on control port + 2. |
| `5` | HTTP CONNECT fallback | HTTP/2 first, then HTTP/1.1. |
| `6` | Automatic fallback | TCP/TLS first, then WebSocket/TLS. |
| `7` | Full Adaptive Failover | All four inner transports; each lane prefers its last successful transport. |
| `8` | External egress | Select Agent egress: WARP/MASQUE, WARP/WireGuard or Psiphon/SOCKS5. |
| `9` | WARP egress | Per-profile Xray egress through the local WARP SOCKS5 proxy. |

## 🌐 Per-tunnel WARP egress for Xray

<table>
<tr><td>
<h3>🔵✔ Automatic setup for new Agents</h3>
<sub>When an Agent is created with MASQUE and the Cloudflare Local Proxy is already active, ShahTunnel prepares the dedicated Xray sidecar and DNS path before starting that Agent.</sub>
</td></tr>
<tr><td>
<h3>🔵✔ Existing Agent profiles</h3>
<sub>Use Manager → [9] WARP egress. ShahTunnel discovers the Xray inbound associated with the selected profile mapping and creates a loopback-only clone.</sub>
</td></tr>
<tr><td>
<h3>🔵✔ Isolation boundaries</h3>
<sub>Other Xray inbounds and profiles stay Direct. The X-UI-managed Xray service, SSH and host default route are not modified or restarted.</sub>
</td></tr>
</table>

**WARP Local Proxy requirement:** per-tunnel Xray egress requires the Cloudflare `WarpProxy` / MASQUE local SOCKS5 listener. It is not system-wide WARP routing. If the local proxy is unavailable, ShahTunnel does not silently replace the isolated path with a host-wide route.

## Install

Select **🚀 Install on Telegram** above to open the ShahTunnel channel for release and installation guidance. The Linux installer is also available directly:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

Run as root on a supported Linux server (amd64 or arm64) with systemd. The installer downloads the source and builds the ShahTunnel binary on the target server.

## Verify transports

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

---

<p align="center"><strong>SHAH TUNNEL 3.0.0 · GALACTIC EDITION</strong><br/><sub>One Hub. Many Agents. Independent paths. A network that keeps moving.</sub></p>
