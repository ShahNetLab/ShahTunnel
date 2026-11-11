<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V2.2.9 · Secure Reverse TCP Relay · Per-Profile WARP Xray Egress</strong></p>
<p align="center">A reverse TCP relay that carries public client connections through a Hub to mapped target services via authenticated Agent lanes. The private Hub↔Agent channel uses TLS 1.3, SHA-256 certificate pinning and adaptive recovery across four native transports and preconfigured Agent-side external network paths.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## 2.2.9 per-profile WARP egress for Xray clients

- Option 8 still uses Cloudflare WARP Local Proxy (`127.0.0.1:40000`) for the Agent-to-Hub carrier.
- When the Agent wizard asks whether VPN client traffic should also use WARP, it can prepare an isolated Xray sidecar from the currently running local Xray inbound. The original panel Xray config, process, listener and existing direct profiles are not edited or restarted.
- The sidecar listens only on loopback, clones the selected Xray inbound (including users and TLS/Reality settings), and routes its client traffic through the WARP SOCKS5 outbound. Shah Tunnel refreshes this sidecar from the panel config before each sidecar start.
- **Use a separate Hub profile for WARP clients.** Hub transport control port, mapping ID and public client port must be different from the existing direct Hub profile. Wizard defaults are control port +10, mapping ID `warp`, and public listener `0.0.0.0:8443`. Open the selected control port and public listener in the Iran firewall.
- Clients that should use WARP must connect to the dedicated public WARP port (default `8443`). Existing clients on their old public port continue to use the direct Xray target and are not changed.
- The Agent target must be a local Xray inbound on `127.0.0.1` or `::1`. The setup wizard locates the running Xray process/config, validates the cloned configuration with the same Xray binary, and refuses the profile if it cannot safely identify a unique inbound.
- WARP sidecars use the WARP Local Proxy SOCKS5 endpoint, do not add a VPS-wide route, and do not change SSH or the original Xray listener. If the local WARP proxy is not healthy for both IPv4 and IPv6, setup stops before saving the profile.
- This isolates TCP Xray client egress. Do not assume every UDP/QUIC flow is proxied by the Cloudflare Local Proxy; verify the actual protocol/egress required by your deployment.

## Compatibility and safety

Profiles without `target_egress: warp_xray` retain their original target and route. The sidecar is a separate Xray process bound to loopback and a dedicated local port; it never edits the panel's active config or restarts the panel's Xray service. A WARP Agent profile must use its own Hub control listener and public listener so Hub session selection cannot mix direct and WARP mappings. Existing direct tunnel profiles remain on their original Hub port, target port and Xray instance.

## Network flow

<p align="center">
  <img src="docs/img/ShahTunnel-Network-Flow.png" alt="Network flow: public clients, Hub, four authenticated private transports, Agent and local target service" width="100%" />
</p>

## Features

- **Four implemented transports:** TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT and HTTP/1.1 CONNECT/TLS.
- **Automatic recovery:** reconnect with jittered backoff; options 7 and 9 adaptively select the last successful native transport and (for option 9) external route per lane.
- **Security:** TLS 1.3 for the private Hub↔Agent channel, token authentication and SHA-256 certificate pinning.
- **Concurrency:** twelve independent lanes by default, bounded queues and load-aware session selection.
- **Management:** interactive CLI, systemd integration, status and logs, installer and local verification script.

## Transport menu

Choose the same transport policy on both Hub and Agent. Options 1–7 retain their original meaning; options 8 and 9 add external routing without replacing the old transports.

| Option | Transport / strategy | Behaviour |
|---|---|---|
| `1` | TCP/TLS | Native TLS-protected stream. |
| `2` | WebSocket/TLS | Tunnel stream carried in WebSocket binary frames over TLS. |
| `3` | HTTP/2 CONNECT | Bidirectional CONNECT stream over TLS on control port + 1. |
| `4` | HTTP/1.1 CONNECT/TLS | CONNECT stream over TLS on control port + 2. |
| `5` | HTTP CONNECT fallback | Tries HTTP/2 CONNECT, then HTTP/1.1 CONNECT if setup fails. |
| `6` | Automatic fallback | TCP/TLS, then WebSocket/TLS. |
| `7` | FULL ADAPTIVE FAILOVER — legacy | Preserves the original four implemented transports and fails over among them. |
| `8` | EXTERNAL TUNNEL | Uses one selected Agent-side external path with the authenticated TCP/TLS carrier. |
| `9` | FULL ADAPTIVE FAILOVER — all | Tries all four native transports over configured external paths and the direct route; selected external path is tried first, with direct/native fallbacks. |

### Hub firewall ports

If the Hub control port is `9443`:

- `9443/TCP`: TCP/TLS and WebSocket/TLS; also required by external-only option 8.
- `9444/TCP`: HTTP/2 CONNECT in options 3, 5, 7 and 9.
- `9445/TCP`: HTTP/1.1 CONNECT in options 4, 5, 7 and 9.

Option 8 uses only the authenticated TCP/TLS carrier, so it needs the control port. Option 7 keeps the original four native transports. Option 9 can use all four native transports and therefore needs the control port, control+1 and control+2. Open only the ports required by the selected transports.

### Agent-side external paths

The installer adds the official Cloudflare WARP package on supported Debian/Ubuntu APT systems, but it does not register or connect WARP during installation. The Agent wizard offers these external paths. The default selection is option `2` (Cloudflare WARP), not the preconfigured MASQUE gateway:

- **MASQUE:** connect through a preconfigured local MASQUE gateway exposed as a SOCKS5 endpoint (default `127.0.0.1:40001`). The wizard checks that this preconfigured SOCKS5 gateway answers before saving the profile. Shah Tunnel does not start a standalone MASQUE client.
- **Cloudflare WARP:** uses Cloudflare WARP Local Proxy (`127.0.0.1:40000`) over MASQUE as a SOCKS5 next-hop for this Agent profile’s Hub connections only. It does not enable full-device routing, change the VPS default route, or affect other tunnel profiles. Optionally, the wizard creates a separate Xray sidecar for client egress. The original panel listener stays direct.
- **WARP on WARP:** use a separately prepared second SOCKS5 chain endpoint (default `127.0.0.1:40002`). Shah Tunnel does not register a second Cloudflare client or create a second WARP tunnel by itself.
- **Tor/Psiphon:** enter the local SOCKS5 proxy address. Defaults are `127.0.0.1:9050` for Tor and `127.0.0.1:1080` for Psiphon; adjust them to the actual client settings. Destination hostnames are resolved by the proxy.

Option 7 is the original four-transport adaptive mode. Option 8 selects one external path and uses the authenticated TCP/TLS carrier. Option 9 combines the four native transports with configured external paths. SOCKS-backed paths, including WARP, are opened by the relevant Agent lane only; direct/native paths use ordinary direct sockets. Each lane remembers its last successful route and transport. A failed outer connection is re-established on another candidate; an already-active TCP flow is not migrated seamlessly and may reconnect. The Hub must be configured with the corresponding mode.
**WARP scope:** 2.2.9 keeps the Agent carrier and optional isolated Xray client egress on separate SOCKS5-based paths. Full-device route changes are not used. Use a dedicated Hub profile and public client port for WARP Xray clients; old direct profiles remain unchanged.

### WARP installation on restricted networks

The installer uses bounded timeouts when retrieving Cloudflare's official signing key. If `pkg.cloudflareclient.com` is unreachable from the VPS network, WARP package setup is skipped with a clear warning and the Shah Tunnel core installation continues; no routes are changed during installation. WARP paths remain unavailable until the official client is installed. For new profiles, no nftables rule, policy route, or device-level WARP route is needed. If an older full-device WARP profile is still active, restart that profile once with the new release before starting another Agent profile; the migration checks this state and refuses to alter a running legacy tunnel.
