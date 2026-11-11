<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V2.2.8 · Secure Reverse TCP Relay · Profile-Scoped External Paths</strong></p>
<p align="center">A reverse TCP relay that carries public client connections through a Hub to mapped target services via authenticated Agent lanes. The private Hub↔Agent channel uses TLS 1.3, SHA-256 certificate pinning and adaptive recovery across four native transports and preconfigured Agent-side external network paths.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## 2.2.8 profile-scoped external paths

- Cloudflare WARP now uses the official client Local Proxy listener (`127.0.0.1:40000`) as a SOCKS5 next-hop for the selected Agent profile. It never enables device-wide routing as part of a normal Shah Tunnel profile.
- Native transports (options 1–7), other Agent profiles, SSH, and unrelated host applications retain their own normal routes. SOCKS-backed external paths are applied per Agent connection, not through global route or nftables changes.
- If the host is already connected in full-device WARP mode, the interactive wizard asks before switching to Local Proxy. Declining leaves the existing WARP route and saved profile untouched. A non-interactive service start will not silently convert an unknown or device-wide WARP configuration.
- The Hub carrier is the only traffic controlled by the Agent external path. The local target application (for example, Xray listening on `127.0.0.1:2083`) keeps its own outbound policy. To make VPN users' internet traffic exit through WARP, configure that Xray instance's own SOCKS5 outbound/routing separately or use an isolated target instance.
- Existing pre-2.2.8 full-device WARP Agent profiles must be restarted interactively once to migrate. A still-running legacy full-device profile is detected and not stopped or modified automatically.

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
- **Cloudflare WARP:** uses Cloudflare WARP Local Proxy (`127.0.0.1:40000`) over MASQUE as a SOCKS5 next-hop for this Agent profile’s Hub connections only. It does not enable full-device routing, change the VPS default route, or affect other tunnel profiles. The local target service keeps its existing egress policy; configure that application separately if its internet traffic must also use WARP.
- **WARP on WARP:** use a separately prepared second SOCKS5 chain endpoint (default `127.0.0.1:40002`). Shah Tunnel does not register a second Cloudflare client or create a second WARP tunnel by itself.
- **Tor/Psiphon:** enter the local SOCKS5 proxy address. Defaults are `127.0.0.1:9050` for Tor and `127.0.0.1:1080` for Psiphon; adjust them to the actual client settings. Destination hostnames are resolved by the proxy.

Option 7 is the original four-transport adaptive mode. Option 8 selects one external path and uses the authenticated TCP/TLS carrier. Option 9 combines the four native transports with configured external paths. SOCKS-backed paths, including WARP, are opened by the relevant Agent lane only; direct/native paths use ordinary direct sockets. Each lane remembers its last successful route and transport. A failed outer connection is re-established on another candidate; an already-active TCP flow is not migrated seamlessly and may reconnect. The Hub must be configured with the corresponding mode.
**WARP scope:** 2.2.8 uses WARP Local Proxy instead of full-device mode. This removes the global-route conflict between native and WARP Agent profiles, so multiple independent tunnel profiles can run together without changing each other’s routes. WARP here secures the Agent-to-Hub carrier only. It does not automatically change the public IP used by a local Xray/VPN target service; that service needs its own WARP SOCKS5 outbound/routing configuration. Profiles created by older releases with WARP device mode must be restarted once after upgrading so they migrate to the local proxy path.

### WARP installation on restricted networks

The installer uses bounded timeouts when retrieving Cloudflare's official signing key. If `pkg.cloudflareclient.com` is unreachable from the VPS network, WARP package setup is skipped with a clear warning and the Shah Tunnel core installation continues; no routes are changed during installation. WARP paths remain unavailable until the official client is installed. For new profiles, no nftables rule, policy route, or device-level WARP route is needed. If an older full-device WARP profile is still active, restart that profile once with the new release before starting another Agent profile; the migration checks this state and refuses to alter a running legacy tunnel.
