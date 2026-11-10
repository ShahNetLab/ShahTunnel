<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V2.2.5 · Secure Reverse TCP Relay · External Paths + Adaptive Failover</strong></p>
<p align="center">A reverse TCP relay that carries public client connections through a Hub to mapped target services via authenticated Agent lanes. The private Hub↔Agent channel uses TLS 1.3, SHA-256 certificate pinning and adaptive recovery across four native transports and preconfigured Agent-side external network paths.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

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
- **Cloudflare WARP:** configure the official client in device mode (`warp+doh`) using MASQUE. This is required so both the Agent↔Hub carrier and the local target service's IPv4/IPv6 internet egress (including VPN-client egress) use WARP. Before changing modes, Shah Tunnel records the physical IPv4/IPv6 routes and installs an SSH reply route guard; direct native failover sockets use `SO_MARK` to keep using the physical VPS route.
- **WARP on WARP:** use a separately prepared second SOCKS5 chain endpoint (default `127.0.0.1:40002`). Shah Tunnel does not register a second Cloudflare client or create a second WARP tunnel by itself.
- **Tor/Psiphon:** enter the local SOCKS5 proxy address. Defaults are `127.0.0.1:9050` for Tor and `127.0.0.1:1080` for Psiphon; adjust them to the actual client settings. Destination hostnames are resolved by the proxy.

Option 7 is the original four-transport adaptive mode. Before it starts, Shah Tunnel returns any Shah-managed device WARP session to Local Proxy mode so the old native transports do not inherit WARP routing. Option 8 selects one external path and uses the authenticated TCP/TLS carrier. When that path is Cloudflare WARP, device-level MASQUE is enabled so the local target service's internet egress—and therefore VPN clients' visible IPv4/IPv6 egress—also uses WARP. Option 9 combines all four native transports with the configured external paths; the selected external path is tried first, then the physical direct route and other candidates. Direct/native fallback sockets are explicitly marked to use the physical VPS route while the WARP path uses WARP. Each lane remembers its last successful route and transport. A failed outer connection is re-established on another candidate; an already-active TCP flow is not migrated seamlessly and may reconnect. The Hub must be configured with the corresponding mode.

**WARP scope:** When option 8 selects WARP, or option 9 contains a WARP candidate, device-level WARP is active on the Agent host. Consequently, unmarked host traffic—including the local target service's outbound traffic—uses WARP. SSH replies and direct failover sockets are routed over the physical VPS link. Other independently running applications on that VPS may also use WARP during this mode; do not run unrelated services that must remain on the physical egress at the same time. Agent profiles with conflicting WARP and non-WARP egress policies cannot run simultaneously.

For an existing Agent profile that was saved with an unavailable MASQUE endpoint such as `127.0.0.1:40001`, upgrade the binary on the outside host and run:

```bash
ravanreverse repair-external
```

Select the Agent profile and choose option `2` (Cloudflare WARP). The command replaces only the selected external path, creates a private backup first, preserves the token, fingerprint, Hub address, mappings and lane count, and restarts the profile only when it was already active.

## Multiple tunnel profiles and upload throughput

Each create operation asks for a unique tunnel name and stores its configuration separately. Existing profiles remain intact. Every named profile runs as its own systemd instance; Start, Stop, Restart, Status, and Delete act on the selected profile. The profile-management menu keeps its separate delete and full-uninstall actions.

The per-stream in-flight window is increased to 64 frames of up to 64 KiB (about 4 MiB per stream), while each tunnel socket keeps a smaller bounded outbound queue to limit head-of-line delay. On Linux kernels that support BBR, the outer tunnel TCP socket attempts to use BBR per-socket; unsupported kernels retain their existing default. This reduces the throughput ceiling caused by a small flow-control window on high-RTT paths and can improve latency under load. Actual throughput still depends on link capacity, packet loss, congestion, kernel qdisc, and provider limits; application-level changes cannot prevent an uplink from being fully saturated without an appropriate network-level rate limit.

## Responsible use and privacy

ShahTunnel is a general-purpose TCP relay. Configure it only for servers and services you own or are explicitly authorized to administer. Do not use it to access third-party systems without permission, relay abusive traffic, or disrupt services. Operators are responsible for the endpoints and traffic they choose to forward.

The server information display may make outbound HTTPS requests to public IP and GeoIP providers (including ipify, icanhazip, checkip.amazonaws.com, ipinfo.io, ip.sb, ipapi.co and ipwho.is) to determine the server's public IPv4 address and country. These providers can observe the server's public IP and request metadata; the GeoIP lookups do not include the tunnel token or tunnel payload.

## Install

Extract the ZIP and run the installer from its folder as root:

```bash
sudo bash S1T-START.sh
```

After this updated version has been published to the repository's `main` branch, the one-command installer is:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

On supported Debian/Ubuntu APT systems, the installer also installs the official Cloudflare WARP package, but does not register or connect it during installation. When a WARP external path is selected and the Agent starts, Shah Tunnel installs the physical-route and SSH guard first, then enables device-level MASQUE. Options 1–7 return WARP to Local Proxy mode before starting so the old transports do not inherit WARP routing.

### WARP installation on restricted networks

The installer uses bounded timeouts when retrieving Cloudflare's official signing key. If `pkg.cloudflareclient.com` is unreachable from the VPS network, WARP package setup is skipped with a clear warning and the Shah Tunnel core installation continues; no routes are changed during installation. WARP paths remain unavailable until the official client is installed. At tunnel start, WARP device mode is refused if nftables, a physical default route, or the SSH route guard cannot be prepared safely. A not-yet-created numeric FIB table is treated as empty and is instantiated when Shah Tunnel adds its physical default route; existing routes or policy rules that reference the reserved table IDs are left untouched and cause a safe refusal.
