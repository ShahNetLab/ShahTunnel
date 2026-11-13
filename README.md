<div align="center">

<img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel Galactic emblem" width="100%">

# ShahTunnel 4.0.2

[![Version](https://img.shields.io/badge/version-4.0.2-168BFF?style=flat-square)](https://github.com/ShahNetLab/ShahTunnel)
![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey?style=flat-square)
[![Build Go 1.26.1](https://img.shields.io/badge/build-Go%201.26.1-00ADD8?style=flat-square&logo=go)](S1T-START.sh)

<p align="center">
<a href="https://t.me/MediaZet"><img src="https://img.shields.io/badge/Telegram-Channel%20%40MediaZet-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="Join ShahTunnel Telegram channel"></a>
&nbsp;
<a href="https://t.me/cloudflare0_bot"><img src="https://img.shields.io/badge/Telegram-Cloudflare%20Bot%20%40cloudflare0__bot-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="Open Cloudflare bot"></a>
</p>

<p align="center">Support ShahTunnel and get project updates by joining the channel. The bot is for Cloudflare operations.</p>

**English** · [فارسی](README-fa.md)

[⚡ Capabilities](#capabilities) · [🚀 Install](#install)

</div>

---

<a id="network-flow"></a>
## Network Flow

The Hub-to-Agent forwarding path and optional per-profile Internet egress are separate: the tunnel forwards mapped TCP services to Agent-side targets, while the optional Xray sidecar sends only the selected inbound through that Agent profile’s WARP or Psiphon SOCKS5 egress.

```text
Client → Hub public mapping → authenticated Agent lanes → Agent local target
Selected Xray inbound → loopback-only Xray sidecar → WARP or Psiphon SOCKS5 → Internet
```

<p align="center"><img src="docs/img/ShahTunnel-Network-Flow-v4.png" alt="ShahTunnel 4.0.2 Network Flow" width="100%"></p>

## Capabilities

| | Capability | What it does |
|:--:|---|---|
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Hub–Agent reverse relay** | The Hub exposes public TCP listeners; Agents connect outward and forward each mapping to its local target. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Independent tunnel profiles** | Each named profile has its own configuration and systemd service. Start, stop and restart operations are profile-scoped. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Adaptive transport lanes** | Four implemented transports can be selected individually or used by adaptive failover modes. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Lane-level recovery** | Each Agent lane reconnects independently; one failed lane does not require dropping every healthy lane. Direct/WARP Agents default to 12 lanes; Option 9 is capped at 4, and Psiphon-only Agents at 3, to avoid overloading fragile Psiphon relays. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Multiple port mappings** | Mapping IDs pair Hub public listeners with Agent-side local targets. IDs must match on both ends. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **External Agent egress** | Agent traffic can use Direct, Cloudflare WARP/MASQUE or Psiphon/SOCKS5. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Per-profile Xray WARP** | A selected Xray inbound is cloned to a loopback-only sidecar and routed through the local WARP SOCKS5 proxy. |
| ![✓](https://img.shields.io/badge/%E2%9C%93-included-168BFF?style=flat-square) | **Automatic WARP DNS path** | The isolated sidecar handles client DNS and routes its DoH resolver traffic through the same WARP egress. |
| **Per-profile Psiphon user egress** | Selected Agent Xray inbounds are cloned into an isolated sidecar; TCP and DNS use Psiphon SOCKS5, while UDP is blocked to prevent direct leakage. |


### Automatic Psiphon egress for user traffic

When a new Agent profile is created with Psiphon egress, ShahTunnel automatically clones only the mapped Xray inbounds into a dedicated loopback-only sidecar before starting the Agent. TCP and DNS traffic use that profile's Psiphon SOCKS5 proxy. Psiphon's local port-forward SOCKS proxy carries TCP streams, not UDP; UDP and unknown network types are routed to a Blackhole outbound so they cannot silently fall back to the Agent's direct Internet connection. Consequently UDP/QUIC apps and ICMP ping are not supported on this Psiphon-only user path. No separate Psiphon action is added to the manager menu. Existing profiles are left untouched; this automatic setup applies to newly created Agent profiles. The X-UI source config, unrelated inbounds, other profiles, SSH and host routes are left unchanged.

**4.0.2 X-UI detection fix; 4.0.1 adaptive egress and 4.0.0 Psiphon performance tuning:** Tunnel-lane PING/PONG sampling runs every 5 seconds, uses a quicker 1/4 EWMA, and ranks only RTT samples fresher than 15 seconds; stale measurements cannot keep a degraded lane selected. Active-stream load remains part of the score. The isolated Xray sidecar keeps DNS caching enabled. Psiphon buffer limits are selected from actual host resources: below 3 GiB RAM, conservative Meek/relay limits and the documented SSH channel window default of 4 (128 KiB) are retained; at or above 3 GiB, Meek/relay caps are lifted and the SSH channel window is set to 16 (512 KiB) to improve TCP throughput on high-RTT paths. CPU-thread limiting is lifted only on hosts with at least 2 CPUs, and Psiphon's default tunnel-pool size is preserved. These are throughput and path-selection optimisations, not a promise that the physical Psiphon route or a client app's end-to-end connection time will have a lower RTT. The SOCKS5 user path carries TCP/DNS only; UDP/QUIC and ICMP ping are not supported and are blocked rather than sent Direct.

## Hub↔Agent transport modes

Choose a mode during tunnel creation. The Hub and Agent must use compatible settings.

| Wizard option | Mode | Behaviour |
|:--:|---|---|
| `1` | TCP/TLS | TLS-protected stream between Hub and Agent. |
| `2` | WebSocket/TLS | Carries the tunnel stream in WebSocket binary frames over TLS. |
| `3` | HTTP/2 CONNECT | Uses HTTP/2 CONNECT over TLS on the control port + 1. |
| `4` | HTTP/1.1 CONNECT/TLS | Uses HTTP/1.1 CONNECT over TLS on the control port + 2. |
| `5` | HTTP CONNECT fallback | Tries HTTP/2 CONNECT, then HTTP/1.1 CONNECT. |
| `6` | Automatic fallback | Tries TCP/TLS, then WebSocket/TLS. |
| `7` | Full Adaptive Failover | Uses all four implemented transports; each lane remembers its last successful transport. |
| `8` | External egress | On an Agent, select Cloudflare MASQUE or Psiphon/SOCKS5. |
| `9` | All-protocol adaptive | On an Agent, probes Hub routes and ranks reachable paths by connection latency, then uses Xray leastPing to select the client egress between Psiphon and WARP Local Proxy. |

### 4.0.2 X-UI Xray detection fix

Version 4.0.2 fixes legacy Option 9 upgrades on hosts where Xray is launched by `x-ui.service` with a relative config argument such as `-c bin/config.json`. Runtime discovery now reads the complete TCP LISTEN table and selects the PID by its local port, instead of depending on an `ss` filter expression that can return an empty result on some iproute2 builds. This allows an existing Psiphon-only ShahTunnel sidecar to be regenerated with the Psiphon + WARP Local Proxy leastPing balancer. The original X-UI config and service, SSH, host routes, and Hub are not modified. The installer restarts only active Agent profiles configured for Psiphon or adaptive egress.

### Option 9 adaptive behavior in 4.0.2

- Agent-to-Hub candidates (Direct, configured Psiphon, and active WARP/MASQUE) are probed using a real TCP connection to the Hub endpoint. Reachable candidates are ordered by measured connect latency; the shared result is cached for 45 seconds and invalidated when a route exhausts its transport attempts.
- All four adaptive inner transports are attempted on each candidate. A working route remains preferred until its connection fails; the next reconnect re-probes the candidate set. This is a Hub-path latency/health check, not a sustained Mbps throughput benchmark.
- User Xray traffic has a separate egress balancer: Xray Observatory plus `leastPing` chooses between the profile's Psiphon SOCKS5 and a configured WARP Local Proxy, with health/latency probes every 20 seconds. A loopback WARP Proxy configured in `warp-cli settings` is included even when its listener is not ready at process start, allowing Xray to select it once it becomes healthy.
- Direct public-VPS egress is intentionally excluded from the user Xray balancer to prevent the VPS address from becoming the client's apparent exit. If both Psiphon and WARP are unavailable, TCP/DNS is fail-closed (blackholed); UDP/QUIC and ICMP remain blocked on this TCP-only profile. Direct may still be selected for the Agent control connection to Hub.
- If WARP Local Proxy is not configured at all, Psiphon is the only Xray user-egress candidate. Option 9 does not install/configure WARP or alter system routes/SSH.

### Agent egress providers

| Provider | Requirement / path |
|---|---|
| `Direct` | Agent-to-Hub control path over the normal server route; it is not a direct user-Xray exit in Option 9. |
| `Cloudflare WARP / MASQUE` | WARP control route for Agent-to-Hub; isolated user-Xray egress uses the per-app WarpProxy / Local Proxy. System Tunnel is not used as a per-profile client exit. |
| `Psiphon / SOCKS5` | Profile-scoped Agent-to-Hub route and Xray user egress through its loopback SOCKS5; the official ConsoleClient/config are provisioned automatically. |
| `Adaptive` | For Agent-to-Hub control only: probes active MASQUE, configured Psiphon and Direct. User-Xray egress is separately selected between Psiphon and WARP Local Proxy. |

### Psiphon through the public TCP/443 Mapping

When Psiphon cannot reach the Hub control port (for example, a custom `9448`), the Agent uses the Hub public Mapping endpoint on `443` for Psiphon egress only; the Direct path continues to use the configured control port. The Step 06 default is independent of the control port and points to TCP/443. The Hub distinguishes ShahTunnel control traffic from ordinary TLS with the dedicated `shah-tunnel-control/1` ALPN and forwards normal ClientHello bytes unchanged. This does not take over the public port, move a Mapping, or modify X-UI.

For the complete ShahTunnel 4.0.2 feature set, run **4.0.2 on both Hub and Agent**. A public Mapping must already be enabled on the Hub and reachable through Psiphon. The Agent wizard lets you override the alternate endpoint. Existing profiles using `HubAddr` on `9443` automatically derive `PsiphonHubAddr` as the same host on port `443`.

### Automatic Psiphon setup

When an Agent selects `Psiphon / SOCKS5` (or the adaptive egress option), ShahTunnel automatically:

- builds the official Psiphon ConsoleClient from a pinned upstream source revision for the host architecture (`amd64` or `arm64`);
- verifies the resulting executable architecture and version before installation;
- creates a private per-Agent JSON configuration with the public client identity, authenticated server-list mirrors, server-entry signature key, and exchange-obfuscation key;
- assigns a unique `127.0.0.1` SOCKS5 port and private data directory;
- grants that Agent service write access only to its own Psiphon data directory;
- starts ConsoleClient in local-proxy mode. Local SOCKS5 readiness is distinguished from a real Psiphon tunnel and a connected Agent lane. If SOCKS5 becomes ready first, the service remains active and the wizard reports `PENDING` rather than claiming a successful connection. `ListenInterface` remains unset so the local SOCKS5 listener uses Psiphon's loopback binding. Psiphon's WebRTC ICE stack can still enumerate host interfaces through `AF_NETLINK`; the service allow-list explicitly includes that family while retaining `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (no `CAP_NET_ADMIN`). This enables interface discovery without permitting route changes. Diagnostic notices are written to the local journal; they may contain sensitive session/network details and should not be published.

For an existing Agent profile whose earlier Psiphon bootstrap did not connect, run `sudo bash repair-psiphon-profile.sh PROFILE` from the extracted project directory. The helper backs up and repairs only that profile's Psiphon JSON and restarts only its matching `ravanreverse@PROFILE.service` unit.

No TUN device, default route, SSH service, or X-UI service is changed. The first Psiphon setup downloads and builds the official client; it requires access to GitHub source hosting and the Go toolchain distribution. For a newly created Agent that selects Psiphon, both its outer TCP lanes to the Hub and its mapped end-user Xray TCP/DNS traffic use the profile's Psiphon SOCKS5 path; UDP is blocked on the user sidecar to prevent direct leakage.

> The creation wizard's option `9` means **All-protocol adaptive**. There is no WARP egress action in the main manager menu anymore: WARP is applied automatically while creating an Agent profile when selected as its external egress.

## Automatic per-tunnel WARP egress for Xray

- **New Agent profiles:** choose Cloudflare WARP over MASQUE in the Agent creation wizard. ShahTunnel verifies that WARP is connected over MASQUE and that its loopback **WarpProxy / Local Proxy** is available, then prepares the dedicated Xray sidecar and WARP-routed DNS before starting the Agent.
- **Isolation:** only the selected profile's cloned Xray inbounds use that profile's local WARP SOCKS5 proxy. Other profiles and inbounds remain unchanged.
- **Host safety:** the X-UI-managed Xray config/service, SSH and server routes are not modified or restarted by this per-profile integration.
- **Existing Agent profiles:** the automatic integration is performed at creation time. Recreate an Agent profile to add this behavior; there is no separate manager-menu action.

Per-tunnel WARP requires Cloudflare **WarpProxy / Local Proxy** in MASQUE mode. **System Tunnel mode is deliberately rejected** for this per-profile feature because its routing is host-wide and cannot guarantee isolation to one Agent. If Local Proxy is unavailable, profile creation stops with an explanatory error; ShahTunnel does not silently fall back to Direct or modify host routes.

## Day to day

`sudo shah-tunnel menu` opens the manager. Its operations are scoped to the selected profile:

| Menu option | Action |
|:--:|---|
| `1` | Create a new tunnel profile (Hub, Agent or Relay). |
| `2` | Start a selected tunnel. |
| `3` | Stop a selected tunnel. |
| `4` | Restart a selected tunnel. |
| `5` | Show status and recent logs. |
| `6` | Configure scheduled restarts for active tunnels. |
| `7` | Delete one selected tunnel profile. |
| `8` | Complete uninstall. |

Useful commands:

```bash
sudo shah-tunnel version
sudo shah-tunnel menu
sudo systemctl status 'ravanreverse@PROFILE.service' --no-pager -l
sudo journalctl -u 'ravanreverse@PROFILE.service' -n 80 --no-pager
```

Replace `PROFILE` with the selected profile's systemd instance name. The manager's **Status & Logs** entry is the simplest way to inspect the selected tunnel.

## Security

- Keep the Hub token and certificate fingerprint private. The Agent must use the exact values generated by its Hub.
- Restrict the Hub firewall to the selected control/CONNECT ports and the public mapping ports you actually use.
- Do not publish tokens, private keys, full tunnel configs or unredacted logs in issues or screenshots.
- The optional Xray WARP sidecar listens on loopback for its cloned inbound; it does not replace the X-UI-managed Xray service.
- Use ShahTunnel only on servers and services you own or are authorized to administer. See [SECURITY.md](SECURITY.md).

<a id="install"></a>
## Install

ShahTunnel uses a **Hub / Agent** layout. Install it on the Hub and on every Agent that should connect to it. A third server can optionally run as a Relay.

**Requirements:** Linux `amd64` or `arm64`, `systemd`, root access, and outbound connectivity from each Agent to the Hub. The installer downloads and verifies the pinned Go 1.26.1 toolchain, then builds the Linux binary on the server.

**1. Run the installer** on each server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

The manager opens after installation. You can reopen it with:

```bash
sudo shah-tunnel menu
```

**2. Configure the Hub**

1. Choose **Create a new tunnel** and select **HUB**.
2. Set the control listener (default `0.0.0.0:9443`) and the accepted Hub↔Agent transport.
3. Add each public port mapping. Give every mapping an ID such as `main` or `web`.
4. Save the generated **Agent token** and **certificate SHA-256 fingerprint**. The Agent must use both values exactly.

**3. Configure each Agent**

1. Create a tunnel and select **AGENT**.
2. Enter the Hub address and control port, then choose a transport accepted by the Hub.
3. Enter the token and certificate fingerprint from the Hub.
4. Add the same mapping IDs and set each local target, for example `127.0.0.1:443`.
5. Save the profile. ShahTunnel enables its dedicated service and reconnects dropped lanes automatically.

**4. Open only the required firewall ports.** The Hub needs its selected control listener, any selected CONNECT port (`control + 1` for HTTP/2 or `control + 2` for HTTP/1.1), and the public mapping ports. Agents initiate the connection to the Hub; local targets stay on the Agent side.

## Troubleshooting

| Symptom | First check |
|---|---|
| Agent does not connect | Confirm Hub address, token, certificate fingerprint, matching transport mode and firewall ports. |
| HTTP/2 or HTTP/1.1 CONNECT fails | Check the additional Hub TCP port (`control + 1` or `control + 2`) selected for that mode. |
| A mapping does not forward | Confirm the mapping ID matches on Hub and Agent and the Agent-side target is reachable locally. |
| WARP egress does not activate | Before creating the Agent, confirm WARP is Connected over MASQUE and `warp-cli settings` shows a reachable `WarpProxy` Local Proxy listener. System Tunnel mode is not accepted for per-profile isolation. |
| Google/YouTube DNS fails through per-profile WARP | Check the dedicated `shah-tunnel-xray-warp-<profile>.service` status and its recent logs; do not change host routes. |

---

## Psiphon behavior and performance in 4.0.0

- A local SOCKS5 listener is not treated as proof that Psiphon has established an external tunnel. The Agent remains active while ConsoleClient retries, and the wizard reports a pending state until a real tunnel and Agent lanes are ready.
- For the selected Agent profile, TCP and DNS from its cloned Xray inbounds use that profile's loopback Psiphon SOCKS5 proxy. UDP, QUIC and unknown network types are blocked in the isolated sidecar rather than falling back to the server's direct route. ICMP ping is not carried by this SOCKS5 path.
- Psiphon remains in local SOCKS mode. ShahTunnel does not configure a TUN device, alter the host default route, grant `CAP_NET_ADMIN`, or change the X-UI-managed Xray service.
- Hub↔Agent lane RTT is measured with authenticated PING/PONG every five seconds. The Hub ranks lanes using fresh RTT samples and active-stream load; a sample older than 15 seconds is excluded. This internal lane RTT is **not** the same as the end-to-end latency shown by a client app.
- Psiphon buffer limits remain enabled on hosts with less than 3 GiB RAM. On hosts with at least 3 GiB RAM, the Meek and relay buffer caps are removed and the SSH channel window is set to 16 (512 KiB); low-memory hosts retain the documented default window of 4 (128 KiB). CPU thread limiting remains enabled on single-core hosts. The Psiphon tunnel-pool default is retained.
- These settings target TCP throughput and more responsive lane selection. They cannot remove the physical latency of the client's route to the Hub, the Psiphon relay, or the selected destination. A client-reported value such as 635 ms must be measured end-to-end before and after deployment; no fixed reduction is guaranteed.

Full-feature deployments should keep Hub and Agent on the same ShahTunnel 4.0.2 release. Historical version numbers are retained only in migration/repair code where they are needed to recognize existing installations; they are not separate current releases.
