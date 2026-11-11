<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galactic network emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL 3.0.0</h1>
<p align="center"><strong>Reverse TCP Tunnel · Adaptive Lanes · Isolated Egress</strong></p>
<p align="center">A resilient, profile-based tunnel architecture: one Hub, multiple Agents, four inner transports, and independently managed outbound paths.</p>

<p align="center"><a href="README-fa.md">فارسی</a> · <a href="#network-flow">Network Flow</a> · <a href="#install">Install</a></p>

## Network Flow

<p align="center"><img src="docs/img/ShahTunnel-Network-Flow-v3.svg" alt="ShahTunnel 3.0.0 network flow" width="100%" /></p>

## The architecture

ShahTunnel is built like a small orbital network. The **Hub** is the public rendezvous point; each **Agent** establishes authenticated outbound lanes and forwards traffic to its mapped local services. A tunnel is not a single fragile connection: independent lanes can recover without taking down healthy lanes or unrelated profiles.

### Core capabilities

- **Four inner transports:** TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT, and HTTP/1.1 CONNECT/TLS.
- **Adaptive transport:** lane-level recovery and transport selection while preserving the same authenticated Hub–Agent channel.
- **Agent egress:** Direct, Cloudflare WARP over MASQUE or WireGuard, and Psiphon through a local SOCKS5 endpoint.
- **Per-tunnel WARP for Xray:** a dedicated Xray sidecar clones only the selected inbound onto loopback and sends that profile through WARP SOCKS5.
- **Automatic DNS path:** the isolated sidecar intercepts client DNS, uses Cloudflare/Google DoH, and routes resolver traffic through the same WARP egress.
- **Profile isolation:** each tunnel has its own configuration and systemd service; other Xray inbounds and other ShahTunnel profiles remain unchanged.

### WARP isolation, without host-wide routing changes

When a new Agent is created with MASQUE and Cloudflare Local Proxy (`WarpProxy`) is already active, ShahTunnel automatically prepares its per-tunnel Xray sidecar and DNS routing before the Agent starts. No manual JSON edits or shell commands are needed. For an existing Agent, use **Manager → [9] WARP egress**.

Only the selected profile's cloned loopback inbound uses the local WARP SOCKS5 proxy. The X-UI-managed Xray configuration and service are not edited or restarted. Other inbounds—including profiles that remain Direct—are not moved. ShahTunnel does not change the host default route, restart SSH, or connect/disconnect WARP. If Local Proxy is not active, per-tunnel isolation is not silently replaced with system-wide routing.

### Security and reliability

- TLS 1.3, token authentication, and SHA-256 certificate pinning for Hub–Agent authentication.
- Independent tunnel profiles and systemd services.
- Dedicated loopback-only Xray sidecars for selected WARP profiles.
- Failures are scoped to the affected lane/profile; no global route manipulation is performed by the per-tunnel WARP feature.

## Install

On a supported Linux server (amd64 or arm64) with systemd, run as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

The installer downloads the source and builds the ShahTunnel binary on the target server. It does not depend on a prebuilt project binary in the repository.

## Verify

Run the included transport verification script from the source directory:

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

---

<p align="center"><strong>SHAH TUNNEL 3.0.0</strong><br/>One Hub. Many Agents. Independent paths. A network that keeps moving.</p>
