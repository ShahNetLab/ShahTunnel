<p align="center">
  <img src="docs/img/shah-tunnel-logo.png" alt="ShahTunnel logo" width="220" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>v1.8.0 · Authenticated reverse TCP tunnel · TCP + QUIC/UDP adaptive transport</strong></p>
<p align="center">An authenticated Hub↔Agent reverse tunnel with four TCP transport choices and an independent Hysteria 2 / QUIC / UDP path.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## Quick install

After the complete v1.8.0 source has been published to the repository's public `main` branch, run this command as `root` on both servers:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

Until v1.8.0 is published on `main`, install from this release ZIP. The remote bootstrap intentionally rejects an older or mixed-version branch:

```bash
unzip ShahTunnel-v1.8.0.zip
cd ShahTunnel-v1.8.0
bash ./S1T-START.sh
```

Select `Hub` on the Iran server and `Agent` on the outside server.

## Network flow

<p align="center">
  <img src="docs/img/ShahTunnel-Network-Flow-v1.8.0-en.jpg" alt="ShahTunnel 1.8.0 network flow with four TCP transports and Hysteria 2 QUIC over UDP" width="100%" />
</p>

## Multiple named tunnels on one server

- The menu can create several independent tunnel profiles on the same VPS. Give each profile a unique name.
- Each named profile has its own configuration, certificate/key files, Hysteria files, local SOCKS port and `ravanreverse@NAME.service` systemd unit.
- Existing profiles are never overwritten when a new name is created. A new profile is rejected if its TCP/UDP listen ports conflict with an existing profile.
- Menu options 2–6 ask which profile to operate on. Option 7 asks for the exact name twice, stops only that profile and removes only its directory. Option 8 removes all ShahTunnel profiles.
- The old `/etc/ravanreverse/config.json` and `ravanreverse.service` continue to work as the `default` profile.

## Tunnel operation

1. **Hub** accepts public TCP connections and maps each public listener to a configured mapping ID.
2. **Agent** initiates authenticated outbound tunnel lanes to the Hub and forwards each matching mapping ID to its configured local target.
3. Each lane carries framed, multiplexed TCP streams. The default is **12 independent lanes** (configurable up to 16); streams are bounded by per-lane and queue limits.
4. The inner ShahTunnel channel remains protected by TLS 1.3, the setup token and SHA-256 certificate pinning, regardless of the selected outer transport.
5. In option **8**, first-time lanes are spread over five candidates. Every lane remembers its last successfully authenticated transport and tries it first after reconnecting.
6. The per-stream in-flight window is 16 × 32 KiB frames, while the global queued-payload budget remains capped at 64 MiB to bound memory use on small VPS plans.

## Transport menu

Note: options 1–8 below are the transport choices inside the Hub/Agent setup wizard. They are not the main operations-menu numbers. In the main menu, option 1 creates a tunnel and option 7 deletes one selected tunnel.

Choose the same policy on the Hub and Agent:

| Option | Transport | Path |
|---|---|---|
| `1` | TCP/TLS | Native TLS-protected stream on the control port. |
| `2` | WebSocket/TLS | Binary WebSocket frames over TLS on the control port. |
| `3` | HTTP/2 CONNECT | Full-duplex CONNECT on control port + 1. |
| `4` | HTTP/1.1 CONNECT/TLS | CONNECT on control port + 2. |
| `5` | HTTP CONNECT fallback | HTTP/2 CONNECT, then HTTP/1.1 CONNECT. |
| `6` | Automatic TCP fallback | TCP/TLS, then WebSocket/TLS. |
| `7` | Hysteria 2 / QUIC / UDP | Independent UDP transport with Salamander packet obfuscation. No TCP fallback in this single-transport mode. |
| `8` | Full adaptive failover | All four TCP paths plus Hysteria 2 / QUIC / UDP. This is the default recommended configuration when both networks allow the required ports. |

### Option 8 health and recovery

- Each active ShahTunnel lane sends an authenticated heartbeat every 5 seconds.
- A lane is closed after 20 seconds without a PONG. Its worker then reconnects and tries the next path. A single lost heartbeat does not trigger failover.
- Hysteria 2 runs as a managed child process of ShahTunnel. If it exits, ShahTunnel restarts it with jittered backoff.
- When a transport cannot establish a session or its lane closes, that lane tries the remaining transports in order. A failed transport is put into a 12-second per-Agent circuit-breaker cooldown to avoid synchronized retries; it is probed again after the cooldown. If every path is cooling down, the manager probes the full list again.
- In adaptive mode, a Hysteria start/configuration failure is non-fatal: the four TCP alternatives continue to run. In option 7 (Hysteria-only), failure to start the UDP sidecar is fatal by design.
- **Failover is per lane, not seamless migration of an in-flight TCP stream.** If its lane dies, an existing public TCP stream on that lane closes; the lane reconnects for new streams. Silent blackholes can take about 20–25 seconds to be detected, plus the next dial/handshake time.

## Hub firewall ports

For a Hub control port of `9443`:

| Port | Protocol | Purpose |
|---|---|---|
| `9443` | TCP | Native TCP/TLS, WebSocket/TLS and inner loopback control. |
| `9444` | TCP | HTTP/2 CONNECT. |
| `9445` | TCP | HTTP/1.1 CONNECT. |
| `9446` | UDP | Hysteria 2 / QUIC. |

- **Option 7:** expose `9446/UDP` only for the tunnel control path. The inner control listener is bound to `127.0.0.1`; it is not exposed publicly. Keep the configured public service-mapping ports open separately.
- **Option 8:** expose `9443/TCP`, `9444/TCP`, `9445/TCP` and `9446/UDP`. Open only what your chosen mode actually uses, plus the public service-mapping ports.
- The UDP tunnel port is always the control port + 3. Ensure it does not overlap with another UDP listener on the Hub.

## Agent credential display and copy

After Hub setup, the Agent token and certificate fingerprint are shown as compact single-line values for mobile terminals. New Agent tokens still contain 256 bits of randomness and use unpadded Base32. SHA-256 fingerprints are displayed as 43-character unpadded Base64URL; the Agent accepts this representation and continues to accept legacy 64-character hexadecimal fingerprints. New Hysteria and Salamander passwords also contain 256 random bits and use 52-character Base32; existing hexadecimal profile values remain supported.

Each credential is displayed in its own original-style framed card. On SSH terminal apps that forward xterm mouse events and permit OSC 52 clipboard writes, tapping anywhere inside a credential card copies only that card's value. No numbered copy menu is shown. If the SSH app does not forward pointer events or blocks OSC 52, use the terminal's native text-selection/long-press behavior; generic SSH terminals do not provide a universal tap-to-copy API.

## UDP path security

- Hysteria 2 v2.13.0 carries the inner ShahTunnel TLS 1.3 control stream over QUIC/UDP.
- Salamander obfuscation uses a separate random 256-bit password that must match on Hub and Agent. Hysteria authentication has its own random 256-bit password.
- The Agent uses Hysteria's `pinSHA256` against the Hub certificate. The inner ShahTunnel TLS session independently validates the same certificate fingerprint and authenticates the ShahTunnel token.
- The Hub's Hysteria ACL is default-deny: it permits only `127.0.0.1:<control-port>` over TCP and rejects every other destination. The local SOCKS5 endpoint listens only on `127.0.0.1` on the Agent.
- The Hysteria binary and Go toolchain are downloaded as pinned versions and checksum-verified by the installer. Keep `/etc/ravanreverse` restricted to root; it contains credentials and private keys. Named profiles are stored below `/etc/ravanreverse/profiles/NAME`.

## Application traffic and Instagram video

Public mappings in this release are **TCP mappings**. Hysteria 2 / QUIC / UDP is an independent carrier for the ShahTunnel control/data stream, but the Agent's local SOCKS5 connector uses TCP CONNECT (`disableUDP: true`). It does **not** forward arbitrary UDP/443 or an app's native HTTP/3 datagrams as separate UDP mappings. If Instagram falls back to HTTPS over TCP, the larger bounded in-flight window and existing TCP keepalive/low-latency socket settings can help reduce throughput stalls on high-latency links. If the app insists on QUIC/HTTP/3 or the underlying mobile network changes, this version cannot guarantee uninterrupted playback. True end-to-end UDP mapping needs a separate UDP association/datagram data plane and must be built and tested on both Hub and Agent; it is not claimed as implemented here.

## Limits you should plan for

QUIC/UDP provides a genuinely separate transport family from TCP for the outer ShahTunnel transport. Salamander can help when a network filters QUIC/HTTP/3 patterns but still carries UDP. It **cannot** make UDP work when UDP is blocked or unusable. If all Hub IP addresses are blocked, the Hub has no reachable uplink, or international connectivity is completely cut, no protocol on that same server can guarantee a working path. A second independently routed server/uplink is required for that failure domain. IP source spoofing is not included: it does not create a usable return path for a TCP/UDP session.

Hysteria's optional Linux “Mimic / Fake TCP” mode is not enabled. It requires a separate executable and kernel XDP/eBPF support; it is not equivalent to changing UDP packet source addresses and should not be presented as a software-only fallback.

## Compatibility and verification

Legacy v1.6.x configuration files remain readable. Options `1`–`6` retain their earlier behavior. The old `adaptive` setting still means the four legacy TCP paths; the new option 8 uses `adaptive_all` and requires matching Hysteria credentials on both ends. Run Hub setup first, then copy the token, certificate fingerprint, Hysteria password and Salamander password into Agent setup.

Run local checks with Go 1.27.3 already installed:

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

The verification script tests the ShahTunnel code and builds Linux `amd64` / `arm64` binaries. It does not simulate filtering on a real ISP; test the selected UDP/TCP ports from both actual server networks before relying on the tunnel.
