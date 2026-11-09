<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V2.2.1 · Secure Reverse TCP Relay · Legacy + New Protocol Failover</strong></p>
<p align="center">A reverse TCP relay that carries public client connections through a Hub to mapped target services via authenticated Agent lanes. The private Hub↔Agent channel uses TLS 1.3, SHA-256 certificate pinning and independent lane recovery. Option 7 preserves the original four native transports; option 8 adds Agent-side external paths; option 9 combines both sets.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## Network flow

<p align="center">
  <img src="docs/img/ShahTunnel-Network-Flow.png" alt="Network flow: public clients, Hub, four authenticated private transports, Agent and local target service" width="100%" />
</p>

## Features

- **Four implemented transports:** TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT and HTTP/1.1 CONNECT/TLS.
- **Adaptive recovery:** option 7 preserves the old four-transport policy. Option 9 distributes independent lanes across the four direct/native transport variants and each configured Agent external route, so healthy routes can be active concurrently. With the default 12 lanes, the four native variants plus up to six external routes can each receive a lane. If a lane's route fails, that lane rotates through the remaining candidates and reconnects with jittered backoff. A broken active TCP stream is re-established; its existing application session cannot be migrated seamlessly to another socket.
- **Security:** TLS 1.3 for the private Hub↔Agent channel, token authentication and SHA-256 certificate pinning.
- **Concurrency:** twelve independent lanes by default, bounded queues and load-aware session selection.
- **Management:** interactive CLI, systemd integration, status and logs, installer and local verification script.

## Transport menu

Choose the same transport or strategy on both Hub and Agent.

| Option | Transport / strategy | Behaviour |
|---|---|---|
| `1` | TCP/TLS | Native TLS-protected stream. |
| `2` | WebSocket/TLS | Tunnel stream carried in WebSocket binary frames over TLS. |
| `3` | HTTP/2 CONNECT | Bidirectional CONNECT stream over TLS on control port + 1. |
| `4` | HTTP/1.1 CONNECT/TLS | CONNECT stream over TLS on control port + 2. |
| `5` | HTTP CONNECT fallback | Tries HTTP/2 CONNECT, then HTTP/1.1 CONNECT if setup fails. |
| `6` | Automatic fallback | TCP/TLS, then WebSocket/TLS. |
| `7` | **FULL ADAPTIVE FAILOVER — legacy** | Preserves the original adaptive mode: only the four implemented native transports (TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT and HTTP/1.1 CONNECT). It does not add Agent external paths. |
| `8` | **NEW TUNNEL PROTOCOLS** | Uses one selected, prepared Agent-side path: MASQUE / Cloudflare WARP / WARP on WARP / Tor / Psiphon / Backhaul. The authenticated carrier to the Hub is TCP/TLS. |
| `9` | **FULL ADAPTIVE FAILOVER — all old + new** | Combines the four native transports with every configured Agent external path. Each lane tries candidates and reconnects through the next available candidate after a failure. The direct OS route is tried as well. |

The Hub controls which carrier/transport modes it accepts. Configure external clients and routes on the Agent. Options 7–9 must be selected consistently on both endpoints.

**Upgrade compatibility:** existing `agent_external_tcp` profiles continue to use their one selected external Agent path (now option 8). Existing `full_adaptive` profiles keep their combined adaptive behavior (now option 9). The installer does not rewrite or remove existing tunnel profiles.
### Hub firewall ports

If the Hub control port is `9443`:

- `9443/TCP`: native TCP/TLS and WebSocket/TLS.
- `9444/TCP`: HTTP/2 CONNECT (options 3, 5, 7 and 9).
- `9445/TCP`: HTTP/1.1 CONNECT (options 4, 5, 7 and 9).

Open only the ports needed by the selected mode. Mode 8 needs only the control port because its external-path carrier is TCP/TLS. Modes 7 and 9 can use all four native transports and therefore need the control port, control+1 and control+2.

### Agent-side external paths

External paths are configured on the outside Agent. On Ubuntu/Debian, the main Shah Tunnel installer automatically installs the official Cloudflare WARP package and configures its tunnel protocol to MASQUE. A first-time WARP registration/connection is completed only after an interactive acceptance of Cloudflare's Terms of Service and Privacy Policy. Tor, Psiphon and Backhaul clients, and any nested WARP-on-WARP route, must be installed/configured separately by the Agent operator. Add prepared paths in the Agent setup wizard:

- **MASQUE:** uses a prepared Agent-side OS route/interface. It can be the Cloudflare WARP interface configured to use MASQUE, or another MASQUE-capable route prepared by the operator.
- **Cloudflare WARP / WARP on WARP:** require `warp-cli status` to report `Connected` and `Network: healthy`; disconnected WARP paths are rejected rather than silently sent over the ordinary route. An optional interface can pin the socket to a prepared interface. The installer selects MASQUE for the Cloudflare WARP client.
- **WARP on WARP:** requires the nested WARP route/interface to be prepared on the Agent. Selecting it does not create a second independent WARP account or tunnel automatically.
- **Tor and Psiphon:** enter the client’s local SOCKS5 address (Tor defaults to `127.0.0.1:9050`; Psiphon requires its actual configured local endpoint). Shah Tunnel sends the Hub connection through SOCKS5 and uses proxy-side DNS for hostnames.
- **Backhaul:** enter the local raw-TCP forward exposed by the Backhaul client. Option 8 uses the forward for the Hub control port; option 9 also needs corresponding control+1 and control+2 forwards if HTTP/2 or HTTP/1.1 CONNECT candidates are to be used.

Option 7 is deliberately isolated from new external methods and retains the original four-transport adaptive behavior. Option 8 uses one selected new Agent path with a TCP/TLS carrier. Option 9 distributes lanes across all four native candidates and all configured external paths, keeping healthy candidates active concurrently when enough lanes are configured. If a route fails, its lane retries the remaining candidates. Failover is per lane and occurs after a connection fails; it does not migrate an already-open TCP stream without reconnecting. The Hub controls accepted transports; the Agent manages external-client setup and health.

## Multiple tunnel profiles and upload throughput

Each create operation asks for a unique tunnel name and stores its configuration separately. Existing profiles remain intact. Every named profile runs as its own systemd instance; Start, Stop, Restart, Status, and Delete act on the selected profile. The profile-management menu keeps its separate delete and full-uninstall actions.

The per-stream in-flight window is increased to 64 frames of up to 64 KiB (about 4 MiB per stream), while each tunnel socket keeps a smaller bounded outbound queue to limit head-of-line delay. On Linux kernels that support BBR, the outer tunnel TCP socket attempts to use BBR per-socket; unsupported kernels retain their existing default. This reduces the throughput ceiling caused by a small flow-control window on high-RTT paths and can improve latency under load. Actual throughput still depends on link capacity, packet loss, congestion, kernel qdisc, and provider limits; application-level changes cannot prevent an uplink from being fully saturated without an appropriate network-level rate limit.

## Responsible use and privacy

ShahTunnel is a general-purpose TCP relay. Configure it only for servers and services you own or are explicitly authorized to administer. Do not use it to access third-party systems without permission, relay abusive traffic, or disrupt services. Operators are responsible for the endpoints and traffic they choose to forward.

The server information display may make outbound HTTPS requests to public IP and GeoIP providers (including ipify, icanhazip, checkip.amazonaws.com, ipinfo.io, ip.sb, ipapi.co and ipwho.is) to determine the server's public IPv4 address and country. These providers can observe the server's public IP and request metadata; the GeoIP lookups do not include the tunnel token or tunnel payload.

For upgrade compatibility, the installed systemd unit and configuration directory still use the legacy names `ravanreverse.service` and `/etc/ravanreverse`; the installer also provides the `shah-tunnel` command as a symlink. These are local compatibility names, not third-party download destinations. Do not rename them manually on an existing server; a future rename would need an explicit migration.

## Automatic Cloudflare WARP setup and SSH safety

On Ubuntu/Debian, `S1T-START.sh` automatically installs the official Cloudflare WARP client if it is missing, detects the distribution codename for the Cloudflare APT repository, configures MASQUE, and checks WARP health. The installer asks for an explicit one-time acceptance of Cloudflare's Terms of Service and Privacy Policy before first registration/configuration. If consent is declined or no interactive TTY is available, WARP is installed but is not silently registered or connected. If WARP package setup fails because its repository or network is unavailable, the Shah Tunnel installer continues so legacy transports remain usable; WARP-dependent Agent paths stay unavailable until WARP is healthy. If the ordinary APT update fails because a provider mirror is unavailable, the installer tries refreshing the Cloudflare repository separately before giving up.

Before it connects WARP, the installer creates a persistent systemd helper with Linux policy-routing rules for SSH reply packets (including the active SSH port and ports reported by `sshd -T`). It verifies the route to the current SSH client after WARP connects. If the route cannot be verified outside the WARP interface/table, it disconnects WARP rather than knowingly risking the administrator's SSH access. This safeguard is for SSH traffic; it does not promise that unrelated management services retain their previous route. A WARP path is considered usable by Shah Tunnel only while WARP reports `Connected` and `Network: healthy`.

## Install

Run as root on Linux amd64 or arm64 with systemd and HTTPS access to the official Go download hosts. For a downloaded source ZIP, run the local installer from its extracted folder:

```bash
sudo bash S1T-START.sh
```

The local installer builds the exact source tree next to the script. To install directly from the repository's published `main` branch instead, use:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

The installer downloads the Go `1.26.1` toolchain, trying regional mirrors first and then official distribution hosts. If a transfer is interrupted, it retains a separate partial file per mirror and resumes only from that same mirror with HTTP Range where supported. This avoids mixing partial responses from different hosts. It verifies the pinned SHA-256 checksum before using the archive; unverified archives are never accepted. When a local source tree is present, the installer builds that exact tree; when invoked remotely with no local tree, it downloads the source archive from the `main` branch. In both cases it compiles `S1T-CAPSULE` locally for the server architecture with CGO disabled. It does not use GitHub Release assets or install the Go toolchain permanently. The installer prepares Cloudflare WARP/MASQUE and the SSH direct-route safeguard first, before downloading the source and Go toolchain; when WARP is accepted and healthy, those downloads can use the WARP egress route. If the operator declines Cloudflare terms or WARP cannot connect, the installer continues with the ordinary network route when possible. The SSH safeguard is installed before the WARP daemon starts. The built binary's application version and target architecture are checked before installation. An existing binary is backed up before replacement, and an already-active service is not restarted during installation to avoid dropping live tunnel sessions.

## Build and tests

The verification helper requires Go 1.26.1 to already be installed locally; it will not download a toolchain. From the repository root:

```bash
./VERIFY-ALL-TRANSPORTS.sh
```

Or run the main checks directly:

```bash
gofmt -w S1T-CAPSULE/main.go S1T-CAPSULE/main_test.go
go test -race -count=20 ./S1T-CAPSULE
go vet ./S1T-CAPSULE
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-amd64 ./S1T-CAPSULE
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w -buildid=' -o dist/shah-tunnel-linux-arm64 ./S1T-CAPSULE
(cd dist && sha256sum shah-tunnel-linux-amd64 > shah-tunnel-linux-amd64.sha256)
(cd dist && sha256sum shah-tunnel-linux-arm64 > shah-tunnel-linux-arm64.sha256)
```
