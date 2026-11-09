<p align="center">
  <img src="docs/img/ShahTunnel-Network.png" alt="ShahTunnel galaxy emblem" width="360" />
</p>

<h1 align="center">SHAH TUNNEL</h1>
<p align="center"><strong>V2.2.0 · Secure Reverse TCP Relay · External Paths + Adaptive Failover</strong></p>
<p align="center">A reverse TCP relay that carries public client connections through a Hub to mapped target services via authenticated Agent lanes. The private Hub↔Agent channel uses TLS 1.3, SHA-256 certificate pinning and adaptive recovery across four native transports and preconfigured Agent-side external network paths.</p>
<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README-fa.md">🇮🇷 فارسی</a></p>

## Network flow

<p align="center">
  <img src="docs/img/ShahTunnel-Network-Flow.png" alt="Network flow: public clients, Hub, four authenticated private transports, Agent and local target service" width="100%" />
</p>

## Features

- **Four implemented transports:** TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT and HTTP/1.1 CONNECT/TLS.
- **Automatic recovery:** reconnect with jittered backoff and adaptive selection of the last successful transport per lane.
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
| `7` | NEW TUNNEL METHODS | Uses the selected, preconfigured Agent-side external path with the authenticated TCP/TLS carrier. The Hub accepts the carrier; it does not run the external client. |
| `8` | FULL ADAPTIVE FAILOVER | Tries all four native transports over the direct route and every configured Agent external path; each lane selects its next working candidate independently. |

### Hub firewall ports

If the Hub control port is `9443`:

- `9443/TCP`: native TCP/TLS and WebSocket/TLS.
- `9444/TCP`: HTTP/2 CONNECT (options 3, 5 and 8).
- `9445/TCP`: HTTP/1.1 CONNECT (options 4, 5 and 8).

Open only the ports needed by the selected mode. Mode 7 needs only the control port; mode 8 needs the control port, control+1 and control+2 to use all four native transports.

### Agent-side external paths

These external clients must already be installed and running on the outside Agent. Shah Tunnel does not install or manage them. Add the prepared paths in the Agent setup wizard:

- **MASQUE, Cloudflare WARP and WARP on WARP:** Shah Tunnel uses the Agent OS routing table. An optional interface name binds the socket with Linux `SO_BINDTODEVICE`; leaving it blank uses the OS default route. Prepare the correct route/interface in the OS if you need to ensure traffic really traverses WARP/MASQUE.
- **Tor and Psiphon:** enter the client’s local SOCKS5 address (Wizard defaults: `127.0.0.1:9050` for Tor; Psiphon requires its actual configured local endpoint because ports vary by client build/configuration). Shah Tunnel sends the Hub connection through SOCKS5 and passes hostnames for remote DNS resolution.
- **Backhaul:** enter the local raw-TCP forward exposed by the Backhaul client. For mode 8, corresponding control+1 and control+2 forwards must also exist when HTTP/2 or HTTP/1.1 CONNECT is to be used.

Mode 7 uses only the selected external path with TCP/TLS. Mode 8 tests the direct OS route and every configured external path with the four native transports. The Hub controls accepted transports only; external-client setup and health remain the Agent operator’s responsibility.

## Multiple tunnel profiles and upload throughput

Each create operation asks for a unique tunnel name and stores its configuration separately. Existing profiles remain intact. Every named profile runs as its own systemd instance; Start, Stop, Restart, Status, and Delete act on the selected profile. The profile-management menu keeps its separate delete and full-uninstall actions.

The per-stream in-flight window is increased to 64 frames of up to 64 KiB (about 4 MiB per stream), while each tunnel socket keeps a smaller bounded outbound queue to limit head-of-line delay. On Linux kernels that support BBR, the outer tunnel TCP socket attempts to use BBR per-socket; unsupported kernels retain their existing default. This reduces the throughput ceiling caused by a small flow-control window on high-RTT paths and can improve latency under load. Actual throughput still depends on link capacity, packet loss, congestion, kernel qdisc, and provider limits; application-level changes cannot prevent an uplink from being fully saturated without an appropriate network-level rate limit.

## Responsible use and privacy

ShahTunnel is a general-purpose TCP relay. Configure it only for servers and services you own or are explicitly authorized to administer. Do not use it to access third-party systems without permission, relay abusive traffic, or disrupt services. Operators are responsible for the endpoints and traffic they choose to forward.

The server information display may make outbound HTTPS requests to public IP and GeoIP providers (including ipify, icanhazip, checkip.amazonaws.com, ipinfo.io, ip.sb, ipapi.co and ipwho.is) to determine the server's public IPv4 address and country. These providers can observe the server's public IP and request metadata; the GeoIP lookups do not include the tunnel token or tunnel payload.

For upgrade compatibility, the installed systemd unit and configuration directory still use the legacy names `ravanreverse.service` and `/etc/ravanreverse`; the installer also provides the `shah-tunnel` command as a symlink. These are local compatibility names, not third-party download destinations. Do not rename them manually on an existing server; a future rename would need an explicit migration.

## Install

Run as root on Linux amd64 or arm64 with systemd and HTTPS access to the official Go download hosts. For a downloaded source ZIP, run the local installer from its extracted folder:

```bash
sudo bash S1T-START.sh
```

The local installer builds the exact source tree next to the script. To install directly from the repository's published `main` branch instead, use:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
```

The installer downloads the Go `1.26.1` toolchain, trying regional mirrors first and then official distribution hosts. If a transfer is interrupted, it retains a separate partial file per mirror and resumes only from that same mirror with HTTP Range where supported. This avoids mixing partial responses from different hosts. It verifies the pinned SHA-256 checksum before using the archive; unverified archives are never accepted. When a local source tree is present, the installer builds that exact tree; when invoked remotely with no local tree, it downloads the source archive from the `main` branch. In both cases it compiles `S1T-CAPSULE` locally for the server architecture with CGO disabled. It does not use GitHub Release assets or install the Go toolchain permanently. The built binary's application version and target architecture are checked before installation. An existing binary is backed up before replacement, and an already-active service is not restarted during installation to avoid dropping live tunnel sessions.

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
