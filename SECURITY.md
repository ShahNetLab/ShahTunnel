# Security policy

ShahTunnel is intended for systems and services the operator owns or is explicitly authorized to administer.

## v1.8.0 transport security

- Inner Hub-Agent sessions use TLS 1.3, the random ShahTunnel token, and SHA-256 certificate pinning.
- The optional Hysteria 2 / QUIC transport has separate 256-bit Hysteria and Salamander credentials. The Agent pins the Hysteria TLS certificate; the inner ShahTunnel TLS session checks the same certificate again.
- The Hub Hysteria ACL is default-deny and permits only the loopback ShahTunnel control port over TCP. The Agent SOCKS5 listener binds to loopback only.
- Hysteria 2 is installed at a pinned version and its downloaded binary is verified against a pinned SHA-256 manifest before installation.
- The Hysteria sidecar is supervised by the ShahTunnel systemd service; stopping ShahTunnel stops its child sidecar.

Do not publish configuration files, authentication tokens, Hysteria credentials, private keys or certificate material. Keep `/etc/ravanreverse` accessible only to root; named profiles and their private keys are stored below `/etc/ravanreverse/profiles/NAME`. Expose only the transport ports selected on each Hub profile.

## Reporting

For a vulnerability or abuse concern, use GitHub's private vulnerability reporting feature if it is enabled. Otherwise, open a repository issue asking for a private contact route; do not include secrets. Include the ShahTunnel version, Linux distribution, architecture, sanitized logs and reproducible steps.
