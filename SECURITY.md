# Security and abuse reports

ShahTunnel is a general-purpose TCP relay intended for systems and services that the operator owns or is explicitly authorized to administer. Do not use it to access third-party systems without permission, relay abusive traffic, or disrupt services.

For a vulnerability or abuse concern, use GitHub's private vulnerability reporting feature for this repository if it is enabled. Otherwise, open a repository issue asking for a private contact route; do not publish tokens, private keys, complete configuration files, or other secrets in a public issue.

When reporting a technical issue, include the ShahTunnel version, operating system, relevant sanitized logs, and steps to reproduce. Redact tokens, private keys, and other credentials first.


## Local monitoring panel

The optional `tools/install-panel.sh` service installs a read-only dashboard and binds it to `127.0.0.1:8091`. It has no web authentication because it is intended for local access or SSH port forwarding only. Do not change the bind address to a public interface or expose it through an unauthenticated reverse proxy. The panel can display service state, runtime counters, configured endpoint addresses, and recent journal logs; it does not return tunnel tokens or certificate fingerprints.
