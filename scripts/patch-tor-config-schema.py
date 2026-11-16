#!/usr/bin/env python3
"""Compatibility patch for a split ShahTunnel main-branch Tor schema.

Only adds missing optional fields to the existing Config struct when tor.go is
present. It does not remove or rewrite existing fields, logic, menus, or ports.
"""
from __future__ import annotations
import pathlib
import re
import sys

if len(sys.argv) != 2:
    print("usage: patch-tor-config-schema.py S1T-CAPSULE-directory", file=sys.stderr)
    raise SystemExit(2)

capsule = pathlib.Path(sys.argv[1]).resolve()
tor_file = capsule / "tor.go"
main_file = capsule / "main.go"
if not tor_file.is_file():
    print("Tor source not present; no Config schema compatibility patch needed.")
    raise SystemExit(0)
if not main_file.is_file():
    print("ERROR: tor.go exists but S1T-CAPSULE/main.go is missing.", file=sys.stderr)
    raise SystemExit(1)

source = main_file.read_text(encoding="utf-8")
match = re.search(r"(?ms)^type\s+Config\s+struct\s*\{(.*?)^\}", source)
if not match:
    print("ERROR: could not safely locate type Config struct in main.go; refusing an unsafe patch.", file=sys.stderr)
    raise SystemExit(1)

body = match.group(1)
required = [
    ("TorMode", "string", "tor_mode"),
    ("TorBridge", "string", "tor_bridge"),
    ("TorProxy", "string", "tor_proxy"),
    ("TorHubAddr", "string", "tor_hub_addr"),
    ("TorDataDir", "string", "tor_data_dir"),
    ("TorConfigPath", "string", "tor_config_path"),
    ("TorBinary", "string", "tor_binary"),
    ("TorPTBinary", "string", "tor_pt_binary"),
]
existing = set(re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s+", body))
missing = [(name, typ, tag) for name, typ, tag in required if name not in existing]
if not missing:
    print("Tor Config fields already match tor.go; no source changes needed.")
    raise SystemExit(0)

addition = "\n\t// Optional per-profile Tor state used by tor.go. Added by the build-time schema compatibility check.\n"
for name, typ, tag in missing:
    addition += f'\t{name:<14} {typ:<6} `json:"{tag},omitempty"`\n'

patched_body = body.rstrip() + addition
patched = source[:match.start(1)] + patched_body + "\n" + source[match.end(1):]
# Ensure one and only one field declaration remains for each required name.
new_match = re.search(r"(?ms)^type\s+Config\s+struct\s*\{(.*?)^\}", patched)
if not new_match:
    print("ERROR: patched Config struct could not be re-read; refusing to write.", file=sys.stderr)
    raise SystemExit(1)
new_fields = re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s+", new_match.group(1))
for name, _, _ in required:
    if new_fields.count(name) != 1:
        print(f"ERROR: field {name} is not declared exactly once after patch; refusing to write.", file=sys.stderr)
        raise SystemExit(1)

tmp = main_file.with_suffix(".go.schema-tmp")
tmp.write_text(patched, encoding="utf-8")
tmp.replace(main_file)
print("Added only missing optional Config fields required by tor.go: " + ", ".join(name for name, _, _ in missing))
