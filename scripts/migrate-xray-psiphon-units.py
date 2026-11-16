#!/usr/bin/env python3
"""Safely migrate ShahTunnel-owned profile Xray/Psiphon units.

This is called by S1T-START.sh during an upgrade. It does not start or stop
services; it changes only ProtectHome in an Xray sidecar unit after matching
its saved Agent profile metadata, exact service name, description and config
path. Original unit files are backed up before atomic replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")


def tunnel_id(name: str) -> str:
    name = name.strip()
    lowered = name.lower()
    out: list[str] = []
    for char in lowered:
        if char.isascii() and (char.isalpha() or char.isdigit() or char in "-_."):
            out.append(char)
        elif not out or out[-1] != "-":
            out.append("-")
    slug = "".join(out).strip("-._")
    if not slug or slug != lowered:
        digest = hashlib.sha256(name.encode("utf-8")).digest()[:4].hex()
        if not slug:
            slug = "tunnel"
        if len(slug) > 24:
            slug = slug[:24]
        slug += "-" + digest
    if len(slug) > 48:
        digest = hashlib.sha256(name.encode("utf-8")).digest()[:4].hex()
        slug = slug[:39] + "-" + digest
    return slug


def atomic_write(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=".s1t-psiphon-unit-", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, stat.S_IMODE(mode))
        try:
            os.fchown(fd, uid, gid)
        except PermissionError:
            pass
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def update_protect_home(unit_text: str) -> tuple[str, bool]:
    lines = unit_text.splitlines(keepends=True)
    in_service = False
    service_seen = False
    directive_indexes: list[int] = []
    section_end = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[Service]":
            in_service = True
            service_seen = True
            section_end = index + 1
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_service:
                in_service = False
            continue
        if in_service and stripped.startswith("ProtectHome="):
            directive_indexes.append(index)
    if not service_seen:
        raise ValueError("unit has no [Service] section")
    if len(directive_indexes) > 1:
        raise ValueError("unit has duplicate ProtectHome directives")
    if directive_indexes:
        index = directive_indexes[0]
        original = lines[index]
        newline = "\r\n" if original.endswith("\r\n") else "\n" if original.endswith("\n") else ""
        indent = original[: len(original) - len(original.lstrip(" \t"))]
        replacement = indent + "ProtectHome=read-only" + newline
        if original == replacement:
            return unit_text, False
        lines[index] = replacement
    else:
        assert section_end is not None
        lines.insert(section_end, "ProtectHome=read-only\n")
    return "".join(lines), True


def validate_and_migrate_profile(
    config_path: Path, units_dir: Path, backup_dir: Path
) -> tuple[str, Path] | None:
    try:
        with config_path.open("r", encoding="utf-8") as stream:
            cfg = json.load(stream)
    except Exception as exc:
        raise ValueError(f"cannot read profile JSON: {exc}") from exc

    if not isinstance(cfg, dict) or cfg.get("role") != "agent":
        return None
    metadata = cfg.get("xray_psiphon")
    if not isinstance(metadata, dict):
        return None
    name = str(cfg.get("name") or config_path.stem).strip()
    if not name:
        return None
    profile = tunnel_id(name)
    expected_service = f"shah-tunnel-xray-psiphon-{profile}.service"
    expected_config = f"/etc/ravanreverse/xray-psiphon/{profile}/config.json"
    if metadata.get("service") != expected_service:
        return None
    if os.path.normpath(str(metadata.get("config_path", ""))) != expected_config:
        return None
    bindings = metadata.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        return None

    unit_path = units_dir / expected_service
    if unit_path.is_symlink() or not unit_path.is_file():
        raise ValueError(f"expected managed sidecar unit is missing or not a regular file: {unit_path}")
    unit_bytes = unit_path.read_bytes()
    unit_text = unit_bytes.decode("utf-8")
    expected_description = f"Description=ShahTunnel isolated Psiphon Xray ({expected_service[:-8]})"
    lines = [line.strip() for line in unit_text.splitlines()]
    if expected_description not in lines:
        raise ValueError("unit description does not match this ShahTunnel profile")
    expected_exec_suffix = f' run -config "{expected_config}"'
    if not any(line.startswith("ExecStart=") and line.endswith(expected_exec_suffix) for line in lines):
        raise ValueError("unit ExecStart does not reference this profile's exact Xray config")

    updated_text, changed = update_protect_home(unit_text)
    if not changed:
        return None

    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    info = unit_path.stat(follow_symlinks=False)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{expected_service}.{timestamp}.bak"
    counter = 0
    while backup_path.exists():
        counter += 1
        backup_path = backup_dir / f"{expected_service}.{timestamp}.{counter}.bak"
    backup_path.write_bytes(unit_bytes)
    os.chmod(backup_path, stat.S_IMODE(info.st_mode))
    try:
        os.chown(backup_path, info.st_uid, info.st_gid)
    except PermissionError:
        pass
    atomic_write(unit_path, updated_text.encode("utf-8"), info.st_mode, info.st_uid, info.st_gid)
    return expected_service, backup_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles-dir", type=Path, default=Path("/etc/ravanreverse/tunnels"))
    parser.add_argument("--units-dir", type=Path, default=Path("/etc/systemd/system"))
    parser.add_argument(
        "--backup-dir", type=Path,
        default=Path("/var/backups/ravanreverse/psiphon-sidecar-units"),
    )
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    migrated: list[tuple[str, Path]] = []
    failures: list[str] = []
    if args.profiles_dir.is_dir():
        for profile_config in sorted(args.profiles_dir.glob("*.json")):
            try:
                result = validate_and_migrate_profile(profile_config, args.units_dir, args.backup_dir)
                if result:
                    migrated.append(result)
                    print(f"Migrated managed Psiphon Xray sidecar: {result[0]}")
            except Exception as exc:
                failures.append(f"{profile_config.name}: {exc}")

    with args.manifest.open("w", encoding="utf-8") as manifest:
        for service, backup in migrated:
            manifest.write(f"{service}\t{backup}\n")
        manifest.flush()
        os.fsync(manifest.fileno())

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 2
    if not migrated:
        print("No existing ShahTunnel Psiphon Xray sidecar unit required migration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
