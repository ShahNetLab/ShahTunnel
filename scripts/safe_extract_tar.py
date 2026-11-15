#!/usr/bin/env python3
"""Safely extract a GitHub-style .tar.gz archive containing one top-level directory.

Only regular files and directories are accepted. Absolute paths, traversal, links,
special files, duplicate files, multiple archive roots, and oversized archives are
rejected before writing into the destination directory.
"""
from __future__ import annotations

import os
import shutil
import sys
import tarfile
from pathlib import Path

MAX_MEMBERS = 200_000
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024


def safe_extract(archive: Path, destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("destination directory must be empty")
    if destination.is_symlink():
        raise ValueError("destination must not be a symlink")
    destination.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive, mode="r:gz") as tar:
        members = tar.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise ValueError("archive is empty or contains too many entries")

        roots: set[str] = set()
        total_size = 0
        normalized: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []

        for member in members:
            raw_name = member.name
            if not raw_name or raw_name.startswith("/") or "\\" in raw_name:
                raise ValueError(f"unsafe archive path: {raw_name!r}")
            parts = raw_name.split("/")
            while parts and parts[-1] == "":
                parts.pop()
            if not parts or any(part in ("", ".", "..") for part in parts):
                raise ValueError(f"unsafe archive path: {raw_name!r}")
            if parts[0] in (".", ".."):
                raise ValueError(f"unsafe archive root: {raw_name!r}")
            roots.add(parts[0])
            if len(roots) > 1:
                raise ValueError("archive must contain exactly one top-level directory")

            if not (member.isdir() or member.isfile()):
                raise ValueError(f"links and special files are not allowed: {raw_name!r}")
            if member.size < 0:
                raise ValueError(f"invalid file size: {raw_name!r}")
            if member.isfile():
                total_size += member.size
                if total_size > MAX_TOTAL_SIZE:
                    raise ValueError("archive expands beyond the 2 GiB safety limit")
            normalized.append((member, tuple(parts[1:])))

        seen_files: set[tuple[str, ...]] = set()

        for member, relative_parts in normalized:
            if not relative_parts:
                if not member.isdir():
                    raise ValueError("top-level archive entry must be a directory")
                continue
            target = destination.joinpath(*relative_parts)
            # Parents are created only by this extractor; symlink entries are rejected.
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o755)
                continue
            if relative_parts in seen_files:
                raise ValueError(f"duplicate archive file: {member.name!r}")
            seen_files.add(relative_parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(target, flags, 0o600)
            try:
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(f"could not read archive member: {member.name!r}")
                with source, os.fdopen(fd, "wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                # Ignore ownership and setuid/setgid/sticky bits from the archive.
                mode = 0o755 if (member.mode & 0o111) else 0o644
                os.chmod(target, mode)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    target.unlink()
                except OSError:
                    pass
                raise


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {Path(sys.argv[0]).name} ARCHIVE.tar.gz DESTINATION", file=sys.stderr)
        return 2
    archive, destination = map(Path, sys.argv[1:])
    try:
        safe_extract(archive, destination)
    except (OSError, tarfile.TarError, ValueError) as exc:
        print(f"safe archive extraction failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
