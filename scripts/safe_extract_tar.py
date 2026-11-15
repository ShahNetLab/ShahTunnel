#!/usr/bin/env python3
"""Safely extract an untrusted .tar.gz containing regular files and directories only."""
from __future__ import annotations
import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
from typing import List, Optional, Set, Tuple

MAX_MEMBERS = 100_000
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024
MAX_FILE_SIZE = 512 * 1024 * 1024


def safe_extract(archive: Path, destination: Path, strip_components: int = 1,
                 expected_root_prefix: Optional[str] = None) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("destination directory must be empty")

    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise ValueError("empty archive or too many entries")

        roots: Set[str] = set()
        seen: Set[str] = set()
        files: List[Tuple[tarfile.TarInfo, PurePosixPath]] = []
        directories: Set[PurePosixPath] = set()
        total = 0

        for member in members:
            name = member.name
            if not name or "\x00" in name or "\\" in name:
                raise ValueError(f"invalid archive path: {name!r}")
            raw = PurePosixPath(name)
            if raw.is_absolute() or any(part == ".." for part in raw.parts):
                raise ValueError(f"unsafe archive path: {name!r}")
            if not raw.parts or raw.parts[0].endswith(":"):
                raise ValueError(f"empty or drive-qualified archive path: {name!r}")
            roots.add(raw.parts[0])

            # Only normal files and directories are accepted. Reject symbolic
            # links, hard links, devices, FIFOs and sparse/special entries.
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"unsupported archive entry type: {name!r}")
            if member.size < 0 or member.size > MAX_FILE_SIZE:
                raise ValueError(f"invalid or oversized archive entry: {name!r}")
            if member.isfile():
                total += member.size
                if total > MAX_TOTAL_SIZE:
                    raise ValueError("archive expands beyond the configured size limit")

            parts = raw.parts[strip_components:]
            if not parts:
                continue
            rel = PurePosixPath(*parts)
            normalized = rel.as_posix()
            if normalized in ("", ".") or normalized.startswith("../"):
                raise ValueError(f"unsafe stripped archive path: {name!r}")
            if normalized in seen:
                raise ValueError(f"duplicate archive path: {normalized!r}")
            seen.add(normalized)
            if member.isdir():
                directories.add(rel)
            else:
                files.append((member, rel))

        if len(roots) != 1:
            raise ValueError("archive must contain exactly one top-level directory")
        root_name = next(iter(roots))
        if expected_root_prefix and not root_name.startswith(expected_root_prefix):
            raise ValueError(f"unexpected archive root: {root_name!r}")

        # Detect file/directory path conflicts before creating anything.
        file_paths = {rel for _, rel in files}
        for rel in file_paths:
            for parent in rel.parents:
                if parent != PurePosixPath(".") and parent in file_paths:
                    raise ValueError(f"file/directory path conflict: {rel.as_posix()!r}")
        if file_paths.intersection(directories):
            raise ValueError("archive contains a path as both a regular file and directory")

        for rel in sorted(directories, key=lambda p: (len(p.parts), p.as_posix())):
            out = destination.joinpath(*rel.parts)
            out.mkdir(mode=0o755, parents=True, exist_ok=True)

        for member, rel in files:
            out = destination.joinpath(*rel.parts)
            out.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            mode = 0o755 if member.mode & 0o111 else 0o644
            fd = os.open(out, flags, mode)
            try:
                src = tf.extractfile(member)
                if src is None:
                    raise ValueError(f"could not read archive file: {member.name!r}")
                with src, os.fdopen(fd, "wb", closefd=False) as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                    dst.flush()
                    os.fsync(fd)
                os.fchmod(fd, mode)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    out.unlink()
                except OSError:
                    pass
                raise
            else:
                os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--strip-components", type=int, default=1)
    parser.add_argument("--expected-root-prefix")
    args = parser.parse_args()
    if args.strip_components < 0 or args.strip_components > 16:
        parser.error("--strip-components must be between 0 and 16")
    try:
        safe_extract(args.archive, args.destination, args.strip_components, args.expected_root_prefix)
    except (OSError, tarfile.TarError, ValueError) as exc:
        parser.exit(1, f"safe_extract_tar: {exc}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
