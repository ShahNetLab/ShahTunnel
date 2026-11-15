import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from safe_extract_tar import safe_extract


class SafeExtractTests(unittest.TestCase):
    def make_archive(self, path: Path, entries):
        with tarfile.open(path, "w:gz") as tf:
            for name, kind, data in entries:
                info = tarfile.TarInfo(name)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    tf.addfile(info)
                elif kind == "file":
                    payload = data or b""
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = data.decode() if data else "../../outside"
                    tf.addfile(info)
                elif kind == "hardlink":
                    info.type = tarfile.LNKTYPE
                    info.linkname = data.decode() if data else "root/file"
                    tf.addfile(info)

    def test_extracts_regular_files_without_preserving_unsafe_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "safe.tar.gz", base / "out"
            self.make_archive(archive, [
                ("release-root/", "dir", None),
                ("release-root/sub/", "dir", None),
                ("release-root/sub/file.txt", "file", b"ok"),
            ])
            safe_extract(archive, target, strip_components=1, expected_root_prefix="release-root")
            self.assertEqual((target / "sub/file.txt").read_bytes(), b"ok")
            self.assertEqual((target / "sub/file.txt").stat().st_mode & 0o777, 0o644)

    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [("release-root/../../escape", "file", b"bad")])
            with self.assertRaises(ValueError):
                safe_extract(archive, target, strip_components=1)
            self.assertFalse((base / "escape").exists())

    def test_rejects_absolute_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [("/tmp/escape", "file", b"bad")])
            with self.assertRaises(ValueError):
                safe_extract(archive, target, strip_components=0)

    def test_rejects_symlinks_and_hardlinks(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                archive, target = base / "bad.tar.gz", base / "out"
                self.make_archive(archive, [("release-root/link", kind, b"../../outside")])
                with self.assertRaises(ValueError):
                    safe_extract(archive, target, strip_components=1)

    def test_rejects_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [
                ("release-root/a", "file", b"first"),
                ("release-root/a", "file", b"second"),
            ])
            with self.assertRaises(ValueError):
                safe_extract(archive, target, strip_components=1)

    def test_rejects_file_parent_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [
                ("release-root/a", "file", b"file"),
                ("release-root/a/b", "file", b"child"),
            ])
            with self.assertRaises(ValueError):
                safe_extract(archive, target, strip_components=1)

    def test_rejects_drive_qualified_path(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [("C:/outside.txt", "file", b"bad")])
            with self.assertRaises(ValueError):
                safe_extract(archive, target, strip_components=0)

    def test_rejects_wrong_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [("other-root/a", "file", b"x")])
            with self.assertRaises(ValueError):
                safe_extract(archive, target, strip_components=1, expected_root_prefix="release-root")


if __name__ == "__main__":
    unittest.main()
