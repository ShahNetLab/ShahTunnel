import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from safe_extract_tar import safe_extract


def make_archive(path: Path, entries):
    with tarfile.open(path, "w:gz") as archive:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                archive.addfile(info)


class SafeExtractTests(unittest.TestCase):
    def test_extracts_single_root_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "source.tar.gz"
            destination = base / "out"
            make_archive(archive, [
                ("repo-main/", "dir", b""),
                ("repo-main/go.mod", "file", "module example\n"),
                ("repo-main/scripts/", "dir", b""),
                ("repo-main/scripts/run.sh", "file", "#!/bin/sh\n"),
            ])
            safe_extract(archive, destination)
            self.assertEqual((destination / "go.mod").read_text(), "module example\n")
            self.assertTrue((destination / "scripts/run.sh").exists())

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "bad.tar.gz"
            destination = base / "out"
            make_archive(archive, [
                ("repo-main/", "dir", b""),
                ("repo-main/../../escape", "file", "bad"),
            ])
            with self.assertRaises(ValueError):
                safe_extract(archive, destination)
            self.assertFalse((base.parent / "escape").exists())

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "bad-link.tar.gz"
            destination = base / "out"
            make_archive(archive, [
                ("repo-main/", "dir", b""),
                ("repo-main/link", "symlink", "../../outside"),
            ])
            with self.assertRaises(ValueError):
                safe_extract(archive, destination)


if __name__ == "__main__":
    unittest.main()
