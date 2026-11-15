import io
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "S1T-START.sh"


class InstallerSourceExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = INSTALLER.read_text(encoding="utf-8")
        match = re.search(
            r"<<'PY_SAFE_SOURCE_ARCHIVE'\n(.*?)\nPY_SAFE_SOURCE_ARCHIVE",
            text,
            re.DOTALL,
        )
        if not match:
            raise RuntimeError("source archive extractor heredoc not found")
        cls.extractor_code = match.group(1)
        compile(cls.extractor_code, str(INSTALLER) + ":PY_SAFE_SOURCE_ARCHIVE", "exec")

    def make_archive(self, archive, entries):
        with tarfile.open(archive, "w:gz") as tf:
            for name, kind, payload in entries:
                info = tarfile.TarInfo(name)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    tf.addfile(info)
                elif kind == "file":
                    data = payload or b""
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))

    def run_extractor(self, archive, destination):
        return subprocess.run(
            [sys.executable, "-c", self.extractor_code, str(archive), str(destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )

    def test_installer_inline_extractor_compiles_and_extracts_valid_release(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive, target = base / "good.tar.gz", base / "out"
            self.make_archive(archive, [
                ("ShahTunnel-main/", "dir", None),
                ("ShahTunnel-main/go.mod", "file", b"module example.test/shah\n"),
            ])
            result = self.run_extractor(archive, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / "go.mod").read_bytes(), b"module example.test/shah\n")

    def test_installer_inline_extractor_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [
                ("ShahTunnel-main/../../escape", "file", b"bad"),
            ])
            result = self.run_extractor(archive, target)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((base / "escape").exists())

    def test_installer_inline_extractor_rejects_unexpected_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            archive, target = base / "bad.tar.gz", base / "out"
            self.make_archive(archive, [
                ("not-shah-tunnel/file", "file", b"bad"),
            ])
            result = self.run_extractor(archive, target)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected ShahTunnel source archive root", result.stderr)


if __name__ == "__main__":
    unittest.main()
