import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from tools.package import FILES, build


class PackageTests(unittest.TestCase):
    def test_only_regular_allowlisted_guides_are_packaged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in FILES:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('{"version":"test"}' if name == "package.json" else "fixture")
            extra = root / "docs/local.md"
            extra.write_text("not for distribution")
            with ZipFile(build(root)) as archive:
                self.assertNotIn("decky-wireguard/docs/local.md", archive.namelist())
                self.assertIn("decky-wireguard/docs/configuration.md", archive.namelist())
            guide = root / "docs/configuration.md"
            guide.unlink()
            guide.symlink_to(extra)
            with self.assertRaisesRegex(SystemExit, "Refusing to package a symlink"):
                build(root)
            guide.unlink()
            with self.assertRaisesRegex(SystemExit, "Missing package file"):
                build(root)
