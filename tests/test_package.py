import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from tools.package import FILES, build
from tools.verify_package import verify


class PackageTests(unittest.TestCase):
    def test_built_layout_passes_the_independent_release_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in FILES:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('{"version":"1.2.3","license":"MIT"}' if name == "package.json" else "fixture")
            archive = build(root)
            verify(archive, "1.2.3")
            with self.assertRaisesRegex(SystemExit, "does not match"):
                verify(archive, "1.2.4")
            (root / "package.json").write_text('{"version":"1.2.3","license":"ISC"}')
            with self.assertRaisesRegex(SystemExit, "license"):
                verify(build(root), "1.2.3")
            (root / "package.json").write_text('{"version":"1.2.3","license":"MIT"}')
            archive = build(root)
            with ZipFile(archive, "a") as extra:
                extra.writestr("decky-wireguard/docs/local.md", "not for distribution")
            with self.assertRaisesRegex(SystemExit, r"unexpected: \['decky-wireguard/docs/local.md'\]"):
                verify(archive, "1.2.3")

    def test_only_regular_allowlisted_guides_are_packaged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in FILES:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('{"version":"test","license":"MIT"}' if name == "package.json" else "fixture")
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
