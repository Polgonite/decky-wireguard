"""Verify the installable ZIP before it is published."""

import json
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
# Deliberately separate from tools/package.py so a layout change has to be made in both places.
EXPECTED = {
    "plugin.json", "package.json", "main.py", "dist/index.js", "README.md",
    "LICENSE", "THIRD-PARTY-NOTICES.md", "LICENSES/decky-api-LGPL-2.1.txt", "LICENSES/react-icons-MIT.txt",
    "py_modules/nm_keyfile.py", "py_modules/read_conf.py", "docs/configuration.md", "docs/development.md",
    "docs/how-it-works.md", "docs/troubleshooting.md",
}


def verify(archive_path: Path, version: str) -> None:
    with ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise SystemExit(f"Corrupt ZIP archive: {archive_path}")
        names = set(archive.namelist())
        expected = {f"decky-wireguard/{name}" for name in EXPECTED}
        if names != expected:
            raise SystemExit(
                f"Unexpected ZIP layout. Missing: {sorted(expected - names)}, unexpected: {sorted(names - expected)}"
            )
        package = json.loads(archive.read("decky-wireguard/package.json"))
        embedded = package.get("version")
        if embedded != version:
            raise SystemExit(f"Embedded package.json version {embedded!r} does not match {version!r}")
        license_name = package.get("license")
        if license_name != "MIT":
            raise SystemExit(f"Embedded package.json license {license_name!r} does not match 'MIT'")
        legal_files = (
            "LICENSE", "THIRD-PARTY-NOTICES.md",
            "LICENSES/decky-api-LGPL-2.1.txt", "LICENSES/react-icons-MIT.txt",
        )
        for name in legal_files:
            if archive.getinfo(f"decky-wireguard/{name}").file_size == 0:
                raise SystemExit(f"Packaged legal file is empty: {name}")
        if archive.getinfo("decky-wireguard/dist/index.js").file_size == 0:
            raise SystemExit("dist/index.js is empty")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: verify_package.py VERSION")
    path = ROOT / "out" / f"decky-wireguard-{sys.argv[1]}.zip"
    verify(path, sys.argv[1])
    print(f"Verified {path.relative_to(ROOT)}")
