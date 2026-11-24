import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


FILES = (
    "plugin.json", "package.json", "main.py", "py_modules/nm_keyfile.py", "py_modules/read_conf.py", "dist/index.js",
    "LICENSE", "THIRD-PARTY-NOTICES.md", "LICENSES/decky-api-LGPL-2.1.txt", "LICENSES/react-icons-MIT.txt",
    "README.md", "docs/configuration.md", "docs/development.md", "docs/how-it-works.md",
    "docs/troubleshooting.md",
)


def build(root: Path) -> Path:
    for name in FILES:
        path = root / name
        if path.resolve() != path:
            raise SystemExit(f"Refusing to package a symlink: {name}")
        if not path.is_file():
            raise SystemExit(f"Missing package file: {name}. Run npm run build first.")

    version = json.loads((root / "package.json").read_text())["version"]
    output = root / "out" / f"decky-wireguard-{version}.zip"
    output.parent.mkdir(exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name in FILES:
            archive.write(root / name, f"decky-wireguard/{name}")
    return output


if __name__ == "__main__":
    print(build(Path(__file__).resolve().parents[1]))
