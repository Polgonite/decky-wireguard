import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


root = Path(__file__).resolve().parents[1]
version = json.loads((root / "package.json").read_text())["version"]
files = ["plugin.json", "package.json", "main.py", "dist/index.js", "README.md"]
for name in files:
    if not (root / name).is_file():
        raise SystemExit(f"Missing package file: {name}. Run npm run build first.")

output = root / "out" / f"decky-wireguard-{version}.zip"
output.parent.mkdir(exist_ok=True)
with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
    for name in files:
        archive.write(root / name, f"decky-wireguard/{name}")
print(output)
