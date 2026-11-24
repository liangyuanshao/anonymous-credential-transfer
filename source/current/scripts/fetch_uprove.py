"""Vendor the pinned Microsoft reference, preserving its license and provenance."""
from pathlib import Path
import hashlib
import io
import json
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "77933b3e8a739008bb65389d7a8ce79bcde73f91"
URL = f"https://codeload.github.com/microsoft/uprove-node-reference/zip/{COMMIT}"
DEST = ROOT / "baselines/uprove/upstream"


def main():
    archive = urllib.request.urlopen(URL, timeout=60).read()
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for item in z.infolist():
            parts = Path(item.filename).parts[1:]
            if item.is_dir() or not parts:
                continue
            target = DEST.joinpath(*parts)
            if not target.resolve().is_relative_to(DEST.resolve()):
                raise ValueError("Archive path escaped destination")
            data = z.read(item)
            if target.exists() and target.read_bytes() != data:
                raise ValueError(f"Refusing to replace modified upstream file: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files[target.relative_to(DEST).as_posix()] = hashlib.sha256(data).hexdigest()
    manifest = dict(repository="https://github.com/microsoft/uprove-node-reference",
                    commit=COMMIT, archive_url=URL,
                    archive_sha256=hashlib.sha256(archive).hexdigest(),
                    license="MIT; upstream notices preserved", files=files)
    (DEST.parent / "upstream-manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Pinned U-Prove reference: {COMMIT}; {len(files)} files")


if __name__ == "__main__":
    main()
