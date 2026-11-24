"""Build a compatibility copy; never patch the vendored upstream snapshot."""
from pathlib import Path
import json
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "baselines/uprove/upstream"
BUILD = ROOT / "build-native/uprove-reference"
MSR_COMMIT = "5b9a6dd4539a0968ea4ffa68d14c3c99a7bfc3e7"


def main():
    shutil.copytree(SOURCE, BUILD, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("node_modules", "js", "package-lock.json"))
    package = json.loads((BUILD/"package.json").read_text())
    package["dependencies"]["@microsoft/msrcrypto"] = (
        f"https://codeload.github.com/microsoft/MSR-JavaScript-Crypto/tar.gz/{MSR_COMMIT}")
    package["devDependencies"]["typescript"] = "4.9.5"
    (BUILD/"package.json").write_text(json.dumps(package, indent=2), encoding="utf-8")
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    saved_lock = ROOT/"baselines/uprove/runtime-package-lock.json"
    if saved_lock.exists():
        shutil.copy2(saved_lock, BUILD/"package-lock.json")
    subprocess.run([npm, "ci" if saved_lock.exists() else "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                   cwd=BUILD, check=True)
    subprocess.run([npm, "run", "build"], cwd=BUILD, check=True)
    # Node 22+ removed JSON import assertions; only emitted JS gets this syntax fix.
    for p in (BUILD/"js").rglob("*.js"):
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("assert {", "with {"), encoding="utf-8")
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(BUILD/name, ROOT/"baselines/uprove"/("runtime-"+name))
    print("Reference compatibility build:", BUILD)


if __name__ == "__main__":
    main()
