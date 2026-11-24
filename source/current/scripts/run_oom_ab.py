"""Compare both OoM provers in one process using the configured Windows build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/oom-factoring")
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--ell", nargs="+", type=int, default=[64, 16, 256])
    prior_folders = {"direct": "current", "grouped": "oom-factoring", "windowed": "oom-reuse"}
    parser.add_argument("--reference", choices=prior_folders, default="windowed")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    raw = output / "raw_timings.csv"
    if raw.exists():
        parser.error("choose a fresh output directory")

    reference = ROOT / "results/current"
    metadata = json.loads((reference / "environment.json").read_text(encoding="utf-8"))
    before = metadata["source_sha256"]
    shared = [name for name in before if name.startswith("baselines/")]
    shared += ["src/core.hpp", "src/group_arithmetic.hpp", "parameters/type-f.param"]
    for name in shared:
        if sha256((ROOT / name).read_bytes()) != before[name]:
            raise ValueError(f"Reference backend or baseline differs: {name}")
    if sha256((reference / "raw_timings.csv").read_bytes()) != metadata["raw_sha256"]:
        raise ValueError("Reference timing file differs from its manifest")
    prior_run = ROOT / "results" / prior_folders[args.reference]
    if args.reference == "direct":
        prior_hashes = before
    else:
        prior_meta = json.loads((prior_run / "environment.json").read_text(encoding="utf-8"))
        assert prior_meta["complete"]
        prior_hashes = prior_meta["sources_sha256"]
    with ZipFile(prior_run / "measured-source.zip") as sources:
        names = ("src/ours.hpp", "src/oom_windows.hpp", "src/oom_fixed.hpp")
        prior = {name: sources.read(name) for name in names if name in sources.namelist()}
    if "src/ours.hpp" not in prior or any(sha256(contents) != prior_hashes[name]
                                           for name, contents in prior.items()):
        raise ValueError("Reference prover differs from the measured version")

    entries = {}
    for line in (ROOT / "build-native/CMakeCache.txt").read_text(encoding="utf-8").splitlines():
        if line and line[0] not in "#/" and "=" in line:
            key, value = line.split("=", 1)
            entries[key.split(":", 1)[0]] = value
    build = Path(entries["CMAKE_CACHEFILE_DIR"])
    if build.resolve() != (ROOT / "build-native").resolve():
        raise ValueError("Configured build is outside this repository")
    compiler = Path(entries["CMAKE_CXX_COMPILER"])
    env = dict(os.environ, PATH=str(compiler.parent) + os.pathsep + os.environ["PATH"])
    scratch = build / "oom-ab"
    scratch.mkdir(exist_ok=True)
    reference_dir = scratch / args.reference
    reference_dir.mkdir(exist_ok=True)
    for name, contents in prior.items():
        header = "oom_reference.hpp" if name == "src/ours.hpp" else Path(name).name
        (reference_dir / header).write_bytes(contents)
    compiler_args = [
        str(compiler), "-O3", "-DNDEBUG", "-std=gnu++17", "-Wall", "-Wextra",
        "-I../src", f"-Ioom-ab/{args.reference}", "@CMakeFiles/comparison_bench.dir/includes_CXX.rsp",
        "../tests/oom_ab.cpp", "-o", "oom-ab/oom_ab.exe",
        "@CMakeFiles/comparison_bench.dir/linkLibs.rsp",
    ]
    subprocess.run(compiler_args, cwd=build, env=env, check=True)
    variants = [args.reference, "comb"]
    command = [str(scratch / "oom_ab.exe"), "../parameters/type-f.param", str(args.repetitions),
               *variants, "oom-ab/setup.csv", *map(str, args.ell)]
    version_files = ["src/ours.hpp", "src/oom_windows.hpp", "src/oom_fixed.hpp",
                     "tests/oom_ab.cpp", "scripts/run_oom_ab.py"]
    measured = [*version_files, *shared]
    digests = {name: sha256((ROOT / name).read_bytes()) for name in measured}
    record = {
        "complete": False,
        "platform": metadata["platform"],
        "hardware": metadata["hardware"],
        "compiler": subprocess.check_output([str(compiler), "--version"], env=env, text=True).splitlines()[0],
        "libraries": metadata["libraries"],
        "compile_command": compiler_args,
        "run_command": command,
        "reference_ours_sha256": prior_hashes["src/ours.hpp"],
        "reference_source_sha256": {name: prior_hashes[name] for name in prior},
        "variants": variants,
        "sources_sha256": digests,
        "binary_sha256": sha256((scratch / "oom_ab.exe").read_bytes()),
        "fixed_baseline_raw_sha256": metadata["raw_sha256"],
        "n": 16, "d": 4, "ell": args.ell, "warmups": 3, "repetitions": args.repetitions,
        "timing": "Single thread, alternated execution order, same issued credential and candidate pool for each pair",
    }
    manifest = output / "environment.json"
    manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    with raw.open("x", encoding="utf-8", newline="") as handle:
        subprocess.run(command, cwd=build, env=env, stdout=handle, check=True)
    if any(sha256((ROOT / name).read_bytes()) != digest for name, digest in digests.items()):
        raise ValueError("Sources changed during the experiment")
    with ZipFile(output / "measured-source.zip", "x", ZIP_DEFLATED) as archive:
        for name in version_files:
            archive.write(ROOT / name, name)
    setup = (scratch / "setup.csv").read_bytes()
    (output / "setup.csv").write_bytes(setup)
    record.update(complete=True, raw_sha256=sha256(raw.read_bytes()), setup_sha256=sha256(setup))
    manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
