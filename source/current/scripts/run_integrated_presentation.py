"""Stage and run the OAS3 presentation benchmark with its exact OAS2 reference."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import os
import platform
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
OLD_RUN = ROOT / "results/utilization-10000-20261110-n32"
SOURCE_PATHS = (
    "src/ours.hpp", "src/core.hpp", "src/group_arithmetic.hpp", "src/oom_fixed.hpp",
    "src/oom_windows.hpp", "src/benchmark_defaults.hpp", "baselines/acl/acl.hpp",
    "baselines/uprove/uprove.hpp", "baselines/chan_yuen_2022/chan_yuen.hpp",
    "baselines/chan_yuen_2022/pairing.hpp", "baselines/chan_yuen_2022/paillier.hpp",
    "baselines/protocol_checks.hpp", "parameters/type-f.param",
    "tests/presentation_integrated_bench.cpp", "scripts/run_integrated_presentation.py",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stage(target):
    old_env = json.loads((OLD_RUN / "environment.json").read_text(encoding="utf-8"))
    if not old_env["complete"]:
        raise ValueError("OAS2 reference run is incomplete")
    with ZipFile(OLD_RUN / "measured-source.zip") as old, ZipFile(target, "x", ZIP_DEFLATED) as new:
        files = {name: (ROOT / name).read_bytes() for name in SOURCE_PATHS}
        for name in (*SOURCE_PATHS[1:5], "parameters/type-f.param"):
            if sha(files[name]) != old_env["source_sha256"][name] or old.read(name) != files[name]:
                raise ValueError(f"OAS2 and OAS3 require the same common backend for {name}")
        legacy = old.read("src/ours.hpp")
        if sha(legacy) != old_env["source_sha256"]["src/ours.hpp"]:
            raise ValueError("Unexpected OAS2 header checksum")
        files["tests/legacy_ours.hpp"] = legacy
        for name, data in files.items():
            new.writestr(name, data)


def run(libraries, cpu, repetitions, smoke):
    pbc, gmp, pbc_library = (Path(path).resolve() for path in libraries)
    binary = ROOT / "presentation_integrated_bench"
    raw = ROOT / "raw_timings.csv"
    manifest = ROOT / "environment.json"
    if raw.exists() or manifest.exists():
        raise ValueError("Choose a new run directory to preserve results")
    cmd = [
        "g++", "-O3", "-DNDEBUG", "-std=gnu++17", "-Isrc", "-Ibaselines",
        f"-I{pbc / 'include'}", f"-I{pbc}", f"-I{gmp / 'include/x86_64-linux-gnu'}",
        "tests/presentation_integrated_bench.cpp", "-o", str(binary), str(pbc_library), "-lcrypto",
        str(gmp / "lib/x86_64-linux-gnu/libgmp.a"), "-lm",
    ]
    subprocess.run(cmd, cwd=ROOT, check=True)
    if smoke:
        subprocess.run(["taskset", "-c", str(cpu), str(binary), "parameters/type-f.param", "1", "32", "64"],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with raw.open("x", encoding="utf-8", newline="") as stdout:
        subprocess.run(["taskset", "-c", str(cpu), str(binary), "parameters/type-f.param", str(repetitions)],
                       cwd=ROOT, stdout=stdout, check=True)
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    model = next(line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("model name"))
    meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
    mem = int(meminfo.splitlines()[0].split()[1]) * 1024
    info = dict(
        complete=True, started_utc=started, completed_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        hardware={"cpu": model, "total_memory_bytes": mem}, platform=platform.platform(),
        compiler=subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
        build="-O3 -DNDEBUG -std=gnu++17", libraries={"PBC": "1.0.0", "GMP": "6.3.0"}, affinity=[cpu],
        repetitions=repetitions, warmups=3, d=2, attribute_counts=list(range(4, 65, 4)), ell=[32, 64, 128],
        baseline_schemes=["ACL", "UPROVE"], paired_configuration={"n": 32, "ell": 64, "d": 2},
        binary_sha256=sha(binary.read_bytes()), raw_sha256=sha(raw.read_bytes()),
        source_sha256={name: sha((ROOT / name).read_bytes()) for name in (*SOURCE_PATHS, "tests/legacy_ours.hpp")},
        scope="Local presentation and verification. Candidate selection is measured once and reused for the paired OAS2/OAS3 variants, whose order alternates. Verification includes registered-candidate checks and tag insertion for OTAC, and local spent-set insertion for the baselines. Issuance, state copies and wire decoding are outside timed intervals.",
    )
    manifest.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stage", type=Path)
    mode.add_argument("--libraries", nargs=3, metavar=("PBC_SRC", "GMP_USR", "PBC_ARCHIVE"))
    parser.add_argument("--cpu", type=int, default=9)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.stage:
        stage(args.stage)
    elif args.cpu not in os.sched_getaffinity(0) or args.repetitions < 2:
        parser.error("Run requires an allowed CPU and at least two repetitions")
    else:
        run(args.libraries, args.cpu, args.repetitions, args.smoke)


if __name__ == "__main__":
    main()
