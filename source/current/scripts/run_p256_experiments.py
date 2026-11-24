"""Measure the paper's three implemented schemes with the named OpenSSL P-256 group."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZipFile

from benchmark_config import WIDE_ATTRIBUTE_COUNTS
from run_experiments import ROOT, sha, sources


def current_time():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--core", type=int, required=True)
    parser.add_argument("--batch-cores-16", type=int, nargs=6, required=True)
    parser.add_argument("--batch-cores-32", type=int, nargs=6, required=True)
    args = parser.parse_args()
    batch_cores = {16: args.batch_cores_16, 32: args.batch_cores_32}
    cores = [args.core, *batch_cores[16], *batch_cores[32]]
    if len(set(cores)) != len(cores) or not set(cores) <= os.sched_getaffinity(0):
        parser.error("choose distinct available Linux CPUs")
    build, output = args.build.resolve(), args.output.resolve()
    info = json.loads(subprocess.check_output(
        [build / "credential_bench", "info", "prime256v1"], text=True, cwd=ROOT))
    if (info["curve"], info["order_bits"], info["scalar_bytes"], info["group_bytes"],
            info["show_wire_version"]) != ("prime256v1", 256, 32, 33, "OAS3"):
        raise ValueError("Unexpected benchmark backend or wire parameters")

    binaries = ("credential_bench", "issuance_timing", "issuance_communication",
                "presentation_transfer_bench", "utilization_bench")
    before = sources()
    before.pop("parameters/type-f.param")
    for name in ("run_p256_experiments.py", "run_utilization.py"):
        before["scripts/" + name] = sha(ROOT / "scripts" / name)
    binary_hashes = {name: sha(build / name) for name in binaries}
    output.mkdir(parents=True)
    manifest = output / "environment.json"
    commands = {
        "issuance_timings.csv": ["issuance_timing", "prime256v1", "100"],
        "issuance_communication.csv": ["issuance_communication", "prime256v1"],
        "presentation_transfer.csv": ["presentation_transfer_bench", "prime256v1", "100"],
    }
    cpu = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
               if line.startswith("model name"))
    observed_files = {}
    record = dict(
        complete=False, started_utc=current_time(), native_parameters=info,
        platform=platform.platform(), processor=cpu,
        compiler=subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
        build="CMake Release; -O3; C++17", core=args.core, repetitions=100, warmups=3,
        attribute_counts=list(WIDE_ATTRIBUTE_COUNTS), candidate_counts=[32, 64, 128],
        matched_attributes=2, transfer_attributes=list(range(8, 65, 8)),
        schemes=["OTAC", "ACL", "UPROVE"], source_sha256=before, binary_sha256=binary_hashes,
        commands=commands, files=observed_files,
        scope=("The issuance benchmark separates ledger admission. Presentation generation includes "
               "candidate sampling; verification includes registered-list and local spent-state checks. "
               "Transfer includes candidate sampling and local confirmation. Network and consensus are not timed."),
    )
    manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["ctest", "--test-dir", build, "--output-on-failure"], check=True, cwd=ROOT)
    for name, argv in commands.items():
        print(f"Starting {name}", flush=True)
        raw = output / name
        with raw.open("xb") as rows, raw.with_suffix(".log").open("xb") as log:
            subprocess.run(["taskset", "-c", str(args.core), build / argv[0], *argv[1:]],
                           stdout=rows, stderr=log, cwd=ROOT, check=True)
        observed_files[name] = sha(raw)
        manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"Completed {name}", flush=True)

    def run_workload(n):
        print(f"Starting n={n}: six paired batches, 10000 credentials per batch", flush=True)
        subprocess.run([
            sys.executable, ROOT / "scripts/run_utilization.py",
            "--binary", build / "utilization_bench", "--info-binary", build / "credential_bench",
            "--parameters", "prime256v1", "--mode", "first-v2", "--attributes", str(n),
            "--batches", "6", "--credentials-per-batch", "10000",
            "--output", output / f"utilization-n{n}", "--batch-cores", *map(str, batch_cores[n]),
        ], check=True, cwd=ROOT)

    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(run_workload, n) for n in batch_cores]
        for job in jobs:
            job.result()
    if any(sha(ROOT / name) != digest for name, digest in before.items()):
        raise RuntimeError("Benchmark source changed during execution")
    if any(sha(build / name) != digest for name, digest in binary_hashes.items()):
        raise RuntimeError("Benchmark binary changed during execution")
    with ZipFile(output / "measured-source.zip", "x", ZIP_DEFLATED) as archive:
        for name in before:
            archive.write(ROOT / name, name)
    record.update(complete=True, completed_utc=current_time())
    manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
