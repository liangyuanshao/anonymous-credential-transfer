"""Measure complete issuance cohorts and actual one-time consumption prefixes."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import json
import os
import platform
import subprocess
from pathlib import Path
from shutil import copyfileobj
from zipfile import ZIP_DEFLATED, ZipFile

from run_experiments import ROOT, sha, sources
from benchmark_config import DEFAULT_ELL, DEFAULT_N, DEFAULT_D

DEFAULT_CREDENTIALS_PER_BATCH = 64


def run_parallel(command, cores, output, env):
    """Run one complete, single-core paired batch per worker."""
    parts = output / "batches"
    parts.mkdir()
    commands = [["taskset", "-c", str(core), *command, str(index)]
                for index, core in enumerate(cores)]

    def run_one(index, worker):
        with (parts / f"{index}.csv").open("xb") as raw, (parts / f"{index}.log").open("xb") as log:
            subprocess.run(worker, cwd=ROOT, env=env, stdout=raw, stderr=log, check=True)
        return index

    with (output / "run.log").open("x", encoding="utf-8") as log:
        with ThreadPoolExecutor(max_workers=len(cores)) as workers:
            pending = [workers.submit(run_one, index, worker) for index, worker in enumerate(commands)]
            for completed in as_completed(pending):
                index = completed.result()
                message = f"Paired batch {index + 1}/{len(cores)} completed on CPU {cores[index]}"
                print(message, flush=True)
                print(message, file=log, flush=True)
    with (output / "raw_timings.csv").open("xb") as raw:
        header = None
        for index in range(len(cores)):
            with (parts / f"{index}.csv").open("rb") as part:
                columns = part.readline()
                if header is None:
                    header = columns
                    raw.write(header)
                if columns != header or not columns.startswith(b"batch,scheme,"):
                    raise RuntimeError(f"Unexpected CSV header in batch {index}")
                copyfileobj(part, raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/utilization")
    parser.add_argument("--batches", type=int, default=24)
    parser.add_argument("--mode", choices=("legacy", "first-v2"), default="legacy")
    parser.add_argument("--attributes", type=int, choices=(16, 32))
    parser.add_argument("--credentials-per-batch", type=int,
                        help="Cohort size for first-v2; defaults to 64")
    parser.add_argument("--binary", type=Path, help="Path to the utilization benchmark executable")
    parser.add_argument("--info-binary", type=Path, help="Path to credential_bench for parameter metadata")
    parser.add_argument("--parameters", default="parameters/type-f.param",
                        help="Parameter file for Type F, or prime256v1 for the OpenSSL build")
    parser.add_argument("--batch-cores", type=int, nargs="+",
                        help="On Linux, run one paired batch per listed CPU")
    args = parser.parse_args()
    if args.batches < 6 or args.batches % 6:
        parser.error("choose a positive multiple of six for balanced execution order")
    first_v2 = args.mode == "first-v2"
    if first_v2 != (args.attributes is not None):
        parser.error("--attributes 16 or 32 is required in first-v2 mode and reserved for that mode")
    if args.credentials_per_batch is not None and (not first_v2 or args.credentials_per_batch < DEFAULT_ELL):
        parser.error(f"--credentials-per-batch requires first-v2 mode and at least {DEFAULT_ELL} credentials")
    if args.batch_cores is not None:
        cores = args.batch_cores
        if platform.system() != "Linux" or not first_v2:
            parser.error("--batch-cores requires Linux and first-v2 mode")
        if len(cores) != args.batches or len(set(cores)) != len(cores):
            parser.error("--batch-cores requires one distinct CPU per paired batch")
        if not set(cores) <= os.sched_getaffinity(0):
            parser.error("--batch-cores contains unavailable CPUs")
    output = args.output.resolve()
    if output.exists():
        parser.error("choose a fresh output directory")

    default_executable = ROOT / "build-native/utilization_bench.exe"
    if os.name != "nt" or not default_executable.is_file():
        default_executable = ROOT / "build/utilization_bench"
    executable = args.binary.resolve() if args.binary else default_executable
    if not executable.is_file():
        parser.error("build utilization_bench before measuring")
    env = dict(os.environ)
    if os.name == "nt":
        env["PATH"] = r"C:\Strawberry\c\bin" + os.pathsep + env["PATH"]
    default_info = executable.with_name("credential_bench.exe" if os.name == "nt" else "credential_bench")
    info = args.info_binary.resolve() if args.info_binary else default_info
    if not info.is_file():
        parser.error("build credential_bench or provide --info-binary for parameter metadata")
    native = json.loads(subprocess.check_output(
        [str(info), "info", args.parameters], cwd=ROOT, env=env, text=True))
    before = sources()
    libraries = {"GMP": native["gmp_runtime"]}
    if native.get("curve") == "prime256v1":
        before.pop("parameters/type-f.param")
        libraries["OpenSSL"] = native["openssl"]
    else:
        libraries["PBC"] = native["pbc"]
    before["scripts/run_utilization.py"] = sha(Path(__file__))
    command = [str(executable), args.parameters, str(args.batches)]
    if first_v2:
        command.extend((args.mode, str(args.attributes)))
    if args.credentials_per_batch is not None or args.batch_cores is not None:
        command.append(str(args.credentials_per_batch or DEFAULT_CREDENTIALS_PER_BATCH))
    record = {
        "complete": False,
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "compiler": subprocess.check_output(["g++", "--version"], env=env, text=True).splitlines()[0],
        "build": "-O3; C++17" if args.binary else "CMake Release; -O3; C++17",
        "libraries": libraries,
        "native_parameters": native,
        "command": command,
        "source_sha256": before,
        "binary_sha256": sha(executable),
        "paired_batches": args.batches, "warmup_batches": 3,
        "credentials_per_batch": args.credentials_per_batch or DEFAULT_CREDENTIALS_PER_BATCH,
        "warmup_credentials_per_batch": DEFAULT_CREDENTIALS_PER_BATCH, "ell": DEFAULT_ELL,
        "n": args.attributes if first_v2 else DEFAULT_N, "d": DEFAULT_D,
        "issuance_mode": args.mode,
        "schemes": ["OTAC", "ACL", "UPROVE"],
        "order_seed": 20261107,
        "measurement": "Serial local calls using steady_clock; actual issuance, admission and distinct one-time uses",
        "acl": "One first registration per new holder; registration and check recorded separately",
        "practical_margin_pct": 10,
    }
    if args.batch_cores is not None:
        record.update(
            batch_cores=args.batch_cores,
            warmup_batches_per_worker=3,
            measurement="One single-core process per paired batch; serial steady_clock measurements of issuance, admission and distinct one-time uses",
        )
    if os.name == "nt":
        record["hardware"] = json.loads(subprocess.check_output([
            "powershell", "-NoProfile", "-Command",
            "$p=Get-CimInstance Win32_Processor; $c=Get-CimInstance Win32_ComputerSystem; "
            "@{cpu=$p.Name;total_memory_bytes=$c.TotalPhysicalMemory}|ConvertTo-Json -Compress"
        ], encoding="utf-8"))
    elif platform.system() == "Linux":
        cpu = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                   if line.startswith(("model name", "Hardware")))
        memory_kib = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1])
        record["hardware"] = {"cpu": cpu, "total_memory_bytes": memory_kib * 1024}
        record["cpu_affinity"] = sorted(os.sched_getaffinity(0))
        record["distribution"] = platform.freedesktop_os_release()["PRETTY_NAME"]
    output.mkdir(parents=True)
    manifest = output / "environment.json"
    manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raw = output / "raw_timings.csv"
    if args.batch_cores is not None:
        run_parallel(command, args.batch_cores, output, env)
    else:
        with raw.open("x", encoding="utf-8", newline="") as rows, (output / "run.log").open("x", encoding="utf-8") as log:
            with subprocess.Popen(command, cwd=ROOT, env=env, stdout=rows, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace") as run:
                for line in run.stderr:
                    log.write(line)
                    log.flush()
                    print(line, end="", flush=True)
                if run.wait() != 0:
                    raise RuntimeError("Native workload did not complete")
    if any(sha(ROOT / name) != digest for name, digest in before.items()) or sha(executable) != record["binary_sha256"]:
        raise RuntimeError("Native source or executable changed during the run")
    with ZipFile(output / "measured-source.zip", "x", ZIP_DEFLATED) as archive:
        for name in before:
            archive.write(ROOT / name, name)
    record.update(complete=True, raw_sha256=sha(raw),
                  completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"Saved measured workload to {output}")


if __name__ == "__main__":
    main()
