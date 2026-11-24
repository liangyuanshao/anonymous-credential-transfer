"""Run native experiments without overwriting existing measurements; record provenance."""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from benchmark_config import (
    ATTRIBUTE_COUNTS, DEFAULT_ELL, DEFAULT_N, DEFAULT_D, MATCH_COUNTS,
    WIDE_ATTRIBUTE_COUNTS, WIDE_MATCH_COUNTS, WIDE_MATCH_N,
)

ROOT = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def sources():
    paths = list((ROOT/'src').glob('*.hpp'))+list((ROOT/'src').glob('*.cpp'))
    paths += list((ROOT/'baselines').rglob('*.hpp'))
    paths += list((ROOT/'tests').glob('*.cpp'))+list((ROOT/'tests').glob('*.hpp'))
    paths += [ROOT/'CMakeLists.txt', ROOT/'parameters/type-f.param']
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', default='results/current')
    ap.add_argument('--repetitions', type=int, default=100)
    ap.add_argument('--grid', choices=('default','all','wide'), default='all')
    args = ap.parse_args()
    out = ROOT/args.output
    if (out/'raw_timings.csv').exists():
        raise SystemExit('Measurements already exist; choose a new --output directory')
    out.mkdir(parents=True, exist_ok=True)
    exe = ROOT/'build-native/comparison_bench.exe'
    if not exe.exists():
        exe = ROOT/'build/comparison_bench'
    env = dict(os.environ)
    if os.name == 'nt':
        env['PATH'] = r'C:\Strawberry\c\bin'+';'+env['PATH']
    command = [str(exe), 'bench', 'parameters/type-f.param', str(args.repetitions), args.output, args.grid, str(DEFAULT_ELL)]
    info_exe=exe.with_name('credential_bench.exe' if os.name=='nt' else 'credential_bench')
    info=json.loads(subprocess.check_output([str(info_exe),'info','parameters/type-f.param'],cwd=ROOT,env=env,text=True))
    compiler=subprocess.check_output(['g++','--version'],env=env,text=True).splitlines()[0]
    before = sources()
    metadata = dict(revision='anonymous-attribute-credentials', recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        command=command, platform=platform.platform(), architecture=platform.machine(),
        compiler=compiler, build='CMake Release; -O3; C++17', libraries=dict(PBC='1.0.0', GMP=info['gmp_runtime']),
        native_parameters=info,
        arithmetic_backend='PBC fields; Jacobian scalar multiplication/MSM in G1 and G2; public fixed-base preprocessing in parameter setup',
        python=platform.python_version(),
        repetitions=args.repetitions, warmups=3, default_ell=DEFAULT_ELL,
        default_n=WIDE_ATTRIBUTE_COUNTS[0] if args.grid == 'wide' else DEFAULT_N,
        default_d=DEFAULT_D, grid=args.grid, single_threaded=True,
        attribute_counts={'default': (DEFAULT_N,), 'all': ATTRIBUTE_COUNTS, 'wide': WIDE_ATTRIBUTE_COUNTS}[args.grid],
        match_counts={'default': (), 'all': MATCH_COUNTS, 'wide': WIDE_MATCH_COUNTS}[args.grid],
        clock='std::chrono::steady_clock', source_sha256=before, binary_sha256=sha(exe),
        timing='Parsed PBC objects; generation includes fresh randomness and candidate sampling; transport decoding and fixture copies outside timing',
        state='In-memory atomic ledger; no network or blockchain consensus measurements',
        security='No matched end-to-end security-bit claim; manuscript request has no verifier nonce',
        complete=False)
    metadata['python_packages'] = {}
    for package in ('numpy', 'Pillow', 'PyMuPDF'):
        try:
            metadata['python_packages'][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            continue
    if args.grid == 'wide':
        metadata.update(schemes=('OTAC', 'ACL', 'UPROVE'), match_attribute_count=WIDE_MATCH_N)
    else:
        metadata['cy22'] = 'Honest-party issuance core only; pi_U and HE proofs remain uninstantiated'
    if os.name == 'nt':
        cmd = ['powershell','-NoProfile','-Command',
               '$p=Get-CimInstance Win32_Processor; $c=Get-CimInstance Win32_ComputerSystem; '
               '@{cpu=$p.Name;total_memory_bytes=$c.TotalPhysicalMemory}|ConvertTo-Json -Compress']
        metadata['hardware'] = json.loads(subprocess.check_output(cmd, text=True, encoding='utf-8'))
    elif platform.system() == 'Linux':
        model = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                     if line.startswith(('model name', 'Hardware')))
        memory_kib = int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])
        metadata['hardware'] = dict(cpu=model, total_memory_bytes=memory_kib * 1024)
        metadata['distribution'] = platform.freedesktop_os_release()['PRETTY_NAME']
    path = out/'environment.json'
    construction=ROOT.parent/'中文稿/06_详细构造.md'
    if construction.exists():
        metadata['construction_sha256']=sha(construction)
        (out/'construction_snapshot.md').write_bytes(construction.read_bytes())
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    with (out/'run.log').open('w', encoding='utf-8') as log:
        p = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
        for line in p.stdout:
            log.write(line); log.flush()
            print(line, end='', flush=True)
        code = p.wait()
    metadata.update(completed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    returncode=code, source_unchanged=(sources()==before),
                    binary_unchanged=(sha(exe)==metadata['binary_sha256']))
    metadata['complete'] = code==0 and metadata['source_unchanged'] and metadata['binary_unchanged']
    if (out/'raw_timings.csv').exists():
        metadata['raw_sha256'] = sha(out/'raw_timings.csv')
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    if not metadata['complete']:
        raise SystemExit('Run failed or implementation changed during measurement; see environment.json')


if __name__ == '__main__':
    main()
