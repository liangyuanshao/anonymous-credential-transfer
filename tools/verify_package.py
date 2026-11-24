#!/usr/bin/env python3
"""Check release integrity, measured-source versions and archived numerical data."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    manifest = json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))
    for item in manifest['files']:
        p = ROOT / item['path']
        data = p.read_bytes()
        assert len(data) == item['bytes'] and sha(data) == item['sha256'], item['path']
    checksum_count = 0
    for line in (ROOT / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        expected, name = line.split('  ', 1)
        assert sha((ROOT / name).read_bytes()) == expected, name
        checksum_count += 1
    mapping = json.loads((ROOT / 'source/snapshots.json').read_text(encoding='utf-8'))
    source_count = 0
    for name, spec in mapping['snapshots'].items():
        archive = ROOT / spec['archive']
        assert sha(archive.read_bytes()) == spec['archive_sha256'], name
        if archive.suffix == '.zip':
            with zipfile.ZipFile(archive) as z:
                assert z.testzip() is None
                files = {n: z.read(n) for n in z.namelist() if not n.endswith('/')}
        else:
            with tarfile.open(archive, 'r:gz') as z:
                files = {m.name: z.extractfile(m).read() for m in z.getmembers() if m.isfile()}
        for meta in spec['environment_files']:
            env = json.loads((ROOT / meta).read_text(encoding='utf-8'))
            for path, expected in env['source_sha256'].items():
                assert path in files and sha(files[path]) == expected, (name, path)
                source_count += 1
    subprocess.run([sys.executable, '-B', 'scripts/verify.py'], cwd=ROOT / 'data', check=True)
    print(json.dumps({'package_integrity': 'passed', 'checksums_checked': checksum_count, 'unique_measured_archives': len(mapping['snapshots']), 'measured_source_hash_checks': source_count, 'numerical_verifier': 'passed', 'benchmark_compilation_or_full_rerun': 'not performed by this checker'}, indent=2))

if __name__ == '__main__':
    main()
