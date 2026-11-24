#!/usr/bin/env python3
"""Verify and build a preserved measured source without changing its archive."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def archive_files(path):
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as z:
            return {n: z.read(n) for n in z.namelist() if not n.endswith('/')}
    with tarfile.open(path, 'r:gz') as z:
        result = {}
        for m in z.getmembers():
            if m.isdir():
                continue
            if not m.isfile():
                raise ValueError('Unsupported archive member: ' + m.name)
            result[m.name] = z.extractfile(m).read()
        return result

def main():
    info = json.loads((ROOT / 'source/snapshots.json').read_text(encoding='utf-8'))['snapshots']
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--list', action='store_true')
    p.add_argument('--snapshot', choices=sorted(info))
    p.add_argument('--target', help='A target name listed by --list; defaults to all targets for the snapshot')
    p.add_argument('--output', type=Path, help='New extraction directory; defaults to .work/SNAPSHOT')
    p.add_argument('--prepare-only', action='store_true', help='Verify/extract sources without compilation')
    p.add_argument('--compiler', default='g++')
    p.add_argument('--pbc-source', type=Path, help='PBC 1.0.0 source directory')
    p.add_argument('--pbc-library', type=Path, help='Compiled PBC 1.0.0 static archive')
    p.add_argument('--gmp-include', type=Path)
    p.add_argument('--library-directory', type=Path, action='append', default=[])
    a = p.parse_args()
    if a.list:
        print(json.dumps(info, indent=2))
        return
    if not a.snapshot:
        p.error('--snapshot or --list is required')
    s = info[a.snapshot]
    targets = s['targets']
    if a.target:
        if a.target not in targets:
            p.error('--target must be one of: ' + ', '.join(targets))
        targets = {a.target: targets[a.target]}
    if not a.prepare_only and (not a.pbc_source or not a.pbc_library):
        p.error('Compilation requires --pbc-source and --pbc-library')
    archive = ROOT / s['archive']
    if digest(archive.read_bytes()) != s['archive_sha256']:
        raise ValueError('Archive hash mismatch')
    files = archive_files(archive)
    for meta in s['environment_files']:
        env = json.loads((ROOT / meta).read_text(encoding='utf-8'))
        for name, expected in env['source_sha256'].items():
            if name not in files or digest(files[name]) != expected:
                raise ValueError('Measured-source mismatch: ' + name)
    out = (a.output or ROOT / '.work' / a.snapshot).resolve()
    if out.exists():
        raise FileExistsError('Choose a new --output directory; existing sources/results are never overwritten: ' + str(out))
    out.mkdir(parents=True)
    for name, data in files.items():
        rel = PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts or ':' in name or '\\' in name:
            raise ValueError('Unsafe archive path: ' + name)
        dest = out.joinpath(*rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    commands = []
    if not a.prepare_only:
        pbc_source = a.pbc_source.resolve(strict=True)
        pbc_library = a.pbc_library.resolve(strict=True)
        for target, source in targets.items():
            suffix = '.exe' if __import__('os').name == 'nt' else ''
            output = out / (target + suffix)
            command = [a.compiler, '-O3', '-DNDEBUG', '-std=gnu++17', '-Isrc', '-Ibaselines', '-I' + str(pbc_source / 'include'), '-I' + str(pbc_source)]
            if a.gmp_include:
                command.append('-I' + str(a.gmp_include.resolve(strict=True)))
            for libdir in a.library_directory:
                command.append('-L' + str(libdir.resolve(strict=True)))
            command += [source, '-o', str(output), str(pbc_library), '-lcrypto', '-lgmp', '-lm']
            commands.append(command)
            subprocess.run(command, cwd=out, check=True)
    print(json.dumps({'snapshot': a.snapshot, 'output': str(out), 'source_hashes_verified': True, 'compiled_targets': list(targets) if not a.prepare_only else [], 'commands': commands, 'run_working_directory': str(out)}, indent=2))

if __name__ == '__main__':
    main()
