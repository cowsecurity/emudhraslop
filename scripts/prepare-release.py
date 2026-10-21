#!/usr/bin/env python3
"""Validate the complete build-job payload before creating a GitHub release."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import zipfile

SPEC = importlib.util.spec_from_file_location('packaging', Path(__file__).with_name('package-release.py'))
PACKAGING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGING)
MAX_ARCHIVE = 128 << 20
MAX_PAYLOAD = 256 << 20
INSTALLERS = ('install.sh', 'install.ps1')


def installer_payload():
    # Installers come from this tagged checkout, never build-job uploads.
    result = {}
    for name in INSTALLERS:
        data = PACKAGING.read_regular(PACKAGING.ROOT / name)
        if not data or len(data) > 64 << 10:
            raise ValueError('Installer is empty or exceeds 64 KiB')
        result[name] = data
    return result


def archive_payload(path):
    contents = {}
    total = 0
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 64:
                raise ValueError('Archive member limit exceeded')
            for member in members:
                mode = member.external_attr >> 16
                if member.is_dir() or mode & 0o170000 != 0o100000:
                    raise ValueError('Archive must contain regular files only')
                total += member.file_size
                if total > MAX_PAYLOAD:
                    raise ValueError('Archive payload limit exceeded')
                contents = add(contents, member.filename, archive.read(member))
    else:
        with tarfile.open(path, 'r:gz') as archive:
            for index, member in enumerate(archive):
                if index >= 64 or not member.isfile():
                    raise ValueError('Archive member type/count is invalid')
                total += member.size
                if total > MAX_PAYLOAD:
                    raise ValueError('Archive payload limit exceeded')
                stream = archive.extractfile(member)
                contents = add(contents, member.name, stream.read(MAX_PAYLOAD + 1))
    return contents


def add(contents, name, data):
    path = PurePosixPath(name)
    if not name or str(path) != name or path.is_absolute() or '..' in path.parts or '\\' in name or name in contents:
        raise ValueError('Unsafe or duplicate archive path')
    contents[name] = data
    return contents


def prepare(source, output, version):
    targets = sorted(PACKAGING.TARGETS)
    PACKAGING.configuration(version, targets)
    expected = {'emudhraslop-' + version + '-' + target.replace('/', '-') +
                ('.zip' if target.startswith('windows/') else '.tar.gz'): target for target in targets}
    found = {}
    declared = {}
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlinked build artifact')
        if not path.is_file():
            continue
        if path.name == 'SHA256SUMS':
            for line in path.read_text().splitlines():
                digest, name = line.split('  ', 1)
                if name not in expected or name in declared or len(bytes.fromhex(digest)) != 32:
                    raise ValueError('Unexpected or duplicate checksum declaration')
                declared[name] = digest
            continue
        if path.name not in expected or path.name in found or path.stat().st_size > MAX_ARCHIVE:
            raise ValueError('Unexpected, duplicate or oversized artifact')
        found[path.name] = path
    if set(found) != set(expected) or set(declared) != set(expected):
        raise ValueError('Incomplete platform release')
    manifests = []
    for name, target in expected.items():
        path = found[name]
        if hashlib.sha256(path.read_bytes()).hexdigest() != declared[name]:
            raise ValueError('Archive checksum mismatch')
        contents = archive_payload(path)
        manifest = json.loads(contents.pop('RELEASE-MANIFEST.json'))
        if manifest.get('schema_version') != 1 or manifest.get('name') != 'emudhraslop' or manifest.get('version') != version or manifest.get('target') != target:
            raise ValueError('Platform manifest identity mismatch')
        executable = 'emudhraslop.exe' if target.startswith('windows/') else 'emudhraslop'
        names = set(PACKAGING.source_files(target)) | {executable}
        if target.startswith('darwin/'):
            names.add('emudhraslop-sectrust')
        if set(contents) != names or set(manifest['files']) != names:
            raise ValueError('Unexpected platform payload')
        for member, data in contents.items():
            if hashlib.sha256(data).hexdigest() != manifest['files'][member]:
                raise ValueError('Platform payload digest mismatch')
        if not PACKAGING.binary_matches(contents[executable], target):
            raise ValueError('Executable architecture mismatch')
        if target.startswith('darwin/'):
            for member in PACKAGING.JAMF_FILES:
                if contents[member] != PACKAGING.read_regular(PACKAGING.ROOT / member):
                    raise ValueError('Jamf deployment asset differs from tagged source')
        if target.startswith('darwin/') and not PACKAGING.binary_matches(contents['emudhraslop-sectrust'], target):
            raise ValueError('Apple helper architecture mismatch')
        manifests.append(manifest)
    installers = installer_payload()
    installer_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in installers.items()}
    # Validation completes before publishing or copying any untrusted payload.
    if output.exists():
        raise ValueError('Output directory already exists')
    output.mkdir(parents=True)
    for name, path in found.items():
        shutil.copyfile(path, output / name)
    for name, data in installers.items():
        (output / name).write_bytes(data)
    aggregate = {'schema_version': 1, 'name': 'emudhraslop', 'version': version,
                 'platforms': manifests, 'installers': installer_hashes}
    (output / 'RELEASE-MANIFEST.json').write_text(json.dumps(aggregate, indent=2, sort_keys=True) + '\n')
    hashes = {name: declared[name] for name in found}
    hashes.update(installer_hashes)
    hashes['RELEASE-MANIFEST.json'] = hashlib.sha256((output / 'RELEASE-MANIFEST.json').read_bytes()).hexdigest()
    (output / 'SHA256SUMS').write_text(''.join(digest + '  ' + name + '\n' for name, digest in sorted(hashes.items())))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        prepare(args.source, args.output, args.version)
    except (ValueError, KeyError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
