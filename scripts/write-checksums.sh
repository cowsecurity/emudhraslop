#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
VERSION=${VERSION:-0.3.0-dev}
PYTHON=${PYTHON:-python3}
CHECKSUM_DIR=${CHECKSUM_DIR:-dist}
case "$VERSION" in *[!a-zA-Z0-9.+_-]*|'') echo 'Invalid VERSION' >&2; exit 1;; esac
"$PYTHON" - "$CHECKSUM_DIR" "$VERSION" <<'PY'
import hashlib
import os
from pathlib import Path
import sys
import tempfile

directory, version = Path(sys.argv[1]), sys.argv[2]
if directory.is_symlink() or not directory.is_dir():
    raise SystemExit('Checksum directory must be an existing nonsymlink directory')
names = ['emudhraslop', 'emudhraslop-sectrust', f'emudhraslop-{version}.pkg']
for target in ['darwin-amd64', 'darwin-arm64', 'linux-amd64', 'linux-arm64',
               'linux-arm-v7', 'windows-amd64', 'windows-arm64']:
    binary = 'emudhraslop.exe' if target.startswith('windows') else 'emudhraslop'
    names.append(f'{target}/{binary}')
    if target.startswith('darwin'):
        names.append(f'{target}/emudhraslop-sectrust')
for prefix in ['', 'releases/']:
    for extension in ['tar.gz', 'zip']:
        names.extend(str(p.relative_to(directory)) for p in directory.glob(
            f'{prefix}emudhraslop-{version}-*.{extension}'))
lines = []
for name in sorted(set(names)):
    path = directory / name
    if path.is_symlink() or path.parent.is_symlink():
        raise SystemExit('Refusing to hash symlinked artifact')
    if not path.is_file():
        continue
    digest = hashlib.sha256()
    with path.open('rb') as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b''):
            digest.update(chunk)
    lines.append(f'{digest.hexdigest()}  {name}\n')
if not lines:
    raise SystemExit('No release artifacts to hash')
descriptor, temporary = tempfile.mkstemp(prefix='.SHA256SUMS-', dir=directory)
try:
    with os.fdopen(descriptor, 'w', newline='\n') as output:
        output.writelines(lines)
    os.chmod(temporary, 0o444)
    os.replace(temporary, directory / 'SHA256SUMS')
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
