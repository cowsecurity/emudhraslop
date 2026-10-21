#!/usr/bin/env python3
"""Adversarial checks for the release publication boundary, without extracting archives."""
import hashlib
import importlib.util
import json
import struct
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('prepare-release.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PublicationBoundary(unittest.TestCase):
    def test_installers_are_exact_local_regular_bounded_files(self):
        previous = prepare.PACKAGING.ROOT
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prepare.PACKAGING.ROOT = root
                for name in prepare.INSTALLERS:
                    (root / name).write_bytes(b'installer source\n')
                self.assertEqual(set(prepare.installer_payload()), {'install.sh', 'install.ps1'})
                shell = root / 'install.sh'
                shell.write_bytes(b'x' * ((64 << 10) + 1))
                with self.assertRaises(ValueError):
                    prepare.installer_payload()
                shell.write_bytes(b'')
                with self.assertRaises(ValueError):
                    prepare.installer_payload()
                shell.unlink()
                shell.symlink_to(root / 'install.ps1')
                with self.assertRaises(ValueError):
                    prepare.installer_payload()
        finally:
            prepare.PACKAGING.ROOT = previous

    def test_rejects_missing_platforms_before_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                prepare.prepare(root, root / 'publish', '0.1.0')
            self.assertFalse((root / 'publish').exists())

    def test_complete_release_rejects_modified_jamf_assets_despite_matching_hashes(self):
        packaging = prepare.PACKAGING
        previous = packaging.ROOT
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                packaging.ROOT = root
                for name in packaging.DOCUMENTS + packaging.JAMF_FILES + list(prepare.INSTALLERS):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"reviewed source\n")
                source = root / 'incoming'
                source.mkdir()
                hashes = {}
                for target in sorted(packaging.TARGETS):
                    platform, architecture = target.split('/', 1)
                    binary = bytearray(80)
                    if platform == 'linux':
                        binary[:6] = b"\x7fELF" + bytes([1 if architecture == 'arm/v7' else 2, 1])
                        struct.pack_into('<H', binary, 18, {'amd64': 62, 'arm64': 183, 'arm/v7': 40}[architecture])
                    elif platform == 'darwin':
                        binary[:4] = b"\xcf\xfa\xed\xfe"
                        struct.pack_into('<I', binary, 4, {'amd64': 0x01000007, 'arm64': 0x0100000C}[architecture])
                    else:
                        binary[:2] = b'MZ'
                        struct.pack_into('<I', binary, 60, 64)
                        binary[64:68] = b'PE\0\0'
                        struct.pack_into('<H', binary, 68, {'amd64': 0x8664, 'arm64': 0xAA64}[architecture])
                    build = root / 'dist' / target.replace('/', '-')
                    build.mkdir(parents=True)
                    (build / ('emudhraslop.exe' if platform == 'windows' else 'emudhraslop')).write_bytes(binary)
                    if platform == 'darwin':
                        (build / 'emudhraslop-sectrust').write_bytes(binary)
                    payload = packaging.payload('0.3.0', target)
                    name = 'emudhraslop-0.3.0-' + target.replace('/', '-') + ('.zip' if platform == 'windows' else '.tar.gz')
                    packaging.write_archive(source / name, payload)
                    hashes[name] = hashlib.sha256((source / name).read_bytes()).hexdigest()
                def checksums():
                    (source / 'SHA256SUMS').write_text(''.join(digest + '  ' + name + '\n' for name, digest in hashes.items()))
                checksums()
                prepare.prepare(source, root / 'valid', '0.3.0')
                name = 'emudhraslop-0.3.0-darwin-arm64.tar.gz'
                payload = packaging.payload('0.3.0', 'darwin/arm64')
                asset = packaging.JAMF_FILES[0]
                payload[asset] = (b'modified deployment command\n', 0o555)
                manifest = json.loads(payload['RELEASE-MANIFEST.json'][0])
                manifest['files'][asset] = hashlib.sha256(payload[asset][0]).hexdigest()
                payload['RELEASE-MANIFEST.json'] = (json.dumps(manifest).encode(), 0o444)
                packaging.write_archive(source / name, payload)
                hashes[name] = hashlib.sha256((source / name).read_bytes()).hexdigest()
                checksums()
                with self.assertRaisesRegex(ValueError, 'Jamf deployment asset differs'):
                    prepare.prepare(source, root / 'tampered', '0.3.0')
                self.assertFalse((root / 'tampered').exists())
        finally:
            packaging.ROOT = previous

    def test_paths_and_duplicates_cannot_cross_archive_boundary(self):
        for name in ['../escape', '/absolute', 'C:\\escape', './normalized', 'docs/../escape']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                prepare.add({}, name, b'')
        with self.assertRaises(ValueError):
            prepare.add({'same': b'first'}, 'same', b'second')

    def test_tar_links_and_devices_are_rejected(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'invalid.tar.gz'
                with tarfile.open(path, 'w:gz') as archive:
                    member = tarfile.TarInfo('emudhraslop')
                    member.type = kind
                    member.linkname = '/etc/passwd'
                    archive.addfile(member)
                with self.assertRaises(ValueError):
                    prepare.archive_payload(path)

    def test_zip_link_is_not_a_regular_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'invalid.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                member = zipfile.ZipInfo('emudhraslop.exe')
                member.create_system = 3
                member.external_attr = 0o120777 << 16
                archive.writestr(member, '/etc/passwd')
            with self.assertRaises(ValueError):
                prepare.archive_payload(path)

    def test_tar_payloads_are_read_without_filesystem_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'regular.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                member = tarfile.TarInfo('README.md')
                member.size = 7
                archive.addfile(member, io.BytesIO(b'example'))
            self.assertEqual(prepare.archive_payload(path), {'README.md': b'example'})
            self.assertFalse((Path(directory) / 'README.md').exists())


if __name__ == '__main__':
    unittest.main()
