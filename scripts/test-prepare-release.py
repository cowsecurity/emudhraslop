#!/usr/bin/env python3
"""Adversarial checks for the release publication boundary, without extracting archives."""
import importlib.util
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
