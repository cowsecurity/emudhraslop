#!/usr/bin/env python3
"""Run the real shell/tar/hash installer with test-only HTTP failure injection.

python3 scripts/test-install-unix.py
EMUDHRASLOP_TEST_REAL_RELEASE=0.1.0 python3 scripts/test-install-unix.py
The optional real-release check downloads and executes only the version command.
"""
import hashlib
import io
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
BASE = "https://github.com/cowsecurity/emudhraslop/releases"
# Only this explicitly test-owned PATH entry substitutes network transport.
CURL_DOUBLE = r'''
import os, pathlib, shutil, sys
args = sys.argv[1:]
assert args[0] == '-q'
assert args[args.index('--proto') + 1] == '=https'
assert args[args.index('--proto-redir') + 1] == '=https'
assert '--max-time' in args and '--max-filesize' in args
url = args[-1]
assert url.startswith('https://github.com/cowsecurity/emudhraslop/releases/')
source = pathlib.Path(os.environ['INSTALL_TEST_FIXTURES'])
mode = os.environ.get('INSTALL_TEST_MODE', '')
if '--head' in args:
    print('https://evil.invalid/v0.1.0' if mode == 'redirect' else
          'https://github.com/cowsecurity/emudhraslop/releases/tag/v0.1.0', end='')
    raise SystemExit(0)
output = pathlib.Path(args[args.index('--output') + 1])
if mode == 'partial':
    output.write_bytes(b'partial')
    raise SystemExit(18)
name = 'SHA256SUMS' if url.endswith('/SHA256SUMS') else 'release.tar.gz'
shutil.copyfile(source / name, output)
'''


@unittest.skipIf(os.geteuid() == 0, "Installer intentionally refuses root; run as a regular user")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="emudhraslop installer ")
        # macOS /var is a symlink. Test the explicit, canonical destination.
        self.root = Path(self.temp.name).resolve()
        self.bin = self.root / "install space 'quote" / "bin"
        self.doubles = self.root / "doubles"
        self.doubles.mkdir()
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        self.env = dict(os.environ, INSTALL_TEST_FIXTURES=str(self.fixtures),
                        PATH=str(self.doubles) + os.pathsep + os.environ["PATH"])
        self.double("curl", CURL_DOUBLE)
        self.payload = b'#!/bin/sh\nprintf "test-release\\n"\n'
        self.archive()

    def tearDown(self):
        self.temp.cleanup()

    def double(self, name, code):
        path = self.doubles / name
        path.write_text("#!" + sys.executable + "\n" + code)
        path.chmod(0o755)

    def archive(self, defect=""):
        with tarfile.open(self.fixtures / "release.tar.gz", "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name in ["emudhraslop", "emudhraslop-sectrust"]:
                entry = tarfile.TarInfo(name)
                entry.mode = 0o755
                entry.size = len(self.payload)
                if defect in ("symlink", "hardlink") and name == "emudhraslop":
                    entry.type = tarfile.SYMTYPE if defect == "symlink" else tarfile.LNKTYPE
                    entry.linkname = str(self.root / "victim")
                    entry.size = 0
                    archive.addfile(entry)
                elif defect == "missing" and name == "emudhraslop":
                    continue
                else:
                    archive.addfile(entry, io.BytesIO(self.payload))
                    if defect == "duplicate" and name == "emudhraslop":
                        archive.addfile(entry, io.BytesIO(self.payload))
            # Must never be extracted, even though included in verified archive.
            entry = tarfile.TarInfo("../../outside")
            entry.size = 6
            archive.addfile(entry, io.BytesIO(b"escape"))
        digest = hashlib.sha256((self.fixtures / "release.tar.gz").read_bytes()).hexdigest()
        targets = ["darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64", "linux-arm-v7"]
        self.sums = "".join(f"{digest}  emudhraslop-0.1.0-{target}.tar.gz\n" for target in targets)
        (self.fixtures / "SHA256SUMS").write_text(self.sums)

    def run_installer(self, *args, version=True):
        command = ["sh", str(INSTALLER), "--bin-dir", str(self.bin)]
        if version:
            command += ["--version", "0.1.0"]
        result = subprocess.run(command + list(args), env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=420)
        self.assertFalse([p for p in self.bin.glob(".emudhraslop-install.*") if p.name != ".emudhraslop-install.lock"])
        return result

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.bin / "emudhraslop").exists())

    def test_install_upgrade_and_shell_quoting(self):
        for _ in range(2):
            result = self.run_installer()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.bin / "emudhraslop").read_bytes(), self.payload)
            command = result.stdout.split("Run:\n  ", 1)[1].splitlines()[0]
            self.assertEqual(shlex.split(command), [str(self.bin / "emudhraslop"), "check", "--online"])
        self.assertFalse((self.root / "outside").exists())
        self.assertFalse((self.bin.parent / "outside").exists())
        if platform.system() == "Darwin":
            self.assertEqual((self.bin / "emudhraslop-sectrust").read_bytes(), self.payload)

    def test_replace_failure_rolls_back_previous_pair(self):
        self.bin.mkdir(parents=True)
        for name in ("emudhraslop", "emudhraslop-sectrust"):
            (self.bin / name).write_bytes(b"previous " + name.encode())
        self.double("mv", r'''
import os, pathlib, sys
source = pathlib.Path(sys.argv[-2])
if source.name == 'emudhraslop' and source.parent.name.startswith('.emudhraslop-install.'):
    raise SystemExit(1)
os.replace(source, sys.argv[-1])
''')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        for name in ("emudhraslop", "emudhraslop-sectrust"):
            self.assertEqual((self.bin / name).read_bytes(), b"previous " + name.encode())

    def test_concurrent_installer_refused(self):
        self.bin.mkdir(parents=True)
        (self.bin / ".emudhraslop-install.lock").mkdir()
        result = self.run_installer()
        self.assert_refused(result)
        self.assertIn("Another installation", result.stderr)
        self.assertTrue((self.bin / ".emudhraslop-install.lock").is_dir())

    def test_latest(self):
        result = self.run_installer(version=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_checksum_mismatch_preserves_existing_install(self):
        self.bin.mkdir(parents=True)
        previous = self.bin / "emudhraslop"
        previous.write_bytes(b"previous release")
        (self.fixtures / "release.tar.gz").write_bytes(b"corrupted")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum mismatch", result.stderr)
        self.assertEqual(previous.read_bytes(), b"previous release")

    def test_duplicate_or_missing_checksum(self):
        for sums in (self.sums + self.sums, "", self.sums.replace("emudhraslop-", "prefix-emudhraslop-")):
            with self.subTest(sums=sums[:20]):
                (self.fixtures / "SHA256SUMS").write_text(sums)
                self.assert_refused(self.run_installer())

    def test_unsafe_archive_members(self):
        for defect in ("symlink", "hardlink", "duplicate", "missing"):
            with self.subTest(defect=defect):
                self.archive(defect)
                self.assert_refused(self.run_installer())

    def test_partial_download(self):
        self.env["INSTALL_TEST_MODE"] = "partial"
        self.assert_refused(self.run_installer())

    def test_unexpected_latest_redirect(self):
        self.env["INSTALL_TEST_MODE"] = "redirect"
        self.assert_refused(self.run_installer(version=False))

    def test_symlink_directory(self):
        self.bin.parent.mkdir()
        destination = self.root / "other"
        destination.mkdir()
        self.bin.symlink_to(destination)
        self.assert_refused(self.run_installer())
        self.assertFalse(list(destination.iterdir()))

    def test_symlink_executable(self):
        self.bin.mkdir(parents=True)
        victim = self.root / "victim"
        victim.write_bytes(b"keep")
        (self.bin / "emudhraslop").symlink_to(victim)
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(victim.read_bytes(), b"keep")

    def test_hardlinked_executable(self):
        self.bin.mkdir(parents=True)
        victim = self.root / "victim"
        victim.write_bytes(b"keep")
        os.link(victim, self.bin / "emudhraslop")
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(victim.read_bytes(), b"keep")

    def test_oversized_previous_binary_refused_before_backup(self):
        self.bin.mkdir(parents=True)
        previous = self.bin / "emudhraslop"
        with previous.open("wb") as stream:
            stream.truncate(67108865)
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(previous.stat().st_size, 67108865)

    def test_writable_destination(self):
        self.bin.mkdir(parents=True)
        self.bin.chmod(0o777)
        self.assert_refused(self.run_installer())

    def test_invalid_paths_versions_and_options(self):
        for args in [("--bin-dir", "relative"), ("--bin-dir", str(self.root / ".." / "x")),
                     ("--version", "0.1.0\n../../evil"), ("--version", "../../evil"),
                     ("--version",), ("--bogus",)]:
            with self.subTest(args=args):
                self.assert_refused(self.run_installer(*args))

    def test_root_is_refused(self):
        self.double("id", "print('0')\n")
        result = self.run_installer()
        self.assert_refused(result)
        self.assertIn("without sudo", result.stderr)

    def test_unsupported_platform(self):
        self.double("uname", "print('Unsupported')\n")
        self.assert_refused(self.run_installer())

    @unittest.skipUnless(os.environ.get("EMUDHRASLOP_TEST_REAL_RELEASE"), "opt-in real release download")
    def test_real_release(self):
        self.env["PATH"] = os.environ["PATH"]
        version = os.environ["EMUDHRASLOP_TEST_REAL_RELEASE"]
        for _ in range(2):
            result = self.run_installer("--version", version)
            self.assertEqual(result.returncode, 0, result.stderr)
        actual = subprocess.check_output([str(self.bin / "emudhraslop"), "version"], text=True, timeout=10)
        self.assertEqual(actual.strip(), version)


if __name__ == "__main__":
    unittest.main(verbosity=2)
