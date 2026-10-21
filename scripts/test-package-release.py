#!/usr/bin/env python3
"""Boundary checks for release inputs and archive assembly, without extracting files."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location("package_release", Path(__file__).with_name("package-release.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def test_version_and_target_boundaries(self):
        for version in ["0.1.0", "1.2.3-rc.1", "1.2.3+build.4"]:
            package.configuration(version, ["linux/amd64"])
        for version in ["v0.1.0", "01.2.3", "1.2.3-01", "../1.2.3", "1.2.3\n", "1.2.3;id"]:
            with self.assertRaises(ValueError):
                package.configuration(version, ["linux/amd64"])
        for targets in [[], ["linux/amd64", "linux/amd64"], ["linux/../../secret"], ["linux/386"]]:
            with self.assertRaises(ValueError):
                package.configuration("1.2.3", targets)

    def test_binary_header_architecture_and_truncation(self):
        elf = bytearray(20)
        elf[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", elf, 18, 62)
        self.assertTrue(package.binary_matches(elf, "linux/amd64"))
        self.assertFalse(package.binary_matches(elf, "linux/arm64"))
        self.assertFalse(package.binary_matches(elf[:19], "linux/amd64"))
        pe = bytearray(80)
        pe[:2] = b"MZ"
        struct.pack_into("<I", pe, 60, 64)
        pe[64:68] = b"PE\0\0"
        struct.pack_into("<H", pe, 68, 0xAA64)
        self.assertTrue(package.binary_matches(pe, "windows/arm64"))
        self.assertFalse(package.binary_matches(pe, "windows/amd64"))
        struct.pack_into("<I", pe, 60, 0xFFFFFFFF)
        self.assertFalse(package.binary_matches(pe, "windows/arm64"))

    def test_payload_is_allowlisted_and_symlinks_rejected(self):
        original_root = package.ROOT
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                package.ROOT = root
                for document in package.DOCUMENTS:
                    path = root / document
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("release documentation\n")
                directory = root / "dist/linux-amd64"
                directory.mkdir(parents=True)
                elf = bytearray(20)
                elf[:6] = b"\x7fELF\x02\x01"
                struct.pack_into("<H", elf, 18, 62)
                (directory / "emudhraslop").write_bytes(elf)
                (root / "secret-token").write_text("must not be published")
                payload = package.payload("1.2.3", "linux/amd64")
                self.assertNotIn("secret-token", payload)
                manifest = json.loads(payload["RELEASE-MANIFEST.json"][0])
                self.assertEqual(manifest["target"], "linux/amd64")
                self.assertEqual(set(manifest["files"]), set(payload) - {"RELEASE-MANIFEST.json"})
                binary = directory / "emudhraslop"
                binary.unlink()
                binary.symlink_to(root / "secret-token")
                with self.assertRaises(ValueError):
                    package.payload("1.2.3", "linux/amd64")
                darwin = root / "dist/darwin-arm64"
                darwin.mkdir()
                (darwin / "emudhraslop").write_bytes(b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x0100000C))
                with self.assertRaises(ValueError):
                    package.payload("1.2.3", "darwin/arm64")
        finally:
            package.ROOT = original_root

    def test_existing_archive_is_not_replaced(self):
        original_root = package.ROOT
        try:
            with tempfile.TemporaryDirectory() as temporary:
                package.ROOT = Path(temporary)
                destination = package.ROOT / "dist/releases"
                destination.mkdir(parents=True)
                archive = destination / "emudhraslop-1.2.3-linux-amd64.tar.gz"
                archive.write_bytes(b"published bytes")
                with mock.patch.dict(os.environ, {"VERSION": "1.2.3", "TARGETS": "linux/amd64"}):
                    with mock.patch("sys.argv", ["package-release.py"]):
                        with self.assertRaises(ValueError):
                            package.main()
                self.assertEqual(archive.read_bytes(), b"published bytes")
        finally:
            package.ROOT = original_root

    def test_archives_have_stable_content_modes_and_paths(self):
        contents = {"emudhraslop": (b"binary fixture", 0o555), "docs/agents.md": (b"docs", 0o444)}
        with tempfile.TemporaryDirectory() as temporary:
            for suffix in [".tar.gz", ".zip"]:
                first, second = Path(temporary) / ("a" + suffix), Path(temporary) / ("b" + suffix)
                package.write_archive(first, contents)
                package.write_archive(second, contents)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                if suffix == ".zip":
                    with zipfile.ZipFile(first) as archive:
                        self.assertEqual(set(archive.namelist()), set(contents))
                        self.assertEqual(archive.read("emudhraslop"), b"binary fixture")
                        self.assertEqual((archive.getinfo("emudhraslop").external_attr >> 16) & 0o777, 0o555)
                else:
                    with tarfile.open(first) as archive:
                        self.assertEqual(set(archive.getnames()), set(contents))
                        self.assertTrue(all(item.isfile() for item in archive))
                        self.assertEqual(archive.getmember("emudhraslop").mode, 0o555)


if __name__ == "__main__":
    unittest.main()
