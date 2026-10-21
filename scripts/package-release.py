#!/usr/bin/env python3
"""Assemble versioned, deterministic release archives without installing anything."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64",
    "linux/arm/v7", "windows/amd64", "windows/arm64",
}
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
DOCUMENTS = [
    "README.md", "docs/agents.md", "docs/report.schema.json", "docs/coverage.md",
    "docs/negative-proof.md", "docs/security.md", "docs/releases.md",
    "examples/services.json", "examples/container-services.json",
    "examples/openssl-exclusive-services.json", "docs/windows.md",
]


def configuration(version, targets):
    if len(version) > 128 or not SEMVER.fullmatch(version):
        raise ValueError("VERSION must be SemVer without a leading v")
    if not targets or len(targets) != len(set(targets)):
        raise ValueError("TARGETS must be a nonempty, unique list")
    if any(target not in TARGETS for target in targets):
        raise ValueError("Unsupported target in TARGETS")


def read_regular(path):
    # Never follow a source symlink into an operator's home or unrelated files.
    current = path
    while current != ROOT:
        if current.is_symlink():
            raise ValueError("Symlinked release source: " + str(path.relative_to(ROOT)))
        current = current.parent
        if current == current.parent and current != ROOT:
            raise ValueError("Release source outside repository")
    if not path.is_file():
        raise ValueError("Missing release source: " + str(path.relative_to(ROOT)))
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Release source exceeds 128 MiB")
    return path.read_bytes()


def binary_matches(data, target):
    platform, arch = target.split("/", 1)
    if platform == "linux":
        machines = {"amd64": 62, "arm64": 183, "arm/v7": 40}
        width = 1 if arch == "arm/v7" else 2
        return (len(data) >= 20 and data[:4] == b"\x7fELF" and
                data[4] == width and data[5] == 1 and
                struct.unpack_from("<H", data, 18)[0] == machines[arch])
    if platform == "darwin":
        cpu = {"amd64": 0x01000007, "arm64": 0x0100000C}[arch]
        return (len(data) >= 8 and data[:4] == b"\xcf\xfa\xed\xfe" and
                struct.unpack_from("<I", data, 4)[0] == cpu)
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", data, 60)[0]
    machine = {"amd64": 0x8664, "arm64": 0xAA64}[arch]
    return (offset + 6 <= len(data) and data[offset:offset + 4] == b"PE\0\0" and
            struct.unpack_from("<H", data, offset + 4)[0] == machine)


def payload(version, target):
    executable = "emudhraslop.exe" if target.startswith("windows/") else "emudhraslop"
    directory = ROOT / "dist" / target.replace("/", "-")
    contents = {executable: (read_regular(directory / executable), 0o555)}
    if not binary_matches(contents[executable][0], target):
        raise ValueError("Binary header does not match target: " + target)
    if target.startswith("darwin/"):
        helper = read_regular(directory / "emudhraslop-sectrust")
        if not binary_matches(helper, target):
            raise ValueError("Apple helper header does not match target: " + target)
        contents["emudhraslop-sectrust"] = (helper, 0o555)
    for name in DOCUMENTS:
        contents[name] = (read_regular(ROOT / name), 0o444)
    windows = target.startswith("windows/")
    manifest = {
        "schema_version": 1, "name": "emudhraslop", "version": version,
        "target": target, "executable": executable,
        "apple_native_helper": target.startswith("darwin/"),
        "windows_limitations": (["non-elevated execution only", "no native Windows trust adapter",
                                  "cache unavailable"] if windows else []),
        "assessment_contract": "affected / not_affected / unknown; see docs/coverage.md",
        "publisher_signed": False,
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, (data, _) in sorted(contents.items())},
    }
    contents["RELEASE-MANIFEST.json"] = ((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o444)
    return contents


def write_archive(path, contents):
    # No source directory walks: the explicit payload prevents credentials or reports leaking.
    if path.suffix == ".zip":
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, (data, mode) in sorted(contents.items()):
                member = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                member.create_system = 3
                member.external_attr = (0o100000 | mode) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, data)
    else:
        with path.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, (data, mode) in sorted(contents.items()):
                        member = tarfile.TarInfo(name)
                        member.size, member.mode, member.mtime = len(data), mode, 0
                        archive.addfile(member, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    version = os.environ.get("VERSION", "0.1.0-dev")
    targets = os.environ.get("TARGETS", "").split()
    configuration(version, targets)
    if args.validate_only:
        return
    destination = ROOT / "dist" / "releases"
    if destination.is_symlink() or (ROOT / "dist").is_symlink():
        raise ValueError("Symlinked release output directory")
    destination.mkdir(parents=True, exist_ok=True)
    staged = []
    with tempfile.TemporaryDirectory(prefix=".package-", dir=destination) as temporary:
        for target in targets:
            extension = ".zip" if target.startswith("windows/") else ".tar.gz"
            name = "emudhraslop-" + version + "-" + target.replace("/", "-") + extension
            output = destination / name
            if output.exists() or output.is_symlink():
                raise ValueError("Refusing to replace existing release archive: " + name)
            contents = payload(version, target)
            path = Path(temporary) / name
            write_archive(path, contents)
            staged.append((path, output))
        for path, output in staged:
            # Atomic create; another invocation cannot replace an existing published payload.
            os.link(path, output)
            print(output.relative_to(ROOT))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
