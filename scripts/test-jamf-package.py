#!/usr/bin/env python3
"""Build/expand a real local Jamf package; never install it or load a daemon."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GO = os.environ.get("GO", "go")


def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=180, **kwargs)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result


def check_ea(binary, directory):
    private = directory / "private"
    private.mkdir(mode=0o700)
    manifest = private / "services.json"
    cache = private / "status.json"
    manifest.write_text(json.dumps({"schema_version": 1, "services": [{
        "id": "declared-disabled", "kind": "node", "executable": str(binary),
        "environment": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}]}))
    manifest.chmod(0o600)
    scanned = subprocess.run([str(binary), "check", "--offline", "--services",
                              str(manifest), "--cache", str(cache), "--json"],
                             text=True, capture_output=True, timeout=30)
    assert scanned.returncode == 2, scanned.stderr
    report = json.loads(scanned.stdout)
    assert report["errors"] == [], report["errors"]
    # Relocate only fixed installation paths. The actual scanner and extension
    # script execute unchanged; there is no substitute for observation logic.
    ea = (ROOT / "scripts/jamf-extension-attribute.sh").read_text()
    assert ea.count("/Library/Emudhraslop/bin/emudhraslop") == 1
    assert ea.count("/Library/Application Support/Emudhraslop/status.json") == 1
    ea = ea.replace("/Library/Emudhraslop/bin/emudhraslop", str(binary))
    ea = ea.replace("/Library/Application Support/Emudhraslop/status.json", str(cache))
    script = directory / "extension.sh"
    script.write_text(ea)
    assert run(["/bin/sh", str(script)]).stdout == "<result>observed_affected</result>\n"
    observation = json.loads(run([str(binary), "observation", "--cache", str(cache), "--json"]).stdout)
    assert observation["last_observed_status"] == "affected"
    assert observation["current_status"] == "unknown"
    assert observation["observed_at"] == report["scan_time"]
    cache.chmod(0o644)
    assert run(["/bin/sh", str(script)]).stdout == "<result>unknown</result>\n"
    cache.chmod(0o600)
    cache.write_text('{"status":"not_affected"}')
    assert run(["/bin/sh", str(script)]).stdout == "<result>unknown</result>\n"
    cache.unlink()
    assert run(["/bin/sh", str(script)]).stdout == "<result>unknown</result>\n"


def main():
    if sys.platform != "darwin":
        print("Jamf package test requires macOS; no package built")
        return
    # Resolve macOS /var symlinks so the real private-cache boundary is tested.
    with tempfile.TemporaryDirectory(prefix="emudhraslop-jamf-") as temporary:
        directory = Path(temporary).resolve()
        directory.chmod(0o700)
        source = directory / "source"
        for relative in ["scripts/build-jamf-package.sh", "scripts/write-checksums.sh",
                         "examples/jamf/io.emudhraslop.scan.plist"]:
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        version = "0.3.0"
        for arch, swift_arch in [("amd64", "x86_64"), ("arm64", "arm64")]:
            output = source / "dist" / ("darwin-" + arch)
            output.mkdir(parents=True)
            env = dict(os.environ, CGO_ENABLED="0", GOOS="darwin", GOARCH=arch)
            run([GO, "build", "-trimpath", "-ldflags",
                 "-X github.com/cowsecurity/emudhraslop/internal/app.Version=" + version,
                 "-o", str(output / "emudhraslop"), "./cmd/emudhraslop"], cwd=ROOT, env=env)
            run(["/usr/bin/xcrun", "swiftc", "-O", "-target",
                 swift_arch + "-apple-macosx13.0", str(ROOT / "internal/probe/apple_helper.swift"),
                 "-o", str(output / "emudhraslop-sectrust")])
        manifest = directory / "reviewed-services.json"
        manifest.write_text(json.dumps({"schema_version": 1, "services": [{
            "id": "declared", "kind": "node", "client": "tls",
            "executable": "/reviewed/machine/path/node", "uid": 501, "gid": 20}]}))
        manifest.chmod(0o600)
        env = dict(os.environ, VERSION=version, SERVICES_FILE=str(manifest),
                   SIGNING_IDENTITY="", INSTALLER_IDENTITY="", PYTHON=sys.executable)
        # Parent shell settings cannot turn a test package into a deployment.
        env.pop("SCAN_MODE", None)
        for mode in ["online", "offline"]:
            selected = dict(env)
            if mode == "offline":
                selected["SCAN_MODE"] = mode
            run(["/bin/sh", "scripts/build-jamf-package.sh"], cwd=source, env=selected)
            expanded = directory / ("expanded-" + mode)
            run(["/usr/sbin/pkgutil", "--expand-full", str(source / "dist" /
                 ("emudhraslop-" + version + ".pkg")), str(expanded)])
            plists = list(expanded.rglob("io.emudhraslop.scan.plist"))
            assert len(plists) == 1, plists
            plist = plistlib.loads(plists[0].read_bytes())
            assert "--" + mode in plist["ProgramArguments"]
            assert "--allow-root-probes" not in plist["ProgramArguments"]
            assert plist["StartInterval"] == 21600
            assert not list(expanded.rglob("postinstall")), "package must not load daemon"
            binaries = [p for p in expanded.rglob("emudhraslop") if p.is_file()]
            assert len(binaries) == 1, binaries
            binary = binaries[0]
            assert set(run(["/usr/bin/lipo", "-archs", str(binary)]).stdout.split()) == {"x86_64", "arm64"}
            assert binary.stat().st_mode & 0o777 == 0o555
            installed_manifests = list(expanded.rglob("services.json"))
            assert len(installed_manifests) == 1
            installed = installed_manifests[0]
            assert installed.read_bytes() == manifest.read_bytes()
            assert installed.stat().st_mode & 0o777 == 0o600
            assert installed.parent.stat().st_mode & 0o777 == 0o700
            assert run([str(binary), "version"]).stdout.strip() == version
            if mode == "online":
                check_ea(binary, directory)
        for mode in ["invalid", "online; touch forbidden"]:
            denied = subprocess.run(["/bin/sh", "scripts/build-jamf-package.sh"],
                                    cwd=source, env=dict(env, SCAN_MODE=mode),
                                    capture_output=True, text=True, timeout=10)
            assert denied.returncode != 0
        manifest.write_text('{"schema_version":')
        denied = subprocess.run(["/bin/sh", "scripts/build-jamf-package.sh"],
                                cwd=source, env=env, capture_output=True, text=True, timeout=10)
        assert denied.returncode != 0
        print("Jamf online/offline packages expanded; native observation and EA boundaries verified")


if __name__ == "__main__":
    main()
