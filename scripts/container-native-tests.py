#!/usr/bin/env python3
"""Run native TLS adapters in application images without public scan egress."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid


ROOT = Path(__file__).resolve().parent.parent
GO = os.environ.get("GO", "go")
ENGINE = os.environ.get("CONTAINER_ENGINE", "docker")
OUTPUT = Path(os.environ.get("NATIVE_TEST_OUTPUT", "dist/container-native-evidence"))
IMAGES = os.environ.get(
    "NATIVE_TEST_IMAGES",
    "docker.io/library/python:3.11-slim docker.io/library/python:3.14-slim "
    "docker.io/library/node:22-bookworm-slim docker.io/library/node:24-alpine",
).split()
TRUST_TEST = "TestNativeRuntimeRequiresTrustedPeerAndReturnsExactCertificate"
OFFLINE_TEST = "TestOfflineNativeEvidenceCannotBecomeProtection"
PYTHON_TEST = "TestPythonClientsVerifyActualConnection"
FETCH_TESTS = (
    "TestNodeFetchRequiresItsOwnAuthorizedPeer",
    "TestNodeFetchDoesNotBorrowAnotherRequestsSocket",
    "TestNodeFetchMissingAPIAndPerRequestCAStayUnknown",
    "TestNodeFetchTimeoutRemainsUnknown",
    "TestNodeTrustOptionsAgreeAtAllBoundaries",
)


def execute(arguments, log, *, timeout=180, env=None):
    """Bound each operation; keep diagnostics on disk rather than in memory."""
    with log.open("wb") as output:
        try:
            subprocess.run(arguments, cwd=ROOT, env=env, stdout=output,
                           stderr=subprocess.STDOUT, timeout=timeout, check=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            with log.open("rb") as source:
                source.seek(max(0, log.stat().st_size - 8192))
                print(source.read().decode("utf-8", errors="replace"))
            raise


def validate(log, kind):
    clients = ("stdlib", "requests", "httpx", "botocore", "urllib3", "aiohttp") \
        if kind == "python" else ("tls", "https")
    output = log.read_text(encoding="utf-8")
    if "--- SKIP:" in output:
        raise AssertionError(f"native coverage skipped: {log}")
    required = [f"{PYTHON_TEST}/{client}" if kind == "python"
                else f"{TRUST_TEST}/{kind}/{client}" for client in clients]
    required.append(f"{OFFLINE_TEST}/{kind}")
    if kind == "node":
        required.extend(FETCH_TESTS)
    else:
        required.append("TestRequestsDoesNotDrainRedirectBody")
        required.extend(f"TestPythonClientsRetainUnknownOnMissingPackages/{client}"
                        for client in clients if client != "stdlib")
        required.extend(f"TestPythonHTTPFailuresCannotSupplyAcceptance/{client}"
                        for client in clients if client != "stdlib")
        required.extend(f"TestPythonCADirectoryActuallyContributesTrust/{client}"
                        for client in clients if client != "botocore")
        required.extend(f"TestPythonNewClientsLoadBothDeclaredCASources/{client}"
                        for client in ("urllib3", "aiohttp"))
    for name in required:
        if f"--- PASS: {name} (" not in output:
            raise AssertionError(f"native case did not execute: {name} in {log}")
    return required


def main():
    os.chdir(ROOT)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    # A failed rerun must not leave the previous success marker looking current.
    (OUTPUT / "verification.json").unlink(missing_ok=True)
    arch = subprocess.check_output([GO, "env", "GOARCH"], timeout=15,
                                   text=True).strip()
    if arch not in ("amd64", "arm64"):
        raise ValueError("native container tests require amd64 or arm64")
    if not IMAGES:
        raise ValueError("NATIVE_TEST_IMAGES must not be empty")
    evidence = []
    with tempfile.TemporaryDirectory(prefix="emudhraslop-native-") as directory:
        context = Path(directory)
        environment = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=arch)
        execute([GO, "test", "-c", "-o", str(context / "probe.test"),
                 "./internal/probe"], OUTPUT / "compile.log", env=environment)
        shutil.copyfile(ROOT / "tests/python-requirements.txt", context / "requirements.txt")
        for index, base in enumerate(IMAGES, start=1):
            # Explicit families avoid claiming adapter coverage in an arbitrary image.
            family = base.split("/")[-1].split(":")[0]
            if family not in ("python", "node"):
                raise ValueError(f"unsupported native test image family: {base}")
            prefix = OUTPUT / str(index)
            install = ("COPY requirements.txt /opt/requirements.txt\n"
                       "RUN python -m venv /opt/application-venv && "
                       "/opt/application-venv/bin/python -m pip install "
                       "--no-cache-dir --disable-pip-version-check -r /opt/requirements.txt\n"
                       "ENV EMUDHRASLOP_TEST_PYTHON=/opt/application-venv/bin/python\n") \
                if family == "python" else ""
            (context / "Dockerfile").write_text(
                "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n" + install +
                "COPY --chmod=0555 probe.test /opt/probe.test\n"
                "USER 10001:10001\nENV HOME=/tmp\n"
                'ENTRYPOINT ["/opt/probe.test"]\n', encoding="utf-8")
            image = f"localhost/emudhraslop-native-tests:{uuid.uuid4().hex}"
            container = "emudhraslop-native-" + uuid.uuid4().hex
            try:
                execute([ENGINE, "pull", base], prefix.with_suffix(".pull.log"), timeout=300)
                execute([ENGINE, "build", "--build-arg", "BASE_IMAGE=" + base,
                         "-t", image, str(context)], prefix.with_suffix(".build.log"), timeout=600)
                execute([ENGINE, "image", "inspect", image], prefix.with_suffix(".image.json"))
                execute([ENGINE, "image", "inspect", base], prefix.with_suffix(".base-image.json"))
                selection = (f"^(TestPython.*|TestRequestsDoesNotDrainRedirectBody|{OFFLINE_TEST})$/^(stdlib|requests|httpx|botocore|urllib3|aiohttp|python)$"
                             if family == "python" else
                             f"^({TRUST_TEST}|{OFFLINE_TEST}|{'|'.join(FETCH_TESTS)})$/node")
                log = prefix.with_suffix(".tests.log")
                execute([ENGINE, "run", "--rm", "--name", container, "--network", "none",
                         "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                         "--pids-limit", "64", "--memory", "384m", "--cpus", "1",
                         "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777", image,
                         "-test.v", "-test.timeout=90s", "-test.run", selection], log, timeout=120)
                passed = validate(log, family)
                evidence.append({"base_image": base, "architecture": arch, "passed": passed})
                print(f"{base}: native trusted/rejected TLS and offline checks passed without skips")
            finally:
                # On client timeout the daemon may still own the container. Remove only ours.
                subprocess.run([ENGINE, "rm", "-f", container], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30, check=False)
                subprocess.run([ENGINE, "image", "rm", image], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30, check=False)
    (OUTPUT / "verification.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
