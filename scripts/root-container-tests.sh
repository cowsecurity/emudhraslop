#!/bin/sh
# Exercise privileged production boundaries in an isolated Linux container.
set -eu
umask 077
cd "$(dirname "$0")/.."
GO=${GO:-go}
CONTAINER_ENGINE=${CONTAINER_ENGINE:-docker}
ROOT_TEST_BASE=${ROOT_TEST_BASE:-docker.io/library/python:3.11-slim}
ROOT_TEST_OUTPUT=${ROOT_TEST_OUTPUT:-dist/root-container-evidence}
host_arch=$("$GO" env GOARCH)
case "$host_arch" in amd64|arm64) ;; *) echo 'Unsupported test architecture' >&2; exit 1;; esac
mkdir -p "$ROOT_TEST_OUTPUT"
context=$(mktemp -d "${TMPDIR:-/tmp}/emudhraslop-root-tests.XXXXXX")
trap 'rm -rf "$context"' EXIT HUP INT TERM
for package in run probe cache; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$host_arch" "$GO" test -c \
    -o "$context/$package.test" "./internal/$package"
done
cat > "$context/Dockerfile" <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY --chmod=0555 run.test probe.test cache.test /opt/emudhraslop-tests/
USER 0:0
ENV TMPDIR=/var/lib/emudhraslop-tests
ENTRYPOINT ["/bin/sh", "-eu", "-c"]
DOCKERFILE
if ! "$CONTAINER_ENGINE" pull "$ROOT_TEST_BASE" > "$ROOT_TEST_OUTPUT/pull.log" 2>&1; then
  cat "$ROOT_TEST_OUTPUT/pull.log" >&2
  exit 1
fi
image="localhost/emudhraslop-root-tests:fixture"
if ! "$CONTAINER_ENGINE" build --build-arg "BASE_IMAGE=$ROOT_TEST_BASE" -t "$image" "$context" \
  > "$ROOT_TEST_OUTPUT/build.log" 2>&1; then
  cat "$ROOT_TEST_OUTPUT/build.log" >&2
  exit 1
fi
"$CONTAINER_ENGINE" image inspect "$image" > "$ROOT_TEST_OUTPUT/image.json"
"$CONTAINER_ENGINE" image inspect "$ROOT_TEST_BASE" > "$ROOT_TEST_OUTPUT/base-image.json"
for package in run probe cache; do
  case "$package" in
    run) selection='.';;
    probe) selection='^(TestRootNativeFixtureParentIsNotWritableByDroppedIdentity|TestNativeWriteCannotFollowOrReplaceExistingFixture|TestOpenSSL3DroppedIdentityCannotGainTrustFileAccessThroughSnapshot|TestRootPython.*)$';;
    cache) selection='.';;
  esac
  if ! "$CONTAINER_ENGINE" run --rm --network none --read-only --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    --tmpfs /var/lib/emudhraslop-tests:rw,nosuid,nodev,noexec,size=32m,mode=0700 \
    "$image" 'test "$(id -u)" = 0; exec "$1" -test.v -test.timeout=45s -test.run "$2"' \
    sh "/opt/emudhraslop-tests/$package.test" "$selection" \
    > "$ROOT_TEST_OUTPUT/$package.log" 2>&1; then
    cat "$ROOT_TEST_OUTPUT/$package.log" >&2
    exit 1
  fi
done
python3 - "$ROOT_TEST_OUTPUT" <<'PYTHON'
import pathlib, sys
directory = pathlib.Path(sys.argv[1])
required = {
    "run": ["TestRootAndOtherExecutionIdentitiesRequireExplicitAuthority",
            "TestRootDropsToExplicitServiceUIDGIDAndClearsSupplementaryGroups",
            "TestRequestedGroupCannotSilentlyUseInheritedGroup"],
    "probe": ["TestRootNativeFixtureParentIsNotWritableByDroppedIdentity",
              "TestNativeWriteCannotFollowOrReplaceExistingFixture",
              "TestOpenSSL3DroppedIdentityCannotGainTrustFileAccessThroughSnapshot",
              "TestRootPythonCannotBypassDenialWithTrustedPathsOrAllowRoot",
              "TestRootPythonHostileVenvStartupIsNeverExecuted",
              "TestRootPythonExplicitNonrootIdentityStillExecutes"],
    "cache": ["TestPrivateRoundTripAndStoreMutation",
              "TestTrustSourceReplacedByFIFOIsRejectedWithoutBlocking"],
}
for package, names in required.items():
    output = (directory / (package + ".log")).read_text()
    assert "--- SKIP:" not in output, (package, "root boundary test skipped")
    for name in names:
        assert "--- PASS: " + name + " (" in output, (package, name, "did not execute")
print("Actual-root identity, fixture, and cache boundaries executed without skips")
PYTHON
