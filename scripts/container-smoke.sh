#!/bin/sh
# Run real offline checks inside bounded, nonroot test containers.
set -eu
umask 077
cd "$(dirname "$0")/.."
GO=${GO:-go}
CONTAINER_ENGINE=${CONTAINER_ENGINE:-docker}
SMOKE_IMAGES=${SMOKE_IMAGES:-'docker.io/library/python:3.11-slim docker.io/library/node:24-alpine docker.io/library/ubuntu:24.04 scratch'}
SMOKE_OUTPUT=${SMOKE_OUTPUT:-dist/container-evidence}
host_arch=$("$GO" env GOARCH)
case "$host_arch" in amd64|arm64) ;; *) echo 'Unsupported smoke architecture' >&2; exit 1;; esac
mkdir -p "$SMOKE_OUTPUT" "dist/linux-$host_arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$host_arch" "$GO" build -trimpath \
  -o "dist/linux-$host_arch/emudhraslop" ./cmd/emudhraslop
context=$(mktemp -d "${TMPDIR:-/tmp}/emudhraslop-container.XXXXXX")
trap 'rm -rf "$context"' EXIT HUP INT TERM
cp "dist/linux-$host_arch/emudhraslop" "$context/emudhraslop"
cat > "$context/Dockerfile" <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY --chmod=0555 emudhraslop /usr/local/bin/emudhraslop
COPY --chmod=0444 services.json /etc/emudhraslop/services.json
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/emudhraslop"]
DOCKERFILE
index=0
for base in $SMOKE_IMAGES; do
  index=$((index + 1))
  case "$base" in
    *python*) kind=python; client=stdlib; executable=/usr/local/bin/python3;;
    *node*) kind=node; client=https; executable=/usr/local/bin/node;;
    *) kind=unsupported; client=custom; executable=/usr/local/bin/missing-client;;
  esac
  # Fixture parameters come from this case statement, never arbitrary service data.
  cat > "$context/services.json" <<JSON
{"schema_version":1,"services":[{"id":"fixture-$index","kind":"$kind","client":"$client","executable":"$executable","uid":10001,"gid":10001,"source":"container smoke fixture"}]}
JSON
  if [ "$base" != scratch ]; then
    if ! "$CONTAINER_ENGINE" pull "$base" > "$SMOKE_OUTPUT/$index-pull.log" 2>&1; then
      cat "$SMOKE_OUTPUT/$index-pull.log" >&2
      exit 1
    fi
  fi
  image="localhost/emudhraslop-smoke:fixture-$index"
  if ! "$CONTAINER_ENGINE" build --build-arg "BASE_IMAGE=$base" -t "$image" "$context" \
    > "$SMOKE_OUTPUT/$index-build.log" 2>&1; then
    cat "$SMOKE_OUTPUT/$index-build.log" >&2
    exit 1
  fi
  "$CONTAINER_ENGINE" image inspect "$image" > "$SMOKE_OUTPUT/$index-image.json"
  if [ "$base" != scratch ]; then
    "$CONTAINER_ENGINE" image inspect "$base" > "$SMOKE_OUTPUT/$index-base-image.json"
  fi
  code=0
  "$CONTAINER_ENGINE" run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m "$image" \
    check --offline --services /etc/emudhraslop/services.json --timeout 60s \
    --no-cache --json \
    > "$SMOKE_OUTPUT/$index-report.json" 2> "$SMOKE_OUTPUT/$index-stderr.log" || code=$?
  python3 - "$SMOKE_OUTPUT/$index-report.json" "$code" "$kind" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
code = int(sys.argv[2])
assert code in (0, 2, 3), ("fatal scanner exit", code)
assert report["schema_version"] == 1
assert report["status"] in ("affected", "not_affected", "unknown")
assert report["container"] is True, "container context was not recorded"
assert report["results"], "declared fixture silently omitted"
assert any(row["uid"] == 10001 for row in report["results"])
assert all(row["status"] == "unknown" for row in report["results"]), report
assert report["affected"] is None
assert all(row["affected"] is None for row in report["results"])
assert code == 3, "offline Python/Node/unsupported fixtures must remain unknown"
assert "cache_write_failed" not in report["errors"], report["errors"]
if sys.argv[3] in ("python", "node"):
    target = next(row for row in report["results"] if row["id"].startswith("fixture-"))
    assert target.get("runtime_version"), "the native runtime was not invoked"
    assert target["reason"] == "offline_native_policy_not_proven", target
PYTHON
  printf '%s: report validated, exit %s\n' "$base" "$code"
done
