# Run inside the application container

Download and extract the Linux [release archive](releases.md) matching the image architecture: amd64, arm64, or ARM v7. For a source build, use `make release` and select the binary from the matching `dist/linux-*` directory. Copy it into the image that contains the application, runtimes, trust stores, and service configuration. The checker is static; Python, Node, curl, or OpenSSL remain the image's own programs.

```dockerfile
FROM your-application@sha256:REPLACE_WITH_APPROVED_DIGEST
COPY --chmod=0555 emudhraslop /usr/local/bin/emudhraslop
COPY services.json /etc/emudhraslop/services.json
USER 10001:10001
```

Run through the existing container engine or orchestrator:

```sh
docker exec application /usr/local/bin/emudhraslop check \
  --offline --services /etc/emudhraslop/services.json --no-cache --json
kubectl exec deployment/application -- /usr/local/bin/emudhraslop check \
  --offline --services /etc/emudhraslop/services.json --no-cache --json
```

For an image with a Python project, a manifest is optional for checking defaults:

```sh
docker exec application /usr/local/bin/emudhraslop check \
  --online --project /app --agent
```

Use `--services` to reproduce explicit CA settings and choose a particular HTTP client. Python project discovery covers the selected root and `.venv`, `venv`, and `env`, with stdlib, Requests, HTTPX, Botocore, urllib3, and aiohttp checks. Managed Node discovery checks TLS, HTTPS, and built-in fetch. Missing packages stay unknown; the scan never installs them.

The service manifest must describe this image and user. Set its executable and CA paths to paths inside the container. Record the deployed immutable image digest from your deployment system. Reports assess client configurations and always retain `application_status: unknown`; no running application or listening port is tested. The checker does not need a mounted host filesystem, Docker socket, privileged mode, Linux capabilities, or access to another container's namespace.

## Root and filesystem rules

Prefer the application's nonroot identity. A root scan does not execute discovered programs by default. An explicit target UID/GID lets the scanner drop privileges; `--allow-root-probes` permits only reviewed, trusted managed paths and should be reserved for services that actually run as root. Do not run a user-owned virtual environment as root just to collect a result.

Use a writable temporary directory for native subprocess work. Reports can go to stdout on a read-only root filesystem with `--no-cache`. This option does not remove the native probe's temporary-directory requirement. If caching is needed, provide `--cache /tmp/emudhraslop-cache/status.json` on a private writable directory owned by the scanning identity. An unavailable cache is reported as an error. `--no-cache` cannot be combined with `--cache` or `--cached`. Do not mount a host trust store into the container: that changes what you are measuring.

## Build stages and minimal images

Check build stages independently when package installation, dependency downloads, or compilation use TLS. A final image can have different CAs and runtimes from its builder. Check the final deployed image again after rebuilding.

Scratch/distroless images can execute the static Linux binary if the image permits it, but may lack native verifier programs, CA files, a writable temporary directory, or the declared runtime. Those gaps produce unknown. Copying in a verifier from another image can change trust behavior and does not prove the original application's status.

Default offline checks do not need network access. Use online checks only where egress to the incident hosts and clean control is permitted. Proxy or interception behavior may differ from production requests; an ambiguous result stays unknown.

## Reproducible smoke checks

```sh
GO=go CONTAINER_ENGINE=podman ./scripts/container-smoke.sh
```

The smoke script copies a Linux binary and fixture manifest into each test image, runs as UID/GID 10001 with network disabled, validates JSON and exit semantics, and checks that unsupported/minimal contexts remain unknown. It uses no host mounts or socket inside the test containers. Test images are fixture inputs; the script records their resolved image identities. It does not claim that these fixtures establish application coverage.

`make test-root-containers` separately executes compiled boundary tests as container root, including real UID/GID drops, denied fixture mutation, private cache behavior, and nonblocking FIFO rejection. It grants only the Linux capabilities needed for those identity/filesystem tests and uses private temporary filesystems.

Use `SMOKE_IMAGES` to select base images and `SMOKE_OUTPUT` for evidence location. The default fixtures exercise Debian-based Python, Alpine-based Node, minimal Ubuntu, and scratch. The latter images test binary portability and honest unknown handling, not a native TLS verifier. The test script selects Python or Node fixture configuration from the image reference containing `python` or `node`; other references exercise the unsupported-client path. This is test-fixture selection, not application discovery. Existing local images can be supplied for offline testing. Image pulls and build-time package acquisition are separate from the checker, which never installs packages.
