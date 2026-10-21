# emudhraslop

A standalone, read-only checker for the eMudhra 2026 certificate incident. It checks a declared TLS client configuration using that client's native verifier. It has no dependency on Jamf, Docker, or a cloud account.

Results use `affected`, `not_affected`, or `unknown`. The matching machine field is `affected: true`, `false`, or `null`. Findings apply to the declared TLS client configuration; they do not certify an entire machine or application.

`affected` requires native acceptance evidence or explicitly disabled verification. `not_affected` is supported for a declared OpenSSL 3 context with one exclusive CA file under the [negative-proof conditions](docs/negative-proof.md). This requires `exclusive_ca_bundle: true` to describe the service's actual policy: implicit CA directories and stores must already be disabled. Naming a CA file alone is insufficient. Generic TLS rejection, a timeout, package versions, and the checker's own TLS verifier are insufficient; incomplete assessments remain `unknown`. See [coverage](docs/coverage.md) for supported proof boundaries.

## Run

Download the archive for your platform from [GitHub Releases](https://github.com/cowsecurity/emudhraslop/releases/latest), verify it against `SHA256SUMS`, and extract it. On macOS keep `emudhraslop-sectrust` beside `emudhraslop`. Windows uses `emudhraslop.exe`. See [release platforms and installation](docs/releases.md).

Build with Go 1.27.3:

```sh
make build
./dist/emudhraslop inventory --scope managed --json
./dist/emudhraslop check --offline --services examples/services.json --json
./dist/emudhraslop check --online --services /absolute/path/services.json --json
```

Edit the example manifest to match real executable paths, clients, service users, CA configuration, and image digests. Do not put credentials in it. Online checks contact the incident test hosts and a clean control; they require deliberate `--online` selection. Default offline checks make no network requests.

The checker reports each supported context separately. Python `ssl`, Requests, HTTPX, Botocore, Node TLS/HTTPS, curl, OpenSSL, and Apple native trust have different configuration rules. See [coverage and results](docs/coverage.md) before interpreting a result. Automatic inventory cannot prove whole-machine coverage; custom apps and undeclared services remain excluded or unknown.

## Containers

Copy the Linux binary into the **actual application image** and run it as the application user:

```dockerfile
COPY --chmod=0555 emudhraslop /usr/local/bin/emudhraslop
COPY services.json /etc/emudhraslop/services.json
USER 10001:10001
```

```sh
/usr/local/bin/emudhraslop check --offline --services /etc/emudhraslop/services.json --no-cache --json
```

The binary is static and supports Linux amd64, arm64, and ARM v7. It does not need a Docker socket, host mounts, extra capabilities, or a shell. A scanner sidecar has a different trust configuration and cannot establish the application's status. Scratch and distroless images still produce an inventory/report; absent native verifiers remain `unknown`. See [container use](docs/containers.md).

## Automation

| Exit | Meaning |
| --- | --- |
| 0 | Every declared context is `not_affected`, with complete coverage and no errors |
| 1 | Invalid input or fatal failure |
| 2 | At least one affected context, even if others are unknown |
| 3 | Incomplete or unknown, with no affected context found |

Treat exit 3 as a review queue, never a successful security gate. JSON includes the checker and incident-manifest identities, scan time, configuration fingerprint, coverage, per-context evidence, and errors. Keep reports access-controlled because executable paths and service identifiers can reveal internal structure.

The CLI never prompts. Agents should use `--json --no-cache`, check `schema_version`, and handle every exit explicitly. [Agent integration](docs/agents.md) documents the contract and [JSON schema](docs/report.schema.json).

```sh
emudhraslop check --offline --services /etc/emudhraslop/services.json \
  --cache /var/lib/emudhraslop/status.json --json
emudhraslop check --cached --services /etc/emudhraslop/services.json \
  --cache /var/lib/emudhraslop/status.json --json
```

Cached reads do not run probes or use the network. They revalidate configuration and referenced file identities; a missing, stale, or invalid cache is unknown. [Jamf integration](docs/jamf.md) uses this path for inventory attributes.

## Build and verify

```sh
make test
make release VERSION=0.1.0
CONTAINER_ENGINE=podman make test-containers
CONTAINER_ENGINE=podman make test-root-containers
```

Release builds contain no third-party Go modules. Archives cover macOS on amd64/arm64, Linux on amd64/arm64/ARM v7, and Windows on amd64/arm64. A macOS build host compiles the adjacent Apple native helper, so employee machines do not need Swift. Windows supports non-elevated Python, Node, and curl contexts; Windows native trust and cache support remain unavailable. Unsupported assessments stay `unknown`.

`make release` writes versioned archives and checksums to `dist/releases`. Select platforms with `TARGETS`; a macOS host is required for Mac archives. Checksums establish artifact identity; they are not a publisher signature. macOS package signing requires an operator-supplied signing identity. Nothing here deploys to Jamf or changes a trust store.

Public incident certificates and hashes are embedded; no compromised private keys are distributed. See [security design](docs/security.md) and the [incident source](https://emudhra.we-have-a-problem.com/).

Install from source with Go 1.27.3 or newer:

```sh
go install github.com/cowsecurity/emudhraslop/cmd/emudhraslop@latest
```

For a private repository, use authenticated Git access and the appropriate Go private-module configuration, or download an archive with `gh release download --repo cowsecurity/emudhraslop`.
