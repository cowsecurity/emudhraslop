# emudhraslop

Check whether a TLS client trusts certificates involved in the [eMudhra incident](https://emudhra.we-have-a-problem.com/). Runs on macOS, Linux, Windows, and inside containers. It uses the installed client's verifier and does not change trust stores or install updates.

## Get it

[Download a release](https://github.com/cowsecurity/emudhraslop/releases/latest) for your OS and CPU. [Installation instructions](docs/releases.md) include download commands, checksum verification, and extraction for each platform.

- **macOS:** Intel or Apple Silicon. Keep `emudhraslop-sectrust` beside `emudhraslop`.
- **Linux / containers:** x64, ARM64, or ARMv7. Use the container image's architecture.
- **Windows:** x64 or ARM64. Use `emudhraslop.exe` in a non-Administrator PowerShell window.

The repository is currently private; downloads require GitHub access. Mac and Windows binaries are unsigned.

## First check

Run from the extracted directory as your normal user:

```sh
./emudhraslop version
./emudhraslop check --online --no-cache
```

On Windows:

```powershell
.\emudhraslop.exe version
.\emudhraslop.exe check --online --no-cache
```

This discovers supported runtimes in managed locations and on `PATH`, then checks them. `--online` contacts fixed public incident test hosts and a clean control. Add `--json` for machine-readable output. Use `--offline` instead if network calls are not permitted; offline checks often return `unknown`.

To list discovered runtimes without testing them:

```sh
./emudhraslop inventory --no-cache --json
```

Discovery does not cover every app, virtual environment, or service. It cannot return a whole-machine all-clear. Use a service file for the configurations you need to assess.

## Read the result

| Status | Meaning | What to do | Exit code |
| --- | --- | --- | --- |
| `affected` | A tested client accepted an incident certificate, or its declared settings disable verification | Remediate that client's trust settings or dependencies, then rerun | 2 |
| `not_affected` | The declared configuration passed the supported negative checks | Keep the report; reassess after configuration changes | 0 |
| `unknown` | The available checks could not establish either answer | Read the result's `reason` and `next_action`; fill the gap and rerun | 3 |

Check exit codes are **2** for affected, **0** for not affected, **3** for unknown, and **1** for invalid input or a fatal failure. If one context is affected and another is unknown, the overall result is affected; both remain in the report.

**`not_affected` currently requires an explicitly declared OpenSSL 3 configuration using one exclusive CA file.** Other clients can confirm affected status, but a rejected connection alone does not prove they are unaffected. The result applies to the tested configuration, not every service on the machine. See [supported checks](docs/coverage.md) and [negative-proof requirements](docs/negative-proof.md).

## Check an application

Create `services.json` with the application's actual runtime and TLS client. This example checks Python Requests and Node HTTPS; replace the paths and remove entries you do not use:

```json
{
  "schema_version": 1,
  "services": [
    {
      "id": "api-requests",
      "kind": "python",
      "client": "requests",
      "executable": "/srv/api/.venv/bin/python"
    },
    {
      "id": "worker-https",
      "kind": "node",
      "client": "https",
      "executable": "/usr/local/bin/node"
    }
  ]
}
```

Run as the application user:

```sh
./emudhraslop check --online --services services.json --no-cache --json
```

Use the Python executable from the application's virtual environment so the check loads its installed libraries. For Windows, use absolute JSON paths such as `"C:\\apps\\api\\.venv\\Scripts\\python.exe"`. The service-file path itself must also be absolute:

```powershell
.\emudhraslop.exe check --online --services "$((Get-Location).Path)\services.json" --no-cache --json
```

If the application explicitly passes a CA file to its client, set `"ca_bundle": "/etc/company/ca.pem"`. For Node, this replaces the default CA list. If Node instead extends its defaults using `NODE_EXTRA_CA_CERTS`, declare `"environment": {"NODE_EXTRA_CA_CERTS": "/etc/company/ca.pem"}`. For Requests configured through the environment, use `"environment": {"REQUESTS_CA_BUNDLE": "/etc/company/ca.pem"}`. Copy the application's actual settings; a service-file scan does not inherit the shell's trust overrides. Do not include tokens or passwords. Custom TLS contexts created inside application code need a separate assessment.

Omitting `uid` and `gid` uses the current account. For Unix services that require a different identity, see [container identity rules](docs/containers.md#root-and-filesystem-rules). Windows supports only the current non-elevated account. [Example manifests](examples/) cover additional configurations.

## Check a container

Extract the matching Linux release and copy the binary and service file into the **application image**:

```dockerfile
# Add these before the application's final USER instruction.
COPY --chmod=0555 emudhraslop /usr/local/bin/emudhraslop
COPY services.json /etc/emudhraslop/services.json
# Keep the application's existing nonroot USER.
```

Rebuild and deploy through your normal process. The manifest's executable and CA paths must exist inside that image. Run in the application container as its usual user:

```sh
docker exec application /usr/local/bin/emudhraslop check \
  --online --services /etc/emudhraslop/services.json --no-cache --json
```

For Kubernetes, replace the deployment and container names:

```sh
kubectl exec deployment/application -c app -- /usr/local/bin/emudhraslop check \
  --online --services /etc/emudhraslop/services.json --no-cache --json
```

Use `--offline` where egress is unavailable. Native checks need a writable temporary directory, even with `--no-cache`. The checker needs no Docker socket or host mounts. A separate scanner container measures its own runtimes and trust stores. Minimal images without a supported native verifier return `unknown`. See [container details](docs/containers.md).

## Use from an agent or CI job

Use `--json --no-cache`. The CLI never prompts. Capture the exit code before processing the report:

```sh
umask 077
code=0
./emudhraslop check --online --services services.json --no-cache --json \
  > report.json || code=$?
case "$code" in
  0) echo 'Declared configuration is not affected' ;;
  2) echo 'Affected configuration found' ;;
  3) echo 'Could not confirm; review report.json' ;;
  *) echo 'Check failed; inspect stderr' >&2 ;;
esac
exit "$code"
```

This is a script for a CI step; its final line preserves the scan outcome. JSON has `schema_version`, overall `status`, nullable `affected`, and per-client `results` with `reason` and `next_action`. Validate against the [report schema](docs/report.schema.json) before making an automated decision. `affected: null` means unknown; never convert it to `false`. Keep per-client results even when the overall status is affected.

See [agent integration](docs/agents.md) for validation and timeout handling, or [Jamf integration](docs/jamf.md) for scheduled Mac scans and cached inventory attributes.

## Build from source

With Go 1.27.3:

```sh
make build
./dist/emudhraslop version
make test
```

For macOS native trust checks, use the release archive with its bundled helper, or build it on a Mac with Swift using `make release VERSION=0.1.0`. See [release builds](docs/releases.md#build-archives) for prerequisites and target selection.

[Security design](docs/security.md) documents probe isolation and input handling. Embedded incident fixtures contain public certificates only.
