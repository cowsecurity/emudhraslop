# emudhraslop

Check whether a TLS client trusts certificates involved in the [eMudhra incident](https://emudhra.we-have-a-problem.com/). Runs on macOS, Linux, Windows, and inside containers. It uses the installed client's verifier and does not change trust stores or install updates.

## Install

**macOS or Linux** — paste this into a terminal:

```sh
curl --proto '=https' --proto-redir '=https' -fsSL \
  https://github.com/cowsecurity/emudhraslop/releases/latest/download/install.sh \
  -o emudhraslop-install.sh && sh emudhraslop-install.sh &&
export PATH="$HOME/.local/bin:$PATH"
```

**Windows** — paste this into a normal PowerShell window:

```powershell
& {
  $ErrorActionPreference = 'Stop'
  Invoke-WebRequest https://github.com/cowsecurity/emudhraslop/releases/latest/download/install.ps1 -OutFile emudhraslop-install.ps1
  & .\emudhraslop-install.ps1
  $env:PATH = "$env:LOCALAPPDATA\emudhraslop\bin;$env:PATH"
}
```

The installer selects your OS and CPU, checks the download's SHA-256, and installs for your account. No GitHub login, Go, Python, or administrator access is needed. It prints the exact command to run next. The snippets add the install directory to this terminal session's `PATH`; the absolute commands below also work in a new terminal. It does not scan, change trust stores, or edit your shell profile.

Mac and Windows releases are unsigned. If your organization's security policy blocks them, use its approved software distribution process. [Manual download and installation](docs/releases.md) is also available. PowerShell script restrictions can be handled by using the manual ZIP route without changing execution policy.

## First check

On macOS or Linux, run:

```sh
"$HOME/.local/bin/emudhraslop" check --online
```

On Windows:

```powershell
& "$env:LOCALAPPDATA\emudhraslop\bin\emudhraslop.exe" check --online
```

If `emudhraslop` is already on your `PATH`, use `emudhraslop check --online`. To update, run the installer again. For automation, pin a release with `sh emudhraslop-install.sh --version 0.2.0` or `.\emudhraslop-install.ps1 -Version 0.2.0`.

This discovers supported runtimes in managed locations and on `PATH`, then checks them. `--online` contacts fixed public incident test hosts and a clean control. Add `--agent` for machine-readable output without cache reads or writes. Use `--offline` instead if network calls are not permitted; offline checks often return `unknown`.

To list discovered runtimes without testing them:

```sh
emudhraslop inventory --agent
```

Discovery does not cover every app, virtual environment, or service. It cannot return a whole-machine all-clear. Use a service file for the configurations you need to assess.

## Read the result

The report shows the executable path, runtime version when available, what the check found, and a next step for each client. Multiple Python or OpenSSL installations appear separately. A runtime finding does not establish that every application using that runtime has the same TLS configuration.

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
emudhraslop check --online --services services.json
```

Use the Python executable from the application's virtual environment so the check loads its installed libraries. For Windows, use absolute JSON paths such as `"C:\\apps\\api\\.venv\\Scripts\\python.exe"`. A relative service-file path is resolved from the current directory:

```powershell
& "$env:LOCALAPPDATA\emudhraslop\bin\emudhraslop.exe" check --online --services services.json
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
  --online --services /etc/emudhraslop/services.json --agent
```

For Kubernetes, replace the deployment and container names:

```sh
kubectl exec deployment/application -c app -- /usr/local/bin/emudhraslop check \
  --online --services /etc/emudhraslop/services.json --agent
```

Use `--offline` where egress is unavailable. Native checks need a writable temporary directory, even with `--no-cache`. The checker needs no Docker socket or host mounts. A separate scanner container measures its own runtimes and trust stores. Minimal images without a supported native verifier return `unknown`. See [container details](docs/containers.md).

## Use from an agent or CI job

Use `--agent` (shorthand for `--json --no-cache`). The CLI never prompts. Installation and scanning are separate, so agents can pin the binary and choose when to allow network access. Capture the exit code before processing the report:

```sh
umask 077
code=0
emudhraslop check --online --services services.json --agent \
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

Checks save no cache unless you supply `--cache FILE`.

See [agent integration](docs/agents.md) for validation and timeout handling, or [Jamf integration](docs/jamf.md) for scheduled Mac scans and cached inventory attributes.

## Build from source

With Go 1.27.3:

```sh
make build
./dist/emudhraslop version
make test
```

For macOS native trust checks, use the release archive with its bundled helper, or build it on a Mac with Swift using `make release VERSION=0.2.0`. See [release builds](docs/releases.md#build-archives) for prerequisites and target selection.

[Security design](docs/security.md) documents probe isolation and input handling. Embedded incident fixtures contain public certificates only.
