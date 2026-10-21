Check more clients without confusing runtime trust with application impact.

- Reports now use **schema version 2**. `assessment_scope` is `client_configurations`; `application_status` remains `unknown`. Existing status/affected values and exit codes describe the tested client only. Update strict schema consumers before rollout; service manifests remain version 1.
- `--project .` includes Python environments in the selected directory and its `.venv`, `venv`, and `env` children. Activated environments retain their interpreter paths.
- Native Python checks cover stdlib, Requests, HTTPX, Botocore, urllib3, and aiohttp. Node checks cover TLS, HTTPS, and built-in fetch, with peer-certificate attribution from the actual connection. Missing libraries remain unknown; scanning installs nothing.
- Jamf uses scheduled online checks and a separate historical `observation` command. Extension attributes return `observed_*` values; old results never become a fresh protection verdict. Mac archives include the deployment plist and extension attribute.
- Python probes require a nonroot identity, including when root probes are otherwise enabled. Root-started scans must declare nonzero UID/GID values for Python.

## Use

Install or update using the [installation instructions](https://github.com/cowsecurity/emudhraslop#install), then run:

```sh
emudhraslop check --online
emudhraslop check --online --project .
emudhraslop check --online --project . --agent
```

Use `--services services.json` to supply exact interpreter paths, HTTP clients, identities and CA settings. This tests those client settings in isolation; it does not attach to a running application or assess incoming listening ports.

## Deployment

[Jamf rollout](https://github.com/cowsecurity/emudhraslop/blob/main/docs/jamf.md) · [Containers](https://github.com/cowsecurity/emudhraslop/blob/main/docs/containers.md) · [Agent contract](https://github.com/cowsecurity/emudhraslop/blob/main/docs/agents.md)

Runtime tests cover native certificate trust, hostname rejection, redirects, timeouts and exact connection attribution. Container integration runs in Python 3.11/3.14 and Node 22/24 images as a nonroot user with a read-only filesystem and no external network access. Jamf tests build and expand unsigned universal Mac packages and execute the real extension-attribute path.

Archives cover macOS Intel/Apple Silicon, Linux x64/ARM64/ARMv7, and Windows x64/ARM64. SHA256SUMS covers archives and installers. Publisher signing, Apple notarization and Windows Authenticode signing are not supplied. Windows native trust-store assessment and report storage remain unsupported. Browsers, Java, Go, Rust, .NET and application-specific TLS hooks remain outside coverage.
