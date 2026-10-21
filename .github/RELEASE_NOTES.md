Check whether your TLS clients trust certificates involved in the eMudhra incident. The checker reports `affected`, `not_affected`, or `unknown` without changing trust stores or installing updates.

## Download

Choose the archive for your machine or container image:

| Platform | Filename suffix |
| --- | --- |
| macOS — Apple Silicon | `darwin-arm64.tar.gz` |
| macOS — Intel | `darwin-amd64.tar.gz` |
| Linux / containers — x64 | `linux-amd64.tar.gz` |
| Linux / containers — ARM64 | `linux-arm64.tar.gz` |
| Linux / containers — ARMv7 | `linux-arm-v7.tar.gz` |
| Windows — x64 | `windows-amd64.zip` |
| Windows — ARM64 | `windows-arm64.zip` |

Download `SHA256SUMS` too, verify the archive, then extract it. [Step-by-step installation](https://github.com/cowsecurity/emudhraslop/blob/main/docs/releases.md) includes commands for each OS. This repository currently requires GitHub access. Mac and Windows binaries are unsigned; macOS builds are not notarized.

## Run

From the extracted directory, as your normal user:

```sh
./emudhraslop version
./emudhraslop check --online --no-cache
```

On Windows, use a non-Administrator PowerShell window:

```powershell
.\emudhraslop.exe version
.\emudhraslop.exe check --online --no-cache
```

On macOS, keep `emudhraslop-sectrust` beside the executable. Online checks contact public incident test hosts and a clean control. Use `--offline` if network calls are not permitted; incomplete checks return `unknown`.

## Check a specific application

Create a [service file](https://github.com/cowsecurity/emudhraslop#check-an-application) with the application's runtime, client library and trust settings, then run as that application's user:

```sh
./emudhraslop check --online --services services.json --no-cache --json
```

On Windows, use `.\emudhraslop.exe` and an absolute path for `--services`, such as `"C:\apps\services.json"`.

For containers, copy the matching Linux binary into the application image and run it there. See [Docker and Kubernetes examples](https://github.com/cowsecurity/emudhraslop#check-a-container). The checker needs the application's own runtimes and trust stores.

## Use the result

| Result | JSON `affected` | Exit code |
| --- | --- | --- |
| `not_affected` | `false` | 0 |
| `affected` | `true` | 2 |
| `unknown` | `null` | 3 |

Exit 1 means invalid input or a fatal failure. If any context is affected, the overall result is affected even if other contexts are unknown.

`not_affected` currently requires a declared OpenSSL 3 configuration with one exclusive CA file. Other clients can confirm affected status, but a rejected connection alone does not prove they are unaffected. Discovery does not cover every application on a machine. Windows native trust-store assessment and caching are unsupported.

For agents and CI, use `--json --no-cache`, preserve the exit code, and read each result's `reason` and `next_action`. Unknown is not an all-clear. [Agent integration and JSON contract](https://github.com/cowsecurity/emudhraslop/blob/main/docs/agents.md).
