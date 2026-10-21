Install and check your TLS clients with fewer steps.

- Installers select the OS/CPU, verify the archive and install for the current user. No GitHub CLI, Go or administrator access required.
- Human output identifies each executable, explains the finding and gives a next step.
- `--agent` returns the existing JSON report without caching or prompts.
- Checks only write a cache when you pass `--cache FILE`. Existing `--cached` reads still work.
- Windows accepts relative paths for `--services`.

## Install and run

[Copy the install commands for your OS](https://github.com/cowsecurity/emudhraslop#install). The installer prints the exact command to run. On macOS/Linux with the default installation:

```sh
"$HOME/.local/bin/emudhraslop" check --online
```

On Windows:

```powershell
& "$env:LOCALAPPDATA\emudhraslop\bin\emudhraslop.exe" check --online
```

Online checks contact fixed public incident test hosts and a clean control. Use `--offline` when network calls are not permitted. Installers never start a scan automatically.

## Agents and CI

```sh
emudhraslop check --online --agent
emudhraslop check --online --services services.json --agent
```

The second command checks the application configurations in your service file. [Examples for applications, containers and CI](https://github.com/cowsecurity/emudhraslop#check-an-application).

| Result | JSON `affected` | Exit |
| --- | --- | --- |
| `not_affected` | `false` | 0 |
| `affected` | `true` | 2 |
| `unknown` | `null` | 3 |

Exit 1 means invalid input or a fatal failure. Unknown needs review; it is not an all-clear. `not_affected` currently requires a declared OpenSSL 3 configuration with one exclusive CA file. A result applies to the tested configuration, not every application on a machine.

[Manual archives](https://github.com/cowsecurity/emudhraslop/blob/main/docs/releases.md) cover macOS Intel/Apple Silicon; Linux x64/ARM64/ARMv7; and Windows x64/ARM64. `SHA256SUMS` covers the archives and installers. Mac and Windows binaries and installers are unsigned; no notarization or Authenticode signing is claimed. Windows native trust-store assessment and caching remain unsupported.
