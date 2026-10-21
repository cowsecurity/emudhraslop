# Windows

Use the `windows-amd64.zip` archive for x64 Windows and `windows-arm64.zip` for Windows on ARM. Extract the archive and run PowerShell without Administrator elevation.

```powershell
.\emudhraslop.exe inventory --no-cache --json
.\emudhraslop.exe check --online --no-cache --json
.\emudhraslop.exe check --online --services services.json --no-cache --json
```

Managed inventory looks for Python, Node, curl and OpenSSL `.exe` files on bounded absolute PATH entries. It does not run scripts, Windows Store aliases, or enumerate every installed application or Windows service. Declare an application's actual executable, client library and trust settings to assess that context. The CLI resolves relative `--services` paths from the current directory; executable and CA paths inside the JSON must be absolute local paths. Omit `uid` and `gid`: Windows probes use only the current non-elevated process token. Report UID `4294967295` is Go's unsupported Unix UID placeholder, not a Windows SID.

The Python stdlib, Requests, HTTPX, Botocore, Node TLS/HTTPS and curl adapters execute native clients. Online acceptance counts as affected only when the native client verifies the exact embedded incident leaf. Offline Python and Node inventory, failed connections and unattributed certificate rejections remain unknown. OpenSSL requires an explicit CA configuration; see [negative proof](negative-proof.md) for the exclusive CA-file scope required for a negative conclusion.

Windows system trust, arbitrary application contexts, browsers, Java, Windows service identities and code signing are not whole-machine assessment coverage. Elevated execution is refused, including with `--allow-root-probes`. Run under the application's standard account. There is no Windows impersonation or numeric UID/GID switching.

Use `--no-cache`. Windows cache reads and writes are disabled until ACL ownership and integrity can be validated; Unix mode bits are insufficient. Network shares, device paths, alternate data streams and nonregular trust inputs are rejected.

Subprocesses start suspended, join a mandatory kill-on-close Windows Job Object and resume only after assignment. Native output and execution time are bounded. If the platform cannot establish containment, the probe stays unknown.

JSON preserves the common agent contract: `affected: true`, `false`, or `null`; exit `2` means affected, `0` means the complete declared scope is not affected, `3` means unknown/incomplete and `1` means invalid usage or a fatal error. A successful inventory is an inventory result, not a negative incident confirmation.

CI runs native x64 and ARM64 Windows tests. Its temporary standard account exercises real TLS acceptance/rejection, certificate attribution, environment isolation, output limits and descendant termination. The elevated runner first verifies that elevated product probes are refused. Cross-compilation alone does not validate Windows runtime behavior.
