# Coverage and interpretation

The unit of assessment is one TLS client configuration: executable, client library, user, effective CA settings, and image where applicable. A package name, machine, or installed application is a broader scope.

The machine verdict is `affected`, `not_affected`, or `unknown`, with `affected` set to `true`, `false`, or `null` respectively. A `not_affected` decision is limited to the explicitly assessed configuration and supported proof. An unsupported or incomplete negative check remains `unknown`.

## Supported evidence

| Context | Useful evidence | Limits |
| --- | --- | --- |
| OpenSSL 3 with one exclusive CA file | Native incident-fixture verification; bounded `not_affected` proof when every [required condition](negative-proof.md) holds, including an accurate `exclusive_ca_bundle: true` declaration | Does not establish Python, curl, another store, or an application's custom TLS behavior |
| curl / other OpenSSL contexts | Native acceptance checks under the declared trust configuration | Negative or ambiguous results remain unknown |
| macOS native trust | Apple verifier evaluation where available | Negative results remain unknown; does not establish browser, Electron, or custom library behavior |
| Python ssl / Requests / HTTPX / Botocore | Native client online checks and effective CA configuration | No general offline native-verification proof; custom adapters need a declared context |
| Node TLS / HTTPS | Native client online checks and effective CA configuration | Custom agents, embedded apps, fetch dispatchers, and per-request contexts require separate verification |
| Minimal container | Static checker can inspect declared files and report missing tools | Absence of a verifier means unknown |

An online positive result must identify the expected incident leaf or chain. Generic rejection, DNS failure, interception, timeouts, proxy errors, or an unavailable control cannot establish protection. The clean control is diagnostic, not proof that every application path was checked. Once public fixture certificates expire, expiry-based rejection cannot establish incident remediation.

Trust-store key matches are inventory evidence. They do not alone demonstrate that a particular service accepts a chain. A `not_affected` result is limited to the native verifier, trust configuration, hostname, certificate validity, and incident paths actually assessed. It cannot be transferred to another application's trust settings.

## Declaring services

Use a version 1 JSON manifest with a `services` array. Every entry needs a unique `id`, `kind`, absolute `executable` where the kind uses one, `client`, and a meaningful `source`. Set `uid` and `gid` to the service identity when invoking from root. Use `ca_bundle`, `ca_dir`, and permitted `environment` settings only when they match the real service. `image_digest` records the image identity supplied by the operator; it is not remotely verified.

Never copy a complete process environment. The manifest is configuration, not a place for tokens, proxy passwords, preload hooks, or executable arguments. TLS verification disabled in a declared service is a security finding even if package versions are current.

Examples use illustrative paths and identities. The checker does not create users, install libraries, rewrite CA files, or repair service settings.

`exclusive_ca_bundle: true` means the actual OpenSSL service already excludes implicit CA directories and stores. Set it only after confirming that launch configuration; it is not a switch to obtain a clean result. Without it, the check preserves OpenSSL default-store behavior and cannot confirm `not_affected`. The [exclusive OpenSSL example](../examples/openssl-exclusive-services.json) applies only to services that actually use that policy.

## Unassessed contexts

Browser profiles, Electron apps, Java keystores, arbitrary Go and Rust binaries, custom TLS stacks, inbound server certificates, code-signing checks, and services without an exact launch configuration are outside the initial assessment. They remain explicit exclusions or unknown results. A machine may contain configurations with different trust behavior.

Managed inventory is a bounded discovery aid. It is not an exhaustive filesystem search or a guarantee that every process, virtual environment, container, build stage, or user profile was found. Maintain a service manifest from deployment definitions and check each build/runtime stage that performs TLS requests.

## Resources

The default scan budget is two concurrent probes, ten seconds per probe, and two minutes per scan. These are resource limits, not security thresholds; timeout results remain unknown. Runtime work scales with declared contexts and incident paths. Certificate parsing and hashing scale with bytes read. Reports and subprocess output are bounded; an exceeded limit must remain visible.
