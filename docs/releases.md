# Releases

Download from [cowsecurity/emudhraslop releases](https://github.com/cowsecurity/emudhraslop/releases/latest). Choose the archive matching the machine's operating system and CPU; a container needs the architecture of its application image.

| Environment | Archive target | Assessment scope |
| --- | --- | --- |
| macOS 13+ on Intel | `darwin-amd64.tar.gz` | Unix runtime adapters and bundled Apple native helper |
| macOS 13+ on Apple Silicon | `darwin-arm64.tar.gz` | Unix runtime adapters and bundled Apple native helper |
| Linux / containers, x86-64 | `linux-amd64.tar.gz` | Static binary; native clients must exist in the application image |
| Linux / containers, ARM64 | `linux-arm64.tar.gz` | Same adapter boundaries as Linux x86-64 |
| Linux / containers, 32-bit ARM v7 | `linux-arm-v7.tar.gz` | Static binary; ARM v7 execution is not part of the hosted native test matrix |
| Windows on x86-64 | `windows-amd64.zip` | Non-elevated Python, Node, and curl contexts |
| Windows on ARM64 | `windows-arm64.zip` | Non-elevated Python, Node, and curl contexts |

The full filename is `emudhraslop-VERSION-TARGET.EXTENSION`. Platform availability does not mean every application uses a supported trust verifier. Windows native certificate-store evaluation, elevated execution, and cached checks are unsupported; they produce explicit errors or unknown results. See [coverage](coverage.md) before interpreting any verdict.

## Verify and run

Download `SHA256SUMS` from the same release as the archive. On Linux run `sha256sum --check --ignore-missing SHA256SUMS`; on macOS use `shasum -a 256 --check --ignore-missing SHA256SUMS`. A successful check establishes consistency with the published checksum file, not an independent publisher signature.

On Windows compare the archive's `Get-FileHash -Algorithm SHA256` value with its exact filename entry in `SHA256SUMS`. Do not treat the hash of another architecture's archive as a match. Then use `Expand-Archive` into a new directory.

Extract Unix archives into a new directory, retain the included docs and manifest, then run:

```sh
./emudhraslop version
./emudhraslop inventory --scope managed --no-cache --json
./emudhraslop check --offline --services /absolute/path/services.json --no-cache --json
```

On macOS keep the executable and `emudhraslop-sectrust` adjacent. Release archives are not Developer ID signed or notarized; managed distribution must apply the organization's reviewed signing and delivery process. Do not disable Gatekeeper to obtain a result. Windows builds are not Authenticode signed.

Use `emudhraslop.exe` in PowerShell. Run as the service's normal user and declare absolute Windows executable/CA paths in the service manifest. Do not run elevated or add Unix UID/GID fields. A Windows container must contain Windows clients; Linux container clients require the Linux binary inside that Linux image.

## Build archives

Build prerequisites are Go 1.27.3, Python 3.9+, and a POSIX shell. Mac releases also need Xcode command-line tools with Swift. There are no third-party Go or Python build dependencies.

```sh
VERSION=0.1.0 TARGETS='linux/amd64 linux/arm64 linux/arm/v7 windows/amd64 windows/arm64' make release
VERSION=0.1.0 TARGETS='darwin/amd64 darwin/arm64' make release
```

Run the second command on macOS. A Mac host defaults to every listed target; other hosts default to Linux and Windows. Each archive contains the platform executable, an Apple helper on Mac, selected docs/examples, and `RELEASE-MANIFEST.json` with payload hashes and platform limitations. Existing archives are never overwritten. Remove only intentionally disposable local output before rebuilding the same version.

`dist/releases/SHA256SUMS` covers that build's versioned archives. `dist/SHA256SUMS` also covers raw binaries and an optional local Jamf package. Release assembly uses explicit file allowlists; service credentials, scan reports, user manifests, private keys, and fleet-specific Jamf configuration are not included. `build-jamf-package.sh` remains a separate operator step requiring a reviewed service manifest.

Tagged versions use `vMAJOR.MINOR.PATCH` or a SemVer prerelease. Published asset filenames omit the leading `v`. Release automation checks the exact platform set, hashes, archive payload identities, and existing asset names before publishing. A checksum file is not a signature or notarization claim.
