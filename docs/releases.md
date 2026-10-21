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

## Download on macOS or Linux

These commands use the GitHub CLI (`gh`), authenticated with an account that can read this private repository. Run `gh auth login` first if needed. You can also download the archive and `SHA256SUMS` through the release page.

Choose a target from the table above. This example downloads the Apple Silicon build; change `target` to `darwin-amd64`, `linux-amd64`, `linux-arm64`, or `linux-arm-v7` as needed. Run in a new directory:

```sh
version=0.1.0
target=darwin-arm64
archive="emudhraslop-${version}-${target}.tar.gz"
mkdir "emudhraslop-${version}-${target}"
cd "emudhraslop-${version}-${target}"
gh release download "v${version}" --repo cowsecurity/emudhraslop \
  --pattern "$archive" --pattern SHA256SUMS
```

Verify **before** extracting. On macOS:

```sh
shasum -a 256 --check --ignore-missing SHA256SUMS && tar -xzf "$archive"
```

On Linux:

```sh
sha256sum --check --ignore-missing SHA256SUMS && tar -xzf "$archive"
```

The output must show your archive filename followed by `OK`. Then run:

```sh
./emudhraslop version
./emudhraslop check --online --no-cache
```

`--online` contacts public incident test hosts and a clean control. Use `--offline` if network calls are not permitted. Exit 2 means affected; exit 3 means unknown. See the [README](../README.md#read-the-result) before interpreting either result.

On macOS, keep `emudhraslop-sectrust` next to the executable. Mac archives are unsigned and not notarized. If macOS blocks execution, use your organization's approved signing/distribution process; do not disable Gatekeeper.

## Download on Windows

Use a non-Administrator PowerShell window with an authenticated GitHub CLI. Set `$target` to `windows-arm64` for an ARM machine; otherwise use `windows-amd64`:

```powershell
$ErrorActionPreference = 'Stop'
$version = '0.1.0'
$target = 'windows-amd64'
$archive = "emudhraslop-$version-$target.zip"
New-Item -ItemType Directory "emudhraslop-$version-$target" | Out-Null
Set-Location "emudhraslop-$version-$target"
gh release download "v$version" --repo cowsecurity/emudhraslop `
  --pattern $archive --pattern SHA256SUMS
if ($LASTEXITCODE -ne 0) { throw 'Download failed' }

$entries = @(Get-Content SHA256SUMS | Where-Object {
  ($_ -split '\s+', 2)[1] -ceq $archive
})
if ($entries.Count -ne 1) { throw 'Missing or duplicate checksum entry' }
$expected = ($entries[0] -split '\s+', 2)[0]
$actual = (Get-FileHash $archive -Algorithm SHA256).Hash
if ($actual -ine $expected) { throw 'Checksum mismatch' }
Expand-Archive $archive -DestinationPath .

.\emudhraslop.exe version
.\emudhraslop.exe check --online --no-cache
$LASTEXITCODE
```

Windows builds are unsigned. Run as the application's normal account. Use `--no-cache`; Windows caching and native Windows trust-store assessment are unsupported. See [Windows usage](windows.md) for service paths and supported clients.

## Checksums and manifests

`SHA256SUMS` checks that the download matches the published archive. It is not a publisher signature. `RELEASE-MANIFEST.json` records the version, target and payload hashes. Keep both with the archive if you need to reproduce an assessment.

For a precise application check, create a [service file](../README.md#check-an-application). For containers, extract the Linux archive on your workstation or build machine, then [copy the binary into the application image](../README.md#check-a-container).

## Build archives

Build prerequisites are Go 1.27.3, Python 3.9+, and a POSIX shell. Mac releases also need Xcode command-line tools with Swift. There are no third-party Go or Python build dependencies.

```sh
VERSION=0.1.0 TARGETS='linux/amd64 linux/arm64 linux/arm/v7 windows/amd64 windows/arm64' make release
VERSION=0.1.0 TARGETS='darwin/amd64 darwin/arm64' make release
```

Run the second command on macOS. A Mac host defaults to every listed target; other hosts default to Linux and Windows. Each archive contains the platform executable, an Apple helper on Mac, selected docs/examples, and `RELEASE-MANIFEST.json` with payload hashes and platform limitations. Existing archives are never overwritten. Remove only intentionally disposable local output before rebuilding the same version.

`dist/releases/SHA256SUMS` covers that build's versioned archives. `dist/SHA256SUMS` also covers raw binaries and an optional local Jamf package. Release assembly uses explicit file allowlists; service credentials, scan reports, user manifests, private keys, and fleet-specific Jamf configuration are not included. `build-jamf-package.sh` remains a separate operator step requiring a reviewed service manifest.

Tagged versions use `vMAJOR.MINOR.PATCH` or a SemVer prerelease. Published asset filenames omit the leading `v`. Release automation checks the exact platform set, hashes, archive payload identities, and existing asset names before publishing. A checksum file is not a signature or notarization claim.
