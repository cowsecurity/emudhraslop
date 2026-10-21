Standalone, read-only eMudhra TLS trust checker with a noninteractive agent interface.

Downloads cover macOS (Intel/Apple Silicon), Linux (amd64/arm64/ARMv7), and Windows (amd64/arm64). macOS archives include the native Apple trust helper. Linux binaries are static and can be copied into the actual application container.

Extract the matching archive, then run `emudhraslop check --online --no-cache --json` (`emudhraslop.exe` on Windows). Online checks contact fixed public incident test hosts. Use an explicit service manifest to assess a precise configuration.

Decisions are `affected`, `not_affected`, or `unknown`, with matching nullable `affected` booleans and documented exit codes. Negative confirmation is limited to supported, explicitly exclusive OpenSSL CA-file contexts; unknown never means not affected. Windows requires a non-elevated account; native Windows trust-store assessment and caching are unsupported.

Verify the downloaded archive against `SHA256SUMS`. `RELEASE-MANIFEST.json` records platform payload identities and capabilities. These are checksums, not Apple/Windows publisher signatures. No notarization or Authenticode signing is claimed. No scanner secrets, fleet profiles or example Jamf installers are distributed.
