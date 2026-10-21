# Jamf rollout

This repository supplies an installer builder, scheduled scan definition, and cache-only extension attribute. It does not contact Jamf or change employee machines.

1. Define the managed service/runtime contexts for the pilot. Record actual executable paths, client libraries, CA settings, and numeric UID/GID values in `services.json`. Separate developer virtual environments and everyday applications; unsupported contexts remain unknown.
2. Build and review the local installer:

   ```sh
   make release VERSION=0.1.0
   SERVICES_FILE=/absolute/path/reviewed-services.json VERSION=0.1.0 \
     SIGNING_IDENTITY='Developer ID Application: YOUR ORGANIZATION (TEAMID)' \
     INSTALLER_IDENTITY='Developer ID Installer: YOUR ORGANIZATION (TEAMID)' \
     ./scripts/build-jamf-package.sh
   ```

   Real signing identities are optional for local testing and required by your distribution policy. Omitting them produces an explicitly unsigned installer. Notarization is a separate release step using your approved Apple credentials; this script does not claim it happened. Never commit signing secrets.
3. Upload the reviewed package to a pilot policy. Install first, then enable the daemon in that policy:

   ```sh
   launchctl bootstrap system /Library/LaunchDaemons/io.emudhraslop.scan.plist
   launchctl kickstart system/io.emudhraslop.scan
   ```

   Bootstrap is a one-time operation; subsequent policies should inspect whether the job is already loaded. The package itself deliberately does not load or run the job.
4. Add `scripts/jamf-extension-attribute.sh` as a string extension attribute. It only reads and validates the cached report. It returns `unknown` when files, cache freshness, or configuration validation fail. It never starts a scan during Jamf inventory.
5. Create review groups for `affected` and `unknown`. Use each context's reason and next action to assign remediation, then rerun the same scan after updating the underlying runtime/trust configuration. A `not_affected` context does not clear unsupported apps on the machine. Cached reads may require a fresh assessment where the underlying proof is not reusable.

The launch daemon runs offline every six hours, a scheduling choice that can be changed before packaging. Its per-scan limit is two minutes with two native probes at once. Runtime results are stored in the private cache directory, not a world-readable log. The extension attribute exposes only the status word.

The daemon starts as root so it can assess explicitly managed identities. It does not enable root execution of discovered programs. Declare service UID/GID pairs for privilege drops; user-owned executables must not be assessed as root. Where native checks cannot run safely, results remain unknown. Review `--allow-root-probes` only for root services with trusted paths, and amend the plist explicitly if justified.

For offline Python/Node contexts, inventory alone cannot establish protection. Schedule deliberately approved online checks or collect an appropriate native verification result where needed; the supplied offline policy prioritizes safe inventory and evidence collection.

Installed paths are `/Library/Emudhraslop/bin/emudhraslop`, `/Library/Application Support/Emudhraslop/services.json`, `/Library/Application Support/Emudhraslop/status.json`, and `/Library/LaunchDaemons/io.emudhraslop.scan.plist`. The package builder requires a real reviewed manifest and does not ship example identities as fleet configuration.
