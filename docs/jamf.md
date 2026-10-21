# Jamf rollout

The package installs a scheduled checker and a private report. It does not contact Jamf, change trust settings, or start its daemon during installation.

1. Create a reviewed `services.json` for the pilot. Use actual executable paths, client libraries, CA settings, and numeric UID/GID values for each machine group. Preserve virtual-environment interpreter paths. A runtime's default TLS settings do not establish a running application's settings.
2. Build the macOS binaries and package:

   ```sh
   make release VERSION=0.3.0
   SERVICES_FILE=/absolute/path/reviewed-services.json VERSION=0.3.0 \
     SCAN_MODE=online ./scripts/build-jamf-package.sh
   ```

   `SCAN_MODE` accepts `online` (default) or `offline`. Online checks contact the embedded incident hosts under `emudhra.we-have-a-problem.com` and the clean control `www.google.com`, using HTTPS. Approve that egress for the pilot. Offline Python/Node inventory generally remains unknown; use it where online checks are prohibited. The package builder checks manifest syntax; target-machine identity, executable and trust configuration validation happens on that machine.

   For signed packages, supply `SIGNING_IDENTITY` and `INSTALLER_IDENTITY` through your approved build environment. Without them the package is explicitly unsigned. Notarization is a separate distribution step. No signing credentials belong in this repository.
3. Upload the package to a pilot policy. After installation, enable the job:

   ```sh
   launchctl bootstrap system /Library/LaunchDaemons/io.emudhraslop.scan.plist
   launchctl kickstart system/io.emudhraslop.scan
   ```

   Bootstrap is a one-time operation. On later policies, check whether the job is already loaded before bootstrapping again. Review the first report locally before widening deployment.
4. Add `scripts/jamf-extension-attribute.sh` as a string extension attribute named **Emudhraslop Last Observation**. Use these exact groups:

   | Value | Action |
   | --- | --- |
   | `observed_affected` | Investigate the client configurations in the last scan; assign remediation and rescan. |
   | `observed_not_affected` | Retain the proof for the declared scope; this does not clear unassessed applications. |
   | `observed_unknown` | Collect missing client settings, access, or evidence. |
   | `unknown` | No recent usable report; inspect deployment and run a new scan. |

   Update existing smart groups that matched the old `affected`/`not_affected` values. The attribute reports **historical observations**, not current protection. It does not execute client runtimes, contact the network, or reread current trust files. Reports older than 24 hours, from another checker/incident version, malformed reports, and reports without owner-private permissions produce `unknown`.
5. Inspect observation time and freshness when triaging:

   ```sh
   /Library/Emudhraslop/bin/emudhraslop observation \
     --cache '/Library/Application Support/Emudhraslop/status.json' --json
   ```

   JSON includes `last_observed_status`, `observed_at`, `state` (`fresh`, `stale`, or `invalid`), and `current_status`, which is always `unknown`. A stale but valid record retains its historical status and timestamp in JSON. The plain command emits `unknown` for stale records. Exit 0 means a recent observation was read, regardless of its historical verdict; exit 3 means stale/unavailable; exit 1 means invalid arguments or a fatal command error. Use `check` for a new verdict.
6. After remediation, rerun the same client contexts and compare fresh results. Changing a manifest or trust file does not rewrite history. A cached observation may describe the configuration before that change; only a new scan tests the changed configuration.

The daemon runs every six hours with a two-minute scan deadline and two simultaneous native probes. These are adjustable rollout limits; large manifests or slow networks can leave contexts unknown. Reports are private to root at `/Library/Application Support/Emudhraslop/status.json`; the extension attribute exposes only the historical status word.

The daemon starts as root to assess declared service identities. Declare nonroot UID/GID pairs for privilege drops. It does not enable root execution of discovered programs. Never run user-owned virtual environments as root. A root service requires separately reviewed trusted executable paths and explicit `--allow-root-probes`; the supplied daemon does not enable it.

The package installs the binary and Apple helper under `/Library/Emudhraslop/bin`, the manifest and report under `/Library/Application Support/Emudhraslop`, and the daemon under `/Library/LaunchDaemons`. The private report is protected by local ownership and permissions, not a digital signature: an administrator or compromised scanning identity can replace its own evidence. Keep Jamf access limited accordingly.

Python probes require nonroot execution even with `--allow-root-probes`. For a root-started Jamf scan, declare both a nonzero UID and GID for each Python context. Python startup can read virtual-environment and standard-library configuration before the probe script runs.
