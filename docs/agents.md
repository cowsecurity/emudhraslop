# Agent integration

Run the standalone binary from an approved artifact. It needs no login, agent framework, model API, browser, or interactive prompt. Pass arguments directly; do not construct a shell command from untrusted service data.

Install a pinned release with the [installer](../README.md#install), or supply a verified binary in the execution environment. Unix installers accept `--version 0.3.0 --bin-dir /absolute/user-owned/bin`; Windows accepts `-Version 0.3.0 -BinDir C:\absolute\user-owned\bin`. They do not prompt or scan. Run installers as a normal user; for container builds, copy the verified binary into the application image.

```sh
emudhraslop version
emudhraslop inventory --agent
emudhraslop check --online --project /srv/api --agent
emudhraslop check --offline --services services.json --agent
```

`--agent` means `--json --no-cache`. Existing integrations using those two flags still work. Report JSON uses schema version **2**; service manifests still use version **1**. Check exit codes are unchanged. Use `--project` to add a Python virtual environment and `--services` to declare a specific client and trust settings; discovery alone cannot establish complete machine coverage.

Use `--online` only when the operator permits calls to the fixed incident hosts and clean control. Run inside the application container and as its service identity. Default root restrictions still apply to automated callers.

## Decision contract

Validate `schema_version == 2` and `assessment_scope == "client_configurations"` before using a verdict. Report-level and result-level `application_status` are always `"unknown"`. Never turn a client result into an application, listening-port, browser, or whole-machine verdict.

Each result has `assessment_basis`: `client_defaults` when no explicit trust or verification overrides were supplied, or `configured_client` when CA paths, allowed environment overrides, or disabled-verification settings were supplied. A manifest that only names an executable and client still tests defaults; `configuration_source` records how the context was selected. Neither means the running application's configuration was verified. Do not create a service manifest from only a listener PID or runtime version and describe it as an application scan.

| `status` | `affected` | Meaning | Check exit |
| --- | --- | --- | --- |
| `affected` | `true` | Evidence of incident-chain acceptance or explicitly disabled verification | 2 |
| `not_affected` | `false` | Complete supported negative proof for the declared scope | 0 |
| `unknown` | `null` | Unsupported, incomplete, ambiguous, or failed assessment | 3 |

Exit 1 means invalid input or fatal failure; a JSON report is not guaranteed. Exit 0 from `version` or `--help` is not an assessment. Inventory produces unknown decisions because it does not run native checks.

On a check, affected takes precedence over unknown: a report may have `affected: true` while some client configurations remain unknown. Preserve both the aggregate and all individual decisions. A false value applies only to the assessed configuration; it is not proof that every machine service was found. The current supported negative proof is the [exclusive OpenSSL 3 CA-file assessment](negative-proof.md); other negative checks remain unknown. Its manifest requires `exclusive_ca_bundle: true`, asserting that the actual service already disables implicit CA directories and stores. Never add that assertion merely to change the verdict. Never coerce `null`, a missing field, an unreadable report, or an unsupported schema version to `false`.

This example is a decision-field excerpt, not a scan result:

```json
{
  "assessment_basis": "client_defaults",
  "application_status": "unknown",
  "status": "unknown",
  "affected": null,
  "reason": "offline_native_policy_not_proven",
  "next_action": "Run an online native check; application-specific TLS settings require a separate declared context."
}
```

## Read the report

Validate stdout against [report.schema.json](report.schema.json), then verify the process exit agrees with `status`. The schema is versioned by `schema_version`; reject versions your integration does not understand. Fatal diagnostics go to stderr. Check commands emit one JSON report on stdout when assessment reaches report creation. No progress prose or terminal color is mixed into JSON.

Use these fields to decide the next action:

- `coverage.scope`, `complete`, `exclusions`, and `warnings`: what was assessed and what is missing. Complete declared scope does not mean complete machine coverage.
- `results`: every tested client context, its assessment basis, native runtime, verdict, reason, next action, trust sources, and per-chain evidence. Missing optional packages stay visible as unknown; never silently drop their results.
- `checks[].proof` and `error_class`: evidence and failure attribution. Do not infer a decision from an error string or runtime version.
- `errors`: report-level failures that must remain visible. A successful parse does not clear them.
- `checker_version`, incident manifest hash, configuration hash, scan time, and image digest: identities needed to compare evidence. An image digest is operator-supplied metadata, not registry attestation.

Reasons and proof strings help triage; the canonical decision is `status` plus its matching nullable boolean. Do not assume new reason strings are successful negatives. Reports may reveal local executable paths and service IDs; keep them access-controlled and avoid copying unnecessary details into agent logs.

## Nonzero exits are data

Capture output before branching on the exit code:

```sh
code=0
emudhraslop check --offline --services /etc/emudhraslop/services.json \
  --agent > report.json || code=$?
case "$code" in
  0) echo 'Tested clients not affected; retain proof and exclusions';;
  2) echo 'Affected context found; route remediation';;
  3) echo 'Assessment incomplete; route evidence collection';;
  *) echo 'Assessment failed; inspect diagnostics' >&2; exit 1;;
esac
```

Use a private report directory and a bounded process deadline slightly longer than `--timeout`. Do not retry indefinitely: network failures can remain unknown. Do not change trust stores, install dependencies, disable TLS verification, or enable root probes merely to obtain a conclusive status.

Caching is opt-in; ordinary checks no longer write a default cache. For caching, use `--cache FILE` on the initial scan and `--cached --services FILE --cache FILE` for a later read. Cached mode runs no native probes or network requests, but revalidates relevant files. Missing/stale evidence and non-reusable negative proofs remain unknown and require a fresh check. `--no-cache` avoids cache reads and writes and is incompatible with both cache options.


## Broader runtime coverage

Managed discovery tries six clients for each Python executable: `stdlib`, `requests`, `httpx`, `botocore`, `urllib3`, and `aiohttp`. For each Node executable it tries `tls`, `https`, and built-in `fetch`. Pass `--project /srv/api` to add the project's `.venv`, `venv`, or `env`; repeat the flag for other projects or pass a virtual environment root directly. This is a bounded search, not a process inventory or recursive filesystem walk. The checker does not install missing packages.

Use the virtual environment's Python path in explicit manifests. Replacing it with the base interpreter can load different dependencies and CA bundles. `client: fetch` uses Node's built-in fetch with its default dispatcher; custom dispatchers and per-request CA objects are unassessed. Fetch with an explicit `ca_bundle` or `ca_dir` stays unknown rather than substituting a different client.


## Historical inventory

```sh
emudhraslop observation --cache /private/path/status.json --max-age 24h --json
```

This is a separate historical lookup, not a check. It reads an owner-private saved report without executing clients or contacting hosts. JSON contains `last_observed_status`, `observed_at`, `state` (`fresh`, `stale`, or `invalid`), and `current_status`, which is always `unknown`. `fresh` means within the requested age, not unchanged application configuration. Do not convert an observed negative into a current protection claim.

Plain output is `observed_affected`, `observed_not_affected`, or `observed_unknown` for a fresh record; stale or invalid records print `unknown`. Exit 0 means a fresh historical record was read, regardless of its old verdict. Exit 3 means stale/invalid; exit 1 means bad arguments or a fatal error. Stale JSON retains the historical time and verdict. Route automation by this command's contract, not the `check` exit-code table. `observation` is unsupported on Windows because cache access is unsupported there.
