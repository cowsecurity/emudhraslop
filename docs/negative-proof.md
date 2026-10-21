# What `not_affected` confirms

The OpenSSL adapter can confirm `not_affected` for one declared OpenSSL 3 context with one exclusive CA file. The service manifest must explicitly set `exclusive_ca_bundle: true`, meaning the actual service already excludes implicit CA directories and stores. Naming a CA file alone does not establish that policy. This result covers the published TLS certificate paths in the bundled eMudhra incident manifest. It does not certify the whole machine, other applications, code signing, or future incident paths.

For that explicitly exclusive context, the checker reads the entire CA file, snapshots its bytes, and records its SHA-256. Native verification uses `-no-CApath -no-CAstore` to reproduce the declared service policy. Without the exclusive declaration, it preserves OpenSSL's default-store behavior and cannot report `not_affected`. Mixed directory/file contexts and trust environment overrides cannot receive a negative confirmation.

When the checker drops privileges to a service identity, it also confirms that identity can use the original CA-file path. A privileged copy cannot grant the service access it did not have.

A negative confirmation requires all of the following:

- The complete canonical incident fixture set is present, intact, currently valid, and linked to the published issuers.
- The complete CA file contains neither an affected issuing key nor a known incident anchor key.
- Native OpenSSL rejects every fixture specifically because issuer trust is absent. Time, purpose, hostname, signature, execution, output-limit and other failures remain `unknown`.
- Native OpenSSL successfully verifies a currently valid self-signed CA already in the same CA file, including its signature, with the same trust-source isolation. This control uses `purpose=any` because a root CA is not a TLS server leaf. It proves the native verifier can read and recognize the declared trust file; it does not assert that an ordinary TLS connection works. Every incident-chain check still uses TLS-server purpose and hostname validation. The checker adds no control CA to the file.
- The original CA file still has the same bytes after the check.

A timeout, blocked network, package version or generic certificate rejection never means `not_affected`. Unsupported CA-file forms, including OpenSSL trusted-certificate auxiliary attributes, remain `unknown`; they are never silently discarded.

This proof assumes the declared executable and CA file describe the context the service actually uses. Custom application callbacks, additional stores, alternate runtime settings, another execution identity, newly published issuer paths, and a trust-policy change after the scan require another assessment. Run the check inside each relevant container or runtime context.

The CA file is capped at 32 MiB and 2,048 certificates. Exceeding either bound returns `unknown`. Parsing is linear in the file size; native work is linear in the fixed incident fixture set, with a timeout on each subprocess and an overall scan deadline supplied by the caller. Output diagnostics are classified rather than copied into reports.

OpenSSL option and error semantics: [verification options](https://docs.openssl.org/3.0/man1/openssl-verification-options/) and [verify command](https://docs.openssl.org/3.0/man1/openssl-verify/).
