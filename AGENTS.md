# Emudhraslop

Standalone read-only TLS trust checker. Keep the tool vendor-neutral.

- Never equate network failure, a package version, or the scanner's own TLS verifier with target-runtime protection.
- Every omitted or incomplete context must remain visible as Unknown.
- No credentials, complete process arguments, complete environments or private keys in reports.
- Never invoke discovered user-controlled binaries or imports as root. Root execution requires explicit opt-in and trusted managed paths.
- Fixture certificates are public data. Verify embedded hashes and certificate identities before probing.
- Keep files below 500 lines; prefer below 300. Use meaningful adversarial tests and real native-client checks.
- Do not start development servers. Test fixture servers may run only inside bounded tests.
- No package installation or remediation during a scan. No Docker socket or host mounts are required.
