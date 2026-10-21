# Security design

The checker is a local, read-only assessment tool. It crosses boundaries when reading a service manifest, parsing public certificates, invoking a native runtime, contacting fixed test hosts, and writing a report/cache. No telemetry is sent to a vendor.

| Risk | Boundary | Control |
| --- | --- | --- |
| False protection after blocked egress or generic TLS failure | Native result to security verdict | Attribute proof to the declared client and fixture; ambiguous failure stays unknown |
| Poisoned incident fixtures | Embedded public data to probe | Verify payload hashes and certificate/SPKI identities before use; no private keys |
| Root execution of attacker-owned code | Discovered executable to subprocess | Default deny; explicit service UID/GID privilege drop, or reviewed root opt-in with trusted paths |
| Environment injection | Manifest to native process | Allowlisted TLS/proxy settings, isolated working directory, no inherited complete environment or preload hooks |
| Unbounded or hung runtime | Child process to scanner | Bounded concurrency, deadline, process-group cleanup, capped output |
| Secret disclosure | Runtime/configuration to report | No full environments, arguments, private keys, or raw credential-bearing errors |
| Stale result presented as current | Cache to decision | Age and configuration/file identity validation; invalid cache stays unknown |
| Scanner container measures the wrong trust store | Deployment to assessment scope | Execute within the actual application image and user; declare exclusions |
| Modified release binary or installer | Build to distribution | Pinned toolchain and actions; fixed HTTPS release source; exact unique archive checksum before installation; installer source is taken from the tagged checkout |
| Archive or destination redirects writes | Download to local installation | Private staging; expected executable entries only; symlink/reparse and unsafe destination rejection; preserve prior installation on failed validation |
| Terminal control sequences disguise a finding | Runtime/path to human output | Escape untrusted control characters; JSON retains the structured evidence |
| Easier commands silently broaden behavior | CLI to probe/cache | Online mode stays explicit; agent mode never prompts or caches; normal checks cache only with an explicit destination |
| Jamf inventory causes expensive scans | Extension attribute to endpoint | Cache-only read; scheduled bounded scan is separate |

No remote authentication, authorization API, multi-tenant storage, or inbound listener is introduced. The relevant components are business logic, local privilege boundaries, privacy, cryptographic identity, supply chain, infrastructure, networking, and logging.

The operating system, executable binaries, deployment manifest, and approved artifact distributor remain trust assumptions. Checking a binary's path and ownership cannot establish that the binary itself is uncompromised. This tool does not detect active attackers or establish whether credentials were stolen.

Public source: [eMudhra incident and fixture material](https://emudhra.we-have-a-problem.com/). A release must rerun certificate validity and fixture identity checks; stale fixtures cannot support a current `not_affected` verdict. Agents must preserve unknown/null decisions rather than converting missing evidence into a negative finding.
