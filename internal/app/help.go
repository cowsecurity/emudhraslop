package app

const quickstart = `emudhraslop checks whether TLS clients trust certificates from the eMudhra incident.

Start here (runs client checks against fixed public test sites):
  emudhraslop check --online

For an agent or CI job (JSON, no saved report, no prompts):
  emudhraslop check --online --agent

Check an application's declared runtime and trust settings:
  emudhraslop check --online --services services.json

Include a project's Python virtual environments and installed HTTP clients:
  emudhraslop check --online --project .

Other commands:
  emudhraslop inventory             List discovered clients without probing them
  emudhraslop check --offline       Check local evidence without network access
  emudhraslop check --help          Show all check options
  emudhraslop version
  emudhraslop observation --cache /absolute/path/report.json

Affected means exposure was confirmed for a checked client configuration.
Not affected applies only to the checked scope. Unknown needs investigation.
Automatic discovery does not cover every app, browser or container.
Application status remains UNKNOWN: these checks run isolated clients, not the
running application. A listening port does not establish application exposure.
Missing optional client libraries remain unknown; the scanner installs nothing.

Checks do not change trust settings or install updates. Network access requires
--online. Reports are not cached unless you pass --cache PATH.
Exit codes: 0 not affected; 1 command failed; 2 affected; 3 unknown/incomplete.
`

func commandHelp(command string) string {
	if command == "inventory" {
		return "Usage: emudhraslop inventory [--project DIR | --services services.json] [--agent]\nList client configurations without running probes. Results are unknown until checked.\n\nOptions:"
	}
	return "Usage: emudhraslop check --online [--project DIR | --services services.json] [--agent]\nUse --agent for JSON with no report cache. Omit --online for offline checks.\nUnknown is inconclusive, not a clean bill of health.\nExit codes: 0 not affected; 1 command failed; 2 affected; 3 unknown/incomplete.\n\nOptions:"
}
