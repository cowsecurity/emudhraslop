package app

const quickstart = `emudhraslop checks whether TLS clients trust certificates from the eMudhra incident.

Start here (runs client checks against fixed public test sites):
  emudhraslop check --online

For an agent or CI job (JSON, no saved report, no prompts):
  emudhraslop check --online --agent

Check an application's declared runtime and trust settings:
  emudhraslop check --online --services services.json

Other commands:
  emudhraslop inventory             List discovered clients without probing them
  emudhraslop check --offline       Check local evidence without network access
  emudhraslop check --help          Show all check options
  emudhraslop version

Affected means exposure was confirmed for a checked client configuration.
Not affected applies only to the checked scope. Unknown needs investigation.
Automatic discovery does not cover every app, browser or container.

Checks do not change trust settings or install updates. Network access requires
--online. Reports are not cached unless you pass --cache PATH.
Exit codes: 0 not affected; 1 command failed; 2 affected; 3 unknown/incomplete.
`

func commandHelp(command string) string {
	if command == "inventory" {
		return "Usage: emudhraslop inventory [--services services.json] [--agent]\nList client configurations without running probes. Results are unknown until checked.\n\nOptions:"
	}
	return "Usage: emudhraslop check --online [--services services.json] [--agent]\nUse --agent for JSON with no report cache. Omit --online for offline checks.\nUnknown is inconclusive, not a clean bill of health.\nExit codes: 0 not affected; 1 command failed; 2 affected; 3 unknown/incomplete.\n\nOptions:"
}
