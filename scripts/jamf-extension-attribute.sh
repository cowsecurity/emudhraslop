#!/bin/sh
# Jamf extension attribute: cache validation only, never a scan.
set -eu
checker='/Library/Emudhraslop/bin/emudhraslop'
config='/Library/Application Support/Emudhraslop/services.json'
cache='/Library/Application Support/Emudhraslop/status.json'
status=unknown
if [ -x "$checker" ] && [ -f "$config" ]; then
  report=$("$checker" check --cached --services "$config" --cache "$cache" --json 2>/dev/null) || :
  candidate=$(printf '%s' "$report" | /usr/bin/plutil -extract status raw -o - - 2>/dev/null) || :
  case "$candidate" in affected|not_affected|unknown) status=$candidate;; esac
fi
printf '<result>%s</result>\n' "$status"
