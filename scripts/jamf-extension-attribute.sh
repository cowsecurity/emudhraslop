#!/bin/sh
# Jamf last observation: never a fresh verdict, runtime execution or scan.
set -eu
checker='/Library/Emudhraslop/bin/emudhraslop'
cache='/Library/Application Support/Emudhraslop/status.json'
status=unknown
if [ -x "$checker" ]; then
  if candidate=$("$checker" observation --cache "$cache" --max-age 24h 2>/dev/null); then
    case "$candidate" in observed_affected|observed_not_affected|observed_unknown) status=$candidate;; esac
  fi
fi
printf '<result>%s</result>\n' "$status"
