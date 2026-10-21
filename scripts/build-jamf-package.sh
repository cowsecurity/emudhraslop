#!/bin/sh
# Build an installer; does not install it or contact Jamf.
set -eu
umask 077
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Darwin ] || { echo 'macOS packaging requires macOS' >&2; exit 1; }
VERSION=${VERSION:-0.3.0-dev}
PYTHON=${PYTHON:-python3}
SERVICES_FILE=${SERVICES_FILE:-}
SCAN_MODE=${SCAN_MODE:-online}
case "$SCAN_MODE" in online|offline) ;; *) echo 'SCAN_MODE must be online or offline' >&2; exit 1;; esac
SIGNING_IDENTITY=${SIGNING_IDENTITY:-}
INSTALLER_IDENTITY=${INSTALLER_IDENTITY:-}
case "$VERSION" in *[!a-zA-Z0-9.+_-]*|'') echo 'Invalid VERSION' >&2; exit 1;; esac
[ -n "$SERVICES_FILE" ] && [ -f "$SERVICES_FILE" ] || {
  echo 'Set SERVICES_FILE to the reviewed deployment manifest' >&2; exit 1;
}
# Syntax check only: execution identity and paths belong to the target machine.
# The reviewed manifest is validated by the scanner on that machine.
"$PYTHON" - "$SERVICES_FILE" <<'PYJSON'
import json
import sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result

def invalid_constant(value):
    raise ValueError("non-JSON constant")

try:
    with open(sys.argv[1], "rb") as source:
        data = source.read((1 << 20) + 1)
    if len(data) > 1 << 20:
        raise ValueError("manifest size limit")
    manifest = json.loads(data, object_pairs_hook=unique,
                          parse_constant=invalid_constant)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "services"}:
        raise ValueError("manifest fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("manifest version")
    if not isinstance(manifest["services"], list) or not 1 <= len(manifest["services"]) <= 256:
        raise ValueError("manifest service count")
except (OSError, ValueError, RecursionError):
    raise SystemExit("Invalid service manifest syntax or schema envelope")
PYJSON
for arch in amd64 arm64; do
  [ -f "dist/darwin-$arch/emudhraslop" ] || { echo 'Run make release first' >&2; exit 1; }
  [ -f "dist/darwin-$arch/emudhraslop-sectrust" ] || { echo 'Build Apple helpers on macOS first' >&2; exit 1; }
done
mkdir -p dist
stage=$(mktemp -d "${TMPDIR:-/tmp}/emudhraslop-pkg.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
root="$stage/root"
mkdir -p "$root/Library/Emudhraslop/bin" "$root/Library/LaunchDaemons" \
  "$root/Library/Application Support/Emudhraslop"
chmod 0755 "$root" "$root/Library" "$root/Library/Emudhraslop" \
  "$root/Library/Emudhraslop/bin" "$root/Library/LaunchDaemons" \
  "$root/Library/Application Support"
chmod 0700 "$root/Library/Application Support/Emudhraslop"
/usr/bin/lipo -create dist/darwin-amd64/emudhraslop dist/darwin-arm64/emudhraslop \
  -output "$root/Library/Emudhraslop/bin/emudhraslop"
chmod 0555 "$root/Library/Emudhraslop/bin/emudhraslop"
/usr/bin/lipo -create dist/darwin-amd64/emudhraslop-sectrust dist/darwin-arm64/emudhraslop-sectrust \
  -output "$root/Library/Emudhraslop/bin/emudhraslop-sectrust"
chmod 0555 "$root/Library/Emudhraslop/bin/emudhraslop-sectrust"
if [ -n "$SIGNING_IDENTITY" ]; then
  /usr/bin/codesign --force --options runtime --timestamp --sign "$SIGNING_IDENTITY" \
    "$root/Library/Emudhraslop/bin/emudhraslop-sectrust"
  /usr/bin/codesign --force --options runtime --timestamp --sign "$SIGNING_IDENTITY" \
    "$root/Library/Emudhraslop/bin/emudhraslop"
  /usr/bin/codesign --verify --strict "$root/Library/Emudhraslop/bin/emudhraslop"
  /usr/bin/codesign --verify --strict "$root/Library/Emudhraslop/bin/emudhraslop-sectrust"
else
  echo 'Building without a publisher code-signing identity' >&2
fi
cp "$SERVICES_FILE" "$root/Library/Application Support/Emudhraslop/services.json"
chmod 0600 "$root/Library/Application Support/Emudhraslop/services.json"
cp examples/jamf/io.emudhraslop.scan.plist "$root/Library/LaunchDaemons/"
chmod 0644 "$root/Library/LaunchDaemons/io.emudhraslop.scan.plist"
/usr/libexec/PlistBuddy -c "Set :ProgramArguments:2 --$SCAN_MODE" \
  "$root/Library/LaunchDaemons/io.emudhraslop.scan.plist"
/usr/bin/plutil -lint "$root/Library/LaunchDaemons/io.emudhraslop.scan.plist"
# Clear removable extended attributes before archiving the staged payload.
chmod 0755 "$root/Library/Emudhraslop/bin/emudhraslop" "$root/Library/Emudhraslop/bin/emudhraslop-sectrust"
/usr/bin/xattr -cr "$root"
chmod 0555 "$root/Library/Emudhraslop/bin/emudhraslop" "$root/Library/Emudhraslop/bin/emudhraslop-sectrust"
unsigned="$stage/emudhraslop-unsigned.pkg"
/usr/bin/pkgbuild --root "$root" --ownership recommended \
  --identifier io.emudhraslop.agent --version "$VERSION" --install-location / "$unsigned"
destination="dist/emudhraslop-$VERSION.pkg"
if [ -n "$INSTALLER_IDENTITY" ]; then
  /usr/bin/productsign --sign "$INSTALLER_IDENTITY" --timestamp "$unsigned" "$destination"
  /usr/sbin/pkgutil --check-signature "$destination"
else
  cp "$unsigned" "$destination"
  echo 'Installer is unsigned; no notarization was performed' >&2
fi
VERSION="$VERSION" ./scripts/write-checksums.sh
printf 'Created %s (%s scans); daemon remains unloaded until your reviewed Jamf policy enables it.\n' "$destination" "$SCAN_MODE"
