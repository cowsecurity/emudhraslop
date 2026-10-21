#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-go}
PYTHON=${PYTHON:-python3}
VERSION=${VERSION:-0.3.0-dev}
if [ "$(uname -s)" = Darwin ]; then
  default_targets='darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/arm/v7 windows/amd64 windows/arm64'
else
  default_targets='linux/amd64 linux/arm64 linux/arm/v7 windows/amd64 windows/arm64'
fi
TARGETS=${TARGETS:-$default_targets}
export VERSION TARGETS
helper_output=''
trap 'if [ -n "$helper_output" ]; then rm -f "$helper_output"; fi' EXIT HUP INT TERM
"$PYTHON" scripts/package-release.py --validate-only
[ ! -L dist ] || { echo 'Refusing symlinked dist directory' >&2; exit 1; }
mkdir -p dist
for target in $TARGETS; do
  platform=${target%%/*}
  if [ "$platform" = darwin ] && [ "$(uname -s)" != Darwin ]; then
    echo 'Darwin release archives require a macOS build host for the native helper' >&2
    exit 1
  fi
  arch=${target#*/}
  target_name=$(printf '%s' "$target" | tr '/' '-')
  destination="dist/$target_name"
  [ ! -L "$destination" ] || { echo 'Refusing symlinked target directory' >&2; exit 1; }
  goarch=$arch
  goarm=''
  [ "$arch" != arm/v7 ] || { goarch=arm; goarm=7; }
  executable=emudhraslop
  [ "$platform" != windows ] || executable=emudhraslop.exe
  mkdir -p "$destination"
  [ ! -L "$destination/$executable" ] || { echo 'Refusing symlinked executable' >&2; exit 1; }
  CGO_ENABLED=0 GOOS="$platform" GOARCH="$goarch" GOARM="$goarm" "$GO" build -trimpath \
    -ldflags "-s -w -X github.com/cowsecurity/emudhraslop/internal/app.Version=$VERSION" -o "$destination/$executable" ./cmd/emudhraslop
  chmod 0555 "$destination/$executable"
  if [ "$platform" = darwin ] && [ "$(uname -s)" = Darwin ]; then
    case "$arch" in amd64) swift_arch=x86_64;; arm64) swift_arch=arm64;; esac
    helper_output=$(mktemp "$destination/.emudhraslop-sectrust.XXXXXX")
    /usr/bin/xcrun swiftc -O -target "$swift_arch-apple-macosx13.0" \
      internal/probe/apple_helper.swift -o "$helper_output"
    chmod 0555 "$helper_output"
    mv -f "$helper_output" "$destination/emudhraslop-sectrust"
    helper_output=''
  fi
done
host_platform=$("$GO" env GOHOSTOS)
host_arch=$("$GO" env GOHOSTARCH)
if [ -f "dist/$host_platform-$host_arch/emudhraslop" ]; then
  /usr/bin/install -m 0555 "dist/$host_platform-$host_arch/emudhraslop" dist/emudhraslop
fi
if [ -f "dist/$host_platform-$host_arch/emudhraslop-sectrust" ]; then
  /usr/bin/install -m 0555 "dist/$host_platform-$host_arch/emudhraslop-sectrust" dist/emudhraslop-sectrust
fi
"$PYTHON" scripts/package-release.py
VERSION="$VERSION" ./scripts/write-checksums.sh
VERSION="$VERSION" CHECKSUM_DIR=dist/releases ./scripts/write-checksums.sh
printf 'Built %s; archives: dist/releases; checksums: dist/releases/SHA256SUMS\n' "$VERSION"
