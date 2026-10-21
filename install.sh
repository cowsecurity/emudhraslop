#!/bin/sh
# Install a verified release for the current user. Never runs the downloaded code.
set -eu
set -f
umask 077
export LC_ALL=C
base=https://github.com/cowsecurity/emudhraslop/releases
version=
bin_dir=${HOME:?HOME must be set}/.local/bin
stage=
lock=
transaction=
helper_changed=
main_changed=
fail() { printf 'emudhraslop: %s\n' "$*" >&2; exit 1; }
cleanup() {
  restore_failed=
  if [ -n "$transaction" ]; then
    for name in emudhraslop emudhraslop-sectrust; do
      case "$name" in
        emudhraslop) [ -n "$main_changed" ] || continue;;
        *) [ -n "$helper_changed" ] || continue;;
      esac
      if [ -f "$stage/previous-$name" ]; then
        mv -f "$stage/previous-$name" "$bin_dir/$name" || restore_failed=1
      else
        rm -f "$bin_dir/$name" || restore_failed=1
      fi
    done
  fi
  if [ -n "$restore_failed" ]; then
    printf 'Rollback failed. Previous files remain in: %s\n' "$stage" >&2
  else
    [ -z "$stage" ] || rm -rf "$stage"
  fi
  [ -z "$lock" ] || rmdir "$lock"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
usage() {
  cat <<'HELP'
Usage: sh install.sh [--version VERSION] [--bin-dir ABSOLUTE_PATH]

Install the latest release into ~/.local/bin, without sudo.
  --version VERSION  Install a release such as 0.1.0 (optional leading v).
  --bin-dir PATH     Choose a directory owned by the current user.
  --help             Show this help.

Requires curl, tar, and sha256sum or shasum. Does not run a scan or edit
shell profiles. Run again to upgrade. macOS also installs its trust helper.
HELP
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0;;
    --version|--bin-dir)
      option=$1; shift
      [ "$#" -gt 0 ] || fail "$option needs a value"
      case "$option" in --version) version=${1#v}; [ -n "$version" ] || fail 'Version must not be empty';; --bin-dir) bin_dir=$1;; esac;;
    *) fail "Unknown option: $1 (see --help)";;
  esac
  shift
done
uid=$(id -u)
[ "$uid" != 0 ] || fail 'Run this installer as your regular user, without sudo.'
for command in curl tar awk mktemp stat uname; do
  command -v "$command" >/dev/null 2>&1 || fail "Missing required command: $command"
done
if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
else fail 'Install sha256sum or shasum to verify the download.'; fi
system=$(uname -s)
arch=$(uname -m)
case "$system" in
  Darwin)
    platform=darwin
    # uname can report x86_64 in a translated terminal on Apple Silicon.
    if [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then arch=arm64; fi;;
  Linux) platform=linux;;
  *) fail "Unsupported operating system: $system";;
esac
case "$arch" in
  x86_64|amd64) arch=amd64;;
  aarch64|arm64) arch=arm64;;
  armv7l|armv7) arch=arm-v7;;
  *) fail "Unsupported architecture: $arch";;
esac
[ "$platform/$arch" != darwin/arm-v7 ] || fail 'Unsupported macOS architecture'
# Reject ambiguous components and shell-control characters before filesystem use.
case "$bin_dir" in
  /*) ;; *) fail '--bin-dir must be an absolute path';;
esac
case "$bin_dir" in
  *'
'*|*"$(printf '\r')"*|*"$(printf '\t')"*|*/../*|*/./*|*/..|*/.|*//*|/) fail 'Use a simple absolute directory path without dot components';;
esac
bin_dir=${bin_dir%/}
metadata() {
  if [ "$system" = Darwin ]; then stat -f '%u %Lp %l %z' "$1"
  else stat -c '%u %a %h %s' "$1"; fi
}
# Check every ancestor before creating children. Root-owned sticky temporary
# parents are allowed; the installation directory itself must be private-owned.
current=
old_ifs=$IFS; IFS=/
set -- $bin_dir
IFS=$old_ifs
for component do
  [ -n "$component" ] || continue
  current=$current/$component
  [ ! -L "$current" ] || fail "Symlinked directory refused: $current"
  if [ ! -e "$current" ]; then mkdir -m 0755 "$current" || fail "Cannot create $current"; fi
  [ -d "$current" ] || fail "Not a directory: $current"
  set -- $(metadata "$current")
  [ "$1" = 0 ] || [ "$1" = "$uid" ] || fail "Directory belongs to another user: $current"
  if [ $((0$2 & 022)) -ne 0 ]; then
    [ "$1" = 0 ] && [ $((0$2 & 01000)) -ne 0 ] && [ "$current" != "$bin_dir" ] || fail "Directory is writable by other users: $current"
  fi
done
set -- $(metadata "$bin_dir")
[ "$1" = "$uid" ] || fail '--bin-dir must belong to the current user'
check_destination() {
  for name in emudhraslop emudhraslop-sectrust; do
    destination=$bin_dir/$name
    [ ! -L "$destination" ] || fail "Symlinked executable refused: $destination"
    if [ -e "$destination" ]; then
      [ -f "$destination" ] || fail "Not a regular file: $destination"
      set -- $(metadata "$destination")
      [ "$1" = "$uid" ] && [ "$3" = 1 ] && [ "$4" -le 67108864 ] && [ $((0$2 & 022)) -eq 0 ] || fail "Unsafe existing executable: $destination"
    fi
  done
}
check_destination
mkdir -m 0700 "$bin_dir/.emudhraslop-install.lock" 2>/dev/null || fail "Another installation may be running. If it has stopped, remove $bin_dir/.emudhraslop-install.lock and retry."
lock=$bin_dir/.emudhraslop-install.lock
stage=$(mktemp -d "$bin_dir/.emudhraslop-install.XXXXXX") || fail 'Cannot create private staging directory'
# ulimit also caps chunked responses on curl versions whose --max-filesize only
# checks Content-Length. Limits are 64 MiB/file and 30 seconds of tar CPU time.
download() (
  ulimit -f 65536
  curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 --max-filesize "$3" --output "$2" "$1"
)
if [ -z "$version" ]; then
  latest=$(curl -q --fail --silent --show-error --head --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 30 --max-filesize 1048576 --output /dev/null \
    --write-out '%{url_effective}' "$base/latest") || fail 'Cannot find the latest release; retry or use --version.'
  case "$latest" in "$base/tag/v"*) version=${latest#"$base/tag/v"};; *) fail 'Unexpected latest-release redirect';; esac
fi
[ "${#version}" -le 128 ] || fail 'Invalid version'
printf '%s\n' "$version" | awk '
  NR == 1 && /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$/ { valid=1; next }
  { bad=1 }
  END { exit (!valid || bad) }' || fail 'Use a release version such as 0.1.0'
archive=emudhraslop-$version-$platform-$arch.tar.gz
printf 'Downloading emudhraslop %s for %s/%s...\n' "$version" "$platform" "$arch"
download "$base/download/v$version/$archive" "$stage/release.tar.gz" 67108864 || fail 'Release download failed; nothing was installed.'
[ "$(wc -c < "$stage/release.tar.gz")" -le 67108864 ] || fail 'Archive exceeds 64 MiB'
download "$base/download/v$version/SHA256SUMS" "$stage/SHA256SUMS" 1048576 || fail 'Checksum download failed; nothing was installed.'
[ "$(wc -c < "$stage/SHA256SUMS")" -le 1048576 ] || fail 'Checksum file exceeds 1 MiB'
expected=$(awk -v name="$archive" '$2 == name { count++; digest=$1 } END {
  if (count != 1 || length(digest) != 64 || digest ~ /[^0-9a-f]/) exit 1; print digest
}' "$stage/SHA256SUMS") || fail 'Release checksum is missing, duplicated or invalid.'
if [ "$hash_tool" = sha256sum ]; then actual=$(sha256sum "$stage/release.tar.gz")
else actual=$(shasum -a 256 "$stage/release.tar.gz"); fi
actual=${actual%% *}
[ "$expected" = "$actual" ] || fail 'Checksum mismatch; nothing was installed.'
bounded_tar() (ulimit -t 30; ulimit -f 65536; tar "$@")
names=emudhraslop
[ "$platform" != darwin ] || names="$names emudhraslop-sectrust"
for name in $names; do
  # Reading a named regular member to stdout never extracts archive paths,
  # owners, permissions, links, or accompanying files into the filesystem.
  bounded_tar -tzf "$stage/release.tar.gz" "$name" > "$stage/list" || fail "Missing archive member: $name"
  awk -v name="$name" 'NR != 1 || $0 != name { bad=1 } END { exit (bad || NR != 1) }' "$stage/list" || fail "Duplicate or unexpected archive member: $name"
  bounded_tar -tvzf "$stage/release.tar.gz" "$name" > "$stage/type" || fail 'Invalid release archive'
  awk 'NR != 1 || substr($0,1,1) != "-" { bad=1 } END { exit (bad || NR != 1) }' "$stage/type" || fail "Archive member is not a regular file: $name"
  bounded_tar -xOzf "$stage/release.tar.gz" "$name" > "$stage/$name" || fail 'Cannot unpack verified release'
  [ -s "$stage/$name" ] || fail "Empty release executable: $name"
  chmod 0755 "$stage/$name"
done
check_destination
# Install the helper first, then atomically replace the command. Staged files
# share the destination filesystem, so replacing a running binary is safe.
for name in $names; do
  if [ -f "$bin_dir/$name" ]; then cp -p "$bin_dir/$name" "$stage/previous-$name"; fi
done
transaction=1
if [ "$platform" = darwin ]; then
  helper_changed=1
  mv -f "$stage/emudhraslop-sectrust" "$bin_dir/emudhraslop-sectrust" || fail 'Cannot install helper; restoring previous installation.'
fi
main_changed=1
mv -f "$stage/emudhraslop" "$bin_dir/emudhraslop" || fail 'Cannot install command; restoring previous installation.'
transaction=
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
printf '\nInstalled emudhraslop %s. Run:\n  ' "$version"
quote "$bin_dir/emudhraslop"; printf ' check --online\n\nFor agents:\n  '
quote "$bin_dir/emudhraslop"; printf ' check --online --agent\n'
case ":${PATH:-}:" in *":$bin_dir:"*) ;; *) printf '\nThis directory is not on PATH. Use the absolute command above.\n';; esac
