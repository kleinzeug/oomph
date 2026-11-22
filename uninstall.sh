#!/bin/bash
# Stops and removes the oomph daemon: the LaunchDaemon, /usr/local/bin/oomph, the link
# /usr/local/libexec/oomph and every installed version beside it. Logs and the settings in
# /Library/Application Support/oomph are kept unless --purge is given.
# OOMPH_INSTALL_ROOT=<dir> removes what install.sh put below that directory (tests); as root,
# only for a directory that root owns all the way up and nobody else can change.
set -euo pipefail
root_only() {  # root_only DIR: DIR and every folder above it root's, not writable by others (sticky is fine)
  local d u m
  d=$(cd "$1" && pwd -P) || return 1
  while :; do
    read -r u m < <(/usr/bin/stat -f '%u %p' "$d") || return 1
    [ "$u" = 0 ] || return 1
    [ $(( 8#$m & 8#22 )) = 0 ] || [ $(( 8#$m & 8#1000 )) != 0 ] || return 1
    [ "$d" = / ] && return 0
    d=$(dirname "$d")
  done
}
PFX="${OOMPH_INSTALL_ROOT:-}"
if [ -n "$PFX" ]; then
  case "$PFX" in /?*) ;; *) echo "oomph: OOMPH_INSTALL_ROOT must be an absolute path" >&2; exit 1 ;; esac
  [ "$(id -u)" != 0 ] || root_only "$PFX" || {
    echo "oomph: as root, OOMPH_INSTALL_ROOT must be root's all the way up and writable by nobody else" >&2; exit 1; }
else
  [ "$(id -u)" = 0 ] || { echo "oomph: uninstall.sh must run as root (sudo ./uninstall.sh)" >&2; exit 1; }
  launchctl bootout system/local.oomph.daemon 2>/dev/null || true
fi
rm -f "$PFX/Library/LaunchDaemons/local.oomph.daemon.plist" "$PFX/usr/local/bin/oomph" "$PFX"/usr/local/bin/.oomph.link.*
rm -rf "$PFX/usr/local/libexec/oomph" "$PFX"/usr/local/libexec/oomph-* "$PFX"/usr/local/libexec/.oomph-new.* \
       "$PFX"/usr/local/libexec/.oomph.link.*
if [ "${1:-}" = "--purge" ]; then
  rm -rf "$PFX/Library/Logs/oomph" "$PFX/Library/Application Support/oomph"
  echo "oomph: removed (logs and settings purged)"
else
  echo "oomph: removed (logs kept in /Library/Logs/oomph)"
fi
