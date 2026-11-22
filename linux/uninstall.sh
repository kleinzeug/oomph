#!/bin/sh
# Removes what linux/install.sh installed for this user: the skill and the MCP server from Claude
# Code (when they were set up), ~/.local/bin/oomph, ~/.local/lib/oomph and every version beside it.
# The ledger and settings in ~/.local/state/oomph are kept unless --purge is given.
set -eu
[ "$(uname -s)" = Linux ] || { echo "oomph: linux/uninstall.sh is for Linux (on a Mac: sudo ./uninstall.sh)" >&2; exit 1; }
# root only as itself (a container, `su -`): installs into root's own ~/.local; never for someone under sudo
if [ "$(id -u)" = 0 ]; then
  case "${SUDO_UID:-0}${SUDO_USER:-root}" in 0root) ;; *) echo "oomph: run linux/uninstall.sh as the user who installed it, without sudo" >&2; exit 1 ;; esac
  RHOME=$(getent passwd 0 2>/dev/null | cut -d: -f6 || true)
  [ -n "$RHOME" ] || RHOME=$(awk -F: '$3 == 0 { print $6; exit }' /etc/passwd 2>/dev/null || true)
  [ -n "${HOME:-}" ] && [ -n "$RHOME" ] && [ "$(cd "$HOME" 2>/dev/null && pwd -P)" = "$(cd "$RHOME" 2>/dev/null && pwd -P)" ] || {
    echo "oomph: as root, HOME must be root's own folder ($RHOME), not ${HOME:-unset}" >&2; exit 1; }
fi
PURGE=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    *) echo "oomph: linux/uninstall.sh: unknown option $a (usage: linux/uninstall.sh [--purge])" >&2; exit 2 ;;
  esac
done
LIBDIR="$HOME/.local/lib"
BIN="$HOME/.local/bin/oomph"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/oomph"
case "$STATE" in /*) ;; *) STATE="$HOME/.local/state/oomph" ;; esac
if [ -x "$LIBDIR/oomph/oomph.py" ] && [ -d "$HOME/.claude" ]; then
  "$LIBDIR/oomph/oomph.py" setup-claude --remove >/dev/null 2>&1 || true
  echo "oomph: removed the skill and the MCP server from Claude Code"
fi
case "$(readlink "$BIN" 2>/dev/null || true)" in "$LIBDIR"/oomph/*|"$LIBDIR"/oomph-*/*) rm -f "$BIN" ;; esac
rm -f "$HOME"/.local/bin/.oomph.link.* "$LIBDIR"/.oomph.link.*
[ ! -L "$LIBDIR/oomph" ] || rm -f "$LIBDIR/oomph"
for d in "$LIBDIR"/oomph-* "$LIBDIR"/.oomph-new.*; do
  if [ -d "$d" ] && [ ! -L "$d" ]; then rm -rf "$d"; fi
done
if [ "$PURGE" = 1 ]; then
  rm -rf "$STATE"
  echo "oomph: removed (the ledger and settings in $STATE too)"
else
  echo "oomph: removed (your ledger and settings stay in $STATE; --purge removes them)"
fi
