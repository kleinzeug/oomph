#!/bin/sh
# Removes what linux/install.sh installed.
#
#   linux/uninstall.sh [--purge]            for this user: the skill and the MCP server from Claude Code
#       (when they were set up), ~/.local/bin/oomph, ~/.local/lib/oomph and every version beside it. The
#       ledger and settings in ~/.local/state/oomph are kept unless --purge is given.
#   sudo linux/uninstall.sh --system [--purge]   for the machine: the service oomphd and the alert units,
#       /usr/local/bin/oomph and /usr/local/libexec/oomph*. The logs, the ledger, /etc/oomph and the account
#       oomphd are kept unless --purge is given (the ledger then is emptied by a child as nobody: root opens
#       nothing in a folder every account can write). OOMPH_INSTALL_ROOT=DIR: below DIR (tests).
set -eu
[ "$(uname -s)" = Linux ] || { echo "oomph: linux/uninstall.sh is for Linux (on a Mac: sudo ./uninstall.sh)" >&2; exit 1; }
PURGE=0
SYSTEM=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    --system) SYSTEM=1 ;;
    *) echo "oomph: linux/uninstall.sh: unknown option $a (usage: linux/uninstall.sh [--system] [--purge])" >&2; exit 2 ;;
  esac
done
if [ "$SYSTEM" = 1 ]; then
  PFX="${OOMPH_INSTALL_ROOT:-}"
  if [ -n "$PFX" ]; then
    case "$PFX" in /?*) ;; *) echo "oomph: OOMPH_INSTALL_ROOT must be an absolute path" >&2; exit 1 ;; esac
    [ "$(id -u)" != 0 ] || { echo "oomph: OOMPH_INSTALL_ROOT is for tests, not for root" >&2; exit 1; }
  else
    [ "$(id -u)" = 0 ] || { echo "oomph: linux/uninstall.sh --system must run as root: sudo $0 --system" >&2; exit 1; }
  fi
  UNITS="$PFX/etc/systemd/system"
  if [ -z "$PFX" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now oomphd.service oomph-alert.path >/dev/null 2>&1 || true
    systemctl stop oomph-alert.service >/dev/null 2>&1 || true
  fi
  rm -f "$UNITS/oomphd.service" "$UNITS/oomph-alert.service" "$UNITS/oomph-alert.path" \
    "$UNITS/oomphd.service.d/20-nvidia.conf"
  rmdir "$UNITS/oomphd.service.d" 2>/dev/null || true
  [ -n "$PFX" ] || ! command -v systemctl >/dev/null 2>&1 || systemctl daemon-reload
  LIBDIR="$PFX/usr/local/libexec"
  BIN="$PFX/usr/local/bin/oomph"
  case "$(readlink "$BIN" 2>/dev/null || true)" in "$LIBDIR"/oomph/*|"$LIBDIR"/oomph-*/*|/usr/local/libexec/oomph/*) rm -f "$BIN" ;; esac
  [ ! -L "$LIBDIR/oomph" ] || rm -f "$LIBDIR/oomph"
  for d in "$LIBDIR"/oomph-* "$LIBDIR"/.oomph-new.*; do
    if [ -d "$d" ] && [ ! -L "$d" ]; then rm -rf "$d"; fi
  done
  if [ "$PURGE" = 1 ]; then
    L="$PFX/var/lib/oomph/ledger"
    if [ -d "$L" ] && [ ! -L "$L" ]; then
      if [ -z "$PFX" ]; then   # emptied as nobody, then removed: root opens nothing in it
        G=$(stat -c %g "$L")   # with the ledger's group (doctor's way of keeping it to one: 2770), never root's
        [ "$G" != 0 ] || G=$(id -g nobody)
        setpriv --reuid=nobody --regid="$G" --clear-groups find "$L" -mindepth 1 -delete 2>/dev/null || true
      else
        find "$L" -mindepth 1 -delete
      fi
      rmdir "$L" 2>/dev/null || echo "oomph: $L is not empty (something in it is not nobody's to remove); left as it is" >&2
    fi
    rm -rf "$PFX/var/lib/oomph/daemon" "$PFX/var/log/oomph" "$PFX/etc/oomph" "$PFX/var/lib/private/oomph-alert"
    [ ! -L "$PFX/var/lib/oomph-alert" ] || rm -f "$PFX/var/lib/oomph-alert"   # the alert runner's cursor (DynamicUser)
    rmdir "$PFX/var/lib/oomph" 2>/dev/null || true
    if [ -z "$PFX" ] && getent passwd oomphd >/dev/null 2>&1; then userdel oomphd 2>/dev/null || true; fi
    echo "oomph: removed the logger, its logs, the ledger and the account oomphd"
  else
    echo "oomph: removed the logger (its logs in /var/log/oomph, the ledger and the account oomphd stay; --purge removes them)"
  fi
  exit 0
fi
# root only as itself (a container, `su -`): installs into root's own ~/.local; never for someone under sudo
if [ "$(id -u)" = 0 ]; then
  case "${SUDO_UID:-0}${SUDO_USER:-root}" in 0root) ;; *) echo "oomph: run linux/uninstall.sh as the user who installed it, without sudo (for the machine: --system)" >&2; exit 1 ;; esac
  RHOME=$(getent passwd 0 2>/dev/null | cut -d: -f6 || true)
  [ -n "$RHOME" ] || RHOME=$(awk -F: '$3 == 0 { print $6; exit }' /etc/passwd 2>/dev/null || true)
  [ -n "${HOME:-}" ] && [ -n "$RHOME" ] && [ "$(cd "$HOME" 2>/dev/null && pwd -P)" = "$(cd "$RHOME" 2>/dev/null && pwd -P)" ] || {
    echo "oomph: as root, HOME must be root's own folder ($RHOME), not ${HOME:-unset}" >&2; exit 1; }
fi
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
