#!/bin/sh
# oomph on Linux. Two ways, from a checkout:
#
#   git clone https://github.com/kleinzeug/oomph.git && oomph/linux/install.sh [--no-claude]
#       for the user who runs it, no root (1.9.4): checks, reservations, `oomph run`, the MCP server, the
#       hook and `oomph top` measure live, and the ledger is your own (~/.local/state/oomph/ledger/<machine>).
#       The code goes into ~/.local/lib/oomph-<version>, ~/.local/lib/oomph is a link to it (swapped by one
#       rename, so a running MCP server keeps importing from its own directory) and ~/.local/bin/oomph a link
#       to its oomph.py. Then, when Claude Code is here, `oomph setup-claude`; --no-claude skips that.
#
#   sudo oomph/linux/install.sh --system [--no-journal]
#       for the machine, root once (1.13.0): the logger as the systemd service oomphd (user oomphd, no
#       capability, no network) with history, incidents and kills by name in /var/log/oomph; the machine's
#       ledger /var/lib/oomph/ledger, open to every local account as on a Mac (`oomph doctor` says how to
#       keep it to a group); alert hooks in /etc/oomph/alert.d; the code in /usr/local/libexec/oomph-<version>
#       and /usr/local/bin/oomph. --no-journal: the logger stays out of group systemd-journal and counts
#       kills without names. OOMPH_INSTALL_ROOT=DIR installs the files below DIR instead (tests: no
#       accounts, no systemd).
#
# Versions replaced more than 7 days ago are removed. Run it again to update; linux/uninstall.sh
# [--system] [--purge] removes it.
set -eu
REPO=https://github.com/kleinzeug/oomph.git
[ "$(uname -s)" = Linux ] || { echo "oomph: linux/install.sh is for Linux (on a Mac: ./build-app.sh, then Activate in the app)" >&2; exit 1; }
CLAUDE=1
SYSTEM=0
JOURNAL=1
for a in "$@"; do
  case "$a" in
    --no-claude) CLAUDE=0 ;;
    --system) SYSTEM=1 ;;
    --no-journal) JOURNAL=0 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "oomph: linux/install.sh: unknown option $a (usage: linux/install.sh [--no-claude] | --system [--no-journal])" >&2; exit 2 ;;
  esac
done
[ "$SYSTEM" = 1 ] || [ "$JOURNAL" = 1 ] || { echo "oomph: --no-journal goes with --system" >&2; exit 2; }
# root only as itself (a container, `su -`): installs into root's own ~/.local; never for someone under sudo
if [ "$SYSTEM" = 0 ] && [ "$(id -u)" = 0 ]; then
  case "${SUDO_UID:-0}${SUDO_USER:-root}" in 0root) ;; *) echo "oomph: run linux/install.sh as yourself, without sudo: it installs into your ~/.local (for the whole machine: sudo linux/install.sh --system)" >&2; exit 1 ;; esac
  RHOME=$(getent passwd 0 2>/dev/null | cut -d: -f6 || true)
  [ -n "$RHOME" ] || RHOME=$(awk -F: '$3 == 0 { print $6; exit }' /etc/passwd 2>/dev/null || true)
  [ -n "${HOME:-}" ] && [ -n "$RHOME" ] && [ "$(cd "$HOME" 2>/dev/null && pwd -P)" = "$(cd "$RHOME" 2>/dev/null && pwd -P)" ] || {
    echo "oomph: as root, HOME must be root's own folder ($RHOME), not ${HOME:-unset}" >&2; exit 1; }
fi
PFX=""
if [ "$SYSTEM" = 1 ]; then
  PFX="${OOMPH_INSTALL_ROOT:-}"
  if [ -n "$PFX" ]; then
    case "$PFX" in /?*) ;; *) echo "oomph: OOMPH_INSTALL_ROOT must be an absolute path" >&2; exit 1 ;; esac
    [ -d "$PFX" ] || { echo "oomph: OOMPH_INSTALL_ROOT $PFX is not a directory" >&2; exit 1; }
    [ "$(id -u)" != 0 ] || { echo "oomph: OOMPH_INSTALL_ROOT is for tests, not for root" >&2; exit 1; }
  else
    [ "$(id -u)" = 0 ] || { echo "oomph: linux/install.sh --system must run as root: sudo $0 --system" >&2; exit 1; }
  fi
else
  [ -n "${HOME:-}" ] && [ -d "$HOME" ] || { echo "oomph: HOME is not a folder" >&2; exit 1; }
fi
HERE=$(cd "$(dirname "$0")/.." && pwd -P)
SRC="$HERE/daemon"
[ -f "$SRC/oomph.py" ] && [ -f "$SRC/oomph_linux.py" ] || { echo "oomph: run it from a checkout ($REPO)" >&2; exit 1; }

# Python 3.9 or newer: /usr/bin/python3, else the newest /usr/bin/python3.N (RHEL 8: dnf install python39)
new_enough() { "$1" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; }
PY=""
if [ -x /usr/bin/python3 ] && new_enough /usr/bin/python3; then
  PY=/usr/bin/python3
else
  for n in 14 13 12 11 10 9; do
    for c in /usr/bin/python3.$n /usr/local/bin/python3.$n; do
      if [ -z "$PY" ] && [ -x "$c" ] && new_enough "$c"; then PY=$c; fi
    done
  done
fi
[ -n "$PY" ] || { echo "oomph: needs Python 3.9 or newer (Debian/Ubuntu: sudo apt install python3; RHEL 8: sudo dnf install python39)" >&2; exit 1; }

if [ "$SYSTEM" = 1 ]; then
  LIBDIR="$PFX/usr/local/libexec"
  BINDIR="$PFX/usr/local/bin"
  umask 022
else
  LIBDIR="$HOME/.local/lib"
  BINDIR="$HOME/.local/bin"
fi
LIB="$LIBDIR/oomph"
BIN="$BINDIR/oomph"
KEEP_DAYS=7
mkdir -p "$LIBDIR" "$BINDIR"
swap() {  # swap TARGET LINK: point LINK at TARGET by renaming a new link over it (atomic, also over a link to a directory)
  "$PY" -I -c 'import os, secrets, sys
t, l = sys.argv[1], sys.argv[2]
tmp = os.path.join(os.path.dirname(l), ".%s.link.%s" % (os.path.basename(l), secrets.token_hex(4)))
os.symlink(t, tmp)
os.replace(tmp, l)' "$1" "$2"
}

# 1. the new version, complete, in a directory of its own
NEW=$(mktemp -d "$LIBDIR/.oomph-new.XXXXXX")
trap 'rm -rf "$NEW"' EXIT
for f in oomph.py oomphd.py oomph_linux.py oomph_ai.py oomph_upgrade.py oomph_top.py oomph_view.py oomph_net.py oomph_sync.py oomph_gpu.py oomph_traffic.py; do
  cp "$SRC/$f" "$NEW/$f"
done
mkdir -p "$NEW/skills/oomph"
cp "$HERE/skills/oomph/SKILL.md" "$NEW/skills/oomph/SKILL.md"
mkdir -p "$NEW/alert.d.examples"
for f in "$HERE"/linux/alert.d.examples/*; do cp "$f" "$NEW/alert.d.examples/"; done
gitver() {  # tools/version.sh; as root, as the checkout's owner (git refuses another user's folder, and must not leave root's files there)
  u=$(stat -c %u "$HERE" 2>/dev/null || echo 0)
  if [ "$(id -u)" = 0 ] && [ "$u" != 0 ] && command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid="$u" --regid="$(stat -c %g "$HERE")" --clear-groups "$HERE/tools/version.sh" "$@" 2>/dev/null ||
      "$HERE/tools/version.sh" "$@"
  else
    "$HERE/tools/version.sh" "$@"
  fi
}
VER=$(gitver 2>/dev/null || echo 0.0.0-nogit)
COMMIT=$(gitver --commit 2>/dev/null || true)
# stamp the version and this Python into oomph.py (with Python: sed -i differs between systems)
"$PY" -I -c 'import re, sys
p, ver, commit, py = sys.argv[1:5]
s = open(p).read()
s = re.sub(r"\A#![^\n]*", "#!%s -I" % py, s, count=1)
s = re.sub(r"(?m)^VERSION = \"dev\".*$", "VERSION = \"%s\"" % ver, s, count=1)
s = re.sub(r"(?m)^COMMIT = \"\".*$", "COMMIT = \"%s\"" % commit, s, count=1)
open(p, "w").write(s)' "$NEW/oomph.py" "$VER" "$COMMIT" "$PY"
# bytecode, once: every command imports instead of compiling, and oomph top starts again on it
(umask 022; "$PY" -I -m compileall -q "$NEW" >/dev/null 2>&1) || true
chmod 755 "$NEW" "$NEW/oomph.py" "$NEW/oomphd.py"
[ "$SYSTEM" = 0 ] || chmod -R go-w,a+rX "$NEW"   # root's code: nobody else may change what the service runs
NAME="oomph-$(printf '%s' "$VER" | tr -c 'A-Za-z0-9._+-' '_')"
CUR=$(readlink "$LIB" 2>/dev/null || true)
same() { [ -d "$2" ] && [ ! -L "$2" ] && diff -r -x __pycache__ "$1" "$2" >/dev/null 2>&1; }
if [ -n "$CUR" ] && same "$NEW" "$LIBDIR/$CUR"; then
  NAME="$CUR"; rm -rf "$NEW"               # the same files are installed already
elif same "$NEW" "$LIBDIR/$NAME"; then
  rm -rf "$NEW"
else
  [ ! -e "$LIBDIR/$NAME" ] || NAME="$NAME-$(date +%Y%m%d%H%M%S)"
  mv "$NEW" "$LIBDIR/$NAME"
fi
trap - EXIT

# 2. the switch: one rename of a link, then the command
OLD=$(readlink "$LIB" 2>/dev/null || true)
[ ! -e "$LIB" ] || [ -L "$LIB" ] || { echo "oomph: $LIB is not a link this installer made; move it away first" >&2; exit 1; }
[ "$OLD" = "$NAME" ] || swap "$NAME" "$LIB"
[ -z "$OLD" ] || [ "$OLD" = "$NAME" ] || [ ! -d "$LIBDIR/$OLD" ] || touch "$LIBDIR/$OLD"  # its time says when it was replaced
[ ! -e "$BIN" ] || [ -L "$BIN" ] || { echo "oomph: $BIN exists and is not a link; move it away first" >&2; exit 1; }
[ "$(readlink "$BIN" 2>/dev/null)" = "$LIB/oomph.py" ] || swap "$LIB/oomph.py" "$BIN"

# 3. versions replaced more than KEEP_DAYS ago, and leftovers of interrupted installs
for d in "$LIBDIR"/oomph-* "$LIBDIR"/.oomph-new.*; do
  [ -d "$d" ] && [ ! -L "$d" ] && [ "$d" != "$LIBDIR/$NAME" ] || continue
  if [ -n "$(find "$d" -prune -mtime +"$KEEP_DAYS")" ]; then rm -rf "$d"; fi
done

if [ "$SYSTEM" = 1 ]; then
  . "$HERE/linux/system.sh"
  exit 0
fi

echo "oomph: installed $VER into $LIBDIR/$NAME (python: $PY)"
echo "oomph: the command is $BIN"
case ":${PATH:-}:" in
  *":$BINDIR:"*) ;;
  *) echo "oomph: $BINDIR is not on your PATH; add it, e.g.: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.profile" ;;
esac
if [ "$CLAUDE" = 1 ] && { command -v claude >/dev/null 2>&1 || [ -d "$HOME/.claude" ]; }; then
  "$BIN" setup-claude || echo "oomph: setting up Claude Code failed; run: $BIN setup-claude" >&2
elif [ "$CLAUDE" = 1 ]; then
  echo "oomph: Claude Code is not set up for this user; once it is, run: $BIN setup-claude"
fi
echo "oomph: try: oomph doctor · oomph check · oomph top   (every reading is live; history, incidents and a ledger for"
echo "       every account on this machine come with the logger: sudo $HERE/linux/install.sh --system)"
