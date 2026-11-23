#!/bin/sh
# oomph on Linux, for agents (1.9.4): installs this checkout for the user who runs it. No root, no
# service: checks, reservations, `oomph run`, the MCP server, the hook and `oomph top` measure live,
# and the reservation ledger is your own (~/.local/state/oomph/ledger/<machine id>). A logger for the
# whole machine, with history and incidents, comes in a later release.
#
#   git clone https://github.com/kleinzeug/oomph.git && oomph/linux/install.sh [--no-claude]
#
# The code goes into ~/.local/lib/oomph-<version>, ~/.local/lib/oomph is a link to it (swapped by
# one rename, so a running MCP server keeps importing from its own directory) and ~/.local/bin/oomph
# a link to its oomph.py. Versions replaced more than 7 days ago are removed. Then, when Claude Code
# is here (`claude` on the PATH, or ~/.claude), `oomph setup-claude` installs the skill and registers
# the MCP server; --no-claude skips that. Run it again to update; linux/uninstall.sh removes it.
set -eu
REPO=https://github.com/kleinzeug/oomph.git
[ "$(uname -s)" = Linux ] || { echo "oomph: linux/install.sh is for Linux (on a Mac: ./build-app.sh, then Activate in the app)" >&2; exit 1; }
# root only as itself (a container, `su -`): installs into root's own ~/.local; never for someone under sudo
if [ "$(id -u)" = 0 ]; then
  case "${SUDO_UID:-0}${SUDO_USER:-root}" in 0root) ;; *) echo "oomph: run linux/install.sh as yourself, without sudo: it installs into your ~/.local" >&2; exit 1 ;; esac
  RHOME=$(getent passwd 0 2>/dev/null | cut -d: -f6 || true)
  [ -n "$RHOME" ] || RHOME=$(awk -F: '$3 == 0 { print $6; exit }' /etc/passwd 2>/dev/null || true)
  [ -n "${HOME:-}" ] && [ -n "$RHOME" ] && [ "$(cd "$HOME" 2>/dev/null && pwd -P)" = "$(cd "$RHOME" 2>/dev/null && pwd -P)" ] || {
    echo "oomph: as root, HOME must be root's own folder ($RHOME), not ${HOME:-unset}" >&2; exit 1; }
fi
CLAUDE=1
for a in "$@"; do
  case "$a" in
    --no-claude) CLAUDE=0 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "oomph: linux/install.sh: unknown option $a (usage: linux/install.sh [--no-claude])" >&2; exit 2 ;;
  esac
done
[ -n "${HOME:-}" ] && [ -d "$HOME" ] || { echo "oomph: HOME is not a folder" >&2; exit 1; }
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

LIBDIR="$HOME/.local/lib"
BINDIR="$HOME/.local/bin"
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
for f in oomph.py oomphd.py oomph_linux.py oomph_ai.py oomph_upgrade.py oomph_top.py oomph_view.py oomph_net.py oomph_sync.py; do
  cp "$SRC/$f" "$NEW/$f"
done
mkdir -p "$NEW/skills/oomph"
cp "$HERE/skills/oomph/SKILL.md" "$NEW/skills/oomph/SKILL.md"
VER=$("$HERE/tools/version.sh" 2>/dev/null || echo 0.0.0-nogit)
COMMIT=$("$HERE/tools/version.sh" --commit 2>/dev/null || true)
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
chmod 755 "$NEW" "$NEW/oomph.py"
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
echo "oomph: try: oomph doctor · oomph check · oomph top   (every reading is live: no logger on Linux yet)"
