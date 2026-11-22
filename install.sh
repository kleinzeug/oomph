#!/bin/bash
# Installs/updates the oomph root LaunchDaemon. Run: sudo ./install.sh
# Works from the repo (files in ./daemon) and from oomph.app/Contents/Resources (flat).
#
# Installs are side by side: the files go into a new /usr/local/libexec/oomph-<version>, and
# /usr/local/libexec/oomph is a symbolic link to it, swapped by one rename once that directory
# is complete. The LaunchDaemon and /usr/local/bin/oomph go through the link; a process that is
# running keeps importing from the directory it started in (it resolves its real path), so it
# never mixes two versions. Directories replaced more than 7 days ago are removed (a process
# still running from one by then, such as an MCP server left open for over a week, loses the
# modules it hasn't imported yet; restarting it fixes that). The first install over the old
# layout (a real directory) moves that directory aside the same way. The link is only as safe
# as its folder, so /usr/local/libexec becomes root:wheel 755 (as /usr/local/bin always did).
#
# OOMPH_INSTALL_ROOT=<dir> installs below that directory instead of /, for tests: no root
# needed, no launchd, no memwatch migration, files owned by whoever runs it. Run as root, it is
# honoured only for a directory that root owns all the way up and nobody else can change.
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
  [ -d "$PFX" ] || { echo "oomph: OOMPH_INSTALL_ROOT $PFX is not a directory" >&2; exit 1; }
  [ "$(id -u)" != 0 ] || root_only "$PFX" || {
    echo "oomph: as root, OOMPH_INSTALL_ROOT must be root's all the way up and writable by nobody else" >&2; exit 1; }
else
  [ "$(id -u)" = 0 ] || { echo "oomph: install.sh must run as root (sudo ./install.sh)" >&2; exit 1; }
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/daemon/oomphd.py" ]; then SRC="$HERE/daemon"; else SRC="$HERE"; fi
LIBEXEC="$PFX/usr/local/libexec"
LIB="$LIBEXEC/oomph"
PLIST="$PFX/Library/LaunchDaemons/local.oomph.daemon.plist"
KEEP_DAYS=7

# the system's tools by path: a GNU mv (no -h) or install first in PATH must not break a swap
inst() {  # install(1), owned by root:wheel unless this is a test prefix
  if [ -n "$PFX" ]; then /usr/bin/install "$@"; else /usr/bin/install -o root -g wheel "$@"; fi
}
relink() {  # relink TARGET LINK: point LINK at TARGET by renaming a new link over it (atomic)
  local tmp
  tmp="$(dirname "$2")/.$(basename "$2").link.$$"
  rm -f "$tmp"
  ln -s "$1" "$tmp"
  /bin/mv -fh "$tmp" "$2"
}
same() {  # same DIR1 DIR2: the same files (bytecode caches aside)
  [ -d "$2" ] && [ ! -L "$2" ] && /usr/bin/diff -r -x __pycache__ "$1" "$2" >/dev/null 2>&1
}
gitver() {  # tools/version.sh, as whoever ran sudo: git then neither balks at nor leaves root's files in their checkout
  if [ "$(id -u)" = 0 ] && [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
    /usr/bin/sudo -u "#$SUDO_UID" "$HERE/tools/version.sh" "$@" || "$HERE/tools/version.sh" "$@"
  else
    "$HERE/tools/version.sh" "$@"
  fi
}
version_of() {  # the VERSION stamped into an oomph.py, as a safe directory name
  local v
  v=$({ /usr/bin/sed -n 's/^VERSION = "\([^"]*\)".*/\1/p' "$1" 2>/dev/null || true; } | head -n 1 | tr -d '\n' | tr -c 'A-Za-z0-9._+-' '_')
  echo "${v:-unknown}"
}
free_name() {  # free_name BASE: BASE, or BASE-<time> when that is taken
  local n="$1"
  [ -e "$LIBEXEC/$n" ] || [ -L "$LIBEXEC/$n" ] || { echo "$n"; return; }
  n="$1-$(date +%Y%m%d%H%M%S)"
  [ -e "$LIBEXEC/$n" ] || { echo "$n"; return; }
  echo "$n-$$"
}

/usr/bin/python3 -I -c 'import sys; sys.exit(0)' || { echo "oomph: /usr/bin/python3 not usable (install Xcode Command Line Tools)" >&2; exit 1; }

if [ -z "$PFX" ]; then
  # migrate from the old name (memwatch): stop/remove it and keep its logs
  if [ -e /Library/LaunchDaemons/local.memwatch.daemon.plist ] || [ -d /usr/local/libexec/memwatch ]; then
    launchctl bootout system/local.memwatch.daemon 2>/dev/null || true
    rm -f /Library/LaunchDaemons/local.memwatch.daemon.plist /usr/local/bin/memwatch
    rm -rf /usr/local/libexec/memwatch
    echo "oomph: removed legacy memwatch daemon"
  fi
  if [ -d /Library/Logs/memwatch ] && [ ! -d /Library/Logs/oomph ]; then
    mv /Library/Logs/memwatch /Library/Logs/oomph
    echo "oomph: moved logs from /Library/Logs/memwatch"
  fi
  launchctl bootout system/local.oomph.daemon 2>/dev/null || true
fi
# root's and nobody else's: the LaunchDaemon runs what the link in $LIBEXEC points to
if [ -z "$PFX" ] && [ -d "$LIBEXEC" ] && [ "$(/usr/bin/stat -f '%u %Lp' "$LIBEXEC")" != "0 755" ]; then
  echo "oomph: $LIBEXEC was $(/usr/bin/stat -f '%Su %Lp' "$LIBEXEC"); making it root's (755) so nobody else can swap the link the daemon runs through"
fi
inst -d -m 755 "$LIBEXEC" "$PFX/usr/local/bin" "$PFX/Library/Logs/oomph"
[ -z "$PFX" ] || inst -d -m 755 "$(dirname "$PLIST")"

# 1. the new version, complete, in a directory of its own
NEW=$(mktemp -d "$LIBEXEC/.oomph-new.XXXXXX")
trap 'rm -rf "$NEW"' EXIT
inst -m 755 "$SRC/oomphd.py" "$SRC/oomph.py" "$SRC/oomph_darwin.py" "$SRC/oomph_ai.py" "$SRC/oomph_upgrade.py" \
  "$SRC/oomph_top.py" "$SRC/oomph_view.py" "$SRC/oomph_net.py" "$SRC/oomph_sync.py" "$NEW/"
# from a git checkout: stamp the version like build-app.sh does (the app bundle is stamped already)
if [ -x "$HERE/tools/version.sh" ]; then
  VER=$(gitver); COMMIT=$(gitver --commit)
  /usr/bin/sed -i '' -e "s/^VERSION = \"dev\".*/VERSION = \"$VER\"/" -e "s/^COMMIT = \"\".*/COMMIT = \"$COMMIT\"/" "$NEW/oomph.py"
fi
if [ -f "$HERE/skills/oomph/SKILL.md" ]; then
  inst -d -m 755 "$NEW/skills" "$NEW/skills/oomph"
  inst -m 644 "$HERE/skills/oomph/SKILL.md" "$NEW/skills/oomph/SKILL.md"
fi
chmod 755 "$NEW"
[ -n "$PFX" ] || chown root:wheel "$NEW"
NAME="oomph-$(version_of "$NEW/oomph.py")"
CUR=$(readlink "$LIB" 2>/dev/null || true)
case "$CUR" in oomph-*) ;; *) CUR="" ;; esac
if [ -n "$CUR" ] && same "$NEW" "$LIBEXEC/$CUR"; then
  NAME="$CUR"; rm -rf "$NEW"  # the same files are installed already: keep using them
elif same "$NEW" "$LIBEXEC/$NAME"; then
  rm -rf "$NEW"
else
  NAME=$(free_name "$NAME")
  /bin/mv "$NEW" "$LIBEXEC/$NAME"
fi
trap - EXIT

# 2. the switch: one rename of a link. The old layout's real directory is moved aside first.
OLD=""
if [ -L "$LIB" ]; then
  OLD=$(readlink "$LIB")
elif [ -d "$LIB" ]; then
  OLD=$(free_name "oomph-$(version_of "$LIB/oomph.py")")
  ln -s "$NAME" "$LIBEXEC/.oomph.link.$$"
  /bin/mv "$LIB" "$LIBEXEC/$OLD"
  /bin/mv -fh "$LIBEXEC/.oomph.link.$$" "$LIB"
elif [ -e "$LIB" ]; then
  rm -f "$LIB"
fi
[ "$(readlink "$LIB" 2>/dev/null)" = "$NAME" ] || relink "$NAME" "$LIB"
case "$OLD" in /*) ;; ?*) OLD="$LIBEXEC/$OLD" ;; esac
if [ -n "$OLD" ] && [ "$OLD" != "$LIBEXEC/$NAME" ] && [ -d "$OLD" ]; then
  touch "$OLD"  # its time now says when it was replaced
fi

# 3. versions replaced more than KEEP_DAYS ago, and leftovers of interrupted installs
for d in "$LIBEXEC"/oomph-* "$LIBEXEC"/.oomph-new.*; do
  [ -d "$d" ] && [ ! -L "$d" ] && [ "$d" != "$LIBEXEC/$NAME" ] || continue
  if [ -n "$(/usr/bin/find "$d" -prune -mtime +"$KEEP_DAYS")" ]; then rm -rf "$d"; fi
done
for l in "$LIBEXEC"/.oomph.link.* "$PFX"/usr/local/bin/.oomph.link.*; do
  [ ! -L "$l" ] || rm -f "$l"
done

inst -m 644 "$SRC/local.oomph.daemon.plist" "$PLIST"
[ "$(readlink "$PFX/usr/local/bin/oomph" 2>/dev/null)" = "$LIB/oomph.py" ] || relink "$LIB/oomph.py" "$PFX/usr/local/bin/oomph"
if [ -n "$PFX" ]; then
  echo "oomph: installed $NAME into $PFX"; exit 0
fi
launchctl enable system/local.oomph.daemon
launchctl bootstrap system "$PLIST"
sleep 2
if launchctl print system/local.oomph.daemon 2>/dev/null | grep -q "state = running"; then
  echo "oomph: daemon running. Logs: /Library/Logs/oomph  ·  try: oomph status"
else
  echo "oomph: daemon did not start — see /Library/Logs/oomph/daemon.err" >&2; exit 1
fi
