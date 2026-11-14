#!/bin/bash
# Installs/updates the oomph root LaunchDaemon. Run: sudo ./install.sh
# Works from the repo (files in ./daemon) and from oomph.app/Contents/Resources (flat).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "oomph: install.sh must run as root (sudo ./install.sh)" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/daemon/oomphd.py" ]; then SRC="$HERE/daemon"; else SRC="$HERE"; fi
LIB=/usr/local/libexec/oomph
PLIST=/Library/LaunchDaemons/local.oomph.daemon.plist

/usr/bin/python3 -I -c 'import sys; sys.exit(0)' || { echo "oomph: /usr/bin/python3 not usable (install Xcode Command Line Tools)" >&2; exit 1; }

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
install -d -o root -g wheel -m 755 "$LIB" /usr/local/bin /Library/Logs/oomph
install -o root -g wheel -m 755 "$SRC/oomphd.py" "$SRC/oomph.py" "$LIB/"
install -o root -g wheel -m 644 "$SRC/local.oomph.daemon.plist" "$PLIST"
if [ -f "$HERE/skills/oomph/SKILL.md" ]; then
  install -d -o root -g wheel -m 755 "$LIB/skills/oomph"
  install -o root -g wheel -m 644 "$HERE/skills/oomph/SKILL.md" "$LIB/skills/oomph/SKILL.md"
fi
ln -sfn "$LIB/oomph.py" /usr/local/bin/oomph
launchctl enable system/local.oomph.daemon
launchctl bootstrap system "$PLIST"
sleep 2
if launchctl print system/local.oomph.daemon 2>/dev/null | grep -q "state = running"; then
  echo "oomph: daemon running. Logs: /Library/Logs/oomph  ·  try: oomph status"
else
  echo "oomph: daemon did not start — see /Library/Logs/oomph/daemon.err" >&2; exit 1
fi
