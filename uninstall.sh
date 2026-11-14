#!/bin/bash
# Stops and removes the oomph daemon. Logs are kept unless --purge is given.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "oomph: uninstall.sh must run as root (sudo ./uninstall.sh)" >&2; exit 1; }
launchctl bootout system/local.oomph.daemon 2>/dev/null || true
rm -f /Library/LaunchDaemons/local.oomph.daemon.plist /usr/local/bin/oomph
rm -rf /usr/local/libexec/oomph
if [ "${1:-}" = "--purge" ]; then rm -rf /Library/Logs/oomph; echo "oomph: removed (logs purged)"; else echo "oomph: removed (logs kept in /Library/Logs/oomph)"; fi
