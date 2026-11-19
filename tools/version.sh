#!/bin/sh
# The version from git history — same scheme as Glow: tags name releases, everything else
# derives from them. A `v1.5.0` tag builds `1.5.0`; three commits later builds
# `1.5.0-3-g<sha>`; uncommitted changes append `-dirty`; before the first version tag it is
# `0.0.0-g<sha>`; without git (e.g. a source zip) `0.0.0-nogit`. Needs the full history
# (non-shallow clone). `tools/version.sh --commit` prints the full commit id instead.
cd "$(dirname "$0")/.." || exit 1
if [ "${1:-}" = "--commit" ]; then git rev-parse HEAD 2>/dev/null || true; exit 0; fi
d=$(git describe --tags --match 'v*' --always --dirty --first-parent 2>/dev/null) || d=""
case "$d" in
  "") echo "0.0.0-nogit" ;;
  v*) echo "${d#v}" ;;
  *)  echo "0.0.0-g$d" ;;
esac
