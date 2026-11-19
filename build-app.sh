#!/bin/bash
# Builds oomph.app (menu bar) into ~/Applications, bundling the daemon + install scripts.
#   ./build-app.sh [DEST]      DEST defaults to ~/Applications
# The version comes from git history (tools/version.sh) and is stamped into the bundle.
# OOMPH_NO_KILL=1 leaves a running oomph alone (an in-app upgrade builds into a staging folder).
set -euo pipefail
cd "$(dirname "$0")"
DEST="${1:-$HOME/Applications}"
APP="$DEST/oomph.app"
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
VER=$(tools/version.sh)
COMMIT=$(tools/version.sh --commit)

echo "==> Compiling oomph $VER"
swiftc -O -swift-version 5 -parse-as-library -target "$(uname -m)-apple-macos14.0" \
  -o "$BUILD/oomph" app/oomph.swift -framework AppKit -framework SwiftUI -framework Charts -framework Security

echo "==> Assembling the app bundle"
[ -n "${OOMPH_NO_KILL:-}" ] || pkill -x oomph 2>/dev/null || true
mkdir -p "$DEST"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILD/oomph" "$APP/Contents/MacOS/"
cp app/Info.plist "$APP/Contents/"
/usr/bin/plutil -replace CFBundleShortVersionString -string "$VER" "$APP/Contents/Info.plist"
/usr/bin/plutil -replace CFBundleVersion -string "${COMMIT:0:12}" "$APP/Contents/Info.plist"
/usr/bin/plutil -replace OOMPHCommit -string "$COMMIT" "$APP/Contents/Info.plist"
R="$APP/Contents/Resources"
cp daemon/oomphd.py daemon/oomph.py daemon/oomph_ai.py daemon/oomph_upgrade.py daemon/local.oomph.daemon.plist \
   install.sh uninstall.sh "$R/"
# one version for everything: the bundled CLI and daemon report what the app reports
/usr/bin/sed -i '' -e "s/^VERSION = \"dev\".*/VERSION = \"$VER\"/" -e "s/^COMMIT = \"\".*/COMMIT = \"$COMMIT\"/" "$R/oomph.py"
mkdir -p "$R/skills/oomph" && cp skills/oomph/SKILL.md "$R/skills/oomph/"
chmod 755 "$R/"*.sh "$R/"*.py

echo "==> Signing (ad hoc)"
codesign --force --sign - "$APP" >/dev/null
echo "==> Built $APP"
echo "$APP"
