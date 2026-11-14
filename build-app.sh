#!/bin/bash
# Builds oomph.app (menu bar) into ~/Applications, bundling the daemon + install scripts.
set -euo pipefail
cd "$(dirname "$0")"
DEST="${1:-$HOME/Applications}"
APP="$DEST/oomph.app"
BUILD=$(mktemp -d)
swiftc -O -swift-version 5 -parse-as-library -target "$(uname -m)-apple-macos14.0" \
  -o "$BUILD/oomph" app/oomph.swift -framework AppKit -framework SwiftUI -framework Charts
pkill -x oomph 2>/dev/null || true
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILD/oomph" "$APP/Contents/MacOS/"
cp app/Info.plist "$APP/Contents/"
# one version for everything: stamp the app with the CLI's VERSION
VER=$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' daemon/oomph.py)
/usr/bin/plutil -replace CFBundleShortVersionString -string "$VER" "$APP/Contents/Info.plist"
cp daemon/oomphd.py daemon/oomph.py daemon/local.oomph.daemon.plist install.sh uninstall.sh "$APP/Contents/Resources/"
mkdir -p "$APP/Contents/Resources/skills/oomph" && cp skills/oomph/SKILL.md "$APP/Contents/Resources/skills/oomph/"
chmod 755 "$APP/Contents/Resources/"*.sh "$APP/Contents/Resources/"*.py
codesign --force --sign - "$APP" >/dev/null
rm -rf "$BUILD"
echo "$APP"
