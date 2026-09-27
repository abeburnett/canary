#!/bin/bash
# Build the SkillCanary macOS installer (unsigned component + product).
# Usage: packaging/build-pkg.sh <version> [<"Developer ID Installer: NAME (TEAM)">]
# Installs the program root-owned at /Library/Application Support/SkillCanary
# (macOS keeps that path root-owned) and links
# /usr/local/bin/canary. It enables no protection: the person runs
# `canary setup` and chooses a level.
set -euo pipefail
VERSION=$1
IDENTITY=${2:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The payload is SkillCanary's own folder only, installed at its destination,
# so the package never records (or changes) the system folders above it.
LIB="$WORK/payload"
mkdir -p "$LIB/bin" "$WORK/scripts" "$OUT"
cp "$ROOT/LICENSE" "$LIB/"
cp "$ROOT/bin/canary" "$LIB/bin/canary"
(cd "$ROOT" && find canary -name '*.py' -not -path '*/__pycache__/*' -print0 | xargs -0 -I{} rsync -R {} "$LIB/")
chmod 755 "$LIB/bin/canary"
find "$LIB" -type f ! -path "*/bin/canary" -exec chmod 644 {} +
# macOS keeps com.apple.provenance on these files; the package records it as
# AppleDouble entries, which Installer restores as attributes, not files.
xattr -cr "$WORK/payload" 2>/dev/null || true
cat > "$WORK/scripts/postinstall" <<'SH'
#!/bin/sh
mkdir -p /usr/local/bin
ln -sfn "/Library/Application Support/SkillCanary/bin/canary" /usr/local/bin/canary
chown -R root:wheel "/Library/Application Support/SkillCanary"
chmod -R go-w "/Library/Application Support/SkillCanary"
# Open the Get Started page for the person at the screen, if there is one.
PERSON=$(stat -f %Su /dev/console 2>/dev/null)
if [ -n "$PERSON" ] && [ "$PERSON" != root ] && [ "$PERSON" != loginwindow ]; then
  launchctl asuser "$(id -u "$PERSON")" sudo -u "$PERSON" open "https://skillcanary.com/start" || true
fi
exit 0
SH
chmod 755 "$WORK/scripts/postinstall"
COPYFILE_DISABLE=1 pkgbuild --root "$WORK/payload" --scripts "$WORK/scripts" --ownership recommended \
  --identifier com.skillcanary.canary --version "$VERSION" \
  --install-location "/Library/Application Support/SkillCanary" \
  "$WORK/canary-component.pkg" >/dev/null
PRODUCT="$OUT/SkillCanary-$VERSION.pkg"
# A distribution adds the title and the final "what next" screen.
productbuild --synthesize --package "$WORK/canary-component.pkg" "$WORK/distribution.xml" >/dev/null
/usr/bin/python3 - "$WORK/distribution.xml" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s, n = re.subn(r'(<installer-gui-script[^>]*>)',
               r'\1\n    <title>SkillCanary</title>\n    <conclusion file="conclusion.html" mime-type="text/html"/>', s, count=1)
assert n == 1, "distribution has no installer-gui-script element"
open(p, "w").write(s)
PY
SIGN=()
if [ -n "$IDENTITY" ]; then SIGN=(--sign "$IDENTITY"); fi
productbuild --distribution "$WORK/distribution.xml" --resources "$ROOT/packaging/resources" \
  --package-path "$WORK" ${SIGN[@]+"${SIGN[@]}"} "$PRODUCT"
shasum -a 256 "$PRODUCT"
