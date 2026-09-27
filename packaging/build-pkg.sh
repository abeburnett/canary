#!/bin/bash
# Build the SkillCanary macOS installer (unsigned component + product).
# Usage: packaging/build-pkg.sh <version> [<"Developer ID Installer: NAME (TEAM)">]
# Installs the program root-owned at /usr/local/lib/skillcanary and links
# /usr/local/bin/canary. It enables no protection: the person runs
# `canary setup` and chooses a level.
set -euo pipefail
VERSION=$1
IDENTITY=${2:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LIB="$WORK/payload/usr/local/lib/skillcanary"
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
ln -sfn /usr/local/lib/skillcanary/bin/canary /usr/local/bin/canary
chown -R root:wheel /usr/local/lib/skillcanary
chmod -R go-w /usr/local/lib/skillcanary
exit 0
SH
chmod 755 "$WORK/scripts/postinstall"
COPYFILE_DISABLE=1 pkgbuild --root "$WORK/payload" --scripts "$WORK/scripts" --ownership recommended \
  --identifier com.skillcanary.canary --version "$VERSION" --install-location / \
  "$WORK/canary-component.pkg" >/dev/null
PRODUCT="$OUT/SkillCanary-$VERSION.pkg"
if [ -n "$IDENTITY" ]; then
  productbuild --package "$WORK/canary-component.pkg" --sign "$IDENTITY" "$PRODUCT"
else
  productbuild --package "$WORK/canary-component.pkg" "$PRODUCT"
fi
shasum -a 256 "$PRODUCT"
