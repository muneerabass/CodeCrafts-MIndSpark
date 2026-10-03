#!/bin/sh
# Builds the depguard CLI for every platform and the downloadable packages:
#   dist/downloads/cli/depguard-<os>-<arch>   raw binaries (install.sh)
#   dist/downloads/depguard-cli.tgz           npm package (npm i -D <url>)
#   dist/downloads/pypi/*.whl + index.html    pip install --find-links <url> depguard-cli
#   dist/downloads/install.sh                 curl | sh installer
# Env: DEPGUARD_APP_URL (download base), DEPGUARD_API_URL (default API for login), VERSION.
set -eu
cd "$(dirname "$0")/.."
APP_URL="${DEPGUARD_APP_URL:-http://localhost:3000}"
API_URL="${DEPGUARD_API_URL:-}"
VERSION="${VERSION:-0.1.$(git rev-list --count HEAD 2>/dev/null || echo 0)}"
OUT=dist/downloads
rm -rf dist/npm "$OUT"
mkdir -p "$OUT/cli" "$OUT/pypi"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION -X main.defaultAPIURL=$API_URL" \
    -o "$OUT/cli/depguard-$os-$arch$ext" ./cmd/depguard
done
# npm package: launcher + every binary.
mkdir -p dist/npm/vendor
cp -r packaging/npm/bin packaging/npm/README.md dist/npm/
for f in "$OUT"/cli/depguard-*; do
  t=$(basename "$f" .exe); t=${t#depguard-}
  mkdir -p "dist/npm/vendor/$t"
  case "$f" in *.exe) cp "$f" "dist/npm/vendor/$t/depguard.exe" ;; *) cp "$f" "dist/npm/vendor/$t/depguard"; chmod 755 "dist/npm/vendor/$t/depguard" ;; esac
done
cat > dist/npm/package.json <<JSON
{
  "name": "depguard-cli",
  "version": "$VERSION",
  "description": "Check npm, pip, go and cargo installs against your team's supply chain policy before anything is installed",
  "license": "Apache-2.0",
  "bin": { "depguard": "bin/depguard.js" },
  "files": ["bin", "vendor", "README.md"],
  "engines": { "node": ">=18" }
}
JSON
(cd dist/npm && tar --owner=0 --group=0 -czf "../../$OUT/depguard-cli.tgz" --transform 's,^\.,package,' .)
python3 packaging/pypi_build.py "$VERSION" "$OUT/cli" "$OUT/pypi"
sed "s#__BASE__#$APP_URL#g" packaging/install.sh.tmpl > "$OUT/install.sh"
echo "$VERSION" > "$OUT/VERSION"
ls -la "$OUT" "$OUT/cli" | sed -n '1,40p'
