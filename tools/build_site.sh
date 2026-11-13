#!/usr/bin/env bash
# Assemble the GitHub Pages site (browser installer + dashboard update files) into
# <out-dir>, from installer/ and a release's binaries in <dist-dir>.
#
#   tools/build_site.sh <tag> <dist-dir> <out-dir> <min-update-from>
#
# Used by .github/workflows/release.yml (on a tag) and pages.yml (manual redeploy).
# <dist-dir> must hold factory-esp32s3-<tag>.bin and firmware-esp32s3-<tag>.bin.
# <min-update-from>: oldest version that may install this release from the dashboard
# (installer/min-update-from as of that release).
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 <tag> <dist-dir> <out-dir> <min-update-from>" >&2
  exit 2
fi
tag="$1"
dist="$2"
site="$3"
min_from="$4"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "bad tag: $tag" >&2
  exit 1
}
root="$(cd "$(dirname "$0")/.." && pwd)"
ver="${tag#v}"

# esp-web-tools: pinned version + SHA-512 from installer/esp-web-tools.lock, vendored so a
# CDN compromise cannot change what the page flashes.
ewt_ver=$(sed -n 's/^version=//p' "$root/installer/esp-web-tools.lock")
want=$(sed -n 's/^integrity=sha512-//p' "$root/installer/esp-web-tools.lock")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://registry.npmjs.org/esp-web-tools/-/esp-web-tools-${ewt_ver}.tgz" -o "$tmp/ewt.tgz"
got=$(openssl dgst -sha512 -binary "$tmp/ewt.tgz" | base64 | tr -d '\n')
[ "$got" = "$want" ] || {
  echo "esp-web-tools ${ewt_ver}: integrity mismatch" >&2
  exit 1
}
mkdir -p "$site/vendor/esp-web-tools"
tar -xzf "$tmp/ewt.tgz" -C "$tmp"
cp "$tmp"/package/dist/web/*.js "$site/vendor/esp-web-tools/"

sed "s/__VERSION__/${ver}/g" "$root/installer/index.html" >"$site/index.html"
cp "$root/installer/404.html" "$site/"
cp "$root/installer/social-preview.png" "$site/"
# Dashboard demo: the real page with a simulated device (tools/build_demo.py).
python3 "$root/tools/build_demo.py" "$site/demo" "$ver"
cp "$dist/factory-esp32s3-${tag}.bin" "$site/factory-esp32s3.bin"
sed "s/__VERSION__/${ver}/" "$root/installer/manifest.json" >"$site/manifest.json"
# Dashboard update check: the browser fetches these from Pages (release downloads send
# no CORS headers) and uploads the firmware to the device.
cp "$dist/firmware-esp32s3-${tag}.bin" "$site/firmware-esp32s3.bin"
python3 "$root/tools/make_update_json.py" --min-update-from "$min_from" \
  "$site/firmware-esp32s3.bin" "$tag" "$site/update.json" \
  "https://github.com/${GITHUB_REPOSITORY:-denzilrdz/esp32-s3-adblock}/releases/tag/${tag}"
echo "site for ${tag} in ${site}"
