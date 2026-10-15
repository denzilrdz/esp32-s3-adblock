#!/usr/bin/env bash
# Copies the merged ESP32-S3 image (bootloader 0x0 + partition table 0x8000 + OTA data
# 0xe000 + app 0x10000) that can be flashed at offset 0 (first install, web installer).
# The pioarduino platform writes it as firmware.factory.bin after every build, but a
# failed merge only prints a message, so check that it is there and up to date.
#   tools/make_factory.sh [out.bin]     (run after `pio run -e esp32s3`)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-.pio/build/esp32s3/factory.bin}"
B=".pio/build/esp32s3"
[ -f "$B/firmware.bin" ] || {
  echo "missing $B/firmware.bin (run: pio run -e esp32s3)" >&2
  exit 1
}
[ -f "$B/firmware.factory.bin" ] || {
  echo "missing $B/firmware.factory.bin (merge failed? see the build log)" >&2
  exit 1
}
[ ! "$B/firmware.bin" -nt "$B/firmware.factory.bin" ] ||
  {
    echo "$B/firmware.factory.bin is older than firmware.bin (merge failed?)" >&2
    exit 1
  }
# The app must sit at 0x10000 inside the merged image.
cmp -s <(tail -c +$((0x10000 + 1)) "$B/firmware.factory.bin" | head -c "$(wc -c <"$B/firmware.bin")") "$B/firmware.bin" ||
  {
    echo "firmware.factory.bin does not contain firmware.bin at 0x10000" >&2
    exit 1
  }
cp "$B/firmware.factory.bin" "$OUT"
echo "factory image: $OUT"
