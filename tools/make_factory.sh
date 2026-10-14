#!/usr/bin/env bash
# Merges bootloader + partition table + OTA data + app into one ESP32-S3 image that can
# be flashed at offset 0 (first install, web installer). Run after `pio run -e esp32s3`.
#   tools/make_factory.sh [out.bin]
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-.pio/build/esp32s3/factory.bin}"
PIO=".venv/bin/pio"; [ -x "$PIO" ] || PIO="pio"
B=".pio/build/esp32s3"
BOOT_APP0="${PLATFORMIO_CORE_DIR:-$HOME/.platformio}/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"
for f in "$B/bootloader.bin" "$B/partitions.bin" "$B/firmware.bin" "$BOOT_APP0"; do
  [ -f "$f" ] || { echo "missing $f (run: pio run -e esp32s3)" >&2; exit 1; }
done
# Flash mode/frequency/size are kept from the bootloader image header ("keep" defaults).
"$PIO" pkg exec -p tool-esptoolpy -- esptool.py --chip esp32s3 merge_bin -o "$OUT" \
  0x0 "$B/bootloader.bin" 0x8000 "$B/partitions.bin" 0xe000 "$BOOT_APP0" 0x10000 "$B/firmware.bin"
echo "factory image: $OUT"
