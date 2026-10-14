#!/usr/bin/env bash
# Merges bootloader + partition table + OTA data + app into one image that can be
# flashed at offset 0 (first install, web installer). Run after `pio run -e <env>`.
#   tools/make_factory.sh esp32s3 [out.bin]
set -euo pipefail
cd "$(dirname "$0")/.."
ENV="${1:?usage: make_factory.sh <esp32s3|c3|esp32dev> [out.bin]}"
OUT="${2:-.pio/build/$ENV/factory.bin}"
case "$ENV" in
  esp32s3) CHIP=esp32s3; BOOT=0x0 ;;
  c3) CHIP=esp32c3; BOOT=0x0 ;;
  esp32dev) CHIP=esp32; BOOT=0x1000 ;;
  *) echo "unknown env $ENV" >&2; exit 1 ;;
esac
PIO=".venv/bin/pio"; [ -x "$PIO" ] || PIO="pio"
B=".pio/build/$ENV"
BOOT_APP0="${PLATFORMIO_CORE_DIR:-$HOME/.platformio}/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"
for f in "$B/bootloader.bin" "$B/partitions.bin" "$B/firmware.bin" "$BOOT_APP0"; do
  [ -f "$f" ] || { echo "missing $f (build the env first)" >&2; exit 1; }
done
# Flash mode/frequency/size are kept from the bootloader image header ("keep" defaults).
"$PIO" pkg exec -p tool-esptoolpy -- esptool.py --chip "$CHIP" merge_bin -o "$OUT" \
  "$BOOT" "$B/bootloader.bin" 0x8000 "$B/partitions.bin" 0xe000 "$BOOT_APP0" 0x10000 "$B/firmware.bin"
echo "factory image: $OUT"
