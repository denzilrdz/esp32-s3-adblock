---
name: build-flash
description: Build, flash and monitor the firmware. Use when compiling any PlatformIO env (esp32s3, c3, esp32dev), uploading firmware or the LittleFS image over USB, doing an OTA upload over Wi-Fi, finding the board's serial port on macOS, or fixing upload/boot errors.
---

# Build and flash

Main target is `esp32s3` (ESP32-S3-DevKitC-1, WROOM-1-N16R8). Config lives in
[platformio.ini](../../../platformio.ini); partition table in
[partitions_16MB.csv](../../../partitions_16MB.csv).

## First-time setup

```bash
cp src/secrets.example.h src/secrets.h      # gitignored; set WEB_PASS / OTA_PASS
python3 tools/build_blocklist.py data/blocklist.bin
```

## Build

```bash
pio run -e esp32s3            # main target
pio run -e c3                 # lite profile, compile check
pio run -e esp32dev           # lite profile, compile check
pio run                       # every env in default_envs
pio run -e esp32s3 -v         # verbose: shows flags, sdkconfig dir (qio_opi)
```

Check the size report at the end: `Flash:` is the percentage of one 4 MB OTA slot.

## USB upload (board connected)

```bash
pio device list                              # find the port
pio run -e esp32s3 -t upload                 # firmware
pio run -e esp32s3 -t uploadfs               # LittleFS image built from data/
pio run -e esp32s3 -t erase                  # full chip erase (wipes NVS + list!)
pio device monitor -e esp32s3                # 115200 baud, esp32_exception_decoder
```

The DevKitC-1 has **two USB-C ports**:
- `UART` (CP210x/CH343 bridge): `/dev/cu.usbserial-*` or `/dev/cu.wchusbserial-*`.
  Most reliable for flashing.
- `USB` (native USB-Serial-JTAG): `/dev/cu.usbmodem*`. Also works for flashing and
  JTAG.

Set a fixed port with `upload_port = /dev/cu.usbserial-XXXX` in a gitignored
`platformio_override.ini`, or pass `--upload-port`.

## OTA over Wi-Fi

```bash
pio run -e esp32s3 -t upload --upload-port s3adblock.local --upload-protocol espota \
    --upload-flags="--auth=$OTA_PASS"
```

Or upload `.pio/build/esp32s3/firmware.bin` on the dashboard (Firmware → OTA). If
signing is enabled, upload `firmware.signed.bin` from `tools/sign_firmware.py`. A new
image must report healthy within 2 minutes, or the bootloader rolls back (see
[ARCHITECTURE.md §9](../../../docs/ARCHITECTURE.md)).

## Common errors

| Symptom | Fix |
|---|---|
| `Failed to connect to ESP32-S3: No serial data received` | Hold **BOOT**, tap **RST**, release BOOT, retry. Try the other USB-C port or a data-capable cable. |
| `A fatal error occurred: Could not open port ... Resource busy` | Close the serial monitor (`pio device monitor`) or other apps using the port. |
| Port not listed on macOS | Use a data cable. For CH343 boards, install the WCH driver only if the `cu.wchusbserial*` device doesn't appear. |
| Boot loop with `octal_psram` / `PSRAM ID read error` | `memory_type` must be `qio_opi` for N16R8, never `opi_opi`. |
| `psramFound() == false` | Same as above; or `-DBOARD_HAS_PSRAM` is missing. |
| `Error: The program size ... is greater than maximum allowed` | Check `board_build.partitions` points to `partitions_16MB.csv`. |
| `uploadfs` data missing after a firmware flash | Normal: firmware and FS are separate partitions; run `uploadfs` once. |
| `espota` auth failed | `OTA_PASS` in `secrets.h` must match `--auth`. |
| `AttributeError: ... 'resultcallback'` | PlatformIO too old: `brew upgrade platformio`. |
