---
name: build-flash
description: Build, flash and monitor the firmware. Use when compiling the esp32s3 env, uploading firmware over USB or OTA, building a factory image, finding the board's serial port on macOS, first-boot setup (setup code), or fixing upload/boot errors.
---

# Build and flash

Main target is `esp32s3` (ESP32-S3-DevKitC-1, WROOM-1-N16R8). Config:
[platformio.ini](../../../platformio.ini); partitions:
[partitions_16MB.csv](../../../partitions_16MB.csv). ESP32-S3 only.

## First-time setup

```bash
tools/setup-dev.sh                          # pinned tools in .venv (uv) + git hooks
cp src/secrets.example.h src/secrets.h      # gitignored; first-boot defaults only
```

`secrets.h`: optional Wi-Fi; `WEB_PASS` only works if it is a real 10+ char password
(otherwise a setup code is printed on serial); `OTA_PASS` enables ArduinoOTA.

## Build

```bash
pio run -e esp32s3            # the firmware (also the default env)
pio run -e esp32s3 -v         # verbose: flags, sdkconfig dir (must be qio_opi)
tools/make_factory.sh         # .pio/build/esp32s3/factory.bin, flashable at 0x0
```

The size report's `Flash:` is the percentage of one 4 MB OTA slot. The version is
`FW_VERSION` in `platformio.ini`.

## USB upload (board connected)

```bash
pio device list                              # find the port
pio run -e esp32s3 -t upload                 # firmware
pio run -e esp32s3 -t erase                  # full erase: wipes NVS (settings, password) + list
pio device monitor -e esp32s3                # 115200 baud, esp32_exception_decoder
```

The DevKitC-1 has **two USB-C ports**:

- `UART` (CP210x/CH343 bridge): **the firmware log (setup code, PSRAM, Wi-Fi, DNS)
  only appears here.** With macOS's built-in driver a CH343 shows up as
  `/dev/cu.usbmodem<serial>` (e.g. `usbmodem5CE60447761`, or `usbmodem1234561` when
  the chip reports its default serial); with the WCH driver as
  `/dev/cu.wchusbserial-*`; a CP210x as `/dev/cu.usbserial-*`.
- `USB` (native USB-Serial-JTAG): `/dev/cu.usbmodem101`-style names, chip reports
  `USB mode: USB-Serial/JTAG`. Flashing works; it only carries ROM boot messages and
  framework errors, not our log (`ARDUINO_USB_CDC_ON_BOOT` is 0).

**No port at all / LED off or blinking:** on some boards a USB-C port only works
with the plug one way round (missing CC resistor): flip the plug. A charge-only
cable also shows nothing in `system_profiler SPUSBDataType`.

**Capture the log for a fixed time** (no `timeout` on macOS): `pio device monitor`
runs until stopped; for scripted checks use pyserial from
`~/.platformio/penv/bin/python`, pulse RTS to reset, read for N seconds.

Fix the port with `upload_port = /dev/cu.usbserial-XXXX` in a gitignored
`platformio_override.ini` (`[env:esp32s3]` section), or pass `--upload-port`.

Optional: preload a blocklist without network by putting a v2 list at
`data/blocklist.bin` and running `pio run -e esp32s3 -t uploadfs` (normally the device
downloads it itself).

## First boot

1. No Wi-Fi configured: join the `S3-AdBlock-XXXX` AP from a phone, pick a network.
2. Serial log prints `One-time setup code: xxxxxxxxxxxx`. Open `http://s3adblock.local`,
   log in as `admin` with the code, set a password (10+ chars).

## OTA

- Dashboard: _Device → Flash firmware_ with `.pio/build/esp32s3/firmware.bin`.
- Network: `pio run -e esp32s3 -t upload --upload-port s3adblock.local --upload-protocol espota --upload-flags="--auth=<OTA_PASS>"`.

A new image must be healthy (Wi-Fi + DNS running 60 s) within 5 minutes or the
bootloader rolls back (`maintainOtaHealth()` in `src/main.cpp`).

## Common errors

| Symptom                                                  | Fix                                                                                                |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Failed to connect to ESP32-S3: No serial data received` | Hold **BOOT**, tap **RST**, release BOOT, retry. Try the other USB-C port or a data-capable cable. |
| `Could not open port ... Resource busy`                  | Close `pio device monitor` or other apps using the port.                                           |
| Port not listed on macOS                                 | Use a data cable. For CH343 boards, install the WCH driver only if no `cu.wchusbserial*` appears.  |
| Boot loop, `PSRAM ID read error`                         | `memory_type` must be `qio_opi` for N16R8, never `opi_opi`.                                        |
| `[ERROR] No PSRAM found` in the boot log                 | Same as above, or `-DBOARD_HAS_PSRAM` missing, or not an N16R8 module.                             |
| `program size ... greater than maximum allowed`          | Check `board_build.partitions` for the env.                                                        |
| espota auth failed / OTA not listening                   | `OTA_PASS` must be 10+ chars (and match `--auth`); check the boot log.                             |
| `AttributeError: ... 'resultcallback'`                   | PlatformIO too old: use `.venv/bin/pio` (pinned 6.2.0).                                            |
