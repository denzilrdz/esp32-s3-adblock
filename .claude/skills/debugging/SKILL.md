---
name: debugging
description: Diagnose problems on the device. Use when reading serial logs, decoding a crash backtrace or core dump, checking heap/PSRAM/stack usage, investigating task watchdog resets, Wi-Fi drops, slow or failing DNS, or upstream/TLS failures.
---

# Debugging on hardware

## Serial log

```bash
pio device monitor -e esp32s3        # 115200 baud, filters: esp32_exception_decoder, time
```

- **Reading the log without restarting the board** (e.g. a stability check): open
  the port with pyserial (`~/.platformio/penv/bin/python`) and leave DTR and RTS at
  their default (both asserted). On the DevKitC-1 auto-reset circuit only RTS
  asserted alone pulls EN low; pulsing RTS on purpose is how to _get_ a boot log.
  Opening `pio device monitor` may reset the board.
- Logs can contain binary bytes (ROM boot noise): use `grep -a`, otherwise grep
  silently treats the file as binary and matches nothing.
- **OTA slot state:** read otadata with
  `~/.platformio/penv/bin/esptool --chip esp32s3 read-flash 0xe000 0x2000 ota.bin`
  (resets the board). Two 32-byte records (`seq`, label, `state` at +24, crc): the
  higher valid `seq` wins, `(seq-1) % 2` is the slot; state 1 = pending verify,
  2 = valid, 3 = invalid (rolled back).

- Lines look like `[I][up] cloudflare-dot: unknown -> up (180 ms)`. Tags: `dns`, `up`
  (upstream), `bl` (blocklist), `time`, `wifi`, `web`, `ota`, `boot`.
- Log level: dashboard _Settings → Log level_ (error/warn/info/debug), stored in NVS and
  applied live. Use debug only temporarily.
- Boot banner: `[adblock] v<version> booting (<hostname>, PSRAM <n> KB)`, then the
  setup code (if no password is set), list size and `ready`.

## Crash / backtrace

- **Without a cable (v0.2.7+):** _Device → Health_ shows _Last restart_ (power on,
  crash, watchdog, brownout, or the firmware's own reason such as "Wi-Fi down for 10
  min") and, if the `coredump` partition holds one, the crash record: task, panic
  reason and backtrace (`restart` in `/api/stats`). The record stays in flash until
  the next crash, so it survives OTA updates; "earlier crash" means it predates the
  last restart. Decode the backtrace with the ELF of the build that crashed
  (`restart.crash.elf` = the leading digits of its ELF SHA-256; release assets carry
  `firmware-<env>-vX.Y.Z.elf`). The boot log prints the same as `[boot] last restart:`.
- Every deliberate restart goes through `platform::restart(why)`
  (`src/platform/restart_info.h`), never `ESP.restart()`, so its reason is shown.
- The monitor's `esp32_exception_decoder` filter turns `Backtrace: 0x...` into
  file:line if the ELF matches the running firmware. Keep `.pio/build/esp32s3/firmware.elf`
  from the build you flashed.
- Manual decode:
  ```bash
  ~/.platformio/packages/toolchain-xtensa-esp-elf/bin/xtensa-esp32s3-elf-addr2line \
    -pfiaC -e .pio/build/esp32s3/firmware.elf 0x4200abcd 0x4200ef01
  ```
- **Core dump:** written to the `coredump` partition on panic. Read it out:
  ```bash
  ~/.platformio/penv/bin/esptool --chip esp32s3 read-flash 0xFF0000 0x10000 coredump.bin
  uvx esp-coredump info_corefile -t raw -c coredump.bin .pio/build/esp32s3/firmware.elf
  ```
  Release builds attach `firmware-<env>-vX.Y.Z.elf` for decoding field crashes.

## Memory

- `/api/stats` (and the dashboard's _Device → Health_) reports `heap` (internal free),
  `heapMin` (lowest since boot) and `psram` (free PSRAM). From v0.2.6 it needs the
  login: `curl -u admin:<password> http://s3adblock.local/api/stats`.
- Warning signs:
  - **heapMin < 40 KB**: TLS handshakes will fail (each session needs ~45 KB of
    internal RAM; mbedTLS buffers can't go to PSRAM with the prebuilt libs);
  - `heap` drifting down over days: a leak or fragmentation (nothing in the DNS path
    should allocate);
  - stack overflow panics name the task: raise its stack (sizes in
    `src/tasks/dns_service.cpp` and `src/main.cpp`).
- Temporary deep dive: log `uxTaskGetStackHighWaterMark(nullptr)` from a task, or
  `heap_caps_print_heap_info(MALLOC_CAP_INTERNAL)`.

## Watchdog resets

- `E (...) task_wdt: Task watchdog got triggered` lists the task that didn't reset
  in 5 s.
- Usual causes:
  - a blocking call without a timeout (TLS connect, HTTP read, `select()` with
    NULL);
  - a busy loop on core 0 starving `IDLE0` (task `IDLE0` in the crash record): a
    task above idle priority spinning on `yield()`, as the web task did up to v0.2.7;
  - a long flash erase in one go: chunk writes and reset the watchdog between
    chunks.
- Reset reason on boot: `TG1WDT_SYS_RESET` / `TASK_WDT` = watchdog;
  `BROWNOUT_RST` = power. Weak USB ports (routers, hubs) may sag; use a 5 V/1 A supply.

## Stress tests against the board

```bash
python3 tools/dns_load.py <ip> 60000 70      # mixed DNS load, flags silences (restarts)
python3 tools/http_stall.py <ip> 40 trickle  # slow HTTP client; expect "no restart"
python3 tools/http_stall.py <ip> 40 stall    # client that stops reading the page
```

Household DNS goes through the board, so run them when a short outage is acceptable.
A crash overwrites the stored crash record.

## Wi-Fi drops

- Our log shows `[W][wifi] disconnected` / `reconnected after N s`; after 10 minutes
  down the device reboots. For the driver's reason codes, build with
  `-DCORE_DEBUG_LEVEL=3` (Arduino core log). Common ones: `201 NO_AP_FOUND`,
  `15 4WAY_HANDSHAKE_TIMEOUT` (wrong password or weak signal), `8 ASSOC_LEAVE`.
- RSSI below about −75 dBm causes instability: move the board, or keep the antenna
  end clear of metal.
- `WiFi.setSleep(false)` is set; power save adds DNS latency.

## DNS problems

```bash
dig @<ip> example.com              # timing in ";; Query time"
dig @<ip> doubleclick.net          # expect 0.0.0.0
dig @<ip> example.com +tcp         # TCP path
for i in $(seq 50); do dig @<ip> +short r$i.example.com & done; wait   # burst
```

- Slow first lookups but fast repeats → cold TLS handshake (connections idle-close
  after 9 s; resumption should make reconnects cheap). The dashboard's upstream table
  shows each upstream's state, OK/fail counts and last latency; `[up]` log lines show
  state changes.
- Dashboard **Plain DNS in use** banner → ports 853 and 443 to 1.1.1.1/9.9.9.9 are blocked
  or failing. Test from the Mac: `kdig @1.1.1.1 +tls example.com` (knot) or
  `openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com`.
- Clients bypassing the blocker → IPv6 RDNSS or browser DoH (docs/ROUTER_SETUP.md).
