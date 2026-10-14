---
name: debugging
description: Diagnose problems on the device. Use when reading serial logs, decoding a crash backtrace or core dump, checking heap/PSRAM/stack usage, investigating task watchdog resets, Wi-Fi drops, slow or failing DNS, or upstream/TLS failures.
---

# Debugging on hardware

## Serial log

```bash
pio device monitor -e esp32s3        # 115200 baud, filters: esp32_exception_decoder, time
```

- Log tags: `[dns]`, `[up]` (upstream), `[cache]`, `[bl]` (blocklist), `[sched]`,
  `[wifi]`, `[web]`, `[ota]`.
- The level is set by `-DLOG_LEVEL=` in platformio.ini (default INFO). Use DEBUG
  only temporarily: per-query logging slows the hot path.
- Boot banner: firmware version, reset reason, PSRAM size, partition in use, free
  heap.

## Crash / backtrace

- The monitor's `esp32_exception_decoder` filter turns `Backtrace: 0x...` into
  file:line if the ELF matches the running firmware. Keep `.pio/build/esp32s3/firmware.elf`
  from the build you flashed.
- Manual decode:
  ```bash
  ~/.platformio/packages/toolchain-xtensa-esp32s3/bin/xtensa-esp32s3-elf-addr2line \
    -pfiaC -e .pio/build/esp32s3/firmware.elf 0x4200abcd 0x4200ef01
  ```
- **Core dump:** written to the `coredump` partition on panic. Read it out:
  ```bash
  python3 -m esptool --chip esp32s3 read_flash 0xFF0000 0x10000 coredump.bin
  espcoredump.py info_corefile -t raw -c coredump.bin .pio/build/esp32s3/firmware.elf
  ```
  (`espcoredump.py` comes from ESP-IDF's `components/espcoredump`; install with
  `pip install esp-coredump`.)

## Memory

- `/api/stats` and the boot log report `heap_free`, `heap_min`,
  `heap_largest_block`, `psram_free`, plus per-task stack high-water marks
  (`uxTaskGetStackHighWaterMark`).
- Warning signs:
  - **internal heap_min < 40 KB**: TLS handshakes will fail (each needs about
    45 KB internal);
  - `heap_largest_block` shrinking over days: fragmentation (someone is allocating
    in a loop);
  - a stack high-water mark < 512 B: increase that task's stack.

## Watchdog resets

- `E (...) task_wdt: Task watchdog got triggered` lists the task that didn't reset
  in 5 s.
- Usual causes:
  - a blocking call without a timeout (TLS connect, HTTP read, `select()` with
    NULL);
  - a busy loop on core 0 starving `IDLE0`;
  - a long flash erase in one go: chunk writes and reset the watchdog between
    chunks.
- Reset reason on boot: `TG1WDT_SYS_RESET` / `TASK_WDT` = watchdog;
  `BROWNOUT_RST` = power. The router's USB port may sag; use a 5 V/1 A supply.

## Wi-Fi drops

- The log shows a `[wifi]` disconnect with a reason code. Common ones:
  - `201 NO_AP_FOUND`
  - `15 4WAY_HANDSHAKE_TIMEOUT` (wrong password or weak signal)
  - `8 ASSOC_LEAVE`
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

- Slow first lookups but fast repeats → cold TLS handshake. Check `[up]` handshake
  time and resumption hits.
- Dashboard "plain fallback" banner → ports 853 and 443 to 1.1.1.1/9.9.9.9 are
  blocked or failing. Test from the Mac: `kdig @1.1.1.1 +tls example.com`.
- Clients bypassing the blocker → IPv6 RDNSS or browser DoH (see README).
