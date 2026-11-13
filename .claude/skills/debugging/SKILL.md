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
- A LAN host can't cause these any more by design (audit 2026-11): TCP/53 replies
  have a 1 s total budget, `dns_io` yields after 16 datagrams. A watchdog reset right
  after `dnsperf`/`dns_load.py` against the board is a regression.
- Reset reason on boot: `TG1WDT_SYS_RESET` / `TASK_WDT` = watchdog;
  `BROWNOUT_RST` = power. Weak USB ports (routers, hubs) may sag; use a 5 V/1 A supply.

## Stress tests against the board

```bash
python3 tools/dns_load.py <ip> 60000 70      # mixed DNS load, flags silences (restarts)
python3 tools/http_stall.py <ip> 40 trickle  # slow HTTP client; expect "no restart"
python3 tools/http_stall.py <ip> 40 stall    # client that stops reading the page
python3 tools/http_stall.py <ip> 45 slowread # trickle reader; dashboard freed <= ~20 s

# every hang ends in a restart with its reason (needs a netrc with the dashboard login,
# see the script; flashes the self-test build, then the release build back)
pio run -e esp32s3 && pio run -e esp32s3_selftest
python3 tools/selftest_board.py s3adblock.local ~/.s3adblock.netrc
```

Household DNS goes through the board, so run them when a short outage is acceptable.
A crash overwrites the stored crash record. Restart reasons from the software watchdog
(ARCHITECTURE.md §4.3): "web task stuck", "blocklist download stuck", "upstream task
stuck", "software watchdog stopped".

## Firmware update rollback

- `[E][ota] rollback: new firmware without Wi-Fi or DNS after 5 min` / `... never
finished booting` (10-min `esp_timer` from the start of `setup()`, e.g. a Wi-Fi
  regression) → the previous image runs again; the reason is under _Device →
  Health_.
- An image stays **pending** (no "marked valid" line) while the dashboard doesn't
  answer its local self-check (`GET /` with the board's IP as Host). That never rolls
  back by itself (a LAN host could hold the web task to force a downgrade); the
  bootloader rolls back at the next restart if it never answers.

## Blocklist download failures

The dashboard's _Blocklist_ result carries the details (v0.2.8+): `hop N <stage>:
<esp_err>, errno E, tls -0xXXXX cert 0xF, T s`. Hop 1 is the list URL (github.com),
hop 2 the redirect target (release-assets.githubusercontent.com). `tls` is the mbedTLS
error (e.g. `-0x2700` = certificate verify failed; then `cert` holds the
`MBEDTLS_X509_BADCERT_*` flags), `errno 113` = host unreachable, a time near 20 s = a
read or connect timeout. One failure on a slow connection is normal: the scheduler
retries hourly (up to 6 times a day) and the old list stays active.

## Wi-Fi drops

- Our log shows `[W][wifi] disconnected (reason N NAME)`, `still down after N s (last
reason ...): retry N` (our own retries: 10 s, 20 s, then every 30 s; a due retry waits
  up to 30 s while associated and waiting for DHCP: `joined, waiting for an address`) and
  `reconnected after N s (N retries, rssi ...)`; after 10 minutes down the device
  reboots. Set _Settings → Log level_ to **debug** for every driver event: each
  disconnect with its reason and RSSI, and which BSSID (mesh node) and channel it joins.
- Common reasons: `201 NO_AP_FOUND` (router off), `210` (network seen, security doesn't
  match: a Deco reboots in stages), `6 NOT_AUTHED`, `200 BEACON_TIMEOUT`, `15`
  (handshake timeout: wrong password or weak signal). `8 ASSOC_LEAVE` and
  `36 STA_LEAVING` are our own or the core's disconnects before a retry.
- **Arduino's auto-reconnect gives up for good** on reasons outside its list in
  `WiFi/src/STA.cpp` (`_is_staReconnectableReason`, e.g. 202, 210-212): that's why
  `superviseWifi()` (`util::WifiSupervisor`) retries on its own. Test reconnects by
  rebooting the router while recording the UART log (`/dev/cu.usbmodem…` = "USB Single
  Serial", the CH343; "USB JTAG_serial debug unit" is the native port, which only shows
  ROM boot lines).
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
- A standby upstream (Quad9, DoH, plain) shows **down/degraded with 0 OK** for days →
  usually stale: a short outage made it fail, and a standby is only used again when
  the active one fails. _Test all upstreams_ under Upstream DNS (`POST
/api/upstreams/test`) sends `example.com` through every upstream once and shows the
  result per upstream (`[up] test <name>: ...` in the log); a pass puts it back to standby. A
  `connect failed (TLS -0x....)` there is real: decode the mbedTLS code.
- `[up] <name>: answer for <name> larger than 4096 bytes, answering SERVFAIL` → a
  huge answer (big TXT/DNSKEY sets with DO). Expected for that name; the upstream is
  not marked down for it.
- `[up] <name>: TLS connect failed (error -0x2700)` after the clock synced, with the
  CA bundle unchanged → a certificate in the upstream's chain is outside its validity
  dates by more than an hour (or the board's clock is wrong: check _time_ on the
  dashboard).
- Encrypted upstreams no longer go down because one website's own DNS servers are
  slow: silence counts once per upstream per 1.2 s, never if it answered anything
  meanwhile. Repeated "down" with plain fallback is a real outage of port 853/443.
- Dashboard **Plain DNS in use** banner → ports 853 and 443 to 1.1.1.1/9.9.9.9 are blocked
  or failing. While it shows, the encrypted upstreams are retried every 10 s. Test from the Mac: `kdig @1.1.1.1 +tls example.com` (knot) or
  `openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com`.
- Clients bypassing the blocker → IPv6 RDNSS or browser DoH (docs/ROUTER_SETUP.md).
