---
name: blocklist
description: Blocklist format, building and updating. Use when changing the hash/index format, tools/build_blocklist.py, the 02:00 IST auto-update (scheduler, ETag, validation, atomic swap), custom block/allow rules, or when a list fails to load or update.
---

# Blocklist

Design: [ARCHITECTURE.md §6](../../../docs/ARCHITECTURE.md).

## Format v2 (`/blocklist.bin` on LittleFS)

- **Hash:** FNV-1a 64 of the lowercase name (no trailing dot), **low 48 bits**.
  The top 16 of those bits are the bucket; the low 32 bits are the stored suffix.
- **Header (32 bytes, LE):**

  | Bytes | Field |
  |---|---|
  | 0–3 | magic `ADBL` |
  | 4 | version 2 |
  | 5 | hash_bits 48 |
  | 6 | prefix_bits 16 |
  | 7 | flags 0 |
  | 8–11 | count N |
  | 12–15 | CRC-32 of the payload |
  | 16–23 | build time (unix s) |
  | 24–31 | reserved 0 |

- **Payload:** `uint32 bucket_start[65537]` (monotonic, last == N), then
  `uint32 suffix[N]`, sorted within each bucket.
- **Matching:** the name and each parent down to two labels (never the bare TLD).
  No `www.` stripping.
- **Legacy:** upstream's headerless 40-bit sorted blob is accepted on manual
  upload only, if strictly ascending.
- **Rule:** the C++ (`lib/core/blocklist/hash.h`, `format.cpp`) and Python
  (`tools/build_blocklist.py`) must agree. A test checks golden hashes on both
  sides; change them together.

## Build a list

```bash
python3 tools/build_blocklist.py data/blocklist.bin                 # default sources
python3 tools/build_blocklist.py out.bin hosts.txt https://...      # custom sources
python3 tools/build_blocklist.py --format legacy out.bin            # upstream C3 devices
python3 -m unittest discover -s tools -p 'test_*.py'
```

- Inputs: hosts files, plain domain lists, AdGuard `||d^` / `@@||d^`.
- Regex, `$modifiers` and cosmetic rules are skipped and counted.
- A missing source fails the build (`--allow-missing` to override).
- CI rebuilds the default list weekly and publishes it at
  `https://github.com/denzilrdz/esp32-s3-adblock/releases/download/blocklist/blocklist.bin`.

## Daily update (maintenance task)

Code: `lib/core/sched/daily_scheduler.*`, `lib/core/update/updater.*`.

1. Wait for NTP sync (and a plausible year). Timezone `IST-5:30`.
2. Due when local time ≥ 02:00 + jitter (0–10 min) and the last success date ≠
   today (stored in NVS: no double runs across reboots).
3. GET with `If-None-Match: <stored ETag>`. 304 → "unchanged", done.
4. Stream 200 → `/blocklist.tmp`, resetting the watchdog per chunk. Check free space
   first.
5. Validate: magic/version/bits, size formula, N ≤ max, N ≥ min (1000), CRC, bucket
   monotonicity, suffix order. Any failure → delete tmp, keep the old list.
6. Swap: live → `.old`, tmp → live, delete `.old`. Load into a new PSRAM buffer,
   `store(release)`, wait for the readers' quiescent generation, free the old one.
   If PSRAM can't hold both, bridge via the file-backed index.
7. Failure → retry hourly, max 6 times, then wait for the next 02:00.
8. Record time, result, count, ETag and build date in NVS; shown on the dashboard.

Boot recovery: valid live → use it; else valid `.old` → restore it; else empty
list + immediate download.

## Tests to keep green (`test/test_blocklist`, `test_scheduler`, `test_updater`)

- **Parent matching:** `ads.example.com` blocks `x.ads.example.com`, not
  `example.com`.
- **Collisions:** forged equal hashes resolve consistently; the allowlist overrides.
- **Corrupt download:** bad magic, CRC, truncation, unsorted data, oversize → old
  list stays.
- **Scheduler:** 02:00 trigger, reboot after a run, retry after failure, no run
  before time sync.
- **ETag:** 304 path, and a changed ETag downloads.

## Troubleshooting

- Dashboard says `validation failed: crc` → the download was truncated or the CDN
  changed it; check `Content-Length` in the serial log.
- `entries 0` after boot → no valid list and no `.old` file; trigger "Update now" or
  run `uploadfs`.
- The list is too big → raise `max_entries` only if the PSRAM budget allows it (see
  ARCHITECTURE §11).
