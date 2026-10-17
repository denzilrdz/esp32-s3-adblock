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

  | Bytes | Field                 |
  | ----- | --------------------- |
  | 0–3   | magic `ADBL`          |
  | 4     | version 2             |
  | 5     | hash_bits 48          |
  | 6     | prefix_bits 16        |
  | 7     | flags 0               |
  | 8–11  | count N               |
  | 12–15 | CRC-32 of the payload |
  | 16–23 | build time (unix s)   |
  | 24–31 | reserved 0            |

- **Payload:** `uint32 bucket_start[65537]` (monotonic, last == N), then
  `uint32 suffix[N]`, sorted within each bucket.
- **Matching:** the name and each parent down to two labels (never the bare TLD).
  No `www.` stripping.
- Upstream's headerless 40-bit format is **not** supported (48-bit hashes can't be
  derived from it).
- **Rule:** the C++ (`lib/core/blocklist/hash.h`, `format.cpp`) and Python
  (`tools/build_blocklist.py`) must agree. A test checks golden hashes on both
  sides; change them together.

## Build a list

```bash
python3 tools/build_blocklist.py out.bin                             # default sources
python3 tools/build_blocklist.py out.bin hosts.txt https://...      # custom sources
python3 -m unittest discover -s tools -p 'test_*.py'
```

- Inputs: hosts files, plain domain lists, AdGuard `||d^` / `@@||d^`.
- Regex, `$modifiers` and cosmetic rules are skipped and counted.
- A missing source fails the build (`--allow-missing` to override).
- CI rebuilds the default list daily at 00:17 IST (before the boards check at 02:00) and publishes it at
  `https://github.com/denzilrdz/esp32-s3-adblock/releases/download/blocklist/blocklist.bin`.

## Daily update (maintenance task)

Code: `lib/core/sched/daily_scheduler.*`, `lib/core/update/updater.*`, wired up in
`src/app/blocklist_manager.*` (PSRAM/file index install, custom rules, NVS settings
`bl_url`, `bl_hour`, `bl_min`, `bl_etag`, `sch_last`). HTTPS client:
`src/platform/esp_http.*` (esp_http_client + CA bundle, manual redirects, ETag).

1. Wait for NTP sync (and a plausible year). Timezone `IST-5:30`.
2. Due when local time ≥ 02:00 + jitter (0–10 min) and the last success date ≠
   today (stored in NVS: no double runs across reboots).
3. GET with `If-None-Match: <stored ETag>`. 304 → "unchanged", done.
4. Stream 200 → `/blocklist.tmp`, resetting the watchdog per chunk. Check free space
   first.
5. Validate: magic/version/bits, size formula, N ≤ max, N ≥ min (1000), CRC, bucket
   monotonicity, suffix order. Any failure → delete tmp, keep the old list.
6. Swap: `prepareSwap()` (a file-backed bridge index releases the open file), live → `.old`,
   tmp → live, delete `.old`; any rename failure reinstalls the live list. Then
   `BlocklistManager::install()` loads the file into a new PSRAM buffer and
   `IndexHolder::publish()` swaps it in (readers never lock; the old index is freed
   once its reader count is zero). If PSRAM can't hold both, it bridges through a
   file-backed index.
7. Failure → retry hourly, max 6 times, then wait for the next 02:00.
8. ETag in NVS (`bl_etag`), last result/time in NVS (`bl_res`, `bl_at`); entry
   count and build date come from the loaded list. All shown on the dashboard.
   Only `https://` URLs are accepted, for the request and every redirect.

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

- Dashboard says `invalid list: crc mismatch` / `download truncated` → network
  problem or a wrong file at the URL; the old list stays. `bad magic` → not a v2
  file (e.g. an HTML error page or an old 40-bit list).
- `0 domains` after boot → no valid list and no `.old` file; it downloads as soon as
  the clock syncs. Or _Update now_ / upload a file on the dashboard.
- `too many entries` → the limit is 1M entries, set in
  `BlocklistManager`'s constructor; raise only if the budget (ARCHITECTURE §11) allows.
