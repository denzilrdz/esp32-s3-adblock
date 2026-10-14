# CLAUDE.md

Pi-hole-style DNS ad blocker for the **ESP32-S3 N16R8** (16 MB flash, 8 MB octal
PSRAM). It answers blocked names locally (0.0.0.0 / :: / NODATA), forwards the rest
over DNS-over-TLS (Cloudflare, Quad9) with DoH and optional plain-UDP fallback, caches
answers in PSRAM, and refreshes its blocklist daily at 02:00 IST. Fork of
M-Abozaid/esp32-c3-adblock (MIT). **Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
before changing core logic or tasks.** User docs: README.md, docs/ROUTER_SETUP.md.

## Hardware and environments

| Env | Board | Notes |
|---|---|---|
| `esp32s3` | esp32-s3-devkitc-1, N16R8 | **main target** (default env); `qio_opi`, 16 MB, PSRAM |
| `c3` | esp32-c3-devkitm-1 | "lite" profile: no PSRAM, list read from flash; compile-tested |
| `esp32dev` | classic ESP32, 4 MB | lite profile; compile-tested |
| `native` | host (macOS/Linux) | Unity tests for `lib/core`, ASan + UBSan |
| `coverage` | host | like `native` with `--coverage` (used by `tools/coverage.sh`) |

Framework: Arduino-ESP32 **2.0.17** on **ESP-IDF 4.4** (platform `espressif32@7.1.3`,
pinned). Check APIs against those versions, not IDF 5 / core 3.x docs (the planned
move to pioarduino/core 3.x is in ARCHITECTURE.md §15).

## Commands

```bash
tools/setup-dev.sh                       # once: uv sync (.venv from uv.lock) + git hooks
cp src/secrets.example.h src/secrets.h   # once: first-boot defaults (gitignored)
pio run -e esp32s3                       # build firmware
pio run -e esp32s3 -t upload             # flash over USB
pio device monitor -e esp32s3            # serial monitor (115200, exception decoder)
pio test -e native                       # all native unit tests
pio test -e native -f test_dns           # one test folder
tools/coverage.sh                        # native tests + coverage -> coverage/index.html
tools/format.sh [--check]                # clang-format (C/C++) + black (Python)
tools/lint.sh                            # clang-tidy on lib/core (.clang-tidy)
tools/make_factory.sh esp32s3            # merged image flashable at 0x0 (after a build)
python3 tools/build_blocklist.py out.bin # build a format-v2 blocklist (stdlib only)
python3 -m unittest discover -s tools -p 'test_*.py'   # tool tests
```

`pio` may be the Homebrew one or `.venv/bin/pio` (same pinned 6.2.0). Details, OTA and
port troubleshooting: skill `build-flash`.

## Layout

```
lib/core/      portable C++17 logic, NO Arduino/IDF headers (tested natively)
  dns/ blocklist/ cache/ upstream/ sched/ update/ config/ auth/ hal/ util/
src/           ESP32-only: main.cpp (composition root), platform/ (HAL impls: TLS,
               transports, LittleFS, NVS, HTTP), tasks/ (DNS service tasks),
               app/ (blocklist manager, client table, DNS policy),
               web/ (dashboard REST API, page.h, Wi-Fi setup portal)
test/          Unity tests: test/test_<area>/test_main.cpp, fakes in test/fakes/
tools/         blocklist builder, factory image, setup/format/lint/coverage scripts
installer/     browser installer (esp-web-tools pinned by SHA-512), deployed by CI
docs/          ARCHITECTURE.md, ROUTER_SETUP.md
.github/       CI (build.yml), release.yml (v* tags), weekly blocklist.yml
.claude/skills/ task playbooks (see list below)
```

## Coding rules

- C++17 (`-std=gnu++17`), no exceptions in our code (status enums/structs), no RTTI.
- Naming: `PascalCase` types, `camelCase` functions/variables, `kPascalCase`
  constants, `member_` trailing underscore, `snake_case` file names. Format with
  `tools/format.sh` (clang-format, 110 columns).
- `lib/core` must not include `Arduino.h`, FreeRTOS, lwIP or ESP-IDF headers. Hardware
  goes behind interfaces in `lib/core/hal/`; inject dependencies through constructors,
  no new globals.
- **DNS hot path** (`dns_io`/`dns_tcp`, policy, blocklist lookup, cache lookup): no
  heap allocation, no `String`, no blocking calls, no flash writes, no per-query
  logging above DEBUG.
- Large buffers (blocklist, cache, pending pool) go in PSRAM (`platform::allocLarge`).
  Never PSRAM for task stacks, DMA buffers, or anything touched with the flash cache
  disabled.
- RAII for sockets, TLS sessions, files, PSRAM buffers and mutexes.
- Every blocking call in a watched task needs a timeout < 5 s (task watchdog).
- One task per socket: lwIP is built without full-duplex netconn.
- `-Wall -Wextra` must stay clean (src/ and lib/core); native tests use `-Werror`.

## Testing rule

Every feature or bug fix comes with native tests in `test/` (use fakes behind the HAL
interfaces; skill `native-tests`). `pio test -e native` must pass before every
commit. Hooks from `tools/setup-dev.sh`: pre-commit = secrets guard, format check,
native tests; pre-push = clang-tidy + esp32s3 firmware build.

## Git rules

- Commit directly on `main`; small, focused commits; Conventional Commits
  (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`, `refactor:`).
- All commits and tags are GPG-signed (configured in the local repo config).
- Never change global git config. Never force-push without asking. Ask before pushing.
- Never commit `src/secrets.h` or any real password, key, or token.
- Remotes: `origin` = git@github-denzil:denzilrdz/esp32-s3-adblock.git, `upstream` =
  M-Abozaid/esp32-c3-adblock (unrelated history: cherry-pick, don't merge; no tags).
- Add user-visible changes to `CHANGELOG.md` under `[Unreleased]`.
- When you learn a new command, gotcha, or convention, update this file or the
  relevant skill in the same commit.

## Gotchas

- **Octal PSRAM:** `board_build.arduino.memory_type = qio_opi` (quad flash, octal
  PSRAM). `opi_opi` boot-loops the N16R8. GPIO 35–37 belong to the PSRAM.
- **Partition tables:** `partitions_16MB.csv` (S3), `partitions_4MB.csv` (lite). The
  LittleFS partition must stay labelled and typed `spiffs` (IDF 4.4 has no littlefs
  subtype). Changing offsets wipes data and needs a USB flash.
- **mbedTLS buffers are internal RAM only** (prebuilt libs): about 45 KB per TLS
  session, so at most 2 at once.
- **UDP socket buffers only 6 datagrams** (`LWIP_UDP_RECVMBOX_SIZE`), so the DNS
  receive task must never block.
- **Only 16 lwIP sockets in total**: budget in ARCHITECTURE.md §11 before adding one.
- **ARP/lwIP core calls** (e.g. `etharp_find_addr`) only via `tcpip_callback`.
- **C hooks from Arduino** (`verifyRollbackLater`, …) need `extern "C"` to override.
- `<esp_crt_bundle.h>` resolves to the Arduino copy; use `platform/crt_bundle.h`.
- mDNS name: `s3adblock.local` on the S3, `c3adblock.local` on C3/ESP32.
- **First boot:** a placeholder/weak `WEB_PASS` never works; the serial console prints
  a one-time setup code. ArduinoOTA stays off until `OTA_PASS` is real (10+ chars).
- **IPv6 / browser secure DNS bypass** the blocker: docs/ROUTER_SETUP.md.
- **SSH alias:** the `origin` remote uses the `github-denzil` host alias from
  `~/.ssh/config`; don't rewrite it to `github.com`.
- **macOS:** `pio` is at `/opt/homebrew/bin/pio` (or `.venv/bin/pio`). Don't name test
  globals `clock`/`time` (libc clash).

## Skills (.claude/skills/)

`build-flash`, `native-tests`, `dns-protocol`, `upstream-resolvers`, `blocklist`,
`debugging`, `release`, `security-checklist`.
