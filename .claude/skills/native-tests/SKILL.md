---
name: native-tests
description: Write and run host-side unit tests. Use when adding or fixing any feature or bug (tests are mandatory), creating a fake for a hardware-abstraction interface, running `pio test -e native`, checking coverage, or debugging a failing Unity test.
---

# Native tests (PlatformIO + Unity, runs on macOS)

## Rules

- Every feature and bug fix needs a test. `pio test -e native` must be green before
  committing.
- Only `lib/core/` is testable natively. If logic you need to test lives in `src/`,
  move it into `lib/core/` behind an interface first.
- No real time, randomness, network or filesystem in tests: use the fakes.

## Layout

```
test/
  fakes/                 header-only fakes (FakeClock, FakeRandom, FakeTransport,
                         FakeHttpClient, MemFileSystem, MemKvStore, CapturingLogger)
                         and builders (dns_builder.h packets, blocklist_builder.h v2 files)
  test_dns/test_main.cpp         parser/builder, EDNS0, malformed, blocked replies,
                                 question case echoed exactly (DNS 0x20)
  test_policy/test_main.cpp      policy order: loopback bypass, ban, rewrite, pause, lists
  test_blocklist/test_main.cpp   hash, index, parent matching, collisions, format
  test_cache/test_main.cpp       TTL decrement/expiry, LRU eviction, negative caching,
                                 CD=1 answers never cached
  test_scheduler/test_main.cpp   02:00 local trigger, dedupe, retry, no-sync gating
  test_upstream/test_main.cpp    fallback chain, health FSM, pipelining, timeouts, blame
                                 windows (stuck bursts), kTooBig, plain-UDP socket rotation
  test_updater/test_main.cpp     ETag, validation, atomic swap, corrupt download
  test_config/test_main.cpp      settings validation, NVS round trip, upstream chain
  test_auth/test_main.cpp        password hashing, setup code, lockout, Host/Origin, sessions
  test_diag/test_main.cpp        restart cause names, crash summary, backtrace text,
                                 software watchdog (LivenessMonitor), OTA rollback verdict
  test_clients/test_main.cpp     ban list, pause timer, client directory (stalest
                                 replaced, wrap-safe), per-client in-flight limiter
  test_soak/test_main.cpp        DNS pipeline soak under ASan (-DSOAK_SCALE=10 for long)
  test_netsim/test_main.cpp      90 days of bad internet: scheduler + updater + watchdog
  test_local_zones/test_main.cpp localhost, canary domains, private reverse zones
  test_util/test_main.cpp        CRC-32, civil time, SHA-256/HMAC/PBKDF2 vectors, paced
                                 send (pieces and partial sends under one deadline),
                                 private-IPv4 ranges, certificate validity dates
  test_json/test_main.cpp        JSON reader/writer (malformed input, depth, escapes),
                                 weekday/addDays/HH:MM parsing
  test_reboot/test_main.cpp      scheduled reboot: window, DST, midnight, fresh boot, once a day
  test_backup/test_main.cpp      settings file round trip, every rejection path, rb_* keys,
                                 rule-domain normal form
```

Each `test_<area>` folder is a separate binary. Only folders starting `test_` are run.
`test_build_src = no`, so `src/` is never compiled for native.

## Run

```bash
pio test -e native                    # everything
pio test -e native -f test_cache      # one folder
pio test -e native -f test_dns -v     # verbose (shows each assertion)
tools/coverage.sh                     # tests + coverage -> coverage/index.html
```

Coverage (`[env:coverage]`, no sanitizers) uses `--coverage` and gcovr with
`--gcov-executable "xcrun llvm-cov gcov"` on macOS (wrapped in `tools/coverage.sh`;
run `tools/setup-dev.sh` once). Only `lib/core` is measured: `src/` needs hardware.

## Writing a test

```cpp
#include <unity.h>
#include "sched/daily_scheduler.h"
#include "fakes/fake_clock.h"  // test/ is on the include path (-Itest)

static FakeClock fakeClock;

void setUp() { fakeClock = FakeClock{}; }
void tearDown() {}

static void test_runs_once_at_2am_local() {
  fakeClock.setSynced(true);
  fakeClock.setLocal(2026, 10, 15, 1, 59, 0);          // 01:59 local (FakeClock: UTC+05:30)
  DailyScheduler s(fakeClock, /*hour=*/2, /*minute=*/0);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.advanceSeconds(60);                         // 02:00
  TEST_ASSERT_TRUE(s.due());
  s.markSuccess();
  TEST_ASSERT_FALSE(s.due());                       // no double run
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_runs_once_at_2am_local);
  return UNITY_END();
}
```

Python tests in `tools/` (`python3 -m unittest discover -s tools -p 'test_*.py'`) guard
the web pages and the dashboard's server rules (`test_web_pages.py`) and the blocklist
builder, including its limits against `format.h` and `partitions_16MB.csv`
(`test_build_blocklist.py`).

## Testing code in src/

`src/` can't be compiled natively, so put the **decision** in `lib/core` as a small
pure function or class and keep only the I/O in `src/`: e.g. `dns::decidePolicy()`
(AppPolicy), `diag::otaVerdict()` (rollback), `clients::InFlightLimiter` and
`util::sendAllWithDeadline()` (DnsService), `util::certValidity()` (TlsStream). A
change in `src/` that has no such seam needs one before its fix.

## Adding a fake

1. Find the interface in `lib/core/hal/` (e.g. `IHttpClient`).
2. Add `test/fakes/fake_<thing>.h`: header-only, records calls, returns scripted
   results (queue of responses, injectable errors).
3. Keep fakes dumb. Logic under test belongs in `lib/core`.

## Make sure a test can fail

For bug fixes and security fixes, break the fixed line on purpose (keep it
compiling: `-Werror` turns an unused variable into a build error that looks like
`ERRORED`), confirm the new test fails, then restore. Several tests in this repo were
strengthened this way.

## Pitfalls

- Use `TEST_ASSERT_EQUAL_HEX8_ARRAY` for packet bytes, so failures show a diff.
- Build DNS test packets with helpers in `test/fakes/dns_builder.h`, not hand-typed
  hex, except for deliberately malformed packets.
- The native env compiles with `-Wall -Wextra -Werror`, so warnings fail the test.
- If a test needs a static/global, reset it in `setUp()`; tests in one binary share
  state.
- Don't name test globals `clock`, `time` or `random`: they collide with libc
  functions on macOS. Use `fakeClock`, `fakeRandom`. Never name anything `unix`: it
  is a predefined macro on the host compilers.
- `FakeTransport` reports an inbox entry bigger than the receive buffer as
  `IoStatus::kTooBig` with its ID, like the real DoT/DoH transports.
- A health test that relies on N stuck queries making N failures no longer holds:
  silence counts once per upstream per `hedgeAfterMs`. Lower `failuresToDown`
  instead.
- Native tests run under AddressSanitizer + UBSan. An out-of-bounds read shows up
  as `ERRORED`; run `pio test -e native -f <test> -v` to see the ASan report.
