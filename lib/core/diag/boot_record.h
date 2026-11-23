#pragma once
// What GET /api/health reports about restarts across boots: how many boots and crashes
// the board has had (bootCount, crashCount) and whether this boot follows a firmware
// rollback (otaRolledBack). Both are read and written once, in setup(), never later.

#include <cstdint>

#include "diag/restart.h"
#include "hal/kv_store.h"

namespace diag {

struct BootCounters {
  uint32_t boots = 0;
  uint32_t crashes = 0;
};

// NVS keys (<= 15 chars).
constexpr const char* kBootCountKey = "boot_count";
constexpr const char* kCrashCountKey = "crash_count";
constexpr const char* kOtaBadKey = "ota_bad";
constexpr const char* kNoInvalidImage = "-";  // stored when no image is marked invalid

// A panic, any watchdog, a CPU lockup (isCrash) or a brownout: the board stopped
// without the firmware deciding to.
bool countsAsCrash(ResetCause cause);

// Adds this boot (and its crash, if any) to the stored totals and returns them.
// Totals saturate instead of wrapping.
BootCounters recordBoot(hal::IKeyValueStore& kv, ResetCause cause);

// The bootloader (crash loop of a new image) or diag::otaVerdict() marks a rolled-back
// image invalid; ESP-IDF keeps reporting that partition afterwards. `invalidImage` is an
// id of the image now marked invalid (e.g. hex of its app SHA-256), or nullptr/"" when
// none is. True only on the first boot that sees a given invalid image, so the flag
// means "rolled back since the last boot", not "ever". Remembers the id in kv; the
// first boot with nothing stored only records (an old rollback is not news).
bool rolledBackThisBoot(hal::IKeyValueStore& kv, const char* invalidImage);

}  // namespace diag
