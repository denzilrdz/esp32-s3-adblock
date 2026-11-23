#include "diag/boot_record.h"

#include <cstring>

namespace diag {

bool countsAsCrash(ResetCause cause) {
  return isCrash(cause) || cause == ResetCause::kBrownout;
}

BootCounters recordBoot(hal::IKeyValueStore& kv, ResetCause cause) {
  BootCounters c;
  kv.getU32(kBootCountKey, c.boots);
  kv.getU32(kCrashCountKey, c.crashes);
  if (c.boots < UINT32_MAX) c.boots++;
  kv.setU32(kBootCountKey, c.boots);
  if (countsAsCrash(cause)) {
    if (c.crashes < UINT32_MAX) c.crashes++;
    kv.setU32(kCrashCountKey, c.crashes);
  }
  return c;
}

bool rolledBackThisBoot(hal::IKeyValueStore& kv, const char* invalidImage) {
  const char* now = invalidImage && *invalidImage ? invalidImage : kNoInvalidImage;
  char stored[72] = "";
  if (!kv.getString(kOtaBadKey, stored, sizeof(stored))) {
    // First boot with this feature: an image rolled back long ago (still marked invalid)
    // is not news. Remember the state, report nothing.
    kv.setString(kOtaBadKey, now);
    return false;
  }
  if (strcmp(stored, now) == 0) return false;
  kv.setString(kOtaBadKey, now);  // "-" once the slot is rewritten: the same image can count again
  return strcmp(now, kNoInvalidImage) != 0;
}

}  // namespace diag
