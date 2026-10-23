#pragma once
// Restart bookkeeping on the device (lib/core/diag names and formats it):
//  - restart(why) / noteRestart(why): every deliberate restart leaves `why` in RTC
//    memory, which survives a software reset but not a power cut.
//  - readRestartInfo(): once at boot, combines esp_reset_reason(), that note and the
//    summary of the core dump ESP-IDF wrote to flash on the last panic or watchdog.
//    The core dump stays in flash, so after an OTA update the new firmware still shows
//    the crash that happened before it.

#include "diag/restart.h"

namespace platform {

void noteRestart(const char* why);  // for restarts done elsewhere (rollback, ArduinoOTA)
[[noreturn]] void restart(const char* why);
diag::RestartInfo readRestartInfo();

}  // namespace platform
