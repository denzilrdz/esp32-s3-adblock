#pragma once
// Why the board last restarted, for the boot log, /api/stats and the dashboard
// (skill debugging). The platform layer (src/platform/restart_info.cpp) fills a
// RestartInfo at boot from esp_reset_reason(), a note that platform::restart() leaves
// in RTC memory, and the summary of the core dump that ESP-IDF writes to flash on a
// panic or watchdog. This part only names and formats it.

#include <cstddef>
#include <cstdint>

namespace diag {

// Same order and values as ESP-IDF 5.5's esp_reset_reason_t (static_assert'ed on the
// device), so resetCauseFromIdf() is a range check.
enum class ResetCause : uint8_t {
  kUnknown,
  kPowerOn,
  kExternal,
  kSoftware,
  kPanic,
  kInterruptWatchdog,
  kTaskWatchdog,
  kOtherWatchdog,
  kDeepSleep,
  kBrownout,
  kSdio,
  kUsb,
  kJtag,
  kEfuse,
  kPowerGlitch,
  kCpuLockup,
};

ResetCause resetCauseFromIdf(int reason);  // out of range -> kUnknown
const char* resetCauseName(ResetCause cause);
// Panic, any watchdog or a CPU lockup: ESP-IDF writes a core dump for these.
bool isCrash(ResetCause cause);

constexpr size_t kMaxBacktrace = 16;

struct CrashRecord {
  bool present = false;
  char task[17] = {0};
  uint32_t pc = 0;
  uint32_t backtrace[kMaxBacktrace] = {0};
  uint8_t depth = 0;
  bool corrupted = false;
  char reason[96] = {0};  // panic text, e.g. "Task watchdog got triggered"
  char elfSha[17] = {0};  // leading hex digits of the crashed build's ELF SHA-256
};

// "0x4200abcd 0x4200ef01 ..." (pc first, then the backtrace frames that differ from
// it), ready for addr2line. Truncates at whole addresses; returns the length written.
size_t formatBacktrace(const CrashRecord& r, char* out, size_t cap);

struct RestartInfo {
  ResetCause cause = ResetCause::kUnknown;
  char note[40] = {0};  // why the firmware restarted itself (software restarts only)
  CrashRecord crash;    // may be left over from an earlier crash: see crashThisBoot()
  // The crash record belongs to this restart (a crash cause and a record present).
  bool crashThisBoot() const { return crash.present && isCrash(cause); }
};

// One line, e.g. "power on", "restarted by the firmware: Wi-Fi down for 10 min",
// "crash in task dns_up: LoadProhibited ...", "crash (task watchdog): dns_up (CPU 1)".
// For a watchdog crash the task named in the record is only whichever task happened
// to run when the watchdog fired, so the line names the tasks that didn't check in.
void describe(const RestartInfo& info, char* out, size_t cap);

// ESP-IDF's panic text for a task watchdog is long and multi-line:
//   "Task watchdog got triggered. The following tasks/users did not reset the
//    watchdog in time:\n - dns_up (CPU 1)\n - IDLE0 (CPU 0)\n"
// Condensed to one line that fits CrashRecord::reason with the culprits first:
//   "Task watchdog got triggered: dns_up (CPU 1), IDLE0 (CPU 0)".
// Other texts only get their newlines turned into spaces. Always NUL-terminates.
void condensePanicReason(const char* raw, char* out, size_t cap);

}  // namespace diag
