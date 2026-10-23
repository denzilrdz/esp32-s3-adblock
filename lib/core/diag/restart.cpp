#include "diag/restart.h"

#include <cstdio>
#include <cstring>

namespace diag {

ResetCause resetCauseFromIdf(int reason) {
  return (reason >= 0 && reason <= static_cast<int>(ResetCause::kCpuLockup)) ? static_cast<ResetCause>(reason)
                                                                             : ResetCause::kUnknown;
}

const char* resetCauseName(ResetCause cause) {
  switch (cause) {
    case ResetCause::kPowerOn: return "power on";
    case ResetCause::kExternal: return "reset pin";
    case ResetCause::kSoftware: return "restarted by the firmware";
    case ResetCause::kPanic: return "crash";
    case ResetCause::kInterruptWatchdog: return "crash (interrupt watchdog)";
    case ResetCause::kTaskWatchdog: return "crash (task watchdog)";
    case ResetCause::kOtherWatchdog: return "crash (watchdog)";
    case ResetCause::kDeepSleep: return "wake from deep sleep";
    case ResetCause::kBrownout: return "power dip (brownout)";
    case ResetCause::kSdio: return "SDIO reset";
    case ResetCause::kUsb: return "USB reset";
    case ResetCause::kJtag: return "JTAG reset";
    case ResetCause::kEfuse: return "eFuse error";
    case ResetCause::kPowerGlitch: return "power glitch";
    case ResetCause::kCpuLockup: return "crash (CPU lockup)";
    case ResetCause::kUnknown: break;
  }
  return "unknown";
}

bool isCrash(ResetCause cause) {
  switch (cause) {
    case ResetCause::kPanic:
    case ResetCause::kInterruptWatchdog:
    case ResetCause::kTaskWatchdog:
    case ResetCause::kOtherWatchdog:
    case ResetCause::kCpuLockup: return true;
    default: return false;
  }
}

size_t formatBacktrace(const CrashRecord& r, char* out, size_t cap) {
  if (!out || cap == 0) return 0;
  out[0] = 0;
  size_t len = 0;
  auto add = [&](uint32_t addr) {
    char a[12];
    const int n = snprintf(a, sizeof(a), "%s0x%08lx", len ? " " : "", static_cast<unsigned long>(addr));
    if (n <= 0 || len + static_cast<size_t>(n) >= cap) return false;
    for (int i = 0; i <= n; i++) out[len + i] = a[i];  // copies the NUL too
    len += static_cast<size_t>(n);
    return true;
  };
  if (r.pc && !add(r.pc)) return len;
  const size_t depth = r.depth < kMaxBacktrace ? r.depth : kMaxBacktrace;
  for (size_t i = 0; i < depth; i++) {
    if (i == 0 && r.backtrace[0] == r.pc) continue;  // the first frame usually is the pc
    if (!add(r.backtrace[i])) break;
  }
  return len;
}

void condensePanicReason(const char* raw, char* out, size_t cap) {
  if (!out || cap == 0) return;
  out[0] = 0;
  if (!raw) return;
  static const char kList[] = ". The following tasks/users did not reset the watchdog in time:";
  size_t n = 0;
  auto put = [&](char c) {
    if (n + 1 < cap) out[n++] = c;
  };
  const char* p = raw;
  const char* list = strstr(raw, kList);
  if (list) {
    for (; p < list; p++) put(*p);
    put(':');
    p = list + sizeof(kList) - 1;
  }
  bool first = true, space = false;
  for (; *p; p++) {
    if (list && p[0] == '\n' && p[1] == ' ' && p[2] == '-' && p[3] == ' ') {  // next culprit
      put(first ? ' ' : ',');
      if (!first) put(' ');
      first = false;
      space = false;
      p += 3;
      continue;
    }
    if (*p == '\n' || *p == '\r') {
      space = true;
      continue;
    }
    if (space && n) put(' ');
    space = false;
    put(*p);
  }
  while (n && out[n - 1] == ' ') n--;
  out[n] = 0;
}

void describe(const RestartInfo& info, char* out, size_t cap) {
  if (!out || cap == 0) return;
  const char* name = resetCauseName(info.cause);
  const bool watchdog =
      info.cause == ResetCause::kTaskWatchdog || info.cause == ResetCause::kInterruptWatchdog;
  if (info.cause == ResetCause::kSoftware && info.note[0]) {
    snprintf(out, cap, "%s: %s", name, info.note);
  } else if (info.crashThisBoot() && watchdog) {
    // "Task watchdog got triggered: dns_up (CPU 1)" -> name the culprits only.
    const char* why = info.crash.reason;
    const char* colon = strchr(why, ':');
    snprintf(out, cap, "%s%s%s", name, colon ? ":" : (*why ? ": " : ""), colon ? colon + 1 : why);
  } else if (info.crashThisBoot()) {
    const char* why = info.crash.reason[0] ? info.crash.reason : "";
    if (info.crash.task[0])
      snprintf(out, cap, "%s in task %s%s%s", name, info.crash.task, *why ? ": " : "", why);
    else
      snprintf(out, cap, "%s%s%s", name, *why ? ": " : "", why);
  } else {
    snprintf(out, cap, "%s", name);
  }
}

}  // namespace diag
