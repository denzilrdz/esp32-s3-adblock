#include "diag/health.h"

#include <cstdarg>
#include <cstdio>

#include "util/civil_time.h"

namespace diag {

HealthReport evaluateHealth(const HealthInput& in) {
  HealthReport r;
  if (!in.blockingOn) r.issues |= kIssueBlockingOff;
  if (in.entries == 0 || !in.inMemory) r.issues |= kIssueBlocklistEmpty;
  if (in.timeSynced && in.lastSuccessUnix > 0) {
    const int64_t age = in.nowUnix > in.lastSuccessUnix ? in.nowUnix - in.lastSuccessUnix : 0;
    r.successAgeH = static_cast<int32_t>(age / 3600 > INT32_MAX ? INT32_MAX : age / 3600);
    if (age > kBlocklistStaleAfterS) r.issues |= kIssueBlocklistStale;
  }
  if (in.updateAttempted && !in.lastUpdateOk) r.issues |= kIssueBlocklistUpdateFailed;
  if (in.plainFallback) r.issues |= kIssuePlainFallback;
  if (!in.encryptedHealthy) r.issues |= kIssueUpstreamDown;
  if (in.heapBlock < kHeapLowBlockBytes) r.issues |= kIssueHeapLow;
  if (isCrash(in.resetCause)) r.issues |= kIssueCrashed;
  if (!in.timeSynced && in.uptimeS > kClockSyncGraceS) r.issues |= kIssueClockUnsynced;
  if (in.rssi < kWifiWeakBelowDbm) r.issues |= kIssueWifiWeak;
  return r;
}

const char* healthIssueCode(uint16_t issue) {
  switch (issue) {
    case kIssueBlockingOff: return "blocking_off";
    case kIssueBlocklistEmpty: return "blocklist_empty";
    case kIssueBlocklistStale: return "blocklist_stale";
    case kIssueBlocklistUpdateFailed: return "blocklist_update_failed";
    case kIssuePlainFallback: return "plain_fallback";
    case kIssueUpstreamDown: return "upstream_down";
    case kIssueHeapLow: return "heap_low";
    case kIssueCrashed: return "crashed";
    case kIssueClockUnsynced: return "clock_unsynced";
    case kIssueWifiWeak: return "wifi_weak";
    default: return nullptr;
  }
}

const char* resetCauseCode(ResetCause cause) {
  switch (cause) {
    case ResetCause::kPowerOn: return "poweron";
    case ResetCause::kExternal: return "external";
    case ResetCause::kSoftware: return "software";
    case ResetCause::kPanic: return "panic";
    case ResetCause::kInterruptWatchdog: return "int_wdt";
    case ResetCause::kTaskWatchdog: return "task_wdt";
    case ResetCause::kOtherWatchdog: return "wdt";
    case ResetCause::kDeepSleep: return "deepsleep";
    case ResetCause::kBrownout: return "brownout";
    case ResetCause::kSdio: return "sdio";
    case ResetCause::kUsb: return "usb";
    case ResetCause::kJtag: return "jtag";
    case ResetCause::kEfuse: return "efuse";
    case ResetCause::kPowerGlitch: return "power_glitch";
    case ResetCause::kCpuLockup: return "cpu_lockup";
    case ResetCause::kUnknown: break;
  }
  return "unknown";
}

bool anyEncryptedHealthy(const upstream::UpstreamStatus* status, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (!status[i].authenticated) continue;
    const upstream::HealthState s = status[i].state;
    if (s != upstream::HealthState::kDown && s != upstream::HealthState::kProbing) return true;
  }
  return false;
}

int64_t blocklistSuccessUnix(bool lastOk, int64_t lastAttemptUnix, uint32_t lastSuccessDate,
                             int64_t buildTimeUnix, int32_t utcOffsetSeconds) {
  if (lastOk && lastAttemptUnix > 0) return lastAttemptUnix;
  if (lastSuccessDate != 0) {
    util::CivilTime d;
    d.year = static_cast<int>(lastSuccessDate / 10000);
    d.month = static_cast<int>(lastSuccessDate / 100 % 100);
    d.day = static_cast<int>(lastSuccessDate % 100);
    if (d.month >= 1 && d.month <= 12 && d.day >= 1 && d.day <= 31)
      return util::unixFromCivil(util::addDays(d, 1), utcOffsetSeconds);  // next local midnight
  }
  return buildTimeUnix > 0 ? buildTimeUnix : 0;
}

namespace {

// snprintf into a fixed buffer; remembers overflow instead of truncating silently.
class FixedWriter {
 public:
  FixedWriter(char* out, size_t cap) : out_(out), cap_(cap) {
    if (cap_) out_[0] = 0;
  }
  void add(const char* fmt, ...) __attribute__((format(printf, 2, 3))) {
    if (failed_) return;
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(out_ + len_, cap_ - len_, fmt, ap);
    va_end(ap);
    if (n < 0 || static_cast<size_t>(n) >= cap_ - len_) {
      failed_ = true;
      return;
    }
    len_ += static_cast<size_t>(n);
  }
  size_t finish() const { return failed_ ? 0 : len_; }

 private:
  char* out_;
  size_t cap_;
  size_t len_ = 0;
  bool failed_ = false;
};

bool safeVersionChar(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '+' ||
         c == '_' || c == '-';
}

const char* jsonBool(bool v) {
  return v ? "true" : "false";
}

}  // namespace

size_t writeHealthJson(const HealthInput& in, const HealthReport& report, const char* version, char* out,
                       size_t cap) {
  if (!out || cap == 0) return 0;
  char ver[kMaxVersionChars + 1];
  size_t vlen = 0;
  for (const char* p = version ? version : ""; *p && vlen < kMaxVersionChars; p++)
    ver[vlen++] = safeVersionChar(*p) ? *p : '?';
  ver[vlen] = 0;

  FixedWriter w(out, cap);
  w.add("{\"ok\":%s,\"issues\":[", jsonBool(report.ok()));
  bool first = true;
  for (size_t i = 0; i < kHealthIssueCount; i++) {
    const uint16_t bit = static_cast<uint16_t>(1u << i);
    if (!(report.issues & bit)) continue;
    w.add("%s\"%s\"", first ? "" : ",", healthIssueCode(bit));
    first = false;
  }
  w.add("],\"version\":\"%s\",\"uptimeS\":%lu,\"blocking\":%s", ver, static_cast<unsigned long>(in.uptimeS),
        jsonBool(in.blockingOn));
  w.add(",\"blocklist\":{\"entries\":%lu,\"lastOk\":%s,\"successAgeH\":",
        static_cast<unsigned long>(in.entries), jsonBool(in.lastUpdateOk));
  if (report.successAgeH >= 0)
    w.add("%ld}", static_cast<long>(report.successAgeH));
  else
    w.add("null}");
  w.add(",\"upstream\":{\"encrypted\":%s,\"plainFallback\":%s}",
        jsonBool(in.encryptedHealthy && !in.plainFallback), jsonBool(in.plainFallback));
  w.add(",\"heapBlock\":%lu,\"heapMin\":%lu,\"rssi\":%ld,\"timeSynced\":%s,\"restartCause\":\"%s\"}",
        static_cast<unsigned long>(in.heapBlock), static_cast<unsigned long>(in.heapMin),
        static_cast<long>(in.rssi), jsonBool(in.timeSynced), resetCauseCode(in.resetCause));
  return w.finish();
}

}  // namespace diag
