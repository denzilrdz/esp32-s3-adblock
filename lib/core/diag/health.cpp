#include "diag/health.h"

#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "blocklist/format.h"
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
  if (in.answerSamples >= kDnsSlowMinSamples && in.answerMsAvg > kDnsSlowAboveMs) r.issues |= kIssueDnsSlow;
  if (in.socketsUsed >= kSocketMax - kSocketSpare) r.issues |= kIssueSocketPressure;
  if (in.droppedRise >= kQueriesDroppedRise) r.issues |= kIssueQueriesDropped;
  if (in.fsKnown && fsLow(in.fsFreeBytes, in.entries)) r.issues |= kIssueFsLow;
  if (in.tempKnown && in.tempC > kTempHighAboveC) r.issues |= kIssueTempHigh;
  if (!in.livenessOk) r.issues |= kIssueTaskStalled;
  if (in.otaRolledBack) r.issues |= kIssueOtaRolledBack;
  return r;
}

bool fsLow(uint64_t freeBytes, uint32_t entries) {
  return blocklist::fileSizeFor(entries) > freeBytes;
}

const char* healthIssueCode(uint32_t issue) {
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
    case kIssueDnsSlow: return "dns_slow";
    case kIssueSocketPressure: return "socket_pressure";
    case kIssueQueriesDropped: return "queries_dropped";
    case kIssueFsLow: return "fs_low";
    case kIssueTempHigh: return "temp_high";
    case kIssueTaskStalled: return "task_stalled";
    case kIssueOtaRolledBack: return "ota_rolled_back";
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

namespace {

// Copies `in` into out[kMaxVersionChars + 1], anything outside [0-9A-Za-z.+_-] as '?'.
void sanitize(const char* in, char* out) {
  size_t n = 0;
  for (const char* p = in ? in : ""; *p && n < kMaxVersionChars; p++)
    out[n++] = safeVersionChar(*p) ? *p : '?';
  out[n] = 0;
}

// lastResult must already be a machine code: [a-z_], short.
const char* codeOrUnknown(const char* s) {
  if (!s || !*s || strlen(s) > 20) return "unknown";
  for (const char* p = s; *p; p++)
    if (!((*p >= 'a' && *p <= 'z') || *p == '_')) return "unknown";
  return s;
}

double finiteOrZero(double v) {
  return std::isfinite(v) ? v : 0.0;
}

}  // namespace

size_t writeHealthJson(const HealthInput& in, const HealthReport& report, const char* version,
                       const char* build, char* out, size_t cap) {
  if (!out || cap == 0) return 0;
  char ver[kMaxVersionChars + 1];
  char bld[kMaxVersionChars + 1];
  sanitize(version, ver);
  sanitize(build, bld);

  FixedWriter w(out, cap);
  w.add("{\"ok\":%s,\"issues\":[", jsonBool(report.ok()));
  bool first = true;
  for (size_t i = 0; i < kHealthIssueCount; i++) {
    const uint32_t bit = 1u << i;
    if (!(report.issues & bit)) continue;
    w.add("%s\"%s\"", first ? "" : ",", healthIssueCode(bit));
    first = false;
  }
  w.add("],\"version\":\"%s\",\"uptimeS\":%lu,\"blocking\":%s", ver, static_cast<unsigned long>(in.uptimeS),
        jsonBool(in.blockingOn));
  w.add(",\"blocklist\":{\"entries\":%lu,\"lastOk\":%s,\"successAgeH\":",
        static_cast<unsigned long>(in.entries), jsonBool(in.lastUpdateOk));
  if (report.successAgeH >= 0)
    w.add("%ld", static_cast<long>(report.successAgeH));
  else
    w.add("null");
  w.add(",\"nextUpdateInH\":%ld,\"lastResult\":\"%s\"}",
        static_cast<long>(in.nextUpdateInMin < 0 ? -1 : in.nextUpdateInMin / 60),
        codeOrUnknown(in.lastResult));
  w.add(",\"upstream\":{\"encrypted\":%s,\"plainFallback\":%s}",
        jsonBool(in.encryptedHealthy && !in.plainFallback), jsonBool(in.plainFallback));
  w.add(",\"heapBlock\":%lu,\"heapMin\":%lu,\"rssi\":%ld,\"timeSynced\":%s,\"restartCause\":\"%s\"",
        static_cast<unsigned long>(in.heapBlock), static_cast<unsigned long>(in.heapMin),
        static_cast<long>(in.rssi), jsonBool(in.timeSynced), resetCauseCode(in.resetCause));
  w.add(
      ",\"dns\":{\"queries\":%lu,\"blocked\":%lu,\"forwarded\":%lu,\"cached\":%lu,\"servfail\":%lu,"
      "\"udpDropped\":%lu,\"rateLimited\":%lu,\"answerMsAvg\":%.1f,\"upstreamMsAvg\":%.1f}",
      static_cast<unsigned long>(in.queries), static_cast<unsigned long>(in.blocked),
      static_cast<unsigned long>(in.forwarded), static_cast<unsigned long>(in.cached),
      static_cast<unsigned long>(in.servfail), static_cast<unsigned long>(in.udpDropped),
      static_cast<unsigned long>(in.rateLimited), in.answerSamples ? finiteOrZero(in.answerMsAvg) : 0.0,
      in.upstreamSamples ? finiteOrZero(in.upstreamMsAvg) : 0.0);
  w.add(",\"cache\":{\"hits\":%lu,\"entries\":%lu},\"heapFree\":%lu,\"psramFree\":%lu",
        static_cast<unsigned long>(in.cached), static_cast<unsigned long>(in.cacheEntries),
        static_cast<unsigned long>(in.heapFree), static_cast<unsigned long>(in.psramFree));
  w.add(",\"sockets\":{\"used\":%lu,\"max\":%lu},\"fsUsedPct\":", static_cast<unsigned long>(in.socketsUsed),
        static_cast<unsigned long>(kSocketMax));
  if (in.fsKnown)
    w.add("%lu", static_cast<unsigned long>(in.fsUsedPct > 100 ? 100 : in.fsUsedPct));
  else
    w.add("null");
  w.add(",\"tempC\":");
  if (in.tempKnown && std::isfinite(in.tempC))
    w.add("%.1f", in.tempC);
  else
    w.add("null");
  w.add(
      ",\"wifiReconnects\":%lu,\"bootCount\":%lu,\"crashCount\":%lu,\"livenessOk\":%s,\"otaPending\":%s,"
      "\"otaRolledBack\":%s,\"build\":\"%s\"}",
      static_cast<unsigned long>(in.wifiReconnects), static_cast<unsigned long>(in.bootCount),
      static_cast<unsigned long>(in.crashCount), jsonBool(in.livenessOk), jsonBool(in.otaPending),
      jsonBool(in.otaRolledBack), bld);
  return w.finish();
}

}  // namespace diag
