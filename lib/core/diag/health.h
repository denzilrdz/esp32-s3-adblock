#pragma once
// Verdict and JSON body for the password-free GET /api/health (ARCHITECTURE.md §9, "Health endpoint"):
// a fixed set of harmless status values plus short issue codes, for an uptime
// monitor that polls the board without the admin password.
//
// Everything here is pure (no clock, no allocation): the web task gathers the inputs
// (src/web/dashboard.cpp), evaluateHealth() decides, writeHealthJson() renders into a
// caller's fixed buffer. The JSON carries only the fields listed in writeHealthJson();
// never add client addresses, names, config values, URLs or crash details to it (the
// endpoint answers anyone on the LAN, also during first-boot setup).

#include <cstddef>
#include <cstdint>

#include "diag/restart.h"
#include "upstream/forwarder.h"

namespace diag {

// Bit flags, in the order the codes appear in "issues".
enum HealthIssue : uint16_t {
  kIssueBlockingOff = 1u << 0,
  kIssueBlocklistEmpty = 1u << 1,
  kIssueBlocklistStale = 1u << 2,
  kIssueBlocklistUpdateFailed = 1u << 3,
  kIssuePlainFallback = 1u << 4,
  kIssueUpstreamDown = 1u << 5,
  kIssueHeapLow = 1u << 6,
  kIssueCrashed = 1u << 7,
  kIssueClockUnsynced = 1u << 8,
  kIssueWifiWeak = 1u << 9,
};
constexpr size_t kHealthIssueCount = 10;

// The last successful blocklist update may be this old (the daily run plus a day of
// failed retries); one second more is stale.
constexpr int64_t kBlocklistStaleAfterS = 48 * 3600;

// heap_low: the largest free block of internal RAM (ESP.getMaxAllocHeap()).
// A TLS session takes ~45 KB of internal RAM (ARCHITECTURE.md §11: mbedTLS's 16 KB in
// + 16 KB out record buffers, internal-only in the prebuilt libs, plus ~13 KB of
// context in small pieces). The two record buffers are the only large single
// allocations, so the largest block has to hold both for the next handshake to
// succeed: a failover reconnect, or the third session the 02:00 blocklist download
// opens next to the forwarder's two. Below 32 KB that handshake can fail even with
// enough free heap in total; the context pieces fit in smaller fragments.
constexpr uint32_t kTlsRecordBufferBytes = 16 * 1024;
constexpr uint32_t kHeapLowBlockBytes = 2 * kTlsRecordBufferBytes;

// NTP normally syncs within seconds; still unsynced this long after boot is a fault
// (the scheduler, certificate dates and the blocklist age all wait for it).
constexpr uint32_t kClockSyncGraceS = 10 * 60;

// Below this the Wi-Fi link is marginal (dBm); exactly -80 is still fine.
constexpr int32_t kWifiWeakBelowDbm = -80;

struct HealthInput {
  uint32_t uptimeS = 0;
  bool blockingOn = true;
  // Blocklist
  uint32_t entries = 0;
  bool inMemory = false;
  bool updateAttempted = false;  // at least one update attempt recorded
  bool lastUpdateOk = false;     // the latest attempt succeeded
  int64_t lastSuccessUnix = 0;   // see blocklistSuccessUnix(); 0 = unknown
  // Clock
  bool timeSynced = false;
  int64_t nowUnix = 0;  // only meaningful when timeSynced
  // Upstreams
  bool plainFallback = false;     // plain DNS in use: names leave the LAN unencrypted
  bool encryptedHealthy = false;  // see anyEncryptedHealthy()
  // System
  uint32_t heapBlock = 0;
  uint32_t heapMin = 0;
  int32_t rssi = 0;
  ResetCause resetCause = ResetCause::kUnknown;
};

struct HealthReport {
  uint16_t issues = 0;       // HealthIssue bits
  int32_t successAgeH = -1;  // hours since the last successful update, -1 = unknown
  bool ok() const { return issues == 0; }
};

HealthReport evaluateHealth(const HealthInput& in);

// "blocking_off", "blocklist_stale", ...; nullptr for anything but a single bit.
const char* healthIssueCode(uint16_t issue);

// Short machine-readable reset cause for the health JSON ("poweron", "panic",
// "task_wdt", ...), unlike resetCauseName()'s prose for the dashboard.
const char* resetCauseCode(ResetCause cause);

// At least one encrypted (DoT/DoH) upstream that isn't Down or waiting to be probed
// again. Unknown counts as healthy: right after boot nothing has been tried yet.
bool anyEncryptedHealthy(const upstream::UpstreamStatus* status, size_t count);

// When the blocklist last updated successfully (unix seconds, 0 = unknown):
// the latest attempt's time if it succeeded (exact); otherwise the end of the local
// day the scheduler last recorded a success (yyyymmdd; the end, so the age is never
// overstated); otherwise the installed list's build time.
int64_t blocklistSuccessUnix(bool lastOk, int64_t lastAttemptUnix, uint32_t lastSuccessDate,
                             int64_t buildTimeUnix, int32_t utcOffsetSeconds);

// Renders the response body into out (NUL-terminated). Returns its length, or 0 if
// cap is too small. Fields, and nothing else:
//   ok, issues[], version, uptimeS, blocking,
//   blocklist{entries, lastOk, successAgeH (null when unknown)},
//   upstream{encrypted, plainFallback}, heapBlock, heapMin, rssi, timeSynced, restartCause
// version is copied with anything outside [0-9A-Za-z.+_-] replaced by '?' (at most
// kMaxVersionChars), so it never needs escaping.
constexpr size_t kMaxVersionChars = 31;
constexpr size_t kHealthJsonCap = 512;  // comfortably above the longest body (every issue set)
size_t writeHealthJson(const HealthInput& in, const HealthReport& report, const char* version, char* out,
                       size_t cap);

}  // namespace diag
