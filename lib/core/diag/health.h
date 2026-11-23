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

#include "diag/latency_ring.h"
#include "diag/restart.h"
#include "upstream/forwarder.h"

namespace diag {

// Bit flags, in the order the codes appear in "issues". New codes are only ever
// appended: monitors parse them.
enum HealthIssue : uint32_t {
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
  kIssueDnsSlow = 1u << 10,
  kIssueSocketPressure = 1u << 11,
  kIssueQueriesDropped = 1u << 12,
  kIssueFsLow = 1u << 13,
  kIssueTempHigh = 1u << 14,
  kIssueTaskStalled = 1u << 15,
  kIssueOtaRolledBack = 1u << 16,
};
constexpr size_t kHealthIssueCount = 17;

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

// dns_slow: the board's own answer time (cache hits, blocked and forwarded answers
// alike), averaged over the answers of the last kAnswerWindowMs (at most 256). Fewer
// than kDnsSlowMinSamples answers say nothing: one cold-start miss on a quiet board
// would otherwise raise it.
constexpr double kDnsSlowAboveMs = 200.0;
constexpr uint32_t kDnsSlowMinSamples = 20;  // window: kAnswerWindowMs (latency_ring.h)

// socket_pressure: lwIP has 16 sockets in all (ARCHITECTURE.md §11); with two or fewer
// left a failover connect or the 02:00 download may find none.
constexpr uint32_t kSocketMax = 16;
constexpr uint32_t kSocketSpare = 2;

// queries_dropped: queries the board discarded or refused (droppedPlusLimited) rose by
// this many over the last kDropWindowMs.
constexpr uint32_t kQueriesDroppedRise = 10;
constexpr uint32_t kDropWindowMs = 10 * 60 * 1000;

// temp_high: the ESP32-S3 is rated to 85 °C ambient on the N16R8 module; its internal
// sensor reads a few degrees above ambient. Above 80 °C, cool it.
constexpr double kTempHighAboveC = 80.0;
// Fields are grouped by size (clang-tidy's padding check), not by topic.
struct HealthInput {
  // --- 8 bytes ---
  int64_t lastSuccessUnix = 0;  // blocklist: see blocklistSuccessUnix(); 0 = unknown
  int64_t nowUnix = 0;          // only meaningful when timeSynced
  double answerMsAvg = 0;       // rolling averages (diag::LatencyRing)
  double upstreamMsAvg = 0;
  uint64_t fsFreeBytes = 0;
  double tempC = 0;
  const char* lastResult = "never";  // updateStatusCode() or "never"; must be [a-z_]
  // --- 4 bytes ---
  uint32_t uptimeS = 0;
  uint32_t entries = 0;  // blocklist
  uint32_t heapBlock = 0;
  uint32_t heapMin = 0;
  int32_t rssi = 0;
  // DNS totals since boot (RAM counters, zero after every restart).
  uint32_t queries = 0;
  uint32_t blocked = 0;
  uint32_t forwarded = 0;
  uint32_t cached = 0;  // answered from the cache (= cacheHits)
  uint32_t servfail = 0;
  uint32_t udpDropped = 0;   // queries the board discarded (see ARCHITECTURE.md §9)
  uint32_t rateLimited = 0;  // refused by the per-client in-flight share, or a banned client
  uint32_t droppedRise = 0;  // udpDropped + rateLimited over the last kDropWindowMs
  uint32_t answerSamples = 0;
  uint32_t upstreamSamples = 0;
  uint32_t cacheEntries = 0;
  uint32_t heapFree = 0;
  uint32_t psramFree = 0;
  uint32_t socketsUsed = 0;
  uint32_t fsUsedPct = 0;
  uint32_t wifiReconnects = 0;
  int32_t nextUpdateInMin = -1;  // -1 while the clock isn't synced
  uint32_t bootCount = 0;
  uint32_t crashCount = 0;
  // --- 1 byte ---
  bool blockingOn = true;
  bool inMemory = false;
  bool updateAttempted = false;  // at least one update attempt recorded
  bool lastUpdateOk = false;     // the latest attempt succeeded
  bool timeSynced = false;
  bool plainFallback = false;     // plain DNS in use: names leave the LAN unencrypted
  bool encryptedHealthy = false;  // see anyEncryptedHealthy()
  ResetCause resetCause = ResetCause::kUnknown;
  bool fsKnown = false;    // measured at least once (the maintenance task, every minute)
  bool tempKnown = false;  // false if the sensor read failed (NaN)
  bool livenessOk = true;
  bool otaPending = false;
  bool otaRolledBack = false;
};

struct HealthReport {
  uint32_t issues = 0;       // HealthIssue bits
  int32_t successAgeH = -1;  // hours since the last successful update, -1 = unknown
  bool ok() const { return issues == 0; }
};

HealthReport evaluateHealth(const HealthInput& in);

// "blocking_off", "blocklist_stale", ...; nullptr for anything but a single bit.
const char* healthIssueCode(uint32_t issue);

// fs_low: LittleFS can't take one more copy of a list this size, by the same rule the
// updater applies before a download (blocklist::fileSizeFor() > free bytes): the next
// update would fail with no_space.
bool fsLow(uint64_t freeBytes, uint32_t entries);

// lwIP sockets currently open, from a per-descriptor "is it open" test (the caller's
// fcntl probe) over the kSocketMax descriptors.
template <typename IsOpen>
uint32_t countOpenSockets(int firstFd, IsOpen isOpen) {
  uint32_t n = 0;
  for (uint32_t i = 0; i < kSocketMax; i++)
    if (isOpen(firstFd + static_cast<int>(i))) n++;
  return n;
}

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
//   blocklist{entries, lastOk, successAgeH (null when unknown), nextUpdateInH, lastResult},
//   upstream{encrypted, plainFallback}, heapBlock, heapMin, rssi, timeSynced, restartCause,
//   dns{queries, blocked, forwarded, cached, servfail, udpDropped, rateLimited,
//       answerMsAvg, upstreamMsAvg}, cache{hits, entries}, heapFree, psramFree,
//   sockets{used, max}, fsUsedPct (null until measured), tempC (null if unreadable),
//   wifiReconnects, bootCount, crashCount, livenessOk, otaPending, otaRolledBack, build
// version and build are copied with anything outside [0-9A-Za-z.+_-] replaced by '?'
// (at most kMaxVersionChars), so they never need escaping; lastResult is taken only if
// it is [a-z_], else "unknown". Averages are 0.0 when there are no samples.
constexpr size_t kMaxVersionChars = 31;
constexpr size_t kHealthJsonCap = 1536;  // comfortably above the longest body (every issue set)
size_t writeHealthJson(const HealthInput& in, const HealthReport& report, const char* version,
                       const char* build, char* out, size_t cap);

}  // namespace diag
