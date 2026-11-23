// Tests for diag/health: the verdict behind the password-free GET /api/health (every
// issue code, its boundaries and the unsynced-clock exemptions), the JSON body, which
// must carry exactly the documented fields and nothing else, and the pieces that feed
// it: the rolling latency average, the drop-rise window and the boot counters.

#include <unity.h>

#include <cmath>
#include <cstring>
#include <set>
#include <string>

#include "blocklist/format.h"
#include "diag/boot_record.h"
#include "diag/health.h"
#include "diag/latency_ring.h"
#include "diag/rise_window.h"
#include "fakes/mem_kv_store.h"
#include "util/civil_time.h"
#include "util/json.h"

using diag::HealthInput;
using diag::HealthReport;
using diag::ResetCause;

namespace {

constexpr int64_t kNow = 1795000000;  // 2026-11-17, synced wall clock
constexpr int32_t kIst = 5 * 3600 + 30 * 60;

// A board with nothing wrong: every test changes one thing from here.
HealthInput healthy() {
  HealthInput in;
  in.uptimeS = 12345;
  in.blockingOn = true;
  in.entries = 812345;
  in.inMemory = true;
  in.updateAttempted = true;
  in.lastUpdateOk = true;
  in.lastSuccessUnix = kNow - 5 * 3600;
  in.timeSynced = true;
  in.nowUnix = kNow;
  in.plainFallback = false;
  in.encryptedHealthy = true;
  in.heapBlock = 51234;
  in.heapMin = 40000;
  in.rssi = -58;
  in.resetCause = ResetCause::kPowerOn;
  // v0.8 fields
  in.queries = 1000;
  in.blocked = 150;
  in.forwarded = 300;
  in.cached = 540;
  in.servfail = 2;
  in.udpDropped = 1;
  in.rateLimited = 0;
  in.droppedRise = 1;
  in.answerMsAvg = 12.34;
  in.answerSamples = 256;
  in.upstreamMsAvg = 45.6;
  in.upstreamSamples = 40;
  in.cacheEntries = 900;
  in.heapFree = 140000;
  in.psramFree = 2000000;
  in.socketsUsed = 9;
  in.fsKnown = true;
  in.fsUsedPct = 31;
  in.fsFreeBytes = 8u * 1024 * 1024;
  in.tempKnown = true;
  in.tempC = 47.3;
  in.wifiReconnects = 2;
  in.nextUpdateInMin = 17 * 60 + 5;
  in.lastResult = "ok";
  in.bootCount = 12;
  in.crashCount = 1;
  in.livenessOk = true;
  in.otaPending = false;
  in.otaRolledBack = false;
  return in;
}

uint32_t issuesOf(const HealthInput& in) {
  return diag::evaluateHealth(in).issues;
}

std::string json(const HealthInput& in, const char* version = "0.6.1", const char* build = "a1b2c3d") {
  char buf[diag::kHealthJsonCap];
  const size_t n = diag::writeHealthJson(in, diag::evaluateHealth(in), version, build, buf, sizeof(buf));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_size_t(strlen(buf), n);
  return std::string(buf, n);
}

}  // namespace

void setUp() {}
void tearDown() {}

// --- verdict -------------------------------------------------------------------

static void test_healthy_board_has_no_issues() {
  const HealthReport r = diag::evaluateHealth(healthy());
  TEST_ASSERT_TRUE(r.ok());
  TEST_ASSERT_EQUAL_UINT32(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(5, r.successAgeH);
}

static void test_blocking_off() {
  HealthInput in = healthy();
  in.blockingOn = false;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueBlockingOff, issuesOf(in));
}

static void test_blocklist_empty_when_no_entries_or_not_loaded() {
  HealthInput in = healthy();
  in.entries = 0;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueBlocklistEmpty, issuesOf(in));
  in = healthy();
  in.inMemory = false;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueBlocklistEmpty, issuesOf(in));
}

static void test_blocklist_stale_boundary_is_48_hours() {
  HealthInput in = healthy();
  in.lastSuccessUnix = kNow - diag::kBlocklistStaleAfterS;  // exactly 48 h: fine
  HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT32(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(48, r.successAgeH);
  in.lastSuccessUnix -= 1;  // one second more: stale
  r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueBlocklistStale, r.issues);
  TEST_ASSERT_EQUAL_INT32(48, r.successAgeH);
}

static void test_blocklist_stale_skipped_while_clock_unsynced() {
  HealthInput in = healthy();
  in.timeSynced = false;
  in.uptimeS = 60;  // inside the sync grace period
  in.lastSuccessUnix = kNow - 30 * 86400;
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT32(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(-1, r.successAgeH);  // unknown, not a guess
}

static void test_unknown_success_time_is_not_stale() {
  HealthInput in = healthy();
  in.lastSuccessUnix = 0;
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT32(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(-1, r.successAgeH);
}

static void test_success_in_the_future_counts_as_now() {
  HealthInput in = healthy();
  in.lastSuccessUnix = kNow + 3600;  // clock stepped back after the update
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT32(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(0, r.successAgeH);
}

static void test_update_failed_only_after_an_attempt() {
  HealthInput in = healthy();
  in.lastUpdateOk = false;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueBlocklistUpdateFailed, issuesOf(in));
  in.updateAttempted = false;  // never tried yet: nothing failed
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
}

static void test_plain_fallback() {
  HealthInput in = healthy();
  in.plainFallback = true;
  in.encryptedHealthy = false;  // plain fallback only runs with every encrypted one down
  TEST_ASSERT_EQUAL_UINT32(diag::kIssuePlainFallback | diag::kIssueUpstreamDown, issuesOf(in));
}

static void test_upstream_down() {
  HealthInput in = healthy();
  in.encryptedHealthy = false;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueUpstreamDown, issuesOf(in));
}

static void test_heap_low_boundary() {
  HealthInput in = healthy();
  in.heapBlock = diag::kHeapLowBlockBytes;  // both TLS record buffers still fit
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.heapBlock = diag::kHeapLowBlockBytes - 1;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueHeapLow, issuesOf(in));
  TEST_ASSERT_EQUAL_UINT32(32768, diag::kHeapLowBlockBytes);
}

static void test_crashed_only_for_panics_and_watchdogs() {
  const ResetCause crashes[] = {ResetCause::kPanic, ResetCause::kInterruptWatchdog, ResetCause::kTaskWatchdog,
                                ResetCause::kOtherWatchdog, ResetCause::kCpuLockup};
  for (ResetCause c : crashes) {
    HealthInput in = healthy();
    in.resetCause = c;
    TEST_ASSERT_EQUAL_UINT32(diag::kIssueCrashed, issuesOf(in));
  }
  const ResetCause normal[] = {ResetCause::kPowerOn,  ResetCause::kExternal, ResetCause::kSoftware,
                               ResetCause::kBrownout, ResetCause::kUsb,      ResetCause::kUnknown};
  for (ResetCause c : normal) {
    HealthInput in = healthy();
    in.resetCause = c;  // scheduled reboots, OTA and the reboot button are kSoftware
    TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  }
}

static void test_clock_unsynced_after_ten_minutes() {
  HealthInput in = healthy();
  in.timeSynced = false;
  in.uptimeS = diag::kClockSyncGraceS;  // exactly 10 min: still waiting
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.uptimeS = diag::kClockSyncGraceS + 1;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueClockUnsynced, issuesOf(in));
}

static void test_wifi_weak_boundary() {
  HealthInput in = healthy();
  in.rssi = -80;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.rssi = -81;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueWifiWeak, issuesOf(in));
}

static void test_several_issues_at_once() {
  HealthInput in = healthy();
  in.blockingOn = false;
  in.lastUpdateOk = false;
  in.lastSuccessUnix = kNow - 72 * 3600;
  in.heapBlock = 1000;
  in.rssi = -90;
  in.resetCause = ResetCause::kTaskWatchdog;
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_FALSE(r.ok());
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueBlockingOff | diag::kIssueBlocklistStale |
                               diag::kIssueBlocklistUpdateFailed | diag::kIssueHeapLow | diag::kIssueCrashed |
                               diag::kIssueWifiWeak,
                           r.issues);
  TEST_ASSERT_EQUAL_INT32(72, r.successAgeH);
  const std::string j = json(in);
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(),
                              "\"issues\":[\"blocking_off\",\"blocklist_stale\",\"blocklist_update_failed\","
                              "\"heap_low\",\"crashed\",\"wifi_weak\"]"));
}

static void test_every_issue_has_a_distinct_code() {
  std::set<std::string> codes;
  for (size_t i = 0; i < diag::kHealthIssueCount; i++) {
    const char* c = diag::healthIssueCode((1u << i));
    TEST_ASSERT_NOT_NULL(c);
    codes.insert(c);
  }
  TEST_ASSERT_EQUAL_size_t(diag::kHealthIssueCount, codes.size());
  TEST_ASSERT_NULL(diag::healthIssueCode(0));
  TEST_ASSERT_NULL(diag::healthIssueCode(diag::kIssueHeapLow | diag::kIssueWifiWeak));
  TEST_ASSERT_NULL(diag::healthIssueCode((1u << diag::kHealthIssueCount)));
}

// --- inputs --------------------------------------------------------------------

static void test_any_encrypted_healthy() {
  upstream::UpstreamStatus s[3];
  s[0].authenticated = true;
  s[0].state = upstream::HealthState::kDown;
  s[1].authenticated = true;
  s[1].state = upstream::HealthState::kProbing;
  s[2].authenticated = false;  // plain UDP never counts
  s[2].state = upstream::HealthState::kUp;
  TEST_ASSERT_FALSE(diag::anyEncryptedHealthy(s, 3));
  TEST_ASSERT_FALSE(diag::anyEncryptedHealthy(s, 0));
  const upstream::HealthState good[] = {upstream::HealthState::kUp, upstream::HealthState::kDegraded,
                                        upstream::HealthState::kUnknown};
  for (upstream::HealthState g : good) {
    s[1].state = g;
    TEST_ASSERT_TRUE(diag::anyEncryptedHealthy(s, 3));
  }
}

static void test_success_time_prefers_the_successful_attempt() {
  TEST_ASSERT_EQUAL_INT64(kNow - 100, diag::blocklistSuccessUnix(true, kNow - 100, 20261101, 5, kIst));
}

static void test_success_time_from_date_is_the_end_of_that_local_day() {
  // Latest attempt failed: the scheduler's date of the last success counts, to the
  // next local midnight so the age is never overstated.
  util::CivilTime midnight;
  midnight.year = 2026;
  midnight.month = 11;
  midnight.day = 16;
  const int64_t expected = util::unixFromCivil(midnight, kIst);
  TEST_ASSERT_EQUAL_INT64(expected, diag::blocklistSuccessUnix(false, kNow, 20261115, 5, kIst));
  // Month and year ends roll over.
  midnight.year = 2027;
  midnight.month = 1;
  midnight.day = 1;
  TEST_ASSERT_EQUAL_INT64(util::unixFromCivil(midnight, 0),
                          diag::blocklistSuccessUnix(false, 0, 20261231, 0, 0));
}

static void test_success_time_falls_back_to_build_time() {
  TEST_ASSERT_EQUAL_INT64(777, diag::blocklistSuccessUnix(false, 0, 0, 777, kIst));
  TEST_ASSERT_EQUAL_INT64(777, diag::blocklistSuccessUnix(true, 0, 0, 777, kIst));  // attempt before sync
  TEST_ASSERT_EQUAL_INT64(777, diag::blocklistSuccessUnix(false, 0, 20261399, 777, kIst));  // bad date
  TEST_ASSERT_EQUAL_INT64(0, diag::blocklistSuccessUnix(false, 0, 0, 0, kIst));
}

static void test_reset_cause_codes() {
  TEST_ASSERT_EQUAL_STRING("poweron", diag::resetCauseCode(ResetCause::kPowerOn));
  TEST_ASSERT_EQUAL_STRING("software", diag::resetCauseCode(ResetCause::kSoftware));
  TEST_ASSERT_EQUAL_STRING("panic", diag::resetCauseCode(ResetCause::kPanic));
  TEST_ASSERT_EQUAL_STRING("task_wdt", diag::resetCauseCode(ResetCause::kTaskWatchdog));
  for (int i = -1; i <= 16; i++) {
    const char* c = diag::resetCauseCode(diag::resetCauseFromIdf(i));
    TEST_ASSERT_TRUE(*c);
    for (const char* p = c; *p; p++) TEST_ASSERT_TRUE((*p >= 'a' && *p <= 'z') || *p == '_');
  }
}

// --- JSON body -----------------------------------------------------------------

static void test_json_of_a_healthy_board() {
  TEST_ASSERT_EQUAL_STRING(
      "{\"ok\":true,\"issues\":[],\"version\":\"0.6.1\",\"uptimeS\":12345,\"blocking\":true,"
      "\"blocklist\":{\"entries\":812345,\"lastOk\":true,\"successAgeH\":5,\"nextUpdateInH\":17,"
      "\"lastResult\":\"ok\"},"
      "\"upstream\":{\"encrypted\":true,\"plainFallback\":false},"
      "\"heapBlock\":51234,\"heapMin\":40000,\"rssi\":-58,\"timeSynced\":true,\"restartCause\":\"poweron\","
      "\"dns\":{\"queries\":1000,\"blocked\":150,\"forwarded\":300,\"cached\":540,\"servfail\":2,"
      "\"udpDropped\":1,\"rateLimited\":0,\"answerMsAvg\":12.3,\"upstreamMsAvg\":45.6},"
      "\"cache\":{\"hits\":540,\"entries\":900},\"heapFree\":140000,\"psramFree\":2000000,"
      "\"sockets\":{\"used\":9,\"max\":16},\"fsUsedPct\":31,\"tempC\":47.3,\"wifiReconnects\":2,"
      "\"bootCount\":12,\"crashCount\":1,\"livenessOk\":true,\"otaPending\":false,\"otaRolledBack\":false,"
      "\"build\":\"a1b2c3d\"}",
      json(healthy()).c_str());
}

static void test_json_unknown_age_is_null_and_plain_is_not_encrypted() {
  HealthInput in = healthy();
  in.timeSynced = false;
  in.plainFallback = true;
  in.encryptedHealthy = true;  // just recovered, plain still active: say plain
  const std::string j = json(in);
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"successAgeH\":null"));
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"upstream\":{\"encrypted\":false,\"plainFallback\":true}"));
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"ok\":false"));
}

// Walks one object level, checking every key is in `allowed`, recursing into the two
// nested objects. Any other key (a client IP, a URL, a hostname, a backtrace...) fails.
static void checkKeys(util::JsonReader& r, const std::set<std::string>& allowed, std::set<std::string>& seen,
                      const std::string& prefix) {
  TEST_ASSERT_TRUE(r.beginObject());
  char key[32];
  while (r.nextKey(key, sizeof(key))) {
    const std::string k = prefix + key;
    TEST_ASSERT_TRUE_MESSAGE(allowed.count(k) == 1, k.c_str());
    TEST_ASSERT_TRUE_MESSAGE(seen.insert(k).second, k.c_str());  // no duplicates
    if (k == "blocklist" || k == "upstream" || k == "dns" || k == "cache" || k == "sockets")
      checkKeys(r, allowed, seen, k + ".");
    else
      TEST_ASSERT_TRUE(r.skipValue());
  }
}

static void test_json_has_exactly_the_allowed_fields() {
  const std::set<std::string> allowed = {"ok",
                                         "issues",
                                         "version",
                                         "uptimeS",
                                         "blocking",
                                         "blocklist",
                                         "blocklist.entries",
                                         "blocklist.lastOk",
                                         "blocklist.successAgeH",
                                         "blocklist.nextUpdateInH",
                                         "blocklist.lastResult",
                                         "upstream",
                                         "upstream.encrypted",
                                         "upstream.plainFallback",
                                         "heapBlock",
                                         "heapMin",
                                         "rssi",
                                         "timeSynced",
                                         "restartCause",
                                         "dns",
                                         "dns.queries",
                                         "dns.blocked",
                                         "dns.forwarded",
                                         "dns.cached",
                                         "dns.servfail",
                                         "dns.udpDropped",
                                         "dns.rateLimited",
                                         "dns.answerMsAvg",
                                         "dns.upstreamMsAvg",
                                         "cache",
                                         "cache.hits",
                                         "cache.entries",
                                         "heapFree",
                                         "psramFree",
                                         "sockets",
                                         "sockets.used",
                                         "sockets.max",
                                         "fsUsedPct",
                                         "tempC",
                                         "wifiReconnects",
                                         "bootCount",
                                         "crashCount",
                                         "livenessOk",
                                         "otaPending",
                                         "otaRolledBack",
                                         "build"};
  HealthInput worst = healthy();  // every issue at once: the longest body
  worst.blockingOn = false;
  worst.entries = 0xFFFFFFFFu;
  worst.inMemory = false;
  worst.lastUpdateOk = false;
  worst.lastSuccessUnix = 1;
  worst.plainFallback = true;
  worst.encryptedHealthy = false;
  worst.heapBlock = 0;
  worst.heapMin = 0xFFFFFFFFu;
  worst.rssi = -2147483647 - 1;
  worst.uptimeS = 0xFFFFFFFFu;
  worst.resetCause = ResetCause::kInterruptWatchdog;
  worst.queries = worst.blocked = worst.forwarded = worst.cached = worst.servfail = 0xFFFFFFFFu;
  worst.udpDropped = worst.rateLimited = worst.droppedRise = worst.cacheEntries = 0xFFFFFFFFu;
  worst.answerMsAvg = worst.upstreamMsAvg = 3600000.0;  // the ring's cap
  worst.answerSamples = worst.upstreamSamples = 256;
  worst.heapFree = worst.psramFree = worst.wifiReconnects = 0xFFFFFFFFu;
  worst.bootCount = worst.crashCount = 0xFFFFFFFFu;
  worst.socketsUsed = 16;
  worst.fsFreeBytes = 0;
  worst.fsUsedPct = 100;
  worst.tempC = 125.5;
  worst.nextUpdateInMin = 0x7FFFFFFF;
  worst.lastResult = "install_failed";
  worst.livenessOk = false;
  worst.otaPending = true;
  worst.otaRolledBack = true;
  HealthInput worstUnsynced = worst;
  worstUnsynced.timeSynced = false;
  for (const HealthInput& in : {healthy(), worst, worstUnsynced}) {
    const std::string j = json(in);
    util::JsonReader r(j.data(), j.size());
    std::set<std::string> seen;
    checkKeys(r, allowed, seen, "");
    TEST_ASSERT_TRUE_MESSAGE(r.ok(), r.error());
    TEST_ASSERT_TRUE(r.atEnd());
    TEST_ASSERT_EQUAL_size_t(allowed.size(), seen.size());  // and every one of them
  }
  // Every issue code can be listed: all of them but clock_unsynced in the worst case
  // (stale needs a synced clock), clock_unsynced once the clock is lost too.
  HealthInput unsynced = worst;
  unsynced.timeSynced = false;
  const std::string both = json(worst) + json(unsynced);
  TEST_ASSERT_TRUE(json(worst).size() < diag::kHealthJsonCap);
  TEST_ASSERT_TRUE(json(unsynced).size() < diag::kHealthJsonCap);
  for (size_t i = 0; i < diag::kHealthIssueCount; i++) {
    const std::string code = std::string("\"") + diag::healthIssueCode((1u << i)) + "\"";
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(both.c_str(), code.c_str()), code.c_str());
  }
}

static void test_json_version_is_sanitized_and_bounded() {
  std::string j = json(healthy(), "1.2\"},\"ip\":\"10.0.0.1");
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"version\":\"1.2????ip???10.0.0.1\""));
  j = json(healthy(), nullptr);
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"version\":\"\""));
  const std::string longVersion(100, 'a');
  j = json(healthy(), longVersion.c_str());
  TEST_ASSERT_NOT_NULL(
      strstr(j.c_str(), ("\"version\":\"" + std::string(diag::kMaxVersionChars, 'a') + "\"").c_str()));
}

static void test_json_refuses_a_buffer_too_small() {
  const HealthInput in = healthy();
  const HealthReport r = diag::evaluateHealth(in);
  char buf[diag::kHealthJsonCap];
  const size_t full = diag::writeHealthJson(in, r, "0.6.1", "a1b2c3d", buf, sizeof(buf));
  TEST_ASSERT_TRUE(full > 0);
  TEST_ASSERT_EQUAL_size_t(
      0, diag::writeHealthJson(in, r, "0.6.1", "a1b2c3d", buf, full));  // no room for the NUL
  TEST_ASSERT_EQUAL_size_t(full, diag::writeHealthJson(in, r, "0.6.1", "a1b2c3d", buf, full + 1));
  TEST_ASSERT_EQUAL_size_t(0, diag::writeHealthJson(in, r, "0.6.1", "a1b2c3d", buf, 10));
  TEST_ASSERT_EQUAL_size_t(0, diag::writeHealthJson(in, r, "0.6.1", "a1b2c3d", nullptr, 100));
}

// --- v0.8 issue codes ---------------------------------------------------------------

static void test_dns_slow_needs_enough_samples() {
  HealthInput in = healthy();
  in.answerMsAvg = 200.0;  // exactly 200 ms: fine
  in.answerSamples = 20;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.answerMsAvg = 200.1;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueDnsSlow, issuesOf(in));
  in.answerSamples = 19;  // not enough answers to judge
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.answerSamples = 0;
  in.answerMsAvg = 5000;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  // Upstream time alone never raises it: a slow upstream with a hitting cache is fine.
  in = healthy();
  in.upstreamMsAvg = 1500;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
}

static void test_socket_pressure_boundary() {
  HealthInput in = healthy();
  in.socketsUsed = 13;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.socketsUsed = 14;  // max - 2
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueSocketPressure, issuesOf(in));
  in.socketsUsed = 16;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueSocketPressure, issuesOf(in));
}

static void test_queries_dropped_boundary() {
  HealthInput in = healthy();
  in.droppedRise = 9;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.droppedRise = 10;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueQueriesDropped, issuesOf(in));
  in.droppedRise = 0;
  in.udpDropped = 5000;  // old drops alone: only the recent rise counts
  in.rateLimited = 5000;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
}

static void test_fs_low_uses_the_updaters_size_rule() {
  HealthInput in = healthy();
  const uint64_t need = blocklist::fileSizeFor(in.entries);
  in.fsFreeBytes = need;  // exactly one more copy fits
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.fsFreeBytes = need - 1;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueFsLow, issuesOf(in));
  in.fsKnown = false;  // not measured yet: no verdict
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  TEST_ASSERT_TRUE(diag::fsLow(0, 0));  // even an empty list needs its header
  TEST_ASSERT_FALSE(diag::fsLow(blocklist::fileSizeFor(0), 0));
}

static void test_temp_high_boundary() {
  HealthInput in = healthy();
  in.tempC = 80.0;
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
  in.tempC = 80.1;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueTempHigh, issuesOf(in));
  in.tempKnown = false;  // sensor read failed
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
}

static void test_task_stalled_and_ota_rolled_back() {
  HealthInput in = healthy();
  in.livenessOk = false;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueTaskStalled, issuesOf(in));
  in = healthy();
  in.otaRolledBack = true;
  TEST_ASSERT_EQUAL_UINT32(diag::kIssueOtaRolledBack, issuesOf(in));
  in = healthy();
  in.otaPending = true;  // a new image being verified is normal, not an issue
  TEST_ASSERT_EQUAL_UINT32(0, issuesOf(in));
}

static void test_new_issue_codes_are_appended_in_order() {
  // Monitors already parse the v0.7 codes: their bits and names must never move.
  TEST_ASSERT_EQUAL_STRING("wifi_weak", diag::healthIssueCode(1u << 9));
  const char* added[] = {"dns_slow",  "socket_pressure", "queries_dropped", "fs_low",
                         "temp_high", "task_stalled",    "ota_rolled_back"};
  for (size_t i = 0; i < 7; i++) TEST_ASSERT_EQUAL_STRING(added[i], diag::healthIssueCode(1u << (10 + i)));
}

// --- inputs: rolling average, drop window, boot counters -----------------------------

static void test_latency_ring_average_and_window() {
  diag::LatencyRing ring;
  diag::LatencyAverage a = ring.average(1000, diag::kAnswerWindowMs);
  TEST_ASSERT_EQUAL_UINT32(0, a.samples);
  TEST_ASSERT_TRUE(a.avgMs == 0.0);
  ring.record(1000, 1000);  // 1 ms
  ring.record(2000, 3000);  // 3 ms
  ring.record(3000, 500);   // 0.5 ms
  a = ring.average(3000, diag::kAnswerWindowMs);
  TEST_ASSERT_EQUAL_UINT32(3, a.samples);
  TEST_ASSERT_TRUE(std::fabs(a.avgMs - (1.5)) < 1e-9);
  // Samples older than the window drop out (5 min after the first one).
  a = ring.average(1000 + diag::kAnswerWindowMs + 1, diag::kAnswerWindowMs);
  TEST_ASSERT_EQUAL_UINT32(2, a.samples);
  TEST_ASSERT_TRUE(std::fabs(a.avgMs - (1.75)) < 1e-9);
}

static void test_latency_ring_keeps_the_last_256() {
  diag::LatencyRing ring;
  for (uint32_t i = 0; i < 300; i++) ring.record(10000 + i, i < 44 ? 1000000 : 2000);  // 44 slow, then fast
  const diag::LatencyAverage a = ring.average(10300, diag::kAnswerWindowMs);
  TEST_ASSERT_EQUAL_UINT32(256, a.samples);
  TEST_ASSERT_TRUE(std::fabs(a.avgMs - (2.0)) < 1e-9);  // the 44 oldest were overwritten
}

static void test_latency_ring_survives_the_millisecond_wrap_and_caps_values() {
  diag::LatencyRing ring;
  ring.record(0xFFFFFF00u, 4000);
  ring.record(0x00000100u, 0xFFFFFFFFu);  // capped at an hour
  const diag::LatencyAverage a = ring.average(0x00000200u, diag::kAnswerWindowMs);
  TEST_ASSERT_EQUAL_UINT32(2, a.samples);
  TEST_ASSERT_TRUE(std::fabs(a.avgMs - ((4000 + 3600000000.0) / 2 / 1000)) < 1e-6);
}

static void test_rise_window_counts_the_last_ten_minutes() {
  diag::RiseWindow w(diag::kDropWindowMs);        // starts with (boot, 0)
  TEST_ASSERT_EQUAL_UINT32(7, w.rise(30000, 7));  // a burst right after boot counts
  uint32_t total = 7;
  for (uint32_t m = 1; m <= 20; m++) {
    w.sample(m * 60000, total);
    if (m == 15) total += 9;  // 9 drops in minute 15
  }
  // At minute 20 the window reaches back to minute 10: 9 new drops, just below 10.
  TEST_ASSERT_EQUAL_UINT32(9, w.rise(20 * 60000, total));
  TEST_ASSERT_EQUAL_UINT32(10, w.rise(20 * 60000, total + 1));
  // At minute 26 the burst (between the samples of minutes 15 and 16) has aged out.
  for (uint32_t m = 21; m <= 26; m++) w.sample(m * 60000, total);
  TEST_ASSERT_EQUAL_UINT32(0, w.rise(26 * 60000, total));
}

static void test_rise_window_after_a_long_gap_uses_the_newest_sample() {
  diag::RiseWindow w(diag::kDropWindowMs);
  w.sample(60000, 100);
  // No samples for an hour (maintenance task busy): compare with the newest one.
  TEST_ASSERT_EQUAL_UINT32(5, w.rise(3660000, 105));
  TEST_ASSERT_EQUAL_UINT32(0, w.rise(3660000, 50));  // never negative
}

static void test_dns_counters_start_from_zero_every_boot() {
  // The DNS totals live in RAM: a fresh window (a new boot) has a (boot, 0) baseline, so
  // counts from before the restart can never make a rise.
  diag::RiseWindow afterReboot(diag::kDropWindowMs);
  TEST_ASSERT_EQUAL_UINT32(0, afterReboot.rise(1000, 0));
  TEST_ASSERT_EQUAL_UINT32(3, afterReboot.rise(1000, 3));
}

static void test_boot_counters_persist_and_count_crashes() {
  MemKvStore kv;
  diag::BootCounters c = diag::recordBoot(kv, ResetCause::kPowerOn);
  TEST_ASSERT_EQUAL_UINT32(1, c.boots);
  TEST_ASSERT_EQUAL_UINT32(0, c.crashes);
  c = diag::recordBoot(kv, ResetCause::kSoftware);  // scheduled reboot, OTA, button
  TEST_ASSERT_EQUAL_UINT32(2, c.boots);
  TEST_ASSERT_EQUAL_UINT32(0, c.crashes);
  const ResetCause crashes[] = {
      ResetCause::kPanic,         ResetCause::kTaskWatchdog, ResetCause::kInterruptWatchdog,
      ResetCause::kOtherWatchdog, ResetCause::kCpuLockup,    ResetCause::kBrownout};
  for (ResetCause cause : crashes) c = diag::recordBoot(kv, cause);
  TEST_ASSERT_EQUAL_UINT32(8, c.boots);
  TEST_ASSERT_EQUAL_UINT32(6, c.crashes);
  uint32_t stored = 0;
  TEST_ASSERT_TRUE(kv.getU32(diag::kBootCountKey, stored));
  TEST_ASSERT_EQUAL_UINT32(8, stored);
  kv.setU32(diag::kBootCountKey, 0xFFFFFFFFu);  // saturates, never wraps to 0
  c = diag::recordBoot(kv, ResetCause::kPowerOn);
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, c.boots);
}

static void test_rolled_back_only_on_the_first_boot_that_sees_it() {
  MemKvStore kv;
  TEST_ASSERT_FALSE(diag::rolledBackThisBoot(kv, nullptr));  // first boot: records "none"
  TEST_ASSERT_TRUE(diag::rolledBackThisBoot(kv, "ab12"));    // new invalid image
  TEST_ASSERT_FALSE(diag::rolledBackThisBoot(kv, "ab12"));   // next boot: same, old news
  TEST_ASSERT_TRUE(diag::rolledBackThisBoot(kv, "cd34"));    // a different one rolled back
  TEST_ASSERT_FALSE(diag::rolledBackThisBoot(kv, ""));       // slot rewritten by an update
  TEST_ASSERT_TRUE(diag::rolledBackThisBoot(kv, "cd34"));    // the same image again: counts
}

// --- the JSON never carries addresses, names or URLs ---------------------------------

static void test_old_rollback_is_not_news_on_the_first_boot_with_the_feature() {
  // Upgrading a board that had a rollback months ago (ESP-IDF still reports that
  // partition): no ota_rolled_back on the upgrade boot.
  MemKvStore kv;
  TEST_ASSERT_FALSE(diag::rolledBackThisBoot(kv, "old1"));
  TEST_ASSERT_FALSE(diag::rolledBackThisBoot(kv, "old1"));
  TEST_ASSERT_TRUE(diag::rolledBackThisBoot(kv, "new2"));
}

static void test_json_never_carries_addresses_names_or_urls() {
  // Whatever the inputs, the body is numbers, booleans, null and a few sanitized codes.
  HealthInput in = healthy();
  in.lastResult = "http://evil.example/";  // not a code: replaced
  const std::string j = json(in, "192.168.68.104", "aa:bb:cc:dd:ee:ff");
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"lastResult\":\"unknown\""));
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"build\":\"aa?bb?cc?dd?ee?ff\""));
  for (const char* bad : {"http", "://", ".local", ".example", "aa:bb", "evil"})
    TEST_ASSERT_NULL_MESSAGE(strstr(j.c_str(), bad), bad);
  // Only version can hold a dotted value, and it is the caller's FW_VERSION; every other
  // string value is [a-z_0-9?-] (no dots, so no domain or IPv4 address can appear).
  util::JsonReader r(j.data(), j.size());
  TEST_ASSERT_TRUE(r.beginObject());
  char key[32];
  while (r.nextKey(key, sizeof(key))) {
    if (r.peek() == util::JsonReader::Type::kString) {
      char v[64];
      TEST_ASSERT_TRUE(r.readString(v, sizeof(v)));
      if (strcmp(key, "version") == 0) continue;
      TEST_ASSERT_NULL_MESSAGE(strchr(v, '.'), key);
      TEST_ASSERT_NULL_MESSAGE(strchr(v, ':'), key);
    } else {
      TEST_ASSERT_TRUE(r.skipValue());
    }
  }
  TEST_ASSERT_TRUE(r.ok());
}

static void test_json_unmeasured_values_are_null_and_averages_zero() {
  HealthInput in = healthy();
  in.fsKnown = false;
  in.tempKnown = false;
  in.answerSamples = 0;
  in.answerMsAvg = 999;  // ignored without samples
  in.upstreamSamples = 0;
  in.nextUpdateInMin = -1;
  const std::string j = json(in);
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"fsUsedPct\":null"));
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"tempC\":null"));
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"answerMsAvg\":0.0,\"upstreamMsAvg\":0.0"));
  TEST_ASSERT_NOT_NULL(strstr(j.c_str(), "\"nextUpdateInH\":-1"));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_healthy_board_has_no_issues);
  RUN_TEST(test_blocking_off);
  RUN_TEST(test_blocklist_empty_when_no_entries_or_not_loaded);
  RUN_TEST(test_blocklist_stale_boundary_is_48_hours);
  RUN_TEST(test_blocklist_stale_skipped_while_clock_unsynced);
  RUN_TEST(test_unknown_success_time_is_not_stale);
  RUN_TEST(test_success_in_the_future_counts_as_now);
  RUN_TEST(test_update_failed_only_after_an_attempt);
  RUN_TEST(test_plain_fallback);
  RUN_TEST(test_upstream_down);
  RUN_TEST(test_heap_low_boundary);
  RUN_TEST(test_crashed_only_for_panics_and_watchdogs);
  RUN_TEST(test_clock_unsynced_after_ten_minutes);
  RUN_TEST(test_wifi_weak_boundary);
  RUN_TEST(test_several_issues_at_once);
  RUN_TEST(test_every_issue_has_a_distinct_code);
  RUN_TEST(test_any_encrypted_healthy);
  RUN_TEST(test_success_time_prefers_the_successful_attempt);
  RUN_TEST(test_success_time_from_date_is_the_end_of_that_local_day);
  RUN_TEST(test_success_time_falls_back_to_build_time);
  RUN_TEST(test_reset_cause_codes);
  RUN_TEST(test_json_of_a_healthy_board);
  RUN_TEST(test_json_unknown_age_is_null_and_plain_is_not_encrypted);
  RUN_TEST(test_json_has_exactly_the_allowed_fields);
  RUN_TEST(test_json_version_is_sanitized_and_bounded);
  RUN_TEST(test_json_refuses_a_buffer_too_small);
  RUN_TEST(test_dns_slow_needs_enough_samples);
  RUN_TEST(test_socket_pressure_boundary);
  RUN_TEST(test_queries_dropped_boundary);
  RUN_TEST(test_fs_low_uses_the_updaters_size_rule);
  RUN_TEST(test_temp_high_boundary);
  RUN_TEST(test_task_stalled_and_ota_rolled_back);
  RUN_TEST(test_new_issue_codes_are_appended_in_order);
  RUN_TEST(test_latency_ring_average_and_window);
  RUN_TEST(test_latency_ring_keeps_the_last_256);
  RUN_TEST(test_latency_ring_survives_the_millisecond_wrap_and_caps_values);
  RUN_TEST(test_rise_window_counts_the_last_ten_minutes);
  RUN_TEST(test_rise_window_after_a_long_gap_uses_the_newest_sample);
  RUN_TEST(test_dns_counters_start_from_zero_every_boot);
  RUN_TEST(test_boot_counters_persist_and_count_crashes);
  RUN_TEST(test_rolled_back_only_on_the_first_boot_that_sees_it);
  RUN_TEST(test_old_rollback_is_not_news_on_the_first_boot_with_the_feature);
  RUN_TEST(test_json_never_carries_addresses_names_or_urls);
  RUN_TEST(test_json_unmeasured_values_are_null_and_averages_zero);
  return UNITY_END();
}
