// Tests for diag/health: the verdict behind the password-free GET /api/health (every
// issue code, its boundaries and the unsynced-clock exemptions) and the JSON body,
// which must carry exactly the documented fields and nothing else.

#include <unity.h>

#include <cstring>
#include <set>
#include <string>

#include "diag/health.h"
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
  return in;
}

uint16_t issuesOf(const HealthInput& in) {
  return diag::evaluateHealth(in).issues;
}

std::string json(const HealthInput& in, const char* version = "0.6.1") {
  char buf[diag::kHealthJsonCap];
  const size_t n = diag::writeHealthJson(in, diag::evaluateHealth(in), version, buf, sizeof(buf));
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
  TEST_ASSERT_EQUAL_UINT16(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(5, r.successAgeH);
}

static void test_blocking_off() {
  HealthInput in = healthy();
  in.blockingOn = false;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueBlockingOff, issuesOf(in));
}

static void test_blocklist_empty_when_no_entries_or_not_loaded() {
  HealthInput in = healthy();
  in.entries = 0;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueBlocklistEmpty, issuesOf(in));
  in = healthy();
  in.inMemory = false;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueBlocklistEmpty, issuesOf(in));
}

static void test_blocklist_stale_boundary_is_48_hours() {
  HealthInput in = healthy();
  in.lastSuccessUnix = kNow - diag::kBlocklistStaleAfterS;  // exactly 48 h: fine
  HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT16(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(48, r.successAgeH);
  in.lastSuccessUnix -= 1;  // one second more: stale
  r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueBlocklistStale, r.issues);
  TEST_ASSERT_EQUAL_INT32(48, r.successAgeH);
}

static void test_blocklist_stale_skipped_while_clock_unsynced() {
  HealthInput in = healthy();
  in.timeSynced = false;
  in.uptimeS = 60;  // inside the sync grace period
  in.lastSuccessUnix = kNow - 30 * 86400;
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT16(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(-1, r.successAgeH);  // unknown, not a guess
}

static void test_unknown_success_time_is_not_stale() {
  HealthInput in = healthy();
  in.lastSuccessUnix = 0;
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT16(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(-1, r.successAgeH);
}

static void test_success_in_the_future_counts_as_now() {
  HealthInput in = healthy();
  in.lastSuccessUnix = kNow + 3600;  // clock stepped back after the update
  const HealthReport r = diag::evaluateHealth(in);
  TEST_ASSERT_EQUAL_UINT16(0, r.issues);
  TEST_ASSERT_EQUAL_INT32(0, r.successAgeH);
}

static void test_update_failed_only_after_an_attempt() {
  HealthInput in = healthy();
  in.lastUpdateOk = false;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueBlocklistUpdateFailed, issuesOf(in));
  in.updateAttempted = false;  // never tried yet: nothing failed
  TEST_ASSERT_EQUAL_UINT16(0, issuesOf(in));
}

static void test_plain_fallback() {
  HealthInput in = healthy();
  in.plainFallback = true;
  in.encryptedHealthy = false;  // plain fallback only runs with every encrypted one down
  TEST_ASSERT_EQUAL_UINT16(diag::kIssuePlainFallback | diag::kIssueUpstreamDown, issuesOf(in));
}

static void test_upstream_down() {
  HealthInput in = healthy();
  in.encryptedHealthy = false;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueUpstreamDown, issuesOf(in));
}

static void test_heap_low_boundary() {
  HealthInput in = healthy();
  in.heapBlock = diag::kHeapLowBlockBytes;  // both TLS record buffers still fit
  TEST_ASSERT_EQUAL_UINT16(0, issuesOf(in));
  in.heapBlock = diag::kHeapLowBlockBytes - 1;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueHeapLow, issuesOf(in));
  TEST_ASSERT_EQUAL_UINT32(32768, diag::kHeapLowBlockBytes);
}

static void test_crashed_only_for_panics_and_watchdogs() {
  const ResetCause crashes[] = {ResetCause::kPanic, ResetCause::kInterruptWatchdog, ResetCause::kTaskWatchdog,
                                ResetCause::kOtherWatchdog, ResetCause::kCpuLockup};
  for (ResetCause c : crashes) {
    HealthInput in = healthy();
    in.resetCause = c;
    TEST_ASSERT_EQUAL_UINT16(diag::kIssueCrashed, issuesOf(in));
  }
  const ResetCause normal[] = {ResetCause::kPowerOn,  ResetCause::kExternal, ResetCause::kSoftware,
                               ResetCause::kBrownout, ResetCause::kUsb,      ResetCause::kUnknown};
  for (ResetCause c : normal) {
    HealthInput in = healthy();
    in.resetCause = c;  // scheduled reboots, OTA and the reboot button are kSoftware
    TEST_ASSERT_EQUAL_UINT16(0, issuesOf(in));
  }
}

static void test_clock_unsynced_after_ten_minutes() {
  HealthInput in = healthy();
  in.timeSynced = false;
  in.uptimeS = diag::kClockSyncGraceS;  // exactly 10 min: still waiting
  TEST_ASSERT_EQUAL_UINT16(0, issuesOf(in));
  in.uptimeS = diag::kClockSyncGraceS + 1;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueClockUnsynced, issuesOf(in));
}

static void test_wifi_weak_boundary() {
  HealthInput in = healthy();
  in.rssi = -80;
  TEST_ASSERT_EQUAL_UINT16(0, issuesOf(in));
  in.rssi = -81;
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueWifiWeak, issuesOf(in));
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
  TEST_ASSERT_EQUAL_UINT16(diag::kIssueBlockingOff | diag::kIssueBlocklistStale |
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
    const char* c = diag::healthIssueCode(static_cast<uint16_t>(1u << i));
    TEST_ASSERT_NOT_NULL(c);
    codes.insert(c);
  }
  TEST_ASSERT_EQUAL_size_t(diag::kHealthIssueCount, codes.size());
  TEST_ASSERT_NULL(diag::healthIssueCode(0));
  TEST_ASSERT_NULL(diag::healthIssueCode(diag::kIssueHeapLow | diag::kIssueWifiWeak));
  TEST_ASSERT_NULL(diag::healthIssueCode(static_cast<uint16_t>(1u << diag::kHealthIssueCount)));
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
      "\"blocklist\":{\"entries\":812345,\"lastOk\":true,\"successAgeH\":5},"
      "\"upstream\":{\"encrypted\":true,\"plainFallback\":false},"
      "\"heapBlock\":51234,\"heapMin\":40000,\"rssi\":-58,\"timeSynced\":true,\"restartCause\":\"poweron\"}",
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
    if (k == "blocklist" || k == "upstream")
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
                                         "upstream",
                                         "upstream.encrypted",
                                         "upstream.plainFallback",
                                         "heapBlock",
                                         "heapMin",
                                         "rssi",
                                         "timeSynced",
                                         "restartCause"};
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
    const std::string code = std::string("\"") + diag::healthIssueCode(static_cast<uint16_t>(1u << i)) + "\"";
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
  const size_t full = diag::writeHealthJson(in, r, "0.6.1", buf, sizeof(buf));
  TEST_ASSERT_TRUE(full > 0);
  TEST_ASSERT_EQUAL_size_t(0, diag::writeHealthJson(in, r, "0.6.1", buf, full));  // no room for the NUL
  TEST_ASSERT_EQUAL_size_t(full, diag::writeHealthJson(in, r, "0.6.1", buf, full + 1));
  TEST_ASSERT_EQUAL_size_t(0, diag::writeHealthJson(in, r, "0.6.1", buf, 10));
  TEST_ASSERT_EQUAL_size_t(0, diag::writeHealthJson(in, r, "0.6.1", nullptr, 100));
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
  return UNITY_END();
}
