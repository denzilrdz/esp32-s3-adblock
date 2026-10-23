// Tests for lib/core/diag: naming the restart cause and formatting the crash record
// that the dashboard shows and that gets decoded with addr2line.

#include <unity.h>

#include <cstring>

#include "diag/restart.h"

using diag::ResetCause;

void setUp() {}
void tearDown() {}

static void test_reset_cause_follows_idf_order() {
  // esp_reset_reason_t: ESP_RST_UNKNOWN = 0 ... ESP_RST_CPU_LOCKUP = 15.
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(1) == ResetCause::kPowerOn);
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(3) == ResetCause::kSoftware);
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(4) == ResetCause::kPanic);
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(6) == ResetCause::kTaskWatchdog);
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(9) == ResetCause::kBrownout);
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(15) == ResetCause::kCpuLockup);
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(16) == ResetCause::kUnknown);  // newer IDF value
  TEST_ASSERT_TRUE(diag::resetCauseFromIdf(-1) == ResetCause::kUnknown);
  for (int i = 0; i <= 16; i++) TEST_ASSERT_TRUE(*diag::resetCauseName(diag::resetCauseFromIdf(i)));
}

static void test_only_panics_and_watchdogs_count_as_crashes() {
  TEST_ASSERT_TRUE(diag::isCrash(ResetCause::kPanic));
  TEST_ASSERT_TRUE(diag::isCrash(ResetCause::kTaskWatchdog));
  TEST_ASSERT_TRUE(diag::isCrash(ResetCause::kInterruptWatchdog));
  TEST_ASSERT_TRUE(diag::isCrash(ResetCause::kOtherWatchdog));
  TEST_ASSERT_TRUE(diag::isCrash(ResetCause::kCpuLockup));
  TEST_ASSERT_FALSE(diag::isCrash(ResetCause::kPowerOn));
  TEST_ASSERT_FALSE(diag::isCrash(ResetCause::kSoftware));
  TEST_ASSERT_FALSE(diag::isCrash(ResetCause::kBrownout));
}

static diag::CrashRecord sampleCrash() {
  diag::CrashRecord c;
  c.present = true;
  strcpy(c.task, "dns_up");
  strcpy(c.reason, "Task watchdog got triggered");
  c.pc = 0x4200abcd;
  c.backtrace[0] = 0x4200abcd;  // ESP-IDF puts the pc first
  c.backtrace[1] = 0x42001234;
  c.backtrace[2] = 0x40380f00;
  c.depth = 3;
  return c;
}

static void test_backtrace_is_ready_for_addr2line() {
  char out[200];
  const diag::CrashRecord c = sampleCrash();
  const size_t n = diag::formatBacktrace(c, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("0x4200abcd 0x42001234 0x40380f00", out);
  TEST_ASSERT_EQUAL(strlen(out), n);

  char small[24];  // room for two addresses: never a cut-off one
  diag::formatBacktrace(c, small, sizeof(small));
  TEST_ASSERT_EQUAL_STRING("0x4200abcd 0x42001234", small);

  diag::CrashRecord deep = c;
  deep.depth = 200;  // corrupt depth must not read past the array
  diag::formatBacktrace(deep, out, sizeof(out));
  TEST_ASSERT_TRUE(strlen(out) <= 16 * 11);

  diag::CrashRecord none;
  TEST_ASSERT_EQUAL(0, diag::formatBacktrace(none, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

static void test_describe_restart() {
  char out[160];
  diag::RestartInfo info;
  info.cause = ResetCause::kPowerOn;
  diag::describe(info, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("power on", out);

  info.cause = ResetCause::kSoftware;
  strcpy(info.note, "Wi-Fi down for 10 min");
  diag::describe(info, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("restarted by the firmware: Wi-Fi down for 10 min", out);

  info = diag::RestartInfo{};
  info.cause = ResetCause::kTaskWatchdog;
  info.crash = sampleCrash();
  TEST_ASSERT_TRUE(info.crashThisBoot());
  diag::describe(info, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("crash (task watchdog) in task dns_up: Task watchdog got triggered", out);

  // A record left from an earlier crash doesn't explain a later firmware update.
  info.cause = ResetCause::kSoftware;
  strcpy(info.note, "firmware update");
  TEST_ASSERT_FALSE(info.crashThisBoot());
  diag::describe(info, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("restarted by the firmware: firmware update", out);

  info = diag::RestartInfo{};
  info.cause = ResetCause::kPanic;  // crash, but the core dump couldn't be read
  diag::describe(info, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("crash", out);

  char tiny[6];
  info.cause = ResetCause::kPowerOn;
  diag::describe(info, tiny, sizeof(tiny));
  TEST_ASSERT_EQUAL_STRING("power", tiny);  // truncated, still terminated
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_reset_cause_follows_idf_order);
  RUN_TEST(test_only_panics_and_watchdogs_count_as_crashes);
  RUN_TEST(test_backtrace_is_ready_for_addr2line);
  RUN_TEST(test_describe_restart);
  return UNITY_END();
}
