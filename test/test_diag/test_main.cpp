// Tests for lib/core/diag: naming the restart cause, formatting the crash record that
// the dashboard shows and that gets decoded with addr2line, and the software watchdog
// (LivenessMonitor) that backs up the hardware one.

#include <unity.h>

#include <atomic>
#include <cstring>
#include <thread>

#include "diag/liveness.h"
#include "diag/restart.h"
#include "fakes/fake_clock.h"

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

static void test_liveness_flags_only_silent_armed_activities() {
  FakeClock clock;
  diag::LivenessMonitor m(clock);
  const int web = m.add("web task", 180000, true);
  const int dl = m.add("blocklist download", 360000, false);
  TEST_ASSERT_EQUAL(0, web);
  TEST_ASSERT_EQUAL(1, dl);
  TEST_ASSERT_NULL(m.check());

  for (int i = 0; i < 100; i++) {  // a busy web task: beats keep it alive for hours
    clock.advanceMs(170000);
    m.beat(web);
    TEST_ASSERT_NULL(m.check());
  }
  clock.advanceMs(180001);  // silent just past its limit
  TEST_ASSERT_EQUAL_STRING("web task", m.check());
  m.beat(web);
  TEST_ASSERT_NULL(m.check());

  // The download is only watched while armed; arming counts as a beat.
  clock.advanceMs(10 * 60000);
  m.beat(web);
  TEST_ASSERT_NULL(m.check());  // disarmed: an old beat doesn't matter
  m.arm(dl);
  clock.advanceMs(359000);
  m.beat(web);
  TEST_ASSERT_NULL(m.check());
  clock.advanceMs(2000);  // 6 min after arming, no beat: stuck however busy it looks
  m.beat(web);
  TEST_ASSERT_EQUAL_STRING("blocklist download", m.check());
  m.disarm(dl);
  TEST_ASSERT_NULL(m.check());
}

static void test_liveness_survives_the_32_bit_millisecond_wrap() {
  FakeClock clock;
  clock.advanceMs(0xFFFFFFFFull - 30000 - 1000);  // 30 s before the 32-bit wrap
  diag::LivenessMonitor m(clock);
  const int up = m.add("upstream task", 30000, true);
  for (int i = 0; i < 10; i++) {  // beats across the wrap
    clock.advanceMs(20000);
    m.beat(up);
    TEST_ASSERT_NULL(m.check());
  }
  clock.advanceMs(30001);
  TEST_ASSERT_EQUAL_STRING("upstream task", m.check());
}

static void test_liveness_checker_is_watched_too() {
  FakeClock clock;
  diag::LivenessMonitor m(clock);
  TEST_ASSERT_FALSE(m.checkerStalled(30000));  // never ran yet: not judged
  TEST_ASSERT_EQUAL_UINT32(0, m.lastCheckMs());
  m.check();
  TEST_ASSERT_TRUE(m.lastCheckMs() != 0);
  clock.advanceMs(29000);
  TEST_ASSERT_FALSE(m.checkerStalled(30000));
  clock.advanceMs(2000);
  TEST_ASSERT_TRUE(m.checkerStalled(30000));  // the timer that runs check() stopped
  m.check();
  TEST_ASSERT_FALSE(m.checkerStalled(30000));
}

static void test_liveness_table_limits_and_bad_ids() {
  FakeClock clock;
  diag::LivenessMonitor m(clock);
  for (int i = 0; i < diag::LivenessMonitor::kMaxActivities; i++)
    TEST_ASSERT_EQUAL(i, m.add("x", 1000, true));
  TEST_ASSERT_EQUAL(-1, m.add("one too many", 1000, true));
  m.beat(-1);  // ignored, never out of bounds
  m.arm(99);
  m.disarm(diag::LivenessMonitor::kMaxActivities);
  TEST_ASSERT_NULL(m.check());
}

static void test_liveness_concurrent_beats_never_false_alarm() {
  // Beats, arm/disarm and checks from different threads, as on the board (web task,
  // maintenance task, esp_timer task). With every activity beating well inside its
  // limit, check() must never report one.
  FakeClock clock;  // time stands still: only the races are exercised
  diag::LivenessMonitor m(clock);
  const int a = m.add("a", 1000, true);
  const int b = m.add("b", 1000, false);
  std::atomic<bool> stop{false};
  std::atomic<int> alarms{0};
  std::thread beater([&] {
    while (!stop.load()) {
      m.beat(a);
      m.arm(b);
      m.beat(b);
      m.disarm(b);
    }
  });
  for (int i = 0; i < 200000; i++)
    if (m.check()) alarms++;
  stop.store(true);
  beater.join();
  TEST_ASSERT_EQUAL(0, alarms.load());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_reset_cause_follows_idf_order);
  RUN_TEST(test_only_panics_and_watchdogs_count_as_crashes);
  RUN_TEST(test_backtrace_is_ready_for_addr2line);
  RUN_TEST(test_describe_restart);
  RUN_TEST(test_liveness_flags_only_silent_armed_activities);
  RUN_TEST(test_liveness_survives_the_32_bit_millisecond_wrap);
  RUN_TEST(test_liveness_checker_is_watched_too);
  RUN_TEST(test_liveness_table_limits_and_bad_ids);
  RUN_TEST(test_liveness_concurrent_beats_never_false_alarm);
  return UNITY_END();
}
