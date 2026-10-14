// Tests for lib/core/sched: the 02:00 IST daily trigger, jitter, no double runs
// (also across reboots), catch-up, retries after failure, and no runs before sync.

#include <unity.h>

#include "fakes/fake_clock.h"
#include "fakes/fake_random.h"
#include "fakes/mem_kv_store.h"
#include "sched/daily_scheduler.h"

using sched::DailyScheduler;
using sched::ScheduleConfig;

static FakeClock fakeClock;
static FakeRandom fakeRandom;
static MemKvStore kv;

static ScheduleConfig noJitter() {
  ScheduleConfig c;
  c.maxJitterMinutes = 0;
  return c;
}

void setUp() {
  fakeClock = FakeClock{};
  fakeRandom = FakeRandom{};
  kv = MemKvStore{};
  fakeClock.setSynced(true);
}
void tearDown() {}

static void test_not_due_before_time_sync_or_with_bogus_year() {
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 3, 0);
  fakeClock.setSynced(false);
  TEST_ASSERT_FALSE(s.due());
  TEST_ASSERT_FALSE(s.timeValid());
  fakeClock.setSynced(true);
  fakeClock.setLocal(1970, 1, 1, 3, 0);  // synced flag set but clock clearly wrong
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 10, 15, 3, 0);
  TEST_ASSERT_TRUE(s.due());
}

static void test_triggers_at_2am_ist_exactly() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);  // ran yesterday
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 1, 59, 59);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.advanceSeconds(1);  // 02:00:00 IST == 20:30 UTC the previous day
  TEST_ASSERT_EQUAL(20, util::civilFromUnix(fakeClock.unixTime(), 0).hour);
  TEST_ASSERT_TRUE(s.due());
}

static void test_jitter_delays_within_window() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);
  ScheduleConfig c;  // default 10 min jitter
  fakeRandom.push(7);  // jitter = 7 % 11 = 7 minutes
  DailyScheduler s(c, fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 2, 6, 59);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.advanceSeconds(1);
  TEST_ASSERT_TRUE(s.due());
  TEST_ASSERT_EQUAL_UINT32(127, s.targetMinuteOfDay());
}

static void test_no_double_run_same_day_even_after_reboot() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);
  {
    DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
    fakeClock.setLocal(2026, 10, 15, 2, 0);
    TEST_ASSERT_TRUE(s.due());
    s.markSuccess();
    TEST_ASSERT_FALSE(s.due());
    fakeClock.advanceSeconds(3600);
    TEST_ASSERT_FALSE(s.due());
  }
  DailyScheduler rebooted(noJitter(), fakeClock, kv, fakeRandom);  // same NVS
  fakeClock.setLocal(2026, 10, 15, 2, 30);
  TEST_ASSERT_FALSE(rebooted.due());
  fakeClock.setLocal(2026, 10, 16, 2, 0);  // next night
  TEST_ASSERT_TRUE(rebooted.due());
}

static void test_catches_up_after_missing_the_slot() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 15, 0);  // device was off at 02:00
  TEST_ASSERT_TRUE(s.due());
  fakeClock.setLocal(2026, 10, 15, 1, 0);  // before today's slot: wait
  DailyScheduler early(noJitter(), fakeClock, kv, fakeRandom);
  TEST_ASSERT_FALSE(early.due());
}

static void test_first_boot_runs_once_synced() {
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);  // never ran
  fakeClock.setLocal(2026, 10, 15, 10, 0);
  TEST_ASSERT_TRUE(s.due());
}

static void test_failure_retries_hourly_then_gives_up_until_tomorrow() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 2, 0);
  for (int attempt = 1; attempt <= 6; attempt++) {
    TEST_ASSERT_TRUE(s.due());
    s.markFailure();
    TEST_ASSERT_FALSE(s.due());
    fakeClock.advanceSeconds(3599);
    TEST_ASSERT_FALSE(s.due());
    fakeClock.advanceSeconds(1);
  }
  TEST_ASSERT_TRUE(s.due());  // 7th try
  s.markFailure();
  TEST_ASSERT_TRUE(s.gaveUpToday());
  fakeClock.advanceSeconds(3600 * 3);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 10, 16, 2, 0);
  TEST_ASSERT_TRUE(s.due());
  TEST_ASSERT_EQUAL_UINT32(0, s.retriesToday());
}

static void test_retry_success_records_the_day() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 2, 0);
  s.markFailure();
  fakeClock.advanceSeconds(3600);
  TEST_ASSERT_TRUE(s.due());
  s.markSuccess();
  TEST_ASSERT_FALSE(s.due());
  uint32_t stored = 0;
  TEST_ASSERT_TRUE(kv.getU32(DailyScheduler::kLastSuccessKey, stored));
  TEST_ASSERT_EQUAL_UINT32(20261015, stored);
}

static void test_manual_request_runs_even_if_done_today() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261015);
  DailyScheduler s(noJitter(), fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 12, 0);
  TEST_ASSERT_FALSE(s.due());
  s.requestNow();
  TEST_ASSERT_TRUE(s.due());
  s.markSuccess();
  TEST_ASSERT_FALSE(s.due());
}

static void test_configurable_time_and_late_slot_clamped() {
  kv.setU32(DailyScheduler::kLastSuccessKey, 20261014);
  ScheduleConfig c;
  c.hour = 23;
  c.minute = 55;
  fakeRandom.push(10);  // would push past midnight
  DailyScheduler s(c, fakeClock, kv, fakeRandom);
  fakeClock.setLocal(2026, 10, 15, 23, 58);
  TEST_ASSERT_FALSE(s.due());
  TEST_ASSERT_EQUAL_UINT32(1439, s.targetMinuteOfDay());
  fakeClock.setLocal(2026, 10, 15, 23, 59);
  TEST_ASSERT_TRUE(s.due());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_not_due_before_time_sync_or_with_bogus_year);
  RUN_TEST(test_triggers_at_2am_ist_exactly);
  RUN_TEST(test_jitter_delays_within_window);
  RUN_TEST(test_no_double_run_same_day_even_after_reboot);
  RUN_TEST(test_catches_up_after_missing_the_slot);
  RUN_TEST(test_first_boot_runs_once_synced);
  RUN_TEST(test_failure_retries_hourly_then_gives_up_until_tomorrow);
  RUN_TEST(test_retry_success_records_the_day);
  RUN_TEST(test_manual_request_runs_even_if_done_today);
  RUN_TEST(test_configurable_time_and_late_slot_clamped);
  return UNITY_END();
}
