// Tests for lib/core/sched/reboot_schedule: daily and weekly reboots at a local time,
// the late window, no reboot before clock sync or right after a boot, once per day
// (also across the restart itself and DST's repeated hour), midnight-crossing
// windows, DST gaps, and the "next reboot" shown on the dashboard.

#include <unity.h>

#include "fakes/fake_clock.h"
#include "fakes/mem_kv_store.h"
#include "sched/reboot_schedule.h"

using sched::RebootMode;
using sched::RebootPlan;
using sched::RebootScheduler;

static FakeClock fakeClock;
static MemKvStore kv;

constexpr uint64_t kHourMs = 3600000;

void setUp() {
  fakeClock = FakeClock{};
  kv = MemKvStore{};
  fakeClock.setSynced(true);
  fakeClock.advanceMs(5 * kHourMs);  // up for a while unless a test says otherwise
}
void tearDown() {}

static RebootPlan plan(RebootMode mode, int hour, int minute, int weekday = 0) {
  RebootPlan p;
  p.mode = mode;
  p.hour = static_cast<uint8_t>(hour);
  p.minute = static_cast<uint8_t>(minute);
  p.weekday = static_cast<uint8_t>(weekday);
  return p;
}

static void test_mode_names_round_trip() {
  for (RebootMode m : {RebootMode::kOff, RebootMode::kDaily, RebootMode::kWeekly}) {
    RebootMode out = RebootMode::kOff;
    TEST_ASSERT_TRUE(sched::parseRebootMode(sched::rebootModeName(m), out));
    TEST_ASSERT_EQUAL(static_cast<int>(m), static_cast<int>(out));
  }
  RebootMode out = RebootMode::kDaily;
  TEST_ASSERT_FALSE(sched::parseRebootMode("monthly", out));
  TEST_ASSERT_FALSE(sched::parseRebootMode("Daily", out));
  TEST_ASSERT_FALSE(sched::parseRebootMode("", out));
  TEST_ASSERT_FALSE(sched::parseRebootMode(nullptr, out));
  TEST_ASSERT_EQUAL(static_cast<int>(RebootMode::kDaily), static_cast<int>(out));
}

static void test_off_never_reboots() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kOff, 4, 0));
  fakeClock.setLocal(2026, 11, 7, 4, 0);
  TEST_ASSERT_FALSE(s.due());
  util::CivilTime next;
  TEST_ASSERT_FALSE(s.next(next));
}

static void test_daily_due_in_window_only() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kDaily, 4, 0));
  fakeClock.setLocal(2026, 11, 7, 3, 59);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 11, 7, 4, 0);
  TEST_ASSERT_TRUE(s.due());
  fakeClock.setLocal(2026, 11, 7, 4, 59);
  TEST_ASSERT_TRUE(s.due());  // late by up to the window (busy, clock just synced)
  fakeClock.setLocal(2026, 11, 7, 5, 0);
  TEST_ASSERT_FALSE(s.due());  // missed: no catch-up hours later
  fakeClock.setLocal(2026, 11, 7, 23, 0);
  TEST_ASSERT_FALSE(s.due());
}

static void test_not_before_clock_sync_or_with_bogus_year() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kDaily, 4, 0));
  fakeClock.setLocal(2026, 11, 7, 4, 10);
  fakeClock.setSynced(false);
  TEST_ASSERT_FALSE(s.due());
  util::CivilTime next;
  TEST_ASSERT_FALSE(s.next(next));
  fakeClock.setSynced(true);
  fakeClock.setLocal(1970, 1, 1, 4, 10);
  TEST_ASSERT_FALSE(s.due());
}

static void test_once_per_day_and_survives_the_restart() {
  {
    RebootScheduler s(fakeClock, kv);
    s.setPlan(plan(RebootMode::kDaily, 4, 0));
    fakeClock.setLocal(2026, 11, 7, 4, 0);
    TEST_ASSERT_TRUE(s.due());
    s.markRebooting();
    TEST_ASSERT_EQUAL(20261107u, s.lastRebootDate());
    TEST_ASSERT_FALSE(s.due());
  }
  // "After the restart": fresh object, saved date, and the board has been up a long
  // time in this test (as if the NVS read were the only guard).
  RebootScheduler again(fakeClock, kv);
  again.setPlan(plan(RebootMode::kDaily, 4, 0));
  fakeClock.setLocal(2026, 11, 7, 4, 30);
  TEST_ASSERT_FALSE(again.due());
  fakeClock.setLocal(2026, 11, 8, 4, 0);
  TEST_ASSERT_TRUE(again.due());  // next day
}

static void test_fresh_boot_skips_the_day() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kDaily, 4, 0));
  fakeClock = FakeClock{};
  fakeClock.setSynced(true);
  // Started at 03:55 (5 min before): skip today's reboot, it just restarted.
  fakeClock.advanceMs(5 * 60000);
  fakeClock.setLocal(2026, 11, 7, 4, 0);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.advanceMs(20 * 60000);
  fakeClock.setLocal(2026, 11, 7, 4, 20);
  TEST_ASSERT_FALSE(s.due());  // still the same boot, still "started just before"
  // Started at 03:50 exactly (10 min before): reboots.
  fakeClock = FakeClock{};
  fakeClock.setSynced(true);
  fakeClock.advanceMs(10 * 60000);
  fakeClock.setLocal(2026, 11, 7, 4, 0);
  TEST_ASSERT_TRUE(s.due());
  // Started at 04:30 (inside the window, e.g. after a power cut): skips.
  fakeClock = FakeClock{};
  fakeClock.setSynced(true);
  fakeClock.advanceMs(2 * 60000);
  fakeClock.setLocal(2026, 11, 7, 4, 32);
  TEST_ASSERT_FALSE(s.due());
}

static void test_markRebooting_without_due_saves_nothing() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kDaily, 4, 0));
  fakeClock.setLocal(2026, 11, 7, 12, 0);
  TEST_ASSERT_FALSE(s.due());
  s.markRebooting();
  TEST_ASSERT_EQUAL(0u, s.lastRebootDate());
  TEST_ASSERT_EQUAL(0u, kv.writes);
}

static void test_weekly_only_on_its_day() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kWeekly, 3, 30, 0));  // Sundays 03:30
  fakeClock.setLocal(2026, 11, 7, 3, 30);          // Saturday
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 11, 8, 3, 30);  // Sunday
  TEST_ASSERT_TRUE(s.due());
  s.markRebooting();
  fakeClock.setLocal(2026, 11, 9, 3, 30);  // Monday
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 11, 15, 3, 45);  // next Sunday
  TEST_ASSERT_TRUE(s.due());
  for (int day = 0; day < 7; day++) {  // every weekday value works
    s.setPlan(plan(RebootMode::kWeekly, 12, 0, day));
    int hits = 0;
    for (int d = 16; d < 23; d++) {
      fakeClock.setLocal(2026, 11, d, 12, 0);
      hits += s.due();
    }
    TEST_ASSERT_EQUAL(1, hits);
  }
}

// 23:30 + 60 min runs into the next day: the slot still belongs to the day it started.
static void test_window_crossing_midnight() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kWeekly, 23, 30, 6));  // Saturdays 23:30
  fakeClock.setLocal(2026, 11, 8, 0, 15);           // Sunday 00:15 = Saturday's window
  TEST_ASSERT_TRUE(s.due());
  s.markRebooting();
  TEST_ASSERT_EQUAL(20261107u, s.lastRebootDate());  // recorded for Saturday
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 11, 8, 0, 30);  // window over
  RebootScheduler fresh(fakeClock, kv);
  fresh.setPlan(s.plan());
  TEST_ASSERT_FALSE(fresh.due());
  // A Sunday-only schedule is not due early Sunday morning from Saturday's slot.
  fresh.setPlan(plan(RebootMode::kWeekly, 23, 30, 0));
  fakeClock.setLocal(2026, 11, 8, 0, 15);
  TEST_ASSERT_FALSE(fresh.due());
  // Daily at 23:59: due until 00:58 the next day.
  MemKvStore otherKv;
  RebootScheduler daily(fakeClock, otherKv);
  daily.setPlan(plan(RebootMode::kDaily, 23, 59));
  fakeClock.setLocal(2026, 11, 9, 0, 58);
  TEST_ASSERT_TRUE(daily.due());
  fakeClock.setLocal(2026, 11, 9, 0, 59);
  TEST_ASSERT_FALSE(daily.due());
}

// Spring forward (02:00 -> 03:00): 02:30 never shows on the clock, 03:00..03:29 does.
// Fall back: 01:30 happens twice, the reboot only once.
static void test_dst_gap_and_repeated_hour() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kDaily, 2, 30));
  fakeClock.setLocal(2026, 3, 29, 1, 59);
  TEST_ASSERT_FALSE(s.due());
  fakeClock.setLocal(2026, 3, 29, 3, 0);  // the clock jumped
  TEST_ASSERT_TRUE(s.due());
  s.setPlan(plan(RebootMode::kDaily, 1, 30));
  fakeClock.setLocal(2026, 10, 25, 1, 30);
  TEST_ASSERT_TRUE(s.due());
  s.markRebooting();
  fakeClock.setLocal(2026, 10, 25, 1, 30);  // the same local hour again, an hour later
  TEST_ASSERT_FALSE(s.due());
}

static void test_failed_save_still_blocks_a_loop_this_boot() {
  RebootScheduler s(fakeClock, kv);
  s.setPlan(plan(RebootMode::kDaily, 4, 0));
  kv.failWrites = true;
  fakeClock.setLocal(2026, 11, 7, 4, 0);
  TEST_ASSERT_TRUE(s.due());
  s.markRebooting();
  TEST_ASSERT_FALSE(s.due());  // remembered in memory
  // After the restart the date is lost, but the fresh-boot rule stops a loop.
  RebootScheduler after(fakeClock, kv);
  after.setPlan(s.plan());
  fakeClock = FakeClock{};
  fakeClock.setSynced(true);
  fakeClock.advanceMs(60000);
  fakeClock.setLocal(2026, 11, 7, 4, 1);
  TEST_ASSERT_FALSE(after.due());
}

static void test_next_reboot_for_the_dashboard() {
  RebootScheduler s(fakeClock, kv);
  util::CivilTime n;
  s.setPlan(plan(RebootMode::kDaily, 4, 0));
  fakeClock.setLocal(2026, 11, 7, 3, 0);
  TEST_ASSERT_TRUE(s.next(n));
  TEST_ASSERT_EQUAL(20261107u, n.dateKey());
  TEST_ASSERT_EQUAL(4, n.hour);
  TEST_ASSERT_EQUAL(0, n.minute);
  fakeClock.setLocal(2026, 11, 7, 4, 0);  // the minute it is due: next is tomorrow
  TEST_ASSERT_TRUE(s.next(n));
  TEST_ASSERT_EQUAL(20261108u, n.dateKey());
  s.setPlan(plan(RebootMode::kWeekly, 4, 0, 3));  // Wednesdays
  TEST_ASSERT_TRUE(s.next(n));
  TEST_ASSERT_EQUAL(20261111u, n.dateKey());
  fakeClock.setLocal(2026, 11, 11, 3, 59);  // Wednesday, before the time
  TEST_ASSERT_TRUE(s.next(n));
  TEST_ASSERT_EQUAL(20261111u, n.dateKey());
  fakeClock.setLocal(2026, 11, 11, 4, 1);  // Wednesday, after: a week later
  TEST_ASSERT_TRUE(s.next(n));
  TEST_ASSERT_EQUAL(20261118u, n.dateKey());
  TEST_ASSERT_EQUAL(0, n.second);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_mode_names_round_trip);
  RUN_TEST(test_off_never_reboots);
  RUN_TEST(test_daily_due_in_window_only);
  RUN_TEST(test_not_before_clock_sync_or_with_bogus_year);
  RUN_TEST(test_once_per_day_and_survives_the_restart);
  RUN_TEST(test_fresh_boot_skips_the_day);
  RUN_TEST(test_markRebooting_without_due_saves_nothing);
  RUN_TEST(test_weekly_only_on_its_day);
  RUN_TEST(test_window_crossing_midnight);
  RUN_TEST(test_dst_gap_and_repeated_hour);
  RUN_TEST(test_failed_save_still_blocks_a_loop_this_boot);
  RUN_TEST(test_next_reboot_for_the_dashboard);
  return UNITY_END();
}
