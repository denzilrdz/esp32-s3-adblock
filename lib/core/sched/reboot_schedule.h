#pragma once
// Scheduled reboot (ARCHITECTURE.md §8.2): off, daily, or weekly on one day, at a
// local time of day. Rules:
//
//  - Nothing happens until the wall clock is synced and plausible (year >= minYear).
//  - The reboot is due from the scheduled minute for kWindowMinutes. A board that was
//    off, busy (firmware upload) or without a clock for the whole window skips that
//    day: catching up hours later would restart it at a time nobody chose. The window
//    also covers a time that a DST change skips (02:30 on a spring-forward night runs
//    at 03:00).
//  - A board that started less than kFreshBootMinutes before the scheduled time (or
//    after it) skips that day: it has only just restarted.
//  - The date of each scheduled reboot is saved before restarting, so the board never
//    restarts twice for the same day (e.g. the repeated hour when DST ends).

#include <cstdint>

#include "hal/clock.h"
#include "hal/kv_store.h"
#include "util/civil_time.h"

namespace sched {

enum class RebootMode : uint8_t { kOff, kDaily, kWeekly };

const char* rebootModeName(RebootMode m);  // "off", "daily", "weekly"
bool parseRebootMode(const char* s, RebootMode& out);

struct RebootPlan {
  RebootMode mode = RebootMode::kOff;
  uint8_t weekday = 0;  // 0 = Sunday .. 6 = Saturday (weekly only)
  uint8_t hour = 4;
  uint8_t minute = 0;

  bool operator==(const RebootPlan& o) const {
    return mode == o.mode && weekday == o.weekday && hour == o.hour && minute == o.minute;
  }
  bool operator!=(const RebootPlan& o) const { return !(*this == o); }
};

class RebootScheduler {
 public:
  static constexpr const char* kLastKey = "rb_last";  // yyyymmdd of the last scheduled reboot
  static constexpr uint32_t kWindowMinutes = 60;
  static constexpr uint32_t kFreshBootMinutes = 10;

  RebootScheduler(const hal::IClock& clock, hal::IKeyValueStore& kv, int minYear = 2026);

  void setPlan(const RebootPlan& plan) { plan_ = plan; }
  const RebootPlan& plan() const { return plan_; }

  // True when the board should restart now. Call markRebooting() right before doing it.
  bool due();
  // Records the scheduled date that due() found, so it is not repeated.
  void markRebooting();

  // Local date and time of the next scheduled reboot; false when off or the clock is
  // not set. Ignores DST shifts (display only).
  bool next(util::CivilTime& out) const;

  uint32_t lastRebootDate() const { return last_; }

 private:
  bool clockValid() const;
  bool dayMatches(const util::CivilTime& date) const;

  const hal::IClock& clock_;
  hal::IKeyValueStore& kv_;
  int minYear_;
  RebootPlan plan_;
  uint32_t last_ = 0;
  uint32_t dueDate_ = 0;
};

}  // namespace sched
