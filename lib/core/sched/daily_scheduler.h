#pragma once
// Decides when the daily blocklist update runs (default 02:00 local time, IST).
//
//  - Nothing runs until the wall clock is synced and plausible (year >= minYear).
//  - Due once per local day, at hour:minute plus a per-day random jitter, so many
//    devices don't hit the list server at the same second. A device that was off at
//    02:00 catches up as soon as it is on and synced.
//  - The date of the last successful run is persisted, so a reboot never causes a
//    second run on the same day.
//  - After a failure: retry every retryIntervalMs, up to maxRetries, then wait for
//    the next day.

#include <cstdint>

#include "hal/clock.h"
#include "hal/kv_store.h"
#include "hal/random.h"

namespace sched {

struct ScheduleConfig {
  uint8_t hour = 2;
  uint8_t minute = 0;
  uint32_t maxJitterMinutes = 10;
  uint32_t retryIntervalMs = 3600000;  // 1 h
  uint32_t maxRetries = 6;
  int minYear = 2026;
};

class DailyScheduler {
 public:
  static constexpr const char* kLastSuccessKey = "sch_last";

  DailyScheduler(const ScheduleConfig& cfg, const hal::IClock& clock, hal::IKeyValueStore& kv,
                 hal::IRandom& random);

  bool timeValid() const;
  bool due();
  void markSuccess();
  void markFailure();
  void requestNow() { manual_ = true; }  // dashboard "Update now"
  void setTime(uint8_t hour, uint8_t minute);

  uint32_t lastSuccessDate() const { return lastSuccess_; }  // yyyymmdd, 0 = never
  uint32_t retriesToday() const { return retries_; }
  bool gaveUpToday() const { return gaveUp_; }
  // Minutes after local midnight when today's run becomes due (incl. jitter).
  uint32_t targetMinuteOfDay() const;

 private:
  void rollDay(uint32_t today);

  ScheduleConfig cfg_;
  const hal::IClock& clock_;
  hal::IKeyValueStore& kv_;
  hal::IRandom& random_;
  uint32_t lastSuccess_ = 0;
  uint32_t stateDate_ = 0;
  uint32_t jitter_ = 0;
  uint32_t retries_ = 0;
  bool retryPending_ = false;
  uint64_t retryAtMs_ = 0;
  bool gaveUp_ = false;
  bool manual_ = false;
};

}  // namespace sched
