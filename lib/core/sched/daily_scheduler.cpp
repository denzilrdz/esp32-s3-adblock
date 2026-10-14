#include "sched/daily_scheduler.h"

namespace sched {

DailyScheduler::DailyScheduler(const ScheduleConfig& cfg, const hal::IClock& clock, hal::IKeyValueStore& kv,
                               hal::IRandom& random)
    : cfg_(cfg), clock_(clock), kv_(kv), random_(random) {
  uint32_t v = 0;
  if (kv_.getU32(kLastSuccessKey, v)) lastSuccess_ = v;
}

bool DailyScheduler::timeValid() const {
  return clock_.wallClockSynced() && clock_.localTime().year >= cfg_.minYear;
}

void DailyScheduler::setTime(uint8_t hour, uint8_t minute) {
  cfg_.hour = hour < 24 ? hour : 2;
  cfg_.minute = minute < 60 ? minute : 0;
}

uint32_t DailyScheduler::targetMinuteOfDay() const {
  const uint32_t t = cfg_.hour * 60u + cfg_.minute + jitter_;
  return t > 1439 ? 1439 : t;
}

void DailyScheduler::rollDay(uint32_t today) {
  if (today == stateDate_) return;
  stateDate_ = today;
  retries_ = 0;
  retryPending_ = false;
  gaveUp_ = false;
  jitter_ = cfg_.maxJitterMinutes ? random_.uniform(cfg_.maxJitterMinutes + 1) : 0;
}

bool DailyScheduler::due() {
  if (manual_) return true;
  if (!timeValid()) return false;
  const util::CivilTime t = clock_.localTime();
  rollDay(t.dateKey());
  if (lastSuccess_ == stateDate_ || gaveUp_) return false;
  if (retryPending_) return clock_.monotonicMs() >= retryAtMs_;
  return static_cast<uint32_t>(t.hour * 60 + t.minute) >= targetMinuteOfDay();
}

void DailyScheduler::markSuccess() {
  manual_ = false;
  retries_ = 0;
  retryPending_ = false;
  if (!timeValid()) return;  // manual run before sync: don't record a bogus date
  rollDay(clock_.localTime().dateKey());
  lastSuccess_ = stateDate_;
  kv_.setU32(kLastSuccessKey, lastSuccess_);
}

void DailyScheduler::markFailure() {
  manual_ = false;
  retries_++;
  if (retries_ > cfg_.maxRetries) {
    gaveUp_ = true;
    retryPending_ = false;
    return;
  }
  retryPending_ = true;
  retryAtMs_ = clock_.monotonicMs() + cfg_.retryIntervalMs;
}

}  // namespace sched
