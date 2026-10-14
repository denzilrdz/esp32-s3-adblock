#pragma once
// Deterministic clock for tests. Wall time and monotonic time advance together.

#include "hal/clock.h"

class FakeClock final : public hal::IClock {
 public:
  static constexpr int32_t kIstOffset = 5 * 3600 + 30 * 60;

  uint64_t monotonicMs() const override { return mono_ms_; }
  bool wallClockSynced() const override { return synced_; }
  int64_t unixTime() const override { return unix_; }
  util::CivilTime localTime() const override { return util::civilFromUnix(unix_, offset_); }

  void setSynced(bool synced) { synced_ = synced; }
  void setUtcOffset(int32_t seconds) { offset_ = seconds; }
  void setUnix(int64_t unixSeconds) { unix_ = unixSeconds; }

  // Sets wall time from a local (IST by default) civil time.
  void setLocal(int year, int month, int day, int hour, int minute, int second = 0) {
    util::CivilTime t;
    t.year = year;
    t.month = month;
    t.day = day;
    t.hour = hour;
    t.minute = minute;
    t.second = second;
    unix_ = util::unixFromCivil(t, offset_);
  }

  void advanceMs(uint64_t ms) {
    mono_ms_ += ms;
    sub_ms_ += ms;
    unix_ += static_cast<int64_t>(sub_ms_ / 1000);
    sub_ms_ %= 1000;
  }
  void advanceSeconds(uint64_t s) { advanceMs(s * 1000); }

 private:
  uint64_t mono_ms_ = 1000;
  uint64_t sub_ms_ = 0;
  bool synced_ = false;
  int32_t offset_ = kIstOffset;
  int64_t unix_ = 0;
};
