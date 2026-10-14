#pragma once
// IClock backed by esp_timer (monotonic) and the libc wall clock set by SNTP.

#include <esp_timer.h>
#include <time.h>

#include <atomic>

#include "hal/clock.h"

namespace platform {

class EspClock final : public hal::IClock {
 public:
  uint64_t monotonicMs() const override { return static_cast<uint64_t>(esp_timer_get_time() / 1000); }
  bool wallClockSynced() const override { return synced_.load(std::memory_order_acquire); }
  int64_t unixTime() const override { return static_cast<int64_t>(time(nullptr)); }

  util::CivilTime localTime() const override {
    const time_t now = time(nullptr);
    struct tm tmv;
    localtime_r(&now, &tmv);  // uses the TZ set by configTzTime()
    util::CivilTime t;
    t.year = tmv.tm_year + 1900;
    t.month = tmv.tm_mon + 1;
    t.day = tmv.tm_mday;
    t.hour = tmv.tm_hour;
    t.minute = tmv.tm_min;
    t.second = tmv.tm_sec;
    return t;
  }

  // Called from the SNTP sync callback.
  void setSynced(bool synced) { synced_.store(synced, std::memory_order_release); }

 private:
  std::atomic<bool> synced_{false};
};

}  // namespace platform
